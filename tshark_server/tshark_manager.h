/**
 * @file tshark_manager.h
 * @author abumpkin (forwardslash@foxmail.com)
 * @link https://github.com/abumpkin/tsharkY @endlink
 *
 * ISC License
 *
 * @copyright Copyright (c) 2025 abumpkin
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#pragma once
#include "mutils.h"
#include "parser_stream.h"
#include "rapidjson/allocators.h"
#include "traffic_statistics.h"
#include "tshark_info.h"
#include "unistream.h"
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <functional>
#include <future>
#include <initializer_list>
#include <loguru.hpp>
#include <memory>
#include <mutex>
#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

class TSharkManager;
struct SharkCaptureThread;

struct SharkLoader {
    protected:
    volatile std::atomic_bool stop_ctl = false;

    public:
    SharkLoader() = delete;
    SharkLoader(SharkLoader &) = delete;
    SharkLoader &operator=(SharkLoader &) = delete;
    SharkLoader(SharkLoader &&) = delete;
    SharkLoader &operator=(SharkLoader &&) = delete;
    std::vector<char> fixed_data;
    std::shared_ptr<UniStreamInterface> parser_stream;
    std::vector<std::shared_ptr<ParserStream>> parsers;
    std::shared_ptr<UniStreamInterface> in_stream;

    SharkLoader(std::shared_ptr<UniStreamInterface> stream)
        : in_stream(stream) {}

    template <typename... T>
    void register_parser_streams(T const &...parsers) {
        this->parsers =
            std::initializer_list<std::shared_ptr<ParserStream>>{parsers...};
        parser_stream = UniSyncR2W::Make(in_stream, parsers...);
    }

    virtual bool load() {
        stop_ctl = false;
        if (!this->parser_stream) {
            this->parser_stream = this->in_stream;
        }
        return false;
    }

    virtual void close_streams() {
        if (in_stream) in_stream->close_read();
        if (parser_stream) parser_stream->close_read();
    }

    virtual void interrupt_load() {
        if (!stop_ctl) stop_ctl = true;
    }
};

struct SharkPcapngLoader : SharkLoader {
    struct GeneralHeader {
        uint32_t block_type;
        uint32_t block_length;
    };

    struct SectionHeaderBlockHeader {
        GeneralHeader block_info = {0x0a0d0d0a, 0};
        uint32_t byte_order = 0x1a2b3c4d;
        uint16_t major_version = 0x0001;
        uint16_t minor_version = 0x0000;
        uint64_t section_length = 0xffffffffffffffffull;
    };

    struct InterfaceDescriptionBlockHeader {
        GeneralHeader block_info = {0x00000001, 0};
        uint16_t link_type;
        uint16_t resv;
        uint32_t snap_length;
    };

    struct EnhancedPacketBlockHeader {
        GeneralHeader block_info = {0x00000006, 0};
        uint32_t interface_id;
        uint32_t timestamp_upper;
        uint32_t timestamp_lower;
        uint32_t captured_packet_length;
        uint32_t original_packet_length;
    };

    SharkPcapngLoader(std::shared_ptr<UniStreamInterface> stream)
        : SharkLoader(stream) {}

    virtual bool load() override {
        SharkLoader::load();
        auto bin_stream = this->parser_stream;
        GeneralHeader section;
        EnhancedPacketBlockHeader packet_section;
        char *p_section = reinterpret_cast<char *>(&section);
        uint32_t rd_len, t;
        bool right_format = false;
        std::vector<char> buf;
        bool ret = false;
        while (true) {
            if (bin_stream->eof()) {
                ret = true;
                break;
            }
            using namespace std::chrono_literals;
            rd_len = 0;
            t = 0;
            while (!stop_ctl && !bin_stream->eof() &&
                   rd_len < sizeof(section)) {
                t = bin_stream->read_ub(
                    p_section + rd_len, sizeof(section) - rd_len);
                rd_len += t;
                if (!t) std::this_thread::sleep_for(1ms);
            }

            if (stop_ctl) break;
            if (!rd_len) break;
            if (section.block_type == 0x0a0d0d0a ||
                section.block_type == 0x00000001) {
                if (fixed_data.capacity() - fixed_data.size() <
                    section.block_length) {
                    fixed_data.reserve(
                        fixed_data.size() + section.block_length);
                }
                memcpy(fixed_data.data() + fixed_data.size(), p_section,
                    sizeof(GeneralHeader));
                fixed_data.resize(fixed_data.size() + sizeof(GeneralHeader));
                rd_len = bin_stream->read(fixed_data.data() + fixed_data.size(),
                    section.block_length - sizeof(GeneralHeader));
                fixed_data.resize(fixed_data.size() + rd_len);
                if (!rd_len) {
                    LOG_F(ERROR, "pcapng wrong format");
                    break;
                }
                LOG_F(INFO, "pcapng found Pcapng Header Block!");
                right_format = true;
                continue;
            }
            if (!right_format) {
                std::vector<char> header(sizeof(GeneralHeader));
                memcpy(header.data(), reinterpret_cast<char *>(&section),
                    header.size());
                LOG_F(ERROR, "pcapng wrong format: %s",
                    utils_data_to_hex(header).c_str());
                break;
            }
            if (section.block_type == 0x00000006) {
                uint32_t cap_off, cap_len;
                while (buf.capacity() < section.block_length) {
                    if (buf.capacity() == 0) buf.reserve(section.block_length);
                    buf.reserve(buf.capacity() << 1);
                }
                buf.resize(section.block_length);
                packet_section.block_info = section;
                rd_len = bin_stream->read(
                    reinterpret_cast<char *>(&packet_section.interface_id),
                    sizeof(EnhancedPacketBlockHeader) - sizeof(GeneralHeader));
                if (!rd_len) {
                    LOG_F(ERROR, "pcapng wrong format");
                    break;
                }
                cap_off = sizeof(EnhancedPacketBlockHeader);
                cap_len = packet_section.captured_packet_length;
                memcpy(buf.data(), &packet_section, cap_off);
                rd_len = bin_stream->read(
                    buf.data() + cap_off, section.block_length - cap_off);
                bin_stream->flush();

                if (rd_len != section.block_length - cap_off) {
                    LOG_F(ERROR, "pcapng wrong format");
                    break;
                }
                try {
                    for (auto const &i : parsers) {
                        i->packet_arrived(fixed_data, buf, cap_off, cap_len);
                    }
                }
                catch (...) {
                    LOG_F(ERROR, "parse failure");
                    break;
                }
                continue;
            }
            rd_len = bin_stream->read_to_null(
                section.block_length - sizeof(GeneralHeader));
            if (!rd_len) {
                LOG_F(ERROR, "pcapng wrong format");
                break;
            }
        }
        for (auto const &i : parsers) {
            i->wait_done();
        }
        close_streams();
        return ret;
    }
};

struct SharkPcapLoader : SharkLoader {
    struct PcapHeader {
        uint32_t magic_number;
        uint16_t version_major;
        uint16_t version_minor;
        int32_t thiszone;
        uint32_t sigfigs;
        uint32_t snaplen;
        uint32_t network;
    };

    struct PcapPacketHeader {
        uint32_t ts_sec;
        uint32_t ts_usec;
        uint32_t caplen;
        uint32_t len;
    };

    SharkPcapLoader(std::shared_ptr<UniStreamInterface> stream)
        : SharkLoader(stream) {}

    virtual bool load() override {
        SharkLoader::load();
        auto bin_stream = parser_stream;
        PcapPacketHeader section;
        char *p_section = reinterpret_cast<char *>(&section);
        fixed_data.resize(sizeof(PcapHeader));
        PcapHeader *pcap_header =
            reinterpret_cast<PcapHeader *>(fixed_data.data());
        bin_stream->read(fixed_data.data(), sizeof(PcapHeader));
        if (pcap_header->magic_number != 0xa1b23c4d &&
            pcap_header->magic_number != 0xa1b2c3d4) {
            LOG_F(ERROR, "pcap wrong format: %s",
                utils_data_to_hex(fixed_data).c_str());
            close_streams();
            return false;
        }
        uint32_t rd_len, t;
        std::vector<char> buf;
        bool ret = false;
        while (true) {
            if (bin_stream->eof()) {
                ret = true;
                break;
            }
            using namespace std::chrono_literals;
            rd_len = 0;
            t = 0;
            while (!stop_ctl && !bin_stream->eof() &&
                   rd_len < sizeof(PcapPacketHeader)) {
                t = bin_stream->read_ub(
                    p_section + rd_len, sizeof(PcapPacketHeader) - rd_len);
                rd_len += t;
                if (!t) std::this_thread::sleep_for(1ms);
            }
            if (stop_ctl) break;
            if (!rd_len) break;

            uint32_t cap_off, cap_len;
            uint32_t block_len = sizeof(PcapPacketHeader) + section.caplen;
            while (buf.capacity() < block_len) {
                if (buf.capacity() == 0) buf.reserve(block_len);
                buf.reserve(buf.capacity() << 1);
            }
            buf.resize(block_len);
            cap_off = sizeof(PcapPacketHeader);
            cap_len = section.caplen;
            memcpy(buf.data(), p_section, cap_off);
            rd_len =
                bin_stream->read(buf.data() + cap_off, block_len - cap_off);
            bin_stream->flush();

            if (rd_len != block_len - cap_off) {
                LOG_F(ERROR, "pcapng wrong format");
                break;
            }
            try {
                for (auto const &i : parsers) {
                    i->packet_arrived(fixed_data, buf, cap_off, cap_len);
                }
            }
            catch (...) {
                LOG_F(ERROR, "parse failure");
                break;
            }
        }
        for (auto const &i : parsers) {
            i->wait_done();
        }
        close_streams();
        return ret;
    }
};

struct SharkCaptureThread {
    using LoaderConfig = std::function<void(std::shared_ptr<SharkLoader>)>;
    std::shared_ptr<SharkLoader> loader;

    private:
    std::unique_ptr<std::thread> t_t;
    std::condition_variable t_cv;
    std::mutex t_m;
    std::promise<bool> start_status;
    std::promise<bool> stop_status;
    volatile std::atomic_bool is_capturing = false;
    volatile std::atomic_bool is_done_with_succeed = false;

    public:
    SharkCaptureThread() = default;

    bool load_capture_file(std::filesystem::path path, LoaderConfig config) {
        std::string ext = path.extension().generic_string();
        utils_str_lowcase(ext);
        if (!std::filesystem::exists(path)) {
            LOG_F(ERROR, "ERROR: (%s) File not exists.",
                std::filesystem::absolute(path).c_str());
            return false;
        }
        if (ext != ".pcap" && ext != ".pcapng") {
            LOG_F(ERROR, "ERROR: (%s) Unkown file format. (%s)", ext.c_str(),
                std::filesystem::absolute(path).c_str());
            return false;
        }
        if (capturing_status()) stop_capture().wait();
        auto stream = std::make_shared<UniStreamFile>(path.generic_string());
        if (ext == ".pcap") {
            loader = std::make_shared<SharkPcapLoader>(stream);
        }
        else if (ext == ".pcapng") {
            loader = std::make_shared<SharkPcapngLoader>(stream);
        }
        if (config) config(loader);
        loader->load();
        return true;
    }

    bool start_capture_blocked(LoaderConfig config, std::string if_name = "",
        std::filesystem::path save_to = "") {
        std::shared_ptr<UniStreamInterface> stream;
        std::string cmd = DUMPCAP_PATH " -Q -w -";
        if (!if_name.empty()) {
            cmd += " -i " + if_name;
        }
        if (loader) loader.reset();
        if (!save_to.empty()) {
            save_to = utils_test_valid_filename(save_to);
            if (save_to.empty()) {
                LOG_F(ERROR, "ERROR: (%s) Path to write is not valid.",
                    save_to.c_str());
                return false;
            }
            std::string ext = save_to.extension().generic_string();
            if (ext != ".pcap" && ext != ".pcapng") {
                LOG_F(ERROR,
                    "ERROR: (%s) Please specify a supported save format. "
                    "\".pcap\" or \".pcapng\".",
                    save_to.c_str());
                return false;
            }
            if (std::filesystem::exists(save_to)) {
                LOG_F(WARNING,
                    "WARING: (%s) File has been exists. Deleted now!",
                    save_to.c_str());
                std::filesystem::remove(save_to);
            }
            if (!std::filesystem::exists(save_to.parent_path())) {
                std::filesystem::create_directories(save_to.parent_path());
            }
            stream = UniSyncR2W::Make(std::make_shared<UniStreamDualPipeU>(cmd),
                std::make_shared<UniStreamFile>(
                    save_to.generic_string(), std::ios::trunc));
            if (ext == ".pcap") {
                loader = std::make_shared<SharkPcapLoader>(stream);
                cmd += " -F pcap";
            }
            else if (ext == ".pcapng") {
                loader = std::make_shared<SharkPcapngLoader>(stream);
            }
        }
        if (!stream) {
            stream = std::make_shared<UniStreamDualPipeU>(cmd);
        }
        if (!loader) {
            loader = std::make_shared<SharkPcapngLoader>(stream);
        }
        if (config) config(loader);
        loader->load();
        return true;
    }

    std::future<bool> start_capture(LoaderConfig config,
        std::string const &if_name = "", std::filesystem::path save_to = "") {
        std::future<bool> ret;
        if (t_t) {
            {
                std::lock_guard<std::mutex> lock(t_m);
                if (is_capturing) {
                    LOG_F(ERROR,
                        "ERROR: Thread create fail. Capture thread already in "
                        "running.");
                    return std::async(std::launch::deferred, []() {
                        return false;
                    });
                }
            }
            t_t->join();
        }
        {
            std::lock_guard<std::mutex> lock(t_m);
            this->is_capturing = false;
            this->is_done_with_succeed = false;
            start_status = std::promise<bool>();
            stop_status = std::promise<bool>();
            ret = start_status.get_future();
        }
        t_t = std::make_unique<std::thread>(
            thread, this, config, if_name, save_to);
        return ret;
    }

    std::future<bool> stop_capture() {
        std::lock_guard<std::mutex> lock(t_m);
        std::future<bool> ret;
        if (!is_capturing) {
            LOG_F(ERROR,
                "ERROR: Not in capturing. There is no need to stop capture.");
            return std::async(std::launch::deferred, []() {
                return false;
            });
        }
        loader->interrupt_load();
        stop_status = std::promise<bool>();
        ret = stop_status.get_future();
        return ret;
    }

    bool capturing_status() {
        std::lock_guard<std::mutex> lock(t_m);
        return is_capturing;
    }
    bool capture_done_with_succeed() noexcept(false) {
        if (capturing_status()) {
            LOG_F(ERROR, "ERROR: Capture thread in running.");
            throw std::runtime_error("Capture Thread in running.");
        }
        if (!t_t) {
            LOG_F(ERROR, "ERROR: Capture thread never been run.");
            throw std::runtime_error("Capture Thread never been run.");
        }
        return is_done_with_succeed;
    }

    static void thread(SharkCaptureThread *const tobj, LoaderConfig config,
        std::string if_name = "", std::filesystem::path save_to = "") {
        {
            std::lock_guard<std::mutex> lock(tobj->t_m);
            tobj->is_capturing = true;
            tobj->start_status.set_value(true);
        }
        tobj->is_done_with_succeed =
            tobj->start_capture_blocked(config, if_name, save_to);
        {
            std::lock_guard<std::mutex> lock(tobj->t_m);
            tobj->is_capturing = false;
            tobj->stop_status.set_value_at_thread_exit(true);
        }
        LOG_F(INFO, "Capture thread exit.");
    }

    ~SharkCaptureThread() {
        if (t_t) {
            if (is_capturing) {
                stop_capture().wait();
            }
            if (t_t->joinable()) {
                t_t->join();
            }
        }
    }
};

class TSharkManager {

    enum class CTLSIG : uint32_t {
        NO_ACTION = 0,
        START_CAPTURE,

    } ctl_thread_sig;

    SharkCaptureThread capture_thread;
    InterfacesActivityThread statistics_thread;

    std::shared_ptr<ParserStreamPacketBrief<>> ps_brief;
    std::shared_ptr<ParserStreamPacketDetail> ps_detail;

    std::condition_variable ctl_cv;
    std::mutex ctl_m;

    SharkCaptureThread::LoaderConfig parser_config(
        ParserStreamPacketBrief<>::PacketHandler brief_handler = nullptr,
        ParserStreamPacketDetail::PacketHandler detail_handler = nullptr) {
        ps_brief = std::make_shared<ParserStreamPacketBrief<>>(brief_handler);
        ps_detail = std::make_shared<ParserStreamPacketDetail>(detail_handler);
        return [=](std::shared_ptr<SharkLoader> loader) {
            loader->register_parser_streams(ps_brief, ps_detail);
        };
    }

    public:
    TSharkManager() {}
    static void thread(TSharkManager *const manager) {
        std::unique_lock<std::mutex> lock(manager->ctl_m);
        manager->ctl_cv.wait(lock, [&]() {
            return manager->ctl_thread_sig != CTLSIG::NO_ACTION;
        });
        switch (manager->ctl_thread_sig) {
        case CTLSIG::START_CAPTURE:
            break;
        default:
            break;
        }
        manager->ctl_thread_sig = CTLSIG::NO_ACTION;
    }

    std::future<bool> capture_start(std::string const &if_name = "",
        std::filesystem::path save_to = "",
        ParserStreamPacketBrief<>::PacketHandler brief_handler = nullptr,
        ParserStreamPacketDetail::PacketHandler detail_handler = nullptr) {
        if (capture_is_running())
            return std::async(std::launch::deferred, [] {
                return false;
            });
        return capture_thread.start_capture(
            parser_config(brief_handler, detail_handler), if_name, save_to);
    }

    std::future<bool> capture_stop() {
        return capture_thread.stop_capture();
    }

    std::future<bool> capture_from_file(std::filesystem::path path) {
        return std::async(std::launch::async, [=]() {
            return capture_thread.load_capture_file(path, parser_config());
        });
    }

    bool capture_is_running() {
        return capture_thread.capturing_status();
    }

    std::string capture_get_brief(uint32_t pos = 0, uint32_t len = 0) {
        std::string ret;
        if (!ps_brief) return ret;
        uint32_t total = ps_brief->packets_list.size();
        if (pos > total) return ret;
        if (pos + len > total || len == 0) len = total - pos;
        rapidjson::Document obj;
        rapidjson::MemoryPoolAllocator<> allocator;
        obj.SetArray();
        for (auto i = ps_brief->packets_list.cbegin() + pos;
            i != ps_brief->packets_list.cbegin() + pos + len; i++) {
            obj.PushBack(i->get()->to_json_obj(allocator), allocator);
        }
        return utils_to_json(obj, true);
    }

    std::string capture_get_detail(uint32_t pos) {
        std::string ret;
        if (!ps_detail) return ret;
        if (pos >= ps_detail->packets_list.size()) return ret;
        return ps_detail->packets_list[pos]->to_json();
    }

    std::future<std::vector<IfaceInfo>> interfaces_get_info() {
        return std::async(std::launch::async, [&]() {
            std::vector<IfaceInfo> ret;
            auto pipe = UniStreamDualPipeU(DUMPCAP_PATH " -M -D");
            std::string json_str = pipe.read_until_eof();
            rapidjson::Document doc;
            doc.Parse(json_str.c_str(), json_str.size());

            if (doc.HasParseError() || !doc.IsArray()) {
                LOG_F(ERROR, "ERROR: Get interfaces info failed!");
                return ret;
            }

            for (auto &i : doc.GetArray()) {
                IfaceInfo info;
                if (i.IsObject() && i.MemberCount()) {
                    info.name = i.MemberBegin()->name.GetString();
                    rapidjson::Value &val = i.MemberBegin()->value;
                    if (val.IsObject()) {
                        if (val.HasMember("friendly_name") &&
                            val["friendly_name"].IsString()) {
                            info.friendly_name =
                                val["friendly_name"].GetString();
                        }
                        if (val.HasMember("type") && val["type"].IsNumber()) {
                            info.type = static_cast<InterfaceType>(
                                val["type"].GetInt());
                        }
                        if (val.HasMember("addrs") && val["addrs"].IsArray()) {
                            for (auto &p : val["addrs"].GetArray()) {
                                info.addrs.push_back(p.GetString());
                            }
                        }
                    }
                }
                ret.push_back(info);
            }

            return ret;
        });
    }

    std::future<bool> interfaces_activity_monitor_start() {
        return statistics_thread.start();
    }

    std::future<bool> interfaces_activity_monitor_stop() {
        return statistics_thread.stop();
    }

    bool interfaces_activity_monitor_is_running() {
        return statistics_thread.operating_status();
    }

    std::unordered_map<std::string, uint32_t>
    interfaces_activity_monitor_read() {
        return statistics_thread.read();
    }
};
