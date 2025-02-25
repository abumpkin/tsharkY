/**
 * @file tshark_manager.h
 * @author abumpkin (forwardslash@foxmail.com)
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
#include "boost/filesystem/operations.hpp"
#include "boost/filesystem/path.hpp"
#include "mutils.h"
#include "traffic_statistics.h"
#include "tshark_info.h"
#include "unistream.h"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <functional>
#include <future>
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
    enum class PKT_TREATMENT {
        PKT_DROP,
        PKT_SAVE,
        PKT_ERROR
    };
    using PacketHandler = std::function<PKT_TREATMENT(std::shared_ptr<Packet>)>;

    protected:
    volatile std::atomic_bool stop_ctl = false;
    struct CMD_Fields {
        char const *frame_number = "frame.number";
        char const *frame_timestamp = "frame.time_epoch";
        char const *frame_protocol = "_ws.col.Protocol";
        char const *frame_info = "_ws.col.Info";
        char const *eth_src = "eth.src";
        char const *eth_dst = "eth.dst";
        char const *ip_src = "ip.src";
        char const *ip_dst = "ip.dst";
        char const *ipv6_src = "ipv6.src";
        char const *ipv6_dst = "ipv6.dst";
        char const *udp_port = "udp.port";
        char const *tcp_port = "tcp.port";
    };
    constexpr static const uint32_t CMD_FIELD_NUM =
        sizeof(CMD_Fields) / sizeof(char const *);

    static PKT_TREATMENT pkt_pase_routine(std::string const &info,
        std::shared_ptr<Packet> packet, PacketHandler handler) {
        std::vector<std::string> fields;
        CMD_Fields cmd_field;
        fields = utils_split_str(info, "\t");
        if (fields.size() < CMD_FIELD_NUM) {
            return PKT_TREATMENT::PKT_ERROR;
        }
        for (uint32_t i = 0; i < CMD_FIELD_NUM; i++) {
            reinterpret_cast<char const **>(&cmd_field)[i] = "";
            if (i < fields.size())
                reinterpret_cast<char const **>(&cmd_field)[i] =
                    fields[i].c_str();
        }

        // frame
        packet->frame_number = strlen(cmd_field.frame_number)
                                   ? std::stoi(cmd_field.frame_number)
                                   : 0;
        packet->frame_timestamp = cmd_field.frame_timestamp;
        packet->frame_protocol = cmd_field.frame_protocol;
        packet->frame_info = cmd_field.frame_info;
        // MAC
        packet->src_mac = cmd_field.eth_src;
        packet->dst_mac = cmd_field.eth_dst;
        // IP
        packet->src_ip =
            strlen(cmd_field.ip_src) ? cmd_field.ip_src : cmd_field.ipv6_src;
        packet->dst_ip =
            strlen(cmd_field.ip_dst) ? cmd_field.ip_dst : cmd_field.ipv6_dst;
        // 端口
        std::string src_dst_port = strlen(cmd_field.tcp_port)
                                       ? cmd_field.tcp_port
                                       : cmd_field.udp_port;
        if (!src_dst_port.empty()) {
            std::vector<std::string> ports = utils_split_str(src_dst_port, ",");
            if (ports.size() == 2) {
                packet->src_port = static_cast<uint16_t>(std::stoi(ports[0]));
                packet->dst_port = static_cast<uint16_t>(std::stoi(ports[1]));
            }
        }
        // 归属地
        packet->src_location = utils_ip2region(packet->src_ip);
        packet->dst_location = utils_ip2region(packet->dst_ip);

        // 其他处理
        if (handler) {
            return handler(packet);
        }
        return PKT_TREATMENT::PKT_SAVE;
    }

    static std::shared_ptr<UniStreamInterface> create_parser_stream() {
        CMD_Fields cmd_field;
        std::vector<std::string> cmd_args = {
            TSHARK_PATH " -Q -l -r - -T fields"};
        for (uint32_t i = 0; i < CMD_FIELD_NUM; i++) {
            cmd_args.push_back("-e");
            cmd_args.push_back(reinterpret_cast<char const **>(&cmd_field)[i]);
        }
        auto parser = std::make_shared<UniStreamPipeUnblocked>(
            utils_join_str(cmd_args, " "));
        return parser;
    }

    public:
    SharkLoader() = default;
    SharkLoader(SharkLoader &) = delete;
    SharkLoader &operator=(SharkLoader &) = delete;
    SharkLoader(SharkLoader &&) = delete;
    SharkLoader &operator=(SharkLoader &&) = delete;
    std::vector<char> fixed_data;
    std::vector<std::shared_ptr<Packet>> packets_list;
    std::unordered_map<uint32_t, std::shared_ptr<Packet>> packets;

    virtual bool load(
        std::shared_ptr<UniStreamInterface>, PacketHandler = nullptr) {
        stop_ctl = false;
        return false;
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

    virtual bool load(std::shared_ptr<UniStreamInterface> stream,
        PacketHandler handler = nullptr) override {
        SharkLoader::load(stream, handler);
        auto parser_stream = create_parser_stream();
        auto bin_stream = UniSyncR2W::Make(stream, parser_stream);
        GeneralHeader section;
        EnhancedPacketBlockHeader packet_section;
        char *p_section = reinterpret_cast<char *>(&section);
        uint32_t rd_len;
        bool right_format = false;
        std::future<uint32_t> read_len;
        while (true) {
            read_len = bin_stream->read_async(p_section, sizeof(section));
            do {
                if (stop_ctl) {
                    bin_stream->close_read();
                    return false;
                }
            } while (read_len.wait_for(std::chrono::milliseconds(100)) ==
                     std::future_status::timeout);
            rd_len = read_len.get();
            if (!rd_len) return false;
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
                    return false;
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
                return false;
            }
            if (section.block_type == 0x00000006) {
                std::shared_ptr<Packet> pkt = std::make_shared<Packet>();
                packet_section.block_info = section;
                rd_len = bin_stream->read(
                    reinterpret_cast<char *>(&packet_section.interface_id),
                    sizeof(EnhancedPacketBlockHeader) - sizeof(GeneralHeader));
                if (!rd_len) {
                    LOG_F(ERROR, "pcapng wrong format");
                    return false;
                }
                pkt->frame_offset = bin_stream->read_offset();
                pkt->frame_caplen = packet_section.captured_packet_length;
                rd_len = pkt->load_data(bin_stream, pkt->frame_caplen);
                int64_t tail_size =
                    static_cast<uint64_t>(section.block_length) -
                    sizeof(EnhancedPacketBlockHeader) - pkt->frame_caplen;
                if (tail_size < 0) {
                    LOG_F(ERROR, "pcapng wrong format");
                    return false;
                }
                rd_len = bin_stream->read_to_null(tail_size);
                if (!rd_len) {
                    LOG_F(ERROR, "pcapng wrong format");
                    return false;
                }
                std::string explain = parser_stream->read_until('\n');
                PKT_TREATMENT stat = pkt_pase_routine(explain, pkt, handler);
                if (stat == PKT_TREATMENT::PKT_ERROR) {
                    LOG_F(ERROR, "ERROR: packet parse failure.");
                    return false;
                }
                if (stat == PKT_TREATMENT::PKT_SAVE) {
                    packets_list.push_back(pkt);
                    packets.emplace(pkt->frame_number, pkt);
                }
                continue;
            }
            rd_len = bin_stream->read_to_null(
                section.block_length - sizeof(GeneralHeader));
            if (!rd_len) {
                LOG_F(ERROR, "pcapng wrong format");
                return false;
            }
        }
        return true;
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

    virtual bool load(std::shared_ptr<UniStreamInterface> stream,
        PacketHandler handler = nullptr) override {
        SharkLoader::load(stream, handler);
        auto parser_stream = create_parser_stream();
        auto bin_stream = UniSyncR2W::Make(stream, parser_stream);
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
            return false;
        }
        uint32_t rd_len;
        std::future<uint32_t> read_len;
        while (true) {
            read_len =
                bin_stream->read_async(p_section, sizeof(PcapPacketHeader));
            do {
                if (stop_ctl) {
                    bin_stream->close_read();
                    return false;
                }
            } while (read_len.wait_for(std::chrono::milliseconds(100)) ==
                     std::future_status::timeout);
            rd_len = read_len.get();
            if (!rd_len) return false;

            std::shared_ptr<Packet> pkt = std::make_shared<Packet>();
            pkt->frame_offset = bin_stream->read_offset();
            pkt->frame_caplen = section.caplen;
            rd_len = pkt->load_data(bin_stream, pkt->frame_caplen);
            if (rd_len != pkt->frame_caplen) {
                LOG_F(ERROR, "pcapng wrong format");
                return false;
            }
            std::string explain = parser_stream->read_until('\n');
            PKT_TREATMENT stat = pkt_pase_routine(explain, pkt, handler);
            if (stat == PKT_TREATMENT::PKT_ERROR) {
                LOG_F(ERROR, "ERROR: packet parse failure.");
                return false;
            }
            if (stat == PKT_TREATMENT::PKT_SAVE) {
                packets_list.push_back(pkt);
                packets.emplace(pkt->frame_number, pkt);
            }
        }
        return true;
    }
};

struct SharkCaptureThread {
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

    bool load_capture_file(boost::filesystem::path path) {
        std::string ext = path.extension().generic_string();
        utils_str_lowcase(ext);
        if (!boost::filesystem::exists(path)) {
            LOG_F(ERROR, "ERROR: (%s) File not exists.",
                boost::filesystem::absolute(path).c_str());
            return false;
        }
        if (ext == ".pcap") {
            loader = std::make_shared<SharkPcapLoader>();
        }
        else if (ext == ".pcapng") {
            loader = std::make_shared<SharkPcapngLoader>();
        }
        else {
            LOG_F(ERROR, "ERROR: (%s) Unkown file format. (%s)", ext.c_str(),
                boost::filesystem::absolute(path).c_str());
            return false;
        }
        auto stream = std::make_shared<UniStreamFile>(path.generic_string());
        loader->load(stream);
        return true;
    }

    bool start_capture_blocked(boost::filesystem::path save_to = "",
        SharkLoader::PacketHandler handler = nullptr,
        std::string if_name = "") {
        std::shared_ptr<UniStreamInterface> stream;
        std::string cmd = DUMPCAP_PATH " -Q -w -";
        if (!if_name.empty()) {
            cmd += " -i " + if_name;
        }
        if (!save_to.empty()) {
            save_to = utils_test_valid_filename(save_to);
            if (save_to.empty()) {
                LOG_F(ERROR, "ERROR: (%s) Path to write is not valid.",
                    save_to.c_str());
                return false;
            }
            std::string ext = save_to.extension().generic_string();
            if (ext == ".pcap") {
                loader = std::make_shared<SharkPcapLoader>();
                cmd += " -F pcap";
            }
            else if (ext == ".pcapng") {
                loader = std::make_shared<SharkPcapngLoader>();
            }
            else {
                LOG_F(ERROR,
                    "ERROR: (%s) Please specify a supported save format. "
                    "\".pcap\" or \".pcapng\".",
                    save_to.c_str());
                return false;
            }
            if (boost::filesystem::exists(save_to)) {
                LOG_F(WARNING,
                    "WARING: (%s) File has been exists. Deleted now!",
                    save_to.c_str());
                boost::filesystem::remove(save_to);
            }
            if (!boost::filesystem::exists(save_to.parent_path())) {
                boost::filesystem::create_directories(save_to.parent_path());
            }
            stream = UniSyncR2W::Make(std::make_shared<UniStreamPipe>(cmd),
                std::make_shared<UniStreamFile>(
                    save_to.generic_string(), std::ios::trunc));
        }
        if (!loader) {
            loader = std::make_shared<SharkPcapngLoader>();
        }
        if (!stream) {
            stream = std::make_shared<UniStreamPipe>(cmd);
        }
        loader->load(stream, handler);
        return true;
    }

    std::future<bool> start_capture(boost::filesystem::path save_to = "",
        SharkLoader::PacketHandler handler = nullptr,
        std::string const &if_name = "") {
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
            ret = start_status.get_future();
        }
        t_t = std::make_unique<std::thread>(
            thread, this, save_to, handler, if_name);
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

    static void thread(SharkCaptureThread *const tobj,
        boost::filesystem::path save_to = "",
        SharkLoader::PacketHandler handler = nullptr,
        std::string if_name = "") {
        {
            std::lock_guard<std::mutex> lock(tobj->t_m);
            tobj->is_capturing = true;
            tobj->start_status.set_value(true);
        }
        tobj->is_done_with_succeed =
            tobj->start_capture_blocked(save_to, handler, if_name);
        {
            std::lock_guard<std::mutex> lock(tobj->t_m);
            tobj->is_capturing = false;
            tobj->stop_status.set_value_at_thread_exit(true);
        }
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
    std::condition_variable ctl_cv;
    std::mutex ctl_m;

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

    std::future<bool> capture_start(boost::filesystem::path save_to = "",
        SharkLoader::PacketHandler handler = nullptr,
        std::string const &if_name = "") {
        return capture_thread.start_capture(save_to, handler, if_name);
    }

    std::future<bool> capture_stop() {
        return capture_thread.stop_capture();
    }

    std::future<std::weak_ptr<SharkLoader>> capture_from_file(
        boost::filesystem::path path) {
        return std::async(
            std::launch::async, [&]() -> std::weak_ptr<SharkLoader> {
                capture_thread.load_capture_file(path);
                return capture_thread.loader;
            });
    }

    std::future<bool> capture_is_running() {
        return std::async(std::launch::deferred, [&]() {
            return capture_thread.capturing_status();
        });
    }

    std::future<std::vector<IfaceInfo>> interfaces_get_info() {
        return std::async(std::launch::async, [&]() {
            std::vector<IfaceInfo> ret;
            auto pipe = UniStreamPipe(DUMPCAP_PATH " -M -D");
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

    std::future<bool> interfaces_activity_monitor_is_running() {
        return std::async(std::launch::deferred, [&]() {
            return statistics_thread.operating_status();
        });
    }

    std::future<std::unordered_map<std::string, uint32_t>>
    interfaces_activity_monitor_read() {
        return std::async(std::launch::deferred, [&]() {
            return statistics_thread.read();
        });
    }
};
