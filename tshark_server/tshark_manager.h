#pragma once
#include "boost/filesystem/operations.hpp"
#include "boost/filesystem/path.hpp"
#include "mutils.h"
#include "rapidjson/allocators.h"
#include "unistream.h"
#include <cstdint>
#include <cstring>
#include <functional>
#include <loguru.hpp>
#include <memory>
#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <string>
#include <unordered_map>
#include <vector>

struct TSharkManager;

struct Packet {
    uint32_t frame_number;
    uint32_t frame_offset;
    uint32_t frame_caplen;
    std::string frame_timestamp;
    std::string frame_protocol;
    std::string frame_info;
    std::string src_location;
    std::string dst_location;
    std::string src_mac;
    std::string dst_mac;
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    std::string data;

    uint32_t load_data(
        std::shared_ptr<UniStreamInterface> stream, uint32_t len) {
        char buf[512];
        uint32_t rd = 0, ret = 0;
        while (!stream->read_eof() && ret < len) {
            rd = len - ret;
            if (rd > sizeof(buf)) rd = sizeof(buf);
            rd = stream->read(buf, rd);
            if (rd) data.append(buf, rd);
            ret += rd;
        }
        return ret;
    }

    rapidjson::Value to_json_obj(rapidjson::MemoryPoolAllocator<> &allocator) {
        rapidjson::Value pkt_obj;
        pkt_obj.SetObject();
        pkt_obj.AddMember("frame_number", frame_number, allocator);
        pkt_obj.AddMember("frame_offset", frame_offset, allocator);
        pkt_obj.AddMember("frame_caplen", frame_caplen, allocator);
        pkt_obj.AddMember("frame_timestamp",
            rapidjson::Value(frame_timestamp.c_str(), allocator), allocator);
        pkt_obj.AddMember("frame_protocol",
            rapidjson::Value(frame_protocol.c_str(), allocator), allocator);
        pkt_obj.AddMember("frame_info",
            rapidjson::Value(frame_info.c_str(), allocator), allocator);
        pkt_obj.AddMember("src_location",
            rapidjson::Value(src_location.c_str(), allocator), allocator);
        pkt_obj.AddMember("dst_location",
            rapidjson::Value(dst_location.c_str(), allocator), allocator);
        pkt_obj.AddMember(
            "src_mac", rapidjson::Value(src_mac.c_str(), allocator), allocator);
        pkt_obj.AddMember(
            "dst_mac", rapidjson::Value(dst_mac.c_str(), allocator), allocator);
        pkt_obj.AddMember(
            "src_ip", rapidjson::Value(src_ip.c_str(), allocator), allocator);
        pkt_obj.AddMember(
            "dst_ip", rapidjson::Value(dst_ip.c_str(), allocator), allocator);
        pkt_obj.AddMember("src_port", src_port, allocator);
        pkt_obj.AddMember("dst_port", dst_port, allocator);
        return pkt_obj;
    }

    std::string to_json(bool pretty = false) {
        rapidjson::MemoryPoolAllocator<> allocator;
        rapidjson::Value json_obj = to_json_obj(allocator);
        rapidjson::StringBuffer json_data;
        std::string ret;
        if (pretty) {
            rapidjson::PrettyWriter<rapidjson::StringBuffer> writer =
                rapidjson::PrettyWriter(json_data);
            json_obj.Accept(writer);
            ret = json_data.GetString();
        }
        else {
            rapidjson::Writer<rapidjson::StringBuffer> writer =
                rapidjson::Writer(json_data);
            json_obj.Accept(writer);
            ret = json_data.GetString();
        }
        return ret;
    }
};

struct SharkLoader {
    protected:
    friend TSharkManager;
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
    using PacketHandler = std::function<void(std::shared_ptr<Packet>)>;
    constexpr static const uint32_t CMD_FIELD_NUM =
        sizeof(CMD_Fields) / sizeof(char const *);

    static bool parse_fields(std::string const &info,
        std::shared_ptr<Packet> packet, PacketHandler handler) {
        std::vector<std::string> fields;
        CMD_Fields cmd_field;
        fields = utils_split_str(info, "\t");
        if (fields.size() < CMD_FIELD_NUM) {
            return false;
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
            handler(packet);
        }
        return true;
    }

    static std::shared_ptr<UniStreamInterface> create_parser_stream() {
        CMD_Fields cmd_field;
        std::vector<std::string> cmd_args = {"tshark -Q -l -r - -T fields"};
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
    SharkLoader(SharkLoader &&) = default;
    SharkLoader &operator=(SharkLoader &&) = default;
    std::vector<char> fixed_data;
    std::vector<std::shared_ptr<Packet>> packets_list;
    std::unordered_map<uint32_t, std::shared_ptr<Packet>> packets;

    virtual bool load(std::shared_ptr<UniStreamInterface> stream,
        PacketHandler handler = nullptr) = 0;
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

    bool load(std::shared_ptr<UniStreamInterface> stream,
        PacketHandler handler = nullptr) override {
        auto parser_stream = create_parser_stream();
        auto bin_stream = UniSyncR2W::Make(stream, parser_stream);
        GeneralHeader section;
        EnhancedPacketBlockHeader packet_section;
        char *p_section = reinterpret_cast<char *>(&section);
        uint32_t rd_len;
        bool right_fomat = false;
        while (bin_stream->read(p_section, sizeof(section))) {
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
                right_fomat = true;
                continue;
            }
            if (!right_fomat) {
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
                std::string explain = parser_stream->read_util('\n');
                if (!parse_fields(explain, pkt, handler)) {
                    LOG_F(ERROR, "ERROR: packet parse failure.");
                    return false;
                }
                packets_list.push_back(pkt);
                packets.emplace(pkt->frame_number, pkt);
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

    bool load(std::shared_ptr<UniStreamInterface> stream,
        PacketHandler handler = nullptr) override {
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
        while (bin_stream->read(p_section, sizeof(PcapPacketHeader))) {
            std::shared_ptr<Packet> pkt = std::make_shared<Packet>();
            pkt->frame_offset = bin_stream->read_offset();
            pkt->frame_caplen = section.caplen;
            rd_len = pkt->load_data(bin_stream, pkt->frame_caplen);
            if (rd_len != pkt->frame_caplen) {
                LOG_F(ERROR, "pcapng wrong format");
                return false;
            }
            std::string explain = parser_stream->read_util('\n');
            if (!parse_fields(explain, pkt, handler)) {
                LOG_F(ERROR, "ERROR: packet parse failure.");
                return false;
            }
            packets_list.push_back(pkt);
            packets.emplace(pkt->frame_number, pkt);
        }
        return true;
    }
};

struct TSharkManager {
    std::unique_ptr<SharkLoader> loader;

    TSharkManager() {}

    bool load_capture_file(boost::filesystem::path path) {
        std::string ext = path.extension().generic_string();
        utils_str_lowcase(ext);
        if (!boost::filesystem::exists(path)) {
            LOG_F(ERROR, "ERROR: (%s) File not exists.",
                boost::filesystem::absolute(path).c_str());
            return false;
        }
        if (ext == ".pcap") {
            loader = std::make_unique<SharkPcapLoader>();
        }
        else if (ext == ".pcapng") {
            loader = std::make_unique<SharkPcapngLoader>();
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

    // TODO: 线程运行，notify() 通知进行线程管理。
    bool start_capture(boost::filesystem::path save_to = "",
        SharkLoader::PacketHandler handler = nullptr) {
        std::shared_ptr<UniStreamInterface> stream;
        std::string cmd = "dumpcap -Q -w -";
        if (!save_to.empty()) {
            save_to = utils_test_valid_filename(save_to);
            if (save_to.empty()) {
                LOG_F(ERROR, "ERROR: (%s) Path to write is not valid.",
                    save_to.c_str());
                return false;
            }
            std::string ext = save_to.extension().generic_string();
            if (ext == ".pcap") {
                loader = std::make_unique<SharkPcapLoader>();
                cmd += " -F pcap";
            }
            else if (ext == ".pcapng") {
                loader = std::make_unique<SharkPcapngLoader>();
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
            loader = std::make_unique<SharkPcapngLoader>();
        }
        if (!stream) {
            stream = std::make_shared<UniStreamPipe>(cmd);
        }
        loader->load(stream, handler);
        return true;
    }
};
