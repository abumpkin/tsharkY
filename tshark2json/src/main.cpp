#include "mutils.h"
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <ios>
#include <iostream>
#include <string>
#include <tuple>
#include <vector>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

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

struct Packet {
    uint32_t frame_number;
    uint32_t frame_offset;
    uint32_t frame_caplen;
    std::string time;
    std::string src_ip;
    uint16_t src_port;
    std::string dst_ip;
    uint16_t dst_port;
    std::string protocol;
    std::string info;
};


std::vector<Packet> load_pcap_data(std::string const &path) {
    std::vector<Packet> packets;
    std::vector<std::tuple<uint32_t, uint32_t>> offset_len;
    std::fstream pcap_data = std::fstream(path, std::ios::binary | std::ios::in);
    PcapHeader pcap_header;
    PcapPacketHeader pcap_pkt;
    pcap_data.read(reinterpret_cast<char*>(&pcap_header), sizeof(PcapHeader));
    if (pcap_header.magic_number != 0xa1b2c3d4) {
        pcap_data.close();
        return packets;
    }
    while (!pcap_data.eof()) {
        pcap_data.read(reinterpret_cast<char*>(&pcap_pkt), sizeof(PcapPacketHeader));
        int64_t pos = static_cast<int64_t>(pcap_data.tellg());
        if (pos == -1)
            break;
        offset_len.emplace_back(static_cast<uint32_t>(pos), pcap_pkt.caplen);
        pcap_data.seekg(pos + pcap_pkt.caplen, std::ios::beg);
    }
    pcap_data.close();

    struct {
        char const *frame_number = " -e frame.number";
        char const *frame_time = " -e frame.time";
        char const *ip_src = " -e ip.src";
        char const *ip_dst = " -e ip.dst";
        char const *ipv6_src = " -e ipv6.src";
        char const *ipv6_dst = " -e ipv6.dst";
        char const *protocol = " -e _ws.col.Protocol";
        char const *info = " -e _ws.col.Info";
        char const *udp_port = " -e udp.port";
        char const *tcp_port = " -e tcp.port";
    } cmd_field;
    constexpr uint32_t cmd_field_size = sizeof(cmd_field) / sizeof(char const*);
    std::string cmd = "tshark -r " + path + " -T fields";
    for (uint32_t i = 0; i < cmd_field_size; i++) {
        cmd += reinterpret_cast<char const**>(&cmd_field)[i];
    }

    std::vector<std::string> lines = utils_split_str(utils_exec_cmd(cmd), "\n");
    for (auto &line : lines) {
        Packet packet = {};
        std::vector<std::string> fields;

        if (line.empty()) continue;
        fields = utils_split_str(line, "\t");
        for (uint32_t i = 0; i < cmd_field_size; i++) {
            reinterpret_cast<char const**>(&cmd_field)[i] = "";
            if (i < fields.size())
                reinterpret_cast<char const**>(&cmd_field)[i] = fields[i].c_str();
        }

        packet.frame_number = strlen(cmd_field.frame_number) ? std::stoi(cmd_field.frame_number) : 0;
        packet.time = cmd_field.frame_time;
        packet.src_ip = strlen(cmd_field.ip_src) ? cmd_field.ip_src : cmd_field.ipv6_src;
        packet.dst_ip = strlen(cmd_field.ip_dst) ? cmd_field.ip_dst : cmd_field.ipv6_dst;
        packet.protocol = cmd_field.protocol;
        packet.info = cmd_field.info;
        // 端口
        std::string src_dst_port = strlen(cmd_field.tcp_port) ? cmd_field.tcp_port : cmd_field.udp_port;
        if (!src_dst_port.empty()) {
            std::vector<std::string> ports = utils_split_str(src_dst_port, ",");
            if (ports.size() == 2) {
                packet.src_port = static_cast<uint16_t>(std::stoi(ports[0]));
                packet.src_port = static_cast<uint16_t>(std::stoi(ports[1]));
            }
        }

        if (packet.frame_number <= offset_len.size()) {
            auto [offset, caplen] = offset_len[packet.frame_number - 1];
            packet.frame_offset = offset;
            packet.frame_caplen = caplen;
        }
        packets.push_back(packet);
    }

    return packets;
}

std::vector<char> const read_raw_packet_data(std::string const &path, Packet const &packet) {
    std::vector<char> ret;
    std::fstream pcap_data = std::fstream(path, std::ios::binary | std::ios::in);
    if (packet.frame_caplen) {
        ret.resize(packet.frame_caplen);
        pcap_data.seekg(packet.frame_offset, std::ios::beg);
        pcap_data.read(ret.data(), packet.frame_caplen);
    }
    pcap_data.close();
    return ret;
}

std::string const get_json_string(rapidjson::Value const &obj) {
    rapidjson::StringBuffer json_data;
    rapidjson::Writer<rapidjson::StringBuffer> writer = rapidjson::Writer(json_data);
    obj.Accept(writer);
    return json_data.GetString();
}

int32_t main() {
    std::string data_path = "dump_data/capture.pcap";
    std::vector<Packet> packets = load_pcap_data(data_path);
    rapidjson::Document pkts_obj;
    rapidjson::Document::AllocatorType &allocator = pkts_obj.GetAllocator();
    pkts_obj.SetArray();
    for (auto &p : packets) {
        rapidjson::Document pkt_obj;
        pkt_obj.SetObject();
        pkt_obj.AddMember("frame_number", p.frame_number, allocator);
        pkt_obj.AddMember("frame_offset", p.frame_offset, allocator);
        pkt_obj.AddMember("frame_caplen", p.frame_caplen, allocator);
        pkt_obj.AddMember("timestamp", rapidjson::Value(p.time.c_str(), allocator), allocator);
        pkt_obj.AddMember("src_ip", rapidjson::Value(p.src_ip.c_str(), allocator), allocator);
        pkt_obj.AddMember("src_port", p.src_port, allocator);
        pkt_obj.AddMember("dst_ip", rapidjson::Value(p.dst_ip.c_str(), allocator), allocator);
        pkt_obj.AddMember("dst_port", p.dst_port, allocator);
        pkt_obj.AddMember("info", rapidjson::Value(p.info.c_str(), allocator), allocator);

        pkts_obj.PushBack(pkt_obj, allocator);

        std::cout << get_json_string(pkts_obj[pkts_obj.Size() - 1]) << std::endl;
        std::cout << "Packet Data: " << utils_data_to_hex(read_raw_packet_data(data_path, p)) << std::endl << std::endl;
    }
    // std::cout << get_json_string(pkts_obj);
    return 0;
}