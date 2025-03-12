#include "boost/filesystem/operations.hpp"
#include "boost/filesystem/path.hpp"
#include "mutils.h"
#include "parser_stream.h"
#include "tinyxml2.h"
#include "tshark_info.h"
#include "tshark_manager.h"
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <ostream>
#include <string>
#include <traffic_statistics.h>
#include <unistream.h>
#include <unordered_map>
#include <utility>
#include <vector>


bool load(std::shared_ptr<UniStreamInterface> bin_stream,
    std::unordered_map<uint32_t, std::pair<uint32_t, uint32_t>> &ret) {
    SharkPcapLoader::PcapPacketHeader section;
    char *p_section = reinterpret_cast<char *>(&section);
    SharkPcapLoader::PcapHeader pcap_header;
    auto frame_number = std::make_shared<UniStreamPipeUnblocked>(
        "tshark -Q -l -r - -T fields -e frame.number");
    bin_stream = UniSyncR2W::Make(bin_stream, frame_number);
    bin_stream->read((char *)&pcap_header, sizeof(SharkPcapLoader::PcapHeader));
    if (pcap_header.magic_number != 0xa1b23c4d &&
        pcap_header.magic_number != 0xa1b2c3d4) {
        return false;
    }
    uint32_t rd_len;
    // std::vector<char> buf;
    while (true) {
        rd_len = bin_stream->read(
            p_section, sizeof(SharkPcapLoader::PcapPacketHeader));
        if (!rd_len) break;

        uint32_t cap_off;
        cap_off = bin_stream->read_offset();
        rd_len = bin_stream->read_to_null(section.caplen);
        ret.emplace(std::stoul(frame_number->read_until('\n')),
            std::pair<uint32_t, uint32_t>{cap_off, section.caplen});
        if (rd_len != section.caplen) {
            return false;
        }
    }
    bin_stream->close_read();
    return true;
}

void print_hex(char *data, uint32_t len) {
    std::string ret;
    char hex[] = "0123456789ABCDEF";
    uint32_t t;
    if (len) {
        for (uint32_t i = 0; i < len; i++) {
            t = static_cast<uint8_t>(data[i]);
            ret.append(1, hex[t / 16]);
            ret.append(1, hex[t % 16]);
            if (i < len - 1) {
                ret.append(" ");
            }
        }
    }
    std::cout << ret << std::endl;
}

int main() {
    boost::filesystem::path path = "dump_data/big.pcap";
    std::unordered_map<uint32_t, std::shared_ptr<PacketDefineDecode>> packets;
    std::unordered_map<uint32_t, std::pair<uint32_t, uint32_t>> packets_offset;
    std::string temp = "data.pdml";
    std::cout << "输入要分析的文件路径：";
    // std::cin >> path;
    path = boost::filesystem::absolute(path);
    // 导出 data.pdml
    {
        utils_timer js;
        std::cout << "获取二进制包偏移..." << std::flush;
        load(std::make_shared<UniStreamFile>(path.generic_string()),
            packets_offset);
        std::cout << "完成" << std::endl;
    }
    std::cout << "包数量: " << packets_offset.size() << std::endl;
    {
        utils_timer js;
        std::cout << "转换为 pdml...";
        auto writer = UniSyncR2W::Make(
            std::make_shared<UniStreamPipe>(
                "tshark -Q -l -T pdml -r " + path.generic_string()),
            std::make_shared<UniStreamFile>(temp, std::ios::trunc));
        while (writer->read_to_null(512))
            ;
        writer->close_read();
        std::cout << "完成" << std::endl;
    }
    {
        utils_timer js;
        std::cout << "解析 pdml..." << std::flush;
        UniStreamFile pdml(temp);
        std::shared_ptr<PacketDefineDecode> packet_def;
        while (!pdml.eof()) {
            std::string xml, line;
            bool f = false;
            while (!pdml.eof()) {
                line = pdml.read_until('\n');
                if (line.find("<packet>") != std::string::npos) f = true;
                if (f) xml.append(line);
                if (line.find("</packet>") != std::string::npos) break;
            }
            if (pdml.eof()) break;
            packet_def = std::make_shared<PacketDefineDecode>(xml);
            // 保存
            packets.emplace(packet_def->frame_number, packet_def);
            // std::cout << packet_def->frame_number << std::endl;
        }
        std::cout << "完成" << std::endl;
    }
    std::cout << "包数量: " << packets.size() << std::endl;

    uint32_t frn;
    std::ifstream f(path.generic_string());
    while (true) {
        std::cout << "输入要查询的编号: " << std::flush;
        std::cin >> frn;
        if (packets.count(frn))
            std::cout << packets[frn]->to_json(true) << std::endl;
        if (packets_offset.count(frn)) {
            char *data = new char[packets_offset[frn].second];
            f.seekg(packets_offset[frn].first, std::ios::beg);
            f.read(data, packets_offset[frn].second);
            print_hex(data, packets_offset[frn].second);
            delete[] data;
        }
    }
    return 0;
}