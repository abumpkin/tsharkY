/**
 * @file tshark_info.h
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
#include "mutils.h"
#include "rapidjson/allocators.h"
#include "rapidjson/document.h"
#include "tinyxml2.h"
#include "unistream.h"
#include <cstdint>
#include <string>
#include <vector>
#ifndef TSHARK_PATH
#define TSHARK_PATH "tshark"
#endif
#ifndef DUMPCAP_PATH
#define DUMPCAP_PATH "dumpcap"
#endif

// 网络接口类型枚举
enum class InterfaceType : int {
    Unknown = 0,    // 通用或虚拟接口 (如 any, lo, nflog, nfqueue, dbus)
    Ethernet = 1,   // 以太网
    TokenRing = 2,  // Token Ring
    Bluetooth = 4,  // 蓝牙
    WiFi = 5,       // 802.11 无线网络
    FrameRelay = 6, // Frame Relay
    ATM = 7,        // ATM (Asynchronous Transfer Mode)
    PPP = 8,        // 点对点协议 (PPP)
    SLIP = 9,       // SLIP 协议
    EthernetLinkAggregation = 11, // 802.3ad 链路聚合
    Zigbee = 12                   // 802.15 (例如 Zigbee)
};

// 将接口类型转换为字符串
inline const char *InterfaceTypeToString(InterfaceType type) {
    switch (type) {
    case InterfaceType::Unknown:
        return "Unknown (Virtual or Generic Interface)";
    case InterfaceType::Ethernet:
        return "Ethernet";
    case InterfaceType::TokenRing:
        return "Token Ring";
    case InterfaceType::Bluetooth:
        return "Bluetooth";
    case InterfaceType::WiFi:
        return "Wi-Fi";
    case InterfaceType::FrameRelay:
        return "Frame Relay";
    case InterfaceType::ATM:
        return "ATM";
    case InterfaceType::PPP:
        return "PPP";
    case InterfaceType::SLIP:
        return "SLIP";
    case InterfaceType::EthernetLinkAggregation:
        return "Ethernet Link Aggregation";
    case InterfaceType::Zigbee:
        return "Zigbee";
    default:
        return "Unknown";
    }
}


struct IfaceInfo {
    std::string name;
    std::string friendly_name;
    std::vector<std::string> addrs;
    InterfaceType type;
};


struct PacketDefineDecode {
    struct Field {
        std::string name;
        std::string showname;
        // std::string value;
        uint32_t pos;
        uint32_t size;
        // std::shared_ptr<std::vector<char>> data;
        std::vector<Field> fields;
    };

    using Packet = std::vector<Field>;

    private:
    Packet packet;

    static std::vector<PacketDefineDecode::Field> fill_fields(
        tinyxml2::XMLElement *p) {
        std::vector<PacketDefineDecode::Field> fields;
        tinyxml2::XMLElement *cur = p;
        tinyxml2::XMLAttribute const *x_attr;
        do {
            PacketDefineDecode::Field x_field;
            x_attr = cur->FindAttribute("name");
            if (x_attr) x_field.name = x_attr->Value();
            x_attr = cur->FindAttribute("showname");
            if (x_attr) x_field.showname = x_attr->Value();
            x_attr = cur->FindAttribute("show");
            if (x_attr) {
                if (x_field.showname.empty())
                    x_field.showname = x_attr->Value();
                if (x_field.name.empty()) x_field.name = x_attr->Value();
            }
            x_attr = cur->FindAttribute("pos");
            if (x_attr) x_field.pos = x_attr->UnsignedValue();
            x_attr = cur->FindAttribute("size");
            if (x_attr) x_field.size = x_attr->UnsignedValue();

            if (cur->FirstChildElement()) {
                x_field.fields = fill_fields(cur->FirstChildElement());
            }
            fields.push_back(x_field);
        } while ((cur = cur->NextSiblingElement()));
        return fields;
    }

    static std::vector<char> hex_to_data(char const *hex) {
        uint32_t len = strlen(hex);
        std::vector<char> ret;
        uint32_t i = 0;
        const char v[128] = {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0-9 (非打印字符)
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 10-19
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 20-29
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 30-39
            0, 0, 0, 0, 0, 0, 0, 0,       // 40-47
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, // 48-57 ('0'-'9')
            0, 0, 0, 0, 0, 0, 0,          // 58-64
            10, 11, 12, 13, 14, 15,       // 65-70 ('A'-'F')
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 71-80
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 81-90
            0, 0, 0, 0, 0, 0,             // 91-96
            10, 11, 12, 13, 14, 15,       // 97-102 ('a'-'f')
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 103-112
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 113-122
            0, 0, 0, 0, 0                 // 123-126
        };
        uint8_t c = 0;
        if (len % 2) ret.push_back(v[(uint8_t)hex[i++]]);
        while (i < len) {
            c = v[(uint8_t)hex[i++]] << 4;
            c = v[(uint8_t)hex[i++]] | c;
            ret.push_back(c);
        }
        return ret;
    }

    static rapidjson::Value build_json_obj(
        rapidjson::MemoryPoolAllocator<> &allocator, Field const &field) {
        rapidjson::Value obj;
        rapidjson::Value fields;
        fields.SetArray();
        obj.SetObject();
        obj.AddMember(
            "name", rapidjson::Value(field.name.c_str(), allocator), allocator);
        obj.AddMember("showname",
            rapidjson::Value(field.showname.c_str(), allocator), allocator);
        obj.AddMember("pos", field.pos, allocator);
        obj.AddMember("size", field.size, allocator);
        for (auto const &i : field.fields) {
            fields.PushBack(build_json_obj(allocator, i), allocator);
        }
        obj.AddMember("fields", fields, allocator);
        return obj;
    }

    rapidjson::Value to_json_obj(rapidjson::MemoryPoolAllocator<> &allocator) {
        rapidjson::Value json_obj;
        json_obj.SetArray();
        for (auto const &i : packet) {
            json_obj.PushBack(build_json_obj(allocator, i), allocator);
        }
        return json_obj;
    }

    public:
    PacketDefineDecode(std::string const &xml) {
        tinyxml2::XMLDocument doc;
        doc.Parse(xml.c_str());
        tinyxml2::XMLElement *x_packet = doc.RootElement();
        while (x_packet) {
            if (x_packet->Name() == std::string("packet")) break;
            x_packet = x_packet->FirstChildElement();
        }
        while (x_packet) {
            packet = fill_fields(x_packet->FirstChildElement());
            x_packet = x_packet->NextSiblingElement("packet");
            if (packet.size()) break;
        }
    }

    std::string to_json(bool pretty = false) {
        rapidjson::MemoryPoolAllocator<> allocator;
        rapidjson::Value json_obj = to_json_obj(allocator);
        return utils_to_json(json_obj, pretty);
    }
};

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
        return utils_to_json(json_obj, pretty);
    }
};