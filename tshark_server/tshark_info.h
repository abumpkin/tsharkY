/**
 * @file tshark_info.h
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
#include "rapidjson/allocators.h"
#include "rapidjson/document.h"
#include <cstdint>
#include <string>
#include <vector>
#include <pugixml.hpp>
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

inline std::unordered_map<std::string, std::string> PacketTransDict = {
    {"General information", "常规信息"}, {"Frame Number", "帧编号"},
    {"Captured Length", "捕获长度"}, {"Captured Time", "捕获时间"},
    {"Section number", "节号"}, {"Interface id", "接口 id"},
    {"Interface name", "接口名称"}, {"Encapsulation type", "封装类型"},
    {"Arrival Time", "到达时间"}, {"UTC Arrival Time", "UTC到达时间"},
    {"Epoch Arrival Time", "纪元到达时间"},
    {"Time shift for this packet", "该数据包的时间偏移"},
    {"Time delta from previous captured frame", "与上一个捕获帧的时间差"},
    {"Time delta from previous displayed frame", "与上一个显示帧的时间差"},
    {"Time since reference or first frame", "自参考帧或第一帧以来的时间"},
    {"Frame Number", "帧编号"}, {"Frame Length", "帧长度"},
    {"Capture Length", "捕获长度"}, {"Frame is marked", "帧标记"},
    {"Frame is ignored", "帧忽略"}, {"Frame", "帧"},
    {"Protocols in frame", "帧中的协议"}, {"Ethernet II", "以太网 II"},
    {"Destination", "目的地址"},
    {"Address Resolution Protocol", "ARP地址解析地址"},
    {"Address (resolved)", "地址（解析后）"}, {"Type", "类型"},
    {"Stream index", "流索引"},
    {"Internet Protocol Version 4", "互联网协议版本 4"},
    {"Internet Protocol Version 6", "互联网协议版本 6"},
    {"Internet Control Message Protocol", "互联网控制消息协议ICMP"},
    {"Version", "版本"}, {"Header Length", "头部长度"},
    {"Differentiated Services Field", "差分服务字段"},
    {"Total Length", "总长度"}, {"Identification", "标识符"}, {"Flags", "标志"},
    {"Time to Live", "生存时间"},
    {"Transmission Control Protocol", "TCP传输控制协议"},
    {"User Datagram Protocol", "UDP用户数据包协议"},
    {"Domain Name System", "DNS域名解析系统"},
    {"Header Checksum", "头部校验和"}, {"Header checksum status", "校验和状态"},
    {"Source Address", "源地址"}, {"Destination Address", "目的地址"},
    {"Source Port", "源端口"}, {"Destination Port", "目的端口"},
    {"Next Sequence Number", "下一个序列号"}, {"Sequence Number", "序列号"},
    {"Acknowledgment Number", "确认号"}, {"Acknowledgment number", "确认号"},
    {"TCP Segment Len", "TCP段长度"},
    {"Conversation completeness", "会话完整性"},
    {"Window size scaling factor", "窗口缩放因子"},
    {"Calculated window size", "计算窗口大小"}, {"Window", "窗口"},
    {"Urgent Pointer", "紧急指针"}, {"Checksum:", "校验和:"},
    {"TCP Option - Maximum segment size", "TCP选项 - 最大段大小"},
    {"Kind", "种类"}, {"MSS Value", "MSS值"},
    {"TCP Option - Window scale", "TCP选项 - 窗口缩放"},
    {"Shift count", "移位计数"}, {"Multiplier", "倍数"},
    {"TCP Option - Timestamps", "TCP选项 - 时间戳"},
    {"TCP Option - SACK permitted", "TCP选项 - SACK 允许"},
    {"TCP Option - End of Option List", "TCP选项 - 选项列表结束"},
    {"Options", "选项"}, {"TCP Option - No-Operation", "TCP选项 - 无操作"},
    {"Timestamps", "时间戳"},
    {"Time since first frame in this TCP stream", "自第一帧以来的时间"},
    {"Time since previous frame in this TCP stream", "与上一个帧的时间差"},
    {"Protocol:", "协议:"}, {"Source:", "源地址:"}, {"Length:", "长度:"},
    {"Checksum status", "校验和状态"}, {"Checksum Status", "校验和状态"},
    {"TCP payload", "TCP载荷"}, {"UDP payload", "UDP载荷"},
    {"Hypertext Transfer Protocol", "超文本传输协议HTTP"},
    {"Transport Layer Security", "传输层安全协议TLS"}};

inline utils_translator3 FieldTranslator{PacketTransDict};

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
        // std::string show;
        // std::string value;
        uint32_t pos;
        uint32_t size;
        // std::shared_ptr<std::vector<char>> data;
        std::vector<Field> fields;
    };

    using Packet = std::vector<Field>;

    // private:
    Packet packet;
    uint32_t frame_number = 0;

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

    std::vector<PacketDefineDecode::Field> fill_fields(pugi::xml_node p) {
        std::vector<PacketDefineDecode::Field> fields;
        pugi::xml_node cur = p;
        pugi::xml_attribute x_attr;
        do {
            PacketDefineDecode::Field x_field;
            x_attr = cur.attribute("name");

            if (x_attr) x_field.name = x_attr.value();
            x_attr = cur.attribute("showname");
            if (x_attr)
                x_field.showname = FieldTranslator.trans(x_attr.value());
            x_attr = cur.attribute("show");
            if (x_attr) {
                if (x_field.showname.empty())
                    x_field.showname = x_attr.value();
                if (x_field.name.empty()) x_field.name = x_attr.value();
                // x_field.show = x_attr.value();
                if (x_field.name == "frame.number")
                    frame_number = std::stoul(x_attr.value());
            }
            x_attr = cur.attribute("pos");
            if (x_attr) x_field.pos = x_attr.as_uint();
            x_attr = cur.attribute("size");
            if (x_attr) x_field.size = x_attr.as_uint();

            if (cur.first_child()) {
                x_field.fields = fill_fields(cur.first_child());
            }
            fields.push_back(x_field);
        } while ((cur = cur.next_sibling()));
        return fields;
    }

    public:
    PacketDefineDecode(std::string &xml) {
        pugi::xml_document doc;
        pugi::xml_parse_result result =
            doc.load_buffer_inplace(xml.data(), xml.size());
        if (result.status != pugi::status_ok) {
            throw std::runtime_error(result.description());
        }
        pugi::xml_node x_packet = doc.child("packet");
        while (x_packet) {
            packet = fill_fields(x_packet.first_child());
            x_packet = x_packet.next_sibling("packet");
            if (packet.size()) break;
        }
    }

    std::string to_json(bool pretty = false) {
        rapidjson::MemoryPoolAllocator<> allocator;
        rapidjson::Value json_obj = to_json_obj(allocator);
        return utils_to_json(json_obj, pretty);
    }
};

// struct PacketDefineDecode {
//     struct Field {
//         std::string name;
//         std::string showname;
//         // std::string show;
//         // std::string value;
//         uint32_t pos;
//         uint32_t size;
//         // std::shared_ptr<std::vector<char>> data;
//         std::vector<Field> fields;
//     };

//     using Packet = std::vector<Field>;

//     // private:
//     Packet packet;
//     uint32_t frame_number = 0;

//     std::vector<PacketDefineDecode::Field> fill_fields(
//         tinyxml2::XMLElement *p) {
//         std::vector<PacketDefineDecode::Field> fields;
//         tinyxml2::XMLElement *cur = p;
//         tinyxml2::XMLAttribute const *x_attr;
//         do {
//             PacketDefineDecode::Field x_field;
//             x_attr = cur->FindAttribute("name");
//             if (x_attr) x_field.name = x_attr->Value();
//             x_attr = cur->FindAttribute("showname");
//             if (x_attr)
//                 x_field.showname = FieldTranslator.trans(x_attr->Value());
//             // if (x_attr) x_field.showname = x_attr->Value();
//             x_attr = cur->FindAttribute("show");
//             if (x_attr) {
//                 if (x_field.showname.empty())
//                     x_field.showname = x_attr->Value();
//                 if (x_field.name.empty()) x_field.name = x_attr->Value();
//                 // x_field.show = x_attr->Value();
//                 if (x_field.name == "frame.number")
//                     frame_number = std::stoul(x_attr->Value());
//             }
//             x_attr = cur->FindAttribute("pos");
//             if (x_attr) x_field.pos = x_attr->UnsignedValue();
//             x_attr = cur->FindAttribute("size");
//             if (x_attr) x_field.size = x_attr->UnsignedValue();

//             if (cur->FirstChildElement()) {
//                 x_field.fields = fill_fields(cur->FirstChildElement());
//             }
//             fields.push_back(x_field);
//         } while ((cur = cur->NextSiblingElement()));
//         return fields;
//     }

//     static std::vector<char> hex_to_data(char const *hex) {
//         uint32_t len = strlen(hex);
//         std::vector<char> ret;
//         uint32_t i = 0;
//         const char v[128] = {
//             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0-9 (非打印字符)
//             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 10-19
//             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 20-29
//             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 30-39
//             0, 0, 0, 0, 0, 0, 0, 0,       // 40-47
//             0, 1, 2, 3, 4, 5, 6, 7, 8, 9, // 48-57 ('0'-'9')
//             0, 0, 0, 0, 0, 0, 0,          // 58-64
//             10, 11, 12, 13, 14, 15,       // 65-70 ('A'-'F')
//             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 71-80
//             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 81-90
//             0, 0, 0, 0, 0, 0,             // 91-96
//             10, 11, 12, 13, 14, 15,       // 97-102 ('a'-'f')
//             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 103-112
//             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 113-122
//             0, 0, 0, 0, 0                 // 123-126
//         };
//         uint8_t c = 0;
//         if (len % 2) ret.push_back(v[(uint8_t)hex[i++]]);
//         while (i < len) {
//             c = v[(uint8_t)hex[i++]] << 4;
//             c = v[(uint8_t)hex[i++]] | c;
//             ret.push_back(c);
//         }
//         return ret;
//     }

//     static rapidjson::Value build_json_obj(
//         rapidjson::MemoryPoolAllocator<> &allocator, Field const &field) {
//         rapidjson::Value obj;
//         rapidjson::Value fields;
//         fields.SetArray();
//         obj.SetObject();
//         obj.AddMember(
//             "name", rapidjson::Value(field.name.c_str(), allocator), allocator);
//         obj.AddMember("showname",
//             rapidjson::Value(field.showname.c_str(), allocator), allocator);
//         obj.AddMember("pos", field.pos, allocator);
//         obj.AddMember("size", field.size, allocator);
//         for (auto const &i : field.fields) {
//             fields.PushBack(build_json_obj(allocator, i), allocator);
//         }
//         obj.AddMember("fields", fields, allocator);
//         return obj;
//     }

//     rapidjson::Value to_json_obj(rapidjson::MemoryPoolAllocator<> &allocator) {
//         rapidjson::Value json_obj;
//         json_obj.SetArray();
//         for (auto const &i : packet) {
//             json_obj.PushBack(build_json_obj(allocator, i), allocator);
//         }
//         return json_obj;
//     }

//     public:
//     PacketDefineDecode(std::string const &xml) {
//         tinyxml2::XMLDocument doc;
//         doc.Parse(xml.c_str());
//         tinyxml2::XMLElement *x_packet = doc.RootElement();
//         while (x_packet) {
//             if (x_packet->Name() == std::string("packet")) break;
//             x_packet = x_packet->FirstChildElement();
//         }
//         while (x_packet) {
//             packet = fill_fields(x_packet->FirstChildElement());
//             x_packet = x_packet->NextSiblingElement("packet");
//             if (packet.size()) break;
//         }
//     }

//     std::string to_json(bool pretty = false) {
//         rapidjson::MemoryPoolAllocator<> allocator;
//         rapidjson::Value json_obj = to_json_obj(allocator);
//         return utils_to_json(json_obj, pretty);
//     }
// };

struct Packet {
    uint32_t frame_number;
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

    rapidjson::Value to_json_obj(rapidjson::MemoryPoolAllocator<> &allocator) {
        rapidjson::Value pkt_obj;
        pkt_obj.SetObject();
        pkt_obj.AddMember("frame_number", frame_number, allocator);
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