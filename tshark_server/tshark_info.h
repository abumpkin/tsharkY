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
#include <functional>
#include <memory>
#include <pugixml.hpp>
#include <stdexcept>
#include <string>
#include <unordered_map>
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

template <typename Derived>
struct TsharkDataObj {
    rapidjson::Value to_json_obj(rapidjson::MemoryPoolAllocator<> &) const {
        throw std::runtime_error("method not implement.");
    }

    std::string to_json(bool pretty = false) const {
        rapidjson::MemoryPoolAllocator<> allocator;
        rapidjson::Value json_obj =
            static_cast<const Derived *>(this)->to_json_obj(allocator);
        return utils_to_json(json_obj, pretty);
    }
};

struct IfaceInfo : TsharkDataObj<IfaceInfo> {
    std::string name;
    std::string friendly_name;
    std::vector<std::string> addrs;
    InterfaceType type;

    rapidjson::Value to_json_obj(
        rapidjson::MemoryPoolAllocator<> &allocator) const {
        rapidjson::Value json_obj;
        json_obj.SetObject();
        json_obj.AddMember(
            "name", rapidjson::Value(name.c_str(), name.size()), allocator);
        json_obj.AddMember("friendly_name",
            rapidjson::Value(friendly_name.c_str(), friendly_name.size()),
            allocator);
        rapidjson::Value json_addrs;
        json_addrs.SetArray();
        for (auto &i : addrs) {
            json_addrs.PushBack(
                rapidjson::Value(i.c_str(), i.size()), allocator);
        }
        json_obj.AddMember("addrs", json_addrs, allocator);
        json_obj.AddMember("type",
            rapidjson::Value(InterfaceTypeToString(type), allocator),
            allocator);
        return json_obj;
    }
};

struct PacketDefineDecode : TsharkDataObj<PacketDefineDecode> {
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

    using PacketObj = std::vector<Field>;

    // private:
    PacketObj packet;
    // uint32_t frame_number = 0;

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
        obj.AddMember("name",
            rapidjson::Value(field.name.c_str(), field.name.size()), allocator);
        obj.AddMember("showname",
            rapidjson::Value(field.showname.c_str(), field.showname.size()),
            allocator);
        obj.AddMember("pos", field.pos, allocator);
        obj.AddMember("size", field.size, allocator);
        for (auto const &i : field.fields) {
            fields.PushBack(build_json_obj(allocator, i), allocator);
        }
        obj.AddMember("fields", fields, allocator);
        return obj;
    }

    std::vector<PacketDefineDecode::Field> fill_fields(pugi::xml_node p) {
        std::vector<PacketDefineDecode::Field> fields;
        pugi::xml_node cur = p;
        pugi::xml_attribute x_attr;
        do {
            PacketDefineDecode::Field x_field;
            x_attr = cur.attribute("name");
            if (x_attr) x_field.name = x_attr.value();
            if (x_field.name == "geninfo" || x_field.name == "frame") continue;
            x_attr = cur.attribute("showname");
            if (x_attr)
                x_field.showname = FieldTranslator.trans(x_attr.value());
            // if (x_attr)
            //     x_field.showname = x_attr.value();
            x_attr = cur.attribute("show");
            if (x_attr) {
                if (x_field.showname.empty()) x_field.showname = x_attr.value();
                if (x_field.name.empty()) x_field.name = x_attr.value();
                // x_field.show = x_attr.value();
                // if (x_field.name == "frame.number")
                //     frame_number = std::stoul(x_attr.value());
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

    rapidjson::Value to_json_obj(
        rapidjson::MemoryPoolAllocator<> &allocator) const {
        rapidjson::Value json_obj;
        json_obj.SetArray();
        for (auto const &i : packet) {
            json_obj.PushBack(build_json_obj(allocator, i), allocator);
        }
        return json_obj;
    }
};

struct Packet : TsharkDataObj<Packet> {
    enum IP_PROTO_CODE : uint8_t {
        UNKNOWN = 0,
        ICMP = 1,
        IGMP = 2,
        TCP = 6,
        UDP = 17,
        GRE = 47,
        ESP = 50,
        AH = 51,
        EIGRP = 88,
        OSPF = 89,
        SCTP = 132
    };

    inline static const char *get_ip_proto_str(IP_PROTO_CODE const &code) {
        static const std::unordered_map<IP_PROTO_CODE, const char *>
            ipProtoMap = {{ICMP, "ICMP"}, {IGMP, "IGMP"}, {TCP, "TCP"},
                {UDP, "UDP"}, {GRE, "GRE"}, {ESP, "ESP"}, {AH, "AH"},
                {EIGRP, "EIGRP"}, {OSPF, "OSPF"}, {SCTP, "SCTP"}};
        if (ipProtoMap.count(code)) {
            return ipProtoMap.find(code)->second;
        }
        return nullptr;
    }

    inline static IP_PROTO_CODE get_ip_proto_code(const char *code) {
        static const std::unordered_map<std::string, IP_PROTO_CODE> ipProtoMap =
            {{"ICMP", ICMP}, {"IGMP", IGMP}, {"TCP", TCP}, {"UDP", UDP},
                {"GRE", GRE}, {"ESP", ESP}, {"AH", AH}, {"EIGRP", EIGRP},
                {"OSPF", OSPF}, {"SCTP", SCTP}};
        if (ipProtoMap.count(code)) {
            return ipProtoMap.find(code)->second;
        }
        return UNKNOWN;
    }

    uint32_t idx;
    uint32_t sess_idx;
    uint32_t cap_off;
    uint32_t cap_len;
    // uint32_t frame_number;
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
    // 传输层协议号
    IP_PROTO_CODE ip_proto_code;

    std::unique_ptr<std::vector<char>> data;
    std::shared_ptr<std::vector<char>> fixed;

    rapidjson::Value to_json_obj(
        rapidjson::MemoryPoolAllocator<> &allocator) const {
        rapidjson::Value pkt_obj;
        pkt_obj.SetObject();
        pkt_obj.AddMember("idx", idx, allocator);
        // pkt_obj.AddMember("frame_number", frame_number, allocator);
        std::string time = utils_convert_timestamp(frame_timestamp);
        pkt_obj.AddMember("frame_timestamp",
            rapidjson::Value(time.c_str(), allocator), allocator);
        pkt_obj.AddMember("frame_protocol",
            rapidjson::Value(frame_protocol.c_str(), frame_protocol.size()),
            allocator);
        pkt_obj.AddMember("frame_info",
            rapidjson::Value(frame_info.c_str(), frame_info.size()), allocator);
        pkt_obj.AddMember("src_location",
            rapidjson::Value(src_location.c_str(), src_location.size()),
            allocator);
        pkt_obj.AddMember("dst_location",
            rapidjson::Value(dst_location.c_str(), dst_location.size()),
            allocator);
        pkt_obj.AddMember("src_mac",
            rapidjson::Value(src_mac.c_str(), src_mac.size()), allocator);
        pkt_obj.AddMember("dst_mac",
            rapidjson::Value(dst_mac.c_str(), dst_mac.size()), allocator);
        pkt_obj.AddMember("src_ip",
            rapidjson::Value(src_ip.c_str(), src_ip.size()), allocator);
        pkt_obj.AddMember("dst_ip",
            rapidjson::Value(dst_ip.c_str(), dst_ip.size()), allocator);
        pkt_obj.AddMember("src_port", src_port, allocator);
        pkt_obj.AddMember("dst_port", dst_port, allocator);
        return pkt_obj;
    }
};

struct Session {
    uint32_t session_id;
    std::string ip1;
    std::string ip2;
    std::string ip1_location;
    std::string ip2_location;
    uint16_t ip1_port;
    uint16_t ip2_port;
    Packet::IP_PROTO_CODE trans_proto;
    double start_time;
    double end_time;
    std::string app_proto;
    uint32_t ip1_send_packets; // ip1发送的数据包数
    uint32_t ip2_send_packets; // ip2发送的数据包数
    uint32_t ip1_send_bytes;   // ip1发送的字节数
    uint32_t ip2_send_bytes;   // ip2发送的字节数
    uint32_t packet_count;     // 数据包数量
    uint32_t total_bytes;      // 总字节数、

    private:
    Session() = default;

    public:
    static std::shared_ptr<Session> create(Packet &packet);
    static std::shared_ptr<Session> create() {
        return std::make_shared<Session>(Session());
    }

    void update(Packet &packet) {
        packet.sess_idx = session_id;
        end_time = std::stod(packet.frame_timestamp);
        if (packet.frame_protocol != "TCP" && packet.frame_protocol != "UDP") {
            app_proto = packet.frame_protocol;
        }
        if (ip1 == packet.src_ip) {
            ip1_send_packets++;
            ip1_send_bytes += packet.cap_len;
        }
        else {
            ip2_send_packets++;
            ip2_send_bytes += packet.cap_len;
        }
        packet_count++;
        total_bytes += packet.cap_len;
    }

    rapidjson::Value to_json_obj(
        rapidjson::MemoryPoolAllocator<> &allocator) const {
        rapidjson::Value ret;
        ret.SetObject();
        ret.AddMember("session_id", session_id, allocator);
        ret.AddMember(
            "ip1", rapidjson::Value(ip1.c_str(), ip1.size()), allocator);
        ret.AddMember(
            "ip2", rapidjson::Value(ip2.c_str(), ip2.size()), allocator);
        ret.AddMember("ip1_location",
            rapidjson::Value(ip1_location.c_str(), ip1_location.size()),
            allocator);
        ret.AddMember("ip2_location",
            rapidjson::Value(ip2_location.c_str(), ip2_location.size()),
            allocator);
        ret.AddMember("ip1_port", ip1_port, allocator);
        ret.AddMember("ip2_port", ip2_port, allocator);
        ret.AddMember("trans_proto",
            rapidjson::Value(Packet::get_ip_proto_str(trans_proto), allocator),
            allocator);
        ret.AddMember("start_time",
            rapidjson::Value(
                utils_convert_timestamp(std::to_string(start_time)).c_str(),
                allocator),
            allocator);
        ret.AddMember("end_time",
            rapidjson::Value(
                utils_convert_timestamp(std::to_string(end_time)).c_str(),
                allocator),
            allocator);
        ret.AddMember("app_proto",
            rapidjson::Value(app_proto.c_str(), app_proto.size()), allocator);
        ret.AddMember("ip1_send_packets_count", ip1_send_packets, allocator);
        ret.AddMember("ip1_send_bytes_count", ip1_send_bytes, allocator);
        ret.AddMember("ip2_send_packets_count", ip2_send_packets, allocator);
        ret.AddMember("ip2_send_bytes_count", ip2_send_bytes, allocator);
        ret.AddMember("packet_count", packet_count, allocator);
        ret.AddMember("total_bytes", total_bytes, allocator);
        return ret;
    }
};

namespace std {
    template <>
    struct hash<std::shared_ptr<Session>> {
        std::size_t operator()(const std::shared_ptr<Session> &key) const {
            std::hash<std::string> hashFn;
            auto hash1 = hashFn(key->ip1) + key->ip1_port;
            auto hash2 = hashFn(key->ip2) + key->ip2_port;
            return hash1 ^ hash2;
        }
    };

    template <>
    struct equal_to<shared_ptr<Session>> {
        bool operator()(const std::shared_ptr<Session> &lhs,
            const std::shared_ptr<Session> &rhs) const {
            bool ret = ((lhs->ip1 == rhs->ip1 && lhs->ip2 == rhs->ip2 &&
                            lhs->ip1_port == rhs->ip1_port &&
                            lhs->ip2_port == rhs->ip2_port) ||
                           (lhs->ip1 == rhs->ip2 && lhs->ip2 == rhs->ip1 &&
                               lhs->ip1_port == rhs->ip2_port &&
                               lhs->ip2_port == rhs->ip1_port)) &&
                       lhs->trans_proto == rhs->trans_proto;
            return ret;
        }
    };
}

inline std::shared_ptr<Session> Session::create(Packet &packet) {
    std::shared_ptr<Session> ret = std::make_shared<Session>(Session());
    ret->ip1 = packet.src_ip;
    ret->ip2 = packet.dst_ip;
    ret->ip1_location = packet.src_location;
    ret->ip2_location = packet.dst_location;
    ret->ip1_port = packet.src_port;
    ret->ip2_port = packet.dst_port;
    ret->trans_proto = packet.ip_proto_code;
    ret->start_time = std::stod(packet.frame_timestamp);
    return ret;
}

inline const char *get_proto_description(std::string &proto) {
    static std::unordered_map<std::string, const char *> map = {
        {"TCP", "传输控制协议，构建在IP之上，提供可靠、有序、无差错的数据传输，"
                "并具备流量与拥塞控制能力。"},
        {"UDP", "用户数据报协议，面向无连接，传输速度快但不保证可靠性，适用于实"
                "时应用和少量数据传输。"},
        {"HTTP", "超文本传输协议，常用于浏览器与服务器之间的网页数据传输，基于"
                 "请求-响应模式进行通信。"},
        {"HTTPS", "加密版HTTP，通过TLS或SSL建立安全信道，保护传输数据的完整性与"
                  "机密性，广泛用于网站登录与支付。"},
        {"DNS", "域名系统协议，用于将域名解析为IP地址，支持正向解析与反向解析，"
                "维护互联网主机命名体系。"},
        {"TLS", "传输层安全协议，为应用层数据提供加密与完整性校验，通常用于HTTP"
                "S等场景确保通信安全。"},
        {"SSL", "安全套接字层协议，TLS "
                "的前身，曾被广泛用于加密数据传输，现多被TLS替代但在部分场景仍"
                "可见。"},
        {"ARP", "地址解析协议，用于在局域网中通过IP地址获取对应的MAC地址，在以"
                "太网环境下尤为重要。"},
        {"ICMP", "互联网控制报文协议，传输差错与控制信息，例如ping和traceroute"
                 "等诊断工具依赖其回显与报文功能。"},
        {"DHCP", "动态主机配置协议，用于自动分配IP地址、网关、DNS等网络配置信息"
                 "，大幅简化网络管理。"},
        {"FTP", "文件传输协议，使用TCP作为底层协议，可在客户端与服务器之间进行"
                "文件的上传与下载操作。"},
        {"SSH", "安全外壳协议，为远程登录与其他网络服务提供安全加密通道，常用于"
                "替代Telnet进行安全操作。"},
        {"Telnet", "早期的远程登录协议，缺乏加密，通信内容明文传输，已逐渐被SSH"
                   "等更安全的协议取代。"},
        {"SMTP", "简单邮件传输协议，用于在邮件服务器之间或邮件客户端与服务器之"
                 "间发送电子邮件。"},
        {"POP", "邮局协议，用户从邮件服务器获取邮件后默认会将其本地化，常见版本"
                "为POP3，使用简单且高效。"},
        {"IMAP", "Internet邮件访问协议，支持在服务器端管理邮件，客户端可与服务"
                 "器保持同步并进行多文件夹操作。"},
        {"LDAP", "轻量级目录访问协议，主要用于查询和修改目录服务信息，常见于企"
                 "业级用户/权限管理系统。"},
        {"NTP", "网络时间协议，通过UDP实现的时间同步服务，保证各网络设备间时间"
                "的一致性。"},
        {"SNMP", "简单网络管理协议，用于集中监控和管理网络设备，常收集设备CPU、"
                 "内存、接口流量等信息。"},
        {"RIP", "路由信息协议，距离矢量路由协议的一种，使用跳数作为路由度量，适"
                "用于小规模网络环境。"},
        {"OSPF", "开放最短路径优先协议，链路状态路由协议之一，支持大型网络和区"
                 "域划分，收敛速度快。"},
        {"BGP", "边界网关协议，用于跨自治系统（AS）间的路由信息交换，是互联网的"
                "核心路由协议。"},
        {"PPTP", "点对点隧道协议，基于PPP封装的数据隧道技术之一，常用于VPN连接"
                 "但安全性较弱。"},
        {"L2TP", "第二层隧道协议，与IPSec结合使用时可提供更安全的VPN隧道，广泛"
                 "应用于远程访问场景。"},
        {"GRE", "通用路由封装协议，用于在不同网络之间封装各类第三层协议，常见于"
                "隧道与VPN场景。"},
        {"IPsec", "IP安全协议套件，通过加密与认证保障IP层数据的机密性与完整性，"
                  "多用于VPN部署与安全通信。"},
        {"SCTP", "流控制传输协议，面向消息传输，支持多宿主与多流，常在电信及实"
                 "时信令传输场景使用。"},
        {"RTSP", "实时流协议，适合控制多媒体流传输，常与RTP/"
                 "RTCP配合使用，实现点播与直播功能。"},
        {"RTP", "实时传输协议，用于在网络上传输音视频流，结合RTCP进行传输质量控"
                "制，常见于会议系统。"},
        {"RTCP", "实时传输控制协议，与RTP协作用于监控传输质量、统计QoS等，为流"
                 "媒体传输提供反馈机制。"},
        {"TFTP", "简单文件传输协议，基于UDP，通常用于在网络设备中传输配置文件或"
                 "在PXE启动过程中下载镜像。"},
        {"Gopher", "一种早期的文档检索与发布协议，使用分层菜单结构访问信息资源"
                   "，在万维网发展后逐渐式微。"},
        {"TLSv1", "TLS协议的一个早期版本，提供数据加密与完整性校验，兼容性与安"
                  "全性兼顾。"},
        {"TLSv1.2", "TLS协议的一个较常用版本，提供数据加密与完整性校验，兼容性"
                    "与安全性兼顾。"},
        {"TLSv1.3", "TLS协议的最新主流版本，引入零RTT握手与更安全的加密套件，提"
                    "升网络通信的效率与安全性。"},
        {"QUIC", "谷歌提出的基于UDP的传输协议，集成TLS加密，提升HTTP/"
                 "3等应用在弱网络环境下的性能表现。"},
        {"RADIUS", "远程身份验证拨号用户服务，采用UDP封装，集中管理网络用户的认"
                   "证、授权与计费信息。"},
        {"Diameter", "RADIUS "
                     "的升级版，提供更丰富的消息与扩展特性，常用于电信运营商计"
                     "费、认证与策略控制。"},
        {"NetBIOS", "网络基本输入输出系统，为局域网内计算机提供名字解析与会话服"
                    "务，常见于Windows网络。"},
        {"SMB", "服务器消息块协议，用于在Windows网络中共享文件、打印机和其他资"
                "源，也称CIFS。"},
        {"CIFS", "通用Internet文件系统，SMB协议的前期版本，主要用于远程文件访问"
                 "与资源共享。"},
        {"Kerberos", "网络身份认证协议，使用对称密钥与票据机制，为客户端与服务"
                     "器之间的通信提供安全验证。"},
        {"Syslog", "系统日志协议，以UDP或TCP为传输方式，将设备或系统的日志消息"
                   "集中发送到日志服务器进行记录。"},
        {"MQTT", "消息队列遥测传输协议，基于发布/"
                 "订阅模型，适合物联网等低带宽、高延迟或不稳定网络环境。"},
        {"CoAP", "受限应用协议，专为资源受限的物联网设备设计，基于UDP并采用REST"
                 "风格的交互方式。"},
        {"AMQP", "高级消息队列协议，提供消息中间件功能，支持可靠消息传递与灵活"
                 "的路由机制。"},
        {"SOAP", "简单对象访问协议，以XML格式封装的远程调用协议，在Web服务中曾"
                 "被广泛采用。"},
        {"WSDL", "Web服务描述语言，用于描述SOAP "
                 "Web服务的接口、消息格式与访问地址，基于XML进行定义。"},
        {"XML-RPC", "基于HTTP和XML的远程过程调用协议，使用简单的请求-"
                    "响应模型，早期Web服务通信的一种实现。"},
        {"JSON-RPC", "轻量级的远程过程调用协议，用JSON格式封装数据，基于HTTP或"
                     "其他传输层实现跨平台调用。"},
        {"WebSocket", "全双工通信协议，基于HTTP握手，可在浏览器与服务器之间建立"
                      "持续的双向消息通道。"},
        {"SPDY", "由谷歌提出的实验性协议，优化HTTP传输效率，通过多路复用与压缩"
                 "等手段减少网络延迟。"},
        {"HTTP/2", "HTTP协议的升级版本，引入二进制分帧、多路复用与头部压缩，为"
                   "网站加快加载速度。"},
        {"HTTP/3", "基于QUIC的下一代HTTP协议，支持快速握手与更高效的流控制，在"
                   "弱网络环境下表现更佳。"},
        {"DoH", "DNS over "
                "HTTPS，通过HTTPS加密域名解析请求，防止DNS查询被窃听或篡改，提"
                "高隐私与安全。"},
        {"DoT", "DNS over "
                "TLS，基于TLS加密DNS流量，保护解析请求不被截获或篡改，是传统DNS"
                "的安全增强方案。"},
        {"SRTP", "安全实时传输协议，在RTP的基础上增加加密与认证，用于保护音视频"
                 "流免受窃听或篡改。"},
        {"MGCP", "媒体网关控制协议，早期VoIP场景下的集中式呼叫控制协议，用于呼"
                 "叫代理与网关之间的通信。"},
        {"H.323", "ITU-"
                  "T制定的多媒体通信标准，包含呼叫信令、媒体协商和传输等子协议"
                  "，早期视频会议的主流。"},
        {"SIP", "会话发起协议，主要用于IP网络中的语音、视频通话及即时消息，定义"
                "呼叫建立与终止流程。"},
        {"SCCP", "Signaling Connection Control "
                 "Part，常用于Cisco的呼叫管理系统，与VoIP中的呼叫信令相关。"},
        {"IKE", "互联网密钥交换协议，为IPsec提供自动密钥协商与安全策略管理，确"
                "保VPN的加密可靠性。"},
        {"ISAKMP", "互联网安全协会和密钥管理协议，定义了IPsec中用于建立安全关联"
                   "(SA)的框架与消息格式。"},
        {"FCoE", "以太网上的光纤通道协议，将光纤通道帧封装在以太网中传输，整合"
                 "存储网络与以太网络。"},
        {"FibreChannel", "光纤通道协议，用于在专用存储区域网络（SAN）中提供高速"
                         "、低延迟的数据块传输。"},
        {"AoE", "ATA over "
                "Ethernet，将ATA协议封装在以太网中，简化存储网络部署，适合本地"
                "局域环境。"},
        {"iSCSI", "基于IP的SCSI封装协议，通过TCP/"
                  "IP网络传输存储指令，广泛用于服务器与存储设备交互。"},
        {"EIGRP", "增强型内部网关路由协议，Cisco私有的高级距离矢量协议，具有快"
                  "速收敛与低带宽占用特点。"},
        {"HSRP", "热备份路由协议，Cisco私有协议，实现网关冗余，确保网关故障时网"
                 "络客户端仍可正常访问。"},
        {"VRRP", "虚拟路由冗余协议，与HSRP类似但为开放标准协议，多台路由器通过"
                 "选举方式实现网关冗余。"},
        {"GLBP", "网关负载均衡协议，Cisco私有协议，可在多台路由器之间负载均衡流"
                 "量，同时提供冗余能力。"},
        {"LLDP", "链路层发现协议，允许网络设备互相通告自身信息，如设备标识、端"
                 "口信息，方便网络拓扑管理。"},
        {"CDP", "Cisco发现协议，Cisco设备间专用，用于发现相邻设备信息，协助网络"
                "管理员进行拓扑规划。"},
        {"STP", "生成树协议，为以太网生成无环拓扑，防止交换网络出现二层环路，保"
                "护网络稳定性。"},
        {"RSTP", "快速生成树协议，STP的改进版本，通过更快的收敛机制减少生成树重"
                 "计算造成的网络中断时间。"},
        {"MSTP", "多生成树协议，允许在一个网络中维护多条逻辑生成树，充分利用链"
                 "路资源进行负载分担。"},
        {"VLAN", "虚拟局域网技术，通过划分广播域提高网络灵活性与安全性，可在三"
                 "层或二层交换机上配置。"},
        {"QinQ", "双层 VLAN 封装技术，将一个 VLAN Tag 封装在另一个 VLAN Tag "
                 "中，适用于运营商级二层转发。"},
        {"PPP", "点对点协议，常用于串行链路或拨号连接，提供链路配置、鉴权及错误"
                "检测等功能。"},
        {"PPPoE", "以太网上的PPP协议，广泛应用于ADSL或光纤入户宽带拨号，通过PPP"
                  "oE会话建立IP连接。"},
        {"LCP", "链路控制协议，PPP "
                "框架的一部分，用于建立、配置和测试数据链路连接的有效性。"},
        {"NCP", "网络控制协议，PPP协议族中的一部分，负责为不同网络层协议（如IP"
                "、IPX）配置和协商参数。"},
        {"HDLC", "高级数据链路控制协议，面向比特的同步通信协议，常用于点对点或"
                 "帧中继链路承载。"},
        {"FrameRelay", "早期的分组交换技术，基于虚电路提供连接管理，曾在广域网"
                       "构建中得到广泛应用。"},
        {"X.25", "一种面向连接的分组交换协议，历史悠久，支持错误纠正与流量控制"
                 "，早期广域网主流方案。"},
        {"GTP", "GPRS隧道协议，移动通信网络中承载用户数据平面与控制平面流量，关"
                "键于2G/3G/4G核心网。"},
        {"GTPv2", "GTP协议的改进版本，用于4G "
                  "LTE核心网，优化了控制平面流程与承载建立效率。"},
        {"MMS", "多媒体消息服务，移动通信中用于发送图片、音频、视频等富媒体内容"
                "，基于WAP或数据通道。"},
        {"MMS-Encap", "MMS "
                      "在网络上所使用的封装协议形式，Wireshark可对其进行解析，"
                      "显示MMS消息结构。"},
        {"WAP", "无线应用协议，为移动设备提供网络浏览、消息等服务，曾在功能机时"
                "代广泛使用。"},
        {"BGP EVPN", "BGP扩展，结合EVPN提供二层VPN服务，通过BGP传递MAC/"
                     "IP绑定信息，简化数据中心互联。"},
        {"VXLAN", "虚拟可扩展局域网，通过UDP在三层网络构建二层覆盖隧道，支持更"
                  "大规模的数据中心组网。"},
        {"Geneve", "通用可扩展隧道封装协议，与VXLAN类似但扩展性更强，支持自定义"
                   "元数据，便于网络虚拟化。"},
        {"OTV", "Overlay Transport "
                "Virtualization，Cisco技术，通过在三层网络上构建二层覆盖，实现"
                "跨数据中心二层互联。"},
        {"LISP", "位置标识分离协议，将端点标识与位置信息分离，简化地址分配并加"
                 "速路由收敛。"},
        {"VPLS", "虚拟专用LAN服务，在运营商网络上创建面向用户的二层VPN，所有站"
                 "点共享同一个广播域。"},
        {"MPLS", "多协议标签交换，介于第二层和第三层之间，通过标签转发快速传输I"
                 "P、以太网等多种协议。"},
        {"RSVP", "资源预留协议，为IP网络提供资源预留与服务质量保障，通过信令在"
                 "路径上建立带宽预留。"},
        {"LDP", "标签分发协议，MPLS网络中的基础协议，用于在路由器间分发标签信息"
                "以建立标签转发路径。"},
        {"TE", "流量工程(traffic "
               "engineering)，可基于RSVP-TE或CR-"
               "LDP等协议，为网络流量分配最佳路径。"},
        {"BFD", "双向转发检测协议，用于快速检测两端之间通信链路的可达性，提升故"
                "障探测与收敛速度。"},
        {"QUIC", "一种基于UDP的传输协议，集成加密与多路复用，减少握手延迟，对HT"
                 "TP/3具有重要意义。"},
        {"BitTorrent", "分布式文件共享协议，用户通过P2P网络下载资源，大幅提升大"
                       "文件传输效率。"},
        {"MDNS", "多播DNS协议，在局域网内提供名称解析及设备发现功能，无需外部DN"
                 "S服务器。"},
        {"LLMNR", "链路本地多播名称解析协议，主要用于Windows环境，在局域网内解"
                  "析主机名，无需传统DNS。"},
        {"X11", "一种图形窗口系统协议，可在网络环境中运行远程图形界面，常用于Li"
                "nux/Unix平台。"},
        {"NBNS", "NetBIOS名称服务，通过广播/"
                 "多播方式解析主机名与IP地址，常见于早期Windows网络。"},
        {"STUN", "主要用于帮助终端设备在存在网络地址转换（NAT）和防火墙的情况下"
                 "，获取并识别自身在外部网络中的公共IP地址和端口"},
        {"SSDP", "简单服务发现协议（Simple Service Discovery Protocol）是 "
                 "UPnP架构中的一部分，用于在局域网中自动发现设备与服务。"},
        {"DTLS",
            "基于 UDP实现的 TLS协议变体。它为无连接、不可靠的传输提供安全特性"},
        {"DTLSv1.2",
            "基于 UDP实现的 TLS协议变体。它为无连接、不可靠的传输提供安全特性"},
        {"DTLSv1.3", "基于 UDP实现的 "
                     "TLS协议变体。它为无连接、不可靠的传输提供安全特性"}};
    if (map.count(proto)) {
        return map[proto];
    }
    return nullptr;
}