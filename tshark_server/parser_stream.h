/**
 * @file parser_stream.h
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

#include "mutils.h"
#include "tshark_info.h"
#include "unistream.h"
#include <cstdint>
#include <map>
#include <memory>
#include <stdexcept>
#include <vector>
struct ParserStream : virtual UniStreamInterface {
    ParserStream() = default;
    ParserStream(ParserStream &) = delete;
    ParserStream &operator=(ParserStream &) = delete;
    virtual void packet_arrived(std::vector<char> const &fixed,
        std::vector<char> const &block, uint32_t cap_off,
        uint32_t cap_len) noexcept(false) = 0;
};

struct PacketBriefParserStream : ParserStream, UniStreamPipeUnblocked {
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
    using PacketHandler = std::function<void(std::shared_ptr<Packet>)>;
    std::vector<std::shared_ptr<Packet>> packets_list;
    std::map<uint32_t, std::shared_ptr<Packet>> packets;

    PacketHandler handler;

    PacketBriefParserStream() = delete;
    PacketBriefParserStream(std::string const &cmd)
        : UniStreamPipeUnblocked(cmd) {}
    PacketBriefParserStream(PacketHandler handler = nullptr) {
        CMD_Fields cmd_field;
        std::vector<std::string> cmd_args = {
            TSHARK_PATH " -Q -l -r - -T fields"};
        for (uint32_t i = 0; i < CMD_FIELD_NUM; i++) {
            cmd_args.push_back("-e");
            cmd_args.push_back(reinterpret_cast<char const **>(&cmd_field)[i]);
        }
        new (this)(PacketBriefParserStream)(utils_join_str(cmd_args, " "));
        this->handler = handler;
    }

    virtual void packet_arrived(std::vector<char> const &fixed,
        std::vector<char> const &block, uint32_t cap_off,
        uint32_t cap_len) override {
        std::string explain = read_until('\n');
        std::vector<std::string> fields;
        CMD_Fields cmd_field;
        std::shared_ptr<Packet> packet = std::make_shared<Packet>();
        fields = utils_split_str(explain, "\t");
        if (fields.size() < CMD_FIELD_NUM)
            throw std::runtime_error("parser error");
        for (uint32_t i = 0; i < CMD_FIELD_NUM; i++) {
            reinterpret_cast<char const **>(&cmd_field)[i] = "";
            if (i < fields.size())
                reinterpret_cast<char const **>(&cmd_field)[i] =
                    fields[i].c_str();
        }

        // 包数据 data
        packet->data = std::string(
            block.data() + cap_off, block.data() + cap_off + cap_len);
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

        // 保存
        packets_list.push_back(packet);
        packets.insert_or_assign(packet->frame_number, packet);
        // 其他处理
        if (handler) {
            handler(packet);
        }
    }
};
