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

#pragma once
#include "mutils.h"
#include "streambuf.h"
#include "tshark_info.h"
#include "unistream.h"
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <thread>
#include <vector>

struct ParserStream : virtual UniStreamInterface {
    ParserStream() = default;
    ParserStream(ParserStream &) = delete;
    ParserStream &operator=(ParserStream &) = delete;
    virtual void packet_arrived(std::vector<char> const &fixed,
        std::vector<char> const &block, uint32_t cap_off,
        uint32_t cap_len) noexcept(false) = 0;
    virtual void wait_done() = 0;
};

struct ParserStreamPacket : ParserStream, UniStreamDualPipeU {
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
    std::shared_ptr<std::vector<char>> fixed;
    std::vector<std::shared_ptr<Packet>> packets_list;
    std::queue<std::shared_ptr<Packet>> packets_pending;
    volatile std::atomic_bool stop_ctl;
    std::unique_ptr<std::thread> p_t;
    std::mutex t_m;

    PacketHandler handler;

    protected:
    ParserStreamPacket(std::string const &cmd) : UniStreamDualPipeU(cmd) {}

    public:
    ParserStreamPacket(PacketHandler handler = nullptr) : stop_ctl(false) {
        CMD_Fields cmd_field;
        std::vector<std::string> cmd_args = {
            TSHARK_PATH " -Q -l -r - -T fields"};
        for (uint32_t i = 0; i < CMD_FIELD_NUM; i++) {
            cmd_args.push_back("-e");
            cmd_args.push_back(reinterpret_cast<char const **>(&cmd_field)[i]);
        }
        new (this)(ParserStreamPacket)(utils_join_str(cmd_args, " "));
        this->handler = handler;
        p_t = std::make_unique<std::thread>(thread, this);
    }

    virtual void packet_arrived(std::vector<char> const &fixed,
        std::vector<char> const &block, uint32_t cap_off,
        uint32_t cap_len) override {
        std::shared_ptr<Packet> packet = std::make_shared<Packet>();
        if (!this->fixed)
            this->fixed = std::make_shared<std::vector<char>>(fixed);
        // 包数据 data
        packet->cap_len = cap_len;
        packet->cap_off = cap_off;
        packet->data = block;
        packet->fixed = this->fixed;
        // 加入待解析队列
        {
            std::lock_guard<std::mutex> lock(t_m);
            packets_pending.push(packet);
        }
    }

    virtual void wait_done() override {
        using namespace std::chrono_literals;
        if (p_t) {
            while (packets_pending.size()) {
                std::this_thread::sleep_for(1ms);
            }
        }
    }

    virtual std::string read_until(char const t) override {
        using namespace std::chrono_literals;
        char rd;
        std::stringbuf buf;
        while (!eof() && !stop_ctl) {
            if (read(&rd, 1)) {
                buf.sputc(rd);
                if (rd == t) return buf.str();
            }
            else
                std::this_thread::sleep_for(1ms);
        }
        return buf.str();
    }

    // 解析线程
    static void thread(ParserStreamPacket *p) {
        using namespace std::chrono_literals;
        std::string explain;
        StreamBuf buf;
        char data[512];
        uint32_t rd_len;
        auto read_some = [&]() {
            do {
                rd_len = p->read_ub(data, 512);
                if (rd_len) buf.write(data, rd_len);
            } while (!p->eof() && rd_len);
        };
        while (!p->eof()) {
            read_some();
            if (p->packets_pending.empty()) {
                if (p->stop_ctl) break;
                std::this_thread::sleep_for(1ms);
                continue;
            }
            std::shared_ptr<Packet> packet;
            {
                std::lock_guard<std::mutex> lock(p->t_m);
                packet = p->packets_pending.front();
                p->packets_pending.pop();
            }
            // std::string explain = p->read_until('\n');

            do {
                read_some();
                explain = buf.try_read_util('\n');
                if (!explain.empty()) break;
                std::this_thread::sleep_for(1ms);
            } while (!p->stop_ctl);
            explain.pop_back();

            if (p->stop_ctl) break;
            std::vector<std::string> fields;
            CMD_Fields cmd_field;
            fields = utils_split_str(explain, "\t");
            if (fields.size() < CMD_FIELD_NUM)
                throw std::runtime_error("parser error");
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
            packet->src_ip = strlen(cmd_field.ip_src) ? cmd_field.ip_src
                                                      : cmd_field.ipv6_src;
            packet->dst_ip = strlen(cmd_field.ip_dst) ? cmd_field.ip_dst
                                                      : cmd_field.ipv6_dst;
            // 端口
            std::string src_dst_port = strlen(cmd_field.tcp_port)
                                           ? cmd_field.tcp_port
                                           : cmd_field.udp_port;
            if (!src_dst_port.empty()) {
                std::vector<std::string> ports =
                    utils_split_str(src_dst_port, ",");
                if (ports.size() == 2) {
                    packet->src_port =
                        static_cast<uint16_t>(std::stoi(ports[0]));
                    packet->dst_port =
                        static_cast<uint16_t>(std::stoi(ports[1]));
                }
            }
            // 归属地
            packet->src_location = utils_ip2region(packet->src_ip);
            packet->dst_location = utils_ip2region(packet->dst_ip);

            // 保存
            p->packets_list.push_back(packet);
            // 其他处理
            if (p->handler) {
                p->handler(packet);
            }
        }
    }

    virtual ~ParserStreamPacket() {
        stop_ctl = true;
        if (p_t && p_t->joinable()) {
            p_t->join();
        }
    }
};

struct ParserStreamPacketDetail : ParserStream, UniStreamDualPipeU {
    using PacketHandler =
        std::function<void(std::shared_ptr<PacketDefineDecode>)>;
    std::vector<std::shared_ptr<PacketDefineDecode>> packets_list;
    std::atomic_uint32_t packets_pending;
    volatile std::atomic_bool stop_ctl;
    std::unique_ptr<std::thread> p_t;
    std::mutex t_m;

    PacketHandler handler;

    ParserStreamPacketDetail(std::string const &cmd)
        : UniStreamDualPipeU(cmd) {}
    ParserStreamPacketDetail(PacketHandler handler = nullptr)
        : packets_pending(0), stop_ctl(false) {
        std::string cmd = TSHARK_PATH " -Q -l -r - -T pdml";
        new (this)(ParserStreamPacketDetail)(cmd);
        this->handler = handler;
        p_t = std::make_unique<std::thread>(thread, this);
    }

    virtual void packet_arrived(std::vector<char> const &,
        std::vector<char> const &, uint32_t, uint32_t) override {
        std::lock_guard<std::mutex> lock(t_m);
        packets_pending++;
    }

    virtual void wait_done() override {
        using namespace std::chrono_literals;
        if (p_t) {
            while (packets_pending) {
                std::this_thread::sleep_for(1ms);
            }
        }
    }

    // 解析线程
    static void thread(ParserStreamPacketDetail *p) {
        using namespace std::chrono_literals;
        StreamBuf buf;
        char data[512];
        uint32_t rd_len;
        auto read_some = [&]() {
            do {
                rd_len = p->read_ub(data, 512);
                if (rd_len) buf.write(data, rd_len);
            } while (!p->eof() && rd_len);
        };
        std::string xml;
        while (!p->eof()) {
            read_some();
            if (!p->packets_pending) {
                if (p->stop_ctl) break;
                std::this_thread::yield();
                continue;
            }
            std::shared_ptr<PacketDefineDecode> packet;
            {
                std::lock_guard<std::mutex> lock(p->t_m);
                p->packets_pending--;
            }

            bool f = false;
            do {
                read_some();
                xml.resize(0);
                if (!f) xml = buf.try_read_util("<packet>", false);
                if (!xml.empty()) f = true;
                if (f) xml = buf.try_read_util("</packet>");
                if (!xml.empty()) break;
                std::this_thread::sleep_for(1ms);
            } while (!p->stop_ctl);
            if (p->stop_ctl) break;
            packet = std::make_shared<PacketDefineDecode>(xml);

            // 保存
            p->packets_list.push_back(packet);
            // 其他处理
            if (p->handler) {
                p->handler(packet);
            }
        }
    }

    virtual ~ParserStreamPacketDetail() {
        stop_ctl = true;
        if (p_t && p_t->joinable()) {
            p_t->join();
        }
    }
};
