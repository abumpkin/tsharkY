/**
 * @file analysis.h
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
#include "rapidjson/document.h"
#include "tshark_info.h"
#include "unistream.h"
#include <memory>
#include <unordered_set>
#include <vector>

struct Analyzer {
    static std::unique_ptr<PacketDefineDecode> packet_detail(
        std::shared_ptr<Packet> pkt) {
        std::string cmd = TSHARK_PATH " -Q -l -i - -T pdml";
        UniStreamDualPipeU analyzer{cmd, "-"};
        std::unique_ptr<PacketDefineDecode> dec;
        analyzer.write(pkt->fixed->data(), pkt->fixed->size());
        if (pkt->data) analyzer.write(pkt->data->data(), pkt->data->size());
        analyzer.close_write();
        std::string xml = analyzer.read_until_eof();
        auto pos = xml.find("<packet>");
        if (pos != std::string::npos) {
            xml = xml.substr(pos);
        }
        pos = xml.rfind("</packet>");
        if (pos != std::string::npos) {
            xml.resize(pos + 9);
        }
        dec = std::make_unique<PacketDefineDecode>(xml);
        return dec;
    }

    struct SessionAnalyzer : TsharkDataObj<SessionAnalyzer> {
        std::unordered_set<std::shared_ptr<Session>> sessions;

        private:
        SessionAnalyzer() = default;

        public:
        static std::shared_ptr<SessionAnalyzer> create() {
            return std::make_shared<SessionAnalyzer>(SessionAnalyzer());
        }

        void check_packet(Packet &packet) {
            if (packet.ip_proto_code == Packet::TCP ||
                packet.ip_proto_code == Packet::UDP) {
                auto sess = Session::create(packet);
                if (sessions.count(sess)) {
                    sessions.find(sess)->get()->update(packet);
                }
                else {
                    sess->session_id = sessions.size();
                    sess->update(packet);
                    sessions.emplace(sess);
                }
            }
        }

        rapidjson::Value to_json_obj(
            rapidjson::MemoryPoolAllocator<> &allocator) const {
            rapidjson::Value ret;
            ret.SetArray();
            for (auto &i : sessions) {
                ret.PushBack(i->to_json_obj(allocator), allocator);
            }
            return ret;
        }
    };
};
