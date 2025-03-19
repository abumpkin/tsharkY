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
#include "fmt/format.h"
#include "mutils.h"
#include "rapidjson/document.h"
#include "stream.h"
#include "tshark_info.h"
#include "unistream.h"
#include "yaml-cpp/binary.h"
#include "yaml-cpp/node/parse.h"
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>
#include <yaml-cpp/yaml.h>

struct Analyzer {
    static std::unique_ptr<PacketDefineDecode> packet_detail(
        std::shared_ptr<Packet> pkt, std::shared_ptr<Packet> prv_pkt) {
        std::string cmd = TSHARK_PATH " -Q -l -i - -T pdml";
        UniStreamDualPipeU analyzer{cmd, "-"};
        std::unique_ptr<PacketDefineDecode> dec;
        if (!pkt) return nullptr;
        analyzer.write(pkt->fixed->data(), pkt->fixed->size());
        if (prv_pkt && prv_pkt->data)
            analyzer.write(prv_pkt->data->data(), prv_pkt->data->size());
        if (pkt->data) analyzer.write(pkt->data->data(), pkt->data->size());
        analyzer.close_write();
        std::string xml = analyzer.read_until_eof();
        auto pos = xml.rfind("<packet>");
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
        private:
        std::shared_mutex mt;
        std::shared_ptr<std::unordered_set<std::shared_ptr<Session>>> sessions;
        SessionAnalyzer() {
            sessions = std::make_shared<
                std::unordered_set<std::shared_ptr<Session>>>();
        }

        public:
        SessionAnalyzer(SessionAnalyzer &&t) {
            sessions = std::move(t.sessions);
        }

        static std::shared_ptr<SessionAnalyzer> create() {
            return std::make_shared<SessionAnalyzer>(SessionAnalyzer());
        }

        std::shared_ptr<Session> check_packet(Packet &packet) {
            std::shared_ptr<Session> ret;
            if (packet.ip_proto_code == Packet::TCP ||
                packet.ip_proto_code == Packet::UDP) {
                std::unique_lock<std::shared_mutex> lock(mt);
                ret = Session::create(packet);
                if (sessions->count(ret)) {
                    ret = *sessions->find(ret);
                    ret->update(packet);
                }
                else {
                    ret->session_id = sessions->size();
                    ret->update(packet);
                    sessions->emplace(ret);
                }
            }
            return ret;
        }

        rapidjson::Value to_json_obj(
            rapidjson::MemoryPoolAllocator<> &allocator) const {
            rapidjson::Value ret;
            ret.SetArray();
            for (auto &i : *sessions) {
                ret.PushBack(i->to_json_obj(allocator), allocator);
            }
            return ret;
        }

        ProtectedObj<std::unordered_set<std::shared_ptr<Session>>>
        get_sessions() {
            return ProtectedObj(sessions, mt);
        }
    };

    // -z follow,prot,mode,filter[,range]
    struct DatastreamAnalyzer : TsharkDataObj<DatastreamAnalyzer> {
        struct Peer : TsharkDataObj<Peer> {
            uint32_t no;
            std::string host;
            uint32_t port;
            Peer(uint32_t no, std::string host, uint32_t port)
                : no(no), host(host), port(port) {}
        };
        struct Stream : TsharkDataObj<Stream> {
            std::shared_ptr<Packet> pkt;
            std::shared_ptr<Peer> peer;
            std::shared_ptr<std::vector<char>> data;
        };
        std::vector<std::shared_ptr<Stream>> datastream;

        DatastreamAnalyzer(
            std::vector<std::shared_ptr<Packet>> &sess_pkts, std::string type) {
            std::string cmd = TSHARK_PATH " -Q -l -i - -z follow,{},yaml,0";
            cmd = fmt::format(cmd, type);
            UniStreamDualPipeU analyzer{cmd, "-"};
            if (sess_pkts.empty()) throw std::runtime_error("empty session.");
            bool fixed = false;
            for (auto &i : sess_pkts) {
                if (i) {
                    if (i->fixed && !fixed) {
                        analyzer.write(i->fixed->data(), i->fixed->size());
                        fixed = true;
                    }
                    if (fixed && i->data) {
                        analyzer.write(i->data->data(), i->data->size());
                    }
                }
            }
            analyzer.close_write();
            YAML::Node data = YAML::Load(analyzer.read_until_eof());
            std::map<uint32_t, std::shared_ptr<Peer>> peers;
            for (YAML::const_iterator it = data["peers"].begin();
                it != data["peers"].end(); ++it) {
                uint32_t no = (*it)["peer"].as<uint32_t>();
                std::string host = (*it)["host"].as<std::string>();
                uint32_t port = (*it)["port"].as<uint32_t>();
                peers.emplace(no, std::make_shared<Peer>(Peer(no, host, port)));
            }
            for (YAML::const_iterator it = data["packets"].begin();
                it != data["packets"].end(); ++it) {
                std::shared_ptr<Stream> s = std::make_shared<Stream>();
                s->peer = peers.at((*it)["peer"].as<uint32_t>());
                s->pkt = sess_pkts[(*it)["packet"].as<uint32_t>() - 1];
                YAML::Binary data = (*it)["data"].as<YAML::Binary>();
                s->data = std::make_shared<std::vector<char>>(
                    data.data(), data.data() + data.size());
                datastream.push_back(s);
            }
        }
    };

    // -z flow,name,mode[,filter]
};
