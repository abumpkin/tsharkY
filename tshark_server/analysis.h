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
#include "tshark_info.h"
#include "unistream.h"
#include "yaml-cpp/binary.h"
#include "yaml-cpp/node/parse.h"
#include <cmath>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
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

    struct IpStatistic : TsharkDataObj<IpStatistic> {
        struct IpInfo : TsharkDataObj<IpInfo> {
            std::string ip;
            std::string location;
            double earliest_time;
            double latest_time;
            std::set<uint16_t> ports;
            std::set<std::string> trans_protos;
            std::set<std::string> app_protos;
            uint32_t total_sent_packets;
            uint32_t total_sent_bytes;
            uint32_t total_recv_packets;
            uint32_t total_recv_bytes;
            uint32_t tcp_sessions_count;
            uint32_t udp_sessions_count;

            rapidjson::Value to_json_obj(
                rapidjson::MemoryPoolAllocator<> &allocator) const {
                rapidjson::Value ret;
                ret.SetObject();
                ret.AddMember(
                    "ip", rapidjson::Value(ip.c_str(), ip.size()), allocator);
                ret.AddMember("location",
                    rapidjson::Value(location.c_str(), location.size()),
                    allocator);
                ret.AddMember("earliest_time", earliest_time, allocator);
                ret.AddMember("latest_time", latest_time, allocator);
                rapidjson::Value ports_array;
                ports_array.SetArray();
                for (auto &i : ports) {
                    ports_array.PushBack(i, allocator);
                }
                ret.AddMember("ports", ports_array, allocator);
                rapidjson::Value trans_protos_array;
                trans_protos_array.SetArray();
                for (auto &i : trans_protos) {
                    trans_protos_array.PushBack(
                        rapidjson::Value(i.c_str(), i.size()), allocator);
                }
                ret.AddMember("trans_protos", trans_protos_array, allocator);
                rapidjson::Value app_protos_array;
                app_protos_array.SetArray();
                for (auto &i : app_protos) {
                    app_protos_array.PushBack(
                        rapidjson::Value(i.c_str(), i.size()), allocator);
                }
                ret.AddMember("app_protos", app_protos_array, allocator);
                ret.AddMember(
                    "total_sent_packets", total_sent_packets, allocator);
                ret.AddMember("total_sent_bytes", total_sent_bytes, allocator);
                ret.AddMember(
                    "total_recv_packets", total_recv_packets, allocator);
                ret.AddMember(
                    "total_recv_packets", total_recv_packets, allocator);
                ret.AddMember(
                    "tcp_sessions_count", tcp_sessions_count, allocator);
                ret.AddMember(
                    "udp_sessions_count", udp_sessions_count, allocator);
                return ret;
            }
        };
        std::unordered_map<std::string, std::shared_ptr<IpInfo>> infos;
        rapidjson::Value to_json_obj(
            rapidjson::MemoryPoolAllocator<> &allocator) const {
            rapidjson::Value ret;
            ret.SetArray();
            for (auto &i : infos) {
                ret.PushBack(i.second->to_json_obj(allocator), allocator);
            }
            return ret;
        }

        IpStatistic(std::vector<std::shared_ptr<Session>> &s) {
            for (auto &i : s) {
                if (!infos.count(i->ip1))
                    infos.emplace(i->ip1, std::make_shared<IpInfo>());
                if (!infos.count(i->ip2))
                    infos.emplace(i->ip2, std::make_shared<IpInfo>());
                std::shared_ptr<IpInfo> p;
                p = infos[i->ip1];
                p->ip = i->ip1;
                p->location = i->ip1_location;
                if (p->earliest_time == 0) p->earliest_time = i->start_time;
                if (i->start_time < p->earliest_time)
                    p->earliest_time = i->start_time;
                if (p->latest_time == 0) p->latest_time = i->end_time;
                if (i->end_time > p->latest_time) p->latest_time = i->end_time;
                p->ports.emplace(i->ip1_port);
                p->trans_protos.emplace(
                    Packet::get_ip_proto_str(i->trans_proto));
                p->app_protos.emplace(i->app_proto);
                p->total_sent_packets += i->ip1_send_packets;
                p->total_sent_bytes += i->ip1_send_bytes;
                p->total_recv_packets += i->ip2_send_packets;
                p->total_recv_bytes += i->ip2_send_bytes;
                if (i->trans_proto == Packet::TCP) p->tcp_sessions_count++;
                if (i->trans_proto == Packet::UDP) p->udp_sessions_count++;
                p = infos[i->ip2];
                p->ip = i->ip2;
                p->location = i->ip2_location;
                if (p->earliest_time == 0) p->earliest_time = i->start_time;
                if (i->start_time < p->earliest_time)
                    p->earliest_time = i->start_time;
                if (p->latest_time == 0) p->latest_time = i->end_time;
                if (i->end_time > p->latest_time) p->latest_time = i->end_time;
                p->ports.emplace(i->ip2_port);
                p->trans_protos.emplace(
                    Packet::get_ip_proto_str(i->trans_proto));
                p->app_protos.emplace(i->app_proto);
                p->total_sent_packets += i->ip2_send_packets;
                p->total_sent_bytes += i->ip2_send_bytes;
                p->total_recv_packets += i->ip1_send_packets;
                p->total_recv_bytes += i->ip1_send_bytes;
                if (i->trans_proto == Packet::TCP) p->tcp_sessions_count++;
                if (i->trans_proto == Packet::UDP) p->udp_sessions_count++;
            }
        }
    };

    struct ProtoStatistic : TsharkDataObj<ProtoStatistic> {
        struct ProtoInfo : TsharkDataObj<ProtoInfo> {
            std::string protocol;
            uint32_t total_packets;
            uint32_t total_bytes;
            std::unordered_set<std::shared_ptr<Session>> sessions;
            const char *description;
            rapidjson::Value to_json_obj(
                rapidjson::MemoryPoolAllocator<> &allocator) const {
                rapidjson::Value ret;
                ret.SetObject();
                ret.AddMember("protocol",
                    rapidjson::Value(protocol.c_str(), protocol.size()),
                    allocator);
                ret.AddMember("total_packets", total_packets, allocator);
                ret.AddMember("total_bytes", total_bytes, allocator);
                ret.AddMember("session_count", sessions.size(), allocator);
                if (description)
                    ret.AddMember("description",
                        rapidjson::Value(description, std::strlen(description)),
                        allocator);
                else
                    ret.AddMember("description",
                        rapidjson::Value("", allocator), allocator);
                return ret;
            }
        };
        std::unordered_map<std::string, std::shared_ptr<ProtoInfo>> infos;
        rapidjson::Value to_json_obj(
            rapidjson::MemoryPoolAllocator<> &allocator) const {
            rapidjson::Value ret;
            ret.SetArray();
            for (auto &i : infos) {
                ret.PushBack(i.second->to_json_obj(allocator), allocator);
            }
            return ret;
        }

        ProtoStatistic(std::vector<std::shared_ptr<Session>> &s) {
            for (auto &i : s) {
                std::shared_ptr<ProtoInfo> p;
                if (Packet::get_ip_proto_str(i->trans_proto)) {
                    std::string proto =
                        Packet::get_ip_proto_str(i->trans_proto);
                    if (!infos.count(proto))
                        infos.emplace(
                            proto, std::make_shared<ProtoInfo>());
                    p = infos[proto];
                    if (p->protocol.empty()) p->protocol = proto;
                    p->total_packets += i->packet_count;
                    p->total_bytes += i->total_bytes;
                    p->sessions.emplace(i);
                }
                if (!i->app_proto.empty()) {
                    std::string proto = i->app_proto;
                    if (!infos.count(proto))
                        infos.emplace(
                            proto, std::make_shared<ProtoInfo>());
                    p = infos[proto];
                    if (p->protocol.empty()) p->protocol = proto;
                    p->total_packets += i->packet_count;
                    p->total_bytes += i->total_bytes;
                    p->sessions.emplace(i);
                }
                if (p) {
                    p->description = get_proto_description(p->protocol);
                }
            }
        }
    };

    struct CountryStatistic : TsharkDataObj<CountryStatistic> {
        struct CountryInfo : TsharkDataObj<CountryInfo> {
            std::string country;
            uint32_t total_packets;
            uint32_t total_bytes;
            std::unordered_set<std::string> ips;
            std::unordered_set<std::shared_ptr<Session>> sessions;
            rapidjson::Value to_json_obj(
                rapidjson::MemoryPoolAllocator<> &allocator) const {
                rapidjson::Value ret;
                ret.SetObject();
                ret.AddMember("country",
                    rapidjson::Value(country.c_str(), country.size()),
                    allocator);
                rapidjson::Value ips_obj;
                ips_obj.SetArray();
                for (auto &i : ips) {
                    ips_obj.PushBack(
                        rapidjson::Value(i.c_str(), i.size()), allocator);
                }
                ret.AddMember("ips", ips_obj, allocator);
                ret.AddMember("total_packets", total_packets, allocator);
                ret.AddMember("total_bytes", total_bytes, allocator);
                ret.AddMember("session_count", sessions.size(), allocator);
                return ret;
            }
        };
        std::unordered_map<std::string, std::shared_ptr<CountryInfo>> infos;
        rapidjson::Value to_json_obj(
            rapidjson::MemoryPoolAllocator<> &allocator) const {
            rapidjson::Value ret;
            ret.SetArray();
            for (auto &i : infos) {
                ret.PushBack(i.second->to_json_obj(allocator), allocator);
            }
            return ret;
        }

        CountryStatistic(std::vector<std::shared_ptr<Session>> &s) {
            for (auto &i : s) {
                std::shared_ptr<CountryInfo> p;
                std::string country = utils_split_str(i->ip1_location, "-")[0];
                if (!infos.count(country))
                    infos.emplace(country, std::make_shared<CountryInfo>());
                p = infos[country];
                if (p->country.empty()) p->country = country;
                p->ips.emplace(i->ip1);
                p->sessions.emplace(i);
                p->total_packets += i->ip1_send_packets + i->ip2_send_packets;
                p->total_bytes += i->ip1_send_bytes + i->ip2_send_bytes;
            }
            for (auto &i : s) {
                std::shared_ptr<CountryInfo> p;
                std::string country = utils_split_str(i->ip2_location, "-")[0];
                if (!infos.count(country))
                    infos.emplace(country, std::make_shared<CountryInfo>());
                p = infos[country];
                if (p->country.empty()) p->country = country;
                p->ips.emplace(i->ip2);
                p->sessions.emplace(i);
                p->total_packets += i->ip1_send_packets + i->ip2_send_packets;
                p->total_bytes += i->ip1_send_bytes + i->ip2_send_bytes;
            }
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
