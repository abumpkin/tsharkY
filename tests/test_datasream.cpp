
#include "analysis.h"
#include "database.h"
#include "mutils.h"
#include "tshark_info.h"
#include <cstring>
#include <iostream>
#include <memory>
#include <ostream>
#include <pugixml.hpp>
#include <string>
#include <traffic_statistics.h>
#include <unistream.h>
#include <vector>

int main() {
    std::shared_ptr<TsharkDB> db = TsharkDB::connect("dump_data/temp.db3");
    std::vector<std::shared_ptr<Session>> sess =
        db->table_session->select({{"pos", "9"}});

    if (sess.size()) {
        std::vector<std::shared_ptr<Packet>> pkts = db->table_brief->select(
            {{"session_id", std::to_string(sess[0]->session_id)}});
        std::cout << sess[0]->session_id << std::endl;
        std::cout << pkts.size() << std::endl;
        std::string type = Packet::get_ip_proto_str(sess[0]->trans_proto);
        type = utils_str_lowcase(type);
        Analyzer::DatastreamAnalyzer ds(pkts, type);
        for (auto i : ds.datastream) {
            std::cout << i->peer->host << std::endl;
            std::cout << i->peer->port << std::endl;
            ShowHex(i->data->data(), i->data->size());
        }
        std::cout << ds.to_json(true) << std::endl;
    }
    return 0;
}