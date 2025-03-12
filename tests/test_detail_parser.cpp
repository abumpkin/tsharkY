
#include "mutils.h"
#include "parser_stream.h"
#include "tshark_info.h"
#include "tshark_manager.h"
#include "unistream.h"
#include <chrono>
#include <memory>
#include <thread>

int main() {
    auto p = [](std::shared_ptr<PacketDefineDecode> p) {
        std::cout << p->to_json() << std::endl;
    };
    std::string path = "dump_data/capture.pcap";
    {
        utils_timer t;
        int c = 4;
        while (c--) {
            t.beg();
            std::string ret = utils_exec_cmd(
                "tshark -l -Q -T pdml -r " + path + " > /dev/null");
            t.end();
        }
    }
    {
        utils_timer t;
        int c = 4;
        while (c--) {
            t.beg();
            std::shared_ptr<ParserStreamPacketDetail> ps =
                std::make_shared<ParserStreamPacketDetail>();
            std::shared_ptr<UniStreamInterface> data =
                std::make_shared<UniStreamFile>(path);
            SharkPcapLoader loader{data};
            loader.register_parser_streams(ps);
            loader.load();
            t.end();
            // std::cout << ps->packets_list.size() << std::endl;
        }
    }
    return 0;
}