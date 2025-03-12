
#include "mutils.h"
#include "parser_stream.h"
#include "tshark_info.h"
#include "tshark_manager.h"
#include "unistream.h"
#include <chrono>
#include <memory>
#include <thread>

int main() {
    auto p = [](std::shared_ptr<Packet> p) {
        std::cout << p->to_json() << std::endl;
    };
    std::string path = "dump_data/capture.pcap";
    {
        utils_timer t;
        int c = 5;
        while (c--) {
            t.beg();
            std::string ret = utils_exec_cmd(
                "tshark -Q -l -r " + path +
                " -T fields -e frame.number -e frame.time_epoch "
                "-e _ws.col.Protocol -e _ws.col.Info -e eth.src -e eth.dst -e "
                "ip.src -e ip.dst -e ipv6.src -e ipv6.dst -e udp.port -e "
                "tcp.port "
                "> /dev/null");
            t.end();
        }
    }
    {
        utils_timer t;
        int c = 10;
        while (c--) {
            t.beg();
            std::shared_ptr<ParserStreamPacketBrief<UniStreamDualPipeU>> ps =
                std::make_shared<ParserStreamPacketBrief<UniStreamDualPipeU>>(p);
            std::shared_ptr<UniStreamInterface> data =
                std::make_shared<UniStreamFile>(path);
            SharkPcapLoader loader{data};
            loader.register_parser_streams(ps);
            loader.load();
            t.end();
            // std::cout << ps->packets_list.size() << std::endl;
        }
    }
    // {
    //     utils_timer t;
    //     int c = 5;
    //     while (c--) {
    //         t.beg();
    //         std::shared_ptr<ParserStreamPacketBrief<UniStreamPipeUnblocked>>
    //             ps = std::make_shared<
    //                 ParserStreamPacketBrief<UniStreamPipeUnblocked>>();
    //         std::shared_ptr<UniStreamInterface> data =
    //             std::make_shared<UniStreamFile>(path);
    //         SharkPcapLoader loader{data};
    //         loader.register_parser_streams(ps);
    //         loader.load();
    //         t.end();
    //         // std::cout << ps->packets_list.size() << std::endl;
    //     }
    // }
    return 0;
}