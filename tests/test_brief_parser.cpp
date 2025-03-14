
#include "analysis.h"
#include "mutils.h"
#include "parser_stream.h"
#include "tshark_info.h"
#include "tshark_manager.h"
#include "unistream.h"
#include <memory>

std::string path = "dump_data/capture.pcap";
void time_test() {
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
        int c = 5;
        while (c--) {
            t.beg();
            std::shared_ptr<ParserStreamPacket> ps =
                std::make_shared<ParserStreamPacket>();
            std::shared_ptr<UniStreamInterface> data =
                std::make_shared<UniStreamFile>(path);
            SharkPcapLoader loader{data};
            loader.load({ps});
            t.end();
            // std::cout << ps->packets_list.size() << std::endl;
        }
    }
}

void print_test() {
    auto p = [](std::shared_ptr<Packet> p) {
        std::cout << p->to_json() << std::endl;
    };
    std::shared_ptr<ParserStreamPacket> ps =
        std::make_shared<ParserStreamPacket>(p);
    std::shared_ptr<UniStreamInterface> data =
        std::make_shared<UniStreamFile>(path);
    SharkPcapLoader loader{data};
    loader.load({ps});
}

int main() {
    std::shared_ptr<ParserStreamPacket> ps =
        std::make_shared<ParserStreamPacket>();
    std::shared_ptr<UniStreamInterface> data =
        std::make_shared<UniStreamFile>(path);
    SharkPcapLoader loader{data};
    loader.load({ps});
    std::unique_ptr<PacketDefineDecode> dec = Analyzer::packet_detail(ps->packets_list[0]);
    std::cout << dec->to_json() << std::endl;
    return 0;
}