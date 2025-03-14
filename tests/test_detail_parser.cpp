
#include "mutils.h"
#include "parser_stream.h"
#include "tshark_info.h"
#include "tshark_manager.h"
#include "unistream.h"
#include <memory>


// 翻译：1342                         +542ms
// 解析xml 不翻译：800                 +240ms
// 获取<packet> 不解析xml：560         +88ms
// 缓存pdml 不获取<packet>：272        +7ms
// 不缓存pdml + yield：265

int main() {
    auto p = [](std::shared_ptr<PacketDefineDecode> p) {
        // std::cout << p->to_json() << std::endl;
        p->to_json();
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
            loader.load({ps});
            t.end();
            // std::cout << ps->packets_list.size() << std::endl;
        }
    }
    return 0;
}