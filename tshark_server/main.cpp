#include "mutils.h"
#include "tshark_manager.h"
#include <loguru.hpp>
#include <memory>
#include <vector>

int main(int argc, char **argv) {
    loguru::init(argc, argv);
    TSharkManager m;
    m.start_capture("", [](std::shared_ptr<Packet> packet) {
        LOG_F(0, "pcap: offset = %u  len = %u", packet->frame_offset,
            packet->frame_caplen);
        LOG_F(INFO, "%s", packet->to_json().c_str());
    });
    return 0;
}