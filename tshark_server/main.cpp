#include "mutils.h"
#include "tshark_manager.h"
#include <cstdint>
#include <ios>
#include <loguru.hpp>
#include <thread>
#include <chrono>

int main(int argc, char **argv) {
    loguru::init(argc, argv);
    //  loguru::add_file("logs.txt", loguru::Append, loguru::Verbosity_MAX);
    TSharkManager m;
    uint32_t c;

    // 网卡信息
    auto ifs = m.interfaces_get_info().get();
    for (auto &i: ifs) {
        LOG_F(INFO, "网卡名称：%s  别名：%s", i.name.c_str(), i.friendly_name.c_str());
    }
    // 抓包
    c = 5;
    m.capture_start("", [&](std::shared_ptr<Packet> packet) {
        LOG_F(0, "pcap: offset = %u  len = %u", packet->frame_offset,
            packet->frame_caplen);
        LOG_F(INFO, "%s", packet->to_json().c_str());
        if (c-- == 0) return SharkLoader::PKT_PARSE_STAT::PARSE_STOP;
        return SharkLoader::PKT_PARSE_STAT::PARSE_CONTINUE;
    });

    // 流量
    c = 5;
    std::cout << std::boolalpha << m.interfaces_traffic_monitor_start().get() << std::endl;
    while (m.interfaces_traffic_monitor_is_running().get()) {
        std::this_thread::sleep_for(std::chrono_literals::operator""s(1));
        for (auto &[k,v] : m.interfaces_traffic_monitor_read().get()) {
            LOG_F(INFO, "%s: %u", k.c_str(), v);
        }
        if (c-- == 0) m.interfaces_traffic_monitor_stop();
    }
    return 0;
}