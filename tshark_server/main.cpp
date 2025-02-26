#include "mutils.h"
#include "tshark_manager.h"
#include <chrono>
#include <cstdint>
#include <ios>
#include <loguru.hpp>
#include <thread>

int main(int argc, char **argv) {
    loguru::init(argc, argv);
    //  loguru::add_file("logs.txt", loguru::Append, loguru::Verbosity_MAX);
    TSharkManager m;
    uint32_t c;

    // 网卡信息
    // auto ifs = m.interfaces_get_info().get();
    // for (auto &i : ifs) {
    //     LOG_F(INFO, "网卡名称：%s  别名：%s", i.name.c_str(),
    //         i.friendly_name.c_str());
    // }
    // 抓包
    m.interfaces_activity_monitor_start().wait();
    auto pac = [&](std::shared_ptr<Packet> packet) {
        LOG_F(0, "packet: len = %zu", packet->data.size());
        LOG_F(INFO, "%s", packet->to_json().c_str());
    };
    m.capture_start("wlan0", "", pac);
    std::this_thread::sleep_for(std::chrono::seconds(5));
    if (m.capture_stop().get()) {
        LOG_F(INFO, "停止捕获数据");
    }

    // 网卡活动信息
    c = 1;
    while (c--) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        for (auto &[k, v] : m.interfaces_activity_monitor_read().get()) {
            LOG_F(INFO, "%s: %u", k.c_str(), v);
        }
    }
    if (m.interfaces_activity_monitor_stop().get()) {
        LOG_F(INFO, "停止统计所有网卡活动");
    }
    return 0;
}