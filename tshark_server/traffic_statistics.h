/**
 * @file traffic_statistics.h
 * @author abumpkin (forwardslash@foxmail.com)
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
#include "mutils.h"
#include "tshark_info.h"
#include "unistream.h"
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <future>
#include <loguru.hpp>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <tinyxml2.h>
#include <unordered_map>
#include <vector>

struct InterfacesActivityThread {
    private:
    std::unordered_map<std::string, std::atomic_uint_fast32_t> statistics;
    std::unique_ptr<std::thread> t_t;
    std::condition_variable t_cv;
    std::mutex t_m;
    std::promise<bool> start_status;
    std::promise<bool> stop_status;
    volatile std::atomic_bool is_operating = false;
    volatile std::atomic_bool is_done_with_succeed = false;
    volatile std::atomic_bool capture_stop_ctl = false;

    public:
    InterfacesActivityThread() = default;

    bool start_blocked() {
        std::string cmd = DUMPCAP_PATH " -S -M";
        UniStreamPipe pipe(cmd);
        std::string line;
        while (!capture_stop_ctl) {
            line = pipe.read_until('\n');
            auto fields = utils_split_str(line, "\t");
            if (fields.size() >= 2) {
                std::lock_guard<std::mutex> lock(t_m);
                statistics[fields[0]] = std::stoul(fields[1]);
            }
            if (pipe.read_eof()) return false;
        }
        return true;
    }

    std::future<bool> start() {
        std::future<bool> ret;
        if (t_t) {
            {
                std::lock_guard<std::mutex> lock(t_m);
                if (is_operating) {
                    LOG_F(ERROR, "ERROR: In running. Please stop first");
                    return std::async(std::launch::deferred, []() {
                        return false;
                    });
                }
            }
            t_t->join();
        }
        {
            std::lock_guard<std::mutex> lock(t_m);
            this->is_operating = false;
            this->capture_stop_ctl = false;
            this->is_done_with_succeed = false;
            start_status = std::promise<bool>();
            ret = start_status.get_future();
        }
        t_t = std::make_unique<std::thread>(thread, this);
        return ret;
    }

    std::future<bool> stop() {
        std::lock_guard<std::mutex> lock(t_m);
        std::future<bool> ret;
        if (!is_operating) {
            LOG_F(ERROR, "ERROR: Not in running. Nothing to stop.");
            return std::async(std::launch::deferred, []() {
                return false;
            });
        }
        this->capture_stop_ctl = true;
        stop_status = std::promise<bool>();
        ret = stop_status.get_future();
        return ret;
    }

    bool operating_status() {
        std::lock_guard<std::mutex> lock(t_m);
        return is_operating;
    }
    bool operating_done_with_succeed() noexcept(false) {
        if (operating_status()) {
            LOG_F(ERROR, "ERROR: Thread still in running.");
            throw std::runtime_error("Thread still in running.");
        }
        if (!t_t) {
            LOG_F(ERROR, "ERROR: Never been run.");
            throw std::runtime_error("Never been run.");
        }
        return is_done_with_succeed;
    }

    std::unordered_map<std::string, uint32_t> read() {
        std::unordered_map<std::string, uint32_t> ret;
        if (!is_operating) {
            LOG_F(WARNING, "WARNING: Reading nonsense value.");
            return ret;
        }
        std::lock_guard<std::mutex> lock(t_m);
        for (auto &[k, v] : statistics)
            ret[k] = v;
        return ret;
    }

    static void thread(InterfacesActivityThread *const tobj) {
        {
            std::lock_guard<std::mutex> lock(tobj->t_m);
            tobj->is_operating = true;
            tobj->start_status.set_value(true);
        }
        tobj->is_done_with_succeed = tobj->start_blocked();
        {
            std::lock_guard<std::mutex> lock(tobj->t_m);
            tobj->is_operating = false;
            if (tobj->capture_stop_ctl) {
                tobj->capture_stop_ctl = false;
                tobj->stop_status.set_value(true);
            }
        }
    }

    ~InterfacesActivityThread() {
        if (t_t) {
            if (is_operating) {
                stop().wait();
            }
            if (t_t->joinable()) {
                t_t->join();
            }
        }
    }
};
