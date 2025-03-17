/**
 * @file streambuf.h
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
#include "mutils.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <stack>
#include <string>
#include <thread>
#include <utility>
#include <vector>

template <size_t SIZE = 4096, size_t MAX_BLOCK = -1ul>
class StreamBuf {
    public:
    static constexpr size_t BLOCK_SIZE = SIZE;
    static constexpr size_t BLOCK_MAX = MAX_BLOCK;
    uint64_t total_read;

    struct Block {
        std::vector<char> data;
        size_t read_pos = 0;
        size_t write_pos = 0;
        std::mutex block_mutex;
        std::atomic<Block *> next{nullptr};

        Block() : data(BLOCK_SIZE) {}

        void reset() noexcept {
            read_pos = 0;
            write_pos = 0;
            next.store(nullptr, std::memory_order_relaxed);
        }
    };

    // 内存池实现
    class BlockPool {
        private:
        std::stack<Block *> free_pool;
        std::mutex mutex;

        public:
        Block *acquire() {
            std::lock_guard<std::mutex> lock(mutex);
            if (free_pool.empty()) return new Block();
            Block *block = free_pool.top();
            free_pool.pop();
            return block;
        }

        void release(Block *block) noexcept {
            std::lock_guard<std::mutex> lock(mutex);
            block->reset();
            free_pool.push(block);
        }

        ~BlockPool() {
            while (!free_pool.empty()) {
                delete free_pool.top();
                free_pool.pop();
            }
        }
    };

    struct DataView {
        private:
        StreamBuf *p_buf;
        Block *block;
        // BlockPool *pool;
        std::unique_lock<std::mutex> lock;

        public:
        char *data;
        uint64_t len;

        DataView(std::unique_lock<std::mutex> &&lock, StreamBuf *p_buf,
            Block *block, uint64_t off_, uint64_t len_)
            : p_buf(p_buf), block(block) {
            this->lock = std::move(lock);
            len = 0;
            if (block) {
                // block->block_mutex.lock();
                data = block->data.data() + off_;
                len = len_;
            }
        }

        ~DataView() {
            if (block) {
                // block->block_mutex.unlock();
                block->read_pos += len;
            }
            // if (p_buf) {
            //     if ((block->write_pos - block->read_pos) == 0 &&
            //         block->write_pos == block->data.size() &&
            //         p_buf->block_pool) {
            //         if (p_buf->head.load(std::memory_order_acquire) !=
            //                 p_buf->tail.load(std::memory_order_acquire) &&
            //             block->next) {
            //             p_buf->head.store(
            //                 block->next, std::memory_order_release);
            //             if (block->next == nullptr) {
            //                 std::abort();
            //             }
            //             p_buf->block_pool->release(block);
            //             p_buf->block_count_.fetch_sub(1);
            //         }
            //     }
            // }
            if (p_buf) {
                p_buf->total_read += len;
                p_buf->size_.fetch_sub(len, std::memory_order_relaxed);
            }
        }
    };
    friend DataView;

    private:
    struct BlockRecord {
        Block *block;
        size_t start_pos;
        size_t length;

        BlockRecord(Block *b, size_t s, size_t l)
            : block(b), start_pos(s), length(l) {}
    };
    std::unique_ptr<BlockPool> block_pool;
    std::atomic<Block *> head;
    std::atomic<Block *> tail;
    std::atomic<size_t> size_{0};
    std::atomic<size_t> block_count_{1};
    std::shared_mutex global_mutex; // 全局读写锁，防止遍历时结构变化

    size_t write_impl(const void *input, size_t len, bool blocking) {
        using namespace std::chrono_literals;
        const char *data = static_cast<const char *>(input);
        size_t written = 0;

        while (written < len) {
            Block *current_block = tail.load(std::memory_order_acquire);
            if (!current_block) return written; // 缓冲区已关闭

            std::unique_lock<std::mutex> lock(current_block->block_mutex);
            size_t remaining = BLOCK_SIZE - current_block->write_pos;

            if (remaining == 0) {
                if (block_count_.load() >= MAX_BLOCK) {
                    // LOG_F(INFO, "MAX block");
                    lock.unlock();
                    std::this_thread::yield();
                    // std::this_thread::sleep_for(1ms);
                    continue;
                }
                if (Block *new_block = block_pool->acquire()) {
                    current_block->next.store(
                        new_block, std::memory_order_release);
                    tail.store(new_block, std::memory_order_release);
                    block_count_.fetch_add(1);
                    continue;
                }
                if (!blocking) return written;
                lock.unlock();
                // std::this_thread::yield();
                continue;
            }

            size_t to_write = std::min(remaining, len - written);
            memcpy(&current_block->data[current_block->write_pos],
                &data[written], to_write);
            current_block->write_pos += to_write;
            written += to_write;
            size_.fetch_add(to_write, std::memory_order_relaxed);
        }
        return written;
    }

    size_t read_impl(void *output, size_t len, bool blocking) {
        char *data = static_cast<char *>(output);
        size_t read = 0;

        while (read < len) {
            Block *current_block = head.load(std::memory_order_acquire);
            if (!current_block) return read; // 缓冲区已关闭

            std::unique_lock<std::mutex> lock(current_block->block_mutex);
            size_t available =
                current_block->write_pos - current_block->read_pos;

            if (available == 0) {
                // if (current_block == tail.load(std::memory_order_acquire))
                //     return read;
                if (Block *next_block =
                        current_block->next.load(std::memory_order_acquire)) {
                    head.store(next_block, std::memory_order_release);
                    block_pool->release(current_block);
                    block_count_.fetch_sub(1);
                    continue;
                }
                if (!blocking) return read;
                lock.unlock();
                // std::this_thread::yield();
                continue;
            }

            size_t to_read = std::min(available, len - read);
            memcpy(&data[read], &current_block->data[current_block->read_pos],
                to_read);
            current_block->read_pos += to_read;
            read += to_read;
            size_.fetch_sub(to_read, std::memory_order_relaxed);
        }
        total_read += read;
        return read;
    }

    public:
    StreamBuf() : block_pool(std::make_unique<BlockPool>()) {
        Block *init_block = block_pool->acquire();
        head.store(init_block);
        tail.store(init_block);
        total_read = 0;
    }

    ~StreamBuf() {
        clear(true); // 强制释放所有内存
    }

    // 写入数据（自动扩容）
    size_t write(const void *data, size_t len) {
        return write_impl(data, len, true);
    }

    // 非阻塞写入
    // size_t try_write(const void *data, size_t len) {
    //     return write_impl(data, len, false);
    // }

    // 读取数据
    size_t read(void *data, size_t len) {
        return read_impl(data, len, true);
    }

    // 非阻塞读取
    std::shared_ptr<DataView> try_read(size_t len) {
        std::shared_ptr<DataView> ret;
        Block *current_block = head.load(std::memory_order_acquire);
        size_t available;
        while (current_block) {
            std::unique_lock<std::mutex> lock(current_block->block_mutex);
            available = current_block->write_pos - current_block->read_pos;
            if (available == 0) {
                if (current_block->write_pos != current_block->data.size())
                    return ret;
                // if (current_block == tail.load(std::memory_order_acquire))
                //     return ret;
                Block *next =
                    current_block->next.load(std::memory_order_acquire);
                if (!next) return ret;
                block_pool->release(current_block);
                block_count_.fetch_sub(1);
                head.store(next, std::memory_order_release);
                current_block = next;
                continue;
            }
            size_t to_read = std::min(available, len);
            ret = std::make_shared<DataView>(std::move(lock), this,
                current_block, current_block->read_pos, to_read);
            break;
        }
        return ret;
    }

    // 预览数据（不移动读指针）
    size_t peek(void *data, size_t len) const {
        size_t read = 0;
        Block *current_block = head.load();
        char *output = static_cast<char *>(data);

        while (current_block && read < len) {
            std::unique_lock<std::mutex> lock(current_block->block_mutex);
            size_t available =
                current_block->write_pos - current_block->read_pos;
            if (available == 0) break;

            size_t to_read = std::min(available, len - read);
            memcpy(&output[read], &current_block->data[current_block->read_pos],
                to_read);
            read += to_read;
            current_block = current_block->next.load();
        }
        return read;
    }

    // 清空缓冲区
    void clear(bool force_free = false) {
        Block *current = head.exchange(nullptr);
        tail.store(nullptr);
        size_.store(0);

        while (current) {
            Block *next = current->next.load();
            if (force_free)
                delete current;
            else
                block_pool->release(current);
            current = next;
        }

        if (!force_free) {
            Block *new_block = block_pool->acquire();
            head.store(new_block);
            tail.store(new_block);
        }
    }

    // 释放未使用内存
    void shrink_to_fit() {
        Block *current = head.load();
        size_t keep_blocks = size_.load() / BLOCK_SIZE + 1;
        size_t count = 0;

        while (current) {
            Block *next = current->next.load();
            if (++count > keep_blocks) {
                block_pool->release(current);
            }
            current = next;
        }
    }

    // 当前数据量
    size_t size() const noexcept {
        return size_.load(std::memory_order_relaxed);
    }

    // 总容量（字节）
    size_t capacity() const noexcept {
        return block_count_.load() * BLOCK_SIZE;
    }

    // 当前块数量
    size_t block_count() const noexcept {
        return block_count_.load();
    }

    std::string try_read_util(char chr) {
        // 第一阶段：扫描并记录需要读取的块
        std::vector<BlockRecord> records;
        size_t total_length = 0;
        bool found = false;
        // Block *stop_block = nullptr;
        // size_t stop_offset = 0;

        Block *current_block = head.load(std::memory_order_acquire);
        while (current_block) {
            std::unique_lock<std::mutex> lock(current_block->block_mutex);

            const size_t start = current_block->read_pos;
            const size_t available = current_block->write_pos - start;
            if (available == 0) {
                lock.unlock();
                current_block =
                    current_block->next.load(std::memory_order_acquire);
                continue;
            }

            // 在当前块中搜索字符
            const char *begin = current_block->data.data() + start;
            // const char *end = begin + available;
            const char *pos =
                static_cast<const char *>(memchr(begin, chr, available));

            if (pos) {
                // 找到终止字符
                const size_t bytes = pos - begin + 1;
                records.emplace_back(current_block, start, bytes);
                total_length += bytes;
                // stop_block = current_block;
                // stop_offset = start + bytes;
                found = true;
                break;
            }
            else {
                // 记录整块数据
                records.emplace_back(current_block, start, available);
                total_length += available;
            }

            lock.unlock();
            current_block = current_block->next.load(std::memory_order_acquire);
        }

        if (!found) return "";
        std::string ret;
        if (total_length) {
            ret.resize(total_length);
            read(ret.data(), total_length);
        }
        return ret;
    }

    size_t find(const std::string &target) {
        if (target.empty()) return 0;

        const size_t target_len = target.size();
        auto lps = buildKMPTABLE(target); // 预处理目标
        size_t current_pos = 0;
        Block *current_block = head.load(std::memory_order_acquire);
        std::string window; // 跨块滑动窗口
        std::shared_lock<std::shared_mutex> global_lock(
            global_mutex); // 全局读锁防止结构修改

        while (current_block) {
            std::lock_guard<std::mutex> lock(
                current_block->block_mutex); // 读锁优化
            size_t available =
                current_block->write_pos - current_block->read_pos;
            if (available == 0) {
                current_block =
                    current_block->next.load(std::memory_order_acquire);
                continue;
            }

            // 合并窗口与当前块数据
            std::string current_data(
                current_block->data.data() + current_block->read_pos,
                available);
            std::string combined = window + current_data;

            // KMP搜索
            size_t pos = kmpSearch(combined, lps, target);
            if (pos != std::string::npos) {
                return current_pos - window.size() + pos;
            }

            // 更新滑动窗口为最后(target_len - 1)字节
            if (combined.size() >= target_len) {
                window = combined.substr(combined.size() - (target_len - 1));
            }
            else {
                window = combined;
            }

            current_pos += available;
            current_block = current_block->next.load(std::memory_order_acquire);
        }
        return 0;
    }

    std::string try_read_util(const std::string &target, bool consume = true) {
        size_t pos = find(target);
        std::string ret;
        if (pos) {
            if (consume) pos += target.size();
            ret.resize(pos);
            read(ret.data(), pos);
        }
        return ret;
    }

    static std::vector<size_t> buildKMPTABLE(const std::string &pattern) {
        std::vector<size_t> lps(pattern.size(), 0);
        size_t len = 0;
        for (size_t i = 1; i < pattern.size();) {
            if (pattern[i] == pattern[len]) {
                lps[i++] = ++len;
            }
            else {
                if (len != 0) {
                    len = lps[len - 1];
                }
                else {
                    lps[i++] = 0;
                }
            }
        }
        return lps;
    }

    static size_t kmpSearch(const std::string &text,
        const std::vector<size_t> &lps, const std::string &pattern) {
        size_t i = 0, j = 0;
        while (i < text.size()) {
            if (pattern[j] == text[i]) {
                ++i;
                ++j;
            }
            if (j == pattern.size()) {
                return i - j;
            }
            else if (i < text.size() && pattern[j] != text[i]) {
                j != 0 ? j = lps[j - 1] : i++;
            }
        }
        return std::string::npos;
    }
};