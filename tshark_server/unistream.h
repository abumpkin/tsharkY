/**
 * @file unistream.h
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
#include "boost/asio/buffer.hpp"
#include "boost/asio/error.hpp"
#include "boost/asio/io_context.hpp"
#include "boost/asio/readable_pipe.hpp"
#include "boost/asio/streambuf.hpp"
#include "boost/asio/writable_pipe.hpp"
#include "boost/process/popen.hpp"
#include "boost/system/system_error.hpp"
#include "mutils.h"
#include <boost/asio.hpp>
#include <boost/process/v2/environment.hpp>
#include <boost/process/v2/process.hpp>
#include <boost/process/v2/stdio.hpp>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <future>
#include <ios>
#include <iostream>
#include <istream>
#include <memory>
#include <mutex>
#include <mutils.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

struct UniStreamInterface {
    UniStreamInterface() = default;
    UniStreamInterface(UniStreamInterface &) = delete;
    UniStreamInterface &operator=(UniStreamInterface &) = delete;
    UniStreamInterface(UniStreamInterface &&) = default;
    UniStreamInterface &operator=(UniStreamInterface &&) = default;
    virtual uint32_t read(char *buf, uint32_t len) = 0;
    virtual uint32_t read_ub(char *, uint32_t) {
        throw std::runtime_error("read_ub not implement.");
    }

    virtual uint32_t write(char const *buf, uint32_t len) = 0;
    virtual void flush() = 0;
    virtual void close_write() = 0;
    virtual void close_read() = 0;
    virtual bool eof() = 0;
    virtual uint32_t read_offset() = 0;
    virtual uint32_t write_offset() = 0;

    virtual std::future<uint32_t> read_async(char *buf, uint32_t len) {
        return std::async(std::launch::async, [=]() {
            return read(buf, len);
        });
    }

    virtual std::string read_until(char const t) {
        char rd;
        std::stringbuf buf;
        while (!eof()) {
            if (read(&rd, 1)) {
                buf.sputc(rd);
                if (rd == t) return buf.str();
            }
        }
        return buf.str();
    }

    virtual std::string read_until_eof() {
        size_t rd;
        char buf[512];
        std::string ret;
        while (!eof()) {
            rd = read(buf, sizeof(buf));
            ret.append(buf, rd);
        }
        return ret;
    }

    virtual uint32_t read_to_null(uint32_t len) {
        char buf[1024];
        if (eof()) return 0;
        uint32_t rd_len, o_pos = read_offset();
        while (len) {
            rd_len = sizeof(buf);
            if (rd_len > len) rd_len = len;
            rd_len = read(buf, rd_len);
            if (!rd_len) break;
            len -= rd_len;
        }
        return read_offset() - o_pos;
    }
};

class UniStreamDualPipeU : virtual public UniStreamInterface {
    private:
    volatile size_t r_pos, w_pos;
    bool eof_f = false;
#ifdef _WIN32
    HANDLE hProcess = nullptr;
    HANDLE hThread = nullptr;
    HANDLE hChildStdoutRd = nullptr;
    HANDLE hChildStdinWr = nullptr;
#else
    pid_t pid = -1;
    int childStdout = -1;
    int childStdin = -1;
#endif

    protected:
    UniStreamDualPipeU() {}

    public:
    UniStreamDualPipeU(const std::string &command) : r_pos(0), w_pos(0) {
#ifdef _WIN32
        SECURITY_ATTRIBUTES saAttr;
        saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
        saAttr.bInheritHandle = TRUE;
        saAttr.lpSecurityDescriptor = nullptr;

        // 创建管道
        if (!CreatePipe(&hChildStdoutRd, &hChildStdoutWr, &saAttr, 0) ||
            !CreatePipe(&hChildStdinRd, &hChildStdinWr, &saAttr, 0)) {
            throw std::runtime_error("Failed to create pipes");
        }

        // 设置子进程的标准输入输出
        STARTUPINFO si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.hStdError = hChildStdoutWr;
        si.hStdOutput = hChildStdoutWr;
        si.hStdInput = hChildStdinRd;
        si.dwFlags |= STARTF_USESTDHANDLES;

        ZeroMemory(&pi, sizeof(pi));

        // 创建子进程
        if (!CreateProcess(nullptr, const_cast<char *>(command.c_str()),
                nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi)) {
            CloseHandle(hChildStdoutRd);
            CloseHandle(hChildStdoutWr);
            CloseHandle(hChildStdinRd);
            CloseHandle(hChildStdinWr);
            throw std::runtime_error("Failed to create process");
        }

        // 关闭不需要的句柄
        CloseHandle(hChildStdoutWr);
        CloseHandle(hChildStdinRd);

        hProcess = pi.hProcess;
        hThread = pi.hThread;

        // 设置读取管道为非阻塞模式
        DWORD mode = PIPE_NOWAIT;
        if (!SetNamedPipeHandleState(hChildStdoutRd, &mode, nullptr, nullptr)) {
            throw std::runtime_error("Failed to set pipe to non-blocking mode");
        }
#else
        // Linux平台
        int stdoutPipe[2];
        int stdinPipe[2];

        if (pipe(stdoutPipe)) {
            throw std::runtime_error("Failed to create stdout pipe");
        }
        if (pipe(stdinPipe)) {
            throw std::runtime_error("Failed to create stdin pipe");
        }

        pid = fork();
        if (pid == 0) {
            // 子进程
            close(stdoutPipe[0]); // 关闭读取端
            close(stdinPipe[1]);  // 关闭写入端

            dup2(stdoutPipe[1], STDOUT_FILENO); // 重定向标准输出
            dup2(stdinPipe[0], STDIN_FILENO);   // 重定向标准输入

            std::vector<std::string> args = utils_split_str(command, " ");
            std::string exe = args[0];
            std::vector<char *> p_args;
            for (auto &i : args) {
                p_args.push_back(i.data());
            }
            p_args.push_back(nullptr);
            execvp(exe.c_str(), p_args.data());
            exit(1); // 如果execl失败
        }
        else if (pid > 0) {
            // 父进程
            close(stdoutPipe[1]); // 关闭写入端
            close(stdinPipe[0]);  // 关闭读取端

            childStdout = stdoutPipe[0];
            childStdin = stdinPipe[1];

            // 设置非阻塞模式
            fcntl(childStdout, F_SETFL, O_NONBLOCK);
            // fcntl(childStdin, F_SETFL, O_NONBLOCK);
        }
        else {
            throw std::runtime_error("Failed to fork");
        }
#endif
    }

    virtual ~UniStreamDualPipeU() {
        terminate();
    }

    bool alive() {
#ifdef _WIN32
        DWORD exitCode;
        if (GetExitCodeProcess(hProcess, &exitCode)) {
            return exitCode == STILL_ACTIVE;
        }
        return false;
#else
        if (pid > 0) {
            int status;
            return waitpid(pid, &status, WNOHANG) == 0;
        }
        return false;
#endif
    }

    void terminate() {
        close_write();
#ifdef _WIN32
        if (hProcess) {
            TerminateProcess(hProcess, 0);
            CloseHandle(hProcess);
            CloseHandle(hThread);
            CloseHandle(hChildStdoutRd);
            CloseHandle(hChildStdinWr);
            hProcess = nullptr;
        }
#else
        if (pid > 0) {
            kill(pid, SIGINT);
            kill(pid, SIGTERM);
            waitpid(pid, nullptr, 0);
            close(childStdout);
            close(childStdin);
            pid = -1;
        }
#endif
    }

    virtual uint32_t read(char *buf, uint32_t len) override {
        using namespace std::chrono_literals;
        uint32_t ret = 0, t = 0;
        while (!eof() && ret < len) {
            t = read_ub(buf + ret, len - ret);
            ret += t;
            if (!t) std::this_thread::sleep_for(1ms);
        }
        return ret;
    }

    virtual uint32_t read_ub(char *buf, uint32_t len) override {
#ifdef _WIN32
        DWORD bytesRead;
        if (ReadFile(hChildStdoutRd, buf, static_cast<DWORD>(len), &bytesRead,
                nullptr)) {
            r_pos += ret;
            return bytesRead;
        }
        if (GetLastError() == ERROR_HANDLE_EOF) {
            eof_f = true;
        }
        return 0;
#else
        size_t ret = ::read(childStdout, buf, len);
        if (!ret) eof_f = true;
        if (ret == -1ull) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                eof_f = true;
            }
            return 0;
        }
        r_pos += ret;
        return ret;
#endif
    }

    virtual uint32_t write(const char *buf, uint32_t len) override {
        if (!alive()) return 0;
#ifdef _WIN32
        DWORD bytesWritten;
        if (WriteFile(hChildStdinWr, buf, static_cast<DWORD>(len),
                &bytesWritten, nullptr)) {
            w_pos += ret;
            return bytesWritten;
        }
        return 0;
#else
        size_t ret = ::write(childStdin, buf, len);
        if (ret == -1ull) return 0;
        w_pos += ret;
        return ret;
#endif
    }

    virtual void flush() override {
#ifdef _WIN32
        // Windows平台：调用FlushFileBuffers刷新管道
        FlushFileBuffers(hChildStdinWr);
#else
        // Linux平台：调用fsync刷新文件描述符
        fsync(childStdin);
#endif
    }

    virtual void close_write() override {
        flush();
#ifdef _WIN32
        // Windows平台：关闭写入管道的句柄
        if (hChildStdinWr != nullptr) {
            CloseHandle(hChildStdinWr);
            hChildStdinWr = nullptr;
        }
#else
        // Linux平台：关闭写入管道的文件描述符
        if (childStdin != -1) {
            close(childStdin);
            childStdin = -1;
        }
#endif
    }

    virtual void close_read() override {
        terminate();
    }

    virtual bool eof() override {
        return eof_f;
    }

    virtual uint32_t read_offset() override {
        return r_pos;
    }
    virtual uint32_t write_offset() override {
        return w_pos;
    }
};

// class UniStreamPipeUnblocked : virtual public UniStreamInterface {
//     boost::asio::io_context ctx;
//     boost::asio::readable_pipe rp;
//     boost::asio::writable_pipe wp;
//     std::unique_ptr<boost::process::process> p;
//     std::mutex lock;
//     boost::asio::streambuf read_buf;
//     // std::stringbuf read_buf;
//     std::iostream stream;
//     std::thread t;
//     volatile size_t r_pos, w_pos;

//     static void read_thread(UniStreamPipeUnblocked *const p) {
//         char b;
//         while (true) {
//             try {
//                 p->rp.read_some(boost::asio::mutable_buffer(&b, 1));
//             }
//             catch (boost::system::system_error &e) {
//                 // std::cerr << std::endl
//                 //           << "Boost system error: " << e.what() << std::endl;
//                 // std::cerr << "Error code: " << e.code() << " ("
//                 //           << e.code().message() << ")" << e.code().value()
//                 //           << std::endl;
//                 if (e.code().value() == boost::asio::error::eof) {
//                     break;
//                 }
//                 if (e.code().value() == boost::asio::error::bad_descriptor) {
//                     break;
//                 }
//                 if (e.code().value() == boost::asio::error::operation_aborted) {
//                     break;
//                 }
//             }
//             p->lock.lock();
//             p->read_buf.sputc(b);
//             p->lock.unlock();
//         }
//         p->rp.close();
//     }

//     protected:
//     UniStreamPipeUnblocked() : rp(ctx), wp(ctx), stream(&read_buf) {}

//     public:
//     UniStreamPipeUnblocked(std::string cmd)
//         : ctx(), rp(ctx), wp(ctx), stream(&read_buf), r_pos(0), w_pos(0) {
//         std::vector<std::string> args = utils_split_str(cmd, " ");
//         auto exe = boost::process::environment::find_executable(args[0]);
//         args.erase(args.cbegin());
//         p = std::make_unique<boost::process::process>(
//             ctx, exe, args, boost::process::process_stdio{wp, rp, {}});
//         t = std::thread(read_thread, this);
//     }

//     virtual uint32_t read(char *buf, uint32_t len) override {
//         using namespace std::chrono_literals;
//         uint32_t ret = 0, t = 0;
//         while (!eof() && ret < len) {
//             t = read_ub(buf + ret, len - ret);
//             ret += t;
//             if (!t) std::this_thread::sleep_for(1ms);
//         }
//         return ret;
//     }

//     virtual uint32_t read_ub(char *buf, uint32_t len) override {
//         std::lock_guard gd{lock};
//         size_t size = read_buf.size();
//         if (size) stream.clear();
//         if (!stream.eof()) {
//             stream.read(buf, len);
//             len = stream.gcount();
//             r_pos += len;
//             return len;
//         }
//         return 0;
//     }
//     virtual uint32_t write(char const *buf, uint32_t len) override {
//         try {
//             len = wp.write_some(boost::asio::buffer(buf, len));
//             w_pos += len;
//             return len;
//         }
//         catch (...) {
//             return 0;
//         }
//     }
//     virtual bool eof() override {
//         return !(rp.is_open() || read_buf.size());
//     }
//     virtual void close_read() override {
//         try {
//             if (p) p->terminate();
//         }
//         catch (...) {
//         };
//     }
//     virtual void close_write() override {
//         try {
//             wp.close();
//         }
//         catch (...) {
//         };
//     }
//     virtual uint32_t read_offset() override {
//         return r_pos;
//     }
//     virtual uint32_t write_offset() override {
//         return w_pos;
//     }
//     virtual void flush() override {}
//     virtual ~UniStreamPipeUnblocked() {
//         close_write();
//         try {
//             if (p) p->terminate();
//         }
//         catch (...) {
//         };
//         if (t.joinable()) {
//             t.join();
//         }
//     }
// };

// class UniStreamPipe : virtual public UniStreamInterface {
//     boost::asio::io_context ctx;
//     boost::asio::readable_pipe rp;
//     boost::asio::writable_pipe wp;
//     std::unique_ptr<boost::process::process> p;
//     volatile size_t r_pos, w_pos;
//     bool r_eof;

//     public:
//     UniStreamPipe(std::string cmd)
//         : ctx(), rp(ctx), wp(ctx), r_pos(0), w_pos(0) {
//         r_eof = false;
//         std::vector<std::string> args = utils_split_str(cmd, " ");
//         auto exe = boost::process::environment::find_executable(args[0]);
//         args.erase(args.cbegin());
//         p = std::make_unique<boost::process::process>(
//             ctx, exe, args, boost::process::process_stdio{wp, rp, {}});
//     }

//     virtual uint32_t read(char *buf, uint32_t len) override {
//         try {
//             uint32_t ret = rp.read_some(boost::asio::mutable_buffer(buf, len));
//             r_pos += ret;
//             return ret;
//         }
//         catch (...) {
//             if (rp.is_open()) rp.close();
//             r_eof = true;
//             return 0;
//         }
//     }

//     // virtual std::string read_until(char const t) override {
//     //     std::string ret;
//     //     try {
//     //         boost::asio::read_until(rp, boost::asio::dynamic_buffer(ret), t);
//     //         r_pos += ret.size();
//     //     }
//     //     catch (...) {
//     //         if (rp.is_open()) rp.close();
//     //         r_eof = true;
//     //     }
//     //     return ret;
//     // }

//     virtual uint32_t write(char const *buf, uint32_t len) override {
//         try {
//             uint32_t ret = wp.write_some(boost::asio::buffer(buf, len));
//             w_pos += ret;
//             return ret;
//         }
//         catch (...) {
//             return 0;
//         }
//     }
//     virtual bool eof() override {
//         return r_eof;
//     }
//     virtual void close_read() override {
//         try {
//             if (p) p->terminate();
//         }
//         catch (...) {
//         };
//     }
//     virtual void close_write() override {
//         try {
//             wp.close();
//         }
//         catch (...) {
//         };
//     }
//     virtual uint32_t read_offset() override {
//         return r_pos;
//     }
//     virtual uint32_t write_offset() override {
//         return w_pos;
//     }
//     virtual void flush() override {}
//     virtual ~UniStreamPipe() {
//         close_write();
//         close_read();
//     }
// };

/**
 * @brief 一个对象只能单独读或单独写
 */
class UniStreamFile : virtual public UniStreamInterface {
    std::fstream f;
    volatile size_t r_pos, w_pos;

    public:
    UniStreamFile(
        std::string path, std::ios_base::openmode mode = std::ios_base::app)
        : f(path, std::ios_base::binary | std::ios_base::in |
                      std::ios_base::out | mode),
          r_pos(0), w_pos(0) {
        f.seekg(std::ios::beg);
    }
    virtual uint32_t read(char *buf, uint32_t len) override {
        uint32_t ret;
        f.read(buf, len);
        ret = f.gcount();
        r_pos += ret;
        return ret;
    }
    virtual uint32_t read_ub(char *buf, uint32_t len) override {
        return read(buf, len);
    }
    virtual uint32_t write(char const *buf, uint32_t len) override {
        std::ios::pos_type pos = f.tellp(), pos2;
        if (pos == -1) return 0;
        f.write(buf, len);
        pos2 = f.tellp();
        if (pos2 == -1) return 0;
        pos2 -= pos;
        w_pos += pos2;
        return pos2;
    }
    virtual void close_write() override {
        f.close();
    }
    virtual void close_read() override {
        f.close();
    }
    virtual bool eof() override {
        return f.eof();
    }
    virtual uint32_t read_offset() override {
        return r_pos;
    }
    virtual uint32_t write_offset() override {
        return w_pos;
    }
    virtual void flush() override {}
};

class UniStreamMemory : virtual public UniStreamInterface {
    std::unique_ptr<boost::asio::streambuf> mem;
    std::unique_ptr<std::iostream> f;
    volatile size_t r_pos, w_pos;

    public:
    UniStreamMemory() : r_pos(0), w_pos(0) {
        mem = std::make_unique<boost::asio::streambuf>();
        f = std::make_unique<std::iostream>(mem.get());
    }
    virtual uint32_t read(char *buf, uint32_t len) override {
        uint32_t ret;
        f->read(buf, len);
        ret = f->gcount();
        r_pos += ret;
        return ret;
    }
    virtual uint32_t read_ub(char *buf, uint32_t len) override {
        return read(buf, len);
    }
    virtual uint32_t write(char const *buf, uint32_t len) override {
        uint32_t ret;
        ret = mem->sputn(buf, len);
        w_pos += ret;
        return ret;
    }
    virtual void close_write() override {}
    virtual void close_read() override {}
    virtual bool eof() override {
        return f->eof();
    }
    virtual uint32_t read_offset() override {
        return r_pos;
    }
    virtual uint32_t write_offset() override {
        return w_pos;
    }
    virtual void flush() override {}
};

class UniSyncR2W : virtual public UniStreamInterface {
    std::shared_ptr<UniStreamInterface> r;
    std::shared_ptr<UniStreamInterface> w;
    using _T = std::shared_ptr<UniSyncR2W>;

    public:
    template <typename R, typename W>
    UniSyncR2W(R &&r_, W &&w_) {
        // static_assert(std::is_base_of<UniStreamInterface, R>::value ||
        //                   std::is_base_of<UniStreamInterface, W>::value,
        //     "Base is not a base class of Derived");
        // r = std::make_shared<typename std::remove_reference<R>::type>(
        //     std::move(r_));
        // w = std::make_shared<typename std::remove_reference<W>::type>(
        //     std::move(w_));
        r = r_;
        w = w_;
    }

    template <typename R, typename W>
    static _T Make(R &&r_, W &&w_) {
        return std::make_shared<UniSyncR2W>(::UniSyncR2W(r_, w_));
    }

    template <typename R, typename W, typename... Ts>
    static _T Make(R &&r_, W &&w_, Ts &&...args) {
        return Make(Make(r_, w_), args...);
    }

    virtual uint32_t read(char *buf, uint32_t len) override {
        uint32_t ret = r->read(buf, len);
        w->write(buf, ret);
        // w->flush();
        return ret;
    }
    virtual uint32_t read_ub(char *buf, uint32_t len) override {
        uint32_t ret = r->read_ub(buf, len);
        w->write(buf, ret);
        // w->flush();
        return ret;
    }
    virtual uint32_t write(char const *, uint32_t) override {
        return 0;
    }
    virtual void close_write() override {
        w->close_write();
    }
    virtual void close_read() override {
        r->close_read();
        w->close_read();
    }
    virtual bool eof() override {
        return r->eof();
    }
    virtual uint32_t read_offset() override {
        return r->read_offset();
    }
    virtual uint32_t write_offset() override {
        return w->write_offset();
    }
    virtual void flush() override {
        w->flush();
    }
};