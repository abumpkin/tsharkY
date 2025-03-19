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
#include "mutils.h"
#include "streambuf.h"
#include <condition_variable>
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
#include <winbase.h>
#include <winnt.h>
#include <shlwapi.h> // PathFindOnPath
#include <windows.h>
#include <errhandlingapi.h>
#include <handleapi.h>
#include <minwinbase.h>
#include <minwindef.h>
#include <namedpipeapi.h>
#else
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

struct UniStreamInterface {
    UniStreamInterface() = default;
    UniStreamInterface(UniStreamInterface &) = delete;
    UniStreamInterface &operator=(UniStreamInterface &) = delete;
    UniStreamInterface(UniStreamInterface &&) = delete;
    UniStreamInterface &operator=(UniStreamInterface &&) = delete;
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
    public:
    size_t real_w_pos;

    private:
    volatile size_t r_pos, w_pos;
    bool eof_f = false;
#ifdef _WIN32
    OVERLAPPED read_con_ctx;
    std::unique_ptr<OVERLAPPED> read_read_ctx;
    static const HANDLE hNull;
    // 子进程句柄
    HANDLE hProcess = nullptr;
    HANDLE hThread = nullptr;
    HANDLE hReadPipeOut = nullptr, hWritePipeOut = nullptr; // 子进程输出管道
    HANDLE hReadPipeIn = nullptr, hWritePipeIn = nullptr;   // 子进程输入管道

    //
    std::string nwpipe_name;
    std::string nrpipe_name;
    bool nwpipe_con = false;
    bool nrpipe_con = false;
    // HANDLE npipe = nullptr;

#else
    pid_t pid = -1;
    int childStdout = -1;
    int childStdin = -1;
#endif

#ifdef _WIN32
    // 检查管道名称是否可用
    bool is_pipe_available(std::string pname) {
        HANDLE hTest = CreateFile(pname.c_str(), GENERIC_READ | GENERIC_WRITE,
            0, nullptr, OPEN_EXISTING, 0, nullptr);

        if (hTest != INVALID_HANDLE_VALUE) {
            CloseHandle(hTest);
            return false;
        }
        return GetLastError() == ERROR_FILE_NOT_FOUND;
    }
    std::string GenerateUniquePipeName() {
        UUID uuid;
        std::string name;
        do {
            RPC_STATUS status = UuidCreate(&uuid);
            if (status != RPC_S_OK && status != RPC_S_UUID_LOCAL_ONLY) {
                throw std::runtime_error("UuidCreate failed");
            }

            CHAR *str;
            if (UuidToString(&uuid, (RPC_CSTR *)&str) != RPC_S_OK) {
                throw std::runtime_error("UuidToStringW failed");
            }

            name = "\\\\.\\pipe\\" + std::string(str).substr(0, 8);
            RpcStringFree((RPC_CSTR *)&str);
        } while (!is_pipe_available(name));
        return name;
    }
    HANDLE create_wpipe(std::string name) {
        HANDLE ret = CreateNamedPipe(name.c_str(),
            PIPE_ACCESS_OUTBOUND, // 单向写入模式
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,    // 最大实例数
            0,    // 输出缓冲区大小（只写管道不需要）
            4096, // 输入缓冲区大小
            0,    // 默认超时
            nullptr);

        if (ret == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("Failed to create named pipe");
        }
        return ret;
    }
    HANDLE create_rpipe(std::string name) {
        HANDLE ret = CreateNamedPipe(name.c_str(),
            PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED, // 异步读模式
            PIPE_TYPE_BYTE | PIPE_WAIT,
            1,    // 单实例
            4096, // 输出缓冲区大小
            4096, // 输入缓冲区大小
            0,    // 默认超时
            NULL  // 默认安全属性
        );
        if (ret == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("Failed to create named pipe");
        }
        return ret;
    }

    // 规范化命令行
    std::string normalize(std::string cmd, std::string pl) {
        std::istringstream iss(cmd);
        std::string token;
        std::string normalizedCmd;
        bool isFirst = true;

        while (iss >> std::quoted(token)) {
            // 第一个 token（可执行文件路径）
            if (isFirst) {
                char buffer[MAX_PATH + 1] = {};
                ::memcpy_s(
                    buffer, ARRAYSIZE(buffer), token.data(), token.size());
                if (PathFindOnPathA(buffer, nullptr)) {
                    token = buffer;
                }
                else {
                    std::string t = token + ".exe";
                    memset(buffer, 0, ARRAYSIZE(buffer));
                    ::memcpy_s(buffer, ARRAYSIZE(buffer), t.data(), t.size());
                    if (PathFindOnPathA(buffer, nullptr)) {
                        token = buffer;
                    }
                }
                // 如果是相对路径或仅是程序名
                if (PathIsRelativeA(token.c_str())) {
                    if (PathFileExistsA(token.c_str())) {
                        // 转换为绝对路径
                        GetFullPathNameA(
                            token.c_str(), MAX_PATH, buffer, nullptr);
                        token = buffer;
                    }
                    if (PathFileExistsA((token + ".exe").c_str())) {
                        // 转换为绝对路径
                        GetFullPathNameA((token + ".exe").c_str(), MAX_PATH,
                            buffer, nullptr);
                        token = buffer;
                    }
                }
                if (token.find(' ') != std::string::npos ||
                    token.find('"') != std::string::npos) {
                    normalizedCmd += "\"" + token + "\"";
                }
                else {
                    normalizedCmd += token;
                }
                isFirst = false;
            }
            // 其余部分（参数）
            else {
                normalizedCmd += " ";
                if (token.find(' ') != std::string::npos ||
                    token.find('"') != std::string::npos) {
                    normalizedCmd += "\"" + token + "\"";
                }
                else {
                    if (token == pl) {
                        nwpipe_name = GenerateUniquePipeName();
                        token = nwpipe_name;
                    }
                    normalizedCmd += token;
                }
            }
        }
        return normalizedCmd;
    }
#endif
    protected:
    UniStreamDualPipeU() {}

    std::unique_ptr<std::thread> t_write;
    std::mutex t_m;
    std::condition_variable cv;
    bool t_stop_ctl, t_flush_ctl;
    StreamBuf<4096, 1000> write_buffer;
    static void write_thread(UniStreamDualPipeU *p) {
        utils_set_priority(6);
        using namespace std::chrono_literals;
        p->real_w_pos = 0;
        auto exe_write = [&]() {
            auto data = p->write_buffer.try_read(4096);
            if (data) {
                p->real_w_pos += p->_write(data->data, data->len);
            }
            data.reset();
        };
        while (!p->t_stop_ctl && p->alive()) {
            // std::unique_lock<std::mutex> lock(p->t_m);
            // LOG_F(INFO, "Write Wait!");
            // p->cv.wait_for(lock, 100ms, [&] {
            //     return p->write_buffer.size() > 2 || p->t_flush_ctl;
            // });
            // lock.unlock();
            if (p->write_buffer.block_count() < 2 && !p->t_flush_ctl) {
                std::this_thread::sleep_for(10ms);
            }
            exe_write();
            if (p->t_flush_ctl) {
                while (p->write_buffer.size()) {
                    exe_write();
                }
                p->t_flush_ctl = false;
                p->cv.notify_one();
            }
            // LOG_F(INFO, "Write Start!");
            // std::this_thread::yield();
        }
        LOG_F(INFO, "Uni Write Exit! a: %d", p->alive());
    }

    public:
    UniStreamDualPipeU(
        const std::string &command, std::string np_placeholder = "")
        : r_pos(0), w_pos(0), t_stop_ctl(false), t_flush_ctl(false) {
#ifdef _WIN32
        nwpipe_name.clear();
        nwpipe_con = false;
        std::string cmd = normalize(command, np_placeholder);
        SECURITY_ATTRIBUTES saAttr;
        saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
        saAttr.bInheritHandle = TRUE; // 管道句柄可继承
        saAttr.lpSecurityDescriptor = nullptr;

        // std::cout << cmd << std::endl;
        // 子进程输出
        // if (!CreatePipe(&hReadPipeOut, &hWritePipeOut, &saAttr, 0)) {
        //     throw std::runtime_error("Failed to create stdout pipe");
        // }
        ZeroMemory(&read_con_ctx, sizeof(OVERLAPPED));
        read_con_ctx.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        nrpipe_con = false;
        nrpipe_name = GenerateUniquePipeName();
        hReadPipeOut = create_rpipe(nrpipe_name);
        hWritePipeOut = CreateFile( //
            nrpipe_name.c_str(),    //
            GENERIC_WRITE,          //
            0,                      //
            &saAttr,                //
            OPEN_EXISTING,          //
            FILE_ATTRIBUTE_NORMAL,  //
            NULL                    //
        );
        if (hWritePipeOut == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "CreateFile failed, error=%lu\n", GetLastError());
            CloseHandle(hReadPipeOut);
            throw std::runtime_error("Failed to create stdout pipe");
        }

        // 子进程输入
        if (!nwpipe_name.empty()) {
            hWritePipeIn = create_wpipe(nwpipe_name);
            // if (!ConnectNamedPipe(hWritePipeIn, nullptr)) {
            //     DWORD error = GetLastError();
            //     if (error != ERROR_PIPE_CONNECTED) {
            //         CloseHandle(hWritePipeIn);
            //         TerminateProcess(hProcess, 1);
            //         throw std::runtime_error(
            //             "Pipe connection failed: " + std::to_string(error));
            //     }
            // }
        }
        else {
            if (!CreatePipe(&hReadPipeIn, &hWritePipeIn, &saAttr, 0)) {
                throw std::runtime_error("Failed to create stdin pipe");
            }
        }

        // 创建子进程
        STARTUPINFO si;
        PROCESS_INFORMATION pi;

        ZeroMemory(&si, sizeof(si));
        ZeroMemory(&pi, sizeof(pi));
        si.cb = sizeof(si);
        si.hStdError = hNull; // hWritePipeOut;
        si.hStdOutput = hWritePipeOut;
        if (nwpipe_name.empty()) si.hStdInput = hReadPipeIn;
        si.dwFlags |= STARTF_USESTDHANDLES;
        si.wShowWindow = SW_HIDE;

        if (!CreateProcess(nullptr,                      // 应用程序名称
                (LPSTR)cmd.c_str(),                      // 命令行
                nullptr,                                 // 进程安全属性
                nullptr,                                 // 线程安全属性
                TRUE,                                    // 继承句柄
                /*CREATE_NEW_CONSOLE*/ CREATE_NO_WINDOW, // 创建标志
                nullptr,                                 // 环境变量
                nullptr,                                 // 当前目录
                &si,                                     // STARTUPINFO
                &pi)) {                                  // PROCESS_INFORMATION
            throw std::runtime_error("Failed to create subprocess");
        }

        // 设置读管道为非阻塞模式
        // DWORD dwMode = PIPE_NOWAIT; // 非阻塞模式
        // if (!SetNamedPipeHandleState(hReadPipeOut, &dwMode, nullptr,
        // nullptr)) {
        //     throw std::runtime_error("Failed to configure pipe");
        // }
        // 关闭不需要的句柄
        CloseHandle(hWritePipeOut);
        if (hReadPipeIn) CloseHandle(hReadPipeIn);

        hProcess = pi.hProcess;
        hThread = pi.hThread;

        // 等待连接
        if (!ConnectNamedPipe(hReadPipeOut, &read_con_ctx)) {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                fprintf(stderr, "ConnectNamedPipe failed, error=%lu\n", err);
                CloseHandle(hReadPipeOut);
                throw std::runtime_error("Failed to create subprocess");
            }
            else if (err == ERROR_PIPE_CONNECTED) {
                // 客户端已提前连接，直接标记事件为已触发
                SetEvent(read_con_ctx.hEvent);
            }
            else {
                // 等待连接完成
                DWORD waitResult =
                    WaitForSingleObject(read_con_ctx.hEvent, 10000);
                if (waitResult != WAIT_OBJECT_0) {
                    fprintf(stderr, "等待连接失败\n");
                    CloseHandle(hReadPipeOut);
                    throw std::runtime_error("Failed to create subprocess");
                }
            }
        }
        CloseHandle(read_con_ctx.hEvent);
#else
        np_placeholder.clear();
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
        t_write = std::make_unique<std::thread>(write_thread, this);
    }

    virtual ~UniStreamDualPipeU() {
        terminate();
        if (t_write) {
            t_stop_ctl = true;
            t_write->join();
            t_write.reset();
        }
    }

    bool alive() {
#ifdef _WIN32
        DWORD exitCode;
        if (!hProcess) return false;
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
#ifdef _WIN32
        // using namespace std::chrono_literals;
        // while (read_read_ctx) {
        //     std::this_thread::sleep_for(1ms);
        // }
        if (!nwpipe_name.empty() && hWritePipeIn)
            DisconnectNamedPipe(hWritePipeIn);
        if (hReadPipeOut) {
            DisconnectNamedPipe(hReadPipeOut);
            CloseHandle(hReadPipeOut);
            hReadPipeOut = nullptr;
        }
        try {
            if (hWritePipeIn) {
                CloseHandle(hWritePipeIn);
                hWritePipeIn = nullptr;
            }
        }
        catch (...) {
        }
        if (hProcess) {
            TerminateProcess(hProcess, 0);
            CloseHandle(hProcess);
            hProcess = nullptr;
        }
        if (hThread) {
            CloseHandle(hThread);
            hThread = nullptr;
        }
#else
        if (pid > 0) {
            close(childStdout);
            close(childStdin);
            kill(pid, SIGTERM);
            kill(pid, SIGKILL);
            waitpid(pid, nullptr, 0);
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
        DWORD bytesRead = 0;
        if (eof_f) return 0;
        if (!read_read_ctx) {
            read_read_ctx = std::make_unique<OVERLAPPED>();
            ZeroMemory(read_read_ctx.get(), sizeof(OVERLAPPED));
            if (!ReadFile(
                    hReadPipeOut, buf, len, &bytesRead, read_read_ctx.get())) {
                DWORD err = GetLastError();
                if (err == ERROR_IO_PENDING) {
                    // 等待结果
                    return 0;
                }
                else if (err == ERROR_BROKEN_PIPE) {
                    // 管道已关闭
                    eof_f = true;
                    return 0;
                }
                else {
                    fprintf(stderr, "ReadFile failed, error=%lu\n", err);
                    eof_f = true;
                }
            }
            else {
                // 立即读取成功
                read_read_ctx.reset();
                r_pos += bytesRead;
                return bytesRead;
            }
        }
        else {
            // 非阻塞检查操作状态
            BOOL result = GetOverlappedResult(
                hReadPipeOut, read_read_ctx.get(), &bytesRead, FALSE);
            DWORD err = GetLastError();
            if (result) {
                // 收到数据
                read_read_ctx.reset();
                r_pos += bytesRead;
                return bytesRead;
            }
            else if (err == ERROR_IO_INCOMPLETE) {
                // 操作未完成，稍作延迟后继续检查
                return 0;
            }
            else {
                if (err == ERROR_BROKEN_PIPE) {
                    // EOF
                    eof_f = true;
                }
                else {
                    // 读取错误
                    eof_f = true;
                }
            }
        }
        return 0;
        ////////////////////////////
        // if (ReadFile(hReadPipeOut, buf, static_cast<DWORD>(len), &bytesRead,
        //         nullptr)) {
        //     if (!bytesRead) {
        //         eof_f = true;
        //     }
        //     r_pos += bytesRead;
        //     return bytesRead;
        // }
        // else {
        //     if (GetLastError() != ERROR_NO_DATA) {
        //         LOG_F(WARNING, "E: %ld", GetLastError());
        //         eof_f = true;
        //     }
        //     if (GetLastError() == ERROR_HANDLE_EOF ||
        //         GetLastError() == ERROR_BROKEN_PIPE) {}
        // }
        // return 0;
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

    virtual uint32_t _write(const char *buf, uint32_t len) {
        if (!alive()) return 0;
#ifdef _WIN32
        DWORD bytesWritten;
        if (!hWritePipeIn) return 0;
        if (!nwpipe_name.empty() && !nwpipe_con) {
            if (!ConnectNamedPipe(hWritePipeIn, nullptr)) {
                // if (npipe_con) eof_f = true;
            }
            nwpipe_con = true;
        }
        if (WriteFile(hWritePipeIn, buf, static_cast<DWORD>(len), &bytesWritten,
                nullptr)) {
            w_pos += bytesWritten;
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

    virtual uint32_t write(const char *buf, uint32_t len) override {
        if (!alive()) return 0;
        // LOG_F(INFO, "M Write Lock!");
        // std::unique_lock<std::mutex> lock(t_m, std::defer_lock);
        // LOG_F(INFO, "M Write Wait!");
        // while (!lock.try_lock()) {
        //     std::this_thread::yield();
        // }
        write_buffer.write(buf, len);
        // LOG_F(INFO, "M Write notify!");
        // cv.notify_one();
        return len;

        // if (!alive()) return 0;
        // #ifdef _WIN32
        //         DWORD bytesWritten;
        //         if (!hWritePipeIn) return 0;
        //         if (!nwpipe_name.empty() && !nwpipe_con) {
        //             if (!ConnectNamedPipe(hWritePipeIn, nullptr)) {
        //                 // if (npipe_con) eof_f = true;
        //             }
        //             nwpipe_con = true;
        //         }
        //         if (WriteFile(hWritePipeIn, buf, static_cast<DWORD>(len),
        //         &bytesWritten,
        //                 nullptr)) {
        //             w_pos += bytesWritten;
        //             return bytesWritten;
        //         }
        //         return 0;
        // #else
        //         size_t ret = ::write(childStdin, buf, len);
        //         if (ret == -1ull) return 0;
        //         w_pos += ret;
        //         return ret;
        // #endif
    }

    virtual void flush() override {
        t_flush_ctl = true;
#ifdef _WIN32
        // Windows平台：调用FlushFileBuffers刷新管道
        if (hWritePipeIn) FlushFileBuffers(hWritePipeIn);
#else
        // Linux平台：调用fsync刷新文件描述符
        fsync(childStdin);
#endif
    }

    virtual void close_write() override {
        using namespace std::chrono_literals;
        t_flush_ctl = true;
        flush();
        std::unique_lock<std::mutex> lock(t_m);
        cv.wait_for(lock, 10s, [this] {
            return !t_flush_ctl;
        });
        t_stop_ctl = true;
#ifdef _WIN32
        // Windows平台：关闭写入管道的句柄
        if (hWritePipeIn != nullptr) {
            if (!nwpipe_name.empty()) {
                DisconnectNamedPipe(hWritePipeIn);
            }
            CloseHandle(hWritePipeIn);
            hWritePipeIn = nullptr;
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

#ifdef WIN32
inline const HANDLE UniStreamDualPipeU::hNull = ([]() -> HANDLE {
    return CreateFile(
        "NUL", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
})();
#endif

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
        return std::make_shared<UniSyncR2W>(r_, w_);
    }

    template <typename R, typename W, typename... Ts>
    static _T Make(R &&r_, W &&w_, Ts &&...args) {
        return Make(Make(r_, w_), args...);
    }

    virtual uint32_t read(char *buf, uint32_t len) override {
        uint32_t ret = r->read(buf, len);
        if (w) w->write(buf, ret);
        // w->flush();
        return ret;
    }
    virtual uint32_t read_ub(char *buf, uint32_t len) override {
        uint32_t ret = r->read_ub(buf, len);
        if (w) w->write(buf, ret);
        // w->flush();
        return ret;
    }
    virtual uint32_t write(char const *, uint32_t) override {
        return 0;
    }
    virtual void close_write() override {
        if (w) w->close_write();
    }
    virtual void close_read() override {
        r->close_read();
        if (w) w->close_read();
    }
    virtual bool eof() override {
        return r->eof();
    }
    virtual uint32_t read_offset() override {
        return r->read_offset();
    }
    virtual uint32_t write_offset() override {
        if (!w) return 0;
        return w->write_offset();
    }
    virtual void flush() override {
        if (w) w->flush();
    }
};