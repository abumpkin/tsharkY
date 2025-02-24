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
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <ios>
#include <iostream>
#include <istream>
#include <memory>
#include <mutex>
#include <mutils.h>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

struct UniStreamInterface {
    UniStreamInterface() = default;
    UniStreamInterface(UniStreamInterface &) = delete;
    UniStreamInterface &operator=(UniStreamInterface &) = delete;
    UniStreamInterface(UniStreamInterface &&) = default;
    UniStreamInterface &operator=(UniStreamInterface &&) = default;
    virtual uint32_t read(char *buf, uint32_t len) = 0;
    virtual uint32_t write(char const *buf, uint32_t len) = 0;
    virtual void write_eof() = 0;
    virtual bool read_eof() = 0;
    virtual uint32_t read_offset() = 0;
    virtual uint32_t write_offset() = 0;

    virtual std::string read_util(char const t) {
        char rd;
        std::stringbuf buf;
        while (!read_eof()) {
            if (read(&rd, 1)) {
                buf.sputc(rd);
                if (rd == t) return buf.str();
            }
        }
        return buf.str();
    }

    virtual std::string read_util_eof() {
        size_t rd;
        char buf[512];
        std::string ret;
        while (!read_eof()) {
            rd = read(buf, sizeof(buf));
            ret.append(buf, rd);
        }
        return ret;
    }

    virtual uint32_t read_to_null(uint32_t len) {
        char buf[1024];
        if (read_eof()) return 0;
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

class UniStreamPipeUnblocked : public UniStreamInterface {
    boost::asio::io_context ctx;
    boost::asio::readable_pipe rp;
    boost::asio::writable_pipe wp;
    std::unique_ptr<boost::process::process> p;
    std::mutex lock;
    boost::asio::streambuf read_buf;
    // std::stringbuf read_buf;
    std::iostream stream;
    std::thread t;
    volatile size_t rpos, wpos;

    static void read_thread(UniStreamPipeUnblocked *const p) {
        char b;
        while (true) {
            try {
                p->rp.read_some(boost::asio::mutable_buffer(&b, 1));
            }
            catch (boost::system::system_error &e) {
                // std::cerr << std::endl
                //           << "Boost system error: " << e.what() << std::endl;
                // std::cerr << "Error code: " << e.code() << " ("
                //           << e.code().message() << ")" << e.code().value()
                //           << std::endl;
                if (e.code().value() == boost::asio::error::eof) {
                    break;
                }
                if (e.code().value() == boost::asio::error::bad_descriptor) {
                    break;
                }
                if (e.code().value() == boost::asio::error::operation_aborted) {
                    break;
                }
            }
            p->lock.lock();
            p->read_buf.sputc(b);
            p->lock.unlock();
        }
        p->rp.close();
    }

    public:
    UniStreamPipeUnblocked(std::string cmd)
        : ctx(), rp(ctx), wp(ctx), stream(&read_buf), rpos(0), wpos(0) {
        std::vector<std::string> args = utils_split_str(cmd, " ");
        auto exe = boost::process::environment::find_executable(args[0]);
        args.erase(args.cbegin());
        p = std::make_unique<boost::process::process>(
            ctx, exe, args, boost::process::process_stdio{wp, rp, {}});
        t = std::thread(read_thread, this);
    }
    virtual uint32_t read(char *buf, uint32_t len) override {
        std::lock_guard gd{lock};
        size_t size = read_buf.size();
        if (size) stream.clear();
        if (!stream.eof()) {
            stream.read(buf, len);
            len = stream.gcount();
            rpos += len;
            return len;
        }
        return 0;
    }
    virtual uint32_t write(char const *buf, uint32_t len) override {
        try {
            len = wp.write_some(boost::asio::buffer(buf, len));
            wpos += len;
            return len;
        }
        catch (...) {
            return 0;
        }
    }
    virtual bool read_eof() override {
        return !(rp.is_open() || read_buf.size());
    }
    virtual void write_eof() override {
        try {
            wp.close();
        }
        catch (...) {
        };
    }
    virtual uint32_t read_offset() override { return rpos; }
    virtual uint32_t write_offset() override { return wpos; }
    ~UniStreamPipeUnblocked() {
        write_eof();
        try {
            if (p) p->terminate();
        }
        catch (...) {
        };
        if (t.joinable()) {
            t.join();
        }
    }
};

class UniStreamPipe : public UniStreamInterface {
    boost::asio::io_context ctx;
    boost::asio::readable_pipe rp;
    boost::asio::writable_pipe wp;
    std::unique_ptr<boost::process::process> p;
    volatile size_t rpos, wpos;
    bool reof;

    public:
    UniStreamPipe(std::string cmd) : ctx(), rp(ctx), wp(ctx), rpos(0), wpos(0) {
        reof = false;
        std::vector<std::string> args = utils_split_str(cmd, " ");
        auto exe = boost::process::environment::find_executable(args[0]);
        args.erase(args.cbegin());
        p = std::make_unique<boost::process::process>(
            ctx, exe, args, boost::process::process_stdio{wp, rp, {}});
    }
    virtual uint32_t read(char *buf, uint32_t len) override {
        try {
            uint32_t ret = rp.read_some(boost::asio::mutable_buffer(buf, len));
            rpos += ret;
            return ret;
        }
        catch (...) {
            if (rp.is_open()) rp.close();
            reof = true;
            return 0;
        }
    }
    virtual std::string read_util(char const t) override {
        std::string ret;
        try {
            boost::asio::read_until(rp, boost::asio::dynamic_buffer(ret), t);
            rpos += ret.size();
        }
        catch (...) {
            if (rp.is_open()) rp.close();
            reof = true;
        }
        return ret;
    }
    virtual uint32_t write(char const *buf, uint32_t len) override {
        try {
            uint32_t ret = wp.write_some(boost::asio::buffer(buf, len));
            wpos += ret;
            return ret;
        }
        catch (...) {
            return 0;
        }
    }
    virtual bool read_eof() override { return reof; }
    virtual void write_eof() override {
        try {
            wp.close();
        }
        catch (...) {
        };
    }
    virtual uint32_t read_offset() override { return rpos; }
    virtual uint32_t write_offset() override { return wpos; }
    ~UniStreamPipe() { write_eof(); }
};

/**
 * @brief 一个对象只能单独读或单独写
 */
class UniStreamFile : public UniStreamInterface {
    std::fstream f;
    volatile size_t rpos, wpos;

    public:
    UniStreamFile(
        std::string path, std::ios_base::openmode mode = std::ios_base::app)
        : f(path, std::ios_base::binary | std::ios_base::in |
                      std::ios_base::out | mode),
          rpos(0), wpos(0) {
        f.seekg(std::ios::beg);
    }
    virtual uint32_t read(char *buf, uint32_t len) override {
        uint32_t ret;
        f.read(buf, len);
        ret = f.gcount();
        rpos += ret;
        return ret;
    }
    virtual uint32_t write(char const *buf, uint32_t len) override {
        std::ios::pos_type pos = f.tellp(), pos2;
        if (pos == -1) return 0;
        f.write(buf, len);
        pos2 = f.tellp();
        if (pos2 == -1) return 0;
        pos2 -= pos;
        wpos += pos2;
        return pos2;
    }
    virtual void write_eof() override { f.close(); }
    virtual bool read_eof() override { return f.eof(); }
    virtual uint32_t read_offset() override { return rpos; }
    virtual uint32_t write_offset() override { return wpos; }
};

class UniStreamMemory : public UniStreamInterface {
    std::unique_ptr<boost::asio::streambuf> mem;
    std::unique_ptr<std::iostream> f;
    volatile size_t rpos, wpos;

    public:
    UniStreamMemory() : rpos(0), wpos(0) {
        mem = std::make_unique<boost::asio::streambuf>();
        f = std::make_unique<std::iostream>(mem.get());
    }
    virtual uint32_t read(char *buf, uint32_t len) override {
        uint32_t ret;
        f->read(buf, len);
        ret = f->gcount();
        rpos += ret;
        return ret;
    }
    virtual uint32_t write(char const *buf, uint32_t len) override {
        uint32_t ret;
        ret = mem->sputn(buf, len);
        wpos += ret;
        return ret;
    }
    virtual void write_eof() override {}
    virtual bool read_eof() override { return f->eof(); }
    virtual uint32_t read_offset() override { return rpos; }
    virtual uint32_t write_offset() override { return wpos; }
};

class UniSyncR2W : public UniStreamInterface {
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
        return ret;
    }
    virtual uint32_t write(char const *, uint32_t) override { return 0; }
    virtual void write_eof() override { w->write_eof(); }
    virtual bool read_eof() override { return r->read_eof(); }
    virtual uint32_t read_offset() override { return r->read_offset(); }
    virtual uint32_t write_offset() override { return w->write_offset(); }
};