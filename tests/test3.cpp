#include "boost/asio/basic_readable_pipe.hpp"
#include "boost/asio/buffer.hpp"
#include "boost/asio/buffered_stream.hpp"
#include "boost/asio/error.hpp"
#include "boost/asio/io_context.hpp"
#include "boost/asio/read_until.hpp"
#include "boost/asio/readable_pipe.hpp"
#include "boost/asio/streambuf.hpp"
#include "boost/asio/writable_pipe.hpp"
#include "boost/exception/exception.hpp"
#include "boost/process/popen.hpp"
#include "boost/process/v2/popen.hpp"
#include "boost/system/system_error.hpp"
#include "mutils.h"
#include "unistream.h"
#include <boost/asio.hpp>
#include <boost/process/v2/environment.hpp>
#include <boost/process/v2/process.hpp>
#include <boost/process/v2/stdio.hpp>
#include <cstddef>
#include <cstdio>
#include <exception>
#include <fstream>
#include <initializer_list>
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

int main() {
    // asio::io_context ctx;
    // asio::readable_pipe rp{ctx};
    // asio::writable_pipe wp{ctx};
    // auto exe = process::environment::find_executable("tshark");
    // process::process p(
    //     ctx, exe, {"-r", "-"}, process::process_stdio{wp, rp, {}});
    // std::fstream f("dump_data/test.out", std::ios_base::binary|
    // std::ios_base::out);
    std::string path = "dump_data/capture.pcapng";
    auto mem = std::make_shared<UniStreamPipe>("tshark -r " + path);
    auto mem2 = std::make_shared<UniStreamMemory>();
    auto file = std::make_shared<UniStreamFile>("dump_data/out.txt");
    auto file2 = std::make_shared<UniStreamFile>("dump_data/out1.txt");
    auto file3 = std::make_shared<UniStreamFile>("dump_data/out2.txt");
    auto pipe = UniSyncR2W::Make(mem, file2, file3, file);
    // size_t len;
    // char data[1024];
    // while (!f.eof()) {
    //     f.read(data, 1024);
    //     len = f.gcount();
    //     pipe.write(data, len);
    //     // len = pipe.read(data, 1024);
    //     // fwrite(data, 1, len, stdout);
    //     // fflush(stdout);
    // }
    // pipe.write_eof();
    std::string cmd;
    while (!pipe->read_eof()) {
        cmd = pipe->read_until('\n');
        std::cout << cmd;
    }
    // auto file2 = std::make_shared<UniStreamFile>("dump_data/out.txt",
    // std::ios::trunc); while (!file2->read_eof()) {
    //     std::cout << file2->read_util('\n');
    // }

    // asio::streambuf read_buf;
    // // std::stringbuf read_buf;
    // std::iostream stream{&read_buf};
    // std::mutex lock;
    // volatile size_t pos = 0, rpos = 0;

    // auto get = [&]() {
    //     char b;
    //     while (true) {
    //         try {
    //             rp.read_some(asio::mutable_buffer(&b, 1));
    //         }
    //         catch (boost::system::system_error &e) {
    //             std::cerr << std::endl
    //                       << "Boost system error: " << e.what() << std::endl;
    //             std::cerr << "Error code: " << e.code() << " ("
    //                       << e.code().message() << ")" << e.code().value()
    //                       << std::endl;
    //             if (e.code().value() == asio::error::eof) {
    //                 break;
    //             }
    //             if (e.code().value() == asio::error::bad_descriptor) {
    //                 break;
    //             }
    //             if (e.code().value() == asio::error::operation_aborted) {
    //                 break;
    //             }
    //         }
    //         lock.lock();
    //         read_buf.sputc(b);
    //         pos++;
    //         lock.unlock();
    //     }
    //     rp.close();
    // };

    // std::thread t;
    // t = std::thread(get);

    // char *data = new char[700000];
    // auto print = [&]() {
    //     std::lock_guard gd{lock};
    //     size_t size = read_buf.size();
    //     size_t len;
    //     if (size) stream.clear();
    //     while (!stream.eof()) {
    //         stream.read(data, 10000);
    //         len = stream.gcount();
    //         rpos += len;
    //         // fwrite(data, 1, len, stdout);
    //         // fflush(stdout);
    //         std::cout << rpos << std::endl;
    //     }
    // };
    // while (!f.eof()) {
    //     f.read(data, 1024);
    //     size_t len = f.gcount();
    //     wp.write_some(asio::buffer(data, len));
    // }
    // wp.close();
    // // int i = 10000000;
    // // while(i--) ;
    // while (rp.is_open() || read_buf.size()) {
    //     // std::cout << rp.is_open() << std::endl;
    //     print();
    // }
    // // print();
    // t.join();
    return 0;
}