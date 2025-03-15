#include "unistream.h"
#include <cstddef>
#include <cstring>
#include <exception>
#include <ios>
#include <ostream>
#include <string>
#include <winnt.h>

void test_tshark_read() {
    // UniStreamPipeUnblocked pipes("tshark -r -");
    UniStreamDualPipeU pipes("tshark -i -");

    std::ifstream f("test_data/data.pcapng", std::ios_base::binary);
    char *data = new char[1024];
    // f.seekg(std::ios::end);
    // int s = f.tellg();
    // f.seekg(std::ios::beg);
    // std::cout << s << std::endl;
    while (!f.eof()) {
        f.read(data, 100);
        size_t len = f.gcount();
        size_t wt = 0;
        while (wt != len && pipes.alive()) {
            wt += pipes.write(data + wt, len - wt);
            // std::cout << pipes.write_offset() << std::endl;
        }
        // len = pipes.read_ub(data, 1024);
        // std::cout.write(data, len);
        // std::cout.flush();
        // std::cout << "S" << pipes.alive() << std::endl;
    }
    pipes.close_write();
    // pipes.terminate();

    while (!pipes.eof()) {
        size_t len;
        len = pipes.read_ub(data, 1024);
        // if (len == -1ull) {
        //     perror(strerror(errno));
        //     break;
        // }
        std::cout.write(data, len);
        std::cout.flush();
    }
    delete[] data;
}

void windows_test_pipe() {
    UniStreamDualPipeU pipe{"cmd"};
    std::string cmd = "echo nmsl\n";
    pipe.write(cmd.c_str(), cmd.size());
    pipe.close_write();
    while (!pipe.eof()) {
        char buf[512];
        int ret;
        ret = pipe.read_ub(buf, 512);
        std::cout.write(buf, ret);
        std::cout.flush();
    }
}

int main() {
    try {
        test_tshark_read();
        // windows_test_pipe();
    }
    catch (std::exception e) {
        std::cout << e.what() << std::endl;
    }
    return 0;
}