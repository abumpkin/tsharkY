#include "unistream.h"

int main() {
    // UniStreamPipeUnblocked pipes("tshark -r -");
    UniStreamDualPipeU pipes("tshark -r -");

    std::fstream f("test_data/data.pcapng");
    char *data = new char[1024];
    while (!f.eof()) {
        f.read(data, 1024);
        size_t len = f.gcount();
        pipes.write(data, len);
        // len = pipes.read(data, 1024);
        // std::cout.write(data, len);
        // std::cout.flush();
    }
    pipes.close_write();

    while (!pipes.eof()) {
        size_t len;
        len = pipes.read(data, 1024);
        // if (len == -1ull) {
        //     perror(strerror(errno));
        //     break;
        // }
        std::cout.write(data, len);
        std::cout.flush();
    }
    delete[] data;
    return 0;
}