#include "unistream.h"

int main() {
    UniStreamPipeUnblocked pipes("tshark -r -");

    std::fstream f("test_data/data.pcapng");
    char *data = new char[1024];
    while (!f.eof()) {
        f.read(data, 1024);
        size_t len = f.gcount();
        pipes.write(data, len);
    }
    pipes.write_eof();
    std::cout << pipes.read_until_eof() << std::endl;
    return 0;
}