#include "streambuf.h"
#include <iostream>

int main() {
    StreamBuf<1> buf;
    buf.write("abcdefg123f", 11);
    std::cout << buf.try_read_util("f") << std::endl;
    std::cout << buf.find("f") << std::endl;
    std::cout << buf.size() << std::endl;
    std::cout << buf.try_read_util("f") << std::endl;
    return 0;
}