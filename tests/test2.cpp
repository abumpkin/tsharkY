#include <istream>
#include <sstream>
#include <streambuf>
#include <string>
#include <iostream>
#include "boost/asio/streambuf.hpp"


int main() {
    std::stringbuf buf;
    boost::asio::streambuf sbuf;
    std::iostream s(&sbuf);

    std::cout.setf(std::ios::boolalpha);
    s << "ni hao 1213";
    std::string t;
    s >> t;
    // std::cout << t << std::endl;
    std::cout << (char*)sbuf.data().data() << sbuf.size() << std::endl;
    s >> t;
    std::cout << t << std::endl;
    std::cout << s.fail() << std::endl;
    s >> t;
    std::cout << t << std::endl;
    std::cout << s.fail() << std::endl;
    std::cout << s.eof() << std::endl;
    s.clear();
    s.write("fff", 3);
    std::cout << s.fail() << std::endl;
    std::cout << s.eof() << std::endl;
    s >> t;
    std::cout << t << std::endl;
    std::cout << s.fail() << std::endl;
    std::cout << s.eof() << std::endl;
    std::cout << buf.str() << std::endl;
}