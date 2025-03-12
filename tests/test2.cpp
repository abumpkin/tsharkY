
#include <cstring>
#include <iostream>
#include <pugixml.hpp>
#include <string>
#include <traffic_statistics.h>
#include <unistream.h>

void integrate() {
    std::string file = "dump_data/pdml.xml";

    std::string xml = UniStreamFile(file).read_until_eof();
    PacketDefineDecode p(xml);
    std::cout << p.to_json(true) << std::endl;
}

int main() {
    integrate();
    return 0;
}