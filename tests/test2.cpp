
#include "mutils.h"
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
    std::cout << utils_convert_timestamp("1740834145.318869");
    // integrate();
    return 0;
}