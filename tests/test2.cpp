#include "mutils.h"
#include "tinyxml2.h"
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <traffic_statistics.h>
#include <unistream.h>
#include <unordered_map>
#include <vector>


int main() {
    std::string file = "dump_data/pdml.xml";

    std::string xml = UniStreamFile(file).read_until_eof();
    PacketDefineDecode p(xml);
    std::cout << p.to_json(true) << std::endl;

    return 0;
}