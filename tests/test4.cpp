#include "mutils.h"
#include <boost/asio.hpp>
#include <iostream>
#include <string>

std::string proc(std::string x) {
    auto y = utils_split_str(x, " ");
    y.erase(y.begin());
    y.erase(y.begin());
    x = utils_join_str(y, " ");
    x.erase(x.begin());
    x.pop_back();
    return x;
}

int main() {
    std::cout << proc("1. dslkfjlsdkfjalkjdfl (dklafjl)") << std::endl;
    std::string test = "     1 2 љ345";
    utils_erase_elements(test, ' ');
    std::cout << test << std::endl;
    return 0;
}