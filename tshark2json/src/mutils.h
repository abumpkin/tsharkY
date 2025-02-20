#pragma once
#include <cstddef>
#include <vector>
#include <string>
#include <cstdint>

inline std::string const utils_exec_cmd(std::string const &cmd) {
    std::string out;
    FILE *pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        return out;
    }

    char buf[4096];
    size_t len;
    while (true) {
        len = fread(buf, 1, sizeof(buf), pipe);
        if (len <= 0) break;
        out.append(buf, len);
    }
    pclose(pipe);
    return out;
}

inline std::string const utils_data_to_hex(std::vector<char> const &data) {
    std::string ret;
    char hex[] = "0123456789ABCDEF";
    uint32_t len = data.size();
    uint32_t t;
    if (len) {
        for (uint32_t i = 0; i < len; i++) {
            t = static_cast<uint8_t>(data[i]);
            ret.append(1, hex[t / 16]);
            ret.append(1, hex[t % 16]);
            if (i < len - 1) {
                ret.append(" ");
            }
        }
    }
    return ret;
}

inline std::vector<std::string> const utils_split_str(std::string const & str, std::string const & sep) {
    std::vector<std::string> ret;
    std::string::size_type pos1 = 0, pos2 = std::string::npos;
    while (true) {
        pos2 = str.find(sep, pos1);
        ret.push_back(str.substr(pos1, pos2 - pos1));
        if (pos2 == std::string::npos) break;
        pos1 = pos2 + 1;
    }
    return ret;
}