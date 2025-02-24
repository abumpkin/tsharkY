#pragma once
#include "boost/filesystem/operations.hpp"
#include "boost/filesystem/path.hpp"
#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>
#include <xdb_search.h>

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

inline std::vector<std::string> const utils_split_str(
    std::string const &str, std::string const &sep) {
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

inline std::string const utils_join_str(
    std::vector<std::string> const &strs, std::string const &sep) {
    std::string ret;
    for (auto &i : strs) {
        ret.append(sep);
        ret.append(i);
    }
    return ret.substr(sep.size());
}

inline std::string const utils_replace_str_all(
    std::string const &str, std::string const &pat, std::string const &rep) {
    std::vector<std::string> parts = utils_split_str(str, pat);
    std::string ret = utils_join_str(parts, rep);
    return ret;
}

inline std::string &utils_str_lowcase(std::string &t) {
    std::transform(t.cbegin(), t.cend(), t.begin(),
        [](unsigned char c) { return std::tolower(c); });
    return t;
}

inline std::string &utils_str_upcase(std::string &t) {
    std::transform(t.cbegin(), t.cend(), t.begin(),
        [](unsigned char c) { return std::toupper(c); });
    return t;
}

inline std::string const utils_ip2region(std::string ip) {
    std::string ret;
    static xdb_search_t searcher =
        xdb_search_t("3rd/ip2region/data/ip2region.xdb");
    ret = searcher.search(ip);
    if (ret.find("invalid") != std::string::npos) return "";
    if (ret.find("内网") != std::string::npos) return "内网";
    ret = utils_replace_str_all(ret, "0", "");
    std::vector<std::string> parts;
    for (auto &i : utils_split_str(ret, "|")) {
        if (i.empty()) continue;
        parts.push_back(i);
    }
    parts.pop_back();
    ret = utils_join_str(parts, "-");
    return ret;
}

inline boost::filesystem::path utils_test_valid_filename(
    boost::filesystem::path test) {
    test = boost::filesystem::absolute(test);
    // try {
    //     test = boost::filesystem::canonical(test);
    // }
    // catch (...) {
    //     return "";
    // }
    if (boost::filesystem::is_directory(test)) return "";
    return test;
}
