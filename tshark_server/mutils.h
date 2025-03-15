/**
 * @file mutils.h
 * @author abumpkin (forwardslash@foxmail.com)
 * @link https://github.com/abumpkin/tsharkY @endlink
 *
 * ISC License
 *
 * @copyright Copyright (c) 2025 abumpkin
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#pragma once
#include "mutils.h"
#include "rapidjson/document.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <memory>
#include <optional>
#include <queue>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <xdb_search.h>

#ifdef _WIN32
#include <windows.h>
inline class {
    const bool WIN_UTF8 = []() -> bool {
        return SetConsoleOutputCP(65001);
    }();
} WIN_UTF8;
#else
inline class {
} WIN_UTF8;
#endif

// inline std::string const utils_exec_cmd(std::string const &cmd) {
//     std::string out;
//     FILE *pipe = popen(cmd.c_str(), "r");
//     if (!pipe) {
//         return out;
//     }

//     char buf[4096];
//     size_t len;
//     while (true) {
//         len = fread(buf, 1, sizeof(buf), pipe);
//         if (len <= 0) break;
//         out.append(buf, len);
//     }
//     pclose(pipe);
//     return out;
// }

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
        pos1 = pos2 + sep.size();
    }
    return ret;
}

inline std::string const utils_join_str(
    std::vector<std::string> const &strs, std::string const &sep) {
    std::string ret;
    if (strs.empty()) return ret;
    if (strs.size() == 1) return strs[0];
    for (auto &i : strs) {
        if (!i.empty()) {
            ret.append(sep);
            ret.append(i);
        }
    }
    return ret.substr(sep.size());
}

inline std::string const utils_replace_str_all(
    std::string const &str, std::string const &pat, std::string const &rep) {
    std::vector<std::string> parts = utils_split_str(str, pat);
    std::string ret;
    for (auto &i : parts) {
        ret.append(rep);
        ret.append(i);
    }
    return ret.substr(rep.size());
}

inline std::string &utils_str_lowcase(std::string &t) {
    std::transform(t.cbegin(), t.cend(), t.begin(), [](unsigned char c) {
        return std::tolower(c);
    });
    return t;
}

inline std::string &utils_str_upcase(std::string &t) {
    std::transform(t.cbegin(), t.cend(), t.begin(), [](unsigned char c) {
        return std::toupper(c);
    });
    return t;
}

template <typename T, template <typename> typename E>
inline void utils_erase_elements(E<T> &obj, T const &e) {
    for (auto i = obj.end(); i != obj.begin(); i--) {
        if (*i == e) obj.erase(i);
    }
    if (!obj.empty() && obj.front() == e) obj.erase(obj.begin());
}

inline std::string const utils_ip2region(std::string ip) {
    std::string ret;
    static xdb_search_t searcher =
        xdb_search_t("3rd/ip2region/data/ip2region.xdb");
    ret = searcher.search(ip);
    if (ret.find("invalid") != std::string::npos) return "";
    if (ret.find("内网") != std::string::npos) return "内网";
    ret = utils_replace_str_all(ret, "0", "");
    std::vector<std::string> parts = utils_split_str(ret, "|");
    parts.pop_back();
    ret = utils_join_str(parts, "-");
    return ret;
}

inline std::filesystem::path utils_test_valid_filename(
    std::filesystem::path test) {
    test = std::filesystem::absolute(test); // 获取绝对路径
    if (std::filesystem::is_directory(test))
        return ""; // 如果是目录，返回空字符串
    return test;   // 否则返回文件路径
}

inline std::string utils_to_json(
    rapidjson::Value const &json_obj, bool pretty = false) {
    rapidjson::MemoryPoolAllocator<> allocator;
    rapidjson::StringBuffer json_data;
    std::string ret;
    std::unique_ptr<rapidjson::Writer<rapidjson::StringBuffer>> writer;
    if (pretty) {
        rapidjson::PrettyWriter<rapidjson::StringBuffer> writer =
            rapidjson::PrettyWriter(json_data);
        json_obj.Accept(writer);
        ret = json_data.GetString();
    }
    else {
        rapidjson::Writer<rapidjson::StringBuffer> writer =
            rapidjson::Writer(json_data);
        json_obj.Accept(writer);
        ret = json_data.GetString();
    }
    return ret;
}

class ACTranslator {
    struct ACNode {
        std::unordered_map<char, std::shared_ptr<ACNode>> children;
        std::shared_ptr<ACNode> fail = nullptr;
        std::optional<std::string> value;
    };
    std::vector<std::shared_ptr<ACNode>> node_pool;
    std::shared_ptr<ACNode> root;
    std::shared_ptr<ACNode> create() {
        node_pool.emplace_back(std::make_shared<ACNode>());
        return node_pool.back();
    }

    public:
    ACTranslator(const std::unordered_map<std::string, std::string> &dict) {
        root = create();
        build_trie(dict);
        build_fail_links();
    }

    void build_trie(const std::unordered_map<std::string, std::string> &dict) {
        for (const auto &[key, val] : dict) {
            auto node = root;
            for (char c : key) {
                if (!node->children[c]) {
                    node->children[c] = create();
                }
                node = node->children[c];
            }
            node->value = val;
        }
    }

    void build_fail_links() {
        std::queue<std::shared_ptr<ACNode>> q;
        // 初始化根节点的子节点失败指针
        for (auto &[c, child] : root->children) {
            child->fail = root;
            q.push(child);
        }

        // BFS 构建失败指针 [[1]]
        while (!q.empty()) {
            auto current = q.front();
            q.pop();

            for (auto &[c, child] : current->children) {
                auto fail_node = current->fail;
                // 沿失败指针回溯查找最长前缀
                while (fail_node && !fail_node->children[c]) {
                    fail_node = fail_node->fail;
                }
                child->fail = fail_node ? fail_node->children[c] : root;
                // 合并输出链 [[1]]
                if (!child->value && child->fail->value) {
                    child->value = child->fail->value;
                }
                q.push(child);
            }
        }
    }

    std::string trans(const std::string &text) {
        std::string result;
        auto node = root;
        for (char c : text) {
            // 沿失败指针回溯查找匹配 [[1]]
            while (node && !node->children[c]) {
                node = node->fail;
            }
            node = node ? node->children[c] : root;

            // 处理最长匹配 [[1]]
            if (node->value) {
                result += *node->value;
            }
            else {
                result += c; // 未匹配则保留原字符
            }
        }
        return result;
    }
};

struct utils_translator2 {
    struct Node {
        char c;
        std::unordered_map<char, Node> child;
    };

    std::unordered_map<char, Node> root;
    std::unordered_map<std::string, std::string> dict;

    utils_translator2(std::unordered_map<std::string, std::string> &dict) {
        this->dict = dict;
        for (auto &[k, v] : dict) {
            std::unordered_map<char, Node> *cur = &root;
            for (char i : k) {
                if (!cur->count(i)) cur->emplace(i, Node());
                cur->at(i).c = i;
                cur = &cur->at(i).child;
            }
        }
    }

    void add(std::string const &word, std::string const &val) {
        std::unordered_map<char, Node> *cur = &root;
        for (char i : word) {
            if (!cur->count(i)) cur->emplace(i, Node());
            cur->at(i).c = i;
            cur = &cur->at(i).child;
        }
        dict[word] = val;
    }

    std::string trans(std::string const &text) {
        std::string ret = text, word, preword;
        std::unordered_map<uint32_t, std::unordered_map<char, Node> *> p;
        uint32_t rp, len;
        std::vector<int> offset = {0};
        for (uint32_t i = 0; i < text.size(); i++) {
            std::vector<uint32_t> rm;
            word.clear();
            rp = 0;
            len = 0;
            p[i] = &root;
            for (auto &[_, o] : p) {
                if (o->count(text[i])) {
                    o = &o->at(text[i]).child;
                    if (!o->size()) {
                        if (i - _ > len) {
                            rp = _;
                            len = i - _ + 1;
                            preword = text.substr(_, len);
                            word = dict[preword];
                        }
                        rm.push_back(_);
                    }
                    continue;
                }
                rm.push_back(_);
            }
            for (auto _ : rm)
                p.erase(_);
            if (word.size()) {
                // std::cout << "找到待翻译文本：" << preword << std::endl;
                ret.replace(
                    rp - offset[rp], i - offset[i] - rp + offset[rp] + 1, word);
                offset.push_back(offset[rp] + (int)len - word.size());
                continue;
            }
            offset.push_back(offset.back());
        }
        // std::cout << "循环次数：" << c << std::endl;
        return ret;
    }
};

struct utils_translator3 {
    struct Node {
        char c;
        bool is_end = false;
        std::unordered_map<char, Node> child;
    };

    std::unordered_map<char, Node> root;
    std::unordered_map<std::string, std::string> dict;

    utils_translator3(std::unordered_map<std::string, std::string> &dict)
        : dict(dict) {
        for (auto &[k, v] : dict) {
            add_word_to_trie(k);
        }
    }

    void add(const std::string &word, const std::string &val) {
        add_word_to_trie(word);
        dict[word] = val;
    }

    std::string trans(const std::string &text) {
        std::string result;
        const size_t n = text.size();

        for (size_t i = 0; i < n;) {
            size_t max_len = 0;
            std::string replacement;

            auto *current = &root;
            for (size_t j = i; j < n; ++j) {
                const char c = text[j];
                if (!current->count(c)) break;

                Node &node = current->at(c);
                if (node.is_end) {
                    if (auto it = dict.find(text.substr(i, j - i + 1));
                        it != dict.end()) {
                        max_len = j - i + 1;
                        replacement = it->second;
                    }
                }
                current = &node.child;
            }

            if (max_len) {
                result += replacement;
                i += max_len;
            }
            else {
                result += text[i];
                ++i;
            }
        }

        return result;
    }

    private:
    void add_word_to_trie(const std::string &word) {
        auto *current = &root;
        for (size_t i = 0; i < word.size(); ++i) {
            const char c = word[i];
            if (!current->count(c)) {
                current->emplace(c, Node{c, false, {}});
            }
            Node &node = current->at(c);
            if (i == word.size() - 1) {
                node.is_end = true;
            }
            current = &node.child;
        }
    }
};

inline std::string utils_url_encode(const std::string &str) {
    std::ostringstream escaped;
    escaped.fill('0'); // fill with leading zeros
    escaped << std::hex;

    for (char ch : str) {
        // Printable ASCII characters and alphanumeric characters do not need
        // encoding
        if (isalnum(static_cast<unsigned char>(ch)) ||
            strchr(" -_.!~*'()", ch)) {
            escaped << ch;
        }
        else {
            escaped << '%' << std::setw(2)
                    << static_cast<int>(static_cast<unsigned char>(ch));
        }
    }
    return escaped.str();
}

inline std::string utils_url_decode(const std::string &str) {
    std::ostringstream decoded;
    std::istringstream encoded(str);
    char ch;
    while (encoded.get(ch)) {
        if (ch == '%' && encoded.peek() != std::istream::traits_type::eof()) {
            // Read the next two characters as a hex number
            char hex[3] = {0};
            encoded.get(hex, 3);
            int value = std::stoi(hex, nullptr, 16);
            if (value == -1) {
                throw std::invalid_argument("Invalid hex sequence in URL");
            }
            decoded << static_cast<char>(value);
        }
        else if (ch == '+') {
            // '+' should be converted to ' ' (space)
            decoded << ' ';
        }
        else {
            // All other characters are added directly to the output
            decoded << ch;
        }
    }
    return decoded.str();
}

class utils_timer {
    public:
    utils_timer() {
        std::cout << "开始计时" << std::endl;
    }

    ~utils_timer() {
        std::cout << std::endl
                  << "总用时: " << t << " ms" << "  平均：" << (t / c) << "ms"
                  << std::endl;
    }

    void beg() {
        start = std::chrono::high_resolution_clock::now();
        c++;
    }

    void end() {
        auto ed = std::chrono::high_resolution_clock::now();
        std::chrono::milliseconds elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(ed - start);
        t += elapsed.count();
        std::cout << elapsed.count() << " " << std::flush;
    }

    private:
    std::chrono::high_resolution_clock::time_point start;
    uint32_t c = 0;
    uint32_t t = 0;
};

inline std::string utils_sql_fuzz_escape(const std::string &input) {
    std::string result;
    // 遍历输入字符串的每个字符
    for (char c : input) {
        // 对 %、_、\ 进行转义
        if (c == '%' || c == '_' || c == '\\') {
            result.push_back('\\'); // 添加转义字符
        }
        result.push_back(c); // 添加原字符
    }
    return result;
}
