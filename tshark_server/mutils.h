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
#include "fmt/format.h"
#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <loguru.hpp>
#include <memory>
#include <optional>
#include <queue>
#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <shared_mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <xdb_search.h>

#ifdef __linux__
#include <pthread.h>
#include <sched.h>
#include <sys/resource.h> // for setpriority, getpriority
#include <sys/syscall.h>  // SYS_gettid
#include <unistd.h>
#endif

#ifdef _WIN32
#include <windows.h>
inline class {
    const bool WIN_UTF8 = []() -> bool {
        return SetConsoleOutputCP(65001);
    }();
} WIN_UTF8;

inline std::string utils_exec_cmd(const std::string &cmd) {
    std::string out;

    // 使用 _popen 并采用二进制读取模式
    FILE *pipe = _popen(cmd.c_str(), "rb");
    if (!pipe) {
        return out; // 返回空字符串表示失败
    }

    char buffer[4096];
    size_t count;

    // 循环读取命令输出
    while ((count = fread(buffer, 1, sizeof(buffer), pipe)) > 0) {
        out.append(buffer, count);
    }

    _pclose(pipe); // 关闭管道
    return out;
}
#else
// inline class {
// } WIN_UTF8;

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
#endif

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

inline std::vector<std::string> utils_split_str(
    const std::string &s, char delimiter) {
    std::vector<std::string> tokens;
    // 预分配内存（通过计算分隔符数量）
    size_t delimiter_count = 0;
    for (char c : s) {
        if (c == delimiter) delimiter_count++;
    }
    tokens.reserve(delimiter_count + 1);
    // 单次遍历分割字符串
    size_t start = 0;
    while (true) {
        size_t end = s.find(delimiter, start);
        tokens.push_back(s.substr(start,
            (end == std::string::npos) ? s.size() - start : end - start));
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return tokens;
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
    static const char *db[] = {
        "resources/ip2region.xdb", "3rd/ip2region/data/ip2region.xdb"};
    std::string ret;
    static std::unique_ptr<xdb_search_t> searcher = []() {
        const char *path = nullptr;
        if (std::filesystem::exists(db[0])) path = db[0];
        if (std::filesystem::exists(db[1])) path = db[1];
        if (!path)
            throw std::runtime_error("could not open resources/ip2region.xdb!");
        LOG_F(INFO, "Ip Region Data: Load from file %s", path);
        auto xdb = std::make_unique<xdb_search_t>(path);
        xdb->init_content();
        return xdb;
    }();
    ret = searcher->search(ip);
    // 提前返回条件检查
    if (ret.find("invalid") != std::string::npos) return "";
    if (ret.find("内网") != std::string::npos) return "内网";
    // 原地过滤字符'0'（比替换更高效）
    ret.erase(std::remove(ret.begin(), ret.end(), '0'), ret.end());

    // 分割字符串并拼接
    std::string result;
    size_t start = 0;
    size_t end = ret.find('|');
    // uint32_t size = 0;

    // 预分配内存优化拼接
    result.reserve(ret.size()); // 预分配足够的内存

    while (end != std::string::npos) {
        if (start != end) { // 避免空字符串
            if (!result.empty()) result += '-';
            result.append(ret, start, end - start);
            // size++;
        }
        start = end + 1;
        end = ret.find('|', start);
    }

    // 处理最后一个部分
    // if (start < ret.size()) {
    //     if (!result.empty()) result += '-';
    //     result.append(ret, start, ret.size() - start);
    // }

    return result;
}

inline std::filesystem::path utils_test_valid_filename(
    std::filesystem::path test) {
    test = std::filesystem::absolute(test); // 获取绝对路径
    if (std::filesystem::is_directory(test))
        return ""; // 如果是目录，返回空字符串
    return test;   // 否则返回文件路径
}

inline std::filesystem::path utils_path_parent_mkdirs(
    std::filesystem::path path) {
    path = path.parent_path();
    std::filesystem::create_directories(path);
    return path;
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

template <typename T>
struct ProtectedObj : std::shared_lock<std::shared_mutex> {
    std::shared_ptr<T> p;
    ProtectedObj(std::shared_ptr<T> p, std::shared_mutex &mt)
        : std::shared_lock<std::shared_mutex>(mt) {
        this->p = p;
    }
    T *operator->() {
        return p.get();
    }
    T &operator*() {
        return *p.get();
    }
};

inline std::string FriendlyFileSize(uint64_t size) {
    std::stringstream output;
    double res = size;
    const char *const units[] = {"B", "KB", "MB", "GB", "TB"};
    int scale = 0;
    while (res > 1024.0 && scale < 4) {
        res /= 1024.0;
        scale++;
    }
    output << std::setprecision(3) << std::fixed << res << " " << units[scale];
    return output.str();
}

inline void ShowHex(char const *data, uint64_t len, int width = 32,
    int preWhite = 0, uint32_t divisionHeight = (uint32_t)-1,
    bool showAscii = true) {
    uint64_t dpos = 0;
    uint32_t dDivide = divisionHeight;
    uint32_t blockNum = 1;
    while (dpos < len) {
        for (int p = preWhite; p; p--) {
            std::cout << " ";
        }
        for (int p = 0; p < width; p++) {
            if (dpos + p >= len) {
                for (int o = (width - p) * 3; o; o--) {
                    std::cout << " ";
                }
                break;
            }
            std::cout << std::uppercase << std::hex << std::setw(2)
                      << std::right << std::setfill('0')
                      << (uint32_t)(uint8_t)data[dpos + p] << " ";
        }
        if (showAscii) {
            std::cout << "    ";
            for (int p = 0; p < width; p++) {
                if (dpos + p >= len) {
                    break;
                }
                if ((uint8_t)data[dpos + p] >= 0x20 &&
                    (uint8_t)data[dpos + p] <= 0x7E) {
                    std::cout << data[dpos + p];
                }
                else {
                    std::cout << ".";
                }
            }
        }
        std::cout << std::endl;
        if (!(--dDivide)) {
            for (int p = preWhite; p; p--) {
                std::cout << " ";
            }
            std::cout << "  偏移: 0x" << std::hex << std::uppercase
                      << std::setw(8) << std::setfill('0') << dpos + width;
            std::cout << "  块号: " << std::dec << blockNum;
            std::cout << std::endl;
            dDivide = divisionHeight;
            blockNum++;
        }
        dpos += width;
    }
    std::cout.unsetf(std::ios::basefield | std::ios::adjustfield | std::ios::floatfield);
}

inline std::thread::native_handle_type utils_get_thread_handle() {
#ifdef _WIN32
    return GetCurrentThread(); // Windows
#else
    return pthread_self(); // Linux
#endif
}

// 正常优先级 = 7
inline void utils_set_priority(int priority) {
    // 确保优先级在 0-9 范围内
    if (priority < 0 || priority > 9) {
        std::cerr << "Priority must be between 0 and 9.\n";
        return;
    }

#ifdef _WIN32
    // Windows 平台
    // 将 0-9 映射到 Windows 的线程优先级范围
    int winPriority;
    if (priority == 0) {
        winPriority = THREAD_PRIORITY_IDLE;
    }
    else if (priority <= 3) {
        winPriority = THREAD_PRIORITY_LOWEST;
    }
    else if (priority <= 5) {
        winPriority = THREAD_PRIORITY_BELOW_NORMAL;
    }
    else if (priority <= 7) {
        winPriority = THREAD_PRIORITY_NORMAL;
    }
    else if (priority <= 8) {
        winPriority = THREAD_PRIORITY_ABOVE_NORMAL;
    }
    else {
        winPriority = THREAD_PRIORITY_HIGHEST;
    }

    if (!SetThreadPriority(utils_get_thread_handle(), winPriority)) {
        std::cerr << "Failed to set thread priority. Error: " << GetLastError()
                  << "\n";
    }
#else
    // nice 值范围（-20 到 19）
    int niceValue = 20 - ((priority + 1) * 2);
    if (niceValue < -19) niceValue = -20; // 确保不超过最小值
    if (niceValue > 19) niceValue = 19;   // 确保不超过最大值

    // 获取线程的 TID（线程 ID）
    pid_t tid = syscall(SYS_gettid);

    // 设置指定线程的 nice 值
    if (setpriority(PRIO_PROCESS, tid, niceValue) != 0) {
        perror("Failed to set thread priority");
    }
#endif
}

inline std::string utils_convert_timestamp(const std::string &timestamp) {
    // 分割秒和毫秒部分
    size_t dotPos = timestamp.find('.');
    std::string secondsStr = timestamp.substr(0, dotPos);
    std::string millisStr =
        (dotPos != std::string::npos) ? timestamp.substr(dotPos + 1) : "0";
    // 转换为time_t类型
    time_t seconds = std::stoll(secondsStr);
    // 转换为本地时间结构
    // 平台相关的localtime函数封装
    tm tm_time{};
#ifdef _WIN32
    if (localtime_s(&tm_time, &seconds) != 0) {
        return "Invalid time conversion";
    }
#else
    if (localtime_r(&seconds, &tm_time) == nullptr) {
        return "Invalid time conversion";
    }
#endif

    // 格式化时间主体（包含时区偏移）
    char buffer[80];
    if (!strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S{} %z", &tm_time)) {
        return "Formatting error";
    }
    // 处理毫秒部分（保证3位精度）
    std::string result = buffer;
    if (!millisStr.empty()) {
        // 取前3位并补零
        while (millisStr.size() < 3) {
            millisStr.insert(0, 1, '0');
        }
        millisStr = "." + millisStr.substr(0, 3);
    }
    else {
        millisStr = ".000";
    }
    result = fmt::format(result, millisStr);
    // 移除strftime可能添加的换行符
    if (!result.empty() && result.back() == '\n') {
        result.pop_back();
    }
    return result;
}