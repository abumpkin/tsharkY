#include "mutils.h"
#include <cstdint>
#include <iostream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

// std::vector<std::pair<std::string, std::string>> map = {
//     {"General information", "常规信息"}, {"Frame Number", "帧编号"},
//     {"Captured Length", "捕获长度"}, {"Captured Time", "捕获时间"},
//     {"Section number", "节号"}, {"Interface id", "接口 id"},
//     {"Interface name", "接口名称"}, {"Encapsulation type", "封装类型"},
//     {"Arrival Time", "到达时间"}, {"UTC Arrival Time", "UTC到达时间"},
//     {"Epoch Arrival Time", "纪元到达时间"},
//     {"Time shift for this packet", "该数据包的时间偏移"},
//     {"Time delta from previous captured frame", "与上一个捕获帧的时间差"},
//     {"Time delta from previous displayed frame", "与上一个显示帧的时间差"},
//     {"Time since reference or first frame", "自参考帧或第一帧以来的时间"},
//     {"Frame Number", "帧编号"}, {"Frame Length", "帧长度"},
//     {"Capture Length", "捕获长度"}, {"Frame is marked", "帧标记"},
//     {"Frame is ignored", "帧忽略"}, {"Frame", "帧"},
//     {"Protocols in frame", "帧中的协议"}, {"Ethernet II", "以太网 II"},
//     {"Destination", "目的地址"},
//     {"Address Resolution Protocol", "ARP地址解析地址"},
//     {"Address (resolved)", "地址（解析后）"}, {"Type", "类型"},
//     {"Stream index", "流索引"},
//     {"Internet Protocol Version 4", "互联网协议版本 4"},
//     {"Internet Protocol Version 6", "互联网协议版本 6"},
//     {"Internet Control Message Protocol", "互联网控制消息协议ICMP"},
//     {"Version", "版本"}, {"Header Length", "头部长度"},
//     {"Differentiated Services Field", "差分服务字段"},
//     {"Total Length", "总长度"}, {"Identification", "标识符"}, {"Flags", "标志"},
//     {"Time to Live", "生存时间"},
//     {"Transmission Control Protocol", "TCP传输控制协议"},
//     {"User Datagram Protocol", "UDP用户数据包协议"},
//     {"Domain Name System", "DNS域名解析系统"},
//     {"Header Checksum", "头部校验和"}, {"Header checksum status", "校验和状态"},
//     {"Source Address", "源地址"}, {"Destination Address", "目的地址"},
//     {"Source Port", "源端口"}, {"Destination Port", "目的端口"},
//     {"Next Sequence Number", "下一个序列号"}, {"Sequence Number", "序列号"},
//     {"Acknowledgment Number", "确认号"}, {"Acknowledgment number", "确认号"},
//     {"TCP Segment Len", "TCP段长度"},
//     {"Conversation completeness", "会话完整性"},
//     {"Window size scaling factor", "窗口缩放因子"},
//     {"Calculated window size", "计算窗口大小"}, {"Window", "窗口"},
//     {"Urgent Pointer", "紧急指针"}, {"Checksum:", "校验和:"},
//     {"TCP Option - Maximum segment size", "TCP选项 - 最大段大小"},
//     {"Kind", "种类"}, {"MSS Value", "MSS值"},
//     {"TCP Option - Window scale", "TCP选项 - 窗口缩放"},
//     {"Shift count", "移位计数"}, {"Multiplier", "倍数"},
//     {"TCP Option - Timestamps", "TCP选项 - 时间戳"},
//     {"TCP Option - SACK permitted", "TCP选项 - SACK 允许"},
//     {"TCP Option - End of Option List", "TCP选项 - 选项列表结束"},
//     {"Options", "选项"}, {"TCP Option - No-Operation", "TCP选项 - 无操作"},
//     {"Timestamps", "时间戳"},
//     {"Time since first frame in this TCP stream", "自第一帧以来的时间"},
//     {"Time since previous frame in this TCP stream", "与上一个帧的时间差"},
//     {"Protocol:", "协议:"}, {"Source:", "源地址:"}, {"Length:", "长度:"},
//     {"Checksum status", "校验和状态"}, {"Checksum Status", "校验和状态"},
//     {"TCP payload", "TCP载荷"}, {"UDP payload", "UDP载荷"},
//     {"Hypertext Transfer Protocol", "超文本传输协议HTTP"},
//     {"Transport Layer Security", "传输层安全协议TLS"}};

// struct utils_translator {
//     struct Node {
//         char c;
//         std::unordered_map<char, Node> child;
//     };

//     std::unordered_map<char, Node> root;
//     std::unordered_map<std::string, std::string> dict;

//     void add(std::string const &word, std::string const &val) {
//         std::unordered_map<char, Node> *cur = &root;
//         for (char i : word) {
//             if (!cur->count(i)) cur->emplace(i, Node());
//             cur->at(i).c = i;
//             cur = &cur->at(i).child;
//         }
//         dict[word] = val;
//     }

//     std::string trans(std::string const &text) {
//         std::string ret = text, word, preword;
//         std::unordered_map<uint32_t, std::unordered_map<char, Node> *> p;
//         uint32_t rp, len;
//         std::vector<int> offset = {0};
//         uint32_t c = 0;
//         for (uint32_t i = 0; i < text.size(); i++) {
//             std::vector<uint32_t> rm;
//             word.clear();
//             rp = 0;
//             len = 0;
//             p[i] = &root;
//             for (auto &[_, o] : p) {
//                 c++;
//                 if (o->count(text[i])) {
//                     o = &o->at(text[i]).child;
//                     if (!o->size()) {
//                         if (i - _ > len) {
//                             rp = _;
//                             len = i - _ + 1;
//                             preword = text.substr(_, len);
//                             word = dict[preword];
//                         }
//                         rm.push_back(_);
//                     }
//                     continue;
//                 }
//                 rm.push_back(_);
//             }
//             for (auto _ : rm)
//                 p.erase(_);
//             if (word.size()) {
//                 std::cout << "找到待翻译文本：" << preword << std::endl;
//                 ret.replace(
//                     rp - offset[rp], i - offset[i] - rp + offset[rp] + 1, word);
//                 offset.push_back(offset[rp] + (int)len - word.size());
//                 continue;
//             }
//             offset.push_back(offset.back());
//         }
//         std::cout << "循环次数：" << c << std::endl;
//         return ret;
//     }
// };

int main() {
    // utils_translator t;
    // for (auto &i : map) {
    //     t.add(i.first, i.second);
    // }
    std::string ori = "General information";
    std::cout << "原字符串：" << ori << std::endl;
    std::cout << "长度：" << ori.size() << std::endl;
    ori = utils::FieldTranslator.trans(ori);
    std::cout << "翻译结果：" << ori << std::endl;
}