#include <iostream>
#include <set>
#include <vector>
#include <algorithm>

class IntervalManager {
private:
    // 定义区间类型 [start, end)
    using Interval = std::pair<int, int>;

    // 自定义比较函数，用于 std::set 排序
    struct IntervalCompare {
        bool operator()(const Interval& a, const Interval& b) const {
            return a.first < b.first; // 按区间起点排序
        }
    };

    // 使用 std::set 存储区间
    std::set<Interval, IntervalCompare> intervals;

public:
    // 添加区间
    void add_range(int pos, int len) {
        int start = pos;
        int end = pos + len;

        // 找到第一个与新区间相交或相邻的区间
        auto it = intervals.lower_bound({start, start});
        if (it != intervals.begin()) {
            --it;
            if (it->second < start) {
                ++it; // 前一个区间不相交
            }
        }

        // 合并所有相交或相邻的区间
        while (it != intervals.end() && it->first <= end) {
            start = std::min(start, it->first);
            end = std::max(end, it->second);
            it = intervals.erase(it); // 删除旧的区间
        }

        // 插入合并后的区间
        intervals.insert({start, end});
    }

    // 删除区间
    void delete_range(int pos, int len) {
        int start = pos;
        int end = pos + len;

        // 找到第一个与删除区间相交的区间
        auto it = intervals.lower_bound({start, start});
        if (it != intervals.begin()) {
            --it;
            if (it->second < start) {
                ++it; // 前一个区间不相交
            }
        }

        // 处理所有与删除区间相交的区间
        while (it != intervals.end() && it->first < end) {
            if (it->first < start) {
                // 区间被删除部分分割为左半部分
                intervals.insert({it->first, start});
            }
            if (it->second > end) {
                // 区间被删除部分分割为右半部分
                intervals.insert({end, it->second});
            }
            it = intervals.erase(it); // 删除旧的区间
        }
    }

    // 查询缺失区间
    std::vector<Interval> query_range(int pos, int len) const {
        int start = pos;
        int end = pos + len;
        std::vector<Interval> missing;

        // 找到第一个与查询区间相交的区间
        auto it = intervals.lower_bound({start, start});
        if (it != intervals.begin()) {
            --it;
            if (it->second < start) {
                ++it; // 前一个区间不相交
            }
        }

        // 初始化缺失区间的起点
        int last_end = start;

        // 遍历所有与查询区间相交的区间
        while (it != intervals.end() && it->first < end) {
            if (it->first > last_end) {
                // 发现缺失区间
                missing.push_back({last_end, it->first});
            }
            last_end = std::max(last_end, it->second);
            ++it;
        }

        // 检查查询区间的末尾是否有缺失
        if (last_end < end) {
            missing.push_back({last_end, end});
        }

        return missing;
    }

    // 获取所有区间
    std::vector<Interval> get_ranges() const {
        return std::vector<Interval>(intervals.begin(), intervals.end());
    }
};


// 测试代码
int main() {
    IntervalManager manager;

    // 添加区间
    manager.add_range(10, 90);
    manager.delete_range(20, 50); // 10,20  70,100
    manager.add_range(30, 10); // 10,20 30,40 70,100
    // manager.add_range(25, 15);

    // 获取所有区间
    auto ranges = manager.get_ranges();
    std::cout << "Current ranges:\n";
    for (const auto& range : ranges) {
        std::cout << "[" << range.first << ", " << range.second << ")\n";
    }

    // 删除区间
    manager.delete_range(12, 10); // 删除 [12, 22)，分割为 [10, 12) 和 [22, 25)

    // 获取所有区间
    ranges = manager.get_ranges();
    std::cout << "After deletion:\n";
    for (const auto& range : ranges) {
        std::cout << "[" << range.first << ", " << range.second << ")\n";
    }

    // 查询缺失区间
    auto missing = manager.query_range(8, 20); // 查询 [8, 28) 的缺失区间
    std::cout << "Missing ranges:\n";
    for (const auto& range : missing) {
        std::cout << "[" << range.first << ", " << range.second << ")\n";
    }

    return 0;
}