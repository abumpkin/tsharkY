#include <iostream>
#include <fstream>
#include <string>

int main() {
    // 创建一个 fstream 对象
    std::fstream file;

    // 以读写模式打开文件（如果文件不存在，将创建它）
    file.open("example.txt", std::ios::in | std::ios::out);

    // 检查文件是否成功打开
    if (!file.is_open()) {
        std::cerr << "无法打开文件" << std::endl;
        return 1;
    }

    // 写入一些内容到文件
    file << "Hello, World!" << std::endl;

    // 刷新缓冲区，确保数据被写入文件（通常不是必需的，因为关闭文件时会自动刷新）
    file.flush();

    // 将文件指针移动到文件的开头以便读取
    file.seekg(0, std::ios::beg);

    // 读取文件内容
    std::string content;
    while (std::getline(file, content)) {
        std::cout << content << std::endl;
    }

    // 关闭文件
    file.close();

    return 0;
}