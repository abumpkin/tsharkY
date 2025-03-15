#include <windows.h>
#include <iostream>
#include <string>
#include "mutils.h"

int main() {
    // 管道句柄
    HANDLE hReadPipeOut, hWritePipeOut; // 子进程输出管道
    HANDLE hReadPipeIn, hWritePipeIn;  // 子进程输入管道

    // 创建子进程输出管道
    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE; // 管道句柄可继承
    saAttr.lpSecurityDescriptor = nullptr;

    if (!CreatePipe(&hReadPipeOut, &hWritePipeOut, &saAttr, 0)) {
        std::cerr << "CreatePipe failed: " << GetLastError() << std::endl;
        return 1;
    }

    // 创建子进程输入管道
    if (!CreatePipe(&hReadPipeIn, &hWritePipeIn, &saAttr, 0)) {
        std::cerr << "CreatePipe failed: " << GetLastError() << std::endl;
        return 1;
    }

    // 设置读管道为非阻塞模式
    DWORD dwMode = PIPE_NOWAIT; // 非阻塞模式
    if (!SetNamedPipeHandleState(hReadPipeOut, &dwMode, nullptr, nullptr)) {
        std::cerr << "SetNamedPipeHandleState failed: " << GetLastError() << std::endl;
        return 1;
    }

    // 创建子进程
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdError = hWritePipeOut;
    si.hStdOutput = hWritePipeOut;
    si.hStdInput = hReadPipeIn;
    si.dwFlags |= STARTF_USESTDHANDLES;

    ZeroMemory(&pi, sizeof(pi));

    // 创建子进程
    if (!CreateProcess(
            nullptr,                  // 应用程序名称
            "cmd.exe",      // 命令行
            nullptr,                  // 进程安全属性
            nullptr,                  // 线程安全属性
            TRUE,                     // 继承句柄
            0,                        // 创建标志
            nullptr,                  // 环境变量
            nullptr,                  // 当前目录
            &si,                      // STARTUPINFO
            &pi)) {                   // PROCESS_INFORMATION
        std::cerr << "CreateProcess failed: " << GetLastError() << std::endl;
        return 1;
    }

    // 关闭不需要的句柄
    CloseHandle(hWritePipeOut);
    CloseHandle(hReadPipeIn);

    // 父进程读取子进程输出（非阻塞）
    char buffer[4096];
    DWORD dwRead;
    while (true) {
        if (ReadFile(hReadPipeOut, buffer, sizeof(buffer), &dwRead, nullptr)) {
            if (dwRead > 0) {
                std::string output(buffer, dwRead);
                std::cout << "Child process output: " << output << std::endl;
            }
        } else {
            DWORD dwError = GetLastError();
            if (dwError == ERROR_NO_DATA) {
                // 没有数据可读，继续等待
                Sleep(100);
            } else {
                std::cerr << "ReadFile failed: " << dwError << std::endl;
                break;
            }
        }

        // 检查子进程是否退出
        DWORD dwExitCode;
        if (GetExitCodeProcess(pi.hProcess, &dwExitCode) && dwExitCode != STILL_ACTIVE) {
            std::cout << "Child process exited with code: " << dwExitCode << std::endl;
            break;
        }
    }

    // 关闭句柄
    CloseHandle(hReadPipeOut);
    CloseHandle(hWritePipeIn);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}