#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <ios>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

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

typedef struct {
    FILE *stdin;
    FILE *stdout;
} popen2_t;

int popen2(const char *command, popen2_t *pipes) {
    int stdin_pipe[2];
    int stdout_pipe[2];
    pid_t pid;

    if (pipe(stdin_pipe) || pipe(stdout_pipe)) {
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        return -1;
    }

    std::vector<std::string> args = utils_split_str(command, " ");
    std::vector<char *> p_args;
    for (size_t i = 0; i < args.size(); i++) {
        p_args.push_back(args[i].data());
    }
    p_args.push_back(nullptr);
    std::string file = args.front();
    if (pid == 0) { // 子进程
        close(stdin_pipe[1]);
        close(stdout_pipe[0]);

        dup2(stdin_pipe[0], STDIN_FILENO);
        dup2(stdout_pipe[1], STDOUT_FILENO);

        execvp(file.c_str(), p_args.data());
        exit(127);
    }
    else { // 父进程
        close(stdin_pipe[0]);
        close(stdout_pipe[1]);

        pipes->stdin = fdopen(stdin_pipe[1], "w");
        pipes->stdout = fdopen(stdout_pipe[0], "r");

        return pid;
    }
}

struct UniStreamInterface {
    virtual uint32_t read(char *buf, uint32_t len) = 0;
    virtual uint32_t write(char const *buf, uint32_t len) = 0;
    virtual uint32_t read_offset() = 0;
    virtual uint32_t write_offset() = 0;
    virtual bool read_eof() = 0;
    virtual void close() = 0;

    virtual uint32_t read_to_null(uint32_t len) {
        if (!read_eof()) return 0;
        static char buf[1024];
        uint32_t rd_len, o_pos = read_offset();
        while (len) {
            rd_len = sizeof(buf);
            if (rd_len > len) rd_len = len;
            rd_len = read(buf, rd_len);
            if (!rd_len) break;
            len -= rd_len;
        }
        return read_offset() - o_pos;
    }
};

class UniStreamPipeUnblocked : public UniStreamInterface {
#ifdef __linux__
    typedef struct {
        FILE *stdin;
        FILE *stdout;
    } popen2_t;

    int popen2(const char *command, popen2_t *pipes) {
        int stdin_pipe[2];
        int stdout_pipe[2];
        pid_t pid;

        if (pipe(stdin_pipe) || pipe(stdout_pipe)) {
            return -1;
        }

        pid = fork();
        if (pid < 0) {
            return -1;
        }

        std::vector<std::string> args = utils_split_str(command, " ");
        std::vector<char *> p_args;
        for (size_t i = 0; i < args.size(); i++) {
            p_args.push_back(args[i].data());
        }
        p_args.push_back(nullptr);
        std::string file = args.front();
        if (pid == 0) { // 子进程
            ::close(stdin_pipe[1]);
            ::close(stdout_pipe[0]);

            dup2(stdin_pipe[0], STDIN_FILENO);
            dup2(stdout_pipe[1], STDOUT_FILENO);
            printf("aaaaaaaaaaa");
            execvp(file.c_str(), p_args.data());
            exit(127);
        }
        else { // 父进程
            ::close(stdin_pipe[0]);
            ::close(stdout_pipe[1]);

            pipes->stdin = fdopen(stdin_pipe[1], "w");
            pipes->stdout = fdopen(stdout_pipe[0], "r");

            return pid;
        }
    }

    public:
    UniStreamPipeUnblocked(std::string const &cmd) {
        popen2_t pipes;
        if (popen2(cmd.c_str(), &pipes) < 0) {
            perror("popen2 failed");
            exit(EXIT_FAILURE);
        }
        setvbuf(pipes.stdin, NULL, _IONBF, 0);
        setvbuf(pipes.stdout, NULL, _IONBF, 0);
    }
    virtual uint32_t read(char *buf, uint32_t len) override {
        // fread
    }
    virtual uint32_t write(char const *buf, uint32_t len) = 0;
    virtual uint32_t read_offset() = 0;
    virtual uint32_t write_offset() = 0;
    virtual bool read_eof() = 0;
    virtual void close() = 0;
#endif
};

int main() {
    popen2_t pipes;
    char buffer[1000];

    if (popen2("tshark -l -r -", &pipes) < 0) {
        perror("popen2 failed");
        exit(EXIT_FAILURE);
    }
    setvbuf(pipes.stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    std::fstream f("dump_data/capture.pcapng");
    char *data = new char[700000];
    while (!f.eof()) {
        f.read(data, 1024);
        size_t len = f.gcount();
        fwrite(data, len, 1, pipes.stdin);
        // std::cout << feof(pipes.stdin) << ferror(pipes.stdin) << std::endl;
        // fread(buffer, 1000, 1, pipes.stdout);
        // puts(buffer);
        while (!ferror(pipes.stdout)) {
            size_t len = fread(buffer, 1, 1, pipes.stdout);
            fwrite(buffer, len, 1, stdout);
        }
        std::cout << feof(pipes.stdout) << ferror(pipes.stdout) << std::endl;
        clearerr(pipes.stdout);
    }

    // 关闭管道
    fclose(pipes.stdin);
    while (!feof(pipes.stdout)) {
        size_t len = fread_unlocked(buffer, 1000, 1, pipes.stdout);
        fwrite(buffer, len, 1, stdout);
    }
    fclose(pipes.stdout);

    return 0;
}