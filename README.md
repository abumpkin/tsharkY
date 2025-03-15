#

## tsharkY

基于 tshark 编写的一个抓包程序。

tshark 是抓包软件 wireshark 的一个命令行抓包程序，使用 tshark 可以实现和 wireshark 近乎同等的功能。

## 编译

下载代码：

```shell
# 克隆仓库
git clone https://github.com/abumpkin/tsharkY.git
cd tsharkY
# 拉取子模块
git update --init
```

### Linux

**前置条件：**

* GCC 或 LLVM
* VS Code
* Cmake

**使用 VS Code：**

使用 VS Code 打开项目文件夹，从菜单选择 "终端" -> "运行任务".

### Windows

**前置条件：**

1. 确认电脑已安装：

    * [VS 2022 Build Tools](https://visualstudio.microsoft.com/zh-hans/downloads/?q=build+tools#build-tools-for-visual-studio-2022)
    * Cmake
2. 确认 **VS 2022 Build Tools** 安装路径（默认安装在 `C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools`）

**使用脚本编译：**

`Win + R` 运行 cmd，输入以下命令：

* 设置编译模式（`Release` 或 `Debug`）：

  ```shell
  set CMAKE_DEBUG_TYPE=Release
  ```

* 设置 **VS 2022 Build Tools** 安装路径（如果不在默认位置）：

  ```shell
  set VS_BUILD_TOOL="位置\Microsoft Visual Studio\2022\BuildTools"
  ```

* 运行编译脚本（设置编译架构 `x64` 或 `x86`）：

  ```shell
  build.bat x64
  ```

**使用 VS Code：**

使用 VS Code 打开项目文件夹，从菜单选择 "终端" -> "运行任务".
