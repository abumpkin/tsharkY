@echo off
chcp 65001
REM 检查是否提供了参数
if "%~1"=="" (
    echo 请提供一个参数: x64 或 x86
    exit /b 1
)
REM 设置架构变量
set ARCH=%1
if not defined VS_BUILD_TOOL (
    set VS_BUILD_TOOL="C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
)
if not defined CMAKE_BUILD_TYPE (
    set CMAKE_BUILD_TYPE=Release
)
REM 检查参数是否为有效的架构
if /i not "%ARCH%"=="x64" if /i not "%ARCH%"=="x86" (
    echo 无效的参数: %ARCH%
    echo 请提供一个有效的参数: x64 或 x86
    exit /b 1
)
REM 调用vcvarsall.bat以设置正确的环境变量
call "%VS_BUILD_TOOL:"=%\VC\Auxiliary\Build\vcvarsall.bat" %ARCH%
REM 设置CMake预设（这里假设预设文件已经根据架构进行了适当的配置）
set PRESET=windows-nmake-%ARCH%
REM 运行CMake以配置构建目录
cmake -B build -DCMAKE_BUILD_TYPE=%CMAKE_BUILD_TYPE% --preset=%PRESET%
REM 构建项目
cmake --build build --target help
cmake --build build
echo 构建完成。