cmake_minimum_required(VERSION 3.16)

project(tsharkY)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(BUILD_SHARED_LIBS OFF CACHE BOOL "default build static library")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

if (LINUX)
    set(CMAKE_GENERATOR "Unix Makefiles" CACHE INTERNAL "")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
    set(CMAKE_CXX_FLAGS_RELEASE "-O2")
    
endif()
if (WIN32)
    set(CMAKE_GENERATOR "Visual Studio 17 2022" CACHE INTERNAL "")
    set(CMAKE_GENERATOR_PLATFORM "x64" CACHE INTERNAL "")
endif()
if (MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "/Zi")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4") # 设置为警告级别4
    add_definitions(-D_CRT_SECURE_NO_WARNINGS) # 忽略某些安全相关的警告
    set(CMAKE_CXX_FLAGS_RELEASE "/O2 /Ob2 /MD") # Release模式下的优化选项
    set(CMAKE_CXX_FLAGS_DEBUG "/Od /Ob0 /MTd") # Debug模式下的非优化选项
    add_definitions(-DWIN32 -D_WINDOWS)
endif()

# 定义一个名为 clean_build 的自定义目标
add_custom_target(clean_build
    # 使用 COMMAND 指定要执行的操作
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}
    COMMENT "Removing build directory: ${CMAKE_BINARY_DIR}"
    VERBATIM
)

# 设置该目标为默认不构建，除非被显式调用
set_target_properties(clean_build PROPERTIES FOLDER "Utilities")

###############################################################################
# include list
set(INCLUDE_LIST ${CMAKE_SOURCE_DIR})

# 3rd library
set(THIRD_LIST)

function(load_3rd tar)
    set(INC)
    get_target_property(INC1 ${tar} INCLUDE_DIRECTORIES)
    get_target_property(INC2 ${tar} INTERFACE_INCLUDE_DIRECTORIES)
    foreach(item IN LISTS INC1 INC2)
        list(FIND INC "${item}" found_index)
        if(found_index EQUAL -1 AND NOT item STREQUAL "INC1-NOTFOUND" AND NOT item STREQUAL "INC2-NOTFOUND")
            list(APPEND INC "${item}")
        endif()
    endforeach()
    list(LENGTH INC length)
    if(NOT length EQUAL 0)
        set(INCLUDE_LIST ${INCLUDE_LIST} ${INC} PARENT_SCOPE)
        set(THIRD_LIST ${THIRD_LIST} ${tar} PARENT_SCOPE)
    else()
        message(FATAL_ERROR "ERROR: Could not found include directories for ${tar}.")
    endif()
endfunction()

# pugixml
add_subdirectory(3rd/pugixml)
load_3rd(pugixml-static)

# oatpp
set(OATPP_INSTALL OFF CACHE BOOL "oatpp install target")
set(OATPP_BUILD_TESTS OFF CACHE BOOL "oatpp test targets")
set(OATPP_LINK_TEST_LIBRARY OFF CACHE BOOL "oatpp++")
add_subdirectory(3rd/oatpp)
load_3rd(oatpp)

# loguru
add_subdirectory(3rd/loguru)
load_3rd(loguru)

# rapidjson
set(RAPIDJSON_BUILD_DOC OFF CACHE BOOL "build rapidjson docs")
set(RAPIDJSON_BUILD_EXAMPLES OFF CACHE BOOL "build rapidjson examples")
set(RAPIDJSON_BUILD_TESTS OFF CACHE BOOL "build rapidjson test")
set(RAPIDJSON_BUILD_THIRDPARTY_GTEST OFF CACHE BOOL "build rapidjson thirdparty")
set(RAPIDJSON_BUILD_CXX17 ON CACHE BOOL "enable repidjson c++17")
add_subdirectory(3rd/rapidjson)
load_3rd(RapidJSON)

# 配置 ip2region
set(IP2REGION_SRC
    3rd/ip2region/binding/cpp/xdb_search.cc
)
add_library(ip2region STATIC ${IP2REGION_SRC})
set_target_properties(ip2region PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ip2region)
target_include_directories(ip2region PUBLIC 3rd/ip2region/binding/cpp)
load_3rd(ip2region)

###############################################################################
message("###### INCLUDE LIST ######")
foreach(x ${INCLUDE_LIST})
    message("- Include: ${x}")
endforeach()
include_directories(${INCLUDE_LIST})
message("##########################\n")
message("###### 3RD LIBRARY #######")
foreach(x ${THIRD_LIST})
    message("- Library: ${x}")
endforeach()
message("##########################\n")


# tshark_server
add_subdirectory(tshark_server)

# tests
add_subdirectory(tests)





