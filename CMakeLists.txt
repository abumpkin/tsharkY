cmake_minimum_required(VERSION 3.16)

project(TsharkY)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)


set(RAPIDJSON_BUILD_DOC OFF)
set(RAPIDJSON_BUILD_EXAMPLES OFF)
set(RAPIDJSON_BUILD_TESTS OFF)
set(RAPIDJSON_BUILD_THIRDPARTY_GTEST OFF)
set(APIDJSON_BUILD_CXX17 ON)

# rapidjson
add_subdirectory(3rd/rapidjson)

# 配置 ip2region
set(IP2REGION_SRC
    3rd/ip2region/binding/cpp/xdb_search.cc
    3rd/ip2region/binding/cpp/xdb_bench.cc
)
add_library(ip2region STATIC ${IP2REGION_SRC})
set_target_properties(ip2region PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ip2region)

# tshark2json
add_subdirectory(tshark2json)





