cmake_minimum_required(VERSION 3.16)

project(tshark2json)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)


aux_source_directory(src SRC_LIST)
add_executable(tshark2json ${SRC_LIST})


target_link_libraries(tshark2json PRIVATE RapidJSON)
get_target_property(RAPIDJSON_INCLUDE RapidJSON INTERFACE_INCLUDE_DIRECTORIES)
target_include_directories(tshark2json PRIVATE ${CMAKE_SOURCE_DIR}/3rd/rapidjson/include ${RAPIDJSON_INCLUDE})
