cmake_minimum_required(VERSION 3.16)

project(tshark2json)

aux_source_directory(src SRC_LIST)
add_executable(tshark2json ${SRC_LIST})


target_link_libraries(tshark2json PRIVATE RapidJSON ip2region)
get_target_property(RAPIDJSON_INCLUDE RapidJSON INTERFACE_INCLUDE_DIRECTORIES)
target_include_directories(tshark2json PRIVATE
    ${CMAKE_SOURCE_DIR}/3rd/rapidjson/include
    ${CMAKE_SOURCE_DIR}/3rd/ip2region/binding/cpp
    ${RAPIDJSON_INCLUDE}
)
