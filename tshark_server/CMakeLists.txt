cmake_minimum_required(VERSION 3.16)

project(tshark_server)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} SRC_LIST)
add_executable(tshark_server ${SRC_LIST})
target_include_directories(tshark_server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(tshark_server PRIVATE
    RapidJSON
    ip2region
    loguru
    Boost::process
    tinyxml2
    oatpp
)
