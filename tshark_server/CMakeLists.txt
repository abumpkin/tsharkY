cmake_minimum_required(VERSION 3.16)

project(tshark_server)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} SRC_LIST)
add_executable(tshark_server ${SRC_LIST})
target_include_directories(tshark_server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(tshark_server PUBLIC
    RapidJSON
    ip2region
    loguru
    oatpp
    pugixml-static
    SQLiteCpp
    fmt
    yaml-cpp
)
if (WIN32)
    target_link_libraries(tshark_server PUBLIC
        shlwapi.lib
        Rpcrt4.lib
    )
endif()

# 资源文件路径
set(RESOURCE_FILES
    ${CMAKE_SOURCE_DIR}/3rd/ip2region/data/ip2region.xdb
)

# 目标输出目录
set(TARGET_OUTPUT_DIR ${PROJECT_BINARY_DIR}/resources)

function(CreateResFiles)
    # 创建目标输出目录
    file(MAKE_DIRECTORY ${TARGET_OUTPUT_DIR})
    foreach(X IN ITEMS ${RESOURCE_FILES})
        get_filename_component(FILE_NAME "${X}" NAME)
        if(NOT EXISTS "${TARGET_OUTPUT_DIR}/${FILE_NAME}")
            message(STATUS "File not exists!")
            file(COPY "${X}" DESTINATION "${TARGET_OUTPUT_DIR}")
        endif()
    endforeach()
endfunction()

CreateResFiles()
