cmake_minimum_required(VERSION 3.16)

project(tsharkY)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(BUILD_SHARED_LIBS OFF CACHE BOOL "default build static library")

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

# tinyxml2
set(BUILD_TESTING OFF)
set(tinyxml2_BUILD_TESTING OFF CACHE BOOL "tinyxml2 build test")
add_subdirectory(3rd/tinyxml2)
load_3rd(tinyxml2)

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
    3rd/ip2region/binding/cpp/xdb_bench.cc
)
add_library(ip2region STATIC ${IP2REGION_SRC})
set_target_properties(ip2region PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ip2region)
target_include_directories(ip2region PUBLIC 3rd/ip2region/binding/cpp)
load_3rd(ip2region)

# boost
foreach(X
    unordered
    intrusive conversion atomic regex functional
    container integer numeric/conversion scope range typeof
    smart_ptr lexical_cast pool utility function tuple
    mp11 preprocessor io exception date_time type_traits variant2
    static_assert describe detail bind context function_types concept_check throw_exception mpl
    align array assert container_hash filesystem predef
    algorithm asio config core fusion iterator move optional system tokenizer type_index winapi
    process
)
    add_subdirectory(3rd/boost/libs/${X})
    if(X STREQUAL "numeric/conversion")
        set(X numeric_conversion)
    endif()
    load_3rd(Boost::${X})
endforeach()

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





