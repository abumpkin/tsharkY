cmake_minimum_required(VERSION 3.16)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} TEST_SRC)



foreach(TEST_UNIT ${TEST_SRC})
    get_filename_component(TEST_UNIT_TARGET ${TEST_UNIT} NAME_WE)
    add_executable(${TEST_UNIT_TARGET} ${TEST_UNIT})

    get_target_property(TEST_INCLUDE tshark_server INCLUDE_DIRECTORIES)
    target_include_directories(${TEST_UNIT_TARGET} PRIVATE ${TEST_INCLUDE})
    target_link_libraries(${TEST_UNIT_TARGET} ${THIRD_LIST})
endforeach()
