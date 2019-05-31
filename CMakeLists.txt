cmake_minimum_required(VERSION 2.6)

project(scli C)

#add_definitions("-std=c++11 -Wall")

aux_source_directory(. SRC_LIST)
aux_source_directory(./slib/ SRC_LIST)

include_directories(./slib/)

# List of librarires to link with executable
set(LIBS pthread crypto ssl )

add_executable(${PROJECT_NAME} ${SRC_LIST})

target_link_libraries(${PROJECT_NAME} ${LIBS})
