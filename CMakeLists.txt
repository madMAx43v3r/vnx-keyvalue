cmake_minimum_required(VERSION 2.6)
project(vnx-keyvalue)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -fPIC -pthread")

file(GLOB GENERATED_SOURCE_FILES generated/src/*.cpp)

add_library(vnx_keyvalue SHARED
	${GENERATED_SOURCE_FILES}
	src/Server.cpp
)

target_include_directories(vnx_keyvalue PUBLIC include generated/include)
target_link_libraries(vnx_keyvalue vnx_base)

add_executable(vnx_keyvalue_server src/vnx_keyvalue_server.cpp)
target_link_libraries(vnx_keyvalue_server vnx_keyvalue)

install(DIRECTORY include/ DESTINATION include)
install(DIRECTORY generated/include/ DESTINATION include)
install(DIRECTORY interface/ DESTINATION interface/vnx/keyvalue)

install(TARGETS vnx_keyvalue DESTINATION lib)
install(TARGETS vnx_keyvalue_server DESTINATION bin)
