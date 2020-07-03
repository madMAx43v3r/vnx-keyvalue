cmake_minimum_required(VERSION 3.8)
project(vnx-keyvalue)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -pthread")

file(GLOB GENERATED_SOURCE_FILES generated/src/*.cpp)

add_library(vnx_keyvalue SHARED
	${GENERATED_SOURCE_FILES}
	src/Server.cpp
	src/SyncModule.cpp
)

target_include_directories(vnx_keyvalue PUBLIC include generated/include)
target_link_libraries(vnx_keyvalue vnx_addons vnx_base)

add_executable(vnx_keyvalue_server src/vnx_keyvalue_server.cpp)
target_link_libraries(vnx_keyvalue_server vnx_keyvalue)

add_executable(vnx_keyvalue_get src/vnx_keyvalue_get.cpp)
target_link_libraries(vnx_keyvalue_get vnx_keyvalue)

add_executable(vnx_keyvalue_sync src/vnx_keyvalue_sync.cpp)
target_link_libraries(vnx_keyvalue_sync vnx_keyvalue)

add_executable(test_server_get test/test_server_get.cpp)
target_link_libraries(test_server_get vnx_keyvalue)

add_executable(test_server_store test/test_server_store.cpp)
target_link_libraries(test_server_store vnx_keyvalue)

add_executable(test_server_delete test/test_server_delete.cpp)
target_link_libraries(test_server_delete vnx_keyvalue)

add_executable(test_server_sync test/test_server_sync.cpp)
target_link_libraries(test_server_sync vnx_keyvalue)

install(DIRECTORY include/ DESTINATION include)
install(DIRECTORY generated/include/ DESTINATION include)
install(DIRECTORY interface/ DESTINATION interface/vnx/keyvalue)

install(TARGETS vnx_keyvalue DESTINATION lib)
install(TARGETS vnx_keyvalue_server DESTINATION bin)
install(TARGETS vnx_keyvalue_get DESTINATION bin)
