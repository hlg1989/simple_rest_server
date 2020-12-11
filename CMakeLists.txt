cmake_minimum_required(VERSION 3.6)

set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "build type")

project(simple_rest_server  LANGUAGES C CXX)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include_directories(common/others)
include_directories(authlicense)

find_library(LIBRT rt)
find_package(OpenSSL REQUIRED)
set(CMAKE_PREFIX_PATH "${CMAKE_SOURCE_DIR}/cmake")
message(STATUS "CMAKE_PREFIX_PATH : ${CMAKE_PREFIX_PATH}")
find_package(workflow REQUIRED CONFIG HINTS ..)
include_directories(${OPENSSL_INCLUDE_DIR} ${WORKFLOW_INCLUDE_DIR})
link_directories(${WORKFLOW_LIB_DIR})

set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -Wall -fPIC -pipe -std=gnu90")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fPIC -pipe -std=c++11 -fexceptions")

set(WORKFLOW_LIB workflow ${LIBRT} pthread OpenSSL::SSL OpenSSL::Crypto)

add_executable(${PROJECT_NAME} simple_rest_server.cpp rest_request_process.cpp logger_factory.cpp authlicense/authenticate_license.cpp authlicense/base64.cpp authlicense/openssl-RSA.cpp)
target_link_libraries(${PROJECT_NAME} ${WORKFLOW_LIB})





