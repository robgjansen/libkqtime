project(libkqtime)

## ensure cmake version
cmake_minimum_required(VERSION 2.8.0 FATAL_ERROR)

## ensure unix environment (CMAKE_SYSTEM_NAME == "Linux")
if((NOT UNIX) OR (NOT ("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")))
    message(FATAL_ERROR "Unix/Linux environment is required.")
endif((NOT UNIX) OR (NOT ("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")))

## make it easier for sub-projects to add CFLAGS
macro(add_cflags)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${ARGN}")
endmacro(add_cflags)

## now handle the options, set up our own flags
set(CMAKE_C_FLAGS_DEBUG "")
set(CMAKE_C_FLAGS_RELEASE "")
message(STATUS "CMAKE_BUILD_TYPE = ${CMAKE_BUILD_TYPE}")
if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    message(STATUS "Debug enabled. Setting '-DDEBUG' and '-g'.")
    add_definitions(-DDEBUG)
    add_cflags(-g)
else()
    message(STATUS "Release enabled. Setting '-DNDEBUG' and '-O3'.")
    add_definitions(-DNDEBUG)
    add_cflags(-O3)
endif()

## get general includes
include(CheckIncludeFile)
include(CheckFunctionExists)
include(CheckLibraryExists)
include(TestBigEndian)

## general tests and configurations
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
set(CMAKE_INCLUDE_DIRECTORIES_BEFORE ON)
set(CMAKE_INCLUDE_DIRECTORIES_PROJECT_BEFORE ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

if(EXISTS "${CMAKE_INSTALL_PREFIX}")
    message(STATUS "CMAKE_INSTALL_PREFIX = ${CMAKE_INSTALL_PREFIX}")
else()
    message(FATAL_ERROR "CMAKE_INSTALL_PREFIX path does not exist: '${CMAKE_INSTALL_PREFIX}'")
endif()

## we use custom cmake files
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/" ${CMAKE_MODULE_PATH})
include_directories(${CMAKE_MODULE_PATH})

## find dependencies
find_package(DL REQUIRED)
include_directories(${DL_INCLUDES})
find_package(PCAP REQUIRED)
include_directories(${PCAP_INCLUDES})
find_package(GLIB REQUIRED)
include_directories(${GLIB_INCLUDES})

## CFLAGS status update
add_definitions(-D_GNU_SOURCE)
add_cflags(-fPIC)
message(STATUS "CMAKE_C_FLAGS = ${CMAKE_C_FLAGS}")

## build libraries
add_library(kqtime-preload SHARED src/kqtime-preload.c)
add_library(kqtime SHARED src/kqtime.c)
target_link_libraries(kqtime-preload ${GLIB_CORE_LIBRARIES} ${DL_LIBRARIES})
target_link_libraries(kqtime ${GLIB_CORE_LIBRARIES} ${GLIB_GTHREAD_LIBRARIES} ${PCAP_LIBRARIES} ${DL_LIBRARIES})

install(TARGETS kqtime-preload DESTINATION lib)
install(TARGETS kqtime DESTINATION lib)
install(FILES src/kqtime.h DESTINATION include/)