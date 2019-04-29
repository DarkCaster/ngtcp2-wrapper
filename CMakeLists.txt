cmake_minimum_required(VERSION 3.12)
project(ngtcp2_wrapper C CXX)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)
endif()

if(NOT TARGET_OS)
  set(TARGET_OS "linux")
endif()

if(NOT TARGET_ARCH)
  set(TARGET_ARCH "x86_64")
endif()

if(NOT TARGET_LIBDIR)
  set(TARGET_LIBDIR "lib64")
endif()

if(("${LIBS_BUILD_TYPE}" STREQUAL "STATIC") OR ("${LIBS_BUILD_TYPE}" STREQUAL "static"))
  set(LIBS_BUILD_TYPE "STATIC")
  set(OPENSSL_USE_STATIC_LIBS TRUE)
else()
  set(LIBS_BUILD_TYPE "SHARED")
  set(OPENSSL_USE_STATIC_LIBS FALSE)
endif()

set(OPENSSL_ROOT_DIR "${CMAKE_SOURCE_DIR}/External/dist/openssl_${TARGET_OS}_${TARGET_ARCH}")
set(OPENSSL_LIBRARIES "${CMAKE_SOURCE_DIR}/External/dist/openssl_${TARGET_OS}_${TARGET_ARCH}/lib")

find_package(OpenSSL REQUIRED)

find_library(LIBEV_LIB NAMES ev PATHS "${CMAKE_SOURCE_DIR}/External/dist/libev_${TARGET_OS}_${TARGET_ARCH}/lib" NO_DEFAULT_PATH)
if(NOT LIBEV_LIB)
  message(FATAL_ERROR "libev not found")
else()
  message(STATUS "Found libev: ${LIBEV_LIB}")
endif()

find_path(LIBEV_INCLUDE ev.h PATHS "${CMAKE_SOURCE_DIR}/External/dist/libev_${TARGET_OS}_${TARGET_ARCH}" NO_DEFAULT_PATH PATH_SUFFIXES include)
if(NOT LIBEV_INCLUDE)
  message(FATAL_ERROR "libev include directory not found")
else()
  message(STATUS "Found libev include dir: ${LIBEV_INCLUDE}")
endif()

find_library(LIBNGHTTP3_LIB NAMES nghttp3 PATHS "${CMAKE_SOURCE_DIR}/External/dist/nghttp3_${TARGET_OS}_${TARGET_ARCH}/${TARGET_LIBDIR}" NO_DEFAULT_PATH)
if(NOT LIBNGHTTP3_LIB)
  message(FATAL_ERROR "libnghttp3 not found")
else()
  message(STATUS "Found libnghttp3: ${LIBNGHTTP3_LIB}")
endif()

find_path(LIBNGHTTP3_INCLUDE nghttp3/nghttp3.h PATHS "${CMAKE_SOURCE_DIR}/External/dist/nghttp3_${TARGET_OS}_${TARGET_ARCH}" NO_DEFAULT_PATH PATH_SUFFIXES include)
if(NOT LIBNGHTTP3_INCLUDE)
  message(FATAL_ERROR "libnghttp3 include directory not found")
else()
  message(STATUS "Found libnghttp3 include dir: ${LIBNGHTTP3_INCLUDE}")
endif()

find_library(LIBNGTCP2_LIB NAMES ngtcp2 PATHS "${CMAKE_SOURCE_DIR}/External/dist/ngtcp2_${TARGET_OS}_${TARGET_ARCH}/${TARGET_LIBDIR}" NO_DEFAULT_PATH)
if(NOT LIBNGTCP2_LIB)
  message(FATAL_ERROR "libngtcp2 not found")
else()
  message(STATUS "Found libngtcp2: ${LIBNGTCP2_LIB}")
endif()

find_path(LIBNGTCP2_INCLUDE ngtcp2/ngtcp2.h PATHS "${CMAKE_SOURCE_DIR}/External/dist/ngtcp2_${TARGET_OS}_${TARGET_ARCH}" NO_DEFAULT_PATH PATH_SUFFIXES include)
if(NOT LIBNGTCP2_INCLUDE)
  message(FATAL_ERROR "libngtcp2 include directory not found")
else()
  message(STATUS "Found libngtcp2 include dir: ${LIBNGTCP2_INCLUDE}")
endif()

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_C_STANDARD 11)

set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(CMAKE_USE_RELATIVE_PATHS TRUE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)

set(CMAKE_INSTALL_RPATH "./lib${ARCHSUFFIX}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Build/lib${ARCHSUFFIX}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Build/lib${ARCHSUFFIX}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Build")

file(MAKE_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
file(MAKE_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})

include_directories("${CMAKE_BINARY_DIR}")

#set flags for gcc
if(CMAKE_COMPILER_IS_GNUCC)
  set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

  #platform dependent gcc flags
  set(OPTFLAGS "-pedantic")

  #general compiler flags for gcc compiler
  ##You can enable additional warnings for paranoics: -Wunsuffixed-float-constants -Wpadded
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11 -Wall -Wextra -Wshadow -Wstrict-overflow=5 -Wwrite-strings -Winit-self -Wmissing-include-dirs -Wbad-function-cast -Wc++-compat -Wcast-qual -Wcast-align -Wconversion -Wlogical-op -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes -Wmissing-declarations -Wpacked -Wredundant-decls -Wnested-externs -Winline -Wdisabled-optimization -Woverlength-strings -Wfloat-equal -Wswitch-default ${OPTFLAGS}")
  #set build-type dependent additional flags
  set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")
  set(CMAKE_C_FLAGS_DEBUG "-O0 -DDEBUG -ggdb")

  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11 -fpermissive -fno-exceptions -Wall -Wextra -Wshadow -Wstrict-overflow=5 -Wwrite-strings -Winit-self -Wmissing-include-dirs -Wcast-qual -Wcast-align -Wconversion -Wlogical-op -Wpacked -Wredundant-decls -Winline -Wdisabled-optimization -Woverlength-strings -Wfloat-equal -Wswitch-default -Wno-missing-field-initializers ${OPTFLAGS}")
  #set build-type dependent additional flags
  set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")
  set(CMAKE_CXX_FLAGS_DEBUG "-O0 -DDEBUG -ggdb")

  add_definitions(-D_GNU_SOURCE)
  set(EXELINKFLAGS "-Wl,-rpath-link,'${CMAKE_LIBRARY_OUTPUT_DIRECTORY}'")
endif()

#check include files
include(CheckIncludeFile)
include(CheckSymbolExists)
check_include_file(inttypes.h HAVE_INTTYPES_H)
check_include_file(stdint.h HAVE_STDINT_H)
check_include_file(stddef.h HAVE_STDDEF_H)
check_include_file(stdarg.h HAVE_STDARG_H)
if(NOT(HAVE_STDARG_H))
  message(FATAL_ERROR "C header file stdarg.h not available for your platform. Cannot proceed.")
endif()
check_include_file(ctype.h HAVE_CTYPE_H)
check_symbol_exists(isdigit ctype.h HAVE_ISDIGIT)
if((NOT(HAVE_CTYPE_H)) OR (NOT(HAVE_ISDIGIT)))
  message(FATAL_ERROR "C header file ctype.h or isdigit() function not available for your platform. Cannot proceed.")
endif()

#save build configuration to config.h
configure_file(config.h.in config.h)

#qt creator trick
if(CMAKE_C_IMPLICIT_INCLUDE_DIRECTORIES)
  include_directories("${CMAKE_C_IMPLICIT_INCLUDE_DIRECTORIES}")
endif(CMAKE_C_IMPLICIT_INCLUDE_DIRECTORIES)

include_directories(
  "${CMAKE_SOURCE_DIR}/lib"
  "${OPENSSL_INCLUDE_DIR}"
  "${LIBEV_INCLUDE}"
  "${LIBNGHTTP3_INCLUDE}"
  "${LIBNGTCP2_INCLUDE}"
)

set(lib_SOURCES
  "Lib/dummy.c"
  "Lib/dummy.cpp"
)

# Public shared library
add_library(ngtcp2_wrapper SHARED ${lib_SOURCES})
target_link_libraries(ngtcp2_wrapper ${OPENSSL_LIBRARIES} ${LIBEV_LIB} ${LIBNGHTTP3_LIB} ${LIBNGTCP2_LIB})
