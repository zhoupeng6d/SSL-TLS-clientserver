include(CMakeForceCompiler)
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_VERSION 1)

if("$ENV{SDKTARGETSYSROOT}" STREQUAL "")
    message(FATAL_ERROR "No cross-compile environment variable found, please using \"source ql-ol-crosstool-env-init\" first")
endif()

set(CMAKE_FIND_ROOT_PATH "$ENV{SDKTARGETSYSROOT}")

set(GCC_BIN_PATH "$ENV{QL_OL_CROSSTOOL_PATH}/sysroots/x86_64-oesdk-linux/usr/bin/arm-oe-linux-gnueabi")

# Cross compiler
set(CMAKE_C_COMPILER   "${GCC_BIN_PATH}/arm-oe-linux-gnueabi-gcc")
set(CMAKE_CXX_COMPILER "${GCC_BIN_PATH}/arm-oe-linux-gnueabi-g++")
#set(ZEROMQ_LIBRARIES   ${CMAKE_SOURCE_DIR}/c++/libs/libzmq/prebuilt/ql/libzmq.so)
#set(ZEROMQ_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/c++/libs/libzmq/include/)

# specify the cross compiler
#CMAKE_FORCE_C_COMPILER("${GCC_BIN_PATH}/arm-oe-linux-gnueabi-gcc" GNU)
#CMAKE_FORCE_CXX_COMPILER("${GCC_BIN_PATH}/arm-oe-linux-gnueabi-g++" GNU)

set(USER_C_FLAGS "-march=armv7-a -mfloat-abi=softfp -mfpu=neon --sysroot=$ENV{SDKTARGETSYSROOT}")
set(CMAKE_C_FLAGS "${USER_C_FLAGS} -O2 -fexpensive-optimizations -frename-registers -fomit-frame-pointer -ftree-vectorize -Wno-error=maybe-uninitialized -finline-functions -finline-limit=64  -include quectel-features-config.h -fstack-protector-strong -pie -fpie -Wa,--noexecstack")

set(CMAKE_CXX_FLAGS "${USER_C_FLAGS} -std=c++11 -O2 -fexpensive-optimizations -frename-registers -fomit-frame-pointer -ftree-vectorize -Wno-error=maybe-uninitialized -finline-functions -finline-limit=64  -include quectel-features-config.h -fstack-protector-strong -pie -fpie -Wa,--noexecstack")

# Search for programs in the build host directories
set(THREADS_PREFER_PTHREAD_FLAG ON)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

# Libraries and headers in the target directories
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
