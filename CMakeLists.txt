cmake_minimum_required(VERSION 3.14.0)

if(BUILD_QL)
    set(CMAKE_TOOLCHAIN_FILE cmake/ql.cmake)
    message(STATUS "Cross compilation with CMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}")
endif()

project(SSL-TLS-clientserver VERSION 0.0.1)

find_package(OpenSSL REQUIRED)


message(STATUS "openssl libs: ${OPENSSL_LIBRARIES}")

include_directories(
${OPENSSL_INCLUDE_DIR}/
libgd/
$ENV{SDKTARGETSYSROOT}/usr/include
$ENV{SDKTARGETSYSROOT}/usr/include/openssl
$ENV{SDKTARGETSYSROOT}/usr/include/data
$ENV{SDKTARGETSYSROOT}/usr/include/dsutils
$ENV{SDKTARGETSYSROOT}/usr/include/qmi
$ENV{SDKTARGETSYSROOT}/usr/include/qmi-framework
$ENV{SDKTARGETSYSROOT}/usr/include/quectel-openlinux-sdk
)

link_directories(
libgd/
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -w -c -fPIC -O2 -DENGINE_DYNAMIC_SUPPORT -DSPI")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

#add_executable(server  ssl_server_libssl.c)
#target_link_libraries(server ${OPENSSL_LIBRARIES})

#add_executable(client  ssl_client_libssl.c)
#target_link_libraries(client ${OPENSSL_LIBRARIES})

add_executable(gd_se_test gd_se_test.cc)
target_link_libraries(gd_se_test ${OPENSSL_LIBRARIES} GDEngine_spi GDHAL_spi_ag35)
