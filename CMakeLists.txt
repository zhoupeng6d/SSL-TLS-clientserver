cmake_minimum_required(VERSION 3.14.0)
project(SSL-TLS-clientserver VERSION 0.0.1)

find_package(OpenSSL REQUIRED)

message(STATUS "openssl libs: ${OPENSSL_LIBRARIES}")

include_directories(
${OPENSSL_INCLUDE_DIR}/
)

add_executable(server  ssl_server_libssl.c)
target_link_libraries(server ${OPENSSL_LIBRARIES})

add_executable(client  ssl_client_libssl.c)
target_link_libraries(client ${OPENSSL_LIBRARIES})
