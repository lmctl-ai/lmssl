# Build the pinned OpenSSL once (scripts/build-openssl.sh) and expose its static archives.
set(LMSSL_OPENSSL_DIR "${CMAKE_BINARY_DIR}/openssl")
set(LMSSL_OPENSSL_SRC "${CMAKE_SOURCE_DIR}/third_party/openssl")
set(LMSSL_OPENSSL_LIBS
  "${LMSSL_OPENSSL_DIR}/liblmssl_cli.a"
  "${LMSSL_OPENSSL_DIR}/apps/libapps.a"
  "${LMSSL_OPENSSL_DIR}/libssl.a"
  "${LMSSL_OPENSSL_DIR}/libcrypto.a")
find_program(LMSSL_BASH bash REQUIRED)
find_program(LMSSL_PERL perl REQUIRED)
include(ProcessorCount)
ProcessorCount(LMSSL_JOBS)
if(LMSSL_JOBS EQUAL 0)
  set(LMSSL_JOBS 4)
endif()
add_custom_command(
  OUTPUT ${LMSSL_OPENSSL_LIBS}
  COMMAND "${LMSSL_BASH}" "${CMAKE_SOURCE_DIR}/scripts/build-openssl.sh" "${LMSSL_OPENSSL_DIR}" ${LMSSL_JOBS}
  DEPENDS "${CMAKE_SOURCE_DIR}/scripts/build-openssl.sh" "${CMAKE_SOURCE_DIR}/openssl.lock"
  COMMENT "Building OpenSSL (static libraries and CLI objects)"
  VERBATIM)
add_custom_target(lmssl_openssl_build DEPENDS ${LMSSL_OPENSSL_LIBS})

add_library(lmssl_openssl_apps INTERFACE)
add_dependencies(lmssl_openssl_apps lmssl_openssl_build)
target_include_directories(lmssl_openssl_apps INTERFACE "${LMSSL_OPENSSL_DIR}/include" "${LMSSL_OPENSSL_SRC}/include")
target_link_libraries(lmssl_openssl_apps INTERFACE ${LMSSL_OPENSSL_LIBS})
if(WIN32)
  target_link_libraries(lmssl_openssl_apps INTERFACE ws2_32 crypt32 user32 advapi32 gdi32)
else()
  find_package(Threads REQUIRED)
  target_link_libraries(lmssl_openssl_apps INTERFACE Threads::Threads ${CMAKE_DL_LIBS})
endif()
