cmake_minimum_required(VERSION 3.16)
project(cno_nghttp2 C)

# ── Options ────────────────────────────────────────────────────────
option(CNO_NGHTTP2_SHARED "Build as shared library" OFF)

# ── Dependencies ───────────────────────────────────────────────────
find_package(PkgConfig REQUIRED)
pkg_check_modules(NGHTTP2 REQUIRED libnghttp2)

# QuickJS — expect QUICKJS_INCLUDE_DIR and QUICKJS_LIB to be passed in
# or found via pkg-config if packaged
if(NOT DEFINED QUICKJS_INCLUDE_DIR)
    pkg_check_modules(QUICKJS quickjs)
    if(QUICKJS_FOUND)
        set(QUICKJS_INCLUDE_DIR ${QUICKJS_INCLUDE_DIRS})
        set(QUICKJS_LIB         ${QUICKJS_LIBRARIES})
    else()
        message(FATAL_ERROR "QuickJS not found. Pass -DQUICKJS_INCLUDE_DIR=... -DQUICKJS_LIB=...")
    endif()
endif()

# circu.js src dir for tjs.h (DEF_MODULE macro).
# Pass -DCIRCU_SRC_DIR=/path/to/circu.js/src when configuring.
if(NOT DEFINED CIRCU_SRC_DIR)
    # Guess relative to this file: ../../circu.js/src
    get_filename_component(_guess "${CMAKE_CURRENT_SOURCE_DIR}/../../circu.js/src" ABSOLUTE)
    if(EXISTS "${_guess}/tjs.h")
        set(CIRCU_SRC_DIR "${_guess}")
    else()
        message(WARNING "CIRCU_SRC_DIR not set and tjs.h not found at ${_guess}. "
                        "Pass -DCIRCU_SRC_DIR=<circu.js/src path> to fix.")
    endif()
endif()

# ── Target ─────────────────────────────────────────────────────────
set(SOURCES http2.c)

if(CNO_NGHTTP2_SHARED)
    add_library(CNO_nghttp2 SHARED ${SOURCES})
else()
    add_library(CNO_nghttp2 STATIC ${SOURCES})
endif()

target_include_directories(CNO_nghttp2
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        ${QUICKJS_INCLUDE_DIR}
        ${NGHTTP2_INCLUDE_DIRS}
    PRIVATE
        ${CIRCU_SRC_DIR}
)

target_link_libraries(CNO_nghttp2
    PUBLIC
        ${NGHTTP2_LIBRARIES}
        ${QUICKJS_LIB}
)

target_compile_options(CNO_nghttp2 PRIVATE
    -Wall -Wextra -Wno-unused-parameter
    $<$<CONFIG:Release>:-O2>
    $<$<CONFIG:MinSizeRel>:-Os>
)

# ── Install ─────────────────────────────────────────────────────────
include(GNUInstallDirs)
install(TARGETS CNO_nghttp2
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(FILES http2.h  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/circu)
install(FILES http2.d.ts     DESTINATION ${CMAKE_INSTALL_DATADIR}/circu/types/)
