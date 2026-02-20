cmake_minimum_required(VERSION 3.18)
project(KernKlawLinux VERSION 0.1.0 LANGUAGES C)

# ── Standards ─────────────────────────────────────────────────────────
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)   # GNU extensions needed for Linux APIs

# ── Default build type ────────────────────────────────────────────────
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "" FORCE)
endif()

# ── Compiler flags ────────────────────────────────────────────────────
add_compile_options(
  -Wall -Wextra -Wpedantic
  -Wno-unused-parameter
  -fstack-protector-strong
  $<$<CONFIG:Release>:-O2>
  $<$<CONFIG:Debug>:-O0 -g3 -fsanitize=address,undefined>
)
add_link_options(
  -Wl,-z,relro,-z,now
  $<$<CONFIG:Debug>:-fsanitize=address,undefined>
)

# ── Install paths ─────────────────────────────────────────────────────
include(GNUInstallDirs)
set(CLAW_BPF_DIR  "${CMAKE_INSTALL_LIBDIR}/claw/bpf")
set(CLAW_SKILL_DIR "/etc/claw/skills")

# ── Find dependencies ─────────────────────────────────────────────────
find_package(PkgConfig REQUIRED)

pkg_check_modules(CURL      REQUIRED IMPORTED_TARGET libcurl)
pkg_check_modules(JSONC     REQUIRED IMPORTED_TARGET json-c)
pkg_check_modules(LIBBPF    REQUIRED IMPORTED_TARGET libbpf)
pkg_check_modules(LIBURING  REQUIRED IMPORTED_TARGET liburing)
pkg_check_modules(SYSTEMD   REQUIRED IMPORTED_TARGET libsystemd)

find_library(READLINE_LIB NAMES readline REQUIRED)
find_library(HISTORY_LIB  NAMES history)
find_library(CAP_LIB      NAMES cap     REQUIRED)

# ── Common library ─────────────────────────────────────────────────────
add_library(claw_common STATIC
  src/common/json_utils.c
)
target_include_directories(claw_common PUBLIC src)
target_link_libraries(claw_common PUBLIC PkgConfig::JSONC)

# ── IPC library (shared between daemon and shell) ──────────────────────
add_library(claw_ipc STATIC
  src/daemon/ipc.c
)
target_include_directories(claw_ipc PUBLIC src)
target_link_libraries(claw_ipc PUBLIC claw_common)

# ── claw-daemon ────────────────────────────────────────────────────────
add_executable(claw-daemon
  src/daemon/claw-daemon.c
  src/daemon/ollama.c
  src/daemon/skill_loader.c
  src/daemon/ebpf_hooks.c
)
target_compile_definitions(claw-daemon PRIVATE
  CLAW_LOG_IMPL CLAW_LOG_SYSLOG)
target_include_directories(claw-daemon PRIVATE src)
target_link_libraries(claw-daemon PRIVATE
  claw_common claw_ipc
  PkgConfig::CURL
  PkgConfig::LIBBPF
  PkgConfig::SYSTEMD
  Threads::Threads
  ${CMAKE_DL_LIBS}
  m
)
find_package(Threads REQUIRED)
target_link_libraries(claw-daemon PRIVATE Threads::Threads)

# ── claw-shell ────────────────────────────────────────────────────────
add_executable(claw-shell
  src/shell/claw-shell.c
  src/shell/parser.c
  src/shell/workflow.c
)
target_compile_definitions(claw-shell PRIVATE CLAW_LOG_IMPL)
target_include_directories(claw-shell PRIVATE src)
target_link_libraries(claw-shell PRIVATE
  claw_common claw_ipc
  ${READLINE_LIB}
  $<$<BOOL:${HISTORY_LIB}>:${HISTORY_LIB}>
  m
)

# ── claw-skill-exec ───────────────────────────────────────────────────
add_executable(claw-skill-exec
  src/skill-exec/claw-skill-exec.c
)
target_include_directories(claw-skill-exec PRIVATE src)
target_link_libraries(claw-skill-exec PRIVATE ${CAP_LIB})
# setuid bit set at install time
set_target_properties(claw-skill-exec PROPERTIES
  INSTALL_RPATH "${CMAKE_INSTALL_FULL_LIBDIR}")

# ── Installation ──────────────────────────────────────────────────────
install(TARGETS claw-daemon claw-shell claw-skill-exec
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Set setuid on skill-exec
install(CODE "
  execute_process(COMMAND chmod u+s
    \"\${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/claw-skill-exec\")
")

install(FILES
  systemd/claw-daemon.service
  systemd/claw-shell@.service
  DESTINATION lib/systemd/system
)

install(DIRECTORY skills/example
  DESTINATION ${CLAW_SKILL_DIR}
  FILE_PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
)

# ── eBPF compilation (optional) ───────────────────────────────────────
option(BUILD_EBPF "Compile eBPF programs (requires clang + bpftool)" OFF)

if(BUILD_EBPF)
  find_program(CLANG_BPF clang REQUIRED)
  find_program(BPFTOOL   bpftool)

  set(BPF_SRCS ebpf/file_watch.bpf.c ebpf/skill_trigger.bpf.c)
  foreach(src ${BPF_SRCS})
    get_filename_component(stem ${src} NAME_WE)
    set(out "${CMAKE_CURRENT_BINARY_DIR}/${stem}.bpf.o")
    add_custom_command(OUTPUT ${out}
      COMMAND ${CLANG_BPF} -O2 -g -target bpf -D__TARGET_ARCH_x86
                           -I/usr/include/bpf
                           -c ${CMAKE_CURRENT_SOURCE_DIR}/${src} -o ${out}
      DEPENDS ${src}
      COMMENT "Compiling eBPF: ${src}"
    )
    list(APPEND BPF_OBJS ${out})
  endforeach()

  add_custom_target(ebpf ALL DEPENDS ${BPF_OBJS})
  install(FILES ${BPF_OBJS} DESTINATION ${CLAW_BPF_DIR})
endif()

# ── CPack (DEB + RPM) ─────────────────────────────────────────────────
set(CPACK_PACKAGE_NAME        "kernklaw-linux")
set(CPACK_PACKAGE_VERSION     "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION "KernKlaw-Linux: AI assistant daemon for Linux")
set(CPACK_PACKAGE_CONTACT     "kernklaw@example.com")
set(CPACK_PACKAGE_VENDOR      "KernKlaw Project")

# DEB
set(CPACK_DEBIAN_PACKAGE_DEPENDS
  "libcurl4, libjson-c5, libcap2, libreadline8, libsystemd0, liburing2")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
  "${CMAKE_SOURCE_DIR}/packaging/debian/postinst")

# RPM
set(CPACK_RPM_PACKAGE_REQUIRES
  "libcurl, json-c, libcap, readline, systemd-libs, liburing")
set(CPACK_RPM_PACKAGE_LICENSE "MIT")

include(CPack)

# ── Summary ───────────────────────────────────────────────────────────
message(STATUS "")
message(STATUS "KernKlaw-Linux ${PROJECT_VERSION} — configuration summary")
message(STATUS "  Build type  : ${CMAKE_BUILD_TYPE}")
message(STATUS "  Install to  : ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  eBPF build  : ${BUILD_EBPF}")
message(STATUS "")
