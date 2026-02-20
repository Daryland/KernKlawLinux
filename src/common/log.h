/* log.h — Unified logging for KernKlaw-Linux
 * Daemon uses syslog; shell/tools use coloured stderr.
 * Set CLAW_LOG_SYSLOG=1 before including to enable syslog mode.
 */
#pragma once
#ifndef CLAW_LOG_H
#define CLAW_LOG_H

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <errno.h>

/* ── Log levels ───────────────────────────────────────────────────── */
typedef enum {
    CLAW_LOG_TRACE = 0,
    CLAW_LOG_DEBUG,
    CLAW_LOG_INFO,
    CLAW_LOG_WARN,
    CLAW_LOG_ERROR,
    CLAW_LOG_FATAL,
} claw_loglevel_t;

extern claw_loglevel_t g_log_level;   /* defined in log.c / set at startup */

/* ── ANSI colours (disabled when not a tty) ───────────────────────── */
#define _CLAW_RST  "\033[0m"
#define _CLAW_GRY  "\033[90m"
#define _CLAW_CYN  "\033[36m"
#define _CLAW_GRN  "\033[32m"
#define _CLAW_YLW  "\033[33m"
#define _CLAW_RED  "\033[31m"
#define _CLAW_BRED "\033[1;31m"

#ifdef CLAW_LOG_SYSLOG
  #include <syslog.h>
  #define _CLAW_LOG(lvl, syl, fmt, ...) \
      do { if ((lvl) >= g_log_level) syslog((syl), fmt, ##__VA_ARGS__); } while(0)
  #define log_trace(fmt,...) _CLAW_LOG(CLAW_LOG_TRACE, LOG_DEBUG,   fmt, ##__VA_ARGS__)
  #define log_debug(fmt,...) _CLAW_LOG(CLAW_LOG_DEBUG, LOG_DEBUG,   fmt, ##__VA_ARGS__)
  #define log_info( fmt,...) _CLAW_LOG(CLAW_LOG_INFO,  LOG_INFO,    fmt, ##__VA_ARGS__)
  #define log_warn( fmt,...) _CLAW_LOG(CLAW_LOG_WARN,  LOG_WARNING, fmt, ##__VA_ARGS__)
  #define log_error(fmt,...) _CLAW_LOG(CLAW_LOG_ERROR, LOG_ERR,     fmt, ##__VA_ARGS__)
  #define log_fatal(fmt,...) _CLAW_LOG(CLAW_LOG_FATAL, LOG_CRIT,    fmt, ##__VA_ARGS__)
#else
  /* stderr path: [TIMESTAMP LEVEL file:line] msg */
  static inline const char *_claw_lname(claw_loglevel_t l) {
      static const char *n[] = {"TRACE","DEBUG"," INFO"," WARN","ERROR","FATAL"};
      return (l < 6) ? n[l] : "?????";
  }
  static inline const char *_claw_lcol(claw_loglevel_t l) {
      static const char *c[] = {_CLAW_GRY,_CLAW_CYN,_CLAW_GRN,
                                  _CLAW_YLW,_CLAW_RED,_CLAW_BRED};
      return (l < 6) ? c[l] : "";
  }
  #define _CLAW_LOG_STDERR(lvl, fmt, ...) \
    do { \
        if ((lvl) >= g_log_level) { \
            struct timespec _ts; clock_gettime(CLOCK_REALTIME, &_ts); \
            fprintf(stderr, "%s[%ld.%03ld %s %s:%d]" _CLAW_RST " " fmt "\n", \
                _claw_lcol(lvl), \
                (long)_ts.tv_sec, (long)(_ts.tv_nsec / 1000000L), \
                _claw_lname(lvl), \
                (strrchr(__FILE__,'/')?strrchr(__FILE__,'/')+1:__FILE__), \
                __LINE__, ##__VA_ARGS__); \
        } \
    } while(0)
  #define log_trace(fmt,...) _CLAW_LOG_STDERR(CLAW_LOG_TRACE, fmt, ##__VA_ARGS__)
  #define log_debug(fmt,...) _CLAW_LOG_STDERR(CLAW_LOG_DEBUG, fmt, ##__VA_ARGS__)
  #define log_info( fmt,...) _CLAW_LOG_STDERR(CLAW_LOG_INFO,  fmt, ##__VA_ARGS__)
  #define log_warn( fmt,...) _CLAW_LOG_STDERR(CLAW_LOG_WARN,  fmt, ##__VA_ARGS__)
  #define log_error(fmt,...) _CLAW_LOG_STDERR(CLAW_LOG_ERROR, fmt, ##__VA_ARGS__)
  #define log_fatal(fmt,...) _CLAW_LOG_STDERR(CLAW_LOG_FATAL, fmt, ##__VA_ARGS__)
#endif

/* die() — log fatal + errno string + abort */
#define die(fmt, ...) \
    do { \
        log_fatal(fmt ": %s", ##__VA_ARGS__, strerror(errno)); \
        _exit(1); \
    } while(0)

/* ── Runtime level (defined once in main translation unit) ───────── */
#ifdef CLAW_LOG_IMPL
claw_loglevel_t g_log_level = CLAW_LOG_INFO;
#endif

#endif /* CLAW_LOG_H */
