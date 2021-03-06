#ifndef _AVD_LOG_H_
#define _AVD_LOG_H_

#include <stdio.h>
#include <stdarg.h>
#include <inttypes.h>
#include <stdbool.h>

enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
    LOG_FATAL
};

#define TIME_SZ         16
#define DATETIME_SZ     32

#define avd_log_debug(...)  avd_log(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define avd_log_info(...)   avd_log(LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define avd_log_warn(...)   avd_log(LOG_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define avd_log_error(...)  avd_log(LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define avd_log_fatal(...)  avd_log(LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__)

void set_log_file(char *fname);
void set_log_level(int32_t level);
void set_log_quiet(bool quiet);
void avd_log (int32_t level, const char *file, int32_t line, const char *fmt,...);

#endif
