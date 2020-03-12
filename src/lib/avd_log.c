#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "avd_log.h"

static struct {
    FILE        *fp;
    int32_t     level;
    int32_t     quiet;
} avd_logger;

static const char *level_tags[] = {
    "DEBUG",
    "INFO",
    "WARN",
    "ERROR",
    "FATAL"
};

void set_log_file(char *fname) {
    avd_logger.fp = fopen(fname, "a+");
}

void set_log_level(int32_t level) {
    avd_logger.level = level;
    if (avd_logger.level <= LOG_DEBUG) {
#define DISABLE_LINE_NO 1
    } else {
#undef DISABLE_LINE_NO
    }
}

void set_log_quiet(int32_t quiet) {
    avd_logger.quiet = quiet ? 1 : 0;
}

void avd_log (int32_t level, const char *fmt, ...) {
    if (level < avd_logger.level || (avd_logger.quiet && !avd_logger.fp)) {
        return;
    }

    time_t tim = time(NULL);
    struct tm *local_time;

    local_time = localtime(&tim);

    if (!avd_logger.quiet) {
        va_list args;
        char buf[TIME_SZ];

        buf[strftime(buf, sizeof(buf), "%H:%M:%S", local_time)] = '\0';

        fprintf(stderr, "[%s][%s] ::: ", buf, level_tags[level]);

        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
        fprintf(stderr, "\n");
        fflush(stderr);
    }

    if (avd_logger.fp) {
        va_list args;
        char buf[DATETIME_SZ];

        buf[strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", local_time)] = '\0';

        fprintf(avd_logger.fp, "[%s][%s] ::: ", buf, level_tags[level]);

        va_start(args, fmt);
        vfprintf(avd_logger.fp, fmt, args);
        va_end(args);
        fprintf(avd_logger.fp, "\n");
        fflush(avd_logger.fp);
    }
}
