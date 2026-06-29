#include "sentinel_common.h"
#include <stdio.h>
#include <stdarg.h>
#include <sys/time.h>

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

const char *log_level_to_str(LogLevel level) {
    switch (level) {
        case LOG_LEVEL_DEBUG:    return "DEBUG";
        case LOG_LEVEL_INFO:     return "INFO";
        case LOG_LEVEL_WARNING:  return "WARN";
        case LOG_LEVEL_ERROR:    return "ERROR";
        case LOG_LEVEL_CRITICAL: return "FATAL";
        default:                 return "UNKNOWN";
    }
}

uint64_t sentinel_current_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)(tv.tv_sec) * 1000 + (tv.tv_usec / 1000);
}

void sentinel_log(LogLevel level, const char *format, ...) {
    pthread_mutex_lock(&log_mutex);

    // Print timestamp
    time_t rawtime;
    struct tm *timeinfo;
    char time_buffer[20];

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", timeinfo);

    printf("[%s] [%s] ", time_buffer, log_level_to_str(level));

    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    printf("\n");
    fflush(stdout);

    pthread_mutex_unlock(&log_mutex);
}
