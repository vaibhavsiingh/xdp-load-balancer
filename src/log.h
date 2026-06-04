/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LB_LOG_H
#define LB_LOG_H

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

static inline void lb_log(const char *level, const char *fmt, ...)
{
	char ts[32];
	struct tm tm;
	time_t now = time(NULL);
	va_list ap;

	localtime_r(&now, &tm);
	strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);
	fprintf(stderr, "%s %s ", ts, level);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

#define LOG_INFO(...)  lb_log("INFO", __VA_ARGS__)
#define LOG_WARN(...)  lb_log("WARN", __VA_ARGS__)
#define LOG_ERROR(...) lb_log("ERROR", __VA_ARGS__)

#endif
