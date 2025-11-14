/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef IOR_LOG_H
#define IOR_LOG_H

#include "config.h"
#include <stdio.h>

#ifdef IOR_HAVE_LOG

#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <unistd.h>

/* Log levels */
#define IOR_LOG_LEVEL_TRACE 0
#define IOR_LOG_LEVEL_DEBUG 1
#define IOR_LOG_LEVEL_INFO 2
#define IOR_LOG_LEVEL_WARN 3
#define IOR_LOG_LEVEL_ERROR 4

/* Default log level if not specified */
#ifndef IOR_LOG_LEVEL
#define IOR_LOG_LEVEL IOR_LOG_LEVEL_INFO
#endif

/* Initialize logging (optional - call once at program start)
 *
 * If filename is NULL, logs to stderr (default)
 * If filename is provided, logs to that file (thread-safe, buffered)
 * Subsequent calls are no-ops if already initialized
 *
 * Environment variable IOR_LOG_FILE can also be used to set the log file
 */
void ior_log_init(const char *filename);

/* Cleanup logging (optional - call at program exit) */
void ior_log_destroy(void);

/* Internal logging function - do not call directly */
void ior_log_internal(int level, const char *level_str, const char *func, int line, const char *fmt,
		...) __attribute__((format(printf, 5, 6)));

/* Logging macros */
#define IOR_LOG_TRACE(...) \
	ior_log_internal(IOR_LOG_LEVEL_TRACE, "TRACE", __func__, __LINE__, __VA_ARGS__)

#define IOR_LOG_DEBUG(...) \
	ior_log_internal(IOR_LOG_LEVEL_DEBUG, "DEBUG", __func__, __LINE__, __VA_ARGS__)

#define IOR_LOG_INFO(...) \
	ior_log_internal(IOR_LOG_LEVEL_INFO, "INFO", __func__, __LINE__, __VA_ARGS__)

#define IOR_LOG_WARN(...) \
	ior_log_internal(IOR_LOG_LEVEL_WARN, "WARN", __func__, __LINE__, __VA_ARGS__)

#define IOR_LOG_ERROR(...) \
	ior_log_internal(IOR_LOG_LEVEL_ERROR, "ERROR", __func__, __LINE__, __VA_ARGS__)

#else /* !IOR_HAVE_LOG */

/* Logging disabled - all functions and macros are no-ops */
static inline void ior_log_init(const char *filename)
{
	(void) filename;
}
static inline void ior_log_destroy(void)
{
}

#define IOR_LOG_TRACE(...) \
	do { \
	} while (0)
#define IOR_LOG_DEBUG(...) \
	do { \
	} while (0)
#define IOR_LOG_INFO(...) \
	do { \
	} while (0)
#define IOR_LOG_WARN(...) \
	do { \
	} while (0)
#define IOR_LOG_ERROR(...) \
	do { \
	} while (0)

#endif /* IOR_HAVE_LOG */

#endif /* IOR_LOG_H */
