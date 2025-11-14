/* SPDX-License-Identifier: BSD-3-Clause */
#include "ior_log.h"

#ifdef IOR_HAVE_LOG

#include <stdarg.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* Global logging state */
static struct {
	FILE *file;
	pthread_mutex_t lock;
	int initialized;
} ior_log_state = {
	.file = NULL,
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.initialized = 0,
};

void ior_log_init(const char *filename)
{
	pthread_mutex_lock(&ior_log_state.lock);

	/* Already initialized - skip */
	if (ior_log_state.initialized) {
		pthread_mutex_unlock(&ior_log_state.lock);
		return;
	}

	/* Check environment variable if no filename provided */
	if (filename == NULL) {
		filename = getenv("IOR_LOG_FILE");
	}

	/* Use stderr if no file specified */
	if (filename == NULL || filename[0] == '\0') {
		ior_log_state.file = stderr;
	} else {
		/* Open log file in append mode */
		ior_log_state.file = fopen(filename, "a");
		if (!ior_log_state.file) {
			/* Fall back to stderr on error */
			fprintf(stderr, "Warning: Failed to open log file '%s': %s\n", filename,
					strerror(errno));
			ior_log_state.file = stderr;
		} else {
			/* Set line buffering for better output */
			setvbuf(ior_log_state.file, NULL, _IOLBF, 0);

			/* Write header */
			struct timeval tv;
			gettimeofday(&tv, NULL);
			fprintf(ior_log_state.file, "\n========================================\n");
			fprintf(ior_log_state.file, "IOR Log Started: %ld.%06ld\n", tv.tv_sec, tv.tv_usec);
			fprintf(ior_log_state.file, "PID: %d, File: %s\n", getpid(), filename);
			fprintf(ior_log_state.file, "========================================\n\n");
			fflush(ior_log_state.file);
		}
	}

	ior_log_state.initialized = 1;

	pthread_mutex_unlock(&ior_log_state.lock);
}

void ior_log_destroy(void)
{
	pthread_mutex_lock(&ior_log_state.lock);

	if (!ior_log_state.initialized) {
		pthread_mutex_unlock(&ior_log_state.lock);
		return;
	}

	if (ior_log_state.file && ior_log_state.file != stderr) {
		/* Write footer */
		struct timeval tv;
		gettimeofday(&tv, NULL);
		fprintf(ior_log_state.file, "\n========================================\n");
		fprintf(ior_log_state.file, "IOR Log Ended: %ld.%06ld\n", tv.tv_sec, tv.tv_usec);
		fprintf(ior_log_state.file, "========================================\n\n");
		fflush(ior_log_state.file);
		fclose(ior_log_state.file);
	}

	ior_log_state.file = NULL;
	ior_log_state.initialized = 0;

	pthread_mutex_unlock(&ior_log_state.lock);
}

void ior_log_internal(
		int level, const char *level_str, const char *func, int line, const char *fmt, ...)
{
	/* Check log level */
	if (level < IOR_LOG_LEVEL) {
		return;
	}

	/* Initialize with stderr if not done yet */
	if (!ior_log_state.initialized) {
		ior_log_init(NULL);
	}

	/* Get timestamp */
	struct timeval tv;
	gettimeofday(&tv, NULL);

	/* Thread-safe logging */
	pthread_mutex_lock(&ior_log_state.lock);

	FILE *out = ior_log_state.file ? ior_log_state.file : stderr;

	/* Write log header: [timestamp][level][tid=...][pid=...] func:line: */
	fprintf(out, "[%ld.%06ld][%s][tid=%lu][pid=%d] %s:%d: ", tv.tv_sec, tv.tv_usec, level_str,
			(unsigned long) pthread_self(), getpid(), func, line);

	/* Write message */
	va_list args;
	va_start(args, fmt);
	vfprintf(out, fmt, args);
	va_end(args);

	fprintf(out, "\n");

	/* Flush to ensure output appears immediately (important for debugging crashes) */
	fflush(out);

	pthread_mutex_unlock(&ior_log_state.lock);
}

#endif /* IOR_HAVE_LOG */
