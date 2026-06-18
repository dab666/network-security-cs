#include "logger.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

static FILE *g_logger = NULL;
static char g_role[32] = "stage3";
static pthread_mutex_t g_logger_lock = PTHREAD_MUTEX_INITIALIZER;

static void logger_prefix_locked(void) {
	time_t now = time(NULL);
	struct tm tm_now;
	localtime_r(&now, &tm_now);

	char ts[32];
	strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_now);
	fprintf(g_logger, "[%s] [%s] [pid=%ld] ", ts, g_role, (long)getpid());
}

int logger_init(const char *path, const char *role) {
	if (!path) {
		return -1;
	}

	pthread_mutex_lock(&g_logger_lock);
	if (g_logger) {
		fclose(g_logger);
		g_logger = NULL;
	}

	g_logger = fopen(path, "w");
	if (!g_logger) {
		pthread_mutex_unlock(&g_logger_lock);
		return -1;
	}

	if (role && role[0] != '\0') {
		snprintf(g_role, sizeof(g_role), "%s", role);
	}

	logger_prefix_locked();
	fprintf(g_logger, "logger started, path=%s\n", path);
	fflush(g_logger);
	pthread_mutex_unlock(&g_logger_lock);
	return 0;
}

void logger_close(void) {
	pthread_mutex_lock(&g_logger_lock);
	if (g_logger) {
		logger_prefix_locked();
		fprintf(g_logger, "logger closed\n");
		fclose(g_logger);
		g_logger = NULL;
	}
	pthread_mutex_unlock(&g_logger_lock);
}

void logger_log(const char *fmt, ...) {
	if (!fmt) {
		return;
	}

	pthread_mutex_lock(&g_logger_lock);
	if (!g_logger) {
		pthread_mutex_unlock(&g_logger_lock);
		return;
	}

	logger_prefix_locked();
	va_list ap;
	va_start(ap, fmt);
	vfprintf(g_logger, fmt, ap);
	va_end(ap);
	fputc('\n', g_logger);
	fflush(g_logger);
	pthread_mutex_unlock(&g_logger_lock);
}

void logger_hex(const char *label, const uint8_t *buf, size_t len) {
	pthread_mutex_lock(&g_logger_lock);
	if (!g_logger) {
		pthread_mutex_unlock(&g_logger_lock);
		return;
	}

	logger_prefix_locked();
	fprintf(g_logger, "%s len=%zu hex=", label ? label : "hex", len);
	for (size_t i = 0; i < len; i++) {
		fprintf(g_logger, "%02x", buf[i]);
	}
	fputc('\n', g_logger);
	fflush(g_logger);
	pthread_mutex_unlock(&g_logger_lock);
}

