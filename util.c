// SPDX-License-Identifier: ISC
#include "util.h"
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <syslog.h>
#include <sys/epoll.h>

#include <varlink.h>

static_assert(EPOLLIN  == POLLIN, "EPOLLIN and POLLIN must match");
static_assert(EPOLLOUT == POLLOUT, "EPOLLIN and POLLIN must match");

extern void freep(void *p);

void log_err_varlink(pam_handle_t *pamh, long rv, const char* reason)
{
	pam_syslog(pamh, LOG_ERR, "%s: %s", reason, varlink_error_string(-rv));
}

void log_err_pam(pam_handle_t *pamh, int rv, const char* reason)
{
	pam_syslog(pamh, LOG_ERR, "%s: %s", reason, pam_strerror(pamh, rv));
}

void log_err_errno(pam_handle_t *pamh, const char* reason)
{
	pam_syslog(pamh, LOG_ERR, "%s: %s", reason, strerror(errno));
}

void pam_msg(pam_handle_t *pamh, int flags, int style, const char *msg)
{
	if (flags & PAM_SILENT)
		return;
	pam_prompt(pamh, style, NULL, "%s", msg);
}

char *trim_prefix(const char *str, const char *pfx)
{
	while (*str == *pfx)
		str++, pfx++;
	return *pfx ? NULL : (char*)str;
}

typedef struct {
	bool done;
	char **error;
	VarlinkObject **ret;
} call_ctx;

static long varlink_call_sync_cb(
	VarlinkConnection *connection,
	const char *error,
	VarlinkObject *parameters,
	uint64_t flags,
	void *userdata)
{
	call_ctx *ctx = userdata;

	ctx->done = true;
	*ctx->error = error      ? strdup(error)                  : NULL;
	*ctx->ret   = parameters ? varlink_object_ref(parameters) : NULL;
	return 0;
}

long varlink_call_sync(
	VarlinkConnection *conn,
	const char *method,
	VarlinkObject *params,
	char **error,
	VarlinkObject **ret)
{
	call_ctx ctx = {
		.done = false,
		.error = error,
		.ret = ret,
	};

	long rv = varlink_connection_call(conn, method, params, 0, varlink_call_sync_cb, &ctx);
	if (rv < 0) return rv;

	struct pollfd pfd;
	// (returns fd, or a negative varlink error)
	pfd.fd = varlink_connection_get_fd(conn);
	if (pfd.fd < 0) return pfd.fd;

	do {
		pfd.events = varlink_connection_get_events(conn);
	    rv = poll(&pfd, 1, -1);
	    if (rv < 0) return -VARLINK_ERROR_SENDING_MESSAGE;
	    rv = varlink_connection_process_events(conn, pfd.revents);
	    if (rv < 0) return rv;
   } while (!ctx.done);
   return 0;
}
