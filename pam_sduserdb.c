// SPDX-License-Identifier: ISC

#define _GNU_SOURCE //asprintf
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include <poll.h>

#define PAM_SM_ACCOUNT
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <varlink.h>

#define CLEANUP(_x) __attribute__((__cleanup__(_x)))

static void str_freep(char **str)
{
	free(*str);
	*str = NULL;
}

static void say(pam_handle_t *pamh, int flags, const char *msg)
{
	if (flags & PAM_SILENT)
		return;

	pam_prompt(pamh, PAM_TEXT_INFO, NULL, "%s", msg);
}

static bool proc_err_varlink(pam_handle_t *pamh, long rv, const char *reason)
{
	if (rv >= 0)
		return false;

	pam_syslog(pamh, LOG_ERR, "(pam_sduserdb) %s: %s", reason, varlink_error_string(-rv));
	return true;
}

static bool proc_errno(pam_handle_t *pamh, bool cond, const char* reason)
{
	if (!cond)
		return false;
	pam_syslog(pamh, LOG_ERR, "(pam_sduserdb) %s: %s", reason, strerror(errno));
	return true;
}

#define RETURN_IF(_ret, _cond) do { if (_cond) return (_ret); } while(0)
#define RETURN_IF_ERRNO(_ret, _cond, _reason) RETURN_IF((_ret), proc_errno(pamh, (_cond), (_reason)))
#define RETURN_IF_VARLINK(_ret, _reason) RETURN_IF((_ret), proc_err_varlink(pamh, rv, (_reason)))

typedef struct {
	bool done;
	char **error;
	VarlinkObject **ret;
} call_ctx;

static long varling_call_sync_cb(
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

static long varlink_call_sync(
	pam_handle_t *pamh,
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

	long rv = varlink_connection_call(conn, method, params, 0, varling_call_sync_cb, &ctx);
	RETURN_IF(rv, rv < 0);

	struct pollfd pfd;
	pfd.fd = varlink_connection_get_fd(conn);
	RETURN_IF(pfd.fd, pfd.fd < 0);

	do {
		pfd.events = varlink_connection_get_events(conn);
	    rv = poll(&pfd, 1, -1);
	    RETURN_IF_ERRNO(-VARLINK_ERROR_SENDING_MESSAGE, rv < 0, "poll");
	    rv = varlink_connection_process_events(conn, pfd.revents);
	    RETURN_IF(rv, rv < 0);
   } while (!ctx.done);
   return 0;
}

typedef struct {
	const char *service;
} config;

static const char* trim_prefix(const char *str, const char *pfx)
{
	size_t slen   = strlen(str);
	size_t pfxlen = strlen(pfx);

	if (slen < pfxlen)
		return NULL;
	if (memcmp(str, pfx, pfxlen) != 0)
		return NULL;
	return str + pfxlen;
}

static int parse_config(pam_handle_t *pamh, config *out, int argc, const char **argv)
{
	for (int i = 0; i < argc; i++) {
		const char *val = NULL;
		if ((val = trim_prefix(argv[i], "service="))) {
			out->service = val;
		} else {
			pam_syslog(pamh, LOG_AUTH | LOG_ERR, "(pam_sduserdb) unknown parameter '%s'", argv[i]);
			return 1;
		}
	}
	return 0;
}

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	long rv;
	const char *username;
	const void *void_username;
	config cfg = {
		.service = "io.systemd.Multiplexer",
	};

	rv = parse_config(pamh, &cfg, argc, argv);
	RETURN_IF(PAM_SERVICE_ERR, rv != 0);

	rv = pam_get_item(pamh, PAM_USER, &void_username);
	username = void_username;
	if (rv != PAM_SUCCESS || username == NULL) {
		pam_syslog(pamh, LOG_ERR, "(pam_sduserdb) unable to identify user");
		return PAM_USER_UNKNOWN;
	}

	CLEANUP(str_freep) char *addr = NULL;
	rv = asprintf(&addr, "unix:/run/systemd/userdb/%s", cfg.service);
	RETURN_IF_ERRNO(PAM_SERVICE_ERR, rv < 0, "building address");

	CLEANUP(varlink_connection_freep) VarlinkConnection *conn = NULL;
	rv = varlink_connection_new(&conn, addr);
	RETURN_IF_VARLINK(PAM_SERVICE_ERR, "error opening connection");

	CLEANUP(varlink_object_unrefp) VarlinkObject *req = NULL;
	rv = varlink_object_new(&req);
	RETURN_IF_VARLINK(PAM_SERVICE_ERR, "error creating object");
	rv = varlink_object_set_string(req, "userName", username);
	RETURN_IF_VARLINK(PAM_SERVICE_ERR, "error creating object");
	rv = varlink_object_set_string(req, "service", cfg.service);
	RETURN_IF_VARLINK(PAM_SERVICE_ERR, "error creating object");

	CLEANUP(str_freep) char *error = NULL;
	CLEANUP(varlink_object_unrefp) VarlinkObject *rsp = NULL;
	rv = varlink_call_sync(pamh, conn, "io.systemd.UserDatabase.GetUserRecord", req, &error, &rsp);
	RETURN_IF_VARLINK(PAM_SERVICE_ERR, "error doing 'io.systemd.UserDatabase.GetUserRecord' call");

	if (error) {
		pam_syslog(pamh, LOG_ERR, "(pam_sduserdb) userdb returned error '%s'", error);
		RETURN_IF(PAM_USER_UNKNOWN, strcmp(error, "io.systemd.UserDatabase.NoRecordFound") == 0);
		return PAM_SERVICE_ERR;
	} else if (rsp == NULL) {
		pam_syslog(pamh, LOG_ERR, "(pam_sduserdb) userdb empty response?");
		return PAM_SERVICE_ERR;
	}

	VarlinkObject *record = NULL;
	rv = varlink_object_get_object(rsp, "record", &record);
	RETURN_IF_VARLINK(PAM_SERVICE_ERR, "error getting record");

	// Normalise username
	rv = varlink_object_get_string(record, "userName", &username);
	RETURN_IF_VARLINK(PAM_SERVICE_ERR, "error getting userName");
	rv = pam_set_item(pamh, PAM_USER, username);
	RETURN_IF(rv, rv != PAM_SUCCESS);

	// Handle lockout conditions
	bool locked;
	rv = varlink_object_get_bool(record, "locked", &locked);
	if (rv != -VARLINK_ERROR_UNKNOWN_FIELD) {
		RETURN_IF_VARLINK(PAM_SERVICE_ERR, "getting 'locked'");
		if (locked) {
			pam_syslog(pamh, LOG_ERR, "(pam_sduserdb) user '%s' account locked", username);
			say(pamh, flags, "Your account is locked");
			return PAM_PERM_DENIED;
		}
	}

	struct timespec now;
	rv = clock_gettime(CLOCK_REALTIME, &now);
	RETURN_IF_ERRNO(PAM_SERVICE_ERR, rv != 0, "clock_gettime");
	int64_t now_usec = now.tv_sec * 1000000 + now.tv_nsec / 1000;

	int64_t not_before_usec, not_after_usec;
	rv = varlink_object_get_int(record, "notBeforeUSec", &not_before_usec);
	if (rv != -VARLINK_ERROR_UNKNOWN_FIELD) {
		RETURN_IF_VARLINK(PAM_SERVICE_ERR, "getting 'notBeforeUSec'");
		if (now_usec < not_before_usec) {
			pam_syslog(pamh, LOG_ERR, "(pam_sduserdb) user '%s' account not yet valid", username);
			say(pamh, flags, "Your account is not yet valid");
			return PAM_ACCT_EXPIRED;
		}
	}

	rv = varlink_object_get_int(record, "notAfterUSec", &not_after_usec);
	if (rv != -VARLINK_ERROR_UNKNOWN_FIELD) {
		RETURN_IF_VARLINK(PAM_SERVICE_ERR, "getting 'notAfterUSec'");
		if (now_usec > not_after_usec) {
			pam_syslog(pamh, LOG_ERR, "(pam_sduserdb) user '%s' account expired", username);
			say(pamh, flags, "Your account has expired");
			return PAM_ACCT_EXPIRED;
		}
	}

	pam_syslog(pamh, LOG_ERR, "(pam_sduserdb) user '%s' approved", username);
	return PAM_SUCCESS;
}