// SPDX-License-Identifier: ISC
#include "common.h"
#include "util.h"
#include <string.h>
#include <syslog.h>

static const char *user_record_data = "pam_sduserdb.user_record";

static void varlink_object_cleanup(pam_handle_t *pamh, void *data, int error_status)
{
	varlink_object_unref((VarlinkObject*) data);
}

int lookup_user_record(
	pam_handle_t *pamh,
	const char **p_username,
	VarlinkObject **p_record
)
{
	const void *v_record;
	long rv = pam_get_data(pamh, user_record_data, &v_record);
	if (rv == PAM_SUCCESS) {
		VarlinkObject *record = (VarlinkObject*)v_record;
		const char *record_username;
		rv = varlink_object_get_string(record, "userName", &record_username);
		if (rv == 0 && strcmp(*p_username, record_username) == 0) {
			*p_record = varlink_object_ref(record);
			return PAM_SUCCESS;
		}
	} else if (rv != PAM_NO_MODULE_DATA) {
		return log_err_pam(pamh, rv, "error looking up cached user record"), rv;
	}

	// No record cached or the wrong record is cached
	// Reach out to the multiplexer
	CLEANUP(varlink_connection_freep) VarlinkConnection *conn = NULL;
	rv = varlink_connection_new(&conn, "unix:/run/systemd/userdb/io.systemd.Multiplexer");
	if (rv < 0)
		return log_err_varlink(pamh, rv, "connecting to multiplexer"), PAM_SERVICE_ERR;

	CLEANUP(varlink_object_unrefp) VarlinkObject *req = NULL;
	rv = varlink_object_new(&req);
	if (rv == 0) rv = varlink_object_set_string(req, "userName", *p_username);
	if (rv == 0) rv = varlink_object_set_string(req, "service", "io.systemd.Multiplexer");
	if (rv < 0)
		return log_err_varlink(pamh, rv, "constructing io.systemd.UserDatabase.GetUserRecord request"), PAM_SERVICE_ERR;

	CLEANUP(freep) char *error = NULL;
	CLEANUP(varlink_object_unrefp) VarlinkObject *rsp = NULL;
	rv = varlink_call_sync(conn, "io.systemd.UserDatabase.GetUserRecord", req, &error, &rsp);
	if (rv < 0) {
		return log_err_varlink(pamh, rv, "calling io.systemd.UserDatabase.GetUserRecord"), PAM_SERVICE_ERR;
	} else if (error && strcmp(error, "io.systemd.UserDatabase.NoRecordFound") == 0) {
		pam_syslog(pamh, LOG_WARNING, "unable to find user '%s'", *p_username);
		return PAM_USER_UNKNOWN;
	} else if (error) {
		pam_syslog(pamh, LOG_ERR, "user lookup returned error '%s' for user '%s'", error, *p_username);
		return PAM_SERVICE_ERR;
	} else if (!rsp) {
		pam_syslog(pamh, LOG_ERR, "user lookup returned null for user '%s'", *p_username);
	}

	VarlinkObject *record = NULL;
	rv = varlink_object_get_object(rsp, "record", &record);
	if (rv < 0)
		return log_err_varlink(pamh, rv, "record missing from user lookup response"), PAM_SERVICE_ERR;

	// Cache record
	rv = pam_set_data(pamh, user_record_data, varlink_object_ref(record), varlink_object_cleanup);
	if (rv != PAM_SUCCESS)
		return log_err_pam(pamh, rv, "caching user record"), rv;

	// Update PAM username
	rv = varlink_object_get_string(record, "userName", p_username);
	if (rv < 0)
		return log_err_varlink(pamh, rv, "getting userName from record"), PAM_SERVICE_ERR;
	rv = pam_set_item(pamh, PAM_USER, *p_username);
	if (rv != PAM_SUCCESS)
		return log_err_pam(pamh, rv, "normalising username"), rv;

	*p_record = varlink_object_ref(record);
	return 0;
}
