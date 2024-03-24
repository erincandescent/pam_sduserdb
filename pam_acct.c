// SPDX-License-Identifier: ISC
#include "common.h"
#include "util.h"
#include <time.h>
#include <syslog.h>

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <varlink.h>

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	long rv;
	
	const char *username = NULL;
	rv = pam_get_string_item(pamh, PAM_USER, &username);
	if (rv != PAM_SUCCESS) {
		log_err_pam(pamh, rv, "retrieving username");
		return rv == PAM_BAD_ITEM ? PAM_USER_UNKNOWN : PAM_SERVICE_ERR;
	} else if (username == NULL) {
		return pam_syslog(pamh, LOG_ERR, "unable to identify user"), PAM_USER_UNKNOWN;
	}

	CLEANUP(varlink_object_unrefp) VarlinkObject *record = NULL;
	rv = lookup_user_record(pamh, &username, &record);
	if (rv != PAM_SUCCESS)
		return rv;

	// Handle lockout conditions
	bool locked;
	rv = varlink_object_get_bool(record, "locked", &locked);
	if (rv == 0 && locked) {
		pam_syslog(pamh, LOG_ERR, "user '%s' account locked", username);
		pam_err(pamh, flags, "Your account is locked");
		return PAM_PERM_DENIED;
	} else if (rv != 0 && rv != -VARLINK_ERROR_UNKNOWN_FIELD) {
		return log_err_varlink(pamh, rv, "getting 'locked' field"), PAM_SERVICE_ERR;
	}

	struct timespec now;
	rv = clock_gettime(CLOCK_REALTIME, &now);
	if (rv != 0)
		return log_err_errno(pamh, "clock_gettime"), PAM_SERVICE_ERR;
	int64_t now_usec = now.tv_sec * 1000000 + now.tv_nsec / 1000;
	int64_t not_before_usec, not_after_usec;
	rv = varlink_object_get_int(record, "notBeforeUSec", &not_before_usec);
	if (rv == 0 && now_usec < not_before_usec) {
		pam_syslog(pamh, LOG_ERR, "user '%s' account not yet valid", username);
		pam_err(pamh, flags, "Your account is not yet valid");
		return PAM_ACCT_EXPIRED;
	} else if (rv != 0 && rv != -VARLINK_ERROR_UNKNOWN_FIELD) {
		return log_err_varlink(pamh, rv, "getting 'notBeforeUSec' field"), PAM_SERVICE_ERR;
	}

	rv = varlink_object_get_int(record, "notAfterUSec", &not_after_usec);
	if (rv == 0 && now_usec > not_after_usec) {
		pam_syslog(pamh, LOG_ERR, "user '%s' account expired", username);
		pam_err(pamh, flags, "Your account has expired");
		return PAM_ACCT_EXPIRED;
	} else if (rv != 0 && rv != -VARLINK_ERROR_UNKNOWN_FIELD) {
		return log_err_varlink(pamh, rv, "getting 'notAfterUSec' field"), PAM_SERVICE_ERR;
	}

	pam_syslog(pamh, LOG_INFO, "user '%s' approved", username);

	return PAM_SUCCESS;
}
