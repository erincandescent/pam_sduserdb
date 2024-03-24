// SPDX-License-Identifier: ISC

// crypt_r
#define _GNU_SOURCE

#include "common.h"
#include "util.h"
#include <time.h>
#include <syslog.h>

#include <crypt.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <varlink.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	long rv;
	const char *username = NULL;
	pam_fail_delay(pamh, 2*1000*1000);

	// Get username (either from PAM_USER item, or by asking the conversation function for it)
	rv = pam_get_user(pamh, &username, NULL);
	if (rv == PAM_CONV_AGAIN) {
		return pam_syslog(pamh, LOG_DEBUG, "pam_get_user not ready yet; returning PAM_INCOMPLETE"), PAM_INCOMPLETE;
	} else if (rv != PAM_SUCCESS) {
		return log_err_pam(pamh, rv, "pam_get_user"), rv;
	} else if (!username) {
		return pam_syslog(pamh, LOG_ERR, "unable to identify user"), PAM_USER_UNKNOWN;
	}

	// Lookup & cache user record,
	CLEANUP(varlink_object_unrefp) VarlinkObject *record = NULL;
	rv = lookup_user_record(pamh, &username, &record);
	if (rv != PAM_SUCCESS)
		return rv;

	// Fetch password
	const char* authtok = NULL;
	rv = pam_get_authtok(pamh, PAM_AUTHTOK, &authtok, NULL);
	if (rv == PAM_CONV_AGAIN) {
		return pam_syslog(pamh, LOG_DEBUG, "pam_get_authtok not ready yet; returning PAM_INCOMPLETE"), PAM_INCOMPLETE;
	} else if (rv != PAM_SUCCESS) {
		return log_err_pam(pamh, rv, "pam_get_authtok"), rv;
	} else if (!authtok) {
		return pam_syslog(pamh, LOG_ERR, "authtok null"), PAM_AUTH_ERR;
	}

	pam_syslog(pamh, LOG_INFO, "user '%s' authtok '%s'", username, authtok);

	// Try user's password(s)
	VarlinkObject *priv = NULL;
	rv = varlink_object_get_object(record, "privileged", &priv);
	if (rv == -VARLINK_ERROR_UNKNOWN_FIELD) {
		return pam_syslog(pamh, LOG_ERR, "user '%s' has no privileged section", username), PAM_AUTHINFO_UNAVAIL;
	} else if (rv < 0) {
		return log_err_varlink(pamh, rv, "get r.privileged"), PAM_SERVICE_ERR;
	}

	VarlinkArray *hashed_passwords;
	rv = varlink_object_get_array(priv, "hashedPassword", &hashed_passwords);
	if (rv == -VARLINK_ERROR_UNKNOWN_FIELD) {
		return pam_syslog(pamh, LOG_ERR, "user '%s' has no hashedPassword field", username), PAM_AUTH_ERR;
	} else if (rv < 0) {
		return log_err_varlink(pamh, rv, "get r.privileged.hashedPassword"), PAM_SERVICE_ERR;
	}

	struct crypt_data crypt_state = {};
	for (unsigned long i = 0, n = varlink_array_get_n_elements(hashed_passwords); i < n; i++) {
		const char *existing_hash = NULL;
		rv = varlink_array_get_string(hashed_passwords, i, &existing_hash);
		if (rv < 0)
			return log_err_varlink(pamh, rv, "getting hashed password"), PAM_SERVICE_ERR;

		const char *k = crypt_r(authtok, existing_hash, &crypt_state);
		if (strcmp(k, existing_hash) == 0) {
			return pam_syslog(pamh, LOG_INFO, "user '%s' authenticated by user record", username), PAM_SUCCESS;
		}
	}

	// TODO: Handle recovery passwords?

	return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	// For now...
	return PAM_IGNORE;
}
