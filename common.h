// SPDX-License-Identifier: ISC
#ifndef COMMON_H
#define COMMON_H
#include <stdbool.h>
#include <string.h>
#include <security/pam_modules.h>
#include <varlink.h>

// If we have a user record cached in the handle and the username is an *exact*
// match for the passed username, returns a reference to it.
//
// Otherwise, asks the multiplexer to lookup that user, caches the returned record,
// updates the PAM username to match that contained within said user record, and
// returns the result.
//
// In all cases you must remember to varlink_object_unref the returned record
//
// Returns a PAM status
int lookup_user_record(
	pam_handle_t *pamh,
	const char **p_username,
	VarlinkObject **p_record);

#endif
