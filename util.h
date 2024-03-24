// SPDX-License-Identifier: ISC
#ifndef UTIL_H
#define UTIL_H
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <varlink.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#define CLEANUP(_x) __attribute__((__cleanup__(_x)))
#define TAKE(_x, _replace) ({\
	typeof(_x) *_p = &(_x); \
	typeof(_x)  _v = *_p; \
	*_p = (_replace); \
	_v; \
})
#define TAKE_PTR(_x) TAKE(_x, NULL)

inline void freep(void *p) {
	free(*(void **)p);
}

void log_err_varlink(pam_handle_t *pamh, long rv, const char* reason);
void log_err_pam(pam_handle_t *pamh, int rv, const char* reason);
void log_err_errno(pam_handle_t *pamh, const char* reason);

// pam_get_item has a very annoying prototype which requires you
// create a temporary void*, pass a pointer to that, and then assign
// the resulting value to a variable of your desired type
//
// This helper hides that from our code
static inline int pam_get_string_item(pam_handle_t *pamh, int item_type, const char **p)
{
	const void *v;
	int rv = pam_get_item(pamh, item_type, &v);
	*p = v;
	return rv;
}

void pam_msg(pam_handle_t *pamh, int flags, int style, const char *msg);
static inline void pam_say(pam_handle_t *pamh, int flags, const char *msg)
{ pam_msg(pamh, flags, PAM_TEXT_INFO, msg); }
static inline void pam_err(pam_handle_t *pamh, int flags, const char *msg)
{ pam_msg(pamh, flags, PAM_ERROR_MSG, msg); }

char* trim_prefix(const char *str, const char *pfx);

long varlink_call_sync(
	VarlinkConnection *conn,
	const char *method,
	VarlinkObject *params,
	char **error,
	VarlinkObject **ret);

#endif
