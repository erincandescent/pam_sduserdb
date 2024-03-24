# pam_sduserdb
A PAM account module backed by the systemd user database

Slot this into your PAM stack with a line along the lines of 

```
auth sufficient pam_sduserdb.so
account sufficient pam_sduserdb.so
```

Note that the systemd-userdbd multiplexer must be enabled. Ensure `systemd-userdbd.socket` 
is active on your system

This module largely functions as a substitute for the default `pam_unix` module and should
have the same behavior

## Why?
The initial motivation was that I run NixOS, and on NixOS NSS plugins are not invoked for
the `shadow`/`gshadow` maps (for complicated but fundamentally good reasons). This means that
`nss_systemd` is not invoked when `pam_unix` calls `getspnam`, and hence `pam_unix` thinks
the user account is disabled.

Previous versions of this module covered just the PAM `account` stack, and would validate
that the account was enabled by doing a direct user record lookup. The current version also
implements the `auth` stack, and will check the user's password against the 
`privileged.hashedPasswords"` array.

## Future Directions
Future versions will proxy a large subset of the `pam_sm_authenticate` and `pam_sm_setcred` 
APIs over Varlink to the service providing the record. This will enable the backend process 
to implement authentication however it wants. 

(If the backend service doesn't implement these APIs, pam_sduserdb will continue to fall back
to folloiwng the information contained statically within the user record)

## Dependencies

 * [Linux PAM](http://linux-pam.org); other PAM implementations untested
 * [libvarlink](http://github.com/varlink/libvarlink), as a client library for the [User/Group Record Lookup API](https://systemd.io/USER_GROUP_API/)
 * a `crypt(3)` implementation (the same one as PAM's `pam_unix` is linked against)
 * [systemd-userdbd](https://www.freedesktop.org/software/systemd/man/systemd-userdbd.service.html), or another service reimplementing the user DB multiplexer
 * A backend service
