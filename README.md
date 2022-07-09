# pam_sduserdb
A PAM account module backed by the systemd user database

Slot this into your PAM stack with a line along the lines of 

```
account sufficient pam_sduserdb.so
```

To lookup in a specific service rather than using the systemd-userdbd multiplexer,
specify the service as a parameter:

```
account sufficient pam_sduserdb.so service=com.example.userdb
```

Note that in the default configuration, the systemd-userdbd multiplexer must be enabled.
Ensure `systemd-userdbd.socket` is active on your system

This module largely functions as a substitute for the default `pam_unix` module and should
have the same behavior

## Why?
My systems run NixOS, and on NixOS NSS lookups via the `shadow` (and `gshadow`) maps only 
works for glibc provided backends (such as `passwd`, but not `systemd` or other dynamic 
providers). There are various reasons for this, both good and bad; but due to the design
of the NSS mechanism this is very difficult to fix.

A consequence of this is that `pam_unix` fails to lookup accounts from 
[User DB API](https://systemd.io/USER_GROUP_API/) backends, and prevents those users from 
logging in.

By instead talking to the User DB API, we avoid the problems with the NSS API.

As a more general matter, the user DB API is preferable to the NSS model of loading arbitrary
plugins into every process, and avoids some of the issues associated with glibc's `nscd`

## Dependencies

 * [Linux PAM](http://linux-pam.org); other PAM implementations untested
 * [libvarlink](http://github.com/varlink/libvarlink), as a client library for the [User/Group Record Lookup API](https://systemd.io/USER_GROUP_API/)
 * A backend service. In the default configuration, [systemd-userdbd](https://www.freedesktop.org/software/systemd/man/systemd-userdbd.service.html) is necessary