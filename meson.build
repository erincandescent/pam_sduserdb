# SPDX-License-Identifier: ISC
project('pam_sduserdb', 'c')

cc = meson.get_compiler('c')

pamlibdir = get_option('pamlibdir')
if pamlibdir == ''
	pamlibdir = get_option('libdir') / 'security'
endif

libpam = dependency('pam')
libvarlink = dependency('libvarlink')

libcrypt = dependency('libcrypt', 'libxcrypt', required: false)
if not libcrypt.found()
	libcrypt = cc.find_library('crypt')
endif

pam_sd_userdb = shared_library(
	'pam_sduserdb',
	['common.c', 'util.c', 'pam_acct.c', 'pam_auth.c'],
	name_prefix : '',
	c_args : ['-g'],
	link_args : ['-shared'],
	dependencies : [libpam, libvarlink, libcrypt],
	install : true,
	install_tag : 'pam',
	install_dir : pamlibdir
)
