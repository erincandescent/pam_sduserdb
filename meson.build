# SPDX-License-Identifier: ISC
project('pam_sduserdb', 'c')

pamlibdir = get_option('pamlibdir')
if pamlibdir == ''
	pamlibdir = get_option('libdir') / 'security'
endif


libpam = dependency('pam')
libvarlink = dependency('libvarlink')

pam_sd_userdb = shared_library(
	'pam_sduserdb',
	'pam_sduserdb.c',
	name_prefix : '',
	c_args : ['-g'],
	link_args : ['-shared'],
	dependencies : [libpam, libvarlink],
	install : true,
	install_tag : 'pam',
	install_dir : pamlibdir
)