# Makefile for GNU tar regression tests.

# Copyright (C) 1996, 1997, 1999, 2000, 2001, 2003, 2004 Free Software
# Foundation, Inc.

# François Pinard <pinard@iro.umontreal.ca>, 1988.
# Sergey Poznyakoff <gray@mirddin.farlep.net>, 2004.

## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2, or (at your option)
## any later version.

## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.

## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
## 02111-1307, USA.

EXTRA_DIST = $(TESTSUITE_AT) testsuite package.m4 
DISTCLEANFILES       = atconfig $(check_SCRIPTS)
CLEANFILES           = confdir
MAINTAINERCLEANFILES = Makefile.in $(TESTSUITE)
SUBDIRS=raddb proxy

## ------------ ##
## package.m4.  ##
## ------------ ##

$(srcdir)/package.m4: $(top_srcdir)/configure.ac
	{                                      \
	  echo '# Signature of the current package.'; \
	  echo 'm4_define([AT_PACKAGE_NAME],      [@PACKAGE_NAME@])'; \
	  echo 'm4_define([AT_PACKAGE_TARNAME],   [@PACKAGE_TARNAME@])'; \
	  echo 'm4_define([AT_PACKAGE_VERSION],   [@PACKAGE_VERSION@])'; \
	  echo 'm4_define([AT_PACKAGE_STRING],    [@PACKAGE_STRING@])'; \
	  echo 'm4_define([AT_PACKAGE_BUGREPORT], [@PACKAGE_BUGREPORT@])'; \
	} >$(srcdir)/package.m4

#

## ------------ ##
## Test suite.  ##
## ------------ ##

TESTSUITE_AT = \
 testsuite.at \
 begin.at \
 end.at \
 status-server.at \
 basic-auth.at \
 reply.at \
 begin-kw.at \
 default-kw.at \
 match-profile.at \
 hints.at \
 huntgroups.at \
 scheme-auth.at \
 acl.at \
 expiration.at \
 menu.at \
 acct.at \
 rewrite.at \
 execwait.at \
 filter.at \
 scheme-acct.at \
 tunnel.at \
 log-mode.at \
 proxy-basic-auth.at \
 proxy-ignorecase.at \
 proxy-vsa.at \
 proxy-menu.at \
 proxy-nested.at \
 proxy-acct.at \
 proxy-tunnel.at \
 begin-proxy.at \
 end-proxy.at 

TESTSUITE = $(srcdir)/testsuite

AUTOTEST = $(AUTOM4TE) --language=autotest
$(TESTSUITE): package.m4 $(TESTSUITE_AT)
	$(AUTOTEST) -I $(srcdir) testsuite.at -o $@.tmp
	mv $@.tmp $@

atconfig: $(top_builddir)/config.status
	cd $(top_builddir) && ./config.status tests/$@

clean-local:
	$(SHELL) $(TESTSUITE) --clean

check-local: atconfig atlocal $(TESTSUITE)
	$(SHELL) $(TESTSUITE)

# Run the test suite on the *installed* tree.
installcheck-local:
	$(SHELL) $(TESTSUITE) AUTOTEST_PATH=$(exec_prefix)/bin


## ------------ ##
## findport     ##
## ------------ ##

check_PROGRAMS = findport

## --------------- ##
## distclean rules ##
## --------------- ##

## Directories raddb and proxy are copied by testsuite if srcdir!=builddir.

distclean-local:
	here=`cd $(top_builddir)/$(subdir) && pwd`; \
	source=`cd $(srcdir) && pwd`; \
	if ! test $$here/raddb -ef $$source/raddb; then \
		rm -rf $$here/raddb; \
	fi; \
	if ! test $$here/proxy -ef $$source/proxy; then \
		rm -rf $$here/proxy; \
	fi