# Makefile for GNU tar regression tests.

# Copyright (C) 1996, 1997, 1999, 2000, 2001, 2003, 2004, 2007,
# 2008 Free Software Foundation, Inc.

# François Pinard <pinard@iro.umontreal.ca>, 1988.
# Sergey Poznyakoff <gray@gnu.org.ua>, 2004.

## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 3, or (at your option)
## any later version.

## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.

## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
## 02110-1301 USA.

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
 acct.at \
 acl.at \
 basic-auth.at \
 begin-kw.at \
 begin-proxy.at \
 begin.at \
 default-kw.at \
 end-proxy.at \
 end.at \
 execwait.at \
 expiration.at \
 ext-acct.at \
 filter.at \
 hints.at \
 huntgroups.at \
 log-mode.at \
 match-profile.at \
 menu.at \
 proxy-acct.at \
 proxy-basic-auth.at \
 proxy-ignorecase.at \
 proxy-menu.at \
 proxy-nested.at \
 proxy-tunnel.at \
 proxy-vsa.at \
 reply.at \
 rewrite.at \
 scheme-acct.at \
 scheme-auth.at \
 status-server.at \
 testsuite.at \
 tunnel.at 

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
