# $Id$
# This file is part of GNU RADIUS.
# Copyright (C) 2000,2001, Sergey Poznyakoff
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

libexec_SCRIPTS=@BUILD_NAS_SCM@
EXTRA_SCRIPTS=nas.scm
CLEANFILES=$(libexec_SCRIPTS)
EXTRA_DIST=nas.rc nas.scm.in
pppdir=/etc/ppp
raddbdir=@ETC_DIR@/raddb
raddb_DATA=nas.rc

nas.scm: $(srcdir)/nas.scm.in
	sed "s,BINDIR,$(bindir)," $(srcdir)/nas.scm.in > nas.scm

install-exec-hook:
	@if [ -d $(pppdir) ]; then \
		echo "***************************************************"; \
		echo "If you wish to use nas.scm for accounting purposes,"; \
		echo "create the following symbolic links:"; \
		echo "  $(LN_S) $(libexecdir)/nas.scm $(pppdir)/ip-up"; \
		echo "  $(LN_S) $(libexecdir)/nas.scm $(pppdir)/ip-down"; \
		echo "***************************************************"; \
	else \
		echo "$(pppdir) does not exist."; \
	fi


