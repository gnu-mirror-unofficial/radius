EXTRA_DIST = config.m4 db.m4 mysql.m4 pgsql.m4

.m4.struct:
	$(M4) -DMODE=STRUCT -DINCLUDE=$< db.m4 > $@

.m4.sh:
	$(M4) -DMODE=CREATE -DINCLUDE=$< db.m4 > $@

SUFFIXES = .m4 .struct .sh

pgsql: pgsql.struct pgsql.sh
	$(SHELL) pgsql.sh

mysql: mysql.struct mysql.sh
	$(SHELL) mysql.sh

pgsql.struct pgsql.sh mysql.struct mysql.sh: config.m4 db.m4

CLEANFILES=mysql.struct mysql.sh pgsql.struct pgsql.sh
