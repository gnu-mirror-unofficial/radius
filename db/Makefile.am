EXTRA_DIST = config.m4 db.m4 mysql.m4 pgsql.m4

.m4.struct:
	m4 -DDB_PWD=test -DMODE=STRUCT -DINCLUDE=$< db.m4 > $@

.m4.sh:
	m4 -DDB_PWD=test -DMODE=CREATE -DINCLUDE=$< db.m4 > $@

SUFFIXES = .m4 .struct .sh

pgsql: pgsql.struct pgsql.sh
	$(SHELL) pgsql.sh

mysql: mysql.struct mysql.sh
	$(SHELL) mysql.sh

CLEANFILES=mysql.struct mysql.sh pgsql.struct pgsql.sh
