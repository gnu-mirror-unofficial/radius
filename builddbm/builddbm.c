/* This file is part of GNU RADIUS.
 * Copyright (C) 2000, Sergey Poznyakoff
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */
/*      RADIUS builddbm utility */

#ifndef lint
static char rcsid[] =
"@(#) $Id$";
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <netinet/in.h>

#include <stdio.h>
#include <netdb.h>
#include <strings.h>
#include <pwd.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#ifdef DBM
# include <dbm.h>
#endif
#ifdef NDBM
# include <ndbm.h>
#endif

#include <radiusd.h>
#include <parser.h>

char		*progname;
int		debug_flag;
char		*radius_dir = RADIUS_DIR;
#ifdef DBM
char            *pag_file;
char            *dir_file;
#endif
char            *db_file;
char            *users_file;
char            *input="users";

typedef struct {
#ifdef NDBM
	DBM *dbm;
#endif
	int defno;   /* ordinal number of next default entry */
} DBM_closure;

VALUE_PAIR pair_buffer[512];
void usage();
int add_user(DBM_closure *closure, int line,
	     char *name, VALUE_PAIR *check, VALUE_PAIR *reply);

int
main(argc, argv)
	int argc;
	char **argv;
{
	char	name[128];
	char    *dict_file;
	int     c;
	DBM_closure closure;
#ifdef DBM
	int fd;
#endif
	
	initlog(argv[0]);

	while ((c = getopt(argc, argv, "hir:")) != EOF) {
		switch (c) {
		case 'h':
			usage();
			/*NOTREACHED*/
		case 'i':
			users_file = optarg;
			break;
		case 'r':
			radius_dir = optarg;
			break;
		default:
			return -1;
		}
	}

	radpath_init();

	if (!users_file && argv[optind])
		users_file = argv[optind];

	dict_file = mkfilename(radius_dir, RADIUS_DICTIONARY);
	if (dict_init(dict_file)) {
		radlog(L_ERR, _("error reading dictionary file"));
		return 1;
	}
	
	/* Make filenames: */
	if (!users_file)
		users_file = mkfilename(radius_dir, input);
#ifdef DBM	
	pag_file = mkfilename(radius_dir, "users.pag");
	dir_file = mkfilename(radius_dir, "users.dir");
#endif
	db_file = mkfilename(radius_dir, "users");
	
	/*
	 *	Initialize a new, empty database.
	 */
#ifdef DBM
	if ((fd = open(pag_file, O_WRONLY | O_CREAT | O_TRUNC, 0600)) < 0) {
		radlog(L_ERR|L_PERROR, _("can't open `%s'"), pag_file);
		return 1;
	}
	close(fd);
	if ((fd = open(dir_file, O_WRONLY | O_CREAT | O_TRUNC, 0600)) < 0) {
		radlog(L_ERR, _("can't open `%s'"), dir_file);
		return 1;
	}
	close(fd);
	if (dbminit(db_file) != 0) {
		radlog(L_ERR, "dbminit(%s)", db_file);
		return 1;
	}
#endif
#ifdef NDBM
	if ((closure.dbm = dbm_open(db_file, O_RDWR|O_CREAT|O_TRUNC, 0600))
	    == NULL) {
		radlog(L_ERR, "dbm_open(%s)", db_file);
		return 1;
	}
#endif

	parse_file(users_file, &closure, add_user);
	
#ifdef DBM
	dbmclose();
#endif
#ifdef NDBM
	dbm_close(closure.dbm);
#endif
	return 0;
}

int
add_user(closure, line, name, check, reply)
	DBM_closure *closure;
	int line;
	char *name;
	VALUE_PAIR *check, *reply;
{
	int len;
	VALUE_PAIR *vp, *q;
	datum	named;
	datum	contentd;
	
	len = list_length(check) + list_length(reply);

	if (len > sizeof(pair_buffer)) {
		radlog(L_ERR, _("%s:%d: too many attributes"),
		       source_filename, source_line_num);
		return -1;
	}

	q = pair_buffer;
	for (vp = check; vp; vp = vp->next) {
		*q = *vp;
		if (vp->next)
			q->next = (VALUE_PAIR*)1;
		q->strvalue = NULL;
		q++;
		if (vp->type == PW_TYPE_STRING) {
			strcpy((char*)q, vp->strvalue);
			q = (VALUE_PAIR*)((char*)q + strlen(vp->strvalue) + 1);
		}
	}
	for (vp = reply; vp; vp = vp->next) {
		*q = *vp;
		if (vp->next)
			q->next = (VALUE_PAIR*)1;
		q->strvalue = NULL;
		q++;
		if (vp->type == PW_TYPE_STRING) {
			strcpy((char*)q, vp->strvalue);
			q = (VALUE_PAIR*)((char*)q + strlen(vp->strvalue) + 1);
		}
	}
	
	if (strcmp(name, "DEFAULT") == 0) {
		if (closure->defno > 0)
			sprintf(name, "DEFAULT%d", closure->defno);
		closure->defno++;
	}

	named.dptr = name;
	named.dsize = strlen(name);
	contentd.dptr = (char*)pair_buffer;
	contentd.dsize = len;
#ifdef DBM
	if (store(named, contentd) != 0)
#endif
#ifdef NDBM
	if (dbm_store(closure->dbm, named, contentd, DBM_INSERT) != 0)
#endif
	{
		radlog(L_ERR, _("can't store datum for %s"), name);
		exit(1);
	}
}



/*
 *	Fixup a check line.
 *	If Password or Crypt-Password is set, but there is no
 *	Auth-Type, add one (kludge!).
 */
void auth_type_fixup(VALUE_PAIR *check)
{
	VALUE_PAIR	*vp;
	VALUE_PAIR	*c = NULL;
	int		n;

	/*
	 *	See if a password is present. Return right away
	 *	if we see Auth-Type.
	 */
	for (vp = check; vp; vp = vp->next) {
		if (vp->attribute == PW_AUTHTYPE)
			return;
		if (vp->attribute == PW_PASSWORD) {
			c = vp;
			n = PW_AUTHTYPE_LOCAL;
		}
		if (vp->attribute == PW_CRYPT_PASSWORD) {
			c = vp;
			n = PW_AUTHTYPE_CRYPT;
		}
	}

	if (c == NULL)
		return;

	/*
	 *	Add an Auth-Type attribute.
	 */
	vp = alloc_pair();
	memset(vp, 0, sizeof(VALUE_PAIR));
	strcpy(vp->name, "Auth-Type");
	vp->attribute = PW_AUTHTYPE;
	vp->type = PW_TYPE_INTEGER;
	vp->lvalue = n;

	vp->next = c;
	c = vp->next;

}

int
list_length(vp)
	VALUE_PAIR *vp;
{
	int len;

	for (len = 0; vp; vp = vp->next) {
		len += sizeof(VALUE_PAIR);
		if (vp->type == PW_TYPE_STRING)
			len += vp->strlength + 1;
	}
	return len;
}

/* needed by users.y */
int
master_process()
{	
	return 1;
}

void
usage()
{
	printf(_("usage: builddbm [-i input_file][-r radius_dir]\n"));
}
