/* This file is part of GNU RADIUS.
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

#include <radiusd.h>
#include <raddbm.h>
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
	DBM_FILE dbmfile;
	int begno;   /* ordinal number of next BEGIN entry */
	int defno;   /* ordinal number of next DEFAULT entry */
} DBM_closure;

int pair_buffer[RAD_BUFFER_SIZE];
void usage();
int add_user(DBM_closure *closure, int line,
	     char *name, VALUE_PAIR *check, VALUE_PAIR *reply);

int
main(argc, argv)
	int argc;
	char **argv;
{
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

	if (dict_init()) {
		radlog(L_ERR, _("error reading dictionary file"));
		return 1;
	}
	
	/* Make filenames: */
	if (!users_file)
		users_file = mkfilename(radius_dir, input);

	db_file = mkfilename(radius_dir, "users");

	/*
	 *	Initialize a new, empty database.
	 */
	closure.defno = closure.begno = 0;
	if (create_dbm(db_file, &closure.dbmfile)) {
		radlog(L_ERR|L_PERROR, _("can't open `%s'"), db_file);
		return 1;
	}

	parse_file(users_file, &closure, add_user);
	
	close_dbm(closure.dbmfile);

	return 0;
}

#define NINT(n) ((n) + sizeof(int) - 1)/sizeof(int)

/*ARGSUSED*/
int
add_user(closure, line, name, check, reply)
	DBM_closure *closure;
	int line;
	char *name;
	VALUE_PAIR *check, *reply;
{
	int     check_len;
	int     reply_len;
	VALUE_PAIR *vp;
	int     *q;
	datum	named;
	datum	contentd;
	
	check_len = list_length(check);
	reply_len = list_length(reply);

	if (2 + check_len + reply_len > sizeof(pair_buffer)) {
		radlog(L_ERR, _("%s:%d: too many attributes"),
		       source_filename, source_line_num);
		return -1;
	}

	q = pair_buffer;
	*q++ = check_len;
	for (vp = check; vp; vp = vp->next) {
		*q++ = vp->attribute;
		*q++ = vp->type;
		*q++ = vp->operator;
		if (vp->type == PW_TYPE_STRING) {
			strcpy((char*)q, vp->strvalue);
			q += NINT(vp->strlength+1);
		} else
			*q++ = vp->lvalue;
	}
	*q++ = reply_len;
	for (vp = reply; vp; vp = vp->next) {
		*q++ = vp->attribute;
		*q++ = vp->type;
		*q++ = vp->operator;
		if (vp->type == PW_TYPE_STRING) {
			strcpy((char*)q, vp->strvalue);
			q += NINT(vp->strlength+1);
		} else
			*q++ = vp->lvalue;
	}
	
	if (strncmp(name, "DEFAULT", 7) == 0) 
		sprintf(name, "DEFAULT%d", closure->defno++);
	else if (strncmp(name, "BEGIN", 5) == 0) 
		sprintf(name, "BEGIN%d", closure->begno++);
	
	named.dptr = name;
	named.dsize = strlen(name);
	contentd.dptr = (char*)pair_buffer;
	contentd.dsize = (2 + check_len + reply_len) * sizeof(int);
	if (insert_dbm(closure->dbmfile, named, contentd)) {
		radlog(L_ERR, _("can't store datum for %s"), name);
		exit(1);
	}
	return 0;
}



/*
 *	Fixup a check line.
 *	If Password or Crypt-Password is set, but there is no
 *	Auth-Type, add one (kludge!).
 */
void
auth_type_fixup(check)
	VALUE_PAIR *check;
{
	VALUE_PAIR	*vp;
	VALUE_PAIR	*c = NULL;
	int		n;

	/*
	 *	See if a password is present. Return right away
	 *	if we see Auth-Type.
	 */
	for (vp = check; vp; vp = vp->next) {
		if (vp->attribute == DA_AUTH_TYPE)
			return;
		if (vp->attribute == DA_PASSWORD) {
			c = vp;
			n = DV_AUTH_TYPE_LOCAL;
		}
		if (vp->attribute == DA_CRYPT_PASSWORD) {
			c = vp;
			n = DV_AUTH_TYPE_CRYPT_LOCAL;
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
	vp->attribute = DA_AUTH_TYPE;
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
		len += 3;
		if (vp->type == PW_TYPE_STRING)
			len += NINT(vp->strlength + 1);
		else
			len++;
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
