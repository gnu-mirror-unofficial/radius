/* This file is part of GNU Radius
   Copyright (C) 2001,2003,2004,2005,2006,2007,
   2008 Free Software Foundation, Inc.

   Written by Sergey Poznyakoff

   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
 
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with GNU Radius; if not, write to the Free Software Foundation, 
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#if defined(USE_DBM)

#include <radiusd.h>
#include <radius/raddbm.h>

#define NINT(n) ((n) + sizeof(int) - 1)/sizeof(int)

typedef struct {
        char *filename;
        DBM_FILE dbmfile;
        int *pair_buffer;
        int pair_buffer_size;
        int begno;   /* ordinal number of next BEGIN entry */
        int defno;   /* ordinal number of next DEFAULT entry */
} DBM_closure;


static int append_symbol(DBM_closure *closure, User_symbol *sym);
static int list_length(grad_avp_t *vp);

int
append_symbol(DBM_closure *closure, User_symbol *sym)
{
        int     check_len;
        int     reply_len;
        grad_avp_t *vp;
        int     *q;
        DBM_DATUM       named;
        DBM_DATUM       contentd;
        char    name[GRAD_STRING_LENGTH];
        
        check_len = list_length(sym->check);
        reply_len = list_length(sym->reply);

        if (2 + check_len + reply_len > closure->pair_buffer_size) {
                grad_log(GRAD_LOG_ERR, "%s:%d: %s",
                         closure->filename, sym->lineno,
		         _("too many attributes"));
                return -1;
        }

        q = closure->pair_buffer;
        *q++ = check_len;
        for (vp = sym->check; vp; vp = vp->next) {
                *q++ = vp->attribute;
                *q++ = vp->type;
                *q++ = vp->operator;
                if (vp->type == GRAD_TYPE_STRING) {
                        strcpy((char*)q, vp->avp_strvalue);
                        q += NINT(vp->avp_strlength+1);
                } else
                        *q++ = vp->avp_lvalue;
        }
        *q++ = reply_len;
        for (vp = sym->reply; vp; vp = vp->next) {
                *q++ = vp->attribute;
                *q++ = vp->type;
                *q++ = vp->operator;
                if (vp->type == GRAD_TYPE_STRING) {
                        strcpy((char*)q, vp->avp_strvalue);
                        q += NINT(vp->avp_strlength+1);
                } else
                        *q++ = vp->avp_lvalue;
        }
        
        if (strncmp(sym->name, "DEFAULT", 7) == 0) 
                sprintf(name, "DEFAULT%d", closure->defno++);
        else if (strncmp(name, "BEGIN", 5) == 0) 
                sprintf(name, "BEGIN%d", closure->begno++);
        else
                strcpy(name, sym->name);
        
        named.dptr = name;
        named.dsize = strlen(name);
        contentd.dptr = (char*)closure->pair_buffer;
        contentd.dsize = (2 + check_len + reply_len) * sizeof(int);
        if (grad_dbm_insert(closure->dbmfile, named, contentd)) {
                grad_log(GRAD_LOG_ERR, _("can't store datum for %s"), name);
                exit(1);
        }
        return 0;
        
}

int
list_length(grad_avp_t *vp)
{
        int len;
        
        for (len = 0; vp; vp = vp->next) {
                len += 3;
                if (vp->type == GRAD_TYPE_STRING)
                        len += NINT(vp->avp_strlength + 1);
                else
                        len++;
        }
        return len;
}

int
builddbm(char *name)
{
        DBM_closure closure;
        char *db_file;

        if (!name)
                name = "users";
        db_file = grad_mkfilename(grad_config_dir, name);

        /*
         *      Initialize a new, empty database.
         */
        closure.filename = db_file;
        closure.pair_buffer_size = RAD_BUFFER_SIZE;
        closure.pair_buffer = grad_emalloc(closure.pair_buffer_size*sizeof(int));
        closure.defno = closure.begno = 0;
        if (grad_dbm_create(db_file, &closure.dbmfile)) {
                grad_log(GRAD_LOG_ERR|GRAD_LOG_PERROR, 
                         _("can't open `%s'"), db_file);
                return 1;
        }

        grad_symtab_iterate(user_tab, append_symbol, &closure);

        return 0;
}

/* ************ */

static grad_avp_t * decode_dbm(int **dbm_ptr);
static int dbm_find(DBM_FILE dbmfile, char *name,
                    radiusd_request_t *req, 
                    grad_avp_t **check_pairs, grad_avp_t **reply_pairs);
static char *_dbm_dup_name(char *buf, size_t bufsize, char *name, int ordnum);
static char *_dbm_number_name(char *buf, size_t bufsize, char *name, int ordnum);
static int dbm_match(DBM_FILE dbmfile, char *name, char *(*fn)(), 
                     radiusd_request_t *req, grad_avp_t **check_pairs,
                     grad_avp_t **reply_pairs, int  *fallthru);

/*
 * DBM lookup:
 *      -1 username not found
 *      0 username found but profile doesn't match the request.
 *      1 username found and matches.
 */
#define NINT(n) ((n) + sizeof(int) - 1)/sizeof(int)

grad_avp_t *
decode_dbm(int **pptr)
{
        int *ptr, *endp, len;
        grad_avp_t *next_pair, *first_pair, *last_pair;
        
        ptr = *pptr;
        len = *ptr++;
        endp = ptr + len;
        
        last_pair = first_pair = NULL;
        while (ptr < endp) {
                next_pair = grad_avp_alloc();
                next_pair->attribute = *ptr++;
                next_pair->type = *ptr++;
                next_pair->operator = *ptr++;
                if (next_pair->type == GRAD_TYPE_STRING) {
                        next_pair->avp_strvalue = grad_estrdup((char*)ptr);
                        next_pair->avp_strlength = strlen(next_pair->avp_strvalue);
                        ptr += NINT(next_pair->avp_strlength+1);
                } else
                        next_pair->avp_lvalue = *ptr++;
                next_pair->name = NULL;
                if (last_pair)
                        last_pair->next = next_pair;
                else
                        first_pair = next_pair;
                last_pair = next_pair;
        } 

        *pptr = ptr;
        return first_pair;
}

/* FIXME: The DBM functions below follow exactly the same algorythm as
 * user_find_sym/match_user pair. This is superfluous. The common wrapper
 * for both calls is needed.
 */
int
dbm_find(DBM_FILE file, char *name, radiusd_request_t *req,
         grad_avp_t **check_pairs, grad_avp_t **reply_pairs)
{
        DBM_DATUM       named;
        DBM_DATUM       contentd;
        int             *ptr;
        grad_avp_t      *check_tmp;
        grad_avp_t      *reply_tmp;
        int             ret = 0;
        
        named.dptr = name;
        named.dsize = strlen(name);

        if (grad_dbm_fetch(file, named, &contentd))
                return -1;

        check_tmp = NULL;
        reply_tmp = NULL;

        /*
         *      Parse the check values
         */
        ptr = (int*)contentd.dptr;
        /* check pairs */
        check_tmp = decode_dbm(&ptr);

        /* reply pairs */
        reply_tmp = decode_dbm(&ptr);

        /*
         *      See if the check_pairs match.
         */
        if (paircmp(req, check_tmp) == 0) {
                grad_avp_t *p;

                /*
                 * Found an almost matching entry. See if it has a
                 * Match-Profile attribute and if so check
                 * the profile it points to.
                 */
                ret = 1;
                if (p = grad_avl_find(check_tmp, DA_MATCH_PROFILE)) {
                        int dummy;
                        char *name;
                        
                        GRAD_DEBUG1(1, "submatch: %s", p->avp_strvalue);
                        name = grad_estrdup(p->avp_strvalue);
                        if (!dbm_match(file, name, _dbm_dup_name,
                                       req,
                                       &check_tmp, &reply_tmp, &dummy))
                                ret = 0;
                        grad_free(name);
                } 
                
                if (ret == 1) {
                        grad_avl_merge(reply_pairs, &reply_tmp);
                        grad_avl_merge(check_pairs, &check_tmp);
                }
        }
        
        /* Should we
         *  free(contentd.dptr);
         */
        grad_avl_free(reply_tmp);
        grad_avl_free(check_tmp);

        return ret;
}

/*ARGSUSED*/
char *
_dbm_dup_name(char *buf, size_t bufsize, char *name, int ordnum)
{
        strncpy(buf, name, bufsize);
        buf[bufsize-1] = 0;
        return buf;
}

char *
_dbm_number_name(char *buf, size_t bufsize, char *name, int ordnum)
{
        snprintf(buf, bufsize, "%s%d", name, ordnum);
        return buf;
}

int
dbm_match(DBM_FILE dbmfile, char *name, char *(*fn)(), radiusd_request_t *req,
          grad_avp_t **check_pairs, grad_avp_t **reply_pairs, int  *fallthru)
{
        int  found = 0;
        int  i, r;
        char buffer[64];
        grad_avp_t *p;
        
        *fallthru = 0;
        for (i = 0;;i++) {
                r = dbm_find(dbmfile,
                             (*fn)(buffer, sizeof(buffer), name, i),
                             req, check_pairs, reply_pairs);
                if (r == 0) {
                        if (strcmp(name, buffer))
                                continue;
                        break;
                }
                
                if (r < 0) 
                        break;
                
                /* OK, found matching entry */

                found = 1;

                if (p = grad_avl_find(*reply_pairs, DA_MATCH_PROFILE)) {
                        int dummy;
                        char *name;
                        
                        GRAD_DEBUG1(1, "next: %s", p->avp_strvalue);
                        name = grad_estrdup(p->avp_strvalue);
                        grad_avl_delete(reply_pairs, DA_MATCH_PROFILE);
                        dbm_match(dbmfile, name, _dbm_dup_name,
                                  req,
                                  check_pairs, reply_pairs, &dummy);
                        grad_free(name);
                }

                if (!fallthrough(*reply_pairs))
                        break;
                grad_avl_delete(reply_pairs, DA_FALL_THROUGH);
                *fallthru = 1;
        }
        return found;
}

/*
 * Find matching profile in the DBM database
 */
int
user_find_db(char *name, radiusd_request_t *req, 
             grad_avp_t **check_pairs, grad_avp_t **reply_pairs)
{
        int             found = 0;
        char            *path;
        DBM_FILE        dbmfile;
        int             fallthru;
        
        path = grad_mkfilename(grad_config_dir, RADIUS_USERS);
        if (grad_dbm_open(path, &dbmfile)) {
                grad_log(GRAD_LOG_ERR, _("cannot open dbm file %s"), path);
                grad_free(path);
                return 0;
        }

        /* This is a fake loop: it is here so we don't have to
         * stack up if's or use goto's
         */
        for (;;) {
                found = dbm_match(dbmfile, "BEGIN", _dbm_number_name,
                                  req,
                                  check_pairs, reply_pairs, &fallthru);
                if (found && fallthru == 0)
                        break;
                
                found = dbm_match(dbmfile, name, _dbm_dup_name,
                                  req,
                                  check_pairs, reply_pairs, &fallthru);

                if (found && fallthru == 0)
                        break;

                found = dbm_match(dbmfile, "DEFAULT", _dbm_number_name,
                                  req,
                                  check_pairs, reply_pairs, &fallthru);
                break;
                /*NOTREACHED*/
        }

        grad_dbm_close(dbmfile);
        grad_free(path);

        GRAD_DEBUG1(1, "returning %d", found);

        return found;
}

#endif

