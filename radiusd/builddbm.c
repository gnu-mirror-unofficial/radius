/* This file is part of GNU RADIUS.
   Copyright (C) 2001, Sergey Poznyakoff
 
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
 
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation, 
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#define RADIUS_MODULE_BUILDDBM_C

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#if defined(USE_DBM)

#include <radiusd.h>
#include <raddbm.h>
#include <symtab.h>
#include <parser.h>

#ifndef lint
static char rcsid[] =
"@(#) $Id$";
#endif

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
static int list_length(VALUE_PAIR *vp);

int
append_symbol(closure, sym)
        DBM_closure *closure;
        User_symbol *sym;
{
        int     check_len;
        int     reply_len;
        VALUE_PAIR *vp;
        int     *q;
        DBM_DATUM       named;
        DBM_DATUM       contentd;
        char    name[AUTH_STRING_LEN];
        
        check_len = list_length(sym->check);
        reply_len = list_length(sym->reply);

        if (2 + check_len + reply_len > closure->pair_buffer_size) {
                radlog(L_ERR, _("%s:%d: too many attributes"),
                       closure->filename, sym->lineno);
                return -1;
        }

        q = closure->pair_buffer;
        *q++ = check_len;
        for (vp = sym->check; vp; vp = vp->next) {
                *q++ = vp->attribute;
                *q++ = vp->type;
                *q++ = vp->operator;
                if (vp->type == TYPE_STRING) {
                        strcpy((char*)q, vp->strvalue);
                        q += NINT(vp->strlength+1);
                } else
                        *q++ = vp->lvalue;
        }
        *q++ = reply_len;
        for (vp = sym->reply; vp; vp = vp->next) {
                *q++ = vp->attribute;
                *q++ = vp->type;
                *q++ = vp->operator;
                if (vp->type == TYPE_STRING) {
                        strcpy((char*)q, vp->strvalue);
                        q += NINT(vp->strlength+1);
                } else
                        *q++ = vp->lvalue;
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
        if (insert_dbm(closure->dbmfile, named, contentd)) {
                radlog(L_ERR, _("can't store datum for %s"), name);
                exit(1);
        }
        return 0;
        
}

int
list_length(vp)
        VALUE_PAIR *vp;
{
        int len;
        
        for (len = 0; vp; vp = vp->next) {
                len += 3;
                if (vp->type == TYPE_STRING)
                        len += NINT(vp->strlength + 1);
                else
                        len++;
        }
        return len;
}

int
builddbm(name)
        char *name;
{
        DBM_closure closure;
        char *db_file;

        if (!name)
                name = "users";
        db_file = mkfilename(radius_dir, name);

        /*
         *      Initialize a new, empty database.
         */
        closure.filename = db_file;
        closure.pair_buffer_size = RAD_BUFFER_SIZE;
        closure.pair_buffer = emalloc(closure.pair_buffer_size*sizeof(int));
        closure.defno = closure.begno = 0;
        if (create_dbm(db_file, &closure.dbmfile)) {
                radlog(L_ERR|L_PERROR, _("can't open `%s'"), db_file);
                return 1;
        }

        symtab_iterate(user_tab, append_symbol, &closure);

        return 0;
}

/* ************ */

static VALUE_PAIR * decode_dbm(int **dbm_ptr);
static int dbm_find(DBM_FILE dbmfile, char *name,
                    RADIUS_REQ *req, 
                    VALUE_PAIR **check_pairs, VALUE_PAIR **reply_pairs);
static char *_dbm_dup_name(char *buf, size_t bufsize, char *name, int ordnum);
static char *_dbm_number_name(char *buf, size_t bufsize, char *name, int ordnum);
static int dbm_match(DBM_FILE dbmfile, char *name, char *(*fn)(), 
                     RADIUS_REQ *req, VALUE_PAIR **check_pairs,
                     VALUE_PAIR **reply_pairs, int  *fallthru);

/*
 * DBM lookup:
 *      -1 username not found
 *      0 username found but profile doesn't match the request.
 *      1 username found and matches.
 */
#define NINT(n) ((n) + sizeof(int) - 1)/sizeof(int)

VALUE_PAIR *
decode_dbm(pptr)
        int **pptr;
{
        int *ptr, *endp, len;
        VALUE_PAIR *next_pair, *first_pair, *last_pair;
        
        ptr = *pptr;
        len = *ptr++;
        endp = ptr + len;
        
        last_pair = first_pair = NULL;
        while (ptr < endp) {
                next_pair = avp_alloc();
                next_pair->attribute = *ptr++;
                next_pair->type = *ptr++;
                next_pair->operator = *ptr++;
                if (next_pair->type == TYPE_STRING) {
                        next_pair->strvalue = make_string((char*)ptr);
                        next_pair->strlength = strlen(next_pair->strvalue);
                        ptr += NINT(next_pair->strlength+1);
                } else
                        next_pair->lvalue = *ptr++;
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
dbm_find(file, name, req, check_pairs, reply_pairs)
        DBM_FILE file;
        char       *name;
        RADIUS_REQ *req;
        VALUE_PAIR **check_pairs;
        VALUE_PAIR **reply_pairs;
{
        DBM_DATUM       named;
        DBM_DATUM       contentd;
        int             *ptr;
        VALUE_PAIR      *check_tmp;
        VALUE_PAIR      *reply_tmp;
        int             ret = 0;
        
        named.dptr = name;
        named.dsize = strlen(name);

        if (fetch_dbm(file, named, &contentd))
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
                VALUE_PAIR *p;

                /*
                 * Found an almost matching entry. See if it has a
                 * Match-Profile attribute and if so check
                 * the profile it points to.
                 */
                ret = 1;
                if (p = avl_find(check_tmp, DA_MATCH_PROFILE)) {
                        int dummy;
                        char *name;
                        
                        debug(1, ("submatch: %s", p->strvalue));
                        name = dup_string(p->strvalue);
                        if (!dbm_match(file, name, _dbm_dup_name,
                                       req,
                                       &check_tmp, &reply_tmp, &dummy))
                                ret = 0;
                        free_string(name);
                } 
                
                if (ret == 1) {
                        avl_merge(reply_pairs, &reply_tmp);
                        avl_merge(check_pairs, &check_tmp);
                }
        }
        
        /* Should we
         *  free(contentd.dptr);
         */
        avl_free(reply_tmp);
        avl_free(check_tmp);

        return ret;
}

/*ARGSUSED*/
char *
_dbm_dup_name(buf, bufsize, name, ordnum)
        char *buf;
        size_t bufsize;
        char *name;
        int ordnum;
{
        strncpy(buf, name, bufsize);
        buf[bufsize-1] = 0;
        return buf;
}

char *
_dbm_number_name(buf, bufsize, name, ordnum)
        char *buf;
        size_t bufsize;
        char *name;
        int ordnum;
{
        snprintf(buf, bufsize, "%s%d", name, ordnum);
        return buf;
}

int
dbm_match(dbmfile, name, fn, req, check_pairs, reply_pairs, fallthru)
        DBM_FILE dbmfile;
        char *name;
        char *(*fn)();
        RADIUS_REQ *req;
        VALUE_PAIR **check_pairs;
        VALUE_PAIR **reply_pairs;
        int  *fallthru;
{
        int  found = 0;
        int  i, r;
        char buffer[64];
        VALUE_PAIR *p;
        
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

                if (p = avl_find(*reply_pairs, DA_MATCH_PROFILE)) {
                        int dummy;
                        char *name;
                        
                        debug(1, ("next: %s", p->strvalue));
                        name = dup_string(p->strvalue);
                        avl_delete(reply_pairs, DA_MATCH_PROFILE);
                        dbm_match(dbmfile, name, _dbm_dup_name,
                                  req,
                                  check_pairs, reply_pairs, &dummy);
                        free_string(name);
                }

                if (!fallthrough(*reply_pairs))
                        break;
                avl_delete(reply_pairs, DA_FALL_THROUGH);
                *fallthru = 1;
        }
        return found;
}

/*
 * Find matching profile in the DBM database
 */
int
user_find_db(name, req, check_pairs, reply_pairs)
        char *name;
        RADIUS_REQ *req;
        VALUE_PAIR **check_pairs;
        VALUE_PAIR **reply_pairs;
{
        int             found = 0;
        char            *path;
        DBM_FILE        dbmfile;
        int             fallthru;
        
        path = mkfilename(radius_dir, RADIUS_USERS);
        if (open_dbm(path, &dbmfile)) {
                radlog(L_ERR, _("cannot open dbm file %s"), path);
                efree(path);
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

        close_dbm(dbmfile);
        efree(path);

        debug(1, ("returning %d", found));

        return found;
}

#endif

