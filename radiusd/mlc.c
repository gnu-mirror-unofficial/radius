/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2006,
   2007,2008 Free Software Foundation, Inc.

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
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

/* Multiple Login Checking */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <radiusd.h>
#include <radius/radutmp.h>

struct mlc_dispatch {
	char *name;
	mlc_collect_user_t collect_user;
	mlc_collect_realm_t collect_realm;
	mlc_close_t close;
	mlc_enabled_t enabled_p;
};

static grad_list_t *mlc_dispatch_list;
struct mlc_dispatch *mlc_disptab;

void
mlc_register_method(char *name,
		    mlc_collect_user_t collect_user,
		    mlc_collect_realm_t collect_realm,
		    mlc_close_t close,
		    mlc_enabled_t enabled_p)
{
	struct mlc_dispatch *mp = grad_emalloc(sizeof(*mp));
	mp->name = grad_estrdup(name);
	mp->collect_user = collect_user;
	mp->collect_realm = collect_realm;
	mp->close = close;
	mp->enabled_p = enabled_p;
	if (!mlc_dispatch_list)
		mlc_dispatch_list = grad_list_create();
	grad_list_append(mlc_dispatch_list, mp);
}


/* Entry points */
int
radius_mlc_enabled_p()
{
	return mlc_disptab ? mlc_disptab->enabled_p() : 0;
}

int
radius_mlc_collect_user(char *name, radiusd_request_t *request,
			grad_list_t **sess_list)
{
	GRAD_DEBUG(20,"Entered");
	return mlc_disptab->collect_user(name, request, sess_list);
}

int
radius_mlc_collect_realm(radiusd_request_t *request, grad_list_t **sess_list)
{
	GRAD_DEBUG(20,"Entered");
	return mlc_disptab->collect_realm(request, sess_list);
}

void
radius_mlc_close(struct radutmp *up)
{
        char ipbuf[GRAD_IPV4_STRING_LENGTH];
	
	GRAD_DEBUG2(20, "Closing session: NAS %s port %d",
	            grad_ip_iptostr(ntohl(up->nas_address), ipbuf),
	            up->nas_port);
	mlc_disptab->close(up);
}


/* Return value: that of checkrad function, i.e. 1 means true (user FOUND)
   0 means false (user NOT found) */
static int
check_ts(struct radutmp *ut)
{
        grad_nas_t     *nas;

        /* Find NAS type. */
        if ((nas = grad_nas_lookup_ip(ntohl(ut->nas_address))) == NULL) {
                grad_log(GRAD_LOG_NOTICE, _("check_ts(): unknown NAS"));
                return -1; 
        }

        /* Handle two special types */
        if (strcmp(nas->nastype, "true") == 0)
                return 1;
        else if (strcmp(nas->nastype, "false") == 0)
                return 0;

        return checkrad(nas, ut);
}

/* Check one terminal server to see if a user is logged in.
   Return value:
        1 if user is logged in
        0 if user is not logged in */

static int
rad_check_ts(struct radutmp *ut)
{
        int result;
        
        switch (result = check_ts(ut)) {
        case 0:
        case 1:
                return result;

                /* The default return value is a question of policy.
                   It is defined in /etc/raddb/config */
        default:
                if (checkrad_assume_logged) 
                        grad_log(GRAD_LOG_NOTICE, _("assuming `%s' is logged in"),
                                 ut->login);
                else
                        grad_log(GRAD_LOG_NOTICE, _("assuming `%s' is NOT logged in"),
                                 ut->login);
                return checkrad_assume_logged;
        }
        /*NOTREACHED*/
}

static int
utmp_free(void *item, void *data ARG_UNUSED)
{
	grad_free(item);
	return 0;
}

/* See if a user is already logged in.
   Check twice. If on the first pass the user exceeds his
   max. number of logins, do a second pass and validate all
   logins by querying the terminal server.

   MPP validation is not as reliable as I'd wish it to be.

   Return:
      0 == OK,
      1 == user exceeds its simultaneous-use parameter */
int
radius_mlc_user(char *name, radiusd_request_t *request,
		size_t maxsimul, size_t *pcount)
{
	void *mlc;
        struct radutmp *up;
        int mpp = 1; /* MPP flag. The sense is reversed: 1 if
                        the session is NOT an MPP one */
        grad_list_t *sess_list = NULL;
	size_t count;

	GRAD_DEBUG2(1, "User %s, maxsimul %lu", name, (u_long) maxsimul);
        if (radius_mlc_collect_user(name, request, &sess_list)) {
		GRAD_DEBUG(1, "radius_mlc_collect_user() failed");
		return 0;
	}
	
        count = grad_list_count(sess_list);
        GRAD_DEBUG2(1, "Found %lu active sessions for user %s",
		    (u_long) count, name);
	      
        if (count >= maxsimul) {
		grad_iterator_t *itr;
		grad_uint32_t ipno = 0;
		grad_avp_t *fra = grad_avl_find(request->request->avlist,
						DA_FRAMED_IP_ADDRESS);
		if (fra)
			ipno = htonl(fra->avp_lvalue);

		/* Pass II. Check all registered logins. */

		count = 0;
		itr = grad_iterator_create(sess_list);
		for (up = grad_iterator_first(itr); up;
		     up = grad_iterator_next(itr)) {
			if (rad_check_ts(up) == 1) {
				count++;
				/* Does it look like a MPP attempt? */
				if (ipno && up->framed_address == ipno)
					switch (up->proto) {
					case DV_FRAMED_PROTOCOL_PPP:
					case DV_FRAMED_PROTOCOL_SLIP:
					case 256: /* Ascend MPP */
						mpp = 0;
					}
			} else {
				/* Hung record */
				radius_mlc_close(up);
			}
		}
		grad_iterator_destroy(&itr);
	}

	grad_list_destroy(&sess_list, utmp_free, NULL);
	
        GRAD_DEBUG1(1, "%lu sessions really active", (u_long) count);
        *pcount = count;
        return (count < maxsimul) ? 0 : mpp;
}

int
radius_mlc_realm(radiusd_request_t *request)
{
        size_t count;
        struct radutmp *up;
        radut_file_t file;
        size_t maxlogins;
	grad_list_t *sess_list = NULL;
	grad_realm_t *realm = request->realm;
	
        if (!realm || (maxlogins = grad_realm_get_quota(realm)) == 0)
                return 0;

	if (radius_mlc_collect_realm(request, &sess_list)) {
		GRAD_DEBUG(1, "radius_mlc_collect_realm() failed");
		return 0;
	}

	count = grad_list_count(sess_list);
	GRAD_DEBUG2(1, "Found %lu active sessions for realm %s",
		    (u_long) count, realm->realm);

        if (count >= maxlogins) {
		grad_iterator_t *itr;

		count = 0;
		itr = grad_iterator_create(sess_list);
		for (up = grad_iterator_first(itr); up;
		     up = grad_iterator_next(itr)) {
			if (rad_check_ts(up) == 1) 
				count++;
			else /* Close hung record */
				radius_mlc_close(up);
		}
		grad_iterator_destroy(&itr);
	}
	grad_list_destroy(&sess_list, utmp_free, NULL);

	GRAD_DEBUG1(1, "%lu sessions really active", (u_long) count);

        return count >= maxlogins;
}



static int
name_cmp(const void *item, const void *data)
{
	const struct mlc_dispatch *mp = item;
	const char *name = data;
	return strcmp(mp->name, name);
}
	

static int
mlc_set_method(int argc, cfg_value_t *argv,
	       void *block_data, void *handler_data)
{
	struct mlc_dispatch *mp;
	
	if (argc != 2 || argv[1].type != CFG_STRING) 
		return 1;

	mp = grad_list_locate(mlc_dispatch_list, argv[1].v.string, name_cmp);
	if (mp) {
		mlc_disptab = mp;
		return 0;
	}
	return 1;
}
	    
struct cfg_stmt mlc_stmt[] = {
	{ "method", CS_STMT, NULL, mlc_set_method, NULL, NULL, NULL },
	{ "checkrad-assume-logged", CS_STMT, NULL,
	  cfg_get_boolean, &checkrad_assume_logged,
	  NULL, NULL },
	{ NULL, }
};



void
mlc_init()
{
	mlc_register_method("system",
			    radutmp_mlc_collect_user,
			    radutmp_mlc_collect_realm,
			    radutmp_mlc_close,
			    radutmp_mlc_enabled_p);
	mlc_disptab = grad_list_item(mlc_dispatch_list, 0);
	grad_insist(mlc_disptab!=NULL);	
}
