/* This file is part of GNU RADIUS.
   Copyright (C) 2000, Sergey Poznyakoff
  
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
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

#define RADIUS_MODULE_PROXY_C
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
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <pwd.h>
#include <time.h>
#include <ctype.h>
#include <string.h>

#include <radiusd.h>

/*
 *	Make sure send_buffer is aligned properly.
 */
static int i_send_buffer[RAD_BUFFER_SIZE];
static u_char *send_buffer = (u_char *)i_send_buffer;

static PROXY_ID *proxy_id;

static void random_vector(char *vector);
static VALUE_PAIR *proxy_addinfo(RADIUS_REQ *radreq, int proxy_id, UINT4 remip);
void proxy_addrequest(RADIUS_REQ *radreq);
static void passwd_recode(VALUE_PAIR *pair,
			  char *old_secret, char *new_secret,
			  char *old_vector, char *new_vector);
static void rad_send_request(int fd, UINT4 ipaddr, int port, int id,
			     int code, char *old_vector, char *old_secret,
			     char *new_secret, VALUE_PAIR *request);


/* ************************************************************************* */
/* Proxy-Id functions */
/* We try to keep a separate proxy_id per remote server so that if we happen
 * to have a lot of proxy requests the proxy id wouldn't wrap around too
 * fast.
 * From the other hand, we can't keep the proxy id in the client struct since
 * it would be reset to zero after each reload of configuration files.
 * This approach has two drawbacks:
 *   1. Linear search. If we have too many clients, its performance will
 *      degradate.
 *   2. Suppose we delete a client and then do a reload. In that case this
 *      client's proxy_id record will hang around just wasting memory. Hence,
 *      the need of proxy_cleanup function.
 */

/* next_proxy_id(): return next proxy id for the given client's IP address.
 * If we don't have one, create it and initialize to zero.
 */
u_char
next_proxy_id(ipaddr)
	UINT4 ipaddr;
{
	PROXY_ID *p;

	for (p = proxy_id; p; p = p->next)
		if (p->ipaddr == ipaddr)
			break;
	if (!p) {
		p = alloc_entry(sizeof *p);
		p->ipaddr = ipaddr;
		p->id = 0;
		p->next = proxy_id;
		proxy_id = p;
	}
	return p->id++;
}

/* Delete any proxy_id's that do not correspond to existing clients
 */
void
proxy_cleanup()
{
	PROXY_ID *p, *prev, *next;

	prev = NULL;
	for (p = proxy_id; p; ) {
		next = p->next;
		if (!client_lookup_ip(p->ipaddr)) {
			if (prev) 
				prev->next = next;
			else
				proxy_id = next;
			free_entry(p);
		}
		p = next;
	}
}

/* ************************************************************************* */
/* Request-queue functions */

/* rad_proxy(): Called right after the request has been added to the request
 * list. The function just creates a dynamic copy of raw request data and
 * attaches it to the request.
 */
/*ARGSUSED*/
int
rad_proxy(radreq, activefd)
	RADIUS_REQ *radreq;
	int activefd;
{
	void *ptr;
	
	/*
	 *	Copy the static data into malloc()ed memory.
	 */
	ptr = emalloc(radreq->data_len);
	debug(1,("allocated ptr %p", ptr));
	memcpy(ptr, radreq->data, radreq->data_len);
	radreq->data = ptr;
	radreq->data_alloced = 1;

	return 0;
}


/* ************************************************************************* */
/* Reply functions. Possibly these should go to libclient? */

/* Generate a random vector. */
static void
random_vector(vector)
	char *vector;
{
	int	randno;
	int	i;

	srand(time(0) + getpid());
	for(i = 0;i < AUTH_VECTOR_LEN;) {
		randno = rand();
		memcpy(vector, &randno, sizeof(int));
		vector += sizeof(int);
		i += sizeof(int);
	}
}

void
rad_send_request(fd, ipaddr, port, id, code, old_vector, old_secret,
		 new_secret, request)
	int   fd;
	UINT4 ipaddr;
	int   port;
	int   id;
	int   code;
	char  *old_vector;
	char  *old_secret;
	char  *new_secret;
	VALUE_PAIR *request;
{
	AUTH_HDR		*auth;
	VALUE_PAIR		*vp;
	u_char			*length_ptr;
	int			len, total_length;
	int			vendorcode, vendorpec;
	UINT4			lval;
	char			vector[AUTH_VECTOR_LEN];
	u_char                  *ptr;
	struct sockaddr_in	saremote, *sin;

#define checkovf(len) \
	if (total_length + len >= sizeof(i_send_buffer)) goto ovf;


	random_vector(vector);
	auth = (AUTH_HDR *)send_buffer;
	memset(auth, 0, sizeof(AUTH_HDR));
	auth->code = code;
	auth->id = id;
	if (auth->code == PW_AUTHENTICATION_REQUEST)
		memcpy(auth->vector, vector, AUTH_VECTOR_LEN);

	total_length = AUTH_HDR_LEN;

	/*
	 *	Put all the attributes into a buffer.
	 */
	ptr = auth->data;
	for (vp = request; vp; vp = vp->next) {

		if (debug_on(10))
			debug_pair("proxy_send", vp);

		/* This could be a vendor-specific attribute. */
		length_ptr = NULL;
		if ((vendorcode = VENDOR(vp->attribute)) > 0 &&
		    (vendorpec  = vendor_id_to_pec(vendorcode)) > 0) {
		        checkovf(11);
			*ptr++ = DA_VENDOR_SPECIFIC;
			length_ptr = ptr;
			*ptr++ = 6;
			lval = htonl(vendorpec);
			memcpy(ptr, &lval, 4);
			ptr += 4;
			total_length += 6;
		} else if (vp->attribute > 0xff) {
			continue;
		} else
			vendorpec = 0;

		*ptr++ = (vp->attribute & 0xFF);

		switch (vp->type) {
		case PW_TYPE_STRING:
			/*
			 *	Re-encode passwd on the fly.
			 */
			if (vp->attribute == DA_PASSWORD)
				passwd_recode(vp, old_secret, new_secret,
					      old_vector, vector);
			
                        checkovf(vp->strlength + 2);

			*ptr++ = vp->strlength + 2;

			if (length_ptr)
				*length_ptr += vp->strlength + 2;
			total_length += 2 + vp->strlength;
			memcpy(ptr, vp->strvalue, vp->strlength);

			ptr += vp->strlength;
			break;
		case PW_TYPE_INTEGER:
		case PW_TYPE_DATE:
		case PW_TYPE_IPADDR:
                        checkovf(sizeof(UINT4) + 2); 

			*ptr++ = sizeof(UINT4) + 2;
			if (length_ptr)
				*length_ptr += sizeof(UINT4)+ 2;
			lval = htonl(vp->lvalue);
			memcpy(ptr, &lval, sizeof(UINT4));
			ptr += sizeof(UINT4);
			total_length += sizeof(UINT4) + 2;
			break;
		default:
			break;
		}
	}
	auth->length = htons(total_length);

	/* If this is not an authentication request, we	need to calculate
	   the md5 hash over the entire packet and put it in the vector. */
	if (auth->code != PW_AUTHENTICATION_REQUEST) {
		len = strlen(new_secret);
		if (total_length + len < sizeof(i_send_buffer)) {
			strcpy(send_buffer + total_length, new_secret);
			md5_calc(auth->vector, send_buffer, total_length+len);
		}
	}

	/*
	 *	And send it to the remote radius server.
	 */
	sin = (struct sockaddr_in *) &saremote;
	memset ((char *) sin, '\0', sizeof (saremote));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(ipaddr);
	sin->sin_port = htons(port);

	sendto(fd, auth, total_length, 0,
	       (struct sockaddr *)sin, sizeof(struct sockaddr_in));

	return;

ovf:
	radlog(L_ERR, _("send buffer overflow"));

}

/* ************************************************************************* */
/* Functions local to this module */

/*
 *	Add a proxy-pair to the end of the request.
 */
static VALUE_PAIR *
proxy_addinfo(radreq, proxy_id, remip)
	RADIUS_REQ *radreq;
	int proxy_id;
	UINT4 remip;
{
	VALUE_PAIR		*proxy_pair, *vp;
	PROXY_STATE		*proxy_state;

	proxy_pair = avp_alloc();
	proxy_pair->name = "Proxy-State";
	proxy_pair->attribute = DA_PROXY_STATE;
	proxy_pair->type = PW_TYPE_STRING;
	proxy_pair->strlength = sizeof(PROXY_STATE);
	proxy_pair->strvalue = alloc_string(proxy_pair->strlength);
	
	proxy_state = (PROXY_STATE *)proxy_pair->strvalue;
	proxy_state->ipaddr = myip;
	proxy_state->id = radreq->id;
	proxy_state->proxy_id = proxy_id;
	proxy_state->rem_ipaddr = remip;

	for (vp = radreq->request; vp && vp->next; vp = vp->next)
		;
	vp->next = proxy_pair;
	return vp;
}

/*
 *	Decode a password and encode it again.
 */
static void
passwd_recode(pass_pair, old_secret, new_secret, old_vector, new_vector)
	VALUE_PAIR *pass_pair;
	char *old_secret;
	char *new_secret;
	char *old_vector;
	char *new_vector;
{
	char	password[AUTH_STRING_LEN];
	decrypt_password(password, pass_pair, old_vector, old_secret);
	free_string(pass_pair->strvalue);
	encrypt_password(pass_pair, password, new_vector, new_secret);
	/* Don't let the cleantext hang around */
	memset(password, 0, AUTH_STRING_LEN);
}

/* ************************************************************************* */
/* Interface functions */

/*
 *	Relay the request to a remote server.
 *	Returns:  1 success (we reply, caller returns without replying)
 *	          0 fail (caller falls through to normal processing)
 *		 -1 fail (we don't reply, caller returns without replying)
 *
 */
int
proxy_send(radreq, activefd)
	RADIUS_REQ *radreq;
	int activefd;
{
	int                     rc;
	char                    *saved_username;
	char                    *username;
	VALUE_PAIR		*namepair;
	VALUE_PAIR		*vp, *pp;
	char			*realmname;
	REALM			*realm;
	CLIENT			*client;
	short			rport;
	char                    *what;
	char                    *secret_key;
	u_char                  proxy_id;
	
	/*
	 *	Look up name.
	 */
	namepair = avl_find(radreq->request, DA_USER_NAME);
	if (namepair == NULL)
		return 0;

	saved_username = estrdup(namepair->strvalue);
	username = namepair->strvalue;

	/* Find the realm from the _end_ so that we can	cascade realms:
	   user@realm1@realm2. Two special realms are handled separately:
	   
	       LOCAL    -- process request locally.
	       NOREALM  -- handle an empty realm name.

	   A realm with special name DEFAULT is returned by realm_find()
	   if no other realm name matches. */

	if ((realmname = strrchr(username, '@')) == NULL) {
		if ((realm = realm_find("NOREALM")) == NULL) {
			efree(saved_username);
			return 0;
		}
	} else if ((realm = realm_find(realmname + 1)) == NULL) {
		/* If the realm is not found, we treat it as usual. */
		efree(saved_username);
		return 0;
	} else if (strcmp(realm->server, "LOCAL") == 0) {
		if (realm->striprealm) {
			*realmname = 0;
			namepair->strlength = strlen(namepair->strvalue);
		}
		efree(saved_username);
		return 0;
	}

	if ((client = client_lookup_ip(realm->ipaddr)) == NULL) {
		radlog(L_PROXY|L_ERR,
		       _("cannot find secret for server %s in clients file"),
		       realm->server);
		efree(saved_username);
		return 0;
	}

	if (realmname) {
		if (realm->striprealm)
			*realmname = 0;
		realmname++;
		radreq->realm = make_string(realmname);
	} else
		radreq->realm = make_string(realm->realm);
	
	replace_string(&namepair->strvalue, username);
	namepair->strlength = strlen(namepair->strvalue);

	if (radreq->code == PW_AUTHENTICATION_REQUEST)
		rport = realm->auth_port;
	else
		rport = realm->acct_port;

	secret_key = client->secret;
	proxy_id = next_proxy_id(client->ipaddr);
	
	radreq->server_ipaddr = realm->ipaddr;
	radreq->server_id = proxy_id;

	/*
	 *	Is this a valid & signed request ?
	 */
	/*
	 *	FIXME: we have already calculated the
	 *	digest in rad_auth_init()
	 */
	switch (radreq->code) {
	case PW_AUTHENTICATION_REQUEST:
		what = _("authentication");
		rc = 0;
		break;
	case PW_ACCOUNTING_REQUEST:
		what = _("accounting");
		rc = calc_acctdigest(radreq) < 0;
		break;
	default:
		what = _("unknown");
		rc = 1;
	}

	if (rc) {
		radlog(L_NOTICE,
		       _("%s request from client %s for user %s - Security Breach"),
		       what, client_lookup_name(radreq->ipaddr),
		       namepair->strvalue);
		efree(saved_username);
		return -1;
	}

	/*
	 *	Add PROXY_STATE attribute.
	 */
	pp = proxy_addinfo(radreq, proxy_id, realm->ipaddr);

	/*
	 *	If there is no DA_CHAP_CHALLENGE attribute but there
	 *	is a DA_CHAP_PASSWORD we need to add it since we can't
	 *	use the request authenticator anymore - we changed it.
	 */
	if (avl_find(radreq->request, DA_CHAP_PASSWORD) &&
	    avl_find(radreq->request, DA_CHAP_CHALLENGE) == NULL) {
		vp = avp_alloc();
		
		memset(vp, 0, sizeof(VALUE_PAIR));

		vp->name = "CHAP-Challenge";
		vp->attribute = DA_CHAP_CHALLENGE;
		vp->type = PW_TYPE_STRING;
		vp->strlength = AUTH_VECTOR_LEN;
		vp->strvalue = alloc_string(AUTH_VECTOR_LEN);
		memcpy(vp->strvalue, radreq->vector, AUTH_VECTOR_LEN);
		avl_add_pair(&radreq->request, vp);
	}

	debug(1, ("Sending %s request of id %d to %lx (server %s:%d)",
		 what, proxy_id, realm->ipaddr, realm->server, rport));

	/* Now build a new request and send it to the remote radiusd. */
	rad_send_request(activefd, realm->ipaddr, rport,
			 proxy_id, radreq->code,
			 radreq->vector,
			 radreq->secret,
			 secret_key,
			 radreq->request);
	
	/* Remove proxy-state from list. */
	if (pp->next) {
		VALUE_PAIR *p = pp->next;
		pp->next = p->next;
		p->next = NULL;  /* be sure to delete *only* this pair */
		avl_free(p);
	}
#if 1	
	/* And restore username. */
	replace_string(&namepair->strvalue, saved_username);
	namepair->strlength = strlen(namepair->strvalue);
#endif
	efree(saved_username);

	return 1;
}

/* ************************************************************************* */
/* Functions for finding the matching request in the list of outstanding ones.
 * There appear to be two cases: i) when the remote server retains the
 * Proxy-State A/V pair, which seems to correspond to RFC 2865,
 * and ii) when the remote server drops the Proxy-State pair.
 */

struct proxy_data {
	PROXY_STATE *state;
	RADIUS_REQ    *radreq;
};

/* proxy_compare_request(): Find matching request based on the information
   preserved in the Proxy-State pair. */
int
proxy_compare_request(data, oldreq)
	struct proxy_data *data;
	RADIUS_REQ *oldreq;
{
	debug(10, ("(old=data) id %d %d, ipaddr %#8x %#8x", 
		oldreq->id,data->state->id,myip,data->state->ipaddr));
	
	if (data->state->ipaddr     == myip &&
	    data->state->id         == oldreq->id) 
		return 0;

	return 1;
}

/* proxy_compare_request_no_state(): Find matching outstanding request if the
   server did not retain the Proxy-State pair.
   miquels@cistron.nl says:
  	Some servers drop the proxy pair. So
        compare in another way if needed.
  	FIXME: hmmm, perhaps we don't even need Proxy-State
  	after all! */
int
proxy_compare_request_no_state(data, oldreq)
	struct proxy_data *data;
	RADIUS_REQ *oldreq;
{
	debug(10, ("(old=data) id %d %d, ipaddr %#8x %#8x",
		oldreq->server_id,
		data->radreq->id,
		oldreq->server_ipaddr,
		data->radreq->ipaddr));
			
	if (data->radreq->ipaddr == oldreq->server_ipaddr &&
	    data->radreq->id     == oldreq->server_id)
		return 0;

	return 1;
}


int
select_allowed(unused, pair)
	void *unused;
	VALUE_PAIR *pair;
{
	return pair->prop & AP_PROPAGATE;
}

/* Called when a response from a remote radius server has been received.
   The function finds the original request and replaces all fields in
   radreq, except `request' with the original data.
   Return:   0 proxy found
  	    -1 error don't reply */
int
proxy_receive(radreq, activefd)
	RADIUS_REQ        *radreq;
	int             activefd;
{
	VALUE_PAIR	*vp, *proxy_state_pair, *prev, *x;
	VALUE_PAIR	*allowed_pairs;
	RADIUS_REQ	*oldreq;
	PROXY_STATE	*state;
	struct proxy_data data;
	int             i;
	
	/* FIXME: calculate md5 checksum! */

	/* Find the last PROXY_STATE attribute. */

	oldreq  = NULL;
	proxy_state_pair = x = prev = NULL;

	for (vp = radreq->request; vp; vp = vp->next) {
		if (vp->attribute == DA_PROXY_STATE) {
			prev = x;
			proxy_state_pair = vp;
		}
		x = vp;
	}

	state = proxy_state_pair ?
		   (PROXY_STATE *)proxy_state_pair->strvalue : NULL;

	if (state)
	  debug(1, ("state: ipaddr %08x, id %u, proxy_id %u, rem_ipaddr %08x",
		 state->ipaddr,
		 state->id,
		 state->proxy_id,
		 state->rem_ipaddr));

	/* Find matching request in the list of outstanding requests. */
	data.state = state;
	data.radreq = radreq;

	debug(1, ("Compare: myip %08x, radreq->id %d, radreq->ipaddr %08x",
		 myip, radreq->id, radreq->ipaddr));
	
	if (state) {
		if (state->proxy_id   == radreq->id &&
		    state->rem_ipaddr == radreq->ipaddr) {
			oldreq = scan_request_list(R_PROXY,
						   proxy_compare_request,
						   &data);
		} else {
			oldreq = NULL;
		}
	} else {
		oldreq = scan_request_list(R_PROXY,
					   proxy_compare_request_no_state,
					   &data);
	}
	
	if (oldreq == NULL) {
		radlog(L_PROXY|L_ERR,
		       _("Unrecognized proxy reply from server %s - ID %d"),
		       client_lookup_name(radreq->ipaddr), radreq->id);
		return -1;
	}

	/* Remove proxy pair from the list. */
	if (proxy_state_pair) {
		if (prev)
			prev->next = proxy_state_pair->next;
		else
			radreq->request = proxy_state_pair->next;
          	proxy_state_pair->next = NULL;
	        avl_free(proxy_state_pair);
	}

	/* Only allow some attributes to be propagated from
	   the remote server back to the NAS, for security. */
	allowed_pairs = NULL;
	avl_move_pairs(&allowed_pairs, &radreq->request, select_allowed, NULL);
	avl_free(radreq->request);

	/* Rebuild the RADIUS_REQ struct, so that the normal functions
	   can process it. Take care not to modify oldreq! */
	
	radreq->server_reply = allowed_pairs;
	radreq->validated    = 1;
	radreq->server_code  = radreq->code;
	radreq->code         = oldreq->code;

	radreq->ipaddr       = oldreq->ipaddr;
	radreq->udp_port     = oldreq->udp_port;
	radreq->id           = oldreq->id;
	memcpy(radreq->vector, oldreq->vector, sizeof radreq->vector);
	radreq->secret       = oldreq->secret;
	radreq->request      = avl_dup(oldreq->request);

	/* Proxy support fields */
	radreq->realm         = dup_string(oldreq->realm);
	radreq->server_ipaddr = oldreq->server_ipaddr;
	radreq->server_id     = oldreq->server_id;
	
	return 0;
}

