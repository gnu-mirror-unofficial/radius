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

#define RADIUS_MODULE 10
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
static char *send_buffer = (char *)i_send_buffer;

static PROXY_ID *proxy_id;

static int allowed[] = {
	DA_SERVICE_TYPE,
	DA_FRAMED_PROTOCOL,
	DA_FILTER_ID,
	DA_FRAMED_MTU,
	DA_FRAMED_COMPRESSION,
	DA_LOGIN_SERVICE,
	DA_REPLY_MESSAGE,
	DA_SESSION_TIMEOUT,
	DA_IDLE_TIMEOUT,
	DA_PORT_LIMIT,
	0,
};

static void random_vector(char *vector);
static VALUE_PAIR *proxy_addinfo(AUTH_REQ *authreq, int proxy_id, UINT4 remip);
void proxy_addrequest(AUTH_REQ *authreq);
static void passwd_recode(char *secret_key, char *vector,
			  char *pw_digest, VALUE_PAIR *pair);


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
		if (!client_find(p->ipaddr)) {
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
int
rad_proxy(authreq, activefd)
	AUTH_REQ *authreq;
	int activefd;
{
	void *ptr;
	
	/*
	 *	Copy the static data into malloc()ed memory.
	 */
	ptr = emalloc(authreq->data_len);
	debug(1,("allocated ptr %p", ptr));
	memcpy(ptr, authreq->data, authreq->data_len);
	authreq->data = ptr;
	authreq->data_alloced = 1;

	return 0;
}


/* ************************************************************************* */
/* Reply functions. Possibly these should go to libclient? */

/*
 *	Generate a random vector.
 */
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
rad_send_request(fd, ipaddr, port, id, code, pw_digest, secret_key, request)
	int   fd;
	UINT4 ipaddr;
	int   port;
	int   id;
	int   code;
	char  *pw_digest;
	char  *secret_key;
	VALUE_PAIR *request;
{
	AUTH_HDR		*auth;
	VALUE_PAIR		*vp;
	char			*length_ptr;
	int			len, total_length;
	int			vendorcode, vendorpec;
	UINT4			lval;
	char			vector[AUTH_VECTOR_LEN];
	char                    *ptr;
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

		/*
		 *	This could be a vendor-specific attribute.
		 */
		length_ptr = NULL;
		if ((vendorcode = VENDOR(vp->attribute)) > 0 &&
		    (vendorpec  = dict_vendorpec(vendorcode)) > 0) {
		        checkovf(11);
			*ptr++ = DA_VENDOR_SPECIFIC;
			length_ptr = ptr;
			*ptr++ = 6;
			lval = htonl(vendorpec);
			memcpy(ptr, &lval, 4);
			ptr += 4;
			total_length += 6;
		} else if (vp->attribute > 0xff) {
			/*
			 *	Ignore attributes > 0xff
			 */
			continue;
		} else
			vendorpec = 0;

#ifdef ATTRIB_NMC
		if (vendorpec == VENDORPEC_USR) {
                        checkovf(4);
			lval = htonl(vp->attribute & 0xFFFF);
			memcpy(ptr, &lval, 4);
			total_length += 2;
                        if (length_ptr)
                             *length_ptr  += 2;
			ptr          += 4;
		} else
#endif
		*ptr++ = (vp->attribute & 0xFF);

		switch (vp->type) {
		case PW_TYPE_STRING:
			/*
			 *	Re-encode passwd on the fly.
			 */
			if (vp->attribute == DA_PASSWORD)
				passwd_recode(secret_key, vector,
					      pw_digest, vp);
                        checkovf(vp->strlength + 2);
#ifdef ATTRIB_NMC
			if (vendorpec != VENDORPEC_USR)
#endif
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
#ifdef ATTRIB_NMC
			if (vendorpec != VENDORPEC_USR)
#endif
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

	/*
	 *	If this is not an authentication request, we
	 *	need to calculate the md5 hash over the entire packet
	 *	and put it in the vector.
	 */
	if (auth->code != PW_AUTHENTICATION_REQUEST) {
		len = strlen(secret_key);
		if (total_length + len < sizeof(i_send_buffer)) {
			strcpy(send_buffer + total_length, secret_key);
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
proxy_addinfo(authreq, proxy_id, remip)
	AUTH_REQ *authreq;
	int proxy_id;
	UINT4 remip;
{
	VALUE_PAIR		*proxy_pair, *vp;
	PROXY_STATE		*proxy_state;

	proxy_pair = alloc_pair();
	proxy_pair->name = "Proxy-State";
	proxy_pair->attribute = DA_PROXY_STATE;
	proxy_pair->type = PW_TYPE_STRING;
	proxy_pair->strlength = sizeof(PROXY_STATE);
	proxy_pair->strvalue = alloc_string(proxy_pair->strlength);
	
	proxy_state = (PROXY_STATE *)proxy_pair->strvalue;
	proxy_state->ipaddr = myip;
	proxy_state->id = authreq->id;
	proxy_state->proxy_id = proxy_id;
	proxy_state->rem_ipaddr = remip;

	for (vp = authreq->request; vp && vp->next; vp = vp->next)
		;
	vp->next = proxy_pair;
	return vp;
}

/*
 *	Decode a password and encode it again.
 */
static void
passwd_recode(secret_key, vector, pw_digest, pass_pair)
	char *secret_key;
	char *vector;
	char *pw_digest;
	VALUE_PAIR *pass_pair;
{
	char	passtmp[AUTH_PASS_LEN];
	char	passwd[AUTH_PASS_LEN];
	char	md5buf[256];
	int	i;
	int	len;

	/*
	 * Decode. First fixup the password padding it with
	 * zeroes to next 16-character boundary
	 */
	memset(passwd, 0, AUTH_PASS_LEN);
	memcpy(passwd, pass_pair->strvalue, AUTH_PASS_LEN);

	for(i = 0 ; i < AUTH_PASS_LEN; i++)
		passwd[i] ^= pw_digest[i];

	/*
	 *	Encode with new secret.
	 */
	memset(passtmp, 0, sizeof(passtmp));
	len = strlen(secret_key);
	strcpy(md5buf, secret_key);
	memcpy(md5buf + len, vector, AUTH_VECTOR_LEN);
	md5_calc(passtmp, md5buf, len + AUTH_VECTOR_LEN);
	for (i = 0; i < AUTH_PASS_LEN; i++)
		passtmp[i] ^= passwd[i];

	/*
	 *	Copy newly encoded password back to
	 *	where we got it from.
	 */
	if (pass_pair->strlength < AUTH_PASS_LEN) {
		free_string(pass_pair->strvalue);
		pass_pair->strvalue = alloc_string(AUTH_PASS_LEN);
	}
	memcpy(pass_pair->strvalue, passtmp, AUTH_PASS_LEN);
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
proxy_send(authreq, activefd)
	AUTH_REQ *authreq;
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
	char			pw_digest[16];
	char                    *secret_key;
	u_char                  proxy_id;
	
	/*
	 *	Look up name.
	 */
	namepair = pairfind(authreq->request, DA_USER_NAME);
	if (namepair == NULL)
		return 0;

	saved_username = estrdup(namepair->strvalue);
	username = namepair->strvalue;

	/*
	 *	Find the realm from the _end_ so that we can
	 *	cascade realms: user@realm1@realm2.
	 *	Use the original username if available.
	 */
	if (authreq->username[0]) {
		username = authreq->username;
	}

	if ((realmname = strrchr(username, '@')) == NULL) {
		efree(saved_username);
		return 0;
	}

	/*
	 *	Now check if we know this realm!
	 *	If not found, we treat it as usual.
	 */
	if ((realm = realm_find(realmname + 1)) == NULL) {
		efree(saved_username);
		return 0;
	}

	/*
	 *	The special realm LOCAL ?
	 */
	if (strcmp(realm->server, "LOCAL") == 0) {
		if (realm->striprealm &&
		    ((realmname = strrchr(namepair->strvalue, '@')) != NULL))
			*realmname = 0;
		efree(saved_username);
		return 0;
	}

	if ((client = client_find(realm->ipaddr)) == NULL) {
		radlog(L_PROXY,
		       _("cannot find secret for server %s in clients file"),
		       realm->server);
		efree(saved_username);
		return 0;
	}

	if (realm->striprealm)
		*realmname++ = 0;
	authreq->realm = make_string(realmname);

	replace_string(&namepair->strvalue, username);
	namepair->strlength = strlen(namepair->strvalue);

	if (authreq->code == PW_AUTHENTICATION_REQUEST)
		rport = realm->auth_port;
	else
		rport = realm->acct_port;

	secret_key = client->secret;
	proxy_id = next_proxy_id(client->ipaddr);
	
	authreq->server_ipaddr = realm->ipaddr;
	authreq->server_id = proxy_id;

	/*
	 *	Is this a valid & signed request ?
	 */
	/*
	 *	FIXME: we have already calculated the
	 *	digest in rad_auth_init()
	 */
	switch (authreq->code) {
	case PW_AUTHENTICATION_REQUEST:
		what = _("authentication");
		rc = calc_digest(pw_digest, authreq) != 0;
		break;
	case PW_ACCOUNTING_REQUEST:
		what = _("accounting");
		rc = calc_acctdigest(pw_digest, authreq) < 0;
		break;
	default:
		what = _("unknown");
		rc = 1;
	}

	if (rc) {
		radlog(L_NOTICE,
		       _("%s request from client %s for user %s - Security Breach"),
		       what, client_name(authreq->ipaddr),
		       namepair->strvalue);
		efree(saved_username);
		authfree(authreq);
		return -1;
	}

	/*
	 *	Add PROXY_STATE attribute.
	 */
	pp = proxy_addinfo(authreq, proxy_id, realm->ipaddr);

	/*
	 *	If there is no DA_CHAP_CHALLENGE attribute but there
	 *	is a DA_CHAP_PASSWORD we need to add it since we can't
	 *	use the request authenticator anymore - we changed it.
	 */
	if (pairfind(authreq->request, DA_CHAP_PASSWORD) &&
	    pairfind(authreq->request, DA_CHAP_CHALLENGE) == NULL) {
		vp = alloc_pair();
		
		memset(vp, 0, sizeof(VALUE_PAIR));

		vp->name = "CHAP-Challenge";
		vp->attribute = DA_CHAP_CHALLENGE;
		vp->type = PW_TYPE_STRING;
		vp->strlength = AUTH_VECTOR_LEN;
		vp->strvalue = alloc_string(AUTH_VECTOR_LEN);
		memcpy(vp->strvalue, authreq->vector, AUTH_VECTOR_LEN);
		pairadd(&authreq->request, vp);
	}

	debug(1, ("Sending %s request of id %d to %lx (server %s:%d)",
		 what, proxy_id, realm->ipaddr, realm->server, rport));

	/*
	 *	Now build a new request and send it to the remote radiusd.
	 */
	rad_send_request(activefd, realm->ipaddr, rport,
			 proxy_id, authreq->code,
			 pw_digest, secret_key,
			 authreq->request);
	
	/*
	 *	Remove proxy-state from list.
	 */
	if (pp->next) {
		VALUE_PAIR *p = pp->next;
		pp->next = p->next;
		pairfree(p);
	}

	/*
	 *	And restore username.
	 */
	replace_string(&namepair->strvalue, saved_username);
	namepair->strlength = strlen(namepair->strvalue);
	efree(saved_username);

	return 1;
}

/* ************************************************************************* */
/* Functions for finding the matching request in the list of outstanding ones.
 * There seem to be two cases: i) when the remote server retains the
 * Proxy-State A/V pair, which seems to correspond to RFC 2865,
 * and ii) when the remote server drops the Proxy-State pair.
 */

struct proxy_data {
	PROXY_STATE *state;
	AUTH_REQ    *authreq;
};

/* proxy_compare_request(): Find matching request based on the information
 * preserved in the Proxy-State pair.
 */
int
proxy_compare_request(data, oldreq)
	struct proxy_data *data;
	AUTH_REQ *oldreq;
{
	debug(1, ("oldreq->id %d", oldreq->id));
	
	if (data->state->ipaddr     == myip &&
	    data->state->id         == oldreq->id) 
		return 0;

	return 1;
}

/* proxy_compare_request_no_state(): Find matching outstanding request if the
 * server did not retain the Proxy-State pair.
 * miquels@cistron.nl says:
 *	Some servers drop the proxy pair. So
 *      compare in another way if needed.
 *	FIXME: hmmm, perhaps we don't even need Proxy-State
 *	after all!
 */
int
proxy_compare_request_no_state(data, oldreq)
	struct proxy_data *data;
	AUTH_REQ *oldreq;
{
	debug(1, ("oldreq->id %d", oldreq->id));
		
	if (data->authreq->ipaddr == oldreq->server_ipaddr &&
	    data->authreq->id     == oldreq->server_id)
		return 0;

	return 1;
}


/*
 *	We received a response from a remote radius server.
 *	Find the original request, then return.
 *	Returns:   0 proxy found
 *		  -1 error don't reply
 */
int
proxy_receive(authreq, activefd)
	AUTH_REQ        *authreq;
	int             activefd;
{
	VALUE_PAIR	*vp, *proxy_state_pair, *prev, *x;
	VALUE_PAIR	*allowed_pairs;
	AUTH_REQ	*oldreq;
	PROXY_STATE	*state;
	struct proxy_data data;
	int             i;
	
	/*
	 *	FIXME: calculate md5 checksum!
	 */

	/*
	 *	Find the last PROXY_STATE attribute.
	 */

	oldreq  = NULL;
	proxy_state_pair = x = prev = NULL;

	for (vp = authreq->request; vp; vp = vp->next) {
		if (vp->attribute == DA_PROXY_STATE) {
			prev = x;
			proxy_state_pair = vp;
		}
		x = vp;
	}

	state = proxy_state_pair ?
		   (PROXY_STATE *)proxy_state_pair->strvalue : NULL;

	if (state)
	  debug(1, ("state: ipaddr %08x, id %d, proxy_id %d, rem_ipaddr %08x",
		 state->ipaddr,
		 state->id,
		 state->proxy_id,
		 state->rem_ipaddr));

	/*
	 *	Now find matching request in the list of outstanding requests.
	 */
	data.state = state;
	data.authreq = authreq;

	debug(1, ("Compare: myip %08x, authreq->id %d, authreq->ipaddr %08x",
		 myip, authreq->id, authreq->ipaddr));
	
	if (state) {
		if (state->proxy_id   == authreq->id &&
		    state->rem_ipaddr == authreq->ipaddr) {
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
		radlog(L_PROXY,
		       _("Unreckognized proxy reply from server %s - ID %d"),
		       client_name(authreq->ipaddr), authreq->id);
		return -1;
	}

	/*
	 *	Remove proxy pair from list.
	 */
	if (proxy_state_pair) {
		if (prev)
			prev->next = proxy_state_pair->next;
		else
			authreq->request = proxy_state_pair->next;
          	proxy_state_pair->next = NULL;
	        pairfree(proxy_state_pair);
	}

	/*
	 *	Only allow some attributes to be propagated from
	 *	the remote server back to the NAS, for security.
	 */
	allowed_pairs = NULL;
	for(i = 0; allowed[i]; i++)
		pairmove2(&allowed_pairs, &authreq->request, allowed[i]);
	pairfree(authreq->request);

	/*
	 *	Now rebuild the AUTHREQ struct, so that the
	 *	normal functions can process it. Take care not to modify
	 *      oldreq!
	 */
	
	authreq->server_reply = allowed_pairs;
	authreq->validated    = 1;
	authreq->server_code  = authreq->code;
	authreq->code         = oldreq->code;

	authreq->ipaddr       = oldreq->ipaddr;
	authreq->udp_port     = oldreq->udp_port;
	authreq->id           = oldreq->id;
	memcpy(authreq->vector, oldreq->vector, sizeof authreq->vector);
	memcpy(authreq->secret, oldreq->secret, sizeof authreq->secret);
	memcpy(authreq->username, oldreq->username, sizeof authreq->username);
	authreq->request      = paircopy(oldreq->request);
	authreq->timestamp    = oldreq->timestamp;

	/* Proxy support fields */
	authreq->realm         = dup_string(oldreq->realm);
	authreq->server_ipaddr = oldreq->server_ipaddr;
	authreq->server_id     = oldreq->server_id;
	
	return 0;
}




