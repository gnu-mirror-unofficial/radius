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

#define RADIUS_MODULE 11
#ifndef lint
static char rcsid[] =
"@(#) $Id$";
#endif

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include	<sys/types.h>
#include	<sys/socket.h>
#include	<sys/time.h>
#include	<netinet/in.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<netdb.h>
#include	<pwd.h>
#include	<time.h>
#include	<ctype.h>

#include	<radiusd.h>


/*
 *	Make sure our buffer is aligned.
 */
static int	i_send_buffer[RAD_BUFFER_SIZE];
static char	*send_buffer = (char *)i_send_buffer;

/*
 *	Reply to the request.  Also attach
 *	reply attribute value pairs and any user message provided.
 */
int
rad_send_reply(code, authreq, oreply, msg, activefd)
	int code;
	AUTH_REQ *authreq;
	VALUE_PAIR *oreply;
	char *msg;
	int activefd;
{
	AUTH_HDR		*auth;
	u_short			total_length;
	struct	sockaddr	saremote;
	struct	sockaddr_in	*sin;
	u_char			*ptr, *length_ptr;
	char			*what;
	int			len;
	UINT4			lval;
	u_char			digest[AUTH_DIGEST_LEN];
	int			secretlen;
	VALUE_PAIR		*reply;
	int			vendorcode, vendorpec;

	auth = (AUTH_HDR *)send_buffer;
	reply = oreply;

	switch (code) {
		case PW_PASSWORD_REJECT:
		case PW_AUTHENTICATION_REJECT:
			what = _("Reject");
			/*
			 *	Also delete all reply attributes
			 *	except proxy-pair and port-message.
			 */
			reply = NULL;
			pairmove2(&reply, &oreply, DA_REPLY_MESSAGE);
			pairmove2(&reply, &oreply, DA_PROXY_STATE);
			break;
		case PW_ACCESS_CHALLENGE:
			what = _("Challenge");
			stat_inc(auth, authreq->ipaddr, num_challenges);
			break;
		case PW_AUTHENTICATION_ACK:
			what = _("Ack");
			break;
		case PW_ACCOUNTING_RESPONSE:
			what = _("Accounting Ack");
			break;
		default:
			what = _("Reply");
			break;
	}

	/*
	 *	Build standard header
	 */
	auth->code = code;
	auth->id = authreq->id;
	memcpy(auth->vector, authreq->vector, AUTH_VECTOR_LEN);

	debug(1, ("Sending %s of id %d to %lx (nas %s)",
		what, authreq->id, (u_long)authreq->ipaddr,
		nas_name2(authreq)));

	total_length = AUTH_HDR_LEN;

	/*
	 *	Load up the configuration values for the user
	 */
	ptr = auth->data;
	while (reply != (VALUE_PAIR *)NULL) {
		if (debug_on(10))
			debug_pair("reply", reply);

		/*
		 *	This could be a vendor-specific attribute.
		 */
		length_ptr = NULL;
		if ((vendorcode = VENDOR(reply->attribute)) > 0 &&
		    (vendorpec  = dict_vendorpec(vendorcode)) > 0) {
			if (total_length + 6 >= RAD_BUFFER_SIZE)
				goto err;
			*ptr++ = DA_VENDOR_SPECIFIC;
			length_ptr = ptr;
			*ptr++ = 6;
			lval = htonl(vendorpec);
			memcpy(ptr, &lval, 4);
			ptr += 4;
			total_length += 6;
		} else if (reply->attribute > 0xff) {
			/*
			 *	Ignore attributes > 0xff
			 */
			reply = reply->next;
			continue;
		} else
			vendorpec = 0;

#ifdef ATTRIB_NMC
		if (vendorpec == VENDORPEC_USR) {
			if (total_length + 2 >= RAD_BUFFER_SIZE)
				goto err;
			lval = htonl(reply->attribute & 0xFFFF);
			memcpy(ptr, &lval, 4);
			total_length += 2;
			*length_ptr  += 2;
			ptr          += 4;
		} else
#endif
		*ptr++ = (reply->attribute & 0xFF);

		switch(reply->type) {

		case PW_TYPE_STRING:
			/*
			 *	FIXME: this is just to make sure but
			 *	should NOT be needed. In fact I have no
			 *	idea if it is needed :)
			 */
			if (reply->strlength == 0 && reply->strvalue[0] != 0)
				reply->strlength = strlen(reply->strvalue);

			len = reply->strlength;
			if (len >= AUTH_STRING_LEN) {
				len = AUTH_STRING_LEN - 1;
			}
			if (total_length + len + 2 >= RAD_BUFFER_SIZE)
				goto err;
#ifdef ATTRIB_NMC
			if (vendorpec != VENDORPEC_USR)
#endif
				*ptr++ = len + 2;
			if (length_ptr) *length_ptr += len + 2;
			memcpy(ptr, reply->strvalue, len);
			ptr += len;
			total_length += len + 2;
			break;

		case PW_TYPE_INTEGER:
		case PW_TYPE_IPADDR:
			if (total_length + sizeof(UINT4) + 2 >= RAD_BUFFER_SIZE)
				goto err;
#ifdef ATTRIB_NMC
			if (vendorpec != VENDORPEC_USR)
#endif
				*ptr++ = sizeof(UINT4) + 2;
			if (length_ptr) *length_ptr += sizeof(UINT4)+ 2;
			lval = htonl(reply->lvalue);
			memcpy(ptr, &lval, sizeof(UINT4));
			ptr += sizeof(UINT4);
			total_length += sizeof(UINT4) + 2;
			break;

		default:
			break;
		}

		reply = reply->next;
	}

	/*
	 *	Append the user message
	 *	Add multiple DA_REPLY_MESSAGEs if it
	 *	doesn't fit into one.
	 */
	if (msg != NULL && (len = strlen(msg)) > 0) {
		int block_len;
		
		while (len > 0) {
			if (len > AUTH_STRING_LEN) {
				block_len = AUTH_STRING_LEN;
			} else {
				block_len = len;
			}

			if (total_length + block_len + 2 >= RAD_BUFFER_SIZE) {
				radlog(L_ERR,
				       _("user message too long in rad_send_reply"));
				return -1; /* be on the safe side */
			}
			
			*ptr++ = DA_REPLY_MESSAGE;
			*ptr++ = block_len + 2;
			memcpy(ptr, msg, block_len);
			msg += block_len;
			ptr += block_len;
			total_length += block_len + 2;
			len -= block_len;
		}
	}

	auth->length = htons(total_length);

	/*
	 *	Append secret and calculate the response digest
	 */
	secretlen = strlen(authreq->secret);
	memcpy(send_buffer + total_length, authreq->secret, secretlen);
	md5_calc(digest, (char *)auth, total_length + secretlen);
	memcpy(auth->vector, digest, AUTH_VECTOR_LEN);
	memset(send_buffer + total_length, 0, secretlen);

	sin = (struct sockaddr_in *) &saremote;
        memset ((char *) sin, '\0', sizeof (saremote));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(authreq->ipaddr);
	sin->sin_port = htons(authreq->udp_port);

	/*
	 *	Send it to the user
	 */
	sendto(activefd, (char *)auth, (int)total_length, (int)0,
			&saremote, sizeof(struct sockaddr_in));

	/*
	 *	Just to be tidy move pairs back.
	 */
	if (reply != oreply) {
		pairmove2(&oreply, &reply, DA_PROXY_STATE);
		pairmove2(&oreply, &reply, DA_REPLY_MESSAGE);
	}

	return 0;
err:
	radlog(L_ERR, _("send buffer overflow"));
	return -1;
}


/*
 *	Validates the requesting client NAS.  Calculates the
 *	digest to be used for decrypting the users password
 *	based on the clients private key.
 */
int
calc_digest(digest, authreq)
	u_char *digest;
	AUTH_REQ *authreq;
{
	u_char	buffer[128];
	int	secretlen;
	CLIENT	*cl;

	/*
	 *	See if we know this client.
	 */
	if ((cl = client_find(authreq->ipaddr)) == NULL) {
		radlog(L_ERR, _("request from unknown client: %s"),
			client_name(authreq->ipaddr));
		return -1;
	}

	/*
	 *	Use the secret to setup the decryption digest
	 */
	secretlen = strlen(cl->secret);
	strcpy(buffer, cl->secret);
	memcpy(buffer + secretlen, authreq->vector, AUTH_VECTOR_LEN);
	md5_calc(digest, buffer, secretlen + AUTH_VECTOR_LEN);
	strcpy(authreq->secret, cl->secret);
	memset(buffer, 0, sizeof(buffer));

	return(0);
}

/*
 *	Validates the requesting client NAS.  Calculates the
 *	signature based on the clients private key.
 */
int
calc_acctdigest(digest, authreq)
	u_char *digest;
	AUTH_REQ *authreq;
{
	int	secretlen;
	CLIENT	*cl;
	char zero[AUTH_VECTOR_LEN];
	char	* recvbuf = authreq->data;
	int	len = authreq->data_len;

	/*
	 *	See if we know this client.
	 */
	if ((cl = client_find(authreq->ipaddr)) == NULL) {
		radlog(L_ERR, _("request from unknown client: %s"),
			client_name(authreq->ipaddr));
		return -1;
	}

	/*
	 *	Copy secret into authreq->secret so that we can
	 *	use it with send_acct_reply()
	 */
	secretlen = strlen(cl->secret);
	strcpy(authreq->secret, cl->secret);

	/*
	 *	Older clients have the authentication vector set to
	 *	all zeros. Return `1' in that case.
	 */
	memset(zero, 0, sizeof(zero));
	if (memcmp(authreq->vector, zero, AUTH_VECTOR_LEN) == 0)
		return 1;

	/*
	 *	Zero out the auth_vector in the received packet.
	 *	Then append the shared secret to the received packet,
	 *	and calculate the MD5 sum. This must be the same
	 *	as the original MD5 sum (authreq->vector).
	 */
	memset(recvbuf + 4, 0, AUTH_VECTOR_LEN);
	memcpy(recvbuf + len, cl->secret, secretlen);
	md5_calc(digest, recvbuf, len + secretlen);

	/*
	 *	Return 0 if OK, 2 if not OK.
	 */
	return memcmp(digest, authreq->vector, AUTH_VECTOR_LEN) ? 2 : 0;
}


/*
 *	Receive UDP client requests, build an authorization request
 *	structure, and attach attribute-value pairs contained in
 *	the request to the new structure.
 */
AUTH_REQ *
radrecv(host, udp_port, buffer, length)
	UINT4 host;
	u_short udp_port;
	u_char *buffer;
	int length;
{
	u_char		*ptr;
	AUTH_HDR	*auth;
	int		totallen;
	int		attribute;
	int		attrlen;
 	DICT_ATTR	*attr;
	UINT4		lval;
	UINT4		vendorcode;
	UINT4		vendorpec;
	VALUE_PAIR	*first_pair;
	VALUE_PAIR	*prev;
	VALUE_PAIR	*pair;
	AUTH_REQ	*authreq;

	/*
	 *	Pre-allocate the new request data structure
	 */

	authreq = alloc_request();
	
	memset(authreq, 0, sizeof(AUTH_REQ));

	auth = (AUTH_HDR *)buffer;
	totallen = ntohs(auth->length);
	if (length > totallen) {
		radlog(L_WARN,
		       _("Received message length > packet length (%d, %d)"),
		    length, totallen);
		length = totallen;
	}
		
	debug(1, ("Request from host %lx code=%d, id=%d, length=%d",
				(u_long)host, auth->code, auth->id, totallen));

	/*
	 *	Fill header fields
	 */
	authreq->ipaddr = host;
	authreq->udp_port = udp_port;
	authreq->id = auth->id;
	authreq->code = auth->code;
	memcpy(authreq->vector, auth->vector, AUTH_VECTOR_LEN);
	authreq->data = buffer;
	authreq->data_len = length;

	/*
	 *	Extract attribute-value pairs
	 */
	ptr = auth->data;
	length -= AUTH_HDR_LEN;
	first_pair = (VALUE_PAIR *)NULL;
	prev = (VALUE_PAIR *)NULL;

	while (length > 0) {

		attribute = *ptr++;
		attrlen = *ptr++;
		if (attrlen < 2) {
			length = 0;
			continue;
		}
		attrlen -= 2;
		length  -= 2;

		/*
		 *	FIXME:
		 *	For now we ignore the length in the vendor-specific
		 *	part, and assume only one entry.
		 */
		if (attribute == DA_VENDOR_SPECIFIC && attrlen > 6) {
			memcpy(&lval, ptr, 4);
			vendorpec = ntohl(lval);
			if ((vendorcode = dict_vendorcode(vendorpec)) != 0) {
#ifdef ATTRIB_NMC
				if (vendorpec == VENDORPEC_USR) {
					ptr += 4;
					memcpy(&lval, ptr, 4);

					attribute = (ntohl(lval) & 0xFFFF) |
							(vendorcode << 16);
					ptr += 4;
					attrlen -= 8;
					length -= 8;
				} else
#endif
				{
					ptr += 4;
					attribute = *ptr | (vendorcode << 16);
					ptr += 2;
					attrlen -= 6;
					length -= 6;
				}
			}
		}

		if ((attr = dict_attrget(attribute)) == (DICT_ATTR *)NULL) {
			debug(1, ("Received unknown attribute %d", attribute));
		} else if ( attrlen >= AUTH_STRING_LEN ) {
			debug(1, ("attribute %d too long, %d >= %d", attribute,
				attrlen, AUTH_STRING_LEN));
		} else if ( attrlen > length ) {
			debug(1,
			      ("attribute %d longer then buffer left, %d > %d",
				attribute, attrlen, length));
		} else {
			pair = alloc_pair();
			
			pair->name = attr->name;
			pair->attribute = attr->value;
			pair->type = attr->type;
			pair->next = (VALUE_PAIR *)NULL;

			switch (attr->type) {

			case PW_TYPE_STRING:
				/* attrlen always < AUTH_STRING_LEN */
				pair->strlength = attrlen;
				pair->strvalue = alloc_string(attrlen + 1);
				memcpy(pair->strvalue, ptr, attrlen);
				pair->strvalue[attrlen] = 0;
				if (debug_on(10))
					debug_pair("send", pair);
				if (first_pair == (VALUE_PAIR *)NULL) {
					first_pair = pair;
				}
				else {
					prev->next = pair;
				}
				prev = pair;
				break;
			
			case PW_TYPE_INTEGER:
			case PW_TYPE_IPADDR:
				memcpy(&lval, ptr, sizeof(UINT4));
				pair->lvalue = ntohl(lval);
				if (debug_on(10))
					debug_pair("send", pair);
				if (first_pair == (VALUE_PAIR *)NULL) {
					first_pair = pair;
				}
				else {
					prev->next = pair;
				}
				prev = pair;
				break;
			
			default:
				debug(1, ("    %s (Unknown Type %d)",
					attr->name,attr->type));
				free_pair(pair);
				break;
			}

		}
		ptr += attrlen;
		length -= attrlen;
	}
	authreq->request = first_pair;
	return(authreq);
}

#ifdef USE_LIVINGSTON_MENUS
/*
 *	Reply to the request with a CHALLENGE.  Also attach
 *	any user message provided and a state value.
 */
void
send_challenge(authreq, msg, state, activefd)
	AUTH_REQ *authreq;
	char *msg;
	char *state;
	int activefd;
{
	AUTH_HDR		*auth;
	struct	sockaddr	saremote;
	struct	sockaddr_in	*sin;
	char			digest[AUTH_VECTOR_LEN];
	int			secretlen;
	int			total_length;
	int block_len;
	u_char			*ptr;
	int			len;

	auth = (AUTH_HDR *)send_buffer;

	/*
	 *	Build standard response header
	 */
	auth->code = PW_ACCESS_CHALLENGE;
	auth->id = authreq->id;
	memcpy(auth->vector, authreq->vector, AUTH_VECTOR_LEN);
	total_length = AUTH_HDR_LEN;
	ptr = auth->data;

	/*
	 *	Append the user message
	 */
	if (msg != NULL && (len = strlen(msg)) > 0) {
		while (len > 0) {
			if (len > AUTH_STRING_LEN) {
				block_len = AUTH_STRING_LEN;
			} else {
				block_len = len;
			}

			if (total_length + block_len + 2 >= RAD_BUFFER_SIZE) {
				radlog(L_ERR,
				    _("user message too long in send_challenge"));
				return;
			}
			
			*ptr++ = DA_REPLY_MESSAGE;
			*ptr++ = block_len + 2;
			memcpy(ptr, msg, block_len);
			msg += block_len;
			ptr += block_len;
			total_length += block_len + 2;
			len -= block_len;
		}
	}

	/*
	 *	Append the state info
	 */
	if ((state != (char *)NULL) && (strlen(state) > 0)) {
		len = strlen(state);
		*ptr++ = DA_STATE;
		*ptr++ = len + 2;
		memcpy(ptr, state, len);
		ptr += len;
		total_length += len + 2;
	}

	/*
	 *	Set total length in the header
	 */
	auth->length = htons(total_length);

	/*
	 *	Calculate the response digest
	 */
	secretlen = strlen(authreq->secret);
	memcpy(send_buffer + total_length, authreq->secret, secretlen);
	md5_calc(digest, (char *)auth, total_length + secretlen);
	memcpy(auth->vector, digest, AUTH_VECTOR_LEN);
	memset(send_buffer + total_length, 0, secretlen);

	sin = (struct sockaddr_in *) &saremote;
        memset ((char *) sin, '\0', sizeof (saremote));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(authreq->ipaddr);
	sin->sin_port = htons(authreq->udp_port);

	debug(1, ("Sending Challenge of id %d to %lx (nas %s)",
		authreq->id, (u_long)authreq->ipaddr,
		nas_name2(authreq)));
	
	/*
	 *	Send it to the user
	 */
	sendto(activefd, (char *)auth, (int)total_length, (int)0,
			&saremote, sizeof(struct sockaddr_in));
}

#endif







