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

#define DOTTED_QUAD_LEN         16

#define AUTH_VECTOR_LEN		16
#define AUTH_PASS_LEN		16
#define AUTH_DIGEST_LEN		16
#define AUTH_STRING_LEN	       253

typedef struct pw_auth_hdr {
	u_char		code;
	u_char		id;
	u_short		length;
	u_char		vector[AUTH_VECTOR_LEN];
	u_char		data[2];
} AUTH_HDR;

#define AUTH_HDR_LEN			20
#define CHAP_VALUE_LENGTH		16

#ifndef PW_AUTH_UDP_PORT
# define PW_AUTH_UDP_PORT		1645
#endif
#ifndef PW_ACCT_UDP_PORT
# define PW_ACCT_UDP_PORT		1646
#endif

#define VENDORPEC_USR			429


#define PW_TYPE_STRING			0
#define PW_TYPE_INTEGER			1
#define PW_TYPE_IPADDR			2
#define PW_TYPE_DATE			3

#define	PW_AUTHENTICATION_REQUEST	1
#define	PW_AUTHENTICATION_ACK		2
#define	PW_AUTHENTICATION_REJECT	3
#define	PW_ACCOUNTING_REQUEST		4
#define	PW_ACCOUNTING_RESPONSE		5
#define	PW_ACCOUNTING_STATUS		6
#define PW_PASSWORD_REQUEST		7
#define PW_PASSWORD_ACK			8
#define PW_PASSWORD_REJECT		9
#define	PW_ACCOUNTING_MESSAGE		10
#define PW_ACCESS_CHALLENGE		11

#define PW_ASCEND_TERMINATE_SESSION     31
#define PW_ASCEND_EVENT_REQUEST         33
#define PW_ASCEND_EVENT_RESPONSE        34
/* These two are not implemented yet */
#define PW_ASCEND_ALLOCATE_IP           51
#define PW_ASCEND_RELEASE_IP            52

#include <raddict.h>

#define DV_ACCT_STATUS_TYPE_QUERY       -1
