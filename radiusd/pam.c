/*
 * pam.c	Functions to access the PAM library. This was taken
 *		from the hacks that miguel a.l. paraz <map@iphil.net>
 *		did on radiusd-cistron-1.5.3 and migrated to a
 *		separate file.
 *
 *		That, in fact, was again based on the original stuff
 *		from Jeph Blaize <jab@kiva.net> done in May 1997.
 *
 * Version:	@(#)pam.c  1.10  14-Jul-1998  cdent@kiva.net
 *
 */

#define RADIUS_MODULE 9
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#ifdef USE_PAM

#ifndef lint
static char rcsid[] = "@(#) $Id$";
#endif

#include	<sys/types.h>
#include	<sys/socket.h>
#include	<sys/time.h>
#include	<netinet/in.h>

#include	<stdio.h>
#include	<netdb.h>
#include	<pwd.h>
#include	<time.h>
#include	<ctype.h>

#include	<security/pam_appl.h>

#include	<radiusd.h>

/*************************************************************************
 *
 *	Function: PAM_conv
 *
 *	Purpose: Dialogue between RADIUS and PAM modules.
 *
 * jab - stolen from pop3d
 *************************************************************************/

static char *PAM_username;
static char *PAM_password;
static int PAM_error =0;

#define COPY_STRING(s) (s) ? strdup(s) : NULL

static int
PAM_conv(num_msg, msg, resp, appdata_ptr)
	int num_msg;
	const struct pam_message **msg;
	struct pam_response **resp;
	void *appdata_ptr;
{
	int count = 0, replies = 0;
	struct pam_response *reply = NULL;

	if ((reply = calloc(num_msg, sizeof(struct pam_response))) == NULL)
		return PAM_CONV_ERR;
	
	for (count = 0; count < num_msg; count++) {
		switch (msg[count]->msg_style) {
		case PAM_PROMPT_ECHO_ON:
			reply[replies].resp_retcode = PAM_SUCCESS;
			reply[replies++].resp = COPY_STRING(PAM_username);
			/* PAM frees resp */
			break;
		case PAM_PROMPT_ECHO_OFF:
			reply[replies].resp_retcode = PAM_SUCCESS;
			reply[replies++].resp = COPY_STRING(PAM_password);
			/* PAM frees resp */
			break;
		case PAM_TEXT_INFO:
			/* ignore it... */
			break;
		case PAM_ERROR_MSG:
		default:
			/* Must be an error of some sort... */
			free (reply);
			PAM_error = 1;
			return PAM_CONV_ERR;
		}
	}
	if (reply)
		*resp = reply;
	return PAM_SUCCESS;
}

struct pam_conv conv = {
	PAM_conv,
	NULL
};

/*************************************************************************
 *
 *	Function: pam_pass
 *
 *	Purpose: Check the users password against the standard UNIX
 *		 password table + PAM.
 *
 * jab start 19970529
 *************************************************************************/

/* cjd 19980706
 * 
 * for most flexibility, passing a pamauth type to this function
 * allows you to have multiple authentication types (i.e. multiple
 * files associated with radius in /etc/pam.d)
 */
int
pam_pass(name, passwd, pamauth)
	char *name;
	char *passwd;
	const char *pamauth;
{
	pam_handle_t *pamh=NULL;
	int retval;
	
	PAM_username = name;
	PAM_password = passwd;

	debug(1,
	     ("using pamauth string <%s> for pam.conf lookup",
	     pamauth));
	retval = pam_start(pamauth, name, &conv, &pamh);
	if (retval == PAM_SUCCESS) {
		debug(1, ("pam_start succeeded for <%s>", name));
		retval = pam_authenticate(pamh, 0);
	}
	if (retval == PAM_SUCCESS) {
		debug(1, ("pam_authenticate succeeded for <%s>", name));
		retval = pam_acct_mgmt(pamh, 0);
	}
	if (retval == PAM_SUCCESS) {
		debug(1, ("pam_acct_mgmt succeeded for <%s>", name));
		pam_end(pamh, 0);
		return 0;
	}
	
	debug(1, ("PAM FAILED for <%s> failed", name));
	pam_end(pamh, 0);
	return -1;
}

#endif /* USE_PAM */

