/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003,2004,2005,
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

#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
        
#ifdef USE_LIVINGSTON_MENUS

#include <stdlib.h>
#include <stdio.h>
#include <radiusd.h>

static grad_avp_t *
menu_pairs(char *menu_name, char *menu_selection)
{
        FILE    *fp;
        char    *menu_path;
        char    buffer[MAX_MENU_SIZE];
        char    selection[MAX_MENU_INPUT];
        int     mode;
        char    *ptr, *errp;
        grad_avp_t      *reply_first;
        int line_num;
        
        menu_path = grad_mkfilename3(grad_config_dir, "menus", menu_name);
        if ((fp = fopen(menu_path, "r")) == NULL) {
                grad_log(GRAD_LOG_NOTICE|GRAD_LOG_PERROR, _("can't open menu `%s'"),
		         menu_name);
                grad_free(menu_path);
                return NULL;
        }

        /* skip past the menu */

        mode = 0;
        line_num = 0;
        while (ptr = fgets(buffer, MAX_MENU_SIZE, fp)) {
                line_num++;
                if (mode == 0) {
                        if (strncmp(ptr, "menu", 4) == 0) 
                                mode = 1;
                } else {
                        if (strncmp(ptr, "end", 3) == 0) 
                                break;
                }
        }

        if (*menu_selection == 0) 
                strcpy(selection, "<CR>");
        else {
                strncpy(selection, menu_selection, sizeof(selection));
                selection[sizeof(selection)-1] = 0;
        }

        reply_first = NULL;

        /* Look for a matching menu entry */

        while ((ptr = fgets(buffer, sizeof(buffer), fp)) != NULL) {
                line_num++;
                while (*ptr && *ptr != '\n') 
                        ptr++;
                if (*ptr == '\n') 
                        *ptr = 0;

                if (strcmp(selection, buffer) == 0
		    || strcmp("DEFAULT", buffer) == 0) {
                        
                        while (fgets(buffer, sizeof(buffer), fp)) {
                                line_num++;
                                if (*buffer == ' ' || *buffer == '\t') {
                                        /*
                                         * Parse the reply values
                                         */
                                        if (userparse(buffer, &reply_first,
                                                      &errp)) {
                                                grad_log(GRAD_LOG_ERR,
                                                         _("menu %s:%d: %s"),
                                                         menu_name,
                                                         line_num,
                                                         errp);
                                                grad_avl_free(reply_first);
                                                reply_first = NULL;
                                                break;
                                        }
                                } else
                                        break;
                        }
                        break;
                }
        }       

        fclose(fp);
        grad_free(menu_path);
        
        return reply_first;
}       

void
menu_reply(radiusd_request_t *radreq, int activefd)
{
        grad_avp_t *pair, *term_pair, *new_pair;
        char menu_name[MAX_MENU_NAME];
        char menu_input[MAX_MENU_INPUT];
        char state_value[MAX_STATE_VALUE];
        char *msg;

        if ((pair = grad_avl_find(radreq->request->avlist, DA_STATE)) == NULL
	    || pair->avp_strvalue == NULL
	    || strncmp(pair->avp_strvalue, "MENU=", 5) != 0) 
                return;
                

        strcpy(menu_name, pair->avp_strvalue + 5);

        /* The menu input is in the Password Field */
        pair = grad_avl_find(radreq->request->avlist, DA_USER_PASSWORD);
        if (!pair) 
                *menu_input = 0;
        else {
                /* Decrypt the password in the request. */
                req_decrypt_password(menu_input, radreq->request, pair);
        }

        pair = menu_pairs(menu_name, menu_input);
        if (!pair) {
                return;
        }
        
        if ((term_pair = grad_avl_find(pair, DA_TERMINATION_MENU)) != NULL) {
                /* Create a menu state attribute */
                snprintf(state_value, sizeof(state_value),
			 "MENU=%s", term_pair->avp_strvalue);
		new_pair = grad_avp_create_string(DA_STATE, state_value);
		grad_avl_merge(&pair, &new_pair);
		grad_avp_free(new_pair);

		/* Remove Termination-Menu */
		grad_avl_delete(&pair, DA_TERMINATION_MENU);
		
                /* Insert RADIUS termination option */
                new_pair = grad_avp_create_integer(DA_TERMINATION_ACTION,
				      DV_TERMINATION_ACTION_RADIUS_REQUEST);
	        grad_avl_merge(&pair, &new_pair);
		grad_avp_free(new_pair);
        }

        if ((term_pair = grad_avl_find(pair, DA_MENU)) != NULL
	    && strcmp(term_pair->avp_strvalue, "EXIT") == 0) {
                radius_send_reply(RT_ACCESS_REJECT, radreq,
                                  radreq->request->avlist, NULL, activefd);
        } else if (pair) {
                if (new_pair = grad_avl_find(pair, DA_MENU)) {
                        msg = menu_read_text(new_pair->avp_strvalue);
                        snprintf(state_value, sizeof(state_value),
                                        "MENU=%s", new_pair->avp_strvalue);
                        radius_send_challenge(radreq, msg, state_value, activefd);
			grad_free(msg);
                } else {
                        radius_send_reply(RT_ACCESS_ACCEPT, radreq,
                                          pair, NULL, activefd);
                }
        } else {
                radius_send_reply(RT_ACCESS_REJECT, radreq,
                                  radreq->request->avlist, NULL, activefd);
        }

        grad_avl_free(pair);

}

char *
menu_read_text(char *menu_name)
{
        FILE    *fp;
        char    *menu_buffer;
        char    *menu_path;
        int     mode;
        char    *ptr;
        int     nread;
        int     len;
                
        menu_path = grad_mkfilename3(grad_config_dir, "menus", menu_name);
        if ((fp = fopen(menu_path, "r")) == NULL) {
                grad_log(GRAD_LOG_NOTICE|GRAD_LOG_PERROR, 
                         _("can't open menu `%s'"),
		         menu_name);
                grad_free(menu_path);
                return grad_estrdup(_("\n*** User Menu is Not Available ***\n"));
        }

        mode = 0;
        nread = 0;
	menu_buffer = grad_emalloc(MAX_MENU_SIZE);
        ptr = menu_buffer;

        while (nread < 4096 && fgets(ptr, MAX_MENU_SIZE - nread, fp)) {
                len = strlen(ptr);
                if (len && ptr[len-1] == '\n')
                        ptr[--len] = 0;

                if (ptr[0] == '#')
                        continue;
                
                if (mode == 0) {
                        if (strncmp(ptr, "menu", 4) == 0) 
                                mode = 1;
                } else {
                        if (strncmp(ptr, "end", 3) == 0) {
                                if (ptr - 2 >= menu_buffer)
                                        ptr -= 2;
                                break;
                        }
                        ptr += len;
                        *ptr++ = '\r';
                        *ptr++ = '\n';
                        nread += len + 1;
                }
        }
        fclose(fp);
        *ptr = 0;
        grad_free(menu_path);
        return menu_buffer;
}
               
        

#endif

