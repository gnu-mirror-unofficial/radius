/* This file is part of GNU RADIUS.
   Copyright (C) 2000,2001, Sergey Poznyakoff
 
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

#if defined(HAVE_CONFIG_H)
# include <config.h>
#endif
        
#ifdef USE_LIVINGSTON_MENUS

#include <stdlib.h>
#include <stdio.h>
#include <radiusd.h>

#ifndef lint
static char rcsid[] =
"@(#) $Id$";
#endif

static VALUE_PAIR * menu_pairs(char *menu_name, char  *menu_selection);


void
process_menu(radreq, activefd)
        RADIUS_REQ        *radreq;
        int             activefd;
{
        VALUE_PAIR *pair, *term_pair, *new_pair;
        char menu_name[MAX_MENU_NAME];
        char menu_input[MAX_MENU_INPUT];
        char state_value[MAX_STATE_VALUE];
        char *msg;

        if ((pair = avl_find(radreq->request, DA_STATE)) == NULL ||
            pair->avp_strvalue == NULL ||           
            strncmp(pair->avp_strvalue, "MENU=", 5) != 0) 
                return;
                

        strcpy(menu_name, pair->avp_strvalue + 5);

        /* The menu input is in the Password Field */
        pair = avl_find(radreq->request, DA_USER_PASSWORD);
        if (!pair) 
                *menu_input = 0;
        else {
                /* Decrypt the password in the request. */
                req_decrypt_password(menu_input, radreq, pair);
        }

        pair = menu_pairs(menu_name, menu_input);
        if (!pair) {
                return;
        }
        
        if ((term_pair = avl_find(pair, DA_TERMINATION_MENU)) != NULL) {
                /* Change this to a menu state */
                snprintf(state_value, sizeof(state_value),
                                "MENU=%s", term_pair->avp_strvalue);
                term_pair->attribute = DA_STATE;
                string_replace(&term_pair->avp_strvalue, state_value);
                term_pair->avp_strlength = strlen(state_value);
                term_pair->name = "Challenge-State";

                /* Insert RADIUS termination option */
                if (new_pair = avp_create(DA_TERMINATION_ACTION,
                                           0, NULL,
                                       DV_TERMINATION_ACTION_RADIUS_REQUEST)) {
                        /* Insert it */
                        new_pair->next = term_pair->next;
                        term_pair->next = new_pair;
                }
        }

        if ((term_pair = avl_find(pair, DA_MENU)) != NULL &&
            strcmp(term_pair->avp_strvalue, "EXIT") == 0) {
                rad_send_reply(RT_AUTHENTICATION_REJECT, radreq,
                               radreq->request, NULL, activefd);
        } else if (pair) {
                if (new_pair = avl_find(pair, DA_MENU)) {
                        msg = get_menu(new_pair->avp_strvalue);
                        snprintf(state_value, sizeof(state_value),
                                        "MENU=%s", new_pair->avp_strvalue);
                        send_challenge(radreq, msg, state_value, activefd);
                } else {
                        rad_send_reply(RT_AUTHENTICATION_ACK, radreq,
                                       pair, NULL, activefd);
                }
        } else {
                rad_send_reply(RT_AUTHENTICATION_REJECT, radreq,
                               radreq->request, NULL, activefd);
        }

        avl_free(pair);

}

char *
get_menu(menu_name)
        char    *menu_name;
{
        FILE    *fp;
        static  char menu_buffer[MAX_MENU_SIZE];
        char    *menu_path;
        int     mode;
        char    *ptr;
        int     nread;
        int     len;
                
        
        menu_path = mkfilename3(radius_dir, "menus", menu_name);
        if ((fp = fopen(menu_path, "r")) == NULL) {
                radlog(L_NOTICE|L_PERROR, _("can't open menu `%s'"), menu_name);
                efree(menu_path);
                return _("\n*** User Menu is Not Available ***\n");
        }

        mode = 0;
        nread = 0;
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
        efree(menu_path);
        return menu_buffer;
}
               
VALUE_PAIR *
menu_pairs(menu_name, menu_selection)
        char    *menu_name;
        char    *menu_selection;
{
        FILE    *fp;
        char    *menu_path;
        char    buffer[MAX_MENU_SIZE];
        char    selection[MAX_MENU_INPUT];
        int     mode;
        char    *ptr, *errp;
        VALUE_PAIR      *reply_first;
        int line_num;
        
        menu_path = mkfilename3(radius_dir, "menus", menu_name);
        if ((fp = fopen(menu_path, "r")) == NULL) {
                radlog(L_NOTICE|L_PERROR, _("can't open menu `%s'"), menu_name);
                efree(menu_path);
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

                if (strcmp(selection, buffer) == 0 ||
                    strcmp("DEFAULT", buffer) == 0) {
                        
                        while (fgets(buffer, sizeof(buffer), fp)) {
                                line_num++;
                                if (*buffer == ' ' || *buffer == '\t') {
                                        /*
                                         * Parse the reply values
                                         */
                                        if (userparse(buffer, &reply_first,
                                                      &errp)) {
                                                radlog(L_ERR,
                                                       _("menu %s:%d: %s"),
                                                       menu_name,
                                                       line_num,
                                                       errp);
                                                avl_free(reply_first);
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
        efree(menu_path);
        
        return reply_first;
}       
        

#endif

