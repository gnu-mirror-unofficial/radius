/* This file is part of GNU Radius.
   Copyright (C) 2000,2001,2002,2003 Sergey Poznyakoff
  
   GNU Radius is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   GNU Radius is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with GNU Radius; if not, write to the Free Software Foundation, 
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

/* debug.c      Debugging module. */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <radius.h>

static struct keyword auth_codes[] = {
#define D(a)  {#a, a}
        D(RT_AUTHENTICATION_REQUEST),
        D(RT_AUTHENTICATION_ACK),
        D(RT_AUTHENTICATION_REJECT),
        D(RT_ACCOUNTING_REQUEST),
        D(RT_ACCOUNTING_RESPONSE),
        D(RT_ACCOUNTING_STATUS),
        D(RT_PASSWORD_REQUEST),
        D(RT_PASSWORD_ACK),
        D(RT_PASSWORD_REJECT),
        D(RT_ACCOUNTING_MESSAGE),
        D(RT_ACCESS_CHALLENGE),
        D(RT_STATUS_SERVER),
        D(RT_ASCEND_TERMINATE_SESSION),
        { 0 }
#undef D        
};

const char *
auth_code_str(int code)
{
        struct keyword *p;

        for (p = auth_codes; p->name; p++)
                if (p->tok == code)
                        return p->name;
        return NULL;
}

static struct keyword auth_codes_abbr[] = {
        { "AUTHREQ", RT_AUTHENTICATION_REQUEST }, 
        { "AUTHACK", RT_AUTHENTICATION_ACK },     
        { "AUTHREJ", RT_AUTHENTICATION_REJECT },  
        { "ACCTREQ", RT_ACCOUNTING_REQUEST },     
        { "ACCTRES", RT_ACCOUNTING_RESPONSE },    
        { "ACCTSTA", RT_ACCOUNTING_STATUS },      
        { "PASSREQ", RT_PASSWORD_REQUEST },       
	{ "PASSACK", RT_PASSWORD_ACK },           
        { "PASSREJ", RT_PASSWORD_REJECT },        
        { "ACCTMSG", RT_ACCOUNTING_MESSAGE },     
        { "CHALNGE", RT_ACCESS_CHALLENGE },       
        { NULL }
};

const char *
auth_code_abbr(int code)
{
        struct keyword *p;
        for (p = auth_codes_abbr; p->name; p++)
                if (p->tok == code)
                        return p->name;
	return "Unknown";
}

#if RADIUS_DEBUG


int
set_module_debug_level(char *name, int level)
{
        int  i;
        int  length;

        length = strlen(name);

        if (level == -1)
                level = MAX_DEBUG_LEVEL;

        for (i = 0; debug_module[i].name; i++) {
                if (strncmp(debug_module[i].name, name, length) == 0) {
                        debug_level[ debug_module[i].modnum ] = level;
                        return 0;
                }
        }
        return 1;
}

void
set_debug_levels(char *str)
{
        int  i;
        char *tok, *p, *save;
        int  length;
        int  level;

        for (tok = strtok_r(str, ",", &save); tok; 
             tok = strtok_r(NULL, ",", &save)) {
                p = strchr(tok, '=');
                if (p) {
                        length = p - tok;
                        level  = atoi(p+1);
                } else {
                        length = strlen(tok);
                        level  = MAX_DEBUG_LEVEL;
                }               
                for (i = 0; debug_module[i].name; i++) {
                        if (strncmp(debug_module[i].name, tok, length) == 0) {
                                debug_level[ debug_module[i].modnum ] = level;
                                break;
                        }
                }
        /*      if (debug_module[i].name == NULL)
                        radlog(L_ERR, "unknown module: %s", tok); */
        }
}

void
clear_debug()
{
        int  i;

        for (i = 0; debug_module[i].name; i++) 
                debug_level[ debug_module[i].modnum ] = 0;
}

#else

#include <radius.h>

/*ARGSUSED*/
int
set_module_debug_level(char *name, int level)
{
        radlog(L_ERR, _("compiled without debugging support"));
}

/*ARGSUSED*/
void
set_debug_levels(char *str)
{
        radlog(L_ERR, _("compiled without debugging support"));
}

void
clear_debug()
{
}

#endif
