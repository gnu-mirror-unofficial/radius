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

#ifndef _RADUTMP_H
#define _RADUTMP_H

#define P_IDLE          0
#define P_LOGIN         1
#define P_NAS_START     128
#define P_NAS_SHUTDOWN  129

#define RUT_NAMESIZE 32
#define RUT_IDSIZE 16
#define RUT_PNSIZE 24           /* Phone number size */

struct radutmp {
        char login[RUT_NAMESIZE];       /* Loginname (maybe modified) */
        char orig_login[RUT_NAMESIZE];  /* Original loginname */
        int  nas_port;                  /* Port on the terminal server */
        char session_id[RUT_IDSIZE];    /* Radius session ID */
                                        /* (last RUT_IDSIZE bytes at least)*/
        unsigned int nas_address;       /* IP of portmaster. */
        unsigned int framed_address;    /* SLIP/PPP address or login-host. */
        int proto;                      /* Protocol. */
        time_t time;                    /* Time the entry was last updated. */
        time_t delay;                   /* Delay time of request */
        int type;                       /* Type of entry (login/logout) */
        char porttype;         /* Porttype (I=ISDN A=Async T=Async-ISDN) */
        char res1,res2,res3;            /* Fills up to one int */
        time_t duration;
        char caller_id[RUT_PNSIZE];      /* calling station ID */
        unsigned int realm_address;
        char reserved[10];              
};

#define LOCK_LEN sizeof(struct radutmp)


struct maxsession {
        time_t start;
        time_t time;
};

typedef struct port_stat {
        struct port_stat *next;
        UINT4 ip;                  /* NAS IP */
        int port_no;               /* port number */
        int active;                /* is the port used now */
        char login[RUT_NAMESIZE];  /* last login name */
        UINT4 framed_address;      /* IP address assigned to that port */
        unsigned long count;       /* number of logins */
        time_t start;
        time_t lastin;             /* last time the user logged in */
        time_t lastout;            /* last time the user logged out */
        time_t inuse;              /* total time the line was in use */
        time_t idle;               /* total idle time */
        struct maxsession maxinuse;
        struct maxsession maxidle;
} PORT_STAT;

/* stat.c */
PORT_STAT * findportbyindex(int ind);

typedef struct _radut_file *radut_file_t;

radut_file_t rut_setent(char *name, int append);
void rut_endent(radut_file_t file);
struct radutmp *rut_getent(radut_file_t file);
int rut_putent(radut_file_t file, struct radutmp *ent);
void rut_rewind(radut_file_t file);

#define PUTENT_SUCCESS 0
#define PUTENT_NOENT   1
#define PUTENT_UPDATE  2

int radutmp_putent(char *filename, struct radutmp *ut, int status);
int radwtmp_putent(char *filename, struct radutmp *ut);

#endif /* _RADUTMP_H */
