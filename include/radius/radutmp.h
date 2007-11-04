/* This file is part of GNU Radius.

   Copyright (C) 2000,2001,2002,2003,2004,2005,
   2007 Free Software Foundation, Inc.

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

#ifndef _gnu_radius_radutmp_h
#define _gnu_radius_radutmp_h

#define P_IDLE          0
#define P_LOGIN         1
#define P_NAS_START     128
#define P_NAS_SHUTDOWN  129
#define P_ACCT_DISABLED 130
#define P_ACCT_ENABLED  131

#define RUT_NAMESIZE 32
#define RUT_IDSIZE 16
#define RUT_PNSIZE 24           /* Phone number size */

struct radutmp {
        char login[RUT_NAMESIZE];       /* Login name (maybe modified) */
        char orig_login[RUT_NAMESIZE];  /* Original login name */
        int  nas_port;                  /* Port on the terminal server */
        char session_id[RUT_IDSIZE];    /* Radius session ID */
                                        /* (last RUT_IDSIZE bytes at least)*/
        grad_uint32_t nas_address;      /* IP of the NAS */
        grad_uint32_t framed_address;   /* SLIP/PPP address or login-host. */
        int proto;                      /* Protocol. */
        time_t time;                    /* Time the entry was last updated. */
        time_t delay;                   /* Delay time of request */
        int type;                       /* Type of entry (login/logout) */
        int porttype;                   /* Value of NAS-Port-Type attr */
        time_t duration;
        char caller_id[RUT_PNSIZE];     /* calling station ID */
        grad_uint32_t realm_address;
        char reserved[10];              
};

#define LOCK_LEN sizeof(struct radutmp)


struct maxsession {
        time_t start;
        time_t time;
};

typedef struct port_stat {
        struct port_stat *next;
        grad_uint32_t ip;          /* NAS IP */
        int port_no;               /* port number */
        int active;                /* is the port used now */
        char login[RUT_NAMESIZE];  /* last login name */
        grad_uint32_t framed_address; /* IP address assigned to that port */
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

radut_file_t grad_ut_setent(const char *name, int append);
void grad_ut_endent(radut_file_t file);
struct radutmp *grad_ut_getent(radut_file_t file);
int grad_ut_putent(radut_file_t file, struct radutmp *ent);
void grad_ut_rewind(radut_file_t file);

#define PUTENT_SUCCESS 0
#define PUTENT_NOENT   1
#define PUTENT_UPDATE  2

int grad_utmp_putent(const char *filename, struct radutmp *ut, int status);
int grad_radwtmp_putent(const char *filename, struct radutmp *ut);

typedef struct format_data format_data_t;

int grad_radutent_print(format_data_t *form, struct radutmp *up, int nl);
format_data_t *grad_radutent_compile_form(char *fmt);
void grad_utent_print_header(format_data_t *form);
format_data_t *grad_utent_compile_form(char *fmt);

extern int grad_printutmp_ip_nodomain; /* do not display domain names */
extern int grad_printutmp_use_naslist; /* use naslist when displaying nas names */
extern char *grad_printutmp_date_format;
extern char *grad_printutmp_empty_string;

#endif /* !_gnu_radius_radutmp_h */
