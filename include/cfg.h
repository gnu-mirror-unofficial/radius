/* This file is part of GNU Radius.
   Copyright (C) 2002,2003,2007 Free Software Foundation, Inc.

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

#ifndef _cfg_h_included
#define _cfg_h_included

#define CS_STMT 0
#define CS_BLOCK 1

typedef struct {
	grad_uint32_t ipaddr;
	grad_uint32_t netmask;
} cfg_network_t;

typedef struct {
	grad_uint32_t ipaddr;
	int port;
} cfg_host_t;

#define CFG_INTEGER  0
#define CFG_BOOLEAN  1
#define CFG_STRING   2
#define CFG_NETWORK  3
#define CFG_IPADDR   4
#define CFG_PORT     5
#define CFG_CHAR     6
#define CFG_HOST     7
#define CFG_UNSIGNED 8
#define CFG_SIZE_T   9

typedef struct {
        int type;
        union {
		char *string;
                grad_uint32_t ipaddr;
                size_t number;
                int bool;
		cfg_network_t network;
		char ch;
		cfg_host_t host;
        } v;
} cfg_value_t;


typedef int (*cfg_handler_fp)(int argc, cfg_value_t *argv,
			      void *block_data,
			      void *handler_data);
typedef int (*cfg_term_fp)(int finish, void *block_data,
			   void *handler_data);
typedef int (*cfg_end_fp)(void *block_data,
			  void *handler_data);

struct cfg_stmt {
	char *keyword;
	int type;
	cfg_term_fp term;
	cfg_handler_fp handler;
	void *data;
	struct cfg_stmt *block;
	cfg_end_fp end;
};

extern char *cfg_filename;
extern int cfg_line_num;

int cfg_ignore(int argc, cfg_value_t *argv,
	       void *block_data, void *handler_data);
int cfg_obsolete(int argc, cfg_value_t *argv,
		 void *block_data, void *handler_data);
int cfg_get_ipaddr(int argc, cfg_value_t *argv,
		   void *block_data, void *handler_data);
int cfg_get_integer(int argc, cfg_value_t *argv,
		    void *block_data, void *handler_data);
int cfg_get_unsigned(int argc, cfg_value_t *argv,
		     void *block_data, void *handler_data);
int cfg_get_size_t(int argc, cfg_value_t *argv,
		   void *block_data, void *handler_data);
int cfg_get_uint32_t(int argc, cfg_value_t *argv,
		     void *block_data, void *handler_data);
int cfg_get_number(int argc, cfg_value_t *argv,
		   void *block_data, void *handler_data);
int cfg_get_string(int argc, cfg_value_t *argv,
		   void *block_data, void *handler_data);
int cfg_get_boolean(int argc, cfg_value_t *argv,
		    void *block_data, void *handler_data);
int cfg_get_network(int argc, cfg_value_t *argv,
		    void *block_data, void *handler_data);
int cfg_get_port(int argc, cfg_value_t *argv,
		 void *block_data, void *handler_data);

int cfg_read(char *fname, struct cfg_stmt *syntax, void *data);
void cfg_type_error(int type);
void cfg_argc_error(int few);
void *cfg_malloc(size_t size, void (*destructor)(void *));


#endif
