/* This is mod_radius.c -- a GNU Radius interface module for PHP
   Copyright (C) 2004, 2007 Sergey Sinkovsky
  
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
  
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

#include "php.h"
#include "zend_ini.h"
#include <radius/radius.h>


ZEND_BEGIN_MODULE_GLOBALS(radius)
	grad_list_t *resources;
ZEND_END_MODULE_GLOBALS(radius)	

#ifdef ZTS
# define MRADG(v) TSRMG(radius_globals_id, zend_radius_globals *, v)
#else
# define MRADG(v) (radius_globals.v)
#endif
	
ZEND_DECLARE_MODULE_GLOBALS(radius);

typedef void (*mod_destroy_resource_t)(void *ptr);

struct mod_resource {
	void *ptr;
	mod_destroy_resource_t destr;
};

static void	
mod_register_resource(void *ptr, mod_destroy_resource_t destr)
{
	struct mod_resource *mr;
	if (!MRADG(resources))
		MRADG(resources) = grad_list_create();
	mr = malloc(sizeof(*mr));
	if (!mr)
		zend_error(E_ERROR, "Not enough memory");
	mr->ptr = ptr;
	mr->destr = destr;
	grad_list_append(MRADG(resources), mr);
}

static int
mod_res_cmp(const void *a, const void *b)
{
	const struct mod_resource *ma = a;
	const struct mod_resource *mb = b;
	return ma->ptr != mb->ptr;
}

static void
mod_destroy_resource(void *ptr)
{
	struct mod_resource *res = grad_list_remove(MRADG(resources), ptr,
						    mod_res_cmp);
	if (res) {
		res->destr(res->ptr);
		free(res);
	}
}

static int
mod_free_res(void *item, void *data)
{
	struct mod_resource *res = item;
	if (res) {
		res->destr(res->ptr);
		free(res);
	}
	return 0;
}

static void
mod_destroy_all_resources()
{
	grad_list_destroy(&MRADG(resources), mod_free_res, NULL);
}
		


static void
mod_destroy_queue(void *ptr)
{
	grad_client_destroy_queue((grad_server_queue_t *)ptr);
}

	

ZEND_MINFO_FUNCTION(radauthmod);
ZEND_MINIT_FUNCTION(radauthmod);
ZEND_MSHUTDOWN_FUNCTION(radauthmod);
ZEND_RSHUTDOWN_FUNCTION(radauthmod);

ZEND_FUNCTION(radius_auth_user);
ZEND_FUNCTION(radius_query);
ZEND_FUNCTION(radius_set_debug);
ZEND_FUNCTION(radius_clear_debug);
ZEND_FUNCTION(radius_lookup_value);
ZEND_FUNCTION(radius_attribute_type);

static unsigned char radius_query_args_force_ref[]  = { 5, BYREF_NONE, BYREF_NONE, BYREF_NONE, BYREF_FORCE, BYREF_FORCE };

/* compiled function list so Zend knows what's in this module */
zend_function_entry radauthmod_functions[] = {
	ZEND_FE(radius_auth_user, NULL)
	ZEND_FE(radius_query, radius_query_args_force_ref)
	ZEND_FE(radius_set_debug, NULL)
	ZEND_FE(radius_clear_debug, NULL)
	ZEND_FE(radius_lookup_value, NULL) 
	ZEND_FE(radius_attribute_type, NULL)
	{NULL, NULL, NULL}
};

zend_module_entry radauthmod_module_entry = {
	STANDARD_MODULE_HEADER,
	"RADIUS auth module",
	radauthmod_functions,
	ZEND_MINIT(radauthmod),
	ZEND_MSHUTDOWN(radauthmod),
	NULL,
	ZEND_RSHUTDOWN(radauthmod),
	ZEND_MINFO(radauthmod),
	NO_VERSION_YET,
	STANDARD_MODULE_PROPERTIES
};

ZEND_MINIT_FUNCTION(radauthmod)
{
	REGISTER_LONG_CONSTANT("RT_ACCESS_REQUEST", RT_ACCESS_REQUEST,
			       CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RT_ACCESS_ACCEPT", RT_ACCESS_ACCEPT,
			       CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RT_ACCESS_REJECT", RT_ACCESS_REJECT,
			       CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RT_ACCOUNTING_REQUEST",
			       RT_ACCOUNTING_REQUEST,
			       CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RT_ACCOUNTING_RESPONSE",
			       RT_ACCOUNTING_RESPONSE,
			       CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RT_ACCOUNTING_STATUS",
			       RT_ACCOUNTING_STATUS,
			       CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RT_PASSWORD_REQUEST", RT_PASSWORD_REQUEST,
			       CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RT_PASSWORD_ACK", RT_PASSWORD_ACK,
			       CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RT_PASSWORD_REJECT", RT_PASSWORD_REJECT,
			       CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RT_ACCOUNTING_MESSAGE",
			       RT_ACCOUNTING_MESSAGE,
			       CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RT_ACCESS_CHALLENGE", RT_ACCESS_CHALLENGE,
			       CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RT_STATUS_SERVER", RT_STATUS_SERVER,
			       CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RT_STATUS_CLIENT", RT_STATUS_CLIENT,
			       CONST_CS | CONST_PERSISTENT);

	/* Not implemented in GNU Radius, but have place in radius.h */
	REGISTER_LONG_CONSTANT("RT_ASCEND_TERMINATE_SESSION",
			       RT_ASCEND_TERMINATE_SESSION,
			       CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RT_ASCEND_EVENT_REQUEST",
			       RT_ASCEND_EVENT_REQUEST,
			       CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RT_ASCEND_EVENT_RESPONSE",
			       RT_ASCEND_EVENT_RESPONSE,
			       CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RT_ASCEND_ALLOCATE_IP",
			       RT_ASCEND_ALLOCATE_IP,
			       CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("RT_ASCEND_RELEASE_IP",
			       RT_ASCEND_RELEASE_IP,
			       CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("PORT_AUTH", GRAD_PORT_AUTH,
			       CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("PORT_ACCT", GRAD_PORT_ACCT,
			       CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("TYPE_INVALID", GRAD_TYPE_INVALID,
			       CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("TYPE_INTEGER", GRAD_TYPE_INTEGER,
			       CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("TYPE_IPADDR", GRAD_TYPE_IPADDR,
			       CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("TYPE_STRING", GRAD_TYPE_STRING,
			       CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("TYPE_DATE", GRAD_TYPE_DATE,
			       CONST_CS | CONST_PERSISTENT);
	
	grad_path_init();
	srand(time(NULL));

	if (grad_dict_init())
		zend_error(E_ERROR, "Can't read RADIUS dictionaries");

	return SUCCESS;
}

ZEND_MSHUTDOWN_FUNCTION(radauthmod)
{
	UNREGISTER_INI_ENTRIES();
	/* deallocate the dictionary entries */
	grad_dict_free();
	grad_path_free();
	return SUCCESS;
}

ZEND_RSHUTDOWN_FUNCTION(radauthmod)
{
	mod_destroy_all_resources();
}

ZEND_MINFO_FUNCTION(radauthmod)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "Function", "Support");
	php_info_print_table_row(2, "Checking user", "Enabled");
	php_info_print_table_row(2, "Passing additional parameters",
				 "Enabled");
	php_info_print_table_row(2, "Build ", __DATE__ "  " __TIME__);

	php_info_print_table_end();
}

#if COMPILE_DL_FIRST_MODULE
ZEND_GET_MODULE(radauthmod)
#endif

static void
put_string(grad_avp_t ** plist, int attrnum, zval * data)
{
	zval dcopy = *data;

	zval_copy_ctor(&dcopy);
	convert_to_string(&dcopy);
	grad_avl_add_pair(plist,
			  grad_avp_create_string(attrnum,
						 Z_STRVAL(dcopy)));
	zval_dtor(&dcopy);
}

static void
put_long(grad_avp_t ** plist, int attrnum, zval * data)
{
	long longval;
	grad_dict_value_t *val = grad_value_name_to_value(Z_STRVAL(*data),
							  attrnum);

	if (val)
		longval = val->value;
	else {
		zval dcopy = *data;
		
		zval_copy_ctor(&dcopy);
		convert_to_long(&dcopy);
		longval = Z_LVAL(dcopy);
		zval_dtor(&dcopy);
	}
	grad_avl_add_pair(plist,
			  grad_avp_create_integer(attrnum, longval));
}

static void
put_ipaddr(grad_avp_t ** plist, int attrnum, zval * data)
{
	zval dcopy = *data;

	zval_copy_ctor(&dcopy);
	convert_to_string(&dcopy);
	grad_avl_add_pair(plist,
			  grad_avp_create_integer(attrnum,
						  grad_ip_strtoip(Z_STRVAL
								  (dcopy))));
	zval_dtor(&dcopy);
}

static void
put_data(grad_avp_t ** plist, grad_dict_attr_t * attr, zval * data)
{
	switch (attr->type) {
	case GRAD_TYPE_STRING:
		put_string(plist, attr->value, data);
		break;
		
	case GRAD_TYPE_INTEGER:
		put_long(plist, attr->value, data);
		break;
		
	case GRAD_TYPE_IPADDR:
		put_ipaddr(plist, attr->value, data);
		break;

	default:
		zend_error(E_ERROR,
			   "Unhadled data type for 3rd argument");
	}
}

int
convert_pair_list(grad_avp_t ** plist, zval * obj)
{
	zval          **data;
	char           *key_str;
	ulong           key_num;

	int             i = 0;

	if (obj != NULL) {
		while (zend_hash_get_current_data(Z_ARRVAL(*obj),
						  (void **) &data)
		       == SUCCESS) {
			grad_dict_attr_t *attr;
			grad_avp_t     *pair;

			key_str = NULL;
			zend_hash_get_current_key(Z_ARRVAL(*obj),
						  &key_str, &key_num,
						  0);
			if (key_str)
				attr = grad_attr_name_to_dict(key_str);
			else
				attr = grad_attr_number_to_dict(key_num);
			if (!attr) {
				zend_error(E_ERROR, "Wrong 3rd parameter");
			}

			if (Z_TYPE_PP(data) == IS_ARRAY) {
				zval          **data2;
				
				while (zend_hash_get_current_data
				       (Z_ARRVAL(**data),
					(void **) &data2) == SUCCESS) {
					
					put_data(plist, attr, *data2);
					zend_hash_move_forward(Z_ARRVAL(**data));
				}
			} else
				put_data(plist, attr, *data);
			zend_hash_move_forward(Z_ARRVAL(*obj));
		}
	}
}

int
convert_from_pair_list(zval * obj, grad_avp_t * plist)
{
	grad_avp_t     *p;
	char            ipaddr[GRAD_IPV4_STRING_LENGTH];

	if (array_init(obj) == FAILURE) {
		zend_error(E_ERROR, "Can't initialize array");
	}

	for (p = plist; p; p = p->next) {
		zval          **found;

		if (zend_hash_find(Z_ARRVAL(*obj), p->name,
				   strlen(p->name) + 1,
				   (void **) &found) == SUCCESS) {
			char           *str;
			long            lval;
			
			switch ((*found)->type) {
			case IS_STRING:
				str = Z_STRVAL(**found);
				array_init(*found);
				add_next_index_string(*found, str, 0);
				break;

			case IS_LONG:
				lval = Z_LVAL(**found);
				array_init(*found);
				add_next_index_long(*found, lval);
				break;
			}

			switch (p->type) {
			case GRAD_TYPE_STRING:
			case GRAD_TYPE_DATE:
				add_next_index_string(*found, p->avp_strvalue,
						      1);
				break;

			case GRAD_TYPE_INTEGER:
			case GRAD_TYPE_IPADDR:
				add_next_index_long(*found, p->avp_lvalue);
				break;
			}
		} else
			switch (p->type) {
			case GRAD_TYPE_STRING:
			case GRAD_TYPE_DATE:
				add_assoc_string(obj, p->name, p->avp_strvalue,
						 1);
				break;
				
			case GRAD_TYPE_INTEGER:
			case GRAD_TYPE_IPADDR:
				add_assoc_long(obj, p->name, p->avp_lvalue);
				break;
			}
	}

}

char *
get_reply_message(grad_avp_t * plist)
{
	grad_avp_t     *p;
	size_t          len;
	char           *str, *s;

	for (len = 0, p = plist; p; p = p->next)
		if (p->attribute == DA_REPLY_MESSAGE)
			len += p->avp_strlength;

	str = emalloc(len + 1);
	
	for (s = str, p = plist; p; p = p->next)
		if (p->attribute == DA_REPLY_MESSAGE) {
			strcpy(s, p->avp_strvalue);
			s += strlen(s);
		}
	
	*s = 0;
	return str;
}

ZEND_FUNCTION(radius_query)
{
	int             port_type;
	int             request_type;
	zval           *pair_list = NULL;
	zval           *reply_pairs = NULL;
	zval           *reply_string = NULL;
	int             reply_code;

	grad_server_queue_t *queue;
	grad_avp_t     *plist = NULL, *p;
	grad_request_t *reply = NULL;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "lla|zz",
				  &port_type,
				  &request_type,
				  &pair_list,
				  &reply_pairs,
				  &reply_string) == FAILURE) {
		return;
	}

	if (reply_pairs && !PZVAL_IS_REF(reply_pairs)) {
		zend_error(E_ERROR, "Argument 4 is not passed by reference");
	}

	if (reply_string && !PZVAL_IS_REF(reply_string)) {
		zend_error(E_ERROR, "Argument 5 is not passed by reference");
	}
	
	queue = grad_client_create_queue(1, 0, 0);
	mod_register_resource(queue, mod_destroy_queue);
	
	convert_pair_list(&plist, pair_list);
	reply = grad_client_send(queue, port_type, request_type, plist);
	
	if (!reply) {
		zend_error(E_ERROR, "No reply from servers");
	}

	reply_code = reply->code;
	if (reply_string) {
		ZVAL_STRING(reply_string, get_reply_message(reply->avlist),
			    0);
	}
	if (reply_pairs) {
		convert_from_pair_list(reply_pairs, reply->avlist);
	}

	grad_avl_free(plist);
	grad_request_free(reply);
	mod_destroy_resource(queue);
	
	RETURN_LONG(reply_code);
}

ZEND_FUNCTION(radius_set_debug)
{
	char           *levels;
	int             levels_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s",
				  &levels,
				  &levels_len) == FAILURE)
		return;

	grad_set_debug_levels(levels);
}

ZEND_FUNCTION(radius_clear_debug)
{
	grad_clear_debug();
}

ZEND_FUNCTION(radius_lookup_value)
{
	char           *attribute;
	int             attribute_len;

	char           *return_name;
	grad_dict_value_t *vp;
	int             value;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "sl",
				  &attribute,
				  &attribute_len,
				  &value) == FAILURE)
		return;

	vp = grad_value_lookup(value, attribute);
	if (!vp) {
		  RETURN_NULL();
	} 
	RETURN_STRING(vp->name, 1);
}

ZEND_FUNCTION(radius_auth_user)
{
	long            return_code;
	char           *username;
	int             username_len;
	char           *password;
	int             passwd_len;
	zval           *pair_list = NULL;

	grad_server_queue_t *queue;
	grad_avp_t     *plist = NULL, *p;
	grad_request_t *reply;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "ss|a",
				  &username,
				  &username_len,
				  &password,
				  &passwd_len,
				  &pair_list) == FAILURE) {
		return;
	}

        /* main auth proc */

	queue = grad_client_create_queue(1, 0, 0);
	mod_register_resource(queue, mod_destroy_queue);
	
	/* Создание списка пар для авторизации */
	convert_pair_list(&plist, pair_list);
	/* 1. Логин: */
	grad_avl_add_pair(&plist,
			  grad_avp_create_string(DA_USER_NAME, username));
	/* 2. Пароль: */
	grad_avl_add_pair(&plist,
			  grad_avp_create_string(DA_USER_PASSWORD,
						 password));

	/* Запрос серверов: */
	reply = grad_client_send(queue, GRAD_PORT_AUTH, RT_ACCESS_REQUEST, plist);

	/* Анализ ответа: */
	if (!reply) {
		zend_printf("No reply from servers");
	}

	switch (reply->code) {
	case RT_ACCESS_ACCEPT:
		return_code = 0;
		break;

	case RT_ACCESS_REJECT:
		return_code = 1;
		break;
		
	default:
		return_code = 1;
		zend_printf("Authentication filed with code %s\n",
			    grad_request_code_to_name(reply->code));
	}

	grad_avl_free(plist);
	grad_request_free(reply);
	mod_destroy_resource(queue);
	RETURN_BOOL(return_code == 0);
}

ZEND_FUNCTION(radius_attribute_type)
{
	char *attrname;
	int attrname_len;
	grad_dict_attr_t *attr;
	int type;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
				  "s",
				  &attrname,
				  &attrname_len) == FAILURE) 
		return;

	attr = grad_attr_name_to_dict(attrname);
	if (!attr)
		type = GRAD_TYPE_INVALID;
	else
		type = attr->type;
	RETURN_LONG(type);
}

#ifdef __DEBUG
/* Guess what we're using it for */
wd()
{
	int volatile    _st = 0;

	printf("PID %lu\n", getpid());
	while (!_st)
		sleep(1);
}
#endif
