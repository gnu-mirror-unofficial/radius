/* This file is part of GNU Radius.
   Copyright (C) 2004,2006,2007,2008 Free Software Foundation, Inc.

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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif  

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>  
#include <string.h>

#include <radiusd.h>

#ifdef HAVE_LIBLTDL
#include <ltdl.h>

static grad_list_t *handle_list;

static void
store_handle(lt_dlhandle handle)
{
	if (handle) {
		if (!handle_list)
			handle_list = grad_list_create();
		grad_list_append(handle_list, handle);
	}
}

static int
_free_loaded_module (void *item, void *data)
{
	lt_dlhandle handle = (lt_dlhandle) item;
	grad_dl_done_t fp = (grad_dl_done_t) lt_dlsym(handle, "done");

	GRAD_DEBUG2(1,"Freeing handle %p, grad_dl_done %p", handle, fp);
	if (fp)
		fp();
	lt_dlclose(handle);
	lt_dlexit();
	return 0;
}

static void
dynload_free_modules()
{
	grad_list_iterate(handle_list, _free_loaded_module, NULL);
	grad_list_destroy(&handle_list, NULL, NULL);
}

void *
radiusd_load_ext(const char *name, const char *ident, void **symbol)
{
	lt_dlhandle handle;

	GRAD_DEBUG2(1,"Loading module '%s', symbol '%s'", name, ident);
	if (lt_dlinit()) {
		GRAD_DEBUG(1,"lt_ldinit failed");
		return NULL;
	}
	
	handle = lt_dlopenext(name);
	if (handle) {
		*symbol = lt_dlsym(handle, ident);
		if (*symbol) {
			grad_dl_init_t initf =
				(grad_dl_init_t) lt_dlsym(handle, "init");
			if (initf) {
				if (initf()) {
					grad_log(GRAD_LOG_ERR,
						 _("Cannot load module %s: init function failed"),
						 name);
					lt_dlclose(handle);
					handle = NULL;
				}
			}

		} else {
			grad_log(GRAD_LOG_ERR,
				 _("Cannot load module %s: symbol %s not found"),
				 name, ident);
			lt_dlclose(handle);
			handle = NULL;
		}
	} else
		grad_log(GRAD_LOG_NOTICE, _("Cannot load module %s: %s"),
			 name, lt_dlerror());

	GRAD_DEBUG1(1,"Handle %p", handle);
	if (!handle) 
		lt_dlexit();
	else
		store_handle(handle);
	return handle;
}

int
radiusd_add_load_path(const char *path)
{
	if (lt_dlinit())
		return 1;
	return lt_dladdsearchdir(path);
}

int
radiusd_set_load_path(const char *path)
{
	if (lt_dlinit())
		return 1;
	return lt_dlsetsearchpath(path);
}

#else

static void
dynload_free_modules()
{
}

void *
radiusd_load_ext(const char *name, const char *ident, void **symbol)
{
	GRAD_DEBUG(1,"radiusd is compiled without dynamic loading support");
	return NULL;
}

int
radiusd_add_load_path(const char *path)
{
	GRAD_DEBUG(1,"radiusd is compiled without dynamic loading support");
	return 1;
}

int
radiusd_set_load_path(const char *path)
{
	GRAD_DEBUG(1,"radiusd is compiled without dynamic loading support");
	return 1;
}

#endif


static void
dynload_before_config_hook(void *a ARG_UNUSED, void *b ARG_UNUSED)
{
	dynload_free_modules();
}

void
dynload_init()
{
	radiusd_set_preconfig_hook(dynload_before_config_hook, NULL, 0);
}

int
dynload_stmt_term(int finish, void *block_data, void *handler_data)
{
	if (!finish) 
		radiusd_set_load_path (RADIUS_LIBDIR "/modules");
}

static int
dynload_cfg_add_load_path(int argc, cfg_value_t *argv,
			  void *block_data, void *handler_data)
{
	if (argc > 2) {
		cfg_argc_error(0);
		return 0;
	}

 	if (argv[1].type != CFG_STRING) {
		cfg_type_error(CFG_STRING);
		return 0;
	}
	
	radiusd_add_load_path(argv[1].v.string);
	return 0;
}


struct cfg_stmt dynload_stmt[] = {
	{ "load-path", CS_STMT, NULL, dynload_cfg_add_load_path, NULL, NULL, NULL },
	{ NULL }
};
