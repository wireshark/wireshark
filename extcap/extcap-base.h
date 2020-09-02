/* extcap_base.h
 * Base function for extcaps
 *
 * Copyright 2016, Dario Lombardo
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __EXTCAP_BASE_H__
#define __EXTCAP_BASE_H__

#include "config.h"

#include <glib.h>
#include <glib/gprintf.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef HAVE_GETOPT_H
	#include <getopt.h>
#endif

#ifndef HAVE_GETOPT_LONG
	#include "wsutil/wsgetopt.h"
#endif

#ifdef _WIN32
	#include <io.h>
#endif

#include <wsutil/socket.h>

#define EXTCAP_BASE_OPTIONS_ENUM \
	EXTCAP_OPT_LIST_INTERFACES, \
	EXTCAP_OPT_VERSION, \
	EXTCAP_OPT_LIST_DLTS, \
	EXTCAP_OPT_INTERFACE, \
	EXTCAP_OPT_CONFIG, \
	EXTCAP_OPT_CAPTURE, \
	EXTCAP_OPT_CAPTURE_FILTER, \
	EXTCAP_OPT_FIFO, \
	EXTCAP_OPT_DEBUG, \
	EXTCAP_OPT_DEBUG_FILE


#define EXTCAP_BASE_OPTIONS \
	{ "extcap-interfaces", no_argument, NULL, EXTCAP_OPT_LIST_INTERFACES}, \
	{ "extcap-version", optional_argument, NULL, EXTCAP_OPT_VERSION}, \
	{ "extcap-dlts", no_argument, NULL, EXTCAP_OPT_LIST_DLTS}, \
	{ "extcap-interface", required_argument, NULL, EXTCAP_OPT_INTERFACE}, \
	{ "extcap-config", no_argument, NULL, EXTCAP_OPT_CONFIG}, \
	{ "capture", no_argument, NULL, EXTCAP_OPT_CAPTURE}, \
	{ "extcap-capture-filter", required_argument,	NULL, EXTCAP_OPT_CAPTURE_FILTER}, \
	{ "fifo", required_argument, NULL, EXTCAP_OPT_FIFO}, \
	{ "debug", no_argument, NULL, EXTCAP_OPT_DEBUG}, \
	{ "debug-file", required_argument, NULL, EXTCAP_OPT_DEBUG_FILE}

typedef struct _extcap_parameters
{
	char * exename;
	char * fifo;
	char * interface;
	char * capture_filter;

	char * version;
	char * compiled_with;
	char * running_with;
	char * helppage;
	uint8_t capture;
	uint8_t show_config;

	char * ws_version;

	/* private content */
	GList * interfaces;
	uint8_t do_version;
	uint8_t do_list_dlts;
	uint8_t do_list_interfaces;

	char * help_header;
	GList * help_options;

	gboolean debug;
} extcap_parameters;

void extcap_base_register_interface(extcap_parameters * extcap, const char * interface, const char * ifdescription, uint16_t dlt, const char * dltdescription );
void extcap_base_register_interface_ext(extcap_parameters * extcap, const char * interface, const char * ifdescription, uint16_t dlt, const char * dltname, const char * dltdescription );
void extcap_base_set_util_info(extcap_parameters * extcap, const char * exename, const char * major, const char * minor, const char * release, const char * helppage);
void extcap_base_set_compiled_with(extcap_parameters * extcap, const char *fmt, ...);
void extcap_base_set_running_with(extcap_parameters * extcap, const char *fmt, ...);
uint8_t extcap_base_parse_options(extcap_parameters * extcap, int result, char * optargument);
uint8_t extcap_base_handle_interface(extcap_parameters * extcap);
void extcap_base_cleanup(extcap_parameters ** extcap);
void extcap_help_add_header(extcap_parameters * extcap, char * help_header);
void extcap_help_add_option(extcap_parameters * extcap, const char * help_option_name, const char * help_optionn_desc);
void extcap_version_print(extcap_parameters * extcap);
void extcap_help_print(extcap_parameters * extcap);
void extcap_cmdline_debug(char** ar, const unsigned n);
void extcap_init_custom_log(const char* filename);
void extcap_config_debug(unsigned* count);
void extcap_base_help(void);

#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
