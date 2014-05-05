/* packet-h248.h
 * Definitions for H.248/MEGACO packet dissection
 *
 * Ronnie Sahlberg 2004
 * Luis Ontanon 2005
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef PACKET_H248_H

#include <epan/gcp.h>
#include "ws_symbol_export.h"
/*#include "packet-h248-exp.h"*/

typedef struct _h248_curr_info_t h248_curr_info_t;

typedef void (*h248_pkg_param_dissector_t)(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo _U_, int hfid, h248_curr_info_t*, void*);

extern void h248_param_bytes_item(proto_tree*, tvbuff_t*, packet_info* , int, h248_curr_info_t*,void* ignored);
extern void h248_param_uint_item(proto_tree*, tvbuff_t*, packet_info* , int, h248_curr_info_t*,void* ignored);
WS_DLL_PUBLIC void h248_param_ber_integer(proto_tree*, tvbuff_t*, packet_info* , int, h248_curr_info_t*,void* ignored);
extern void h248_param_ber_octetstring(proto_tree*, tvbuff_t*, packet_info* , int, h248_curr_info_t*,void* ignored);
extern void h248_param_ber_boolean(proto_tree*, tvbuff_t*, packet_info* , int, h248_curr_info_t*,void* ignored);
extern void external_dissector(proto_tree*, tvbuff_t*, packet_info* , int, h248_curr_info_t*,void* dissector_handle);
extern void h248_param_PkgdName(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo , int hfid _U_, h248_curr_info_t* u _U_, void* dissector_hdl);
extern void h248_param_external_dissector(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo , int hfid _U_, h248_curr_info_t* u _U_, void* dissector_hdl);

typedef enum {
	ADD_PKG,	/* add package at registration ONLY if no matching package ID */
	REPLACE_PKG,	/* replace/add package at registration */
	MERGE_PKG_HIGH,		/* merge h248_package_t at registration favor new package */
	MERGE_PKG_LOW		/* merge h248_package_t at registration favor current package */
} pkg_reg_action;

typedef struct _h248_pkg_param_t {
	guint32 id;
	int* hfid;
	h248_pkg_param_dissector_t dissector;
	void* data;
} h248_pkg_param_t;

typedef struct _h248_pkg_sig_t {
	guint32 id;
	int* hfid;
	gint* ett;
	const h248_pkg_param_t* parameters;
	const value_string* param_names;
} h248_pkg_sig_t;

typedef struct _h248_pkg_evt_t {
	guint32 id;
	int* hfid;
	gint* ett;
	const h248_pkg_param_t* parameters;
	const value_string* param_names;
} h248_pkg_evt_t;

typedef struct _h248_pkg_stat_t {
	guint32 id;
	int* hfid;
	gint* ett;
	const h248_pkg_param_t* parameters;
	const value_string* param_names;
} h248_pkg_stat_t;

typedef struct _h248_package_t {
	guint32 id;                            /**< Package ID */
	int* hfid;                             /**< hfid that will display the package name */
	gint* ett;                             /**< The ett for this item */
	const value_string* param_names;       /**< The parameter names, Value 00000 should be the package name */
	const value_string* signal_names;
	const value_string* event_names;
	const value_string* stats_names;
	const h248_pkg_param_t* properties;
	const h248_pkg_sig_t* signals;
	const h248_pkg_evt_t* events;
	const h248_pkg_stat_t* statistics;
} h248_package_t;

typedef struct _save_h248_package_t {
	h248_package_t *pkg;
	gboolean is_default;
} s_h248_package_t;

struct _h248_curr_info_t {
	gcp_ctx_t* ctx;
	gcp_trx_t* trx;
	gcp_msg_t* msg;
	gcp_term_t* term;
	gcp_cmd_t* cmd;
	const h248_package_t* pkg;
	const h248_pkg_evt_t* evt;
	const h248_pkg_sig_t* sig;
	const h248_pkg_stat_t* stat;
	const h248_pkg_param_t* par;
};

typedef struct h248_term_info {
	guint8 wild_card;
	gchar *str;
} h248_term_info_t;

WS_DLL_PUBLIC
void h248_register_package(h248_package_t* pkg, pkg_reg_action reg_action);

#endif  /* PACKET_H248_H */
