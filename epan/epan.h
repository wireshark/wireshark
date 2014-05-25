/* epan.h
 *
 * Wireshark Protocol Analyzer Library
 *
 * Copyright (c) 2001 by Gerald Combs <gerald@wireshark.org>
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

#ifndef __EPAN_H__
#define __EPAN_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <glib.h>
#include "frame_data.h"
#include "register.h"
#include "ws_symbol_export.h"

typedef struct epan_dissect epan_dissect_t;

struct epan_dfilter;
struct epan_column_info;

/**
	@mainpage Wireshark EPAN the packet analyzing engine. Source code can be found in the epan directory

	@section Introduction

	XXX

	@b Sections:
*/
/*
Ref 1
Epan
Ethereal Packet ANalyzer (XXX - is this correct?) the packet analyzing engine. Source code can be found in the epan directory.

Protocol-Tree - Keep data of the capture file protocol information.

Dissectors - The various protocol dissectors in epan/dissectors.

Plugins - Some of the protocol dissectors are implemented as plugins. Source code can be found at plugins.

Display-Filters - the display filter engine at epan/dfilter



Ref2 for further edits - delete when done
	\section Introduction

	This document describes the data structures and the functions exported by the CACE Technologies AirPcap library.
	The AirPcap library provides low-level access to the AirPcap driver including advanced capabilities such as channel setting,
	link type control and WEP configuration.<br>
	This manual includes the following sections:

	\note throughout this documentation, \e device refers to a physical USB AirPcap device, while \e adapter is an open API
	instance. Most of the AirPcap API operations are adapter-specific but some of them, like setting the channel, are
	per-device and will be reflected on all the open adapters. These functions will have "Device" in their name, e.g.
	AirpcapSetDeviceChannel().

	\b Sections:

	- \ref airpcapfuncs
	- \ref airpcapdefs
	- \ref radiotap
*/
/*
 * Register all the plugin types that are part of libwireshark.
 *
 * Must be called before init_plugins(), which must be called before
 * any registration routines are called, i.e. before epan_init().
 *
 * Must be called only once in a program.
 */
WS_DLL_PUBLIC void epan_register_plugin_types(void);

/** init the whole epan module, this is used to be called only once in a program */
WS_DLL_PUBLIC
void epan_init(void (*register_all_protocols_func)(register_cb cb, gpointer client_data),
	       void (*register_all_handoffs_func)(register_cb cb, gpointer client_data),
	       register_cb cb, void *client_data);

/** cleanup the whole epan module, this is used to be called only once in a program */
WS_DLL_PUBLIC
void epan_cleanup(void);

/**
 * Initialize the table of conversations.  Conversations are identified by
 * their endpoints; they are used for protocols such as IP, TCP, and UDP,
 * where packets contain endpoint information but don't contain a single
 * value indicating to which flow the packet belongs.
 */
void epan_conversation_init(void);
void epan_conversation_cleanup(void);

/**
 * Initialize the table of circuits.  Circuits are identified by a
 * circuit ID; they are used for protocols where packets *do* contain
 * a circuit ID value indicating to which flow the packet belongs.
 *
 * We might want to make a superclass for both endpoint-specified
 * conversations and circuit ID-specified circuits, so we can attach
 * information either to a circuit or a conversation with common
 * code.
 */
void epan_circuit_init(void);
void epan_circuit_cleanup(void);

/** A client will create one epan_t for an entire dissection session.
 * A single epan_t will be used to analyze the entire sequence of packets,
 * sequentially, in a single session. A session corresponds to a single
 * packet trace file. The reaons epan_t exists is that some packets in
 * some protocols cannot be decoded without knowledge of previous packets.
 * This inter-packet "state" is stored in the epan_t.
 */
typedef struct epan_session epan_t;

WS_DLL_PUBLIC epan_t *epan_new(void);

const char *epan_get_user_comment(const epan_t *session, const frame_data *fd);

const char *epan_get_interface_name(const epan_t *session, guint32 interface_id);

const nstime_t *epan_get_frame_ts(const epan_t *session, guint32 frame_num);

WS_DLL_PUBLIC void epan_free(epan_t *session);

WS_DLL_PUBLIC const gchar*
epan_get_version(void);

/**
 * Set/unset the tree to always be visible when epan_dissect_init() is called.
 * This state change sticks until cleared, rather than being done per function call.
 * This is currently used when Lua scripts request all fields be generated.
 * By default it only becomes visible if epan_dissect_init() makes it so, usually
 * only when a packet is selected.
 * Setting this overrides that so it's always visible, although it will still not be
 * created if create_proto_tree is false in the call to epan_dissect_init().
 * Clearing this reverts the decision to epan_dissect_init() and proto_tree_visible.
 */
void epan_set_always_visible(gboolean force);

/** initialize an existing single packet dissection */
WS_DLL_PUBLIC
epan_dissect_t*
epan_dissect_init(epan_dissect_t *edt, epan_t *session, const gboolean create_proto_tree, const gboolean proto_tree_visible);

/** get a new single packet dissection
 * should be freed using epan_dissect_free() after packet dissection completed
 */
WS_DLL_PUBLIC
epan_dissect_t*
epan_dissect_new(epan_t *session, const gboolean create_proto_tree, const gboolean proto_tree_visible);

WS_DLL_PUBLIC
void
epan_dissect_reset(epan_dissect_t *edt);

/** Indicate whether we should fake protocols or not */
WS_DLL_PUBLIC
void
epan_dissect_fake_protocols(epan_dissect_t *edt, const gboolean fake_protocols);

/** run a single packet dissection */
WS_DLL_PUBLIC
void
epan_dissect_run(epan_dissect_t *edt, int file_type_subtype,
        struct wtap_pkthdr *phdr, tvbuff_t *tvb, frame_data *fd,
        struct epan_column_info *cinfo);

WS_DLL_PUBLIC
void
epan_dissect_run_with_taps(epan_dissect_t *edt, int file_type_subtype,
        struct wtap_pkthdr *phdr, tvbuff_t *tvb, frame_data *fd,
        struct epan_column_info *cinfo);

/** run a single file packet dissection */
WS_DLL_PUBLIC
void
epan_dissect_file_run(epan_dissect_t *edt, struct wtap_pkthdr *phdr,
        tvbuff_t *tvb, frame_data *fd, struct epan_column_info *cinfo);

WS_DLL_PUBLIC
void
epan_dissect_file_run_with_taps(epan_dissect_t *edt, struct wtap_pkthdr *phdr,
        tvbuff_t *tvb, frame_data *fd, struct epan_column_info *cinfo);

/** Prime a proto_tree using the fields/protocols used in a dfilter. */
WS_DLL_PUBLIC
void
epan_dissect_prime_dfilter(epan_dissect_t *edt, const struct epan_dfilter *dfcode);

/** fill the dissect run output into the packet list columns */
WS_DLL_PUBLIC
void
epan_dissect_fill_in_columns(epan_dissect_t *edt, const gboolean fill_col_exprs, const gboolean fill_fd_colums);

/** Check whether a dissected packet contains a given named field */
WS_DLL_PUBLIC
gboolean
epan_dissect_packet_contains_field(epan_dissect_t* edt,
                                   const char *field_name);

/** releases resources attached to the packet dissection. DOES NOT free the actual pointer */
WS_DLL_PUBLIC
void
epan_dissect_cleanup(epan_dissect_t* edt);

/** free a single packet dissection */
WS_DLL_PUBLIC
void
epan_dissect_free(epan_dissect_t* edt);

/** Sets custom column */
const gchar *
epan_custom_set(epan_dissect_t *edt, int id, gint occurrence,
				gchar *result, gchar *expr, const int size);

/**
 * Get compile-time information for libraries used by libwireshark.
 */
WS_DLL_PUBLIC
void
epan_get_compiled_version_info(GString *str);

/**
 * Get runtime information for libraries used by libwireshark.
 */
WS_DLL_PUBLIC
void
epan_get_runtime_version_info(GString *str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __EPAN_H__ */
