/** @file
 *
 * Wireshark Protocol Analyzer Library
 *
 * Copyright (c) 2001 by Gerald Combs <gerald@wireshark.org>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __EPAN_H__
#define __EPAN_H__

#include <wireshark.h>

#include <wsutil/feature_list.h>
#include <epan/tvbuff.h>
#include <epan/prefs.h>
#include <epan/frame_data.h>
#include <epan/register.h>
#include <wiretap/wtap_opttypes.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Global variable holding the content of the corresponding environment variable
 * to save fetching it repeatedly.
 */
extern bool wireshark_abort_on_dissector_bug;
extern bool wireshark_abort_on_too_many_items;

typedef struct epan_dissect epan_dissect_t;

struct epan_dfilter;
struct epan_column_info;

/**
 * Opaque structure provided when an epan_t is created; it contains
 * information needed to allow the user of libwireshark to provide
 * time stamps, comments, and other information outside the packet
 * data itself.
 */
struct packet_provider_data;

/**
 * Structure containing pointers to functions supplied by the user
 * of libwireshark.
 */
struct packet_provider_funcs {
	const nstime_t *(*get_frame_ts)(struct packet_provider_data *prov, uint32_t frame_num);
	const char *(*get_interface_name)(struct packet_provider_data *prov, uint32_t interface_id, unsigned section_number);
	const char *(*get_interface_description)(struct packet_provider_data *prov, uint32_t interface_id, unsigned section_number);
	wtap_block_t (*get_modified_block)(struct packet_provider_data *prov, const frame_data *fd);
};

/**
	@section Epan The Enhanced Packet ANalyzer

	XXX

	@b Sections:
*/
/*
Ref 1
Epan
Enhanced Packet ANalyzer, aka the packet analyzing engine. Source code can be found in the epan directory.

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

/**
 * Init the whole epan module.
 *
 * Must be called only once in a program.
 *
 * Returns true on success, false on failure.
 */
WS_DLL_PUBLIC
bool epan_init(register_cb cb, void *client_data, bool load_plugins);

/**
 * Load all settings, from the current profile, that affect epan.
 */
WS_DLL_PUBLIC
e_prefs *epan_load_settings(void);

/** cleanup the whole epan module, this is used to be called only once in a program */
WS_DLL_PUBLIC
void epan_cleanup(void);

typedef struct {
	void (*init)(void);		/* Called before proto_init() */
	void (*post_init)(void);	/* Called at the end of epan_init() */
	void (*dissect_init)(epan_dissect_t *);
	void (*dissect_cleanup)(epan_dissect_t *);
	void (*cleanup)(void);
	void (*register_all_protocols)(register_cb, void *);
	void (*register_all_handoffs)(register_cb, void *);
	void (*register_all_tap_listeners)(void);
} epan_plugin;

WS_DLL_PUBLIC void epan_register_plugin(const epan_plugin *plugin);

/** Returns_
 *     0 if plugins can be loaded for all of libwireshark (tap, dissector, epan).
 *     1 if plugins are not supported by the platform.
 *    -1 if plugins were disabled in the build configuration.
 */
WS_DLL_PUBLIC int epan_plugins_supported(void);

/**
 * Initialize the table of conversations.  Conversations are identified by
 * their endpoints; they are used for protocols such as IP, TCP, and UDP,
 * where packets contain endpoint information but don't contain a single
 * value indicating to which flow the packet belongs.
 */
void epan_conversation_init(void);

/** A client will create one epan_t for an entire dissection session.
 * A single epan_t will be used to analyze the entire sequence of packets,
 * sequentially, in a single session. A session corresponds to a single
 * packet trace file. The reasons epan_t exists is that some packets in
 * some protocols cannot be decoded without knowledge of previous packets.
 * This inter-packet "state" is stored in the epan_t.
 */
typedef struct epan_session epan_t;

WS_DLL_PUBLIC epan_t *epan_new(struct packet_provider_data *prov,
    const struct packet_provider_funcs *funcs);

WS_DLL_PUBLIC wtap_block_t epan_get_modified_block(const epan_t *session, const frame_data *fd);

WS_DLL_PUBLIC const char *epan_get_interface_name(const epan_t *session, uint32_t interface_id, unsigned section_number);

WS_DLL_PUBLIC const char *epan_get_interface_description(const epan_t *session, uint32_t interface_id, unsigned section_number);

const nstime_t *epan_get_frame_ts(const epan_t *session, uint32_t frame_num);

WS_DLL_PUBLIC void epan_free(epan_t *session);

WS_DLL_PUBLIC const char*
epan_get_version(void);

WS_DLL_PUBLIC void epan_get_version_number(int *major, int *minor, int *micro);

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
WS_DLL_PUBLIC
void epan_set_always_visible(bool force);

/** initialize an existing single packet dissection */
WS_DLL_PUBLIC
void
epan_dissect_init(epan_dissect_t *edt, epan_t *session, const bool create_proto_tree, const bool proto_tree_visible);

/** get a new single packet dissection
 * should be freed using epan_dissect_free() after packet dissection completed
 */
WS_DLL_PUBLIC
epan_dissect_t*
epan_dissect_new(epan_t *session, const bool create_proto_tree, const bool proto_tree_visible);

WS_DLL_PUBLIC
void
epan_dissect_reset(epan_dissect_t *edt);

/** Indicate whether we should fake protocols or not */
WS_DLL_PUBLIC
void
epan_dissect_fake_protocols(epan_dissect_t *edt, const bool fake_protocols);

/** run a single packet dissection */
WS_DLL_PUBLIC
void
epan_dissect_run(epan_dissect_t *edt, int file_type_subtype,
        wtap_rec *rec, tvbuff_t *tvb, frame_data *fd,
        struct epan_column_info *cinfo);

WS_DLL_PUBLIC
void
epan_dissect_run_with_taps(epan_dissect_t *edt, int file_type_subtype,
        wtap_rec *rec, tvbuff_t *tvb, frame_data *fd,
        struct epan_column_info *cinfo);

/** run a single file packet dissection */
WS_DLL_PUBLIC
void
epan_dissect_file_run(epan_dissect_t *edt, wtap_rec *rec,
        tvbuff_t *tvb, frame_data *fd, struct epan_column_info *cinfo);

WS_DLL_PUBLIC
void
epan_dissect_file_run_with_taps(epan_dissect_t *edt, wtap_rec *rec,
        tvbuff_t *tvb, frame_data *fd, struct epan_column_info *cinfo);

/** Prime an epan_dissect_t's proto_tree using the fields/protocols used in a dfilter. */
WS_DLL_PUBLIC
void
epan_dissect_prime_with_dfilter(epan_dissect_t *edt, const struct epan_dfilter *dfcode);

/** Prime an epan_dissect_t's proto_tree with a field/protocol specified by its hfid */
WS_DLL_PUBLIC
void
epan_dissect_prime_with_hfid(epan_dissect_t *edt, int hfid);

/** Prime an epan_dissect_t's proto_tree with a set of fields/protocols specified by their hfids in a GArray */
WS_DLL_PUBLIC
void
epan_dissect_prime_with_hfid_array(epan_dissect_t *edt, GArray *hfids);

/** fill the dissect run output into the packet list columns */
WS_DLL_PUBLIC
void
epan_dissect_fill_in_columns(epan_dissect_t *edt, const bool fill_col_exprs, const bool fill_fd_colums);

/** Check whether a dissected packet contains a given named field */
WS_DLL_PUBLIC
bool
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
const char *
epan_custom_set(epan_dissect_t *edt, GSList *ids, int occurrence,
				char *result, char *expr, const int size);

/**
 * Get compile-time information for libraries used by libwireshark.
 */
WS_DLL_PUBLIC
void
epan_gather_compile_info(feature_list l);

/**
 * Get runtime information for libraries used by libwireshark.
 */
WS_DLL_PUBLIC
void
epan_gather_runtime_info(feature_list l);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __EPAN_H__ */
