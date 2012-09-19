/* packet.h
 * Definitions for packet disassembly structures and routines
 *
 * $Id$
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef __PACKET_H__
#define __PACKET_H__

#include "wiretap/wtap.h"
#include "proto.h"
#include "tvbuff.h"
#include "pint.h"
#include "to_str.h"
#include "value_string.h"
#include "column_info.h"
#include "frame_data.h"
#include "packet_info.h"
#include "column-utils.h"
#include "epan.h"
#include "tfs.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define hi_nibble(b) (((b) & 0xf0) >> 4)
#define lo_nibble(b) ((b) & 0x0f)

/* Useful when you have an array whose size you can tell at compile-time */
#define array_length(x)	(sizeof x / sizeof x[0])

/* Check whether the "len" bytes of data starting at "offset" is
 * entirely inside the captured data for this packet. */
#define	BYTES_ARE_IN_FRAME(offset, captured_len, len) \
	((guint)(offset) + (guint)(len) > (guint)(offset) && \
	 (guint)(offset) + (guint)(len) <= (guint)(captured_len))

/* To pass one of two strings, singular or plural */
#define plurality(d,s,p) ((d) == 1 ? (s) : (p))

typedef struct _packet_counts {
  gint           sctp;
  gint           tcp;
  gint           udp;
  gint           icmp;
  gint           ospf;
  gint           gre;
  gint           netbios;
  gint           ipx;
  gint           vines;
  gint           other;
  gint           total;
  gint           arp;
  gint           i2c_event;
  gint           i2c_data;
} packet_counts;

/** Number of packet counts. */
#define PACKET_COUNTS_SIZE sizeof(packet_counts) / sizeof (gint)

/* Types of character encodings */
typedef enum {
	PACKET_CHAR_ENC_CHAR_ASCII	 = 0,	/* ASCII */
	PACKET_CHAR_ENC_CHAR_EBCDIC	 = 1	/* EBCDIC */
} packet_char_enc;

extern void packet_init(void);
extern void packet_cleanup(void);

/* Handle for dissectors you call directly or register with "dissector_add_uint()".
   This handle is opaque outside of "packet.c". */
struct dissector_handle;
typedef struct dissector_handle *dissector_handle_t;

/* Hash table for matching unsigned integers, or strings, and dissectors;
   this is opaque outside of "packet.c". */
struct dissector_table;
typedef struct dissector_table *dissector_table_t;

/*
 * Dissector that returns nothing.
 */
typedef void (*dissector_t)(tvbuff_t *, packet_info *, proto_tree *);

/*
 * Dissector that returns:
 *
 *	The amount of data in the protocol's PDU, if it was able to
 *	dissect all the data;
 *
 *	0, if the tvbuff doesn't contain a PDU for that protocol;
 *
 *	The negative of the amount of additional data needed, if
 *	we need more data (e.g., from subsequent TCP segments) to
 *	dissect the entire PDU.
 */
typedef int (*new_dissector_t)(tvbuff_t *, packet_info *, proto_tree *, void *);

/** Type of a heuristic dissector, used in heur_dissector_add().
 *
 * @param tvb the tv_buff with the (remaining) packet data
 * @param pinfo the packet info of this packet (additional info)
 * @param tree the protocol tree to be build or NULL
 * @return TRUE if the packet was recognized by the sub-dissector (stop dissection here)
 */
typedef gboolean (*heur_dissector_t)(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, void *);

typedef void (*DATFunc) (const gchar *table_name, ftenum_t selector_type,
    gpointer key, gpointer value, gpointer user_data);
typedef void (*DATFunc_handle) (const gchar *table_name, gpointer value,
    gpointer user_data);
typedef void (*DATFunc_table) (const gchar *table_name, const gchar *ui_name,
    gpointer user_data);

typedef void (*DATFunc_heur_table) (const gchar *table_name,gpointer table,
    gpointer user_data);

/* Opaque structure - provides type checking but no access to components */
typedef struct dtbl_entry dtbl_entry_t;

extern dissector_handle_t dtbl_entry_get_handle (dtbl_entry_t *dtbl_entry);
extern dissector_handle_t dtbl_entry_get_initial_handle (dtbl_entry_t * entry);
extern void dissector_table_foreach_changed (const char *name, DATFunc func,
    gpointer user_data);
extern void dissector_table_foreach (const char *name, DATFunc func,
    gpointer user_data);
extern void dissector_all_tables_foreach_changed (DATFunc func,
    gpointer user_data);
extern void dissector_table_foreach_handle(const char *name, DATFunc_handle func,
    gpointer user_data);
extern void dissector_all_tables_foreach_table (DATFunc_table func,
    gpointer user_data, GCompareFunc compare_key_func);

/* a protocol uses the function to register a sub-dissector table */
extern dissector_table_t register_dissector_table(const char *name,
    const char *ui_name, const ftenum_t type, const int base);

/* Find a dissector table by table name. */
extern dissector_table_t find_dissector_table(const char *name);

/* Get the UI name for a sub-dissector table, given its internal name */
extern const char *get_dissector_table_ui_name(const char *name);

/* Get the field type for values of the selector for a dissector table,
   given the table's internal name */
extern ftenum_t get_dissector_table_selector_type(const char *name);

/* Get the base to use when displaying values of the selector for a
   sub-dissector table, given the table's internal name */
extern int get_dissector_table_base(const char *name);

/* Add an entry to a uint dissector table. */
extern void dissector_add_uint(const char *abbrev, const guint32 pattern,
    dissector_handle_t handle);

/* Delete the entry for a dissector in a uint dissector table
   with a particular pattern. */
extern void dissector_delete_uint(const char *name, const guint32 pattern,
    dissector_handle_t handle);

/* Change the entry for a dissector in a uint dissector table
   with a particular pattern to use a new dissector handle. */
extern void dissector_change_uint(const char *abbrev, const guint32 pattern,
    dissector_handle_t handle);

/* Reset an entry in a uint dissector table to its initial value. */
extern void dissector_reset_uint(const char *name, const guint32 pattern);

/* Look for a given value in a given uint dissector table and, if found,
   call the dissector with the arguments supplied, and return TRUE,
   otherwise return FALSE. */
extern gboolean dissector_try_uint(dissector_table_t sub_dissectors,
    const guint32 uint_val, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Look for a given value in a given uint dissector table and, if found,
   call the dissector with the arguments supplied, and return TRUE,
   otherwise return FALSE. */
extern gboolean dissector_try_uint_new(dissector_table_t sub_dissectors,
	const guint32 uint_val, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const gboolean add_proto_name, void *data);

/* Look for a given value in a given uint dissector table and, if found,
   return the dissector handle for that value. */
extern dissector_handle_t dissector_get_uint_handle(
    dissector_table_t const sub_dissectors, const guint32 uint_val);

/* Add an entry to a string dissector table. */
extern void dissector_add_string(const char *name, const gchar *pattern,
    dissector_handle_t handle);

/* Delete the entry for a dissector in a string dissector table
   with a particular pattern. */
extern void dissector_delete_string(const char *name, const gchar *pattern,
	dissector_handle_t handle);

/* Change the entry for a dissector in a string dissector table
   with a particular pattern to use a new dissector handle. */
extern void dissector_change_string(const char *name, const gchar *pattern,
    dissector_handle_t handle);

/* Reset an entry in a string sub-dissector table to its initial value. */
extern void dissector_reset_string(const char *name, const gchar *pattern);

/* Look for a given string in a given dissector table and, if found, call
   the dissector with the arguments supplied, and return TRUE, otherwise
   return FALSE. */
extern gboolean dissector_try_string(dissector_table_t sub_dissectors,
    const gchar *string, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Look for a given value in a given string dissector table and, if found,
   return the dissector handle for that value. */
extern dissector_handle_t dissector_get_string_handle(
    dissector_table_t sub_dissectors, const gchar *string);

/* Add a handle to the list of handles that *could* be used with this
   table.  That list is used by code in the UI. */
extern void dissector_add_handle(const char *name, dissector_handle_t handle);

/* List of "heuristic" dissectors (which get handed a packet, look at it,
   and either recognize it as being for their protocol, dissect it, and
   return TRUE, or don't recognize it and return FALSE) to be called
   by another dissector. */
typedef GSList *heur_dissector_list_t;


typedef struct {
	heur_dissector_t dissector;
	protocol_t *protocol;
	gboolean enabled;
} heur_dtbl_entry_t;

/** A protocol uses this function to register a heuristic sub-dissector list.
 *  Call this in the parent dissectors proto_register function.
 *
 * @param name the name of this protocol
 * @param list the list of heuristic sub-dissectors to be registered
 */
extern void register_heur_dissector_list(const char *name,
    heur_dissector_list_t *list);

extern void dissector_all_heur_tables_foreach_table (DATFunc_heur_table func,
    gpointer user_data);

/** Try all the dissectors in a given heuristic dissector list. This is done,
 *  until we find one that recognizes the protocol.
 *  Call this while the parent dissector running.
 *
 * @param sub_dissectors the sub-dissector list
 * @param tvb the tv_buff with the (remaining) packet data
 * @param pinfo the packet info of this packet (additional info)
 * @param tree the protocol tree to be build or NULL
 * @param data parameter to pass to subdissector
 * @return TRUE if the packet was recognized by the sub-dissector (stop dissection here)
 */
extern gboolean dissector_try_heuristic(heur_dissector_list_t sub_dissectors,
    tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

/** Add a sub-dissector to a heuristic dissector list.
 *  Call this in the proto_handoff function of the sub-dissector.
 *
 * @param name the name of the "parent" protocol, e.g. "tcp"
 * @param dissector the sub-dissector to be registered
 * @param proto the protocol id of the sub-dissector
 */
extern void heur_dissector_add(const char *name, heur_dissector_t dissector,
    const int proto);

/** Remove a sub-dissector from a heuristic dissector list.
 *  Call this in the prefs_reinit function of the sub-dissector.
 *
 * @param name the name of the "parent" protocol, e.g. "tcp"
 * @param dissector the sub-dissector to be unregistered
 * @param proto the protocol id of the sub-dissector
 */
extern void heur_dissector_delete(const char *name, heur_dissector_t dissector, const int proto);

/** Enable/Disable a sub-dissector in a heuristic dissector list
 *  Call this in the prefs_reinit function of the sub-dissector.
 *
 * @param name the name of the "parent" protocol, e.g. "tcp"
 * @param dissector the sub-dissector to be disabled/enabled
 * @param proto the protocol id of the sub-dissector
 * @param TRUE/FALSE to enable/disable the sub-dissector
 */
extern void heur_dissector_set_enabled(const char *name, heur_dissector_t dissector, const int proto, const gboolean enabled);

/* Register a dissector. */
extern void register_dissector(const char *name, dissector_t dissector,
    const int proto);
extern void new_register_dissector(const char *name, new_dissector_t dissector,
    const int proto);

/* Get the long name of the protocol for a dissector handle. */
extern const char *dissector_handle_get_long_name(const dissector_handle_t handle);

/* Get the short name of the protocol for a dissector handle. */
extern const char *dissector_handle_get_short_name(const dissector_handle_t handle);

/* Get the index of the protocol for a dissector handle. */
extern int dissector_handle_get_protocol_index(const dissector_handle_t handle);

/* Find a dissector by name. */
extern dissector_handle_t find_dissector(const char *name);

/* Create an anonymous handle for a dissector. */
extern dissector_handle_t create_dissector_handle(dissector_t dissector,
    const int proto);
extern dissector_handle_t new_create_dissector_handle(new_dissector_t dissector,
    const int proto);

/* Call a dissector through a handle and if no dissector was found
 * pass it over to the "data" dissector instead.
 *
 *   @param handle The dissector to call.
 *   @param  tvb The buffer to dissect.
 *   @param  pinfo Packet Info.
 *   @param  tree The protocol tree.
 *   @param  data parameter to pass to dissector
 *   @return  If the protocol for that handle isn't enabled call the data
 *   dissector. Otherwise, if the handle refers to a new-style
 *   dissector, call the dissector and return its return value, otherwise call
 *   it and return the length of the tvbuff pointed to by the argument.
 */
extern int call_dissector_with_data(dissector_handle_t handle, tvbuff_t *tvb,
    packet_info *pinfo, proto_tree *tree, void *data);
extern int call_dissector(dissector_handle_t handle, tvbuff_t *tvb,
    packet_info *pinfo, proto_tree *tree);

/* Call a dissector through a handle but if no dissector was found
 * just return 0 and do not call the "data" dissector instead.
 *
 *   @param handle The dissector to call.
 *   @param  tvb The buffer to dissect.
 *   @param  pinfo Packet Info.
 *   @param  tree The protocol tree.
 *   @param  data parameter to pass to dissector
 *   @return  If the protocol for that handle isn't enabled, return 0 without
 *   calling the dissector. Otherwise, if the handle refers to a new-style
 *   dissector, call the dissector and return its return value, otherwise call
 *   it and return the length of the tvbuff pointed to by the argument.
 */
extern int call_dissector_only(dissector_handle_t handle, tvbuff_t *tvb,
    packet_info *pinfo, proto_tree *tree, void *data);

/* Do all one-time initialization. */
extern void dissect_init(void);

extern void dissect_cleanup(void);

/*
 * Given a tvbuff, and a length from a packet header, adjust the length
 * of the tvbuff to reflect the specified length.
 */
extern void set_actual_length(tvbuff_t *tvb, const guint specified_len);

/* Allow protocols to register "init" routines, which are called before
   we make a pass through a capture file and dissect all its packets
   (e.g., when we read in a new capture file, or run a "filter packets"
   or "colorize packets" pass over the current capture file). */
extern void register_init_routine(void (*func)(void));

/* Initialize all data structures used for dissection. */
extern void init_dissection(void);

/* Free data structures allocated for dissection. */
extern void cleanup_dissection(void);

/* Allow protocols to register a "cleanup" routine to be
 * run after the initial sequential run through the packets.
 * Note that the file can still be open after this; this is not
 * the final cleanup. */
extern void register_postseq_cleanup_routine(void (*func)(void));

/* Call all the registered "postseq_cleanup" routines. */
extern void postseq_cleanup_all_protocols(void);

/* Allow dissectors to register a "final_registration" routine
 * that is run like the proto_register_XXX() routine, but the end
 * end of the epan_init() function; that is, *after* all other
 * subsystems, liked dfilters, have finished initializing. This is
 * useful for dissector registration routines which need to compile
 * display filters. dfilters can't initialize itself until all protocols
 * have registereed themselvs. */
extern void
register_final_registration_routine(void (*func)(void));

/* Call all the registered "final_registration" routines. */
extern void
final_registration_all_protocols(void);

/*
 * Add a new data source to the list of data sources for a frame, given
 * the tvbuff for the data source and its name.
 */
extern void add_new_data_source(packet_info *pinfo, tvbuff_t *tvb,
    const char *name);

/*
 * Return the data source name.
 */
extern const char* get_data_source_name(data_source *src);

/*
 * Free up a frame's list of data sources.
 */
extern void free_data_sources(packet_info *pinfo);

/* Mark another frame as depended upon by the current frame.
 *
 * This information is used to ensure that the dependend-upon frame is saved
 * if the user does a File->Save-As of only the Displayed packets and the
 * current frame passed the display filter.
 */
extern void mark_frame_as_depended_upon(packet_info *pinfo, guint32 frame_num);

/*
 * Dissectors should never modify the packet data.
 */
extern void dissect_packet(epan_dissect_t *edt,
    union wtap_pseudo_header *pseudo_header, const guchar *pd,
    frame_data *fd, column_info *cinfo);

/* These functions are in packet-ethertype.c */
extern void capture_ethertype(guint16 etype, const guchar *pd, int offset,
		int len, packet_counts *ld);
extern void ethertype(guint16 etype, tvbuff_t *tvb, int offset_after_ethertype,
		packet_info *pinfo, proto_tree *tree, proto_tree *fh_tree,
		int etype_id, int trailer_id, int fcs_len);

/*
 * Dump layer/selector/dissector records in a fashion similar to the
 * proto_registrar_dump_* routines.
 */
extern void dissector_dump_decodes(void);

/*
 * For each heuristic dissector table, dump list of dissectors (filter_names) for that table
 */
extern void dissector_dump_heur_decodes(void);

/*
 * post dissectors are to be called by packet-frame.c after every other
 * dissector has been called.
 */
extern void register_postdissector(dissector_handle_t);
extern gboolean have_postdissector(void);
extern void call_all_postdissectors(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* packet.h */
