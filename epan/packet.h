/* packet.h
 * Definitions for packet disassembly structures and routines
 *
 * $Id: packet.h,v 1.33 2001/05/30 06:41:07 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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

#define hi_nibble(b) (((b) & 0xf0) >> 4)
#define lo_nibble(b) ((b) & 0x0f)

/* Useful when you have an array whose size you can tell at compile-time */
#define array_length(x)	(sizeof x / sizeof x[0])

/* Useful when highlighting regions inside a dissect_*() function. With this
 * macro, you can highlight from an arbitrary offset to the end of the
 * packet (which may come before the end of the frame).
 * See old_dissect_data() for an example.
 */
#define END_OF_FRAME	(pi.captured_len - offset)

/* Check whether the "len" bytes of data starting at "offset" is
 * entirely inside the captured data for this packet. */
#define	BYTES_ARE_IN_FRAME(offset, len)	((offset) + (len) <= pi.captured_len)

/* Check whether there's any data at all starting at "offset". */
#define	IS_DATA_IN_FRAME(offset)	((offset) < pi.captured_len)
		
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
} packet_counts;

/* Types of character encodings */
typedef enum {
	CHAR_ASCII	 = 0,	/* ASCII */
	CHAR_EBCDIC	 = 1	/* EBCDIC */
} char_enc;

/* Struct for boolean enumerations */
typedef struct true_false_string {
	char	*true_string;
	char	*false_string;
} true_false_string;

void packet_init(void);
void packet_cleanup(void);

/* Hash table for matching port numbers and dissectors */
typedef GHashTable* dissector_table_t;

/* types for sub-dissector lookup */
typedef void (*old_dissector_t)(const u_char *, int, frame_data *, proto_tree *);
typedef void (*dissector_t)(tvbuff_t *, packet_info *, proto_tree *);

typedef void (*DATFunc) (gchar *table_name, gpointer key, gpointer value, gpointer user_data);

/* Opaque structure - provides type checking but no access to components */
typedef struct dtbl_entry dtbl_entry_t;

gboolean dissector_get_old_flag (dtbl_entry_t *entry);
gint dissector_get_proto (dtbl_entry_t * entry);
gint dissector_get_initial_proto (dtbl_entry_t * entry);
void dissector_table_foreach_changed (char *name, DATFunc func, gpointer user_data);
void dissector_table_foreach (char *name, DATFunc func, gpointer user_data);
void dissector_all_tables_foreach_changed (DATFunc func, gpointer user_data);

/* a protocol uses the function to register a sub-dissector table */
dissector_table_t register_dissector_table(const char *name);

/* Add a sub-dissector to a dissector table.  Called by the protocol routine */
/* that wants to register a sub-dissector.  */
void old_dissector_add(const char *abbrev, guint32 pattern,
    old_dissector_t dissector, int proto);
void dissector_add(const char *abbrev, guint32 pattern,
    dissector_t dissector, int proto);

/* Add a sub-dissector to a dissector table.  Called by the protocol routine */
/* that wants to de-register a sub-dissector.  */
void old_dissector_delete(const char *name, guint32 pattern, old_dissector_t dissector);
void dissector_delete(const char *name, guint32 pattern, dissector_t dissector);

/* Reset a dissector in a sub-dissector table to its initial value. */
void dissector_change(const char *abbrev, guint32 pattern,
    dissector_t dissector, gboolean old, int proto);
void dissector_reset(const char *name, guint32 pattern);

/* Look for a given port in a given dissector table and, if found, call
   the dissector with the arguments supplied, and return TRUE, otherwise
   return FALSE. */
gboolean dissector_try_port(dissector_table_t sub_dissectors, guint32 port,
    tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* List of "heuristic" dissectors (which get handed a packet, look at it,
   and either recognize it as being for their protocol, dissect it, and
   return TRUE, or don't recognize it and return FALSE) to be called
   by another dissector. */
typedef GSList *heur_dissector_list_t;

/* Type of a heuristic dissector */
typedef gboolean (*heur_dissector_t)(tvbuff_t *, packet_info *,
	proto_tree *);

/* A protocol uses this function to register a heuristic dissector list */
void register_heur_dissector_list(const char *name, heur_dissector_list_t *list);

/* Add a sub-dissector to a heuristic dissector list.  Called by the
   protocol routine that wants to register a sub-dissector.  */
void heur_dissector_add(const char *name, heur_dissector_t dissector,
    int proto);

/* Try all the dissectors in a given heuristic dissector list until
   we find one that recognizes the protocol, in which case we return
   TRUE, or we run out of dissectors, in which case we return FALSE. */
gboolean dissector_try_heuristic(heur_dissector_list_t sub_dissectors,
    tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* List of "conversation" dissectors (they're not heuristic, but are
   assigned to a conversation if some other dissector sees some traffic
   saying "traffic between these hosts on these ports will be of type
   XXX", e.g. RTSP traffic doing so).

   These lists are for use by the UI, which, for a given conversation,
   would offer a list of dissectors that could be used with it; this
   would include dissectors on the conversation dissector list for
   the transport-layer protocol for the conversation, as well as
   dissectors for any port-based lists for that protocol (as a conversation
   between two ports, both of which have dissectors associated with them,
   might have been given to the wrong one of those dissectors). */
typedef GSList *conv_dissector_list_t;

/* A protocol uses this function to register a conversation dissector list */
void register_conv_dissector_list(const char *name, conv_dissector_list_t *list);

/* Add a sub-dissector to a conversation dissector list.  Called by the
   protocol routine that wants to register a sub-dissector.  */
void conv_dissector_add(const char *name, dissector_t dissector,
    int proto);

/* Opaque structure - provides type checking but no access to components */
typedef struct conv_dtbl_entry conv_dtbl_entry_t;

gint conv_dissector_get_proto (conv_dtbl_entry_t * entry);
void dissector_conv_foreach(char *name, DATFunc func, gpointer user_data);
void dissector_all_conv_foreach(DATFunc func, gpointer user_data);

/* Handle for dissectors you call directly.
   This handle is opaque outside of "packet.c". */
struct dissector_handle;
typedef struct dissector_handle *dissector_handle_t;

/* Register a dissector. */
void register_dissector(const char *name, dissector_t dissector, int proto);

/* Find a dissector by name. */
dissector_handle_t find_dissector(const char *name);

/* Call a dissector through a handle. */
void call_dissector(dissector_handle_t handle, tvbuff_t *tvb,
    packet_info *pinfo, proto_tree *tree);

/* Do all one-time initialization. */
void dissect_init(void);

void dissect_cleanup(void);

/* Allow protocols to register "init" routines, which are called before
   we make a pass through a capture file and dissect all its packets
   (e.g., when we read in a new capture file, or run a "filter packets"
   or "colorize packets" pass over the current capture file). */
void register_init_routine(void (*func)(void));

/* Call all the registered "init" routines. */
void init_all_protocols(void);

/*
 * Dissectors should never modify the packet data.
 */
void dissect_packet(tvbuff_t **p_tvb, union wtap_pseudo_header *pseudo_header,
		const u_char *pd, frame_data *fd, proto_tree *tree);
void old_dissect_data(const u_char *, int, frame_data *, proto_tree *);
void dissect_data(tvbuff_t *tvb, int, packet_info *pinfo, proto_tree *tree);


/* These functions are in packet-ethertype.c */
void capture_ethertype(guint16 etype, int offset,
		const u_char *pd, packet_counts *ld);
void ethertype(guint16 etype, tvbuff_t *tvb, int offset_after_ethertype,
		packet_info *pinfo, proto_tree *tree, proto_tree *fh_tree,
		int etype_id, int trailer_id);

#endif /* packet.h */
