/* tap.h
 * packet tap interface   2002 Ronnie Sahlberg
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _TAP_H_
#define _TAP_H_

#include <epan/epan.h>

typedef void (*tap_reset_cb)(void *tapdata);
typedef gboolean (*tap_packet_cb)(void *tapdata, packet_info *pinfo, epan_dissect_t *edt, const void *data);
typedef void (*tap_draw_cb)(void *tapdata);

/*
 * Flags to indicate what a tap listener's packet routine requires.
 */
#define TL_REQUIRES_NOTHING	0x00000000	/**< nothing */
#define TL_REQUIRES_PROTO_TREE	0x00000001	/**< full protocol tree */
#define TL_REQUIRES_COLUMNS	0x00000002	/**< columns */
/* Flags to indicate what the tap listener does */
#define TL_IS_DISSECTOR_HELPER	0x00000004	/** tap helps a dissector do work
						 ** but does not, itself, require dissection */

extern void tap_init(void);
extern int register_tap(const char *name);
extern int find_tap_id(const char *name);
extern void tap_queue_packet(int tap_id, packet_info *pinfo, const void *tap_specific_data);
extern void tap_build_interesting(epan_dissect_t *edt);
extern void tap_queue_init(epan_dissect_t *edt);
extern void tap_push_tapped_queue(epan_dissect_t *edt);
extern void reset_tap_listeners(void);
extern void draw_tap_listeners(gboolean draw_all);
extern GString *register_tap_listener(const char *tapname, void *tapdata,
    const char *fstring, guint flags, tap_reset_cb tap_reset,
    tap_packet_cb tap_packet, tap_draw_cb tap_draw);
extern GString *set_tap_dfilter(void *tapdata, const char *fstring);
extern void remove_tap_listener(void *tapdata);
extern gboolean tap_listeners_require_dissection(void);
extern gboolean have_tap_listener(int tap_id);
extern gboolean have_filtering_tap_listeners(void);
extern guint union_of_tap_listener_flags(void);
extern const void *fetch_tapped_data(int tap_id, int idx);

#endif
