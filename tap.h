/* tap.h
 * packet tap interface   2002 Ronnie Sahlberg
 *
 * $Id: tap.h,v 1.7 2003/03/06 19:04:28 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include "epan/epan.h"

extern int num_tap_filters;

typedef void (*tap_reset_cb)(void *tapdata);
typedef int  (*tap_packet_cb)(void *tapdata, packet_info *pinfo, epan_dissect_t *edt, void *data);
typedef void (*tap_draw_cb)(void *tapdata);


extern void tap_init(void);
extern int register_tap(char *name);
extern int find_tap_id(char *name);
extern void tap_queue_packet(int tap_id, packet_info *pinfo, void *tap_specific_data);
extern void tap_queue_init(epan_dissect_t *edt);
extern void tap_push_tapped_queue(epan_dissect_t *edt);
extern void reset_tap_listeners(void);
extern void draw_tap_listeners(gboolean draw_all);
extern int register_tap_listener(char *tapname, void *tapdata, char *fstring, tap_reset_cb tap_reset, tap_packet_cb tap_packet, tap_draw_cb tap_draw);
extern void remove_tap_listener(void *tapdata);

#endif
