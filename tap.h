/* tap.h
 * packet tap interface   2002 Ronnie Sahlberg
 *
 * $Id: tap.h,v 1.2 2002/09/07 00:41:26 jmayer Exp $
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

#include "wiretap/wtap.h"

void tap_init(void);
int register_tap(char *name);
int find_tap_id(char *name);
void tap_queue_packet(int tap_id, packet_info *pinfo, void *tap_specific_data);
void tap_queue_init(union wtap_pseudo_header *pseudo_header, const u_char *buf, frame_data *fdata);
void tap_push_tapped_queue(void);
extern int tapping_is_active;
void reset_tap_listeners(void);
void draw_tap_listeners(gboolean draw_all);
int register_tap_listener(char *tapname, void *tapdata, char *fstring, void (*reset)(void *tapdata), int (*packet)(void *tapdata, packet_info *pinfo, void *data), void (*draw)(void *tapdata));
void remove_tap_listener(void *tapdata);



