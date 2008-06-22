/* packet-bat.h
 * Routines for B.A.T.M.A.N. Layer 3 dissection
 * Copyright 2008, Sven Eckelmann <sven.eckelmann@gmx.de>
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

#ifndef _PACKET_BAT_H
#define _PACKET_BAT_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/tap.h>

#include "packet-bat-packet.h"

/* forward reference */
void register_bat_batman();
void register_bat_gw();
void register_bat_vis();

void reg_handoff_bat_batman();
void reg_handoff_bat_gw();
void reg_handoff_bat_vis();


extern int proto_bat_plugin;
extern module_t *bat_module;
extern int bat_tap;
extern int bat_follow_tap;

#endif /* _PACKET_BAT_H */
