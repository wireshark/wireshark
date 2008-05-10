/* packet-sercosiii.h
 * Routines for SERCOS III dissection
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

#ifndef _packet_sercosiii_h
#define _packet_sercosiii_h

#define MAX_SERCOS_DEVICES (512)

#define COMMUNICATION_PHASE_0 (0x0)
#define COMMUNICATION_PHASE_1 (0x1)
#define COMMUNICATION_PHASE_2 (0x2)
#define COMMUNICATION_PHASE_3 (0x3)
#define COMMUNICATION_PHASE_4 (0x4)

void dissect_siii_mdt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
void dissect_siii_at(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

void dissect_siii_mst(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

void dissect_siii_mdt_init(gint proto_siii);
void dissect_siii_at_init(gint proto_siii);
void dissect_siii_mdt_devctrl_init(gint proto_siii);
void dissect_siii_at_devstat_init(gint proto_siii);
void dissect_siii_svc_init(gint proto_siii);
void dissect_siii_mst_init(gint proto_siii);
void dissect_siii_hp_init(gint proto_siii);

void dissect_siii_mdt_devctrl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
void dissect_siii_at_devstat(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

void dissect_siii_mdt_hp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
void dissect_siii_at_hp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

void dissect_siii_mdt_svc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint devno);
void dissect_siii_at_svc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint devno);

#endif
