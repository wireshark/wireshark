/* packet-h245.h
 * Routines for H.245 packet dissection
 * 2003  Ronnie Sahlberg
 *
 * $Id: packet-h245.h,v 1.3 2003/07/19 10:25:45 sahlberg Exp $
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

extern void dissect_h245_MultimediaSystemControlMessage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

extern int dissect_h245_OpenLogicalChannel(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

extern int dissect_h245_h221NonStandard(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

extern int dissect_h245_NonStandardParameter(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

extern int dissect_h245_T38FaxProfile(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

extern int dissect_h245_DataProtocolCapability(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
