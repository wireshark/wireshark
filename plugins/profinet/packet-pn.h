/* packet-pn.h
 * Common functions for other PROFINET protocols like DCP, MRP, ...
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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

#define FRAME_ID_DCP_HELLO      0xfefc
#define FRAME_ID_DCP_GETORSET   0xfefd
#define FRAME_ID_DCP_IDENT_REQ  0xfefe
#define FRAME_ID_DCP_IDENT_RES  0xfeff


extern void init_pn(int proto);

extern int dissect_pn_uint8(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                  proto_tree *tree, int hfindex, guint8 *pdata);

extern int dissect_pn_uint16(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, int hfindex, guint16 *pdata);

extern int dissect_pn_uint32(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, int hfindex, guint32 *pdata);

extern int dissect_pn_int16(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, int hfindex, gint16 *pdata);

extern int dissect_pn_int32(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, int hfindex, gint32 *pdata);

extern int dissect_pn_oid(tvbuff_t *tvb, int offset, packet_info *pinfo,
                    proto_tree *tree, int hfindex, guint32 *pdata);

extern int dissect_pn_mac(tvbuff_t *tvb, int offset, packet_info *pinfo,
                    proto_tree *tree, int hfindex, guint8 *pdata);

extern int dissect_pn_ipv4(tvbuff_t *tvb, int offset, packet_info *pinfo,
                    proto_tree *tree, int hfindex, guint32 *pdata);

extern int dissect_pn_uuid(tvbuff_t *tvb, int offset, packet_info *pinfo,
                    proto_tree *tree, int hfindex, e_uuid_t *uuid);

extern int dissect_pn_undecoded(tvbuff_t *tvb, int offset, packet_info *pinfo,
                    proto_tree *tree, guint32 length);

extern int dissect_pn_user_data(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
                    proto_tree *tree, guint32 length, const char *text);

#define SUBST_DATA  1
#define FRAG_DATA   2

extern int dissect_pn_user_data_bytes(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
                    proto_tree *tree, guint32 length, int iSelect);

extern int dissect_pn_malformed(tvbuff_t *tvb, int offset, packet_info *pinfo,
                    proto_tree *tree, guint32 length);

extern int dissect_pn_padding(tvbuff_t *tvb, int offset, packet_info *pinfo,
                    proto_tree *tree, int length);

extern int dissect_pn_align4(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

extern void pn_append_info(packet_info *pinfo, proto_item *dcp_item, const char *text);

extern gboolean dissect_CSF_SDU_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
