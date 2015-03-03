/* packet-aim.h
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __PACKET_AIM_H__
#define __PACKET_AIM_H__

typedef struct _aim_tlv {
  guint16 valueid;
  const char *desc;
  int (*dissector) (proto_item *ti, guint16 value_id, tvbuff_t *tvb, packet_info *);
} aim_tlv;

typedef struct _aim_subtype {
	guint16 id;
	const char *name;
	int (*dissector) (tvbuff_t *, packet_info *, proto_tree *);
} aim_subtype;

typedef struct _aim_family {
	int ett;
	int proto_id;
	protocol_t *proto;
	guint16 family;
	const char *name;
	const aim_subtype *subtypes;
} aim_family;

void aim_init_family(int proto, int ett, guint16 family, const aim_subtype *subtypes);

int dissect_aim_buddyname(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree);
void aim_get_message( guchar *msg, tvbuff_t *tvb, int msg_offset, int msg_length);
int aim_get_buddyname( guint8 **name, tvbuff_t *tvb, int offset);
int dissect_aim_userinfo(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree);

int dissect_aim_snac_error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *aim_tree);

int dissect_aim_ssi_result(tvbuff_t *tvb, packet_info *pinfo, proto_tree *aim_tree);

int dissect_aim_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree, const aim_tlv *);
int dissect_aim_tlv_list(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree, const aim_tlv *);
int dissect_aim_tlv_sequence(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree, const aim_tlv *);

const aim_family *aim_get_family( guint16 family );
const aim_subtype *aim_get_subtype( guint16 family, guint16 subtype);

int dissect_aim_tlv_value_string(proto_item *ti, guint16, tvbuff_t *, packet_info *);
int dissect_aim_tlv_value_string08_array(proto_item *ti, guint16, tvbuff_t *, packet_info *);
int dissect_aim_tlv_value_uint8(proto_item *ti, guint16, tvbuff_t *, packet_info *);
int dissect_aim_tlv_value_uint16(proto_item *ti, guint16, tvbuff_t *, packet_info *);
int dissect_aim_tlv_value_uint32(proto_item *ti, guint16, tvbuff_t *, packet_info *);
int dissect_aim_tlv_value_bytes(proto_item *ti, guint16, tvbuff_t *, packet_info *);
int dissect_aim_tlv_value_ipv4(proto_item *ti, guint16, tvbuff_t *, packet_info *);
int dissect_aim_tlv_value_time(proto_item *ti, guint16, tvbuff_t *, packet_info *);
int dissect_aim_tlv_value_client_capabilities(proto_item *ti, guint16, tvbuff_t *, packet_info *);
int dissect_aim_capability(proto_tree *entry, tvbuff_t *tvb, int offset);
int dissect_aim_userclass(tvbuff_t *tvb, int offset, int len, proto_item *ti, guint32 flags);
int dissect_aim_tlv_value_userclass(proto_item *ti, guint16, tvbuff_t *, packet_info *);
int dissect_aim_tlv_value_messageblock (proto_item *ti, guint16 valueid _U_, tvbuff_t *tvb, packet_info *);

extern const aim_tlv aim_client_tlvs[];
extern const aim_tlv aim_onlinebuddy_tlvs[];
extern const aim_tlv aim_motd_tlvs[];

#endif
