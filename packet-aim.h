/* packet-tcp.h
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
 *
 * $Id: packet-aim.h,v 1.3 2004/04/26 18:21:10 obiot Exp $
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

#ifndef __PACKET_AIM_H__
#define __PACKET_AIM_H__

#define MAX_BUDDYNAME_LENGTH 30

typedef struct _aim_tlv {
  guint16 valueid;
  char *desc;
  int (*dissector) (proto_item *ti, guint16 value_id, tvbuff_t *tvb);
} aim_tlv;

struct aiminfo {
  guint16 family;
  guint16 subtype;
  struct tcpinfo *tcpinfo;
};

void aim_init_family(guint16 family, const char *name, const value_string *subtypes);

int dissect_aim_buddyname(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree);
void aim_get_message( guchar *msg, tvbuff_t *tvb, int msg_offset, int msg_length);
int aim_get_buddyname( char *name, tvbuff_t *tvb, int len_offset, int name_offset);
int dissect_aim_userinfo(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree);

int dissect_aim_snac_error(tvbuff_t *tvb, packet_info *pinfo,
                 int offset, proto_tree *aim_tree);

int dissect_aim_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree, const aim_tlv *);
int dissect_aim_tlv_list(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree, const aim_tlv *);

const char *aim_get_familyname( guint16 family );
const char *aim_get_subtypename( guint16 family, guint16 subtype);

int dissect_aim_tlv_value_string(proto_item *ti, guint16, tvbuff_t *);
int dissect_aim_tlv_value_uint8(proto_item *ti, guint16, tvbuff_t *);
int dissect_aim_tlv_value_uint16(proto_item *ti, guint16, tvbuff_t *);
int dissect_aim_tlv_value_uint32(proto_item *ti, guint16, tvbuff_t *);
int dissect_aim_tlv_value_bytes(proto_item *ti, guint16, tvbuff_t *);
int dissect_aim_tlv_value_ipv4(proto_item *ti, guint16, tvbuff_t *);
int dissect_aim_tlv_value_time(proto_item *ti, guint16, tvbuff_t *);
int dissect_aim_tlv_value_client_capabilities(proto_item *ti, guint16, tvbuff_t *);
int dissect_aim_tlv_value_userclass(proto_item *ti, guint16, tvbuff_t *);

extern const aim_tlv client_tlvs[];
extern const aim_tlv onlinebuddy_tlvs[];
extern const aim_tlv motd_tlvs[];

#endif
