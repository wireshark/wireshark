/* packet-vrrp.c
 * Routines for the Virtual Router Redundancy Protocol (VRRP)
 * RFC2338
 *
 * Heikki Vatiainen <hessu@cs.tut.fi>
 *
 * $Id: packet-vrrp.c,v 1.13 2001/01/09 06:31:44 guy Exp $
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>
#include "packet.h"
#include "packet-ip.h"
#include "in_cksum.h"

static gint proto_vrrp = -1;
static gint ett_vrrp = -1;
static gint ett_vrrp_ver_type = -1;

static gint hf_vrrp_ver_type = -1;
static gint hf_vrrp_version = -1;
static gint hf_vrrp_type = -1;

#define VRRP_VERSION_MASK 0xf0
#define VRRP_TYPE_MASK 0x0f
#define VRRP_AUTH_DATA_LEN 8

#define VRRP_TYPE_ADVERTISEMENT 1
static const value_string vrrp_type_vals[] = {
        {VRRP_TYPE_ADVERTISEMENT, "Advertisement"},
	{0, NULL}
};

#define VRRP_AUTH_TYPE_NONE 0
#define VRRP_AUTH_TYPE_SIMPLE_TEXT 1
#define VRRP_AUTH_TYPE_IP_AUTH_HDR 2
static const value_string vrrp_auth_vals[] = {
        {VRRP_AUTH_TYPE_NONE,        "No Authentication"},
        {VRRP_AUTH_TYPE_SIMPLE_TEXT, "Simple Text Authentication"},
        {VRRP_AUTH_TYPE_IP_AUTH_HDR, "IP Authentication Header"},
	{0,                          NULL}
};

#define VRRP_PRIORITY_MASTER_STOPPING 0
/* Values between 1 and 254 inclusive are for backup VRRP routers */
#define VRRP_PRIORITY_DEFAULT 100
#define VRRP_PRIORITY_OWNER 255
static const value_string vrrp_prio_vals[] = {
        {VRRP_PRIORITY_MASTER_STOPPING,  "Current Master has stopped participating in VRRP"},
        {VRRP_PRIORITY_DEFAULT,          "Default priority for a backup VRRP router"},
        {VRRP_PRIORITY_OWNER,            "This VRRP router owns the virtual router's IP address(es)"},
	{0,                              NULL }
};


static void
dissect_vrrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        int offset = 0;
        gint vrrp_len;
        guint8  ver_type;
	vec_t cksum_vec[1];

        CHECK_DISPLAY_AS_DATA(proto_vrrp, tvb, pinfo, tree);

        pinfo->current_proto = "VRRP";

        if (check_col(pinfo->fd, COL_PROTOCOL))
                col_set_str(pinfo->fd, COL_PROTOCOL, "VRRP");
        if (check_col(pinfo->fd, COL_INFO))
                col_clear(pinfo->fd, COL_INFO);
        
	ver_type = tvb_get_guint8(tvb, 0);
        if (check_col(pinfo->fd, COL_INFO)) {
                col_add_fstr(pinfo->fd, COL_INFO, "%s (v%u)",
                             "Announcement", hi_nibble(ver_type));
        }

        if (tree) {
                proto_item *ti, *tv;
                proto_tree *vrrp_tree, *ver_type_tree;
                guint8 priority, ip_count, auth_type, adver_int;
                guint16 cksum, computed_cksum;
                guint8 auth_buf[VRRP_AUTH_DATA_LEN+1];

                ti = proto_tree_add_item(tree, proto_vrrp, tvb, 0,
                                         tvb_length(tvb), FALSE);
                vrrp_tree = proto_item_add_subtree(ti, ett_vrrp);

                tv = proto_tree_add_uint_format(vrrp_tree, hf_vrrp_ver_type,
                                                tvb, offset, 1, ver_type,
                                                "Version %u, Packet type %u (%s)",
                                                hi_nibble(ver_type), lo_nibble(ver_type),
                                                val_to_str(lo_nibble(ver_type), vrrp_type_vals, "Unknown"));
                ver_type_tree = proto_item_add_subtree(tv, ett_vrrp_ver_type);
                proto_tree_add_uint(ver_type_tree, hf_vrrp_version, tvb,
                                    offset, 1, ver_type);
                proto_tree_add_uint(ver_type_tree, hf_vrrp_type, tvb, offset, 1,
                                    ver_type);
                offset++;
                
                proto_tree_add_text(vrrp_tree, tvb, offset, 1,
                                    "Virtual Router ID: %u",
                                    tvb_get_guint8(tvb, offset));
                offset++;

                priority = tvb_get_guint8(tvb, offset);
                proto_tree_add_text(vrrp_tree, tvb, offset, 1, "Priority: %u (%s)",
                                    priority,
                                    val_to_str(priority, vrrp_prio_vals, "Non-default backup priority"));
                offset++;

                ip_count = tvb_get_guint8(tvb, offset);
                proto_tree_add_text(vrrp_tree, tvb, offset, 1,
                                    "Count IP Addrs: %u", ip_count);
                offset++;

                auth_type = tvb_get_guint8(tvb, offset);
                proto_tree_add_text(vrrp_tree, tvb, offset, 1,
                                    "Authentication Type: %u (%s)", auth_type,
                                    val_to_str(auth_type, vrrp_auth_vals, "Unknown"));
                offset++;

                adver_int = tvb_get_guint8(tvb, offset);
                proto_tree_add_text(vrrp_tree, tvb, offset, 1,
                                    "Advertisement Interval: %u second%s",
                                    adver_int, plurality(adver_int, "", "s"));
                offset++;

                cksum = tvb_get_ntohs(tvb, offset);
                vrrp_len = tvb_reported_length(tvb);
                if (!pinfo->fragmented && tvb_length(tvb) >= vrrp_len) {
                        /* The packet isn't part of a fragmented datagram
                           and isn't truncated, so we can checksum it. */
                        cksum_vec[0].ptr = tvb_get_ptr(tvb, 0, vrrp_len);
                        cksum_vec[0].len = vrrp_len;
                        computed_cksum = in_cksum(&cksum_vec[0], 1);
                        if (computed_cksum == 0) {
                                proto_tree_add_text(vrrp_tree, tvb, offset, 2,
                                                    "Checksum: 0x%04x (correct)",
                                                    cksum);
                        } else {
                                proto_tree_add_text(vrrp_tree, tvb, offset, 2,
                                                    "Checksum: 0x%04x (incorrect, should be 0x%04x)",
                                                    cksum,
                                                    in_cksum_shouldbe(cksum, computed_cksum));
                        }
                } else {
                        proto_tree_add_text(vrrp_tree, tvb, offset, 2,
                                            "Checksum: 0x%04x", cksum);
                }
                offset+=2;

                while (ip_count > 0) {
                        proto_tree_add_text(vrrp_tree, tvb, offset, 4,
                                            "Virtual Router IP address: %s",
                                            ip_to_str(tvb_get_ptr(tvb, offset, 4)));
                        offset+=4;
                        ip_count--;
                }

                if (auth_type != VRRP_AUTH_TYPE_SIMPLE_TEXT)
                        return; /* Contents of the authentication data is undefined */

                tvb_get_nstringz0(tvb, offset, VRRP_AUTH_DATA_LEN, auth_buf);
                if (auth_buf[0] != '\0')
                        proto_tree_add_text(vrrp_tree, tvb, offset,
                                            VRRP_AUTH_DATA_LEN,
                                            "Authentication string: `%s'",
                                            auth_buf);
                offset+=8;
        }
}

void proto_register_vrrp(void)
{
        static hf_register_info hf[] = {
                { &hf_vrrp_ver_type,
                  {"VRRP message version and type", "vrrp.typever",
                   FT_UINT8, BASE_DEC, NULL, 0x0,
                   "VRRP version and type"}},

                { &hf_vrrp_version,
                  {"VRRP protocol version", "vrrp.version",
                   FT_UINT8, BASE_DEC, NULL, VRRP_VERSION_MASK,
                   "VRRP version"}},

                { &hf_vrrp_type,
                  {"VRRP packet type", "vrrp.type",
                   FT_UINT8, BASE_DEC, VALS(vrrp_type_vals), VRRP_TYPE_MASK,
                   "VRRP type"}}
        };

        static gint *ett[] = {
                &ett_vrrp,
                &ett_vrrp_ver_type
        };

        proto_vrrp = proto_register_protocol("Virtual Router Redundancy Protocol",
	    "VRRP", "vrrp");
        proto_register_field_array(proto_vrrp, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));

        return;
}

void
proto_reg_handoff_vrrp(void)
{
	dissector_add("ip.proto", IP_PROTO_VRRP, dissect_vrrp, proto_vrrp);
}
