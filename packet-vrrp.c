/* packet-vrrp.c
 * Routines for the Virtual Router Redundancy Protocol (VRRP)
 * RFC2338
 *
 * Heikki Vatiainen <hessu@cs.tut.fi>
 *
 * $Id: packet-vrrp.c,v 1.8 2000/08/13 14:09:08 deniel Exp $
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

static gint proto_vrrp = -1;
static gint ett_vrrp = -1;
static gint ett_vrrp_ver_type = -1;

static gint hf_vrrp_ver_type = -1;
static gint hf_vrrp_version = -1;
static gint hf_vrrp_type = -1;

struct vrrp_header {
#define VRRP_VERSION_MASK 0xf0
#define VRRP_TYPE_MASK 0x0f
        guint8  ver_type;
        guint8  vrouter_id;
        guint8  priority;
        guint8  count_ip_addrs;
        guint8  auth_type;
        guint8  adver_int;
        guint16 checksum;
        /* One or more IP addresses */
        /* 8 octets of authentication data */
#define VRRP_AUTH_DATA_LEN 8
};


#define VRRP_TYPE_ADVERTISEMENT 1
static const value_string vrrp_type_vals[] = {
        {VRRP_TYPE_ADVERTISEMENT, "Advertisement"}
};

#define VRRP_AUTH_TYPE_NONE 0
#define VRRP_AUTH_TYPE_SIMPLE_TEXT 1
#define VRRP_AUTH_TYPE_IP_AUTH_HDR 2
static const value_string vrrp_auth_vals[] = {
        {VRRP_AUTH_TYPE_NONE,        "No Authentication"},
        {VRRP_AUTH_TYPE_SIMPLE_TEXT, "Simple Text Authentication"},
        {VRRP_AUTH_TYPE_IP_AUTH_HDR, "IP Authentication Header"}
};

#define VRRP_PRIORITY_MASTER_STOPPING 0
/* Values between 1 and 254 inclusive are for backup VRRP routers */
#define VRRP_PRIORITY_DEFAULT 100
#define VRRP_PRIORITY_OWNER 255
static const value_string vrrp_prio_vals[] = {
        {VRRP_PRIORITY_MASTER_STOPPING,  "Current Master has stopped participating in VRRP"},
        {VRRP_PRIORITY_DEFAULT,          "Default priority for a backup VRRP router"},
        {VRRP_PRIORITY_OWNER,            "This VRRP router owns the virtual router's IP address(es)"}
};


static void
dissect_vrrp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
        struct vrrp_header vrh;
        gboolean short_hdr = FALSE;
        gboolean short_packet = FALSE;
        guint calculated_len = -1; /* initialize to silence false warning from gcc */

	OLD_CHECK_DISPLAY_AS_DATA(proto_vrrp, pd, offset, fd, tree);

        if (sizeof(struct vrrp_header) > END_OF_FRAME)
                short_hdr = short_packet = TRUE;
        else {
                memcpy(&vrh, pd + offset, sizeof(struct vrrp_header));
                calculated_len = sizeof(struct vrrp_header) + vrh.count_ip_addrs*4 + VRRP_AUTH_DATA_LEN;
                if (calculated_len > END_OF_FRAME)
                        short_packet = TRUE;
        }

        if (check_col(fd, COL_PROTOCOL))
                col_add_str(fd, COL_PROTOCOL, "VRRP");
        
        if (check_col(fd, COL_INFO)) {
                if (short_hdr)
                        col_add_fstr(fd, COL_INFO, "Short packet header, length %u", END_OF_FRAME);
                else if (short_packet)
                        col_add_fstr(fd, COL_INFO, "Packet length mismatch, calculated %u, real %u",
                                     calculated_len, END_OF_FRAME);
                else
                        col_add_fstr(fd, COL_INFO, "%s (v%u)", "Announcement", hi_nibble(vrh.ver_type));
        }

        if (tree) {
                proto_item *ti, *tv;
                proto_tree *vrrp_tree, *ver_type_tree;
                guint8 ip_count, auth_len, auth_buf[VRRP_AUTH_DATA_LEN+1];

                if (short_hdr) {
                        old_dissect_data(pd, offset, fd, tree);
                        return;
                }

                ti = proto_tree_add_item(tree, proto_vrrp, NullTVB, offset, END_OF_FRAME, FALSE);
                vrrp_tree = proto_item_add_subtree(ti, ett_vrrp);

                tv = proto_tree_add_uint_format(vrrp_tree, hf_vrrp_ver_type, NullTVB, offset, 1,
                                                vrh.ver_type, "Version %u, Packet type %u (%s)",
                                                hi_nibble(vrh.ver_type), lo_nibble(vrh.ver_type),
                                                val_to_str(lo_nibble(vrh.ver_type), vrrp_type_vals, "Unknown"));
                ver_type_tree = proto_item_add_subtree(tv, ett_vrrp_ver_type);
                proto_tree_add_uint(ver_type_tree, hf_vrrp_version, NullTVB, offset, 1, vrh.ver_type);
                proto_tree_add_uint(ver_type_tree, hf_vrrp_type, NullTVB, offset, 1, vrh.ver_type);
                offset++;
                
                proto_tree_add_text(vrrp_tree, NullTVB, offset++, 1, "Virtual Router ID: %u", vrh.vrouter_id);
                proto_tree_add_text(vrrp_tree, NullTVB, offset++, 1, "Priority: %u (%s)", vrh.priority,
                                    val_to_str(vrh.priority, vrrp_prio_vals, "Non-default backup priority"));
                proto_tree_add_text(vrrp_tree, NullTVB, offset++, 1, "Count IP Addrs: %u", vrh.count_ip_addrs);
                proto_tree_add_text(vrrp_tree, NullTVB, offset++, 1, "Authentication Type: %u (%s)", vrh.auth_type,
                                    val_to_str(vrh.auth_type, vrrp_auth_vals, "Unknown"));
                proto_tree_add_text(vrrp_tree, NullTVB, offset++, 1, "Advertisement Interval: %u second%s",
                                    vrh.adver_int, plurality(vrh.adver_int, "", "s"));
                proto_tree_add_text(vrrp_tree, NullTVB, offset, 2, "Checksum: 0x%x", htons(vrh.checksum));
                offset+=2;

                if (short_packet) {
                        old_dissect_data(pd, offset, fd, vrrp_tree);
                        return;
                }
                
                ip_count = vrh.count_ip_addrs;
                while (ip_count > 0) {
                        proto_tree_add_text(vrrp_tree, NullTVB, offset, 4, "Virtual Router IP address: %s",
                                            ip_to_str(pd+offset));
                        offset+=4;
                        ip_count--;
                }

                if (vrh.auth_type != VRRP_AUTH_TYPE_SIMPLE_TEXT)
                        return; /* Contents of the authentication data is undefined */

                strncpy(auth_buf, pd+offset, VRRP_AUTH_DATA_LEN);
                auth_buf[VRRP_AUTH_DATA_LEN] = '\0';
                auth_len = strlen(auth_buf);
                if (auth_len > 0)
                        proto_tree_add_text(vrrp_tree, NullTVB, offset, auth_len, "Authentication string: `%s'", auth_buf);
                offset+=8;

        }

        return;
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

        proto_vrrp = proto_register_protocol("Virtual Router Redundancy Protocol", "vrrp");
        proto_register_field_array(proto_vrrp, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));

        return;
}

void
proto_reg_handoff_vrrp(void)
{
	old_dissector_add("ip.proto", IP_PROTO_VRRP, dissect_vrrp);
}
