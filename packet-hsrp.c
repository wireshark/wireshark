/* packet-hsrp.c
 * Routines for the Cisco Hot Standby Router Protocol (HSRP)
 * RFC2281
 *
 * Heikki Vatiainen <hessu@cs.tut.fi>
 *
 * $Id: packet-hsrp.c,v 1.7 2000/08/13 14:08:12 deniel Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-vrrp.c
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

#include <glib.h>
#include "packet.h"

static gint proto_hsrp = -1;
static gint ett_hsrp = -1;

#define UDP_PORT_HSRP   1985

struct hsrp_packet {          /* Multicast to 224.0.0.2, TTL 1, UDP, port 1985 */
        guint8  version;      /* RFC2281 describes version 0 */
        guint8  opcode;
        guint8  state;
#define HSRP_DEFAULT_HELLOTIME 3
        guint8  hellotime;    /* In seconds */
#define HSRP_DEFAULT_HOLDTIME 10
        guint8  holdtime;     /* In seconds */
        guint8  priority;     /* Higher is stronger, highest IP address tie-breaker */
        guint8  group;        /* Identifies the standby group */
        guint8  reserved;
        guint8  auth_data[8]; /* Clear-text password, recommended default is `cisco' */
        guint32 virt_ip_addr; /* The virtual IP address used by this group */
};


#define HSRP_OPCODE_HELLO  0
#define HSRP_OPCODE_COUP   1
#define HSRP_OPCODE_RESIGN 2
static const value_string hsrp_opcode_vals[] = {
        {HSRP_OPCODE_HELLO,  "Hello"},
        {HSRP_OPCODE_COUP,   "Coup"},
        {HSRP_OPCODE_RESIGN, "Resign"}
};

#define HSRP_STATE_INITIAL  0
#define HSRP_STATE_LEARN    1
#define HSRP_STATE_LISTEN   2
#define HSRP_STATE_SPEAK    4
#define HSRP_STATE_STANDBY  8
#define HSRP_STATE_ACTIVE  16
static const value_string hsrp_state_vals[] = {
        {HSRP_STATE_INITIAL, "Initial"},
        {HSRP_STATE_LEARN,   "Learn"},
        {HSRP_STATE_LISTEN,  "Listen"},
        {HSRP_STATE_SPEAK,   "Speak"},
        {HSRP_STATE_STANDBY, "Standby"},
        {HSRP_STATE_ACTIVE,  "Active"}
};

static void
dissect_hsrp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
        struct hsrp_packet hsrp;
        gboolean short_packet = FALSE;

	OLD_CHECK_DISPLAY_AS_DATA(proto_hsrp, pd, offset, fd, tree);

        if (sizeof(struct hsrp_packet) > END_OF_FRAME)
                short_packet = TRUE;
        else
                memcpy(&hsrp, pd + offset, sizeof(struct hsrp_packet));

        if (check_col(fd, COL_PROTOCOL))
                col_add_str(fd, COL_PROTOCOL, "HSRP");
        
        if (check_col(fd, COL_INFO)) {
                if (short_packet)
                        col_add_fstr(fd, COL_INFO, "Short packet, length %u", END_OF_FRAME);
                else
                        col_add_fstr(fd, COL_INFO, "%s (state %s)",
                                     val_to_str(hsrp.opcode, hsrp_opcode_vals, "Unknown"),
                                     val_to_str(hsrp.state, hsrp_state_vals, "Unknown"));
        }

        if (tree) {
                proto_item *ti;
                proto_tree *hsrp_tree;
                guint8 auth_buf[sizeof(hsrp.auth_data) + 1];

                if (short_packet) {
                        old_dissect_data(pd, offset, fd, tree);
                        return;
                }

                ti = proto_tree_add_item(tree, proto_hsrp, NullTVB, offset, END_OF_FRAME, FALSE);
                hsrp_tree = proto_item_add_subtree(ti, ett_hsrp);

                proto_tree_add_text(hsrp_tree, NullTVB, offset++, 1, "Version: %u", hsrp.version);
                proto_tree_add_text(hsrp_tree, NullTVB, offset++, 1, "Opcode: %u (%s)", hsrp.opcode,
                                    val_to_str(hsrp.opcode, hsrp_opcode_vals, "Unknown"));
                proto_tree_add_text(hsrp_tree, NullTVB, offset++, 1, "State: %u (%s)", hsrp.state,
                                    val_to_str(hsrp.state, hsrp_state_vals, "Unknown"));
                
                proto_tree_add_text(hsrp_tree, NullTVB, offset++, 1, "Hellotime: %u second%s (%sdefault)",
                                    hsrp.hellotime, plurality(hsrp.hellotime, "", "s"),
                                    (hsrp.hellotime == HSRP_DEFAULT_HELLOTIME) ? "" : "non-");
                proto_tree_add_text(hsrp_tree, NullTVB, offset++, 1, "Holdtime: %u second%s (%sdefault)",
                                    hsrp.holdtime, plurality(hsrp.holdtime, "", "s"),
                                    (hsrp.holdtime == HSRP_DEFAULT_HOLDTIME) ? "" : "non-");
                proto_tree_add_text(hsrp_tree, NullTVB, offset++, 1, "Priority: %u", hsrp.priority);
                proto_tree_add_text(hsrp_tree, NullTVB, offset++, 1, "Group: %u", hsrp.group);
                proto_tree_add_text(hsrp_tree, NullTVB, offset++, 1, "Reserved: 0x%x", hsrp.reserved);

                memcpy(auth_buf, hsrp.auth_data, sizeof(hsrp.auth_data));
                auth_buf[sizeof(auth_buf)] = '\0';
                proto_tree_add_text(hsrp_tree, NullTVB, offset, 8, "Authentication Data: `%s'", auth_buf);
                offset+=8;

                proto_tree_add_text(hsrp_tree, NullTVB, offset++, 4, "Virtual IP address: %s",
                                    ip_to_str((guint8 *)&hsrp.virt_ip_addr));
                
        }

        return;
}

void proto_register_hsrp(void)
{
        static gint *ett[] = {
                &ett_hsrp,
        };

        proto_hsrp = proto_register_protocol("Cisco Hot Standby Router Protocol", "hsrp");
        proto_register_subtree_array(ett, array_length(ett));

        return;
}

void
proto_reg_handoff_hsrp(void)
{
	old_dissector_add("udp.port", UDP_PORT_HSRP, dissect_hsrp);
}
