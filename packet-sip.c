/* packet-sip.c
 * Routines for the Session Initiation Protocol (SIP) dissection.
 * RFC 2543
 * 
 * TODO: Make sure that any of CRLF, CR or LF is treated as valid line terminator.
 *       Pay attention to Content-Type: It might not always be SDP.
 *       Add hf_* fields for filtering support.
 *
 * Copyright 2000, Heikki Vatiainen <hessu@cs.tut.fi>
 *
 * $Id: packet-sip.c,v 1.1 2000/11/04 07:50:47 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-cops.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include "packet.h"
#include "packet-sdp.h"

#define TCP_PORT_SIP 5060
#define UDP_PORT_SIP 5060

/* Initialize the protocol and registered fields */
static gint proto_sip = -1;
static gint hf_msg_hdr = -1;

/* Initialize the subtree pointers */
static gint ett_sip = -1;
static gint ett_sip_hdr = -1;

static const char *sip_methods[] = {
        "<Invalid method>",      /* Pad so that the real methods start at index 1 */
        "INVITE",
        "ACK",
        "OPTIONS",
        "BYE",
        "CANCEL",
        "REGISTER"
};

static int sip_is_request(const char *line);
static guint8 *sip_kill_version(guint8 *orig, guint8 *killed);
static gint sip_get_msg_offset(tvbuff_t *tvb, guint32 offset);
 
/* Code to actually dissect the packets */
static void dissect_sip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        guint8 buf[1500], tmp[1500];
        guint32 offset;
        gint eol, msg_offset;
        tvbuff_t *next_tvb;
        const guint8 *next_pd;
        int next_offset;

	CHECK_DISPLAY_AS_DATA(proto_sip, tvb, pinfo, tree);

        pinfo->current_proto = "SIP";
        if (check_col(pinfo->fd, COL_PROTOCOL)) 
                col_add_str(pinfo->fd, COL_PROTOCOL, "SIP");
    
        offset = 0;
        eol = tvb_find_guint8(tvb, 0, tvb_length(tvb), '\r');
        if (eol < 0) goto bad;
        eol = tvb_get_nstringz0(tvb, 0, eol, buf);
        if (eol < 0) goto bad;
        eol += 2;
        if (tvb_get_guint8(tvb, eol) == '\n') {
                eol++;
        }

        if (check_col(pinfo->fd, COL_INFO))
                col_add_fstr(pinfo->fd, COL_INFO, "%s: %s",
                             sip_is_request(buf) ? "Request" : "Status",
                             sip_kill_version(buf, tmp));

        col_set_writable(pinfo->fd, FALSE);

        if (tree) {
                proto_item *ti, *th;
                proto_tree *sip_tree, *hdr_tree;

                ti = proto_tree_add_item(tree, proto_sip, tvb, 0, tvb_length(tvb), FALSE);
                sip_tree = proto_item_add_subtree(ti, ett_sip);

                proto_tree_add_text(sip_tree, tvb, offset, eol, "%s-Line: %s",
                                    sip_is_request(buf) ? "Request" : "Status", buf);

                offset = eol;
                msg_offset = sip_get_msg_offset(tvb, offset);
                if (msg_offset < 0) goto bad;
                th = proto_tree_add_item(sip_tree, hf_msg_hdr, tvb, offset, msg_offset - offset, FALSE);
                hdr_tree = proto_item_add_subtree(th, ett_sip_hdr);
                
                /* - 2 since we have a CRLF separating the message-body */
                while (msg_offset - 2 > offset) {
                        int err;
                        eol = tvb_find_guint8(tvb, offset, tvb_length_remaining(tvb, offset), '\r');
                        err = tvb_get_nstringz0(tvb, offset, eol - offset, buf);
                        if (err < 0) goto bad;
                        proto_tree_add_text(hdr_tree, tvb, offset, strlen(buf) + 2, "%s", buf);
                        offset = eol + 2;
                }
                offset += 2;  /* Skip the CRLF mentioned above */
       }

        if (tvb_length_remaining(tvb, offset) > 0) {
                next_tvb = tvb_new_subset(tvb, offset, -1, -1);
                tvb_compat(next_tvb, &next_pd, &next_offset);
                dissect_sdp(next_pd, next_offset, pinfo->fd, tree);
        }

        return;

  bad:
        next_tvb = tvb_new_subset(tvb, offset, -1, -1);
        dissect_data(tvb, pinfo, tree);

        return;
}

/* Returns the offset to the start of the optional message-body, or
 * -1 for an error.
 */
static gint sip_get_msg_offset(tvbuff_t *tvb, guint32 offset)
{
        gint eol;

        while ((eol = tvb_find_guint8(tvb, offset, tvb_length_remaining(tvb, offset), '\r')) > 0) {
                        if (tvb_get_guint8(tvb, eol + 1) == '\n' && 
                            tvb_get_guint8(tvb, eol + 2) == '\r' && 
                            tvb_get_guint8(tvb, eol + 3) == '\n')
                                return eol + 4;
                        offset = eol + 2;
        }

        return -1;
}
                
/* Remove the SIP-Version, 7 characters, from Request- or Status-Line.
 * Returns the modifed Line
 */
static guint8 *sip_kill_version(guint8 *orig, guint8 *killed)
{
        if (sip_is_request(orig)) {
                strncpy(killed, orig, strlen(orig) - strlen("SIP/2.0"));
                killed[strlen(orig) - strlen("SIP/2.0")] = '\0';
        } else
                strcpy(killed, orig + strlen("SIP/2.0") + 1); /* + 1 to skip the space */
        
        return killed;
}

static int sip_is_request(const char *line)
{
        int i;

        for (i = 1; i < array_length(sip_methods); i++) {
                if (strncmp(line, sip_methods[i], strlen(sip_methods[i])) == 0)
                        return i;
        }

        return 0;
}

/* Register the protocol with Ethereal */
void proto_register_sip(void)
{                 

        /* Setup list of header fields */
        static hf_register_info hf[] = {

                { &hf_msg_hdr,
                        { "Message Header",           "sip.msg_hdr",
                        FT_NONE, 0, NULL, 0,
                        "Message Header in SIP message" }
                },
        };

        /* Setup protocol subtree array */
        static gint *ett[] = {
                &ett_sip,
                &ett_sip_hdr,
        };

        /* Register the protocol name and description */
        proto_sip = proto_register_protocol("Session Initiation Protocol", "sip");

        /* Required function calls to register the header fields and subtrees used */
        proto_register_field_array(proto_sip, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
};

void
proto_reg_handoff_sip(void)
{
        dissector_add("tcp.port", TCP_PORT_SIP, dissect_sip);
        dissector_add("udp.port", UDP_PORT_SIP, dissect_sip);
}
