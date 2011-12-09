/* packet-rohc.h
 * Routines for RObust Header Compression (ROHC) dissection.
 *
 * Copyright 2011, Anders Broman <anders.broman[at]ericsson.com>
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
 *
 * Ref:
 * http://www.ietf.org/rfc/rfc3095.txt         RObust Header Compression (ROHC): Framework and four profiles: RTP, UDP, ESP, and uncompressed
 * http://datatracker.ietf.org/doc/rfc4815/    RObust Header Compression (ROHC): Corrections and Clarifications to RFC 3095
 * http://datatracker.ietf.org/doc/rfc5225/    RObust Header Compression Version 2 (ROHCv2): Profiles for RTP, UDP, IP, ESP and UDP-Lite
 */

#ifndef PACKET_ROHC_H
#define PACKET_ROHC_H

typedef struct rohc_info
{

    /* RoHC settings */
    gboolean           rohc_compression;
    unsigned short     rohc_ip_version;
    gboolean           cid_inclusion_info;
    gboolean           large_cid_present;
    enum rohc_mode     mode;
    gboolean           rnd;
    gboolean           udp_checkum_present;
    unsigned short     profile;
    proto_item         *last_created_item;
} rohc_info;

int dissect_rohc_ir_rtp_profile_dynamic(tvbuff_t *tvb, proto_tree *tree, int offset, rohc_info *p_rohc_info);
#endif /* PACKET_ROHC_H */
