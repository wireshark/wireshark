/* packet-mpls.h
 * Declarations of exported routines from MPLS dissector
 * Author: Carlos Pignataro <cpignata@cisco.com>
 * Copyright 2005, cisco Systems, Inc.
 *
 * (c) Copyright 2006, _FF_ Francesco Fondelli <francesco.fondelli@gmail.com>
 *                     added MPLS OAM support, ITU-T Y.1711
 * (c) Copyright 2011, Shobhank Sharma <ssharma5@ncsu.edu>
 *                     added MPLS Generic Associated Channel as per RFC 5586
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_MPLS_H
#define PACKET_MPLS_H

/* Special labels in MPLS */
enum {
    MPLS_LABEL_IP4_EXPLICIT_NULL = 0,
    MPLS_LABEL_ROUTER_ALERT,
    MPLS_LABEL_IP6_EXPLICIT_NULL,
    MPLS_LABEL_IMPLICIT_NULL,
    MPLS_LABEL_ELI               = 7,
    MPLS_LABEL_GACH              = 13, /* aka GAL */
    MPLS_LABEL_OAM_ALERT         = 14,
    MPLS_LABEL_MAX_RESERVED      = 15,
    MPLS_LABEL_INVALID           = -1
};
/* As per RFC 5718 */
#define PW_ACH_TYPE_MCC               0x0001
/* As per RFC 5718 */
#define PW_ACH_TYPE_SCC               0x0002
/* As per RFC 5885 */
#define PW_ACH_TYPE_BFD               0x0007
/* As per RFC 6374 */
#define PW_ACH_TYPE_DLM               0x000A
#define PW_ACH_TYPE_ILM               0x000B
#define PW_ACH_TYPE_DM                0x000C
#define PW_ACH_TYPE_DLM_DM            0x000D
#define PW_ACH_TYPE_ILM_DM            0x000E
/* As per RFC 4385 clause 6 */
#define PW_ACH_TYPE_IPV4              0x0021
/* As per RFC 6428 Section 3.3 */
#define PW_ACH_TYPE_BFD_CC            0x0022
#define PW_ACH_TYPE_BFD_CV            0x0023
/* As per RFC 6378 */
#define PW_ACH_TYPE_PSC               0x0024
/* As per RFC 6426 Section 7.4 */
#define PW_ACH_TYPE_ONDEMAND_CV       0x0025
/* As per RFC 6478 */
#define PW_ACH_TYPE_PW_OAM            0x0027
/* As per RFC 7769 */
#define PW_ACH_TYPE_MAC               0x0028
/* As per RFC 4385 clause 6 */
#define PW_ACH_TYPE_IPV6              0x0057
/* As per RFC 6427 */
#define PW_ACH_TYPE_MPLSTP_FM         0x0058
/* As per RFC 6671 */
#define PW_ACH_TYPE_MPLSTP_OAM        0x8902

/* MPLS over UDP http://tools.ietf.org/html/draft-ietf-mpls-in-udp-11,
 * udp destination port as defined in
 * http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=6635
 */
#define UDP_PORT_MPLS_OVER_UDP        6635

/*
 * FF: private data passed from the MPLS dissector to subdissectors
 * (data parameter).
 */
struct mplsinfo {
    guint32 label; /* last mpls label in label stack */
    guint8  exp;   /* former EXP bits of last mpls shim in stack */
    guint8  bos;   /* BOS bit of last mpls shim in stack */
    guint8  ttl;   /* TTL bits of last mpls shim in stack */
};

extern const value_string special_labels[];
extern void decode_mpls_label(tvbuff_t *tvb, int offset,
                              guint32 *label, guint8 *exp,
                              guint8 *bos, guint8 *ttl);

extern gboolean dissect_try_cw_first_nibble(tvbuff_t *tvb, packet_info *pinfo,
                                            proto_tree *tree );

#endif
