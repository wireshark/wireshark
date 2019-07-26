/* packet-geonw.h
 * Routines for GeoNetworking and BTP-A/B dissection
 * Coyright 2018, C. Guerber <cguerber@yahoo.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef __PACKET_GEONW_H__
#define __PACKET_GEONW_H__

#define SN_MAX  0xffff

typedef struct geonwheader
{
    guint8  gnw_ver;     /* Version */
    guint8  gnw_lt;      /* Life time */
    guint8  gnw_rhl;     /* Remaining Hop Limit */
    guint8  gnw_proto;   /* Next header */
    guint8  gnw_htype;   /* Header type */
    guint8  gnw_tc;      /* Traffic class */
    guint8  gnw_flags;   /* Flags */
    guint8  gnw_mhl;     /* Remaining Hop Limit */
    guint16 gnw_len;     /* Payload length */
    guint32 gnw_sn;      /* Sequence number or MAX+1 */
    guint32 gnw_tst;     /* TimeStamp */
    address gnw_src;     /* source address */
    address gnw_dst;     /* destination address */
    gint32  gnw_lat;     /* Latitude */
    gint32  gnw_lon;     /* Longitude */
} geonwheader;

typedef struct btpaheader
{
    address gnw_src;     /* source address */
    address gnw_dst;     /* destination address */
    guint16 btp_psrc;     /* Source port */
    guint16 btp_pdst;     /* Destination port */
} btpaheader;

typedef struct btpbheader
{
    address gnw_src;     /* source address */
    address gnw_dst;     /* destination address */
    guint16 btp_pdst;     /* Destination port */
    guint16 btp_idst;     /* Destination info */
} btpbheader;

#endif /* __PACKET_GEONW_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
