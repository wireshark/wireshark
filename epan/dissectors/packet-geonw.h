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
    uint8_t gnw_ver;     /* Version */
    uint8_t gnw_lt;      /* Life time */
    uint8_t gnw_rhl;     /* Remaining Hop Limit */
    uint8_t gnw_proto;   /* Next header */
    uint8_t gnw_htype;   /* Header type */
    uint8_t gnw_tc;      /* Traffic class */
    uint8_t gnw_flags;   /* Flags */
    uint8_t gnw_mhl;     /* Remaining Hop Limit */
    uint16_t gnw_len;     /* Payload length */
    uint32_t gnw_sn;      /* Sequence number or MAX+1 */
    uint32_t gnw_tst;     /* TimeStamp */
    address gnw_src;     /* source address */
    address gnw_dst;     /* destination address */
    int32_t gnw_lat;     /* Latitude */
    int32_t gnw_lon;     /* Longitude */
} geonwheader;

typedef struct btpaheader
{
    address gnw_src;     /* source address */
    address gnw_dst;     /* destination address */
    uint16_t btp_psrc;     /* Source port */
    uint16_t btp_pdst;     /* Destination port */
} btpaheader;

typedef struct btpbheader
{
    address gnw_src;     /* source address */
    address gnw_dst;     /* destination address */
    uint16_t btp_pdst;     /* Destination port */
    uint16_t btp_idst;     /* Destination info */
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
