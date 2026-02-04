/* packet-homeplug-av-vendor-vertexcom.h
 * Routines for HomePlug AV VertexCom MME dissection
 * Copyright 2026, ShanTon Tu <shanton.tu@vertexcom.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_HOMEPLUG_AV_VENDOR_VERTEXCOM_H
#define PACKET_HOMEPLUG_AV_VENDOR_VERTEXCOM_H

#include <epan/proto.h>
#include <epan/ptvcursor.h>

#define HOMEPLUG_AV_OUI_VERTEXCOM 0x0013D7

/**
 * @brief Dissect HomePlug AV VertexCom MME mmhdr mmtype field
 *
 * Invoked by `dissect_homeplug_av_mmhdr()` in packet-homeplug-av.c
 */
proto_tree* dissect_homeplug_av_mmhdr_mmtype_vertexcom(ptvcursor_t* cursor);

/**
 * @brief Dissect HomePlug AV VertexCom MME
 *
 *  Invoked by `dissect_homeplug_av_mme()` in packet-homeplug-av.c
 */
void dissect_homeplug_av_mme_vertexcom(ptvcursor_t* cursor,
                                       uint8_t homeplug_av_mmver,
                                       uint16_t homeplug_av_mmtype,
                                       packet_info* pinfo,
                                       proto_tree* vendor_tree);

/**
 * @brief Append HomePlug AV VertexCom MME mmtype info to the Info column
 *
 * Invoked by `info_column_filler_initial()` in packet-homeplug-av.c
 */
void homeplug_av_mmtype_column_vertexcom(packet_info* pinfo,
                                         uint16_t homeplug_av_mmtype);

#endif /* PACKET_HOMEPLUG_AV_VENDOR_VERTEXCOM_H */
