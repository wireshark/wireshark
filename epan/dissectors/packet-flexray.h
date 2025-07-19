/* packet-flexray.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_FLEXRAY_H__
#define __PACKET_FLEXRAY_H__

#define FLEXRAY_CHANNEL_MASK    0x80
#define FLEXRAY_TYPE_MASK       0x7f
#define FLEXRAY_FRAME           0x01
#define FLEXRAY_SYMBOL          0x02

#define FLEXRAY_ERRORS_DEFINED  0x1f
#define FLEXRAY_FCRC_ERROR      0x10
#define FLEXRAY_HCRC_ERROR      0x08
#define FLEXRAY_FES_ERROR       0x04
#define FLEXRAY_COD_ERROR       0x02
#define FLEXRAY_TSS_ERROR       0x01

#define FLEXRAY_HEADER_LENGTH   5

#define FLEXRAY_RES_MASK        0x80
#define FLEXRAY_PPI_MASK        0x40
#define FLEXRAY_NFI_MASK        0x20
#define FLEXRAY_SFI_MASK        0x10
#define FLEXRAY_STFI_MASK       0x08

#define FLEXRAY_ID_MASK         0x07ff
#define FLEXRAY_LENGTH_MASK     0xfe
#define FLEXRAY_HEADER_CRC_MASK 0x01ffc0
#define FLEXRAY_HEADER_CRC_SHFT 6
#define FLEXRAY_CC_MASK         0x3f

/* Structure that gets passed between dissectors (containing of frame id, counter cycle and channel). */
typedef struct flexray_info {
    uint16_t id;
    uint8_t cc;
    uint8_t ch;
    uint16_t bus_id;
} flexray_info_t;

#define FLEXRAY_ID_CYCLE_MASK    0x000000FF
#define FLEXRAY_ID_FRAME_ID_MASK 0x00FFFF00
#define FLEXRAY_ID_CHANNEL_MASK  0x0F000000
#define FLEXRAY_ID_BUS_ID_MASK   0xF0000000

uint32_t flexray_calc_flexrayid(uint16_t bus_id, uint8_t channel, uint16_t frame_id, uint8_t cycle);
uint32_t flexray_flexrayinfo_to_flexrayid(flexray_info_t *flexray_info);
bool flexray_call_subdissectors(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, flexray_info_t *flexray_info, const bool use_heuristics_first);
bool flexray_set_source_and_destination_columns(packet_info* pinfo, flexray_info_t *flexray_info);

#endif /* __PACKET_FLEXRAY_H__ */

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
