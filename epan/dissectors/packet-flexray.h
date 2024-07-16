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
