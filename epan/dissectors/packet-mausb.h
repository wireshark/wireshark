/* packet-mausb.h
 * Definitions for Media Agnostic USB dissection
 * Copyright 2016, Intel Corporation
 * Author: Sean O. Stalley <sean.stalley@intel.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_MAUSB_H__
#define __PACKET_MAUSB_H__

#define MAUSB_DPH_LENGTH 20
/** Common header fields, per section 6.2.1 */
struct mausb_header {
    /* DWORD 0 */
    uint8_t  ver_flags;
    uint8_t  type;
    uint16_t length;
    /* DWORD 1 */
    uint16_t handle;
    uint8_t  ma_dev_addr;
    uint8_t  mass_id;
    /* DWORD 2 */
    uint8_t  status;
    union {
        uint16_t token;
        struct {
            uint8_t  eps_tflags;
            union {
                uint16_t stream_id;
                uint16_t num_headers_iflags;
            } u1;
            /* DWORD 3 */
            uint32_t seq_num; /* Note: only 24 bits used */
            uint8_t  req_id;
            /* DWORD 4 */
            union {
                uint32_t credit;
                uint32_t present_time_num_seg;
            } u2;
            /* DWORD 5 */
            uint32_t timestamp;
            /* DWORD 6 */
            uint32_t tx_dly; /* Note: if no timestamp, tx_dly will be in DWORD 5 */
        } s;
    } u;
};

bool mausb_is_from_host(struct mausb_header *header);
uint8_t mausb_ep_handle_ep_d(uint16_t handle);
uint8_t mausb_ep_handle_ep_num(uint16_t handle);
uint8_t mausb_ep_handle_dev_addr(uint16_t handle);
uint8_t mausb_ep_handle_bus_num(uint16_t handle);

void mausb_set_usb_conv_info(usb_conv_info_t *usb_conv_info,
                             struct mausb_header *header);

#endif

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
