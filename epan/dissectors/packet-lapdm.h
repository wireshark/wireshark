/* packet-lapdm.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_LAPDM_H__
#define __PACKET_LAPDM_H__

#include <stdbool.h>
#include <glib.h>

/* See GSM TS 04.06 */
enum lapdm_hdr_type {
    LAPDM_HDR_FMT_A,
    LAPDM_HDR_FMT_B,
    LAPDM_HDR_FMT_Bter,
    LAPDM_HDR_FMT_B4,
    LAPDM_HDR_FMT_C,
};

typedef struct _lapdm_data_t {
    bool is_acch;
} lapdm_data_t;

#endif
