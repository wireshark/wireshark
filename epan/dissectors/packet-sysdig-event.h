/* packet-sysdig-event.h
 * Definitions for Sysdig event dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdint.h>

#pragma once

typedef struct _sysdig_event_param_data {
    // sysdig.param.asyncevent.data
    int data_bytes_offset;
    uint32_t data_bytes_length;
} sysdig_event_param_data;
