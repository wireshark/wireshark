/* packet-knxip.h
 * Routines for KNXnet/IP dissection
 * Copyright 2004, Jan Kessler <kessler@ise.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef PACKET_KNXIP_H
#define PACKET_KNXIP_H

#include <glib.h>
#include <epan/expert.h>
#include "packet-knxip_decrypt.h"

#define KIP_ERROR     &ei_knxip_error
#define KIP_WARNING   &ei_knxip_warning

extern expert_field ei_knxip_error;
extern expert_field ei_knxip_warning;

extern guint8 knxip_host_protocol;
extern guint8 knxip_error;

#define MAX_KNX_DECRYPTION_KEYS  10

extern guint8 knx_decryption_keys[ MAX_KNX_DECRYPTION_KEYS ][ KNX_KEY_LENGTH ];
extern guint8 knx_decryption_key_count;

#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
