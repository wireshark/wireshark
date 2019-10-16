/* packet-bthci_evt.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_BTHCI_EVT_H__
#define __PACKET_BTHCI_EVT_H__

extern value_string_ext  bthci_evt_evt_code_vals_ext;
extern const value_string bthci_evt_controller_types[];
extern const value_string bthci_evt_codec_id_vals[];
extern const value_string bthci_evt_mws_transport_layer_vals[];

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

WS_DLL_PUBLIC const value_string bthci_evt_lmp_version[];
WS_DLL_PUBLIC const value_string bthci_evt_hci_version[];

#ifdef __cplusplus
}
#endif /* __cplusplus */

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
