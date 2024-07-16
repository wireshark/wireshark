/* packet-dvbci.h
 * Routines for DVB-CI (Common Interface) dissection
 * Copyright 2013, Martin Kaiser <martin@kaiser.cx>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_DVBCI_H__
#define __PACKET_DVBCI_H__

#include <glib.h>
#include <epan/packet_info.h>
#include <epan/value_string.h>

/* event byte in the PCAP DVB-CI pseudo-header */
#define DVBCI_EVT_DATA_CAM_TO_HOST  0xFF
#define DVBCI_EVT_DATA_HOST_TO_CAM  0xFE
#define DVBCI_EVT_CIS_READ          0xFD
#define DVBCI_EVT_COR_WRITE         0xFC
#define DVBCI_EVT_HW_EVT            0xFB
/* this value is not really part of the PCAP DVB-CI specification
   it's used as return value for dvbci_get_evt_from_addrs() when the
   event can't be determined by looking at source and destination addresses */
#define DVBCI_EVT_INVALID_EVT       0x00

WS_DLL_PUBLIC const value_string dvbci_event[];

int dvbci_set_addrs(uint8_t event, packet_info *pinfo);

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
