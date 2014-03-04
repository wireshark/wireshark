/* packet-dvbci.h
 * Routines for DVB-CI (Common Interface) dissection
 * Copyright 2013, Martin Kaiser <martin@kaiser.cx>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

static const value_string dvbci_event[] = {
    { DVBCI_EVT_DATA_HOST_TO_CAM, "data transfer Host -> CAM" },
    { DVBCI_EVT_DATA_CAM_TO_HOST, "data transfer CAM -> Host" },
    { DVBCI_EVT_CIS_READ,         "read the Card Information Structure (CIS)" },
    { DVBCI_EVT_COR_WRITE,
        "write into the Configuration Option Register (COR)" },
    { DVBCI_EVT_HW_EVT,           "hardware event" },
    { 0, NULL }
};

gint dvbci_set_addrs(guint8 event, packet_info *pinfo);
guint8 dvbci_get_evt_from_addrs(packet_info *pinfo);

#endif

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
