/* network-boot-analysis.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Module for cross-protocol analysis of network boot (PXE, NetBoot, ...).
 * Copyright (C) 2018, VMware, Inc.  All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __NETWORK_BOOT_ANALYSIS_H__
#define __NETWORK_BOOT_ANALYSIS_H__

#include "tap.h"
#include "wmem/wmem.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Structure used to pass information from a BOOTP/DHCP conversation to any
 * "bootp-boot" tap listeners.
 */
typedef struct {
        address client_address;
	gboolean is_pxe;
	guint32 xid;
	guint8 opcode;
        guchar *bootfile_name;
} network_boot_bootp_event;

/*
 * Structure used to pass information from a TFTP conversation to any
 * "tftp-boot" tap listeners.
 */
typedef struct {
        address client_address;
        guchar *file_name;
        gboolean is_first;
        gboolean is_complete;
        guchar *error_text;
        guint64 file_size;
} network_boot_tftp_event;

/* Initialize the network boot analysis module. */
WS_DLL_PUBLIC void start_networkboot(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __NETWORK_BOOT_ANALYSIS_H__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
