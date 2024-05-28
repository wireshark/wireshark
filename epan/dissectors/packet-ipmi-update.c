/* packet-ipmi-update.c
 * Sub-dissectors for IPMI messages (netFn=Firmware Update, PPS-specific)
 * Copyright 2007-2008, Alexey Neyman, Pigeon Point Systems <avn@pigeonpoint.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

#include "packet-ipmi.h"

void proto_register_ipmi_update(void);

static const ipmi_cmd_t cmd_update[] = {
	{ 0x00, IPMI_TBD,   NULL, NULL, "[PPS OEM] Upgrade Status", 0 },
	{ 0x01, IPMI_TBD,   NULL, NULL, "[PPS OEM] Upgrade Start", 0 },
	{ 0x02, IPMI_TBD,   NULL, NULL, "[PPS OEM] Upgrade Prepare", 0 },
	{ 0x03, IPMI_TBD,   NULL, NULL, "[PPS OEM] Upgrade Write", 0 },
	{ 0x04, IPMI_TBD,   NULL, NULL, "[PPS OEM] Upgrade Complete", 0 },
	{ 0x05, IPMI_TBD,   NULL, NULL, "[PPS OEM] Restore Backup", 0 },
	{ 0x06, IPMI_TBD,   NULL, NULL, "[PPS OEM] Query Backup Version", 0 }
};

void
proto_register_ipmi_update(void)
{
	ipmi_register_netfn_cmdtab(IPMI_UPDATE_REQ, IPMI_OEM_PPS, NULL, 0, NULL,
			cmd_update, array_length(cmd_update));
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
