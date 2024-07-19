/* packet-smb-mailslot.h
 * Declaration of routines for SMB mailslot packet dissection
 * Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _PACKET_SMB_MAILSLOT_H_
#define _PACKET_SMB_MAILSLOT_H_

bool
dissect_mailslot_smb(tvbuff_t *total_tvb, tvbuff_t *setup_tvb,
		     tvbuff_t *tvb, const char *mailslot,
		     packet_info *pinfo, proto_tree *tree, smb_info_t* smb_info);

#endif
