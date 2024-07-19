/* packet-smb-browse.h
 * Declaration of routines for SMB Browser packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _PACKET_SMB_BROWSE_H_
#define _PACKET_SMB_BROWSE_H_

int
dissect_smb_server_type_flags(tvbuff_t *tvb, int offset, packet_info *pinfo,
			      proto_tree *parent_tree, uint8_t *drep,
			      bool infoflag);

#endif
