/* packet-smb-pipe.h
 * Declarations of routines for SMB named pipe packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _PACKET_SMB_PIPE_H_
#define _PACKET_SMB_PIPE_H_

extern bool
dissect_pipe_smb(tvbuff_t *sp_tvb, tvbuff_t *s_tvb, tvbuff_t *pd_tvb,
		 tvbuff_t *p_tvb, tvbuff_t *d_tvb, const char *pipe,
		 packet_info *pinfo, proto_tree *tree, smb_info_t *smb_info);
bool
dissect_pipe_dcerpc(tvbuff_t *d_tvb, packet_info *pinfo, proto_tree *parent_tree,
		proto_tree *tree, uint32_t fid, void *data);

#endif
