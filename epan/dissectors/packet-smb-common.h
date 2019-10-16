/* packet-smb-common.h
 * Routines for SMB packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_SMB_COMMON_H__
#define __PACKET_SMB_COMMON_H__

/* **data is allocated with ephemeral scope and will be automatically freed
 * when packet dissection completes.
 * You do NOT need to g_free() that string.
 */
int display_unicode_string(tvbuff_t *tvb, proto_tree *tree, int offset, int hf_index, char **data);

int display_ms_string(tvbuff_t *tvb, proto_tree *tree, int offset, int hf_index, char **data);

int dissect_ms_compressed_string(tvbuff_t *tvb, proto_tree *tree, int offset, int hf_index,
				 const char **data);

extern const value_string share_type_vals[];

#endif
