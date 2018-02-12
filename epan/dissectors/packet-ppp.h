/* packet-ppp.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_PPP_H__
#define __PACKET_PPP_H__

#include <epan/params.h>
#include "ws_symbol_export.h"

tvbuff_t *decode_fcs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *fh_tree, int fcs_decode, int proto_offset);

/*
 * Used by the GTP dissector as well.
 */
extern value_string_ext ppp_vals_ext;

/*
 * Used by CHDLC dissector as well.
 */
extern const enum_val_t fcs_options[];

#endif
