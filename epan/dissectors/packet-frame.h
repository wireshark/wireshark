/* packet-frame.h
 *
 * Top-most dissector. Decides dissector based on Wiretap Encapsulation Type.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ws_symbol_export.h"

#include <wiretap/wtap_opttypes.h>

#include <epan/packet_info.h>
#include <epan/proto.h>

/*
 * Structure passed to custom binary option dissectors.
 */
struct custom_binary_opt_data {
	wtap_optval_t *optval;
};

/*
 * Routine used to register frame end routine.  The routine should only
 * be registered when the dissector is used in the frame, not in the
 * proto_register_XXX function.
 */
void
register_frame_end_routine(packet_info *pinfo, void (*func)(void));
