/* file-file.h
 *
 * Top-most file dissector. Decides dissector based on Filetap Encapsulation Type.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ws_symbol_export.h"

/*
 * Routine used to register file record end routine.  The routine should only
 * be registred when the dissector is used in the file record, not in the
 * proto_register_XXX function.
 */
void
register_file_record_end_routine(packet_info *pinfo, void (*func)(void));
