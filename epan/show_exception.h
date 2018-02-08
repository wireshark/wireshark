/* show_exception.h
 *
 * Routines to put exception information into the protocol tree
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Called to register the pseudo-protocols used for exceptions.
 */
void register_show_exception(void);

/*
 * Routine used to add an indication of an arbitrary exception to the tree.
 */
WS_DLL_PUBLIC
void show_exception(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    unsigned long exception, const char *exception_message);

/*
 * Routine used to add an indication of a ReportedBoundsError exception
 * to the tree.
 */
void
show_reported_bounds_error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
