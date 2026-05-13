/** @file
 *
 * Routines to put exception information into the protocol tree
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include <epan/proto.h>

/**
 * @brief Registers exception handling routines.
 *
 * Called to register the pseudo-protocols used for exceptions
 */
void register_show_exception(void);

/**
 * @brief Routine used to add an indication of an arbitrary exception to the tree.
 *
 * @param tvb The current tvbuff_t structure.
 * @param pinfo The current packet_info structure.
 * @param tree The protocol tree to add the exception indication to.
 * @param exception The exception code.
 * @param exception_message The message describing the exception.
 */
WS_DLL_PUBLIC
void show_exception(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    unsigned long exception, const char *exception_message);

/**
 * @brief Routine used to add an indication of a ReportedBoundsError exception to the tree.
 *
 * @param tvb The TVB containing the data to be analyzed.
 * @param pinfo Packet information structure.
 * @param tree Protocol tree for displaying the error.
 */
WS_DLL_PUBLIC void
show_reported_bounds_error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
