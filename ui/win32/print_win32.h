/* print_mswin.h
 * Printing support for MSWindows
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2002, Jeffrey C. Foster <jfoste@woodward.com>
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef __PRINT_MSWIN_H__
#define __PRINT_MSWIN_H__

/** @file
 * Win32 specific printing.
 */

/** Print the given file.
 *
 * @param file_name the file to print
 */
void print_mswin(const char *file_name);

#endif
