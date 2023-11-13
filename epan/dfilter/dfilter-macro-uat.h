/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _DFILTER_MACRO_UAT_H
#define _DFILTER_MACRO_UAT_H

#define DFILTER_MACRO_FILENAME "dfilter_macros"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * This file is only used to migrate the dfilter_macros UAT file to the
 * new "dmacros" configuration file. It should be removed eventually.
 */

void convert_old_uat_file(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _DFILTER_MACRO_UAT_H */
