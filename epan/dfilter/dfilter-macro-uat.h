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

/**
 * @brief One-shot migration helper for the legacy dfilter_macros UAT file.
 *
 * Reads the old UAT-based macro definitions and writes them to the new
 * "dmacros" configuration file format. This translation unit exists solely
 * for that migration path and should be removed once the transition period
 * has ended.
 *
 * @param app_env_var_prefix Application environment-variable prefix used
 *        to locate the legacy UAT file (e.g. "WIRESHARK" or "STRATOSHARK").
 */
void convert_old_uat_file(const char* app_env_var_prefix);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _DFILTER_MACRO_UAT_H */
