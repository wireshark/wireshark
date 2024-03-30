/** @file
 *
 * Definitions of routines to handle command-line options to set paths
 * for directories containing personal files (configuration, saved
 * captures)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PERSFILEPATH_OPT_H
#define PERSFILEPATH_OPT_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * process command line option that affects the paths of the directories
 * used for personal files (configuration, saved captures)
 */
extern bool persfilepath_opt(int opt, const char *optstr);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PERSFILEPATH_OPT_H */
