/** @file
 *
 * Routines to print various "standard" failure messages used in multiple
 * places
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __FAILURE_MESSAGE_H__
#define __FAILURE_MESSAGE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Register those routines with the report_message mechanism.
 */
extern void init_report_failure_message(const char *friendly_program_name);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FAILURE_MESSAGE_H__ */
