/** @file
 *
 * Routines to put up various "standard" alert boxes used in multiple
 * places
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __ALERT_BOX_H__
#define __ALERT_BOX_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Register these routines with the report_message mechanism.
 */
extern void init_report_alert_box(const char *friendly_program_name);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __ALERT_BOX_H__ */
