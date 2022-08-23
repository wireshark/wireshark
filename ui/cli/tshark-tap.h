/** @file
 *
 * Registation tap hooks for TShark
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __TSHARK_TAP_H__
#define __TSHARK_TAP_H__

#include <epan/conversation_table.h>

extern void init_iousers(struct register_ct* ct, const char *filter);
extern void init_endpoints(struct register_ct* ct, const char *filter);
extern gboolean register_srt_tables(const void *key, void *value, void *userdata);
extern gboolean register_rtd_tables(const void *key, void *value, void *userdata);
extern gboolean register_simple_stat_tables(const void *key, void *value, void *userdata);

#endif /* __TSHARK_TAP_H__ */
