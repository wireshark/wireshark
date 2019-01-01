/* clopts_common.h
 * Handle command-line arguments common to various programs
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __UI_CLOPTS_COMMON_H__
#define __UI_CLOPTS_COMMON_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

extern int
get_natural_int(const char *string, const char *name);

extern int
get_positive_int(const char *string, const char *name);

extern guint32
get_guint32(const char *string, const char *name);

extern guint32
get_nonzero_guint32(const char *string, const char *name);

extern double
get_positive_double(const char *string, const char *name);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UI_CLOPTS_COMMON_H__ */
