/** @file
 *
 * Copyright 2014, Michal Labedzki for Tieto Corporation
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __LANGUAGE_H__
#define __LANGUAGE_H__

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define USE_SYSTEM_LANGUAGE	"system"

extern char *language;

extern void read_language_prefs(void);
extern bool write_language_prefs(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* language.h */
