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

char* get_language_used(void);
/* XXX - This should be temporary until all UI preferences are in place */
void set_language_used(const char* lang);

extern void language_init(void);
extern void language_cleanup(void);
extern void read_language_prefs(const char* app_env_var_prefix);
extern bool write_language_prefs(const char* app_env_var_prefix, char** err_info);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* language.h */
