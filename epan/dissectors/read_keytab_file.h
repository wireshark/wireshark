/* read_keytab_file.h
 * Routines for reading Kerberos keytab files
 * Copyright 2007, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __READ_KEYTAB_FILE_H
#define __READ_KEYTAB_FILE_H

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

WS_DLL_PUBLIC
void read_keytab_file(const char *);

WS_DLL_PUBLIC
void read_keytab_file_from_preferences(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  /* __READ_KEYTAB_FILE_H */
