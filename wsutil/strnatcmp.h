/* strnatcmp.h
 *
 * Original code downloaded from: http://sourcefrog.net/projects/natsort/

  strnatcmp.c -- Perform 'natural order' comparisons of strings in C.
  Copyright (C) 2000, 2004 by Martin Pool <mbp sourcefrog net>

  SPDX-License-Identifier: Zlib
 */

#ifndef STRNATCMP_H
#define STRNATCMP_H

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* CUSTOMIZATION SECTION
 *
 * You can change this typedef, but must then also change the inline
 * functions in strnatcmp.c */
typedef char nat_char;

WS_DLL_PUBLIC int ws_ascii_strnatcmp(nat_char const *a, nat_char const *b);
WS_DLL_PUBLIC int ws_ascii_strnatcasecmp(nat_char const *a, nat_char const *b);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* STRNATCMP_H */
