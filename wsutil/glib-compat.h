/** @file
*
* Definitions to provide some functions that are not present in older
* GLIB versions we support (currently down to 2.50)
*
* Wireshark - Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998 Gerald Combs
*
* SPDX-License-Identifier: GPL-2.0-or-later
*/
#ifndef GLIB_COMPAT_H
#define GLIB_COMPAT_H

#include "ws_symbol_export.h"
#include "ws_attributes.h"

#include <glib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#if !GLIB_CHECK_VERSION(2, 68, 0)
static inline gpointer
g_memdup2(gconstpointer mem, gsize byte_size)
{
  gpointer new_mem;

  if (mem && byte_size != 0) {
      new_mem = g_malloc(byte_size);
      memcpy(new_mem, mem, byte_size);
  }
  else
    new_mem = NULL;

  return new_mem;
}
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* GLIB_COMPAT_H */
