/*
* Provide some functions that are not present in older
* GLIB versions (down to 2.22)
*
* Wireshark - Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998 Gerald Combs
*
* SPDX-License-Identifier: GPL-2.0-or-later
*/
#include "config.h"

#include <glib.h>
#include <string.h>

#include "glib-compat.h"
#if !GLIB_CHECK_VERSION(2, 68, 0)
/**
* g_memdup2:
* mem: the memory to copy
* byte_size: the number of bytes to copy.
*
* Allocates byte_size bytes of memory, and copies byte_size bytes into it from mem . If mem is NULL it returns NULL.
*
* This replaces g_memdup(), which was prone to integer overflows when converting the argument from a gsize to a guint.
*
* Since: 2.68
**/
gpointer
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
