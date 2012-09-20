/* wspy_proto.c
 *
 * $Id$
 *
 * Wireshark Protocol Python Binding
 *
 * Copyright (c) 2009 by Sebastien Tandel <sebastien [AT] tandel [dot] be>
 * Copyright (c) 2001 by Gerald Combs <gerald@wireshark.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#ifdef HAVE_PYTHON
#include <Python.h>

#include <glib.h>

#include <stdio.h>

#include "proto.h"


hf_register_info *hf_register_info_create(const guint8 size)
{
  hf_register_info *hf = g_malloc0(sizeof(hf_register_info) * size);

  /**STA TODO :
   * if (!hf_register_info)
   *  raise exception
   */

  return hf;
}

void hf_register_info_destroy(hf_register_info *hf)
{
  if (hf) {
    g_free(hf);
  }
}

void hf_register_info_add(hf_register_info *hf, guint8 index,
          int *p_id, const char *name, const char *abbrev,
          enum ftenum type, int display, const void *strings,
          guint32 bitmask, const char *blurb)
{
  hf[index].p_id = p_id;
  hf[index].hfinfo.name = name;
  hf[index].hfinfo.abbrev = abbrev;
  hf[index].hfinfo.type = type;
  hf[index].hfinfo.display = display;
  hf[index].hfinfo.strings = strings;
  hf[index].hfinfo.bitmask = bitmask;
  hf[index].hfinfo.blurb = blurb;
  hf[index].hfinfo.id = 0;
  hf[index].hfinfo.parent = 0;
  hf[index].hfinfo.ref_type = HF_REF_TYPE_NONE;
  hf[index].hfinfo.bitshift = 0;
  hf[index].hfinfo.same_name_next = NULL;
  hf[index].hfinfo.same_name_prev = NULL;
}

void hf_register_info_print(hf_register_info *hf, guint8 size)
{
  guint8 c;
  if (!hf)
    return;

  for (c = 0; c < size; c++) {
    printf("%s : %s : %s\n", hf[c].hfinfo.name,
                             hf[c].hfinfo.abbrev,
                             hf[c].hfinfo.blurb);
  }
}

#endif /* HAVE_PYTHON */
