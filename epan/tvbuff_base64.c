/* tvbuff_base64.c
 * Base-64 tvbuff implementation (based on real tvb)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include <epan/tvbuff.h>
#include <wsutil/base64.h>

tvbuff_t *
base64_to_tvb(tvbuff_t *parent, const char *base64)
{
  tvbuff_t *tvb;
  char *data = g_strdup(base64);
  gint len;

  len = (gint) ws_base64_decode_inplace(data);
  tvb = tvb_new_child_real_data(parent, (const guint8 *)data, len, len);

  tvb_set_free_cb(tvb, g_free);

  return tvb;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
