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

tvbuff_t *
base64_to_tvb(tvbuff_t *parent, const char *base64)
{
  tvbuff_t *tvb;
  char *data;
  gsize len;

  data = g_base64_decode(base64, &len);
  tvb = tvb_new_child_real_data(parent, (const guint8 *)data, (gint)len, (gint)len);

  tvb_set_free_cb(tvb, g_free);

  return tvb;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
