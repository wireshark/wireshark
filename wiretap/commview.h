/* commview.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __COMMVIEW_H__
#define __COMMVIEW_H__
#include <glib.h>
#include "ws_symbol_export.h"

wtap_open_return_val commview_open(wtap *wth, int *err, gchar **err_info _U_);
int commview_dump_can_write_encap(int encap);
gboolean commview_dump_open(wtap_dumper *wdh, int *err);

#endif /* __COMMVIEW_H__ */

