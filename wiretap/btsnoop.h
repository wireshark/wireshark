/* btsnoop.h
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_BTSNOOP_H__
#define __W_BTSNOOP_H__
#include <glib.h>
#include "ws_symbol_export.h"

wtap_open_return_val btsnoop_open(wtap *wth, int *err, gchar **err_info);
gboolean btsnoop_dump_open_h1(wtap_dumper *wdh, int *err);
gboolean btsnoop_dump_open_h4(wtap_dumper *wdh, int *err);
int btsnoop_dump_can_write_encap(int encap);

#endif
