/* catapult_dct2000.h
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_CAT_DCT2K_H__
#define __W_CAT_DCT2K_H__

#include <glib.h>
#include "ws_symbol_export.h"

wtap_open_return_val catapult_dct2000_open(wtap *wth, int *err, gchar **err_info);
gboolean catapult_dct2000_dump_open(wtap_dumper *wdh, int *err);
int catapult_dct2000_dump_can_write_encap(int encap);

#define DCT2000_ENCAP_UNHANDLED 0
#define DCT2000_ENCAP_SSCOP     101
#define DCT2000_ENCAP_MTP2      102
#define DCT2000_ENCAP_NBAP      103

#endif

