/* k12.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_K12_H__
#define __W_K12_H__

#include <glib.h>
#include "wtap.h"

wtap_open_return_val k12_open(wtap *wth, int *err, gchar **err_info);
int k12_dump_can_write_encap(int encap);
gboolean k12_dump_open(wtap_dumper *wdh, int *err);
wtap_open_return_val k12text_open(wtap *wth, int *err, gchar **err_info _U_);
int k12text_dump_can_write_encap(int encap);
gboolean k12text_dump_open(wtap_dumper *wdh, int *err);

#endif

