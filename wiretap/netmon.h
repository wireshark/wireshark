/* netmon.h
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __NETMON_H__
#define __NETMON_H__

#include <glib.h>
#include "wtap.h"

wtap_open_return_val netmon_open(wtap *wth, int *err, gchar **err_info);
gboolean netmon_dump_open(wtap_dumper *wdh, int *err);
int netmon_dump_can_write_encap_1_x(int encap);
int netmon_dump_can_write_encap_2_x(int encap);

#endif
