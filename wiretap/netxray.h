/* netxray.h
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __NETXRAY_H__
#define __NETXRAY_H__

#include <glib.h>
#include "wtap.h"

wtap_open_return_val netxray_open(wtap *wth, int *err, gchar **err_info);
int netxray_dump_can_write_encap_1_1(int encap);
gboolean netxray_dump_open_1_1(wtap_dumper *wdh, int *err);
int netxray_dump_can_write_encap_2_0(int encap);
gboolean netxray_dump_open_2_0(wtap_dumper *wdh, int *err);

#endif
