/* ngsniffer.h
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __NGSNIFFER_H__
#define __NGSNIFFER_H__

#include <glib.h>
#include "wtap.h"

wtap_open_return_val ngsniffer_open(wtap *wth, int *err, gchar **err_info);
gboolean ngsniffer_dump_open(wtap_dumper *wdh, int *err);
int ngsniffer_dump_can_write_encap(int encap);

#endif
