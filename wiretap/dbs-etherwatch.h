/* dbs-etherwatch.h
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __W_DBS_ETHERWATCH_H__
#define __W_DBS_ETHERWATCH_H__
#include <glib.h>
#include "wtap.h"
#include "ws_symbol_export.h"

wtap_open_return_val dbs_etherwatch_open(wtap *wth, int *err, gchar **err_info);

#endif
