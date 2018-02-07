/* cosine.h
 *
 * CoSine IPNOS L2 debug output parsing
 * Copyright (c) 2002 by Motonori Shindo <motonori@shin.do>
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __W_COSINE_H__
#define __W_COSINE_H__
#include <glib.h>
#include "wtap.h"
#include "ws_symbol_export.h"

wtap_open_return_val cosine_open(wtap *wth, int *err, gchar **err_info);

#endif
