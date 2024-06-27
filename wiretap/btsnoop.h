/** @file
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
#include "wtap.h"

wtap_open_return_val btsnoop_open(wtap *wth, int *err, char **err_info);

#endif
