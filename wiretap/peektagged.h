/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_PEEKTAGGED_H__
#define __W_PEEKTAGGED_H__
#include <glib.h>
#include "ws_symbol_export.h"
#include "wtap.h"

wtap_open_return_val peektagged_open(wtap *wth, int *err, char **err_info);

#endif
