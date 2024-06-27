/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998-2010 by Tom Alexander <talexander@ixiacom.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __VWR_H__
#define __VWR_H__

#include "ws_symbol_export.h"
#include "wtap.h"

wtap_open_return_val vwr_open(wtap *wth, int *err, char **err_info);

#endif
