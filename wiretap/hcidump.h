/** @file
 *
 * Copyright (c) 2003 by Marcel Holtmann <marcel@holtmann.org>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __HCIDUMP_H__
#define __HCIDUMP_H__

#include <glib.h>
#include "wtap.h"
#include "ws_symbol_export.h"

wtap_open_return_val hcidump_open(wtap *wth, int *err, char **err_info);

#endif
