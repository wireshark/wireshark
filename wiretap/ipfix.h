/** @file
 *
 * Wiretap Library
 * Copyright (c) 2010 by Hadriel Kaplan <hadrielk@yahoo.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_IPFIX_H__
#define __W_IPFIX_H__

#include <glib.h>
#include "wtap.h"
#include "ws_symbol_export.h"

wtap_open_return_val ipfix_open(wtap *wth, int *err, char **err_info);

#endif
