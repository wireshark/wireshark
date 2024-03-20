/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __SYSTEMD_JOURNAL_H__
#define __SYSTEMD_JOURNAL_H__

#include <glib.h>
#include "wtap.h"
#include "ws_symbol_export.h"

wtap_open_return_val systemd_journal_open(wtap *wth, int *err, char **err_info);

#endif // __SYSTEMD_JOURNAL_H__
