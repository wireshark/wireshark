/** @file
 *
 * File format support for Micropross mplog files
 * Copyright (c) 2016 by Martin Kaiser <martin@kaiser.cx>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _MPLOG_H
#define _MPLOG_H

#include <glib.h>
#include <wiretap/wtap.h>

wtap_open_return_val mplog_open(wtap *wth, int *err, char **err_info);

#endif /* _MPLOG_H */
