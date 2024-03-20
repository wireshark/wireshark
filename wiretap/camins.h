/** @file
 *
 * File format support for Rabbit Labs CAM Inspector files
 * Copyright (c) 2013 by Martin Kaiser <martin@kaiser.cx>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _CAMINS_H
#define _CAMINS_H

#include <glib.h>
#include <wiretap/wtap.h>

wtap_open_return_val camins_open(wtap *wth, int *err, char **err_info _U_);

#endif /* _CAMINS_H */
