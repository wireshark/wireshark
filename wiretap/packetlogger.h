/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKETLOGGER_H__
#define __PACKETLOGGER_H__

#include <glib.h>
#include "wtap.h"

wtap_open_return_val packetlogger_open(wtap *wth, int *err, char **err_info _U_);

#endif /* __PACKETLOGGER_H__ */

