/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __COMMVIEW_H__
#define __COMMVIEW_H__
#include <glib.h>
#include "ws_symbol_export.h"
#include "wtap.h"

wtap_open_return_val commview_ncf_open(wtap *wth, int *err, char **err_info);

wtap_open_return_val commview_ncfx_open(wtap *wth, int *err, char **err_info);

#endif /* __COMMVIEW_H__ */

