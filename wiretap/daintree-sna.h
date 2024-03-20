/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __DAINTREE_SNA_H__
#define __DAINTREE_SNA_H__
#include <glib.h>
#include "wtap.h"
#include "ws_symbol_export.h"

wtap_open_return_val daintree_sna_open(wtap *wth, int *err, char **err_info _U_);

#endif /* __DAINTREE_SNA_H__ */

