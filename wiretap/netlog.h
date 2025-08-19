/** @file
 *
 * Wiretap Library
 * Copyright (c) 2025 by Moshe Kaplan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __NETLOG_H__
#define __NETLOG_H__

#include "wtap.h"

wtap_open_return_val netlog_open(wtap *wth, int *err, char **err_info);

#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
