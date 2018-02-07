/* iseries.h
 *
 * Wiretap Library
 * Copyright (c) 2005 by Martin Warnes <martin@warnes.homeip.net>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_ISERIES_H__
#define __W_ISERIES_H__

#include <glib.h>
#include "wtap.h"

wtap_open_return_val iseries_open(wtap *wth, int *err, gchar **err_info);

#endif
