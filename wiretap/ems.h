/** @file
 *
 * EMS file format decoder for the Wiretap library.
 *
 * Copyright (c) 2023 by Timo Warns <timo.warns@gmail.com>
 *
 * Wiretap Library
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_EMS_H__
#define __W_EMS_H__

#include "wtap.h"

wtap_open_return_val ems_open(wtap *wth, int *err, char **err_info);

#endif
