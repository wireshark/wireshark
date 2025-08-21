/** @file
 *
 * Copyright (c) 2000 by Mike Hall <mlh@io.com>
 * Copyright (c) Cisco Systems
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __CSIDS_H__
#define __CSIDS_H__

#include "wtap.h"

wtap_open_return_val csids_open(wtap *wth, int *err, char **err_info);

#endif
