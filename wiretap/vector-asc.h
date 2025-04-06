/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Support for Vector ASC CAN log file format
 * Copyright (c) 2025 by Miklos Marton <martonmiklosqdev@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef VECTOR_ASC__
#define VECTOR_ASC__

#include <wiretap/wtap.h>

wtap_open_return_val
vector_asc_open(wtap *wth, int *err, char **err_info);

#endif  /* PCAN_TRC__ */
