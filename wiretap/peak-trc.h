/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Support for PEAK CAN TRC log file format
 * Copyright (c) 2024 by Miklos Marton <martonmiklosqdev@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PCAN_TRC__
#define PCAN_TRC__

#include <wiretap/wtap.h>

wtap_open_return_val
peak_trc_open(wtap *wth, int *err, char **err_info);

#endif  /* PCAN_TRC__ */
