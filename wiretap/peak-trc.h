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

/**
 * @brief Opens a PCAN-TRC file for reading.
 *
 * @param wth Pointer to the wtap structure that will hold the file information.
 * @param err Pointer to an integer where any error code will be stored.
 * @param err_info Pointer to a char pointer where any error message will be stored.
 * @return wtap_open_return_val The result of the open operation.
 */
wtap_open_return_val
peak_trc_open(wtap *wth, int *err, char **err_info);

#endif  /* PCAN_TRC__ */
