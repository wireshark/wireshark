/* ascend.h
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __ASCENDTEXT_H__
#define __ASCENDTEXT_H__
#include <glib.h>

/*
 * ASCEND_MAX_PKT_LEN is < WTAP_MAX_PACKET_SIZE_STANDARD, so we don't need to
 * check the packet length.
 */
#define ASCEND_MAX_DATA_ROWS 8
#define ASCEND_MAX_DATA_COLS 16
#define ASCEND_MAX_PKT_LEN (ASCEND_MAX_DATA_ROWS * ASCEND_MAX_DATA_COLS)

wtap_open_return_val ascend_open(wtap *wth, int *err, gchar **err_info);

#endif
