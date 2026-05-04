/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __ASCENDTEXT_H__
#define __ASCENDTEXT_H__

#include "wtap.h"

/*
 * ASCEND_MAX_PKT_LEN is < WTAP_MAX_PACKET_SIZE_STANDARD, so we don't need to
 * check the packet length.
 */
#define ASCEND_MAX_DATA_ROWS 8
#define ASCEND_MAX_DATA_COLS 16
#define ASCEND_MAX_PKT_LEN (ASCEND_MAX_DATA_ROWS * ASCEND_MAX_DATA_COLS)

/**
 * @brief Opens an Ascend text file for reading.
 *
 * @param wth Pointer to a wtap structure that will be initialized with the file information.
 * @param err Pointer to an integer where any error code will be stored.
 * @param err_info Pointer to a char pointer where any error message will be stored.
 * @return wtap_open_return_val The result of opening the file, indicating success or failure.
 */
wtap_open_return_val ascend_open(wtap *wth, int *err, char **err_info);

#endif
