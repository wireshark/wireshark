/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Support for RTPDump file format
 * Copyright (c) 2023 by David Perry <boolean263@protonmail.com
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RTPDUMP_H__
#define RTPDUMP_H__

#include <wiretap/wtap.h>

wtap_open_return_val

/**
 * @brief Opens an RTP dump file for reading.
 *
 * @param wth Pointer to a wtap structure representing the capture file.
 * @param err Pointer to an integer that will be set to an error code if an error occurs.
 * @param err_info Pointer to a char pointer that will be set to an error message if an error occurs.
 * @return int WTAP_OPEN_MINE if the file is recognized as an RTP dump file, otherwise an appropriate error code.
 */
rtpdump_open(wtap *wth, int *err, char **err_info);

#endif  /* RTPDUMP_H__ */
