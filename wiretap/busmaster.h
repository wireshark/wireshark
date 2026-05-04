/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Support for Busmaster log file format
 * Copyright (c) 2019 by Maksim Salau <maksim.salau@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef BUSMASTER_H__
#define BUSMASTER_H__

#include <wiretap/wtap.h>

/**
 * @brief Opens a file using the Busmaster log reader.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Pointer to an integer that will hold any error code.
 * @param err_info Pointer to a string that will hold any error information.
 * @return int WTAP_OPEN_OK if successful, otherwise an error code.
 */
wtap_open_return_val
busmaster_open(wtap *wth, int *err, char **err_info);

#endif  /* BUSMASTER_H__ */
