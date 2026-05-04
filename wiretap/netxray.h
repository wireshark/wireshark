/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __NETXRAY_H__
#define __NETXRAY_H__

#include "wtap.h"

/**
 * @brief Open a NetXray capture file.
 *
 * @param wth Pointer to the wtap structure that will hold the file information.
 * @param err Pointer to an integer where an error code will be stored if an error occurs.
 * @param err_info Pointer to a char pointer where an error message will be stored if an error occurs.
 * @return wtap_open_return_val The result of opening the capture file.
 */
wtap_open_return_val netxray_open(wtap *wth, int *err, char **err_info);

#endif
