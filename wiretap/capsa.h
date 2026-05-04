/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_CAPSA_H__
#define __W_CAPSA_H__

#include "wtap.h"

/**
 * @brief Open a Capsa file.
 *
 * Attempts to open and read the header of a Capsa file to determine if it is a valid Capsa capture file.
 *
 * @param wth Pointer to the wtap structure that will be initialized with file information.
 * @param err Pointer to an integer where any error code will be stored.
 * @param err_info Pointer to a char pointer where any error message will be stored.
 * @return A value indicating whether the file is a valid Capsa capture, not a valid Capsa capture, or an error occurred.
 */
wtap_open_return_val capsa_open(wtap *wth, int *err, char **err_info);

#endif
