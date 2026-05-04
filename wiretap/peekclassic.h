/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __W_PEEKCLASSIC_H__
#define __W_PEEKCLASSIC_H__

#include "wtap.h"

/**
 * @brief Opens a file in the Peek Classic format.
 *
 * @param wth Pointer to the wtap structure that will be populated with file information.
 * @param err Pointer to an integer where any error codes will be stored.
 * @param err_info Pointer to a char pointer where any error messages will be stored.
 * @return A value indicating whether the file is in the Peek Classic format, not recognized, or if an error occurred.
 */
wtap_open_return_val peekclassic_open(wtap *wth, int *err, char **err_info);

#endif
