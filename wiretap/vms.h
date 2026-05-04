/** @file
 *
 * Wiretap Library
 * Copyright (c) 2001 by Marc Milgram <ethereal@mmilgram.NOSPAMmail.net>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __W_VMS_H__
#define __W_VMS_H__

#include "wtap.h"

/**
 * @brief Opens a VMS file for reading.
 *
 * @param wth Pointer to the wtap structure that will hold the file information.
 * @param err Pointer to an integer where any error code will be stored.
 * @param err_info Pointer to a char pointer where any error message will be stored.
 * @return wtap_open_return_val The result of opening the file, indicating success or failure.
 */
wtap_open_return_val vms_open(wtap *wth, int *err, char **err_info);

#endif
