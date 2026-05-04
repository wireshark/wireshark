/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __NGSNIFFER_H__
#define __NGSNIFFER_H__

#include "wtap.h"

/**
 * @brief Open a file using the NGSniffer format.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Error code if an error occurs.
 * @param err_info Error information if an error occurs.
 * @return wtap_open_return_val The result of opening the file.
 */
wtap_open_return_val ngsniffer_open(wtap *wth, int *err, char **err_info);

#endif
