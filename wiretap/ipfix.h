/** @file
 *
 * Wiretap Library
 * Copyright (c) 2010 by Hadriel Kaplan <hadrielk@yahoo.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_IPFIX_H__
#define __W_IPFIX_H__

#include "wtap.h"

/**
 * @brief Opens an IPFIX file for reading.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Error code if an error occurs.
 * @param err_info Error information if an error occurs.
 * @return wtap_open_return_val The result of opening the file.
 */
wtap_open_return_val ipfix_open(wtap *wth, int *err, char **err_info);

#endif
