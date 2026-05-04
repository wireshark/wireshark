/** @file
 *
 * MPEG file format decoder for the Wiretap library.
 * Written by Shaun Jackman <sjackman@gmail.com>
 * Copyright 2007 Shaun Jackman
 *
 * Wiretap Library
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_MPEG_H__
#define __W_MPEG_H__

#include "wtap.h"

/**
 * @brief Open a MPEG file.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Error code if an error occurs.
 * @param err_info Error information if an error occurs.
 * @return wtap_open_return_val The result of opening the file.
 */
wtap_open_return_val mpeg_open(wtap *wth, int *err, char **err_info);

#endif
