/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998-2010 by Tom Alexander <talexander@ixiacom.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __VWR_H__
#define __VWR_H__

#include "ws_symbol_export.h"
#include "wtap.h"

/**
 * @brief Opens a VWR file.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Pointer to an integer that will be set to an error code if an error occurs.
 * @param err_info Pointer to a string that will be set to an error message if an error occurs.
 * @return wtap_open_return_val The result of opening the file, indicating success or failure.
 */
wtap_open_return_val vwr_open(wtap *wth, int *err, char **err_info);

#endif
