/** @file
 *
 * Wiretap Library
 * Copyright (c) 1999 by Bert Driehuis <driehuis@playbeing.org>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef __I4BTRACE_H__
#define __I4BTRACE_H__

#include "wtap.h"

/**
 * @brief Open an I4B trace file.
 *
 * @param wth Pointer to the wtap structure.
 * @param err Error code if opening fails.
 * @param err_info Error message if opening fails.
 * @return wtap_open_return_val Return value indicating success or failure.
 */
wtap_open_return_val i4btrace_open(wtap *wth, int *err, char **err_info);

#endif
