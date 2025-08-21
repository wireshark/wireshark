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

wtap_open_return_val i4btrace_open(wtap *wth, int *err, char **err_info);

#endif
