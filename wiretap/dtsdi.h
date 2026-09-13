/* dtsdi.h
 *
 * DekTec DTSDI file reader.
 *
 * Copyright (c) 2026, Devin Heitmueller <dheitmueller@ltnglobal.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_DTSDI_H__
#define __W_DTSDI_H__

#include "wtap.h"

wtap_open_return_val dtsdi_open(wtap *wth, int *err, char **err_info);

#endif
