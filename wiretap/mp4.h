/** @file
 *
 * MP4 (ISO/IEC 14496-12) file format decoder for the Wiretap library.
 *
 * Wiretap Library
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_MP4_H__
#define __W_MP4_H__

#include "wtap.h"

wtap_open_return_val mp4_open(wtap *wth, int *err, char **err_info);

#endif
