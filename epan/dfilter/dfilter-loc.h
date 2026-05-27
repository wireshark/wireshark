
/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DFILTER_LOC_H
#define DFILTER_LOC_H

#include <stddef.h>

/**
 * @brief Represents a location (column start and length) within a display filter string.
 */
typedef struct _dfilter_loc {
    long   col_start; /**< Starting column offset of the location (may be negative to indicate an unset/invalid position). */
    size_t col_len;   /**< Number of columns (characters) spanned by the location. */
} df_loc_t;

extern df_loc_t loc_empty;

#define DFILTER_LOC_EMPTY loc_empty

#endif
