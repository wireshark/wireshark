/* atm.h
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __ATM_H__
#define __ATM_H__
#include <glib.h>
#include "ws_symbol_export.h"

/*
 * Routines to use with ATM capture file types that don't include information
 * about the *type* of ATM traffic (or, at least, where we haven't found
 * that information).
 */

extern void
atm_guess_traffic_type(wtap_rec *rec, const guint8 *pd);

extern void
atm_guess_lane_type(wtap_rec *rec, const guint8 *pd);

#endif /* __ATM_H__ */
