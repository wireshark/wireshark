/** @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __ATM_H__
#define __ATM_H__

#include "wtap.h"

/*
 * Routines to use with ATM capture file types that don't include information
 * about the *type* of ATM traffic (or, at least, where we haven't found
 * that information).
 */

/**
 * @brief Guesses the ATM traffic type based on the packet data.
 *
 * @param rec Pointer to the wtap_rec structure containing the packet data.
 */
extern void
atm_guess_traffic_type(wtap_rec *rec);

/**
 * @brief Guesses the lane type based on the packet data.
 *
 * @param rec Pointer to the wtap_rec structure containing the packet data.
 */
extern void
atm_guess_lane_type(wtap_rec *rec);

#endif /* __ATM_H__ */
