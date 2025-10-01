/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WS_ROUNDUP_H__
#define __WS_ROUNDUP_H__

/*
 * Round up to various powers of 2.
 */

/**
 * @def WS_ROUNDUP_2
 * @brief Round up to the next multiple of 2.
 * @param n Value to round up.
 * @return Rounded-up value aligned to 2 bytes.
 */
#define WS_ROUNDUP_2(n) (((n) + ((unsigned)(2U-1U))) & (~((unsigned)(2U-1U))))

/**
 * @def WS_ROUNDUP_4
 * @brief Round up to the next multiple of 4.
 * @param n Value to round up.
 * @return Rounded-up value aligned to 4 bytes.
 */
#define WS_ROUNDUP_4(n) (((n) + ((unsigned)(4U-1U))) & (~((unsigned)(4U-1U))))

/**
 * @def WS_ROUNDUP_8
 * @brief Round up to the next multiple of 8.
 * @param n Value to round up.
 * @return Rounded-up value aligned to 8 bytes.
 */
#define WS_ROUNDUP_8(n) (((n) + ((unsigned)(8U-1U))) & (~((unsigned)(8U-1U))))

/**
 * @def WS_ROUNDUP_16
 * @brief Round up to the next multiple of 16.
 * @param n Value to round up.
 * @return Rounded-up value aligned to 16 bytes.
 */
#define WS_ROUNDUP_16(n) (((n) + ((unsigned)(16U-1U))) & (~((unsigned)(16U-1U))))

/**
 * @def WS_ROUNDUP_32
 * @brief Round up to the next multiple of 32.
 * @param n Value to round up.
 * @return Rounded-up value aligned to 32 bytes.
 */
#define WS_ROUNDUP_32(n) (((n) + ((unsigned)(32U-1U))) & (~((unsigned)(32U-1U))))


#endif /* __WS_ROUNDUP_H__ */
