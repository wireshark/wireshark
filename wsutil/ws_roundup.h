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
#define WS_ROUNDUP_2(n) (((n) + ((guint)(2U-1U))) & (~((guint)(2U-1U))))
#define WS_ROUNDUP_4(n) (((n) + ((guint)(4U-1U))) & (~((guint)(4U-1U))))
#define WS_ROUNDUP_8(n) (((n) + ((guint)(8U-1U))) & (~((guint)(8U-1U))))
#define WS_ROUNDUP_16(n) (((n) + ((guint)(16U-1U))) & (~((guint)(16U-1U))))
#define WS_ROUNDUP_32(n) (((n) + ((guint)(32U-1U))) & (~((guint)(32U-1U))))

#endif /* __WS_ROUNDUP_H__ */
