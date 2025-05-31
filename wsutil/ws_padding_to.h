/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WS_PADDING_TO_H__
#define __WS_PADDING_TO_H__

/*
 * Amount needed to pad to various powers of 2.
 */
#define WS_PADDING_TO_2(n) ((2U - ((n) % 2U)) % 2U)
#define WS_PADDING_TO_4(n) ((4U - ((n) % 4U)) % 4U)
#define WS_PADDING_TO_8(n) ((8U - ((n) % 8U)) % 8U)
#define WS_PADDING_TO_16(n) ((16U - ((n) % 16U)) % 16U)
#define WS_PADDING_TO_32(n) ((32U - ((n) % 32U)) % 32U)

#endif /* __WS_PADDING_TO_H__ */
