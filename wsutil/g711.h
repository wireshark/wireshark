/*
 * g711.h
 *
 * Definitions for routines for u-law, A-law and linear PCM conversions
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __G711_H__
#define __G711_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

WS_DLL_PUBLIC unsigned char linear2alaw( int );
WS_DLL_PUBLIC int alaw2linear( unsigned char );
WS_DLL_PUBLIC unsigned char linear2ulaw( int );
WS_DLL_PUBLIC int ulaw2linear( unsigned char );

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __G711_H__ */
