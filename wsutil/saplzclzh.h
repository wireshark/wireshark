/* saplzclzh.h
 * Routines for decompression with SAP LZC/LZH algorithms
 * Copyright 2022, Martin Gallo <martin.gallo [AT] gmail.com>
 * Code contributed by SecureAuth Corp.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef __SAPLZCLZH_H__
#define __SAPLZCLZH_H__

#include <wireshark.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* SAP LZC/LZH Decompression routine return codes */
#define CS_END_INBUFFER          3
#define CS_END_OUTBUFFER         2
#define CS_END_OF_STREAM         1
#define CS_OK                    0

#define CS_IEND_OF_STREAM       -1
#define CS_IEND_OUTBUFFER       -2
#define CS_IEND_INBUFFER        -3

#define CS_E_OUT_BUFFER_LEN    -10
#define CS_E_IN_BUFFER_LEN     -11
#define CS_E_NOSAVINGS         -12
#define CS_E_INVALID_SUMLEN    -13
#define CS_E_IN_EQU_OUT        -14
#define CS_E_INVALID_ADDR      -15
#define CS_E_FATAL             -19
#define CS_E_BOTH_ZERO         -20
#define CS_E_UNKNOWN_ALG       -21
#define CS_E_UNKNOWN_TYPE      -22

#define CS_E_FILENOTCOMPRESSED -50
#define CS_E_MAXBITS_TOO_BIG   -51
#define CS_E_BAD_HUF_TREE      -52
#define CS_E_NO_STACKMEM       -53
#define CS_E_INVALIDCODE       -54
#define CS_E_BADLENGTH         -55

#define CS_E_STACK_OVERFLOW    -60
#define CS_E_STACK_UNDERFLOW   -61

#define CS_NOT_INITIALIZED     -71

/* Return code for memory errors */
#define SAP_LZC_LZH_CS_E_MEMORY_ERROR -99

WS_DLL_PUBLIC const char *sap_lzclzh_decompress_error_string(int return_code);

/* SAP LZC/LZH Decompression routine */
WS_DLL_PUBLIC int sap_lzclzh_decompress(wmem_allocator_t *wmem_scope, const guint8 *in, gint in_length, guint8 *out, guint *out_length);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __SAPLZCLZH_H__ */
