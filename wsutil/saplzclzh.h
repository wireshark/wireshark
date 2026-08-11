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


/**
 * @brief Returns a human-readable error string for a given return code.
 *
 * This function takes an integer return code from the SAP LZC/LZH decompression routines
 * and returns a corresponding human-readable error string. It helps in understanding the nature
 * of the error encountered during decompression.
 *
 * @param return_code The integer return code from the decompression routine.
 * @return A constant character pointer to the error string corresponding to the return code.
 */
WS_DLL_PUBLIC const char *sap_lzclzh_decompress_error_string(int return_code);


/**
 * @brief Decompresses data compressed with SAP LZC/LZH algorithms.
 *
 * This function decompresses data that has been compressed using the SAP LZC or LZH algorithms.
 * It takes an input buffer containing the compressed data, its length, and an output buffer to
 * store the decompressed data. The function also requires a memory allocator for managing memory
 * during decompression.
 *
 * @param wmem_scope A pointer to a memory allocator for managing memory during decompression.
 * @param in A pointer to the input buffer containing the compressed data.
 * @param in_length The length of the input buffer.
 * @param out A pointer to the output buffer where the decompressed data will be stored.
 * @param out_length A pointer to a variable that holds the size of the output buffer.
 *                  On return, it will contain the actual length of the decompressed data.
 * @return An integer return code indicating the result of the decompression operation.
 */
WS_DLL_PUBLIC int sap_lzclzh_decompress(wmem_allocator_t *wmem_scope, const guint8 *in, gint in_length, guint8 *out, guint *out_length);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __SAPLZCLZH_H__ */
