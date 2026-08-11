/* saplzclzh.c
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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <glib.h>

#include <wsutil/wmem/wmem.h>

#include "saplzclzh.h"
#include "saplzclzh/csdecompr.h"


/* Returns an error strings for compression library return codes */
const char *sap_lzclzh_decompress_error_string(int return_code)
{
	switch (return_code){
		case CS_IEND_OF_STREAM: return ("CS_IEND_OF_STREAM: end of data (internal)");
		case CS_IEND_OUTBUFFER: return ("CS_IEND_OUTBUFFER: end of output buffer");
		case CS_IEND_INBUFFER: return ("CS_IEND_INBUFFER: end of input buffer");
		case CS_E_OUT_BUFFER_LEN: return ("CS_E_OUT_BUFFER_LEN: invalid output length");
		case CS_E_IN_BUFFER_LEN: return ("CS_E_IN_BUFFER_LEN: invalid input length");
		case CS_E_NOSAVINGS: return ("CS_E_NOSAVINGS: no savings");
		case CS_E_INVALID_SUMLEN: return ("CS_E_INVALID_SUMLEN: invalid len of stream");
		case CS_E_IN_EQU_OUT: return ("CS_E_IN_EQU_OUT: inbuf == outbuf");
		case CS_E_INVALID_ADDR: return ("CS_E_INVALID_ADDR: inbuf == NULL,outbuf == NULL");
		case CS_E_FATAL: return ("CS_E_FATAL: internal error !");
		case CS_E_BOTH_ZERO: return ("CS_E_BOTH_ZERO: inlen = outlen = 0");
		case CS_E_UNKNOWN_ALG: return ("CS_E_UNKNOWN_ALG: unknown algorithm");
		case CS_E_UNKNOWN_TYPE: return ("CS_E_UNKNOWN_TYPE: unknown type");
		/* for decompress */
		case CS_E_FILENOTCOMPRESSED: return ("CS_E_FILENOTCOMPRESSED: input not compressed");
		case CS_E_MAXBITS_TOO_BIG: return ("CS_E_MAXBITS_TOO_BIG: maxbits to large");
		case CS_E_BAD_HUF_TREE: return ("CS_E_BAD_HUF_TREE: bad hufman tree");
		case CS_E_NO_STACKMEM: return ("CS_E_NO_STACKMEM: no stack memory in decomp");
		case CS_E_INVALIDCODE: return ("CS_E_INVALIDCODE: invalid code");
		case CS_E_BADLENGTH: return ("CS_E_BADLENGTH: bad lengths");
		case CS_E_STACK_OVERFLOW: return ("CS_E_STACK_OVERFLOW: stack overflow in decomp");
		case CS_E_STACK_UNDERFLOW: return ("CS_E_STACK_UNDERFLOW: stack underflow in decomp");
		/* only Windows */
		case CS_NOT_INITIALIZED: return ("CS_NOT_INITIALIZED: storage not allocated");
		/* non error return codes */
		case CS_END_INBUFFER: return ("CS_END_INBUFFER: end of input buffer");
		case CS_END_OUTBUFFER: return ("CS_END_OUTBUFFER: end of output buffer");
		case CS_END_OF_STREAM: return ("CS_END_OF_STREAM: end of data");
		/* custom error */
		case SAP_LZC_LZH_CS_E_MEMORY_ERROR: return ("CS_E_MEMORY_ERROR: custom memory error");
		/* unknown error */
		default: return ("unknown error");
	}
}


int sap_lzclzh_decompress(wmem_allocator_t *wmem_scope, const guint8 *in, gint in_length, guint8 *out, guint *out_length)
{
	CSHDL *csObject = NULL;
	int rt = 0;
	SAP_BYTE *bufin = NULL, *bufout = NULL, *bufin_pos = NULL, *bufout_pos = NULL;
	SAP_BYTE padding[2] = { 0, 0 };
	SAP_INT bufin_rest = 0, bufout_length = 0, bufout_rest = 0, internal_bufout_length = 0, bytes_read = 0, bytes_decompressed = 0, total_decompressed = 0;
	SAP_INT algorithm = 0;
	SAP_INT option = CS_INIT_DECOMPRESS;
	guint32 expected_out_length = 0;
	bool have_expected_out_length = false;
	bool used_padding = false;

	/* Check for invalid inputs */
	if (in == NULL)
		return (CS_E_INVALID_ADDR);
	if (in_length <= 0)
		return (CS_E_IN_BUFFER_LEN);
	if (out == NULL)
		return (CS_E_INVALID_ADDR);
	if (out_length == NULL)
		return (CS_E_INVALID_ADDR);
	if (*out_length <= 0)
		return (CS_E_OUT_BUFFER_LEN);
	if (*out_length >= G_MAXINT)
		return (CS_E_OUT_BUFFER_LEN);

	csObject = wmem_new0(wmem_scope, CSHDL);
	if (!csObject){
		return (SAP_LZC_LZH_CS_E_MEMORY_ERROR);
	}

	/* Allocate buffers */
	bufin = (SAP_BYTE*) wmem_alloc0(wmem_scope, in_length);
	if (!bufin){
		wmem_free(wmem_scope, csObject);
		return (SAP_LZC_LZH_CS_E_MEMORY_ERROR);
	}

	/* Copy the in parameter into the buffer */
	for (int i = 0; i < in_length; i++) {
		bufin[i] = (SAP_BYTE) in[i];
	}
	if (in_length >= CS_HEAD_SIZE) {
		algorithm = (SAP_INT)(bufin[4] & 0x0f);
		expected_out_length = (guint32)bufin[0] |
			((guint32)bufin[1] << 8) |
			((guint32)bufin[2] << 16) |
			((guint32)bufin[3] << 24);
		have_expected_out_length = true;
	}

	/* Allocate the output buffer. We use the reported output size
	 * as the output buffer size plus a byte of workspace, so boundary
	 * flushes can still report CS_END_OF_STREAM.
	 */
	bufout_length = (SAP_INT)*out_length;
	internal_bufout_length = bufout_length + 1;
	bufout = (SAP_BYTE*) wmem_alloc0(wmem_scope, internal_bufout_length);
	if (!bufout){
		*out_length = 0;
		wmem_free(wmem_scope, csObject);
		wmem_free(wmem_scope, bufin);
		return (SAP_LZC_LZH_CS_E_MEMORY_ERROR);
	}
	memset(bufout, 0, internal_bufout_length);

	bufin_pos = bufin;
	bufin_rest = (SAP_INT)in_length;
	bufout_pos = bufout;
	bufout_rest = internal_bufout_length;

	do {
		bytes_read = 0;
		bytes_decompressed = 0;

		if (option == CS_INIT_DECOMPRESS) {
			rt = CsDecompr(csObject, bufin_pos, bufin_rest, bufout_pos, bufout_rest, option, &bytes_read, &bytes_decompressed);
		} else if (algorithm == CS_ALGORITHM_LZC) {
			rt = CsDecomprLZC(&csObject->handle.csc, bufin_pos, bufin_rest, bufout_pos, bufout_rest, option, &bytes_read, &bytes_decompressed);
		} else if (algorithm == CS_ALGORITHM_LZH) {
			rt = CsDecomprLZH(&csObject->handle.cshu, bufin_pos, bufin_rest, bufout_pos, bufout_rest, option, &bytes_read, &bytes_decompressed);
		} else {
			rt = CS_E_UNKNOWN_ALG;
		}
		option = CS_NORMAL_COMPRESS;

		if (bytes_read < 0 || bytes_read > bufin_rest) {
			rt = CS_E_FATAL;
			break;
		}
		if (bytes_decompressed < 0 || bytes_decompressed > bufout_rest) {
			rt = CS_E_FATAL;
			break;
		}

		bufin_pos += bytes_read;
		bufin_rest -= bytes_read;
		bufout_pos += bytes_decompressed;
		bufout_rest -= bytes_decompressed;
		total_decompressed += bytes_decompressed;

		if (rt == CS_END_INBUFFER) {
			if (bufin_rest == 0 && !used_padding) {
				bufin_pos = padding;
				bufin_rest = (SAP_INT)sizeof(padding);
				used_padding = true;
				continue;
			}
			if (bytes_read == 0) {
				break;
			}
		}
	} while ((rt == CS_END_INBUFFER && bufin_rest > 0) ||
			(rt == CS_END_OUTBUFFER && bufout_rest > 0));

	if (rt == CS_END_OF_STREAM && total_decompressed > bufout_length) {
		rt = CS_END_OUTBUFFER;
	}
	if ((rt == CS_END_INBUFFER || rt == CS_END_OUTBUFFER) &&
			have_expected_out_length &&
			(guint32)total_decompressed == expected_out_length &&
			total_decompressed <= bufout_length) {
		rt = CS_END_OF_STREAM;
	}

	/* Successful decompression */
	if (rt == CS_END_OF_STREAM) {
		*out_length = total_decompressed;

		/* Copy the buffer in the out parameter */
		for (int i = 0; i < total_decompressed; i++) {
			(out)[i] = (char) bufout[i];
		}
	}

	/* Free the buffers */
	wmem_free(wmem_scope, csObject);
	wmem_free(wmem_scope, bufin);
	wmem_free(wmem_scope, bufout);

	return (rt);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
