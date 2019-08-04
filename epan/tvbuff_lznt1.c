/*
 * Decompression code for LZNT1. This encoding is used by
 * Microsoft in various file formats and protocols including SMB3.
 *
 * See MS-XCA.
 *
 * Copyright (C) 2019  Aurélien Aptel
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <glib.h>
#include <epan/exceptions.h>
#include <epan/tvbuff.h>
#include <epan/wmem/wmem.h>

#define MAX_INPUT_SIZE (16*1024*1024) /* 16MB */

static gboolean
uncompress_chunk(tvbuff_t *tvb, int offset, int in_size, wmem_array_t *obuf)
{
	int in_off = 0, out_off = 0, out_start = 0;
	guint8 flags;
	guint i, j, val, pos;

	out_start = wmem_array_get_count(obuf);

	while (in_off < in_size) {
		flags = tvb_get_guint8(tvb, offset+in_off);
		in_off++;
		for (i = 0; i < 8; i++) {
			if (0 == ((flags>>i)&1)) {
				val = tvb_get_guint8(tvb, offset+in_off);
				in_off++;
				wmem_array_append_one(obuf, val);
				out_off++;
			} else {
				guint f, l_mask = 0x0FFF, o_shift = 12;
				guint match_len, match_off;

				f = tvb_get_letohs(tvb, offset+in_off);
				in_off += 2;
				pos = out_off-1;
				while (pos >= 0x10) {
					l_mask >>= 1;
					o_shift -= 1;
					pos >>= 1;
				}

				match_len = (f & l_mask) + 3;
				match_off = (f >> o_shift) + 1;
				for (j = 0; j < match_len; j++) {
					guint8 byte;
					if (match_off > (guint)out_off)
						return FALSE;
					if (wmem_array_try_index(obuf, out_start+out_off-match_off, &byte))
						return FALSE;
					wmem_array_append_one(obuf, byte);
					out_off++;
				}
			}
			if (in_off == in_size) {
				goto out;
			}
		}
	}
out:
	return TRUE;
}

static gboolean
do_uncompress(tvbuff_t *tvb, int offset, int in_size, wmem_array_t *obuf)
{
	int in_off = 0;
	guint32 header, length, i;
	gboolean ok;

	if (!tvb)
		return FALSE;

	if (in_size > MAX_INPUT_SIZE)
		return FALSE;

	while (in_off < in_size) {
		header = tvb_get_letohs(tvb, offset+in_off);
		in_off += 2;
		length = (header & 0x0FFF) + 1;
		if (!(header & 0x8000)) {
			for (i = 0; i < length; i++) {
				guint8 v = tvb_get_guint8(tvb, offset+in_off);
				wmem_array_append_one(obuf, v);
				in_off++;
			}
		} else {
			ok = uncompress_chunk(tvb, offset + in_off, length, obuf);
			if (!ok)
				return FALSE;
			in_off += length;
		}
	}
	return TRUE;
}

tvbuff_t *
tvb_uncompress_lznt1(tvbuff_t *tvb, const int offset, int in_size)
{
	volatile gboolean ok = FALSE;
	wmem_allocator_t *pool;
	wmem_array_t *obuf;
	tvbuff_t *out;

	pool = wmem_allocator_new(WMEM_ALLOCATOR_SIMPLE);
	obuf = wmem_array_sized_new(pool, 1, in_size*2);

	TRY {
                ok = do_uncompress(tvb, offset, in_size, obuf);
	} CATCH_ALL {
		ok = FALSE;
	}
	ENDTRY;

	if (ok) {
		/*
		 * Cannot pass a tvb free callback that frees the wmem
		 * pool, so we make an extra copy that uses bare
		 * pointers. This could be optimized if tvb API had a
		 * free pool callback of some sort.
		 */
		guint size = wmem_array_get_count(obuf);
		guint8 *p = (guint8 *)g_malloc(size);
		memcpy(p, wmem_array_get_raw(obuf), size);
		out = tvb_new_real_data(p, size, size);
		tvb_set_free_cb(out, g_free);
	} else {
		out = NULL;
	}

	wmem_destroy_allocator(pool);

	return out;
}

tvbuff_t *
tvb_child_uncompress_lznt1(tvbuff_t *parent, tvbuff_t *tvb, const int offset, int in_size)
{
	tvbuff_t *new_tvb = tvb_uncompress_lznt1(tvb, offset, in_size);
	if (new_tvb)
		tvb_set_child_real_data_tvbuff(parent, new_tvb);
	return new_tvb;
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
