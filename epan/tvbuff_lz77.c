/*
 * Decompression code for Plain LZ77. This encoding is used by
 * Microsoft in various file formats and protocols including SMB3.
 *
 * See MS-XCA.
 *
 * Copyright (C) 2019  Aurélien Aptel
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <glib.h>
#include <epan/exceptions.h>
#include <epan/tvbuff.h>
#include <epan/wmem_scopes.h>

#define MAX_INPUT_SIZE (16*1024*1024) /* 16MB */

static bool do_uncompress(tvbuff_t *tvb, int offset, int in_size,
			      wmem_array_t *obuf)
{
	unsigned buf_flags = 0, buf_flag_count = 0;
	int in_off = 0;
	int last_length_half_byte = 0;
	unsigned match_bytes, match_len, match_off;
	unsigned i;

	if (!tvb)
		return false;

	if (!in_size || in_size > MAX_INPUT_SIZE)
		return false;

	while (1) {
		if (buf_flag_count == 0) {
			buf_flags = tvb_get_letohl(tvb, offset+in_off);
			in_off += 4;
			buf_flag_count = 32;
		}
		buf_flag_count--;
		if ((buf_flags & (1u << buf_flag_count)) == 0) {
			uint8_t v = tvb_get_guint8(tvb, offset+in_off);
			wmem_array_append_one(obuf, v);
			in_off++;
		} else {
			if (in_off == in_size)
				return true;
			match_bytes = tvb_get_letohs(tvb, offset+in_off);
			in_off += 2;
			match_len = match_bytes % 8;
			match_off = (match_bytes/8) + 1;
			if (match_len == 7) {
				if (last_length_half_byte == 0) {
					match_len = tvb_get_guint8(tvb, offset+in_off);
					match_len = match_len % 16;
					last_length_half_byte = in_off;
					in_off++;
				} else {
					match_len = tvb_get_guint8(tvb, offset+last_length_half_byte);
					match_len = match_len / 16;
					last_length_half_byte = 0;
				}
				if (match_len == 15) {
					match_len = tvb_get_guint8(tvb, offset+in_off);
					in_off++;
					if (match_len == 255) {
						match_len = tvb_get_letohs(tvb, offset+in_off);
						in_off += 2;
						if (match_len == 0) {
							/* This case isn't documented */
							match_len = tvb_get_letohs(tvb, offset+in_off);
							in_off += 4;
						}
						if (match_len < 15+7)
							return false;
						match_len -= (15 + 7);
					}
					match_len += 15;
				}
				match_len += 7;
			}
			match_len += 3;
			for (i = 0; i < match_len; i++) {
				uint8_t byte;
				if (match_off > wmem_array_get_count(obuf))
					return false;
				if (wmem_array_try_index(obuf, wmem_array_get_count(obuf)-match_off, &byte))
					return false;
				wmem_array_append_one(obuf, byte);
			}
		}
	}

	return true;
}

tvbuff_t *
tvb_uncompress_lz77(tvbuff_t *tvb, const int offset, int in_size)
{
	volatile bool ok = false;
	wmem_allocator_t *pool;
	wmem_array_t *obuf;
	tvbuff_t *out;

	pool = wmem_allocator_new(WMEM_ALLOCATOR_SIMPLE);
	obuf = wmem_array_sized_new(pool, 1, in_size*2);

	TRY {
                ok = do_uncompress(tvb, offset, in_size, obuf);
	} CATCH_ALL {
		ok = false;
	}
	ENDTRY;

	if (ok) {
		/*
		 * Cannot pass a tvb free callback that frees the wmem
		 * pool, so we make an extra copy that uses bare
		 * pointers. This could be optimized if tvb API had a
		 * free pool callback of some sort.
		 */
		unsigned size = wmem_array_get_count(obuf);
		uint8_t *p = (uint8_t *)g_malloc(size);
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
tvb_child_uncompress_lz77(tvbuff_t *parent, tvbuff_t *tvb, const int offset, int in_size)
{
	tvbuff_t *new_tvb = tvb_uncompress_lz77(tvb, offset, in_size);
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
