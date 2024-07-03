/* tvbtest.c
 * Standalone program to test functionality of tvbuffs.
 *
 * tvbtest : tvbtest.o tvbuff.o except.o
 *
 * Copyright (c) 2000 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tvbuff.h"
#include "proto.h"
#include "exceptions.h"
#include "wsutil/array.h"
#include "wsutil/pint.h"

#include <ws_diag_control.h>

bool failed;

typedef struct {
	struct {
		uint8_t needle;
		int offset;
	} g8;
	struct {
		bool test;
		uint16_t needle;
		int offset;
	} g16;
	struct {
		bool test;
		ws_mempbrk_pattern pattern;
		int offset;
		unsigned char found_needle;
	} mempbrk;
} search_test_params;

static bool
test_searches(tvbuff_t *tvb, int offset, search_test_params *sp)
{
	volatile bool ex_thrown = false;

	TRY {
		sp->g8.offset = tvb_find_guint8(tvb, offset, -1, sp->g8.needle);
		if (sp->g16.test) {
			sp->g16.offset = tvb_find_guint16(tvb, offset, -1, sp->g16.needle);
		}
		if (sp->mempbrk.test) {
			sp->mempbrk.offset =
				tvb_ws_mempbrk_pattern_guint8(tvb, offset, -1,
					&sp->mempbrk.pattern, &sp->mempbrk.found_needle);
		}
	}
	CATCH_ALL {
		ex_thrown = true;
	}
	ENDTRY;
	return ex_thrown;
}

/* Tests a tvbuff against the expected pattern/length.
 * Returns true if all tests succeeed, false if any test fails */
static bool
test(tvbuff_t *tvb, const char* name,
     uint8_t* expected_data, unsigned expected_length, unsigned expected_reported_length)
{
	unsigned			length;
	unsigned			reported_length;
	uint8_t			*ptr;
	volatile bool	ex_thrown;
	volatile uint32_t	val32;
	uint32_t			expected32;
	unsigned			incr, i;

	length = tvb_captured_length(tvb);

	if (length != expected_length) {
		printf("01: Failed TVB=%s Length of tvb=%u while expected length=%u\n",
				name, length, expected_length);
		failed = true;
		return false;
	}

	reported_length = tvb_reported_length(tvb);

	if (reported_length != expected_reported_length) {
		printf("01: Failed TVB=%s Reported length of tvb=%u while expected reported length=%u\n",
				name, reported_length, expected_reported_length);
		failed = true;
		return false;
	}

	/* Test boundary case. A BoundsError exception should be thrown. */
	ex_thrown = false;
	TRY {
		tvb_get_ptr(tvb, 0, length + 1);
	}
	CATCH(BoundsError) {
		ex_thrown = true;
	}
	CATCH(FragmentBoundsError) {
		printf("02: Caught wrong exception: FragmentBoundsError\n");
	}
	CATCH(ReportedBoundsError) {
		printf("02: Caught wrong exception: ReportedBoundsError\n");
	}
	CATCH_ALL {
		printf("02: Caught wrong exception: %lu\n", exc->except_id.except_code);
	}
	ENDTRY;

	if (!ex_thrown) {
		printf("02: Failed TVB=%s No BoundsError when retrieving %u bytes\n",
				name, length + 1);
		failed = true;
		return false;
	}

	/* Test boundary case with reported_length+1. A ReportedBoundsError
	   exception should be thrown. */
	ex_thrown = false;
	TRY {
		tvb_get_ptr(tvb, 0, reported_length + 1);
	}
	CATCH(BoundsError) {
		printf("03: Caught wrong exception: BoundsError\n");
	}
	CATCH(FragmentBoundsError) {
		printf("03: Caught wrong exception: FragmentBoundsError\n");
	}
	CATCH(ReportedBoundsError) {
		ex_thrown = true;
	}
	CATCH_ALL {
		printf("03: Caught wrong exception: %lu\n", exc->except_id.except_code);
	}
	ENDTRY;

	if (!ex_thrown) {
		printf("03: Failed TVB=%s No ReportedBoundsError when retrieving %u bytes\n",
				name, reported_length + 1);
		failed = true;
		return false;
	}

	/* Test boundary case. A BoundsError exception should be thrown. */
	ex_thrown = false;
	TRY {
		tvb_get_ptr(tvb, -1, 2);
	}
	CATCH(BoundsError) {
		ex_thrown = true;
	}
	CATCH(FragmentBoundsError) {
		printf("04: Caught wrong exception: FragmentBoundsError\n");
	}
	CATCH(ReportedBoundsError) {
		printf("04: Caught wrong exception: ReportedBoundsError\n");
	}
	CATCH_ALL {
		printf("04: Caught wrong exception: %lu\n", exc->except_id.except_code);
	}
	ENDTRY;

	if (!ex_thrown) {
		printf("04: Failed TVB=%s No BoundsError when retrieving 2 bytes from"
				" offset -1\n", name);
		failed = true;
		return false;
	}

	/* Test boundary case. A BoundsError exception should not be thrown. */
	ex_thrown = false;
	TRY {
		tvb_get_ptr(tvb, 0, length ? 1 : 0);
	}
	CATCH(BoundsError) {
		ex_thrown = true;
	}
	CATCH(FragmentBoundsError) {
		printf("05: Caught wrong exception: FragmentBoundsError\n");
	}
	CATCH(ReportedBoundsError) {
		printf("05: Caught wrong exception: ReportedBoundsError\n");
	}
	CATCH_ALL {
		printf("05: Caught wrong exception: %lu\n", exc->except_id.except_code);
	}
	ENDTRY;

	if (ex_thrown) {
		printf("05: Failed TVB=%s BoundsError when retrieving 1 bytes from"
				" offset 0\n", name);
		failed = true;
		return false;
	}

	/* Test boundary case. A BoundsError exception should not be thrown. */
	ex_thrown = false;
	TRY {
		tvb_get_ptr(tvb, -1, length ? 1 : 0);
	}
	CATCH(BoundsError) {
		ex_thrown = true;
	}
	CATCH(FragmentBoundsError) {
		printf("06: Caught wrong exception: FragmentBoundsError\n");
	}
	CATCH(ReportedBoundsError) {
		printf("06: Caught wrong exception: ReportedBoundsError\n");
	}
	CATCH_ALL {
		printf("06: Caught wrong exception: %lu\n", exc->except_id.except_code);
	}
	ENDTRY;

	if (ex_thrown) {
		printf("06: Failed TVB=%s BoundsError when retrieving 1 bytes from"
				" offset -1\n", name);
		failed = true;
		return false;
	}


	/* Check data at boundary. An exception should not be thrown. */
	if (length >= 4) {
		ex_thrown = false;
		TRY {
			val32 = tvb_get_ntohl(tvb, 0);
		}
		CATCH_ALL {
			ex_thrown = true;
		}
		ENDTRY;

		if (ex_thrown) {
			printf("07: Failed TVB=%s Exception when retrieving "
					"guint32 from offset 0\n", name);
			failed = true;
			return false;
		}

		expected32 = pntoh32(expected_data);
		if (val32 != expected32) {
			printf("08: Failed TVB=%s  uint32_t @ 0 %u != expected %u\n",
					name, val32, expected32);
			failed = true;
			return false;
		}
	}

	/* Check data at boundary. An exception should not be thrown. */
	if (length >= 4) {
		ex_thrown = false;
		TRY {
			val32 = tvb_get_ntohl(tvb, -4);
		}
		CATCH_ALL {
			ex_thrown = true;
		}
		ENDTRY;

		if (ex_thrown) {
			printf("09: Failed TVB=%s Exception when retrieving "
					"guint32 from offset 0\n", name);
			failed = true;
			return false;
		}

		expected32 = pntoh32(&expected_data[length-4]);
		if (val32 != expected32) {
			printf("10: Failed TVB=%s uint32_t @ -4 %u != expected %u\n",
					name, val32, expected32);
			failed = true;
			return false;
		}
	}

	/* Sweep across data in various sized increments checking
	 * tvb_memdup() */
	for (incr = 1; incr < length; incr++) {
		for (i = 0; i < length - incr; i += incr) {
			ptr = (uint8_t*)tvb_memdup(NULL, tvb, i, incr);
			if (memcmp(ptr, &expected_data[i], incr) != 0) {
				printf("11: Failed TVB=%s Offset=%u Length=%u "
						"Bad memdup\n",
						name, i, incr);
				failed = true;
				wmem_free(NULL, ptr);
				return false;
			}
			wmem_free(NULL, ptr);
		}
	}

	/* One big memdup */
	ptr = (uint8_t*)tvb_memdup(NULL, tvb, 0, -1);
	if ((length != 0 && memcmp(ptr, expected_data, length) != 0) ||
	    (length == 0 && ptr != NULL)) {
		printf("12: Failed TVB=%s Offset=0 Length=-1 "
				"Bad memdup\n", name);
		failed = true;
		wmem_free(NULL, ptr);
		return false;
	}
	wmem_free(NULL, ptr);

	/* Test some searches.
	 * For now, just do a few trivial searches with easily verifiable
	 * results... each of the searches is expected to find their target at
	 * the offset from which the search commences.  Walk through the tvb
	 * and run these tests at each byte position. */
	for (i = 0; i < length; i++) {
		search_test_params sp;

		memset(&sp, 0, sizeof sp);

		/* Search for the uint8_t at this offset. */
		sp.g8.needle = expected_data[i];

		/* If at least two bytes left, search for the uint16_t at this offset. */
		sp.g16.test = length - i > 1;
		if (sp.g16.test) {
			sp.g16.needle = (expected_data[i] << 8) | expected_data[i + 1];
		}

		/* If the uint8_t at this offset is nonzero, try
		 * tvb_ws_mempbrk_pattern_guint8 as well.
		 * ws_mempbrk_compile("\0") is not effective... */
		sp.mempbrk.test = expected_data[i] != 0;
		if (sp.mempbrk.test) {
			char pattern_string[2] = {expected_data[i], '\0'};

			ws_mempbrk_compile(&sp.mempbrk.pattern, pattern_string);
		}

		ex_thrown = test_searches(tvb, i, &sp);
		if (ex_thrown) {
			printf("13: Failed TVB=%s Exception when searching, offset %d\n",
					name, i);
			failed = true;
			return false;
		}
		if ((unsigned)sp.g8.offset != i) {
			printf("13: Failed TVB=%s Wrong offset for uint8_t:%02x,"
					" got %d, expected %d\n",
					name, sp.g8.needle, sp.g8.offset, i);
			failed = true;
			return false;
		}
		if (sp.g16.test && (unsigned)sp.g16.offset != i) {
			printf("13: Failed TVB=%s Wrong offset for uint16_t:%04x,"
					" got %d, expected %d\n",
					name, sp.g16.needle, sp.g16.offset, i);
			failed = true;
			return false;
		}
		if (sp.mempbrk.test && (unsigned)sp.mempbrk.offset != i) {
			printf("13: Failed TVB=%s Wrong offset for mempbrk:%02x,"
					" got %d, expected %d\n",
					name, expected_data[i], sp.mempbrk.offset, i);
			failed = true;
			return false;
		}
		if (sp.mempbrk.test && sp.mempbrk.found_needle != expected_data[i]) {
			printf("13: Failed TVB=%s Wrong needle found for mempbrk:%02x,"
					" got %02x, expected %02x\n",
					name, expected_data[i], sp.mempbrk.found_needle, expected_data[i]);
			failed = true;
			return false;
		}
	}


	printf("Passed TVB=%s\n", name);

	return true;
}

static void
run_tests(void)
{
	int		i, j;

	tvbuff_t	*tvb_parent;
	tvbuff_t	*tvb_empty;
	tvbuff_t	*tvb_small[3];
	tvbuff_t	*tvb_large[3];
	tvbuff_t	*tvb_subset[6];
	tvbuff_t	*tvb_empty_subset;
	uint8_t		*small[3];
	unsigned		small_length[3];
	unsigned		small_reported_length[3];
	uint8_t		*large[3];
	unsigned		large_length[3];
	unsigned		large_reported_length[3];
	uint8_t		*subset[6];
	unsigned		subset_length[6];
	unsigned		subset_reported_length[6];
	uint8_t		temp;
	uint8_t		*comp[6];
	tvbuff_t	*tvb_comp[6];
	unsigned		comp_length[6];
	unsigned		comp_reported_length[6];
	tvbuff_t	*tvb_comp_subset;
	unsigned		comp_subset_length;
	unsigned		comp_subset_reported_length;
	uint8_t		*comp_subset;
	int		len;

	tvb_parent = tvb_new_real_data((const uint8_t*)"", 0, 0);
	for (i = 0; i < 3; i++) {
		small[i] = g_new(uint8_t, 16);

		temp = 16 * i;
		for (j = 0; j < 16; j++) {
			small[i][j] = temp + j;
		}
		small_length[i] = 16;
		small_reported_length[i] = 17;
		tvb_small[i] = tvb_new_child_real_data(tvb_parent, small[i], 16, 17);
		tvb_set_free_cb(tvb_small[i], g_free);
	}

	for (i = 0; i < 3; i++) {
		large[i] = g_new(uint8_t, 19);

		temp = 19 * i;
		for (j = 0; j < 19; j++) {
			large[i][j] = temp + j;
		}

		large_length[i] = 19;
		large_reported_length[i] = 20;
		tvb_large[i] = tvb_new_child_real_data(tvb_parent, large[i], 19, 20);
		tvb_set_free_cb(tvb_large[i], g_free);
	}

	/* Test empty tvb */
	tvb_empty = tvb_new_child_real_data(tvb_parent, NULL, 0, 1);
	test(tvb_empty, "Empty", NULL, 0, 1);

	/* Test the "real" tvbuff objects. */
	test(tvb_small[0], "Small 0", small[0], small_length[0], small_reported_length[0]);
	test(tvb_small[1], "Small 1", small[1], small_length[1], small_reported_length[1]);
	test(tvb_small[2], "Small 2", small[2], small_length[2], small_reported_length[2]);

	test(tvb_large[0], "Large 0", large[0], large_length[0], large_reported_length[0]);
	test(tvb_large[1], "Large 1", large[1], large_length[1], large_reported_length[1]);
	test(tvb_large[2], "Large 2", large[2], large_length[2], large_reported_length[2]);

	subset_length[0]	  = 8;
	subset_reported_length[0] = 9;
	tvb_subset[0]		  = tvb_new_subset_length_caplen(tvb_small[0], 0, 8, 9);
	subset[0]		  = &small[0][0];

	subset_length[1]	  = 10;
	subset_reported_length[1] = 11;
	tvb_subset[1]		  = tvb_new_subset_length_caplen(tvb_large[0], -10, 10, 11);
	subset[1]		  = &large[0][9];

	subset_length[2]	  = 16;
	subset_reported_length[2] = 17;
	tvb_subset[2]		  = tvb_new_subset_length_caplen(tvb_small[1], -16, -1, 17);
	subset[2]		  = &small[1][0];

	subset_length[3]	  = 3;
	subset_reported_length[3] = 4;
	tvb_subset[3]		  = tvb_new_subset_length_caplen(tvb_subset[0], 0, 3, 4);
	subset[3]		  = &small[0][0];

	subset_length[4]	  = 5;
	subset_reported_length[4] = 6;
	tvb_subset[4]		  = tvb_new_subset_length_caplen(tvb_subset[1], -5, 5, 6);
	subset[4]		  = &large[0][14];

	subset_length[5]	  = 8;
	subset_reported_length[5] = 9;
	tvb_subset[5]		  = tvb_new_subset_length_caplen(tvb_subset[2], 4, 8, 9);
	subset[5]		  = &small[1][4];

	/* Test the "subset" tvbuff objects. */
	test(tvb_subset[0], "Subset 0", subset[0], subset_length[0], subset_reported_length[0]);
	test(tvb_subset[1], "Subset 1", subset[1], subset_length[1], subset_reported_length[1]);
	test(tvb_subset[2], "Subset 2", subset[2], subset_length[2], subset_reported_length[2]);
	test(tvb_subset[3], "Subset 3", subset[3], subset_length[3], subset_reported_length[3]);
	test(tvb_subset[4], "Subset 4", subset[4], subset_length[4], subset_reported_length[4]);
	test(tvb_subset[5], "Subset 5", subset[5], subset_length[5], subset_reported_length[5]);

	/* Subset of an empty tvb. */
	tvb_empty_subset = tvb_new_subset_length_caplen(tvb_empty, 0, 0, 1);
	test(tvb_empty_subset, "Empty Subset", NULL, 0, 1);

	/* One Real */
	printf("Making Composite 0\n");
	tvb_comp[0]		= tvb_new_composite();
	comp_length[0]		= small_length[0];
	comp_reported_length[0] = small_reported_length[0];
	comp[0]			= small[0];
	tvb_composite_append(tvb_comp[0], tvb_small[0]);
	tvb_composite_finalize(tvb_comp[0]);

	/* Two Reals */
	printf("Making Composite 1\n");
	tvb_comp[1]		= tvb_new_composite();
	comp_length[1]		= small_length[0] + small_length[1];
	comp_reported_length[1] = small_reported_length[0] + small_reported_length[1];
	comp[1]			= (uint8_t*)g_malloc(comp_length[1]);
	memcpy(comp[1], small[0], small_length[0]);
	memcpy(&comp[1][small_length[0]], small[1], small_length[1]);
	tvb_composite_append(tvb_comp[1], tvb_small[0]);
	tvb_composite_append(tvb_comp[1], tvb_small[1]);
	tvb_composite_finalize(tvb_comp[1]);

	/* One subset */
	printf("Making Composite 2\n");
	tvb_comp[2]		= tvb_new_composite();
	comp_length[2]		= subset_length[1];
	comp_reported_length[2] = subset_reported_length[1];
	comp[2]			= subset[1];
	tvb_composite_append(tvb_comp[2], tvb_subset[1]);
	tvb_composite_finalize(tvb_comp[2]);

	/* Two subsets */
	printf("Making Composite 3\n");
	tvb_comp[3]		= tvb_new_composite();
	comp_length[3]		= subset_length[4] + subset_length[5];
	comp_reported_length[3] = subset_reported_length[4] + subset_reported_length[5];
	comp[3]			= (uint8_t*)g_malloc(comp_length[3]);
	memcpy(comp[3], subset[4], subset_length[4]);
	memcpy(&comp[3][subset_length[4]], subset[5], subset_length[5]);
	tvb_composite_append(tvb_comp[3], tvb_subset[4]);
	tvb_composite_append(tvb_comp[3], tvb_subset[5]);
	tvb_composite_finalize(tvb_comp[3]);

	/* One real, one subset */
	printf("Making Composite 4\n");
	tvb_comp[4]		= tvb_new_composite();
	comp_length[4]		= small_length[0] + subset_length[1];
	comp_reported_length[4]	= small_reported_length[0] + subset_reported_length[1];
	comp[4]			= (uint8_t*)g_malloc(comp_length[4]);
	memcpy(&comp[4][0], small[0], small_length[0]);
	memcpy(&comp[4][small_length[0]], subset[1], subset_length[1]);
	tvb_composite_append(tvb_comp[4], tvb_small[0]);
	tvb_composite_append(tvb_comp[4], tvb_subset[1]);
	tvb_composite_finalize(tvb_comp[4]);

	/* 4 composites */
	printf("Making Composite 5\n");
	tvb_comp[5]		= tvb_new_composite();
	comp_length[5]		= comp_length[0] +
					comp_length[1] +
					comp_length[2] +
					comp_length[3];
	comp_reported_length[5]	= comp_reported_length[0] +
					comp_reported_length[1] +
					comp_reported_length[2] +
					comp_reported_length[3];
	comp[5]			= (uint8_t*)g_malloc(comp_length[5]);

	len = 0;
	memcpy(&comp[5][len], comp[0], comp_length[0]);
	len += comp_length[0];
	memcpy(&comp[5][len], comp[1], comp_length[1]);
	len += comp_length[1];
	memcpy(&comp[5][len], comp[2], comp_length[2]);
	len += comp_length[2];
	memcpy(&comp[5][len], comp[3], comp_length[3]);

	tvb_composite_append(tvb_comp[5], tvb_comp[0]);
	tvb_composite_append(tvb_comp[5], tvb_comp[1]);
	tvb_composite_append(tvb_comp[5], tvb_comp[2]);
	tvb_composite_append(tvb_comp[5], tvb_comp[3]);
	tvb_composite_finalize(tvb_comp[5]);

	/* A subset of one of the composites. */
	tvb_comp_subset = tvb_new_subset_remaining(tvb_comp[1], 1);
	comp_subset = &comp[1][1];
	comp_subset_length = comp_length[1] - 1;
	comp_subset_reported_length = comp_reported_length[1] - 1;

	/* Test the "composite" tvbuff objects. */
	test(tvb_comp[0], "Composite 0", comp[0], comp_length[0], comp_reported_length[0]);
	test(tvb_comp[1], "Composite 1", comp[1], comp_length[1], comp_reported_length[1]);
	test(tvb_comp[2], "Composite 2", comp[2], comp_length[2], comp_reported_length[2]);
	test(tvb_comp[3], "Composite 3", comp[3], comp_length[3], comp_reported_length[3]);
	test(tvb_comp[4], "Composite 4", comp[4], comp_length[4], comp_reported_length[4]);
	test(tvb_comp[5], "Composite 5", comp[5], comp_length[5], comp_reported_length[5]);

	/* Test the subset of the composite. */
	test(tvb_comp_subset, "Subset of Composite", comp_subset, comp_subset_length, comp_subset_reported_length);

	/* free memory. */
	/* Don't free: comp[0] */
	g_free(comp[1]);
	/* Don't free: comp[2] */
	g_free(comp[3]);
	g_free(comp[4]);
	g_free(comp[5]);

	tvb_free_chain(tvb_parent);  /* should free all tvb's and associated data */
}

typedef struct
{
	// Raw bytes
	int enc_len;
	const uint8_t *enc;
	// Varint parameters
	int encoding;
	int maxlen;
	// Results
	unsigned long expect_except;
	uint64_t expect_val;
	unsigned expect_len;
} varint_test_s;

DIAG_OFF_PEDANTIC
varint_test_s varint[] = {
	{0, (const uint8_t *)"", 0, FT_VARINT_MAX_LEN, DissectorError, 0, 0}, // no encoding specified
	// ENC_VARINT_PROTOBUF
	{0, (const uint8_t *)"", ENC_VARINT_PROTOBUF, FT_VARINT_MAX_LEN, ReportedBoundsError, 0, 0},
	{1, (const uint8_t *)"\x00", ENC_VARINT_PROTOBUF, FT_VARINT_MAX_LEN, 0, 0, 1},
	{1, (const uint8_t *)"\x01", ENC_VARINT_PROTOBUF, FT_VARINT_MAX_LEN, 0, 1, 1},
	{1, (const uint8_t *)"\x7f", ENC_VARINT_PROTOBUF, FT_VARINT_MAX_LEN, 0, 0x7f, 1},
	{2, (const uint8_t *)"\x80\x01", ENC_VARINT_PROTOBUF, FT_VARINT_MAX_LEN, 0, UINT64_C(1)<<7, 2},
	{1, (const uint8_t *)"\x80", ENC_VARINT_PROTOBUF, FT_VARINT_MAX_LEN, ReportedBoundsError, 0, 0}, // truncated data
	{2, (const uint8_t *)"\x80\x01", ENC_VARINT_PROTOBUF, 1, 0, 0, 0}, // truncated read
	{5, (const uint8_t *)"\x80\x80\x80\x80\x01", ENC_VARINT_PROTOBUF, FT_VARINT_MAX_LEN, 0, UINT64_C(1)<<28, 5},
	{10, (const uint8_t *)"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x01", ENC_VARINT_PROTOBUF, FT_VARINT_MAX_LEN, 0, UINT64_C(1)<<63, 10},
	{10, (const uint8_t *)"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01", ENC_VARINT_PROTOBUF, FT_VARINT_MAX_LEN, 0, 0xffffffffffffffff, 10},
	{10, (const uint8_t *)"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x02", ENC_VARINT_PROTOBUF, FT_VARINT_MAX_LEN, 0, 0, 10}, // overflow
	// ENC_VARINT_SDNV
	{0, (const uint8_t *)"", ENC_VARINT_SDNV, FT_VARINT_MAX_LEN, ReportedBoundsError, 0, 0},
	{1, (const uint8_t *)"\x00", ENC_VARINT_SDNV, FT_VARINT_MAX_LEN, 0, 0, 1},
	{1, (const uint8_t *)"\x01", ENC_VARINT_SDNV, FT_VARINT_MAX_LEN, 0, 1, 1},
	{1, (const uint8_t *)"\x7f", ENC_VARINT_SDNV, FT_VARINT_MAX_LEN, 0, 0x7f, 1},
	{2, (const uint8_t *)"\x81\x00", ENC_VARINT_SDNV, FT_VARINT_MAX_LEN, 0, UINT64_C(1)<<7, 2},
	{1, (const uint8_t *)"\x81", ENC_VARINT_SDNV, FT_VARINT_MAX_LEN, ReportedBoundsError, 1, 0}, // truncated data
	{2, (const uint8_t *)"\x81\x00", ENC_VARINT_SDNV, 1, 0, 1, 0}, // truncated read
	{5, (const uint8_t *)"\x81\x80\x80\x80\x00", ENC_VARINT_SDNV, FT_VARINT_MAX_LEN, 0, UINT64_C(1)<<28, 5},
	{10, (const uint8_t *)"\x81\x80\x80\x80\x80\x80\x80\x80\x80\x00", ENC_VARINT_SDNV, FT_VARINT_MAX_LEN, 0, UINT64_C(1)<<63, 10},
	{10, (const uint8_t *)"\x81\xff\xff\xff\xff\xff\xff\xff\xff\x7f", ENC_VARINT_SDNV, FT_VARINT_MAX_LEN, 0, 0xffffffffffffffff, 10},
	{10, (const uint8_t *)"\x82\x80\x80\x80\x80\x80\x80\x80\x80\x00", ENC_VARINT_SDNV, FT_VARINT_MAX_LEN, 0, UINT64_C(1)<<57, 0}, // overflow
};
DIAG_ON_PEDANTIC

static void
varint_tests(void)
{
	tvbuff_t	*tvb_parent, *tvb;
	volatile unsigned long got_ex;
	uint64_t got_val;
	volatile unsigned got_len;

	tvb_parent = tvb_new_real_data((const uint8_t*)"", 0, 0);

	for (size_t ix = 0; ix < array_length(varint); ++ix) {
		const varint_test_s *vit = &varint[ix];
		tvb = tvb_new_child_real_data(tvb_parent, vit->enc, vit->enc_len, vit->enc_len);

		got_ex = 0;
		got_val = 0;
		got_len = 0;
		TRY {
			got_len = tvb_get_varint(tvb, 0, vit->maxlen, &got_val, vit->encoding);
		}
		CATCH_ALL {
			got_ex = exc->except_id.except_code;
		}
		ENDTRY;
		if (got_ex != vit->expect_except) {
			printf("Failed varint #%zu with exception=%lu while expected exception=%lu\n",
				   ix, got_ex, vit->expect_except);
			failed = true;
			continue;
		}
		if (got_val != vit->expect_val) {
			printf("Failed varint #%zu value=%" PRIu64 " while expected value=%" PRIu64 "\n",
				   ix, got_val, vit->expect_val);
			failed = true;
			continue;
		}
		if (got_len != vit->expect_len) {
			printf("Failed varint #%zu length=%u while expected length=%u\n",
				   ix, got_len, vit->expect_len);
			failed = true;
			continue;
		}
		printf("Passed varint #%zu\n", ix);
	}

	tvb_free_chain(tvb_parent);  /* should free all tvb's and associated data */
}

#define DATA_AND_LEN(X) .data = X, .len = sizeof(X) - 1

static void
zstd_tests (void) {
#ifdef HAVE_ZSTD
	typedef struct {
		const char* desc;
		const uint8_t* data;
		size_t len;
		const char* expect;
	} zstd_testcase;

	zstd_testcase tests[] = {
		{
			.desc = "Uncompressing 'foobar'",
			DATA_AND_LEN ("\x28\xb5\x2f\xfd\x20\x07\x39\x00\x00\x66\x6f\x6f\x62\x61\x72\x00"),
			.expect = "foobar"
		},
		{
			.desc = "Uncompressing invalid data",
			DATA_AND_LEN ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"),
			.expect = NULL
		},
		{
			.desc = "Uncompressing too short length",
			.data = "\x28\xb5\x2f\xfd\x20\x07\x39\x00\x00\x66\x6f\x6f\x62\x61\x72\x00",
			.len = 1,
			.expect = NULL
		},
		{
			.desc = "Uncompressing two frames of data",
			// data is two frames of compressed data with compression level 1.
			// the first frame is the string "foo" with no null terminator.
			// the second frame is the string "bar" with a null terminator.
			DATA_AND_LEN ("\x28\xb5\x2f\xfd\x20\x03\x19\x00\x00\x66\x6f\x6f"
				      "\x28\xb5\x2f\xfd\x20\x04\x21\x00\x00\x62\x61\x72\x00"),
			.expect = "foobar"
		},
		{
			.desc = "Uncompressing two frames of data. 2nd frame has too short length.",
			// data is two frames of compressed data with compression level 1.
			// the first frame is the string "foo" with no null terminator.
			// the second frame is the string "bar" with a null terminator.
			.data ="\x28\xb5\x2f\xfd\x20\x03\x19\x00\x00\x66\x6f\x6f"
			       "\x28\xb5\x2f\xfd\x20\x04\x21\x00\x00\x62\x61\x72\x00",
			.len = 13,
			.expect = NULL
		},
		{
			.desc = "Uncompressing two frames of data. 2nd frame is malformed.",
			// data is two frames of compressed data with compression level 1.
			// the first frame is the string "foo" with no null terminator.
			// the second frame is malformed.
			DATA_AND_LEN ("\x28\xb5\x2f\xfd\x20\x03\x19\x00\x00\x66\x6f\x6f"
			              "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"),
			.expect = NULL
		},
		{
			.desc = "Uncompressing no data",
			.data = "\0",
			.len = 0,
			.expect = ""
		},

	};

	for (size_t i = 0; i < array_length(tests); i++) {
		zstd_testcase *t = tests + i;

		printf ("ZSTD test: %s ... begin\n", t->desc);

		tvbuff_t *tvb = tvb_new_real_data (t->data, (const unsigned) t->len, (const unsigned) t->len);
		tvbuff_t *got = tvb_uncompress_zstd (tvb, 0, (int) t->len);
		if (!t->expect) {
			if (got) {
				fprintf (stderr, "ZSTD test: %s ... FAIL: Expected error, but got non-NULL from uncompress\n", t->desc);
				failed = true;
				return;
			}
		} else {
			if (!got) {
				printf ("ZSTD test: %s ... FAIL: Expected success, but got NULL from uncompress.\n", t->desc);
				failed = true;
				return;
			}
			char * got_str = tvb_get_string_enc (NULL, got, 0, tvb_reported_length (got), ENC_ASCII);
			if (0 != strcmp (got_str, t->expect)) {
				printf ("ZSTD test: %s ... FAIL: Expected \"%s\", got \"%s\".\n", t->desc, t->expect, got_str);
				failed = true;
				return;
			}
			wmem_free (NULL, got_str);
			tvb_free (got);
		}

		tvb_free (tvb);

		printf ("ZSTD test: %s ... OK\n", t->desc);
	}
#else
	printf ("Skipping ZSTD test. ZSTD is not available.\n");
#endif
}
/* Note: valgrind can be used to check for tvbuff memory leaks */
int
main(void)
{
	/* For valgrind: See GLib documentation: "Running GLib Applications" */
	g_setenv("G_DEBUG", "gc-friendly", 1);
	g_setenv("G_SLICE", "always-malloc", 1);

	except_init();
	run_tests();
	varint_tests();
	zstd_tests ();
	except_deinit();
	exit(failed?1:0);
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
