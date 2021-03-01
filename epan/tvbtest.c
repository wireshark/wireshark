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
#include "exceptions.h"
#include "wsutil/pint.h"

gboolean failed = FALSE;

typedef struct {
	struct {
		guint8 needle;
		gint offset;
	} g8;
	struct {
		gboolean test;
		guint16 needle;
		gint offset;
	} g16;
	struct {
		gboolean test;
		ws_mempbrk_pattern pattern;
		gint offset;
		guchar found_needle;
	} mempbrk;
} search_test_params;

static gboolean
test_searches(tvbuff_t *tvb, gint offset, search_test_params *sp)
{
	volatile gboolean ex_thrown = FALSE;

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
		ex_thrown = TRUE;
	}
	ENDTRY;
	return ex_thrown;
}

/* Tests a tvbuff against the expected pattern/length.
 * Returns TRUE if all tests succeeed, FALSE if any test fails */
static gboolean
test(tvbuff_t *tvb, const gchar* name,
     guint8* expected_data, guint expected_length, guint expected_reported_length)
{
	guint			length;
	guint			reported_length;
	guint8			*ptr;
	volatile gboolean	ex_thrown;
	volatile guint32	val32;
	guint32			expected32;
	guint			incr, i;

	length = tvb_captured_length(tvb);

	if (length != expected_length) {
		printf("01: Failed TVB=%s Length of tvb=%u while expected length=%u\n",
				name, length, expected_length);
		failed = TRUE;
		return FALSE;
	}

	reported_length = tvb_reported_length(tvb);

	if (reported_length != expected_reported_length) {
		printf("01: Failed TVB=%s Reported length of tvb=%u while expected reported length=%u\n",
				name, reported_length, expected_reported_length);
		failed = TRUE;
		return FALSE;
	}

	/* Test boundary case. A BoundsError exception should be thrown. */
	ex_thrown = FALSE;
	TRY {
		tvb_get_ptr(tvb, 0, length + 1);
	}
	CATCH(BoundsError) {
		ex_thrown = TRUE;
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
		failed = TRUE;
		return FALSE;
	}

	/* Test boundary case with reported_length+1. A ReportedBoundsError
	   exception should be thrown. */
	ex_thrown = FALSE;
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
		ex_thrown = TRUE;
	}
	CATCH_ALL {
		printf("03: Caught wrong exception: %lu\n", exc->except_id.except_code);
	}
	ENDTRY;

	if (!ex_thrown) {
		printf("03: Failed TVB=%s No ReportedBoundsError when retrieving %u bytes\n",
				name, reported_length + 1);
		failed = TRUE;
		return FALSE;
	}

	/* Test boundary case. A BoundsError exception should be thrown. */
	ex_thrown = FALSE;
	TRY {
		tvb_get_ptr(tvb, -1, 2);
	}
	CATCH(BoundsError) {
		ex_thrown = TRUE;
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
		failed = TRUE;
		return FALSE;
	}

	/* Test boundary case. A BoundsError exception should not be thrown. */
	ex_thrown = FALSE;
	TRY {
		tvb_get_ptr(tvb, 0, length ? 1 : 0);
	}
	CATCH(BoundsError) {
		ex_thrown = TRUE;
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
		failed = TRUE;
		return FALSE;
	}

	/* Test boundary case. A BoundsError exception should not be thrown. */
	ex_thrown = FALSE;
	TRY {
		tvb_get_ptr(tvb, -1, length ? 1 : 0);
	}
	CATCH(BoundsError) {
		ex_thrown = TRUE;
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
		failed = TRUE;
		return FALSE;
	}


	/* Check data at boundary. An exception should not be thrown. */
	if (length >= 4) {
		ex_thrown = FALSE;
		TRY {
			val32 = tvb_get_ntohl(tvb, 0);
		}
		CATCH_ALL {
			ex_thrown = TRUE;
		}
		ENDTRY;

		if (ex_thrown) {
			printf("07: Failed TVB=%s Exception when retrieving "
					"guint32 from offset 0\n", name);
			failed = TRUE;
			return FALSE;
		}

		expected32 = pntoh32(expected_data);
		if (val32 != expected32) {
			printf("08: Failed TVB=%s  guint32 @ 0 %u != expected %u\n",
					name, val32, expected32);
			failed = TRUE;
			return FALSE;
		}
	}

	/* Check data at boundary. An exception should not be thrown. */
	if (length >= 4) {
		ex_thrown = FALSE;
		TRY {
			val32 = tvb_get_ntohl(tvb, -4);
		}
		CATCH_ALL {
			ex_thrown = TRUE;
		}
		ENDTRY;

		if (ex_thrown) {
			printf("09: Failed TVB=%s Exception when retrieving "
					"guint32 from offset 0\n", name);
			failed = TRUE;
			return FALSE;
		}

		expected32 = pntoh32(&expected_data[length-4]);
		if (val32 != expected32) {
			printf("10: Failed TVB=%s guint32 @ -4 %u != expected %u\n",
					name, val32, expected32);
			failed = TRUE;
			return FALSE;
		}
	}

	/* Sweep across data in various sized increments checking
	 * tvb_memdup() */
	for (incr = 1; incr < length; incr++) {
		for (i = 0; i < length - incr; i += incr) {
			ptr = (guint8*)tvb_memdup(NULL, tvb, i, incr);
			if (memcmp(ptr, &expected_data[i], incr) != 0) {
				printf("11: Failed TVB=%s Offset=%u Length=%u "
						"Bad memdup\n",
						name, i, incr);
				failed = TRUE;
				wmem_free(NULL, ptr);
				return FALSE;
			}
			wmem_free(NULL, ptr);
		}
	}

	/* One big memdup */
	ptr = (guint8*)tvb_memdup(NULL, tvb, 0, -1);
	if ((length != 0 && memcmp(ptr, expected_data, length) != 0) ||
	    (length == 0 && ptr != NULL)) {
		printf("12: Failed TVB=%s Offset=0 Length=-1 "
				"Bad memdup\n", name);
		failed = TRUE;
		wmem_free(NULL, ptr);
		return FALSE;
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

		/* Search for the guint8 at this offset. */
		sp.g8.needle = expected_data[i];

		/* If at least two bytes left, search for the guint16 at this offset. */
		sp.g16.test = length - i > 1;
		if (sp.g16.test) {
			sp.g16.needle = (expected_data[i] << 8) | expected_data[i + 1];
		}

		/* If the guint8 at this offset is nonzero, try
		 * tvb_ws_mempbrk_pattern_guint8 as well.
		 * ws_mempbrk_compile("\0") is not effective... */
		sp.mempbrk.test = expected_data[i] != 0;
		if (sp.mempbrk.test) {
			gchar pattern_string[2] = {expected_data[i], '\0'};

			ws_mempbrk_compile(&sp.mempbrk.pattern, pattern_string);
		}

		ex_thrown = test_searches(tvb, i, &sp);
		if (ex_thrown) {
			printf("13: Failed TVB=%s Exception when searching, offset %d\n",
					name, i);
			failed = TRUE;
			return FALSE;
		}
		if ((guint)sp.g8.offset != i) {
			printf("13: Failed TVB=%s Wrong offset for guint8:%02x,"
					" got %d, expected %d\n",
					name, sp.g8.needle, sp.g8.offset, i);
			failed = TRUE;
			return FALSE;
		}
		if (sp.g16.test && (guint)sp.g16.offset != i) {
			printf("13: Failed TVB=%s Wrong offset for guint16:%04x,"
					" got %d, expected %d\n",
					name, sp.g16.needle, sp.g16.offset, i);
			failed = TRUE;
			return FALSE;
		}
		if (sp.mempbrk.test && (guint)sp.mempbrk.offset != i) {
			printf("13: Failed TVB=%s Wrong offset for mempbrk:%02x,"
					" got %d, expected %d\n",
					name, expected_data[i], sp.mempbrk.offset, i);
			failed = TRUE;
			return FALSE;
		}
		if (sp.mempbrk.test && sp.mempbrk.found_needle != expected_data[i]) {
			printf("13: Failed TVB=%s Wrong needle found for mempbrk:%02x,"
					" got %02x, expected %02x\n",
					name, expected_data[i], sp.mempbrk.found_needle, expected_data[i]);
			failed = TRUE;
			return FALSE;
		}
	}


	printf("Passed TVB=%s\n", name);

	return TRUE;
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
	guint8		*small[3];
	guint		small_length[3];
	guint		small_reported_length[3];
	guint8		*large[3];
	guint		large_length[3];
	guint		large_reported_length[3];
	guint8		*subset[6];
	guint		subset_length[6];
	guint		subset_reported_length[6];
	guint8		temp;
	guint8		*comp[6];
	tvbuff_t	*tvb_comp[6];
	guint		comp_length[6];
	guint		comp_reported_length[6];
	tvbuff_t	*tvb_comp_subset;
	guint		comp_subset_length;
	guint		comp_subset_reported_length;
	guint8		*comp_subset;
	int		len;

	tvb_parent = tvb_new_real_data((const guint8*)"", 0, 0);
	for (i = 0; i < 3; i++) {
		small[i] = g_new(guint8, 16);

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
		large[i] = g_new(guint8, 19);

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
	comp[1]			= (guint8*)g_malloc(comp_length[1]);
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
	comp[3]			= (guint8*)g_malloc(comp_length[3]);
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
	comp[4]			= (guint8*)g_malloc(comp_length[4]);
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
	comp[5]			= (guint8*)g_malloc(comp_length[5]);

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

/* Note: valgrind can be used to check for tvbuff memory leaks */
int
main(void)
{
	/* For valgrind: See GLib documentation: "Running GLib Applications" */
	g_setenv("G_DEBUG", "gc-friendly", 1);
	g_setenv("G_SLICE", "always-malloc", 1);

	except_init();
	run_tests();
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
