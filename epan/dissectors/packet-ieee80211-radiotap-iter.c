/*
 * Radiotap parser
 *
 * Copyright 2007		Andy Green <andy@warmcat.com>
 * Copyright 2009		Johannes Berg <johannes@sipsolutions.net>
 *
 * SPDX-License-Identifier: (ISC OR GPL-2.0-only)
 */

#include "config.h"

#include <errno.h>

#include <epan/packet.h>
#include <wsutil/pint.h>

#define le16_to_cpu		GINT16_FROM_LE
#define le32_to_cpu		GINT32_FROM_LE
#define get_unaligned_le16	pletoh16
#define get_unaligned_le32	pletoh32

#include "packet-ieee80211-radiotap-iter.h"

/* function prototypes and related defs are in radiotap_iter.h */

static const struct radiotap_align_size rtap_namespace_sizes[] = {
	/* [IEEE80211_RADIOTAP_TSFT] = 0 */			{ 8, 8 },
	/* [IEEE80211_RADIOTAP_FLAGS] = 1 */			{ 1, 1 },
	/* [IEEE80211_RADIOTAP_RATE] = 2 */			{ 1, 1 },
	/* [IEEE80211_RADIOTAP_CHANNEL] = 3 */			{ 2, 4 },
	/* [IEEE80211_RADIOTAP_FHSS] = 4 */			{ 2, 2 },
	/* [IEEE80211_RADIOTAP_DBM_ANTSIGNAL] = 5 */		{ 1, 1 },
	/* [IEEE80211_RADIOTAP_DBM_ANTNOISE] = 6 */		{ 1, 1 },
	/* [IEEE80211_RADIOTAP_LOCK_QUALITY] = 7 */		{ 2, 2 },
	/* [IEEE80211_RADIOTAP_TX_ATTENUATION] = 8 */		{ 2, 2 },
	/* [IEEE80211_RADIOTAP_DB_TX_ATTENUATION] = 9 */	{ 2, 2 },
	/* [IEEE80211_RADIOTAP_DBM_TX_POWER] = 10 */		{ 1, 1 },
	/* [IEEE80211_RADIOTAP_ANTENNA] = 11 */			{ 1, 1 },
	/* [IEEE80211_RADIOTAP_DB_ANTSIGNAL] = 12 */		{ 1, 1 },
	/* [IEEE80211_RADIOTAP_DB_ANTNOISE] = 13 */		{ 1, 1 },
	/* [IEEE80211_RADIOTAP_RX_FLAGS] = 14 */		{ 2, 2 },
	/* [IEEE80211_RADIOTAP_TX_FLAGS] = 15 */		{ 2, 2 },
	/* [IEEE80211_RADIOTAP_RTS_RETRIES] = 16 */		{ 1, 1 },
	/* [IEEE80211_RADIOTAP_DATA_RETRIES] = 17 */		{ 1, 1 },
	/* [IEEE80211_RADIOTAP_XCHANNEL] = 18 */		{ 0, 0 }, /* Unofficial, used by FreeBSD */
	/* [IEEE80211_RADIOTAP_MCS] = 19 */			{ 1, 3 },
	/* [IEEE80211_RADIOTAP_AMPDU_STATUS] = 20 */		{ 4, 8 },
	/* [IEEE80211_RADIOTAP_VHT] = 21 */			{ 2, 12 },
	/* [IEEE80211_RADIOTAP_TIMESTAMP] = 22 */		{ 8, 12 },
	/* [IEEE80211_RADIOTAP_HE] = 23 */			{ 2, 12 },
	/* [IEEE80211_RADIOTAP_HE_MU] = 24 */			{ 2, 12 },
	/* [IEEE80211_RADIOTAP_HE_MU_USER = 25 notdef */	{ 0, 0 },
	/* [IEEE80211_RADIOTAP_0_LENGTH_PSDU = 26 */		{ 1, 1 },
	/* [IEEE80211_RADIOTAP_L_SIG = 27 */			{ 2, 4 },
	/* [IEEE80211_RADIOTAP_TLV = 28 */                      { 4, 10 },
	/*
	 * add more here as they are defined in
	 * include/net/ieee80211_radiotap.h
	 */
};

static const struct ieee80211_radiotap_namespace radiotap_ns = {
	rtap_namespace_sizes,
	(int)array_length(rtap_namespace_sizes),
	0,
	0
};

/*
 * Sanity check.
 */
#define ITERATOR_VALID(iterator, size) \
    (((iterator)->_arg + (size) - (unsigned char *)((iterator)->_rtheader)) <= \
        (ptrdiff_t)(iterator)->_max_length)

/**
 * ieee80211_radiotap_iterator_init - radiotap parser iterator initialization
 * @iterator: radiotap_iterator to initialize
 * @radiotap_header: radiotap header to parse
 * @max_length: total length we can parse into (eg, whole packet length)
 *
 * Returns: 0 or a negative error code if there is a problem.
 *
 * This function initializes an opaque iterator struct which can then
 * be passed to ieee80211_radiotap_iterator_next() to visit every radiotap
 * argument which is present in the header.  It knows about extended
 * present headers and handles them.
 *
 * How to use:
 * call __ieee80211_radiotap_iterator_init() to init a semi-opaque iterator
 * struct ieee80211_radiotap_iterator (no need to init the struct beforehand)
 * checking for a good 0 return code.  Then loop calling
 * __ieee80211_radiotap_iterator_next()... it returns either 0,
 * -ENOENT if there are no more args to parse, or -EINVAL if there is a problem.
 * The iterator's @this_arg member points to the start of the argument
 * associated with the current argument index that is present, which can be
 * found in the iterator's @this_arg_index member.  This arg index corresponds
 * to the IEEE80211_RADIOTAP_... defines.
 *
 * Radiotap header length:
 * You can find the CPU-endian total radiotap header length in
 * iterator->max_length after executing ieee80211_radiotap_iterator_init()
 * successfully.
 *
 * Alignment Gotcha:
 * You must take care when dereferencing iterator.this_arg
 * for multibyte types... the pointer is not aligned.  Use
 * get_unaligned((type *)iterator.this_arg) to dereference
 * iterator.this_arg for type "type" safely on all arches.
 *
 * Example code:
 * See Documentation/networking/radiotap-headers.txt
 */

int ieee80211_radiotap_iterator_init(
	struct ieee80211_radiotap_iterator *iterator,
	struct ieee80211_radiotap_header *radiotap_header,
	int max_length, const struct ieee80211_radiotap_vendor_namespaces *vns)
{
	/* XXX - in Wireshark, we've already checked for this */
	if (max_length < (int)sizeof(struct ieee80211_radiotap_header))
		return -EINVAL;

	/* Linux only supports version 0 radiotap format */
	/* XXX - this is Wireshark, not Linux, and we should report an expert info */
	if (radiotap_header->it_version)
		return -EINVAL;

	/* sanity check for allowed length and radiotap length field */
	/* XXX - in Wireshark, this compares the length against itself. */
	if (max_length < get_unaligned_le16(&radiotap_header->it_len))
		return -EINVAL;

	iterator->_rtheader = radiotap_header;
	iterator->_max_length = get_unaligned_le16(&radiotap_header->it_len);
	iterator->_arg_index = 0;
	iterator->_bitmap_shifter = get_unaligned_le32(&radiotap_header->it_present);
	iterator->_arg = (uint8_t *)radiotap_header + sizeof(*radiotap_header);
	iterator->_reset_on_ext = 0;
	iterator->_next_ns_data = NULL;
	iterator->_next_bitmap = &radiotap_header->it_present;
	iterator->_next_bitmap++;
	iterator->_vns = vns;
	iterator->current_namespace = &radiotap_ns;
	iterator->is_radiotap_ns = 1;
	iterator->tlv_mode = 0;
#ifdef RADIOTAP_SUPPORT_OVERRIDES
	iterator->n_overrides = 0;
	iterator->overrides = NULL;
#endif

	/* find payload start allowing for extended bitmap(s) */
	if (iterator->_bitmap_shifter & (1U << IEEE80211_RADIOTAP_EXT)) {
		/* XXX - we should report an expert info here */
		if (!ITERATOR_VALID(iterator, sizeof(uint32_t)))
			return -EINVAL;
		while (get_unaligned_le32(iterator->_arg) &
					(1U << IEEE80211_RADIOTAP_EXT)) {
			iterator->_arg += sizeof(uint32_t);

			/*
			 * check for insanity where the present bitmaps
			 * keep claiming to extend up to or even beyond the
			 * stated radiotap header length
			 */
			/* XXX - we should report an expert info here */
			if (!ITERATOR_VALID(iterator, sizeof(uint32_t)))
				return -EINVAL;

			/* XXX - we should report an expert info here */
			if ((get_unaligned_le32(iterator->_arg) &
					(1U << IEEE80211_RADIOTAP_TLVS)) &&
			    (get_unaligned_le32(iterator->_arg) &
					(1U << IEEE80211_RADIOTAP_EXT)))
				return -EINVAL;
		}

		iterator->_arg += sizeof(uint32_t);

		/*
		 * no need to check again for blowing past stated radiotap
		 * header length, because ieee80211_radiotap_iterator_next
		 * checks it before it is dereferenced
		 */
	}

	iterator->this_arg = iterator->_arg;

	/* we are all initialized happily */

	return 0;
}

static void find_ns(struct ieee80211_radiotap_iterator *iterator,
		    uint32_t oui, uint8_t subns)
{
	int i;

	iterator->current_namespace = NULL;

	if (!iterator->_vns)
		return;

	for (i = 0; i < iterator->_vns->n_ns; i++) {
		if (iterator->_vns->ns[i].oui != oui)
			continue;
		if (iterator->_vns->ns[i].subns != subns)
			continue;

		iterator->current_namespace = &iterator->_vns->ns[i];
		break;
	}
}

#ifdef RADIOTAP_SUPPORT_OVERRIDES
static int find_override(struct ieee80211_radiotap_iterator *iterator,
			 int *align, int *size)
{
	int i;

	if (!iterator->overrides)
		return 0;

	for (i = 0; i < iterator->n_overrides; i++) {
		if (iterator->_arg_index == iterator->overrides[i].field) {
			*align = iterator->overrides[i].align;
			*size = iterator->overrides[i].size;
			if (!*align) /* erroneous override */
				return 0;
			return 1;
		}
	}

	return 0;
}
#endif


/**
 * ieee80211_radiotap_iterator_next - return next radiotap parser iterator arg
 * @iterator: radiotap_iterator to move to next arg (if any)
 *
 * Returns: 0 if there is an argument to handle,
 * -ENOENT if there are no more args or -EINVAL
 * if there is something else wrong.
 *
 * This function provides the next radiotap arg index (IEEE80211_RADIOTAP_*)
 * in @this_arg_index and sets @this_arg to point to the
 * payload for the field.  It takes care of alignment handling and extended
 * present fields.  @this_arg can be changed by the caller (eg,
 * incremented to move inside a compound argument like
 * IEEE80211_RADIOTAP_CHANNEL).  The args pointed to are in
 * little-endian format whatever the endianess of your CPU.
 *
 * Alignment Gotcha:
 * You must take care when dereferencing iterator.this_arg
 * for multibyte types... the pointer is not aligned.  Use
 * get_unaligned((type *)iterator.this_arg) to dereference
 * iterator.this_arg for type "type" safely on all arches.
 */

int ieee80211_radiotap_iterator_next(
	struct ieee80211_radiotap_iterator *iterator)
{
	if (iterator->tlv_mode) {
		struct ieee80211_radiotap_tlv *tlv;
		uint32_t size;

#define TLV_LEN_ALIGN(x) ((x + 3) & ~3)
		size = sizeof(*tlv) + TLV_LEN_ALIGN(iterator->this_arg_size);

		/*
		 * We know that without the alignment padding it was valid, so
		 * ignore arbitrary padding and return that we finished if no
		 * further TLV could fit.
		 */
		if (!ITERATOR_VALID(iterator, size))
			return -ENOENT;

		/* move to next entry */
		iterator->_arg += sizeof(*tlv) + TLV_LEN_ALIGN(iterator->this_arg_size);

return_tlv:
		/* and check again if we reached the end */
		if (!ITERATOR_VALID(iterator, 1))
			return -ENOENT;

		/* if it's not the end but a new TLV won't fit - error out */
		if (!ITERATOR_VALID(iterator, sizeof(*tlv)))
			return -EINVAL;

		tlv = (struct ieee80211_radiotap_tlv *)iterator->_arg;

		iterator->this_arg_index = get_unaligned_le16(&tlv->type);
		iterator->this_arg_size = get_unaligned_le16(&tlv->datalen);
		iterator->this_arg = tlv->data;
		iterator->is_radiotap_ns =
			iterator->this_arg_index != IEEE80211_RADIOTAP_VENDOR_NAMESPACE;

		if (!ITERATOR_VALID(iterator, sizeof(*tlv) + iterator->this_arg_size))
			return -EINVAL;
		return 0;
	}

	while (1) {
		int hit = 0;
		int pad, align, size, subns;
		uint32_t oui;

		/* if no more EXT bits, that's it */
		if ((iterator->_arg_index % 32) == IEEE80211_RADIOTAP_EXT &&
		    !(iterator->_bitmap_shifter & 1))
			return -ENOENT;

		if (!(iterator->_bitmap_shifter & 1))
			goto next_entry; /* arg not present */

		/* get alignment/size of data */
		switch (iterator->_arg_index % 32) {
		case IEEE80211_RADIOTAP_TLVS:
			align = 4;
			size = 0;
			break;
		case IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE:
		case IEEE80211_RADIOTAP_EXT:
			align = 1;
			size = 0;
			break;
		case IEEE80211_RADIOTAP_VENDOR_NAMESPACE:
			align = 2;
			size = 6;
			break;
		default:
#ifdef RADIOTAP_SUPPORT_OVERRIDES
			if (find_override(iterator, &align, &size)) {
				/* all set */
			} else
#endif
			if (!iterator->current_namespace ||
			    iterator->_arg_index >= iterator->current_namespace->n_bits) {
				if (iterator->current_namespace == &radiotap_ns)
					return -ENOENT;
				align = 0;
			} else {
				align = iterator->current_namespace->align_size[iterator->_arg_index].align;
				size = iterator->current_namespace->align_size[iterator->_arg_index].size;
			}
			if (!align) {
				/* skip all subsequent data */
				int skip_size = IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE - (iterator->_arg_index % 32);
				/* XXX - we should report an expert info here */
				if (!iterator->_next_ns_data)
					return -EINVAL;
				iterator->_arg = iterator->_next_ns_data;
				/* give up on this namespace */
				iterator->current_namespace = NULL;
				iterator->_next_ns_data = NULL;
				// Remove 1 because jump to next_entry will also shift bitmap by 1
				iterator->_bitmap_shifter >>= skip_size - 1;
				iterator->_arg_index += skip_size - 1;
				/* XXX - we should report an expert info here */
				if (!ITERATOR_VALID(iterator, 0))
					return -EINVAL;
				goto next_entry;
			}
			break;
		}

		/*
		 * arg is present, account for alignment padding
		 *
		 * Note that these alignments are relative to the start
		 * of the radiotap header.  There is no guarantee
		 * that the radiotap header itself is aligned on any
		 * kind of boundary.
		 *
		 * The above is why get_unaligned() is used to dereference
		 * multibyte elements from the radiotap area.
		 */

		pad = (int)((iterator->_arg - (unsigned char *)iterator->_rtheader) & (align - 1));

		if (pad)
			iterator->_arg += align - pad;

		if (iterator->_arg_index % 32 == IEEE80211_RADIOTAP_VENDOR_NAMESPACE) {
			int vnslen;

			/* XXX - we should report an expert info here */
			if (!ITERATOR_VALID(iterator, size))
				return -EINVAL;

			oui = (*iterator->_arg << 16) |
				(*(iterator->_arg + 1) << 8) |
				*(iterator->_arg + 2);
			subns = *(iterator->_arg + 3);

			find_ns(iterator, oui, subns);

			vnslen = get_unaligned_le16(iterator->_arg + 4);
			iterator->_next_ns_data = iterator->_arg + size + vnslen;
			if (!iterator->current_namespace)
				size += vnslen;
		} else if (iterator->_arg_index % 32 == IEEE80211_RADIOTAP_TLVS) {
			iterator->tlv_mode = 1;
			goto return_tlv;
		}

		/*
		 * this is what we will return to user, but we need to
		 * move on first so next call has something fresh to test
		 */
		iterator->this_arg_index = iterator->_arg_index;
		iterator->this_arg = iterator->_arg;
		iterator->this_arg_size = size;

		/* internally move on the size of this arg */
		iterator->_arg += size;

		/*
		 * check for insanity where we are given a bitmap that
		 * claims to have more arg content than the length of the
		 * radiotap section.  We will normally end up equalling this
		 * max_length on the last arg, never exceeding it.
		 */
		/* XXX - we should report an expert info here */
		if (!ITERATOR_VALID(iterator, 0))
			return -EINVAL;

		/* these special ones are valid in each bitmap word */
		switch (iterator->_arg_index % 32) {
		case IEEE80211_RADIOTAP_VENDOR_NAMESPACE:
			iterator->_reset_on_ext = 1;

			iterator->is_radiotap_ns = 0;
			/*
			 * If parser didn't register this vendor
			 * namespace with us, allow it to show it
			 * as 'raw. Do do that, set argument index
			 * to vendor namespace.
			 */
			iterator->this_arg_index =
				IEEE80211_RADIOTAP_VENDOR_NAMESPACE;
			if (!iterator->current_namespace)
				hit = 1;
			goto next_entry;
		case IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE:
			iterator->_reset_on_ext = 1;
			iterator->current_namespace = &radiotap_ns;
			iterator->is_radiotap_ns = 1;
			goto next_entry;
		case IEEE80211_RADIOTAP_EXT:
			/*
			 * bit 31 was set, there is more
			 * -- move to next u32 bitmap
			 */
			iterator->_bitmap_shifter =
				get_unaligned_le32(iterator->_next_bitmap);
			iterator->_next_bitmap++;
			if (iterator->_reset_on_ext)
				iterator->_arg_index = 0;
			else
				iterator->_arg_index++;
			iterator->_reset_on_ext = 0;
			break;
		default:
			/* we've got a hit! */
			hit = 1;
 next_entry:
			iterator->_bitmap_shifter >>= 1;
			iterator->_arg_index++;
		}

		/* if we found a valid arg earlier, return it now */
		if (hit)
			return 0;
	}
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
