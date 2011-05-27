/* tvbuff-int.h
 *
 * Structures that most TVB users should not be accessing directly.
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __TVBUFF_INT_H__
#define __TVBUFF_INT_H__

typedef struct {
	/** The backing tvbuff_t */
	struct tvbuff	*tvb;

	/** The offset of 'tvb' to which I'm privy */
	guint		offset;
	/** The length of 'tvb' to which I'm privy */
	guint		length;

} tvb_backing_t;

typedef struct {
	GSList		*tvbs;

	/* Used for quick testing to see if this
	 * is the tvbuff that a COMPOSITE is
	 * interested in. */
	guint		*start_offsets;
	guint		*end_offsets;

} tvb_comp_t;

struct tvbuff {
	/* Record-keeping */
	tvbuff_type		type;
	gboolean		initialized;
	guint			usage_count;
	struct tvbuff		*ds_tvb;  /**< data source top-level tvbuff */

	/** The tvbuffs in which this tvbuff is a member
	 * (that is, a backing tvbuff for a TVBUFF_SUBSET
	 * or a member for a TVB_COMPOSITE) */
	GSList			*used_in;

	/** TVBUFF_SUBSET and TVBUFF_COMPOSITE keep track
	 * of the other tvbuff's they use */
	union {
		tvb_backing_t	subset;
		tvb_comp_t	composite;
	} tvbuffs;

	/** We're either a TVBUFF_REAL_DATA or a
	 * TVBUFF_SUBSET that has a backing buffer that
	 * has real_data != NULL, or a TVBUFF_COMPOSITE
	 * which has flattened its data due to a call
	 * to tvb_get_ptr().
	 */
	const guint8		*real_data;

	/** Length of virtual buffer (and/or real_data). */
	guint			length;

	/** Reported length. */
	guint			reported_length;

	/* Offset from beginning of first TVBUFF_REAL. */
	gint			raw_offset;

	/** Func to call when actually freed */
	tvbuff_free_cb_t	free_cb;
};

#endif
