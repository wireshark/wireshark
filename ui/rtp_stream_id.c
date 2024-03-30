/* rtp_stream_id.c
 * RTP stream id functions for Wireshark
 *
 * Copyright 2003, Alcatel Business Systems
 * By Lars Ruoff <lars.ruoff@gmx.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include "file.h"

#include "ui/rtp_stream_id.h"
#include "epan/dissectors/packet-rtp.h"

/****************************************************************************/
/* rtpstream id functions */
/****************************************************************************/

/****************************************************************************/
/* deep copy of id */
void rtpstream_id_copy(const rtpstream_id_t *src, rtpstream_id_t *dest)
{
    copy_address(&(dest->src_addr), &(src->src_addr));
    dest->src_port=src->src_port;
    copy_address(&(dest->dst_addr), &(src->dst_addr));
    dest->dst_port=src->dst_port;
    dest->ssrc=src->ssrc;
}

/****************************************************************************/
/* deep copy of id from packet_info */
void rtpstream_id_copy_pinfo(const packet_info *pinfo, rtpstream_id_t *dest, bool swap_src_dst)
{
	if (!swap_src_dst)
	{
		copy_address(&(dest->src_addr), &(pinfo->src));
		dest->src_port=pinfo->srcport;
		copy_address(&(dest->dst_addr), &(pinfo->dst));
		dest->dst_port=pinfo->destport;
	}
	else
	{
		copy_address(&(dest->src_addr), &(pinfo->dst));
		dest->src_port=pinfo->destport;
		copy_address(&(dest->dst_addr), &(pinfo->src));
		dest->dst_port=pinfo->srcport;
	}
}

/****************************************************************************/
/* shallow copy from packet_info to id */
void rtpstream_id_copy_pinfo_shallow(const packet_info *pinfo, rtpstream_id_t *dest, bool swap_src_dst)
{
	if (!swap_src_dst)
	{
		copy_address_shallow(&(dest->src_addr), &(pinfo->src));
		dest->src_port=pinfo->srcport;
		copy_address_shallow(&(dest->dst_addr), &(pinfo->dst));
		dest->dst_port=pinfo->destport;
	}
	else
	{
		copy_address_shallow(&(dest->src_addr), &(pinfo->dst));
		dest->src_port=pinfo->destport;
		copy_address_shallow(&(dest->dst_addr), &(pinfo->src));
		dest->dst_port=pinfo->srcport;
	}
}
/****************************************************************************/
/* free memory allocated for id */
void rtpstream_id_free(rtpstream_id_t *id)
{
	free_address(&(id->src_addr));
	free_address(&(id->dst_addr));
	memset(id, 0, sizeof(*id));
}

/****************************************************************************/
/* convert rtpstream_id_t to hash */
unsigned rtpstream_id_to_hash(const rtpstream_id_t *id)
{
	unsigned hash = 0;

	if (!id) { return 0; }
	/* XOR of: */
	/* SRC PORT | DST_PORT */
	/* SSRC */
	/* SRC ADDR */
	/* DST ADDR */
	hash ^= id->src_port | id->dst_port << 16;
	hash ^= id->ssrc;
	hash = add_address_to_hash(hash, &id->src_addr);
	hash = add_address_to_hash(hash, &id->dst_addr);

	return hash;
}

/****************************************************************************/
/* compare two ids by flags */
bool rtpstream_id_equal(const rtpstream_id_t *id1, const rtpstream_id_t *id2, unsigned flags)
{
	if (addresses_equal(&(id1->src_addr), &(id2->src_addr))
		&& id1->src_port == id2->src_port
		&& addresses_equal(&(id1->dst_addr), &(id2->dst_addr))
		&& id1->dst_port == id2->dst_port)
	{
		bool equal = true;

		if ((flags & RTPSTREAM_ID_EQUAL_SSRC)
			&& id1->ssrc != id2->ssrc)
		{
			equal = false;
		}

		return equal;
	}

	return false;
}

/****************************************************************************/
/* compare an rtpstream id address and ports with pinfo */
bool rtpstream_id_equal_pinfo(const rtpstream_id_t *id, const packet_info *pinfo, bool swap_src_dst)
{
        if (!swap_src_dst) {
                if (addresses_equal(&(id->src_addr), &(pinfo->src))
                        && id->src_port == pinfo->srcport
                        && addresses_equal(&(id->dst_addr), &(pinfo->dst))
                        && id->dst_port == pinfo->destport)
                {
                        return true;
                }
        } else {
                if (addresses_equal(&(id->src_addr), &(pinfo->dst))
                        && id->src_port == pinfo->destport
                        && addresses_equal(&(id->dst_addr), &(pinfo->src))
                        && id->dst_port == pinfo->srcport)
                {
                        return true;
                }
        }

	return false;
}
/****************************************************************************/
/* compare two ids, one in pinfo */
bool rtpstream_id_equal_pinfo_rtp_info(const rtpstream_id_t *id, const packet_info *pinfo, const struct _rtp_info *rtp_info)
{
	if (addresses_equal(&(id->src_addr), &(pinfo->src))
		&& id->src_port == pinfo->srcport
		&& addresses_equal(&(id->dst_addr), &(pinfo->dst))
		&& id->dst_port == pinfo->destport
                && id->ssrc == rtp_info->info_sync_src)
	{
		return true;
	}

	return false;
}

/****************************************************************************/
/* convert packet_info and _rtp_info to hash */
unsigned pinfo_rtp_info_to_hash(const packet_info *pinfo, const struct _rtp_info *rtp_info)
{
	unsigned hash = 0;

	if (!pinfo || !rtp_info) { return 0; }
	/* XOR of: */
	/* SRC PORT | DST_PORT */
	/* SSRC */
	/* SRC ADDR */
	/* DST ADDR */
	hash ^= pinfo->srcport | pinfo->destport << 16;
	hash ^= rtp_info->info_sync_src;
	hash = add_address_to_hash(hash, &pinfo->src);
	hash = add_address_to_hash(hash, &pinfo->dst);

	return hash;
}
