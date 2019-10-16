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
void rtpstream_id_copy_pinfo(const packet_info *pinfo, rtpstream_id_t *dest, gboolean swap_src_dst)
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
/* free memory allocated for id */
void rtpstream_id_free(rtpstream_id_t *id)
{
	free_address(&(id->src_addr));
	free_address(&(id->dst_addr));
	memset(id, 0, sizeof(*id));
}

/****************************************************************************/
/* compare two ids by flags */
gboolean rtpstream_id_equal(const rtpstream_id_t *id1, const rtpstream_id_t *id2, guint flags)
{
	if (addresses_equal(&(id1->src_addr), &(id2->src_addr))
		&& id1->src_port == id2->src_port
		&& addresses_equal(&(id1->dst_addr), &(id2->dst_addr))
		&& id1->dst_port == id2->dst_port)
	{
		gboolean equal = TRUE;

		if ((flags & RTPSTREAM_ID_EQUAL_SSRC)
			&& id1->ssrc != id2->ssrc)
		{
			equal = FALSE;
		}

		return equal;
	}

	return FALSE;
}

/****************************************************************************/
/* compare two ids, one in pinfo */
gboolean rtpstream_id_equal_pinfo_rtp_info(const rtpstream_id_t *id, const packet_info *pinfo, const struct _rtp_info *rtp_info)
{
	if (addresses_equal(&(id->src_addr), &(pinfo->src))
		&& id->src_port == pinfo->srcport
		&& addresses_equal(&(id->dst_addr), &(pinfo->dst))
		&& id->dst_port == pinfo->destport
                && id->ssrc == rtp_info->info_sync_src)
	{
		return TRUE;
	}

	return FALSE;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
