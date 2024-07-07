/* frame_tvbuff.c
 * Implements a tvbuff for frame
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/tvbuff-int.h>
#include <epan/tvbuff.h>

#include "frame_tvbuff.h"

#include "wiretap/wtap-int.h" /* for ->random_fh */

struct tvb_frame {
    struct tvbuff tvb;

    Buffer *buf;         /* Packet data */

    const struct packet_provider_data *prov;	/* provider of packet information */
    int64_t file_off;     /**< File offset */

    unsigned offset;
};

static bool
frame_read(struct tvb_frame *frame_tvb, wtap_rec *rec, Buffer *buf)
{
    int    err;
    char *err_info;
    bool ok = true;

    /* XXX, what if phdr->caplen isn't equal to
     * frame_tvb->tvb.length + frame_tvb->offset?
     */
    if (!wtap_seek_read(frame_tvb->prov->wth, frame_tvb->file_off, rec, buf, &err, &err_info)) {
        /* XXX - report error! */
        switch (err) {
            case WTAP_ERR_BAD_FILE:
                g_free(err_info);
                ok = false;
                break;
        }
    }
    return ok;
}

static GPtrArray *buffer_cache;

static void
frame_cache(struct tvb_frame *frame_tvb)
{
    wtap_rec rec; /* Record metadata */

    wtap_rec_init(&rec);

    if (frame_tvb->buf == NULL) {
        if (G_UNLIKELY(!buffer_cache)) buffer_cache = g_ptr_array_sized_new(1024);

        if (buffer_cache->len > 0) {
            frame_tvb->buf = (struct Buffer *) g_ptr_array_remove_index(buffer_cache, buffer_cache->len - 1);
        } else {
            frame_tvb->buf = g_new(struct Buffer, 1);
        }

        ws_buffer_init(frame_tvb->buf, frame_tvb->tvb.length + frame_tvb->offset);

        if (!frame_read(frame_tvb, &rec, frame_tvb->buf))
        { /* TODO: THROW(???); */ }
    }

    frame_tvb->tvb.real_data = ws_buffer_start_ptr(frame_tvb->buf) + frame_tvb->offset;

    wtap_rec_cleanup(&rec);
}

static void
frame_free(tvbuff_t *tvb)
{
    struct tvb_frame *frame_tvb = (struct tvb_frame *) tvb;

    if (frame_tvb->buf) {
        ws_buffer_free(frame_tvb->buf);
        g_ptr_array_add(buffer_cache, frame_tvb->buf);
    }
}

static const uint8_t *
frame_get_ptr(tvbuff_t *tvb, unsigned abs_offset, unsigned abs_length _U_)
{
    struct tvb_frame *frame_tvb = (struct tvb_frame *) tvb;

    frame_cache(frame_tvb);

    return tvb->real_data + abs_offset;
}

static void *
frame_memcpy(tvbuff_t *tvb, void *target, unsigned abs_offset, unsigned abs_length)
{
    struct tvb_frame *frame_tvb = (struct tvb_frame *) tvb;

    frame_cache(frame_tvb);

    return memcpy(target, tvb->real_data + abs_offset, abs_length);
}

static int
frame_find_guint8(tvbuff_t *tvb, unsigned abs_offset, unsigned limit, uint8_t needle)
{
    struct tvb_frame *frame_tvb = (struct tvb_frame *) tvb;
    const uint8_t *result;

    frame_cache(frame_tvb);

    result = (const uint8_t *)memchr(tvb->real_data + abs_offset, needle, limit);
    if (result)
        return (int) (result - tvb->real_data);
    else
        return -1;
}

static int
frame_pbrk_guint8(tvbuff_t *tvb, unsigned abs_offset, unsigned limit, const ws_mempbrk_pattern* pattern, unsigned char *found_needle)
{
    struct tvb_frame *frame_tvb = (struct tvb_frame *) tvb;

    frame_cache(frame_tvb);

    return tvb_ws_mempbrk_pattern_guint8(tvb, abs_offset, limit, pattern, found_needle);
}

static unsigned
frame_offset(const tvbuff_t *tvb _U_, const unsigned counter)
{
    /* XXX: frame_tvb->offset */
    return counter;
}

static tvbuff_t *frame_clone(tvbuff_t *tvb, unsigned abs_offset, unsigned abs_length);

static const struct tvb_ops tvb_frame_ops = {
    sizeof(struct tvb_frame), /* size */

    frame_free,           /* free */
    frame_offset,         /* offset */
    frame_get_ptr,        /* get_ptr */
    frame_memcpy,         /* memcpy */
    frame_find_guint8,    /* find_guint8 */
    frame_pbrk_guint8,    /* pbrk_guint8 */
    frame_clone,          /* clone */
};

/* based on tvb_new_real_data() */
tvbuff_t *
frame_tvbuff_new(const struct packet_provider_data *prov, const frame_data *fd,
        const uint8_t *buf)
{
    struct tvb_frame *frame_tvb;
    tvbuff_t *tvb;

    tvb = tvb_new(&tvb_frame_ops);

    /*
     * XXX - currently, the length arguments in
     * tvbuff structure are signed, but the captured
     * and reported length values are unsigned; this means
     * that length values > 2^31 - 1 will appear as
     * negative lengths
     *
     * Captured length values that large will already
     * have been filtered out by the Wiretap modules
     * (the file will be reported as corrupted), to
     * avoid trying to allocate large chunks of data.
     *
     * Reported length values will not have been
     * filtered out, and should not be filtered out,
     * as those lengths are not necessarily invalid.
     *
     * For now, we clip the reported length at INT_MAX
     *
     * (XXX, is this still a problem?) There was an exception when we call
     * tvb_new_real_data() now there's no one
     */

    tvb->real_data        = buf;
    tvb->length           = fd->cap_len;
    tvb->reported_length  = fd->pkt_len > INT_MAX ? INT_MAX : fd->pkt_len;
    tvb->contained_length = tvb->reported_length;
    tvb->initialized      = true;

    /*
     * This is the top-level real tvbuff for this data source,
     * so its data source tvbuff is itself.
     */
    tvb->ds_tvb = tvb;

    frame_tvb = (struct tvb_frame *) tvb;

    /* XXX, wtap_can_seek() */
    if (prov->wth && prov->wth->random_fh) {
        frame_tvb->prov = prov;
        frame_tvb->file_off = fd->file_off;
        frame_tvb->offset = 0;
    } else
        frame_tvb->prov = NULL;

    frame_tvb->buf = NULL;

    return tvb;
}

tvbuff_t *
frame_tvbuff_new_buffer(const struct packet_provider_data *prov,
        const frame_data *fd, Buffer *buf)
{
    return frame_tvbuff_new(prov, fd, ws_buffer_start_ptr(buf));
}

static tvbuff_t *
frame_clone(tvbuff_t *tvb, unsigned abs_offset, unsigned abs_length)
{
    struct tvb_frame *frame_tvb = (struct tvb_frame *) tvb;

    tvbuff_t *cloned_tvb;
    struct tvb_frame *cloned_frame_tvb;

    /* file not seekable */
    if (!frame_tvb->prov)
        return NULL;

    abs_offset += frame_tvb->offset;

    cloned_tvb = tvb_new(&tvb_frame_ops);

    /* data will be read when needed */
    cloned_tvb->real_data        = NULL;
    cloned_tvb->length           = abs_length;
    cloned_tvb->reported_length  = abs_length; /* XXX? */
    cloned_tvb->contained_length = cloned_tvb->reported_length;
    cloned_tvb->initialized      = true;

    /*
     * This is the top-level real tvbuff for this data source,
     * so its data source tvbuff is itself.
     */
    cloned_tvb->ds_tvb = cloned_tvb;

    cloned_frame_tvb = (struct tvb_frame *) cloned_tvb;
    cloned_frame_tvb->prov = frame_tvb->prov;
    cloned_frame_tvb->file_off = frame_tvb->file_off;
    cloned_frame_tvb->offset = abs_offset;
    cloned_frame_tvb->buf = NULL;

    return cloned_tvb;
}


/* based on tvb_new_real_data() */
tvbuff_t *
file_tvbuff_new(const struct packet_provider_data *prov, const frame_data *fd,
        const uint8_t *buf)
{
    struct tvb_frame *frame_tvb;
    tvbuff_t *tvb;

    tvb = tvb_new(&tvb_frame_ops);

    /*
     * XXX - currently, the length arguments in
     * tvbuff structure are signed, but the captured
     * and reported length values are unsigned; this means
     * that length values > 2^31 - 1 will appear as
     * negative lengths
     *
     * Captured length values that large will already
     * have been filtered out by the Wiretap modules
     * (the file will be reported as corrupted), to
     * avoid trying to allocate large chunks of data.
     *
     * Reported length values will not have been
     * filtered out, and should not be filtered out,
     * as those lengths are not necessarily invalid.
     *
     * For now, we clip the reported length at INT_MAX
     *
     * (XXX, is this still a problem?) There was an exception when we call
     * tvb_new_real_data() now there's no one
     */

    tvb->real_data        = buf;
    tvb->length           = fd->cap_len;
    tvb->reported_length  = fd->pkt_len > INT_MAX ? INT_MAX : fd->pkt_len;
    tvb->contained_length = tvb->reported_length;
    tvb->initialized      = true;

    /*
     * This is the top-level real tvbuff for this data source,
     * so its data source tvbuff is itself.
     */
    tvb->ds_tvb = tvb;

    frame_tvb = (struct tvb_frame *) tvb;

    /* XXX, wtap_can_seek() */
    if (prov->wth && prov->wth->random_fh) {
        frame_tvb->prov = prov;
        frame_tvb->file_off = fd->file_off;
        frame_tvb->offset = 0;
    } else
        frame_tvb->prov = NULL;

    frame_tvb->buf = NULL;

    return tvb;
}

tvbuff_t *
file_tvbuff_new_buffer(const struct packet_provider_data *prov,
        const frame_data *fd, Buffer *buf)
{
    return frame_tvbuff_new(prov, fd, ws_buffer_start_ptr(buf));
}
