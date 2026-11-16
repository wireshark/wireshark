/* mdf.c
 *
 * File format support for the ASAM MDF (MF4) file format
 * Copyright (c) 2022-2026 by Dr. Lars Voelker <lars.voelker@technica-engineering.de>
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * The following was used as a reference for the file format:
 *     ASAM MDF 4.3.0 Base Standard
 *     ASAM MDF Bus Logging 1.0.2
 *
 * Only bus logging (Ethernet, CAN/CAN FD, LIN and FlexRay) is turned into packets.
 * Everything else in the file is ignored.
 *
 * Reading works in two steps. When the file is opened, the block tree is
 * walked and all data groups with supported bus events are scanned once.
 * This yields a list of events (time stamp, channel group, position in the
 * data of the data group), which is sorted by time. Reading a packet then
 * means reading the record of the event (and its payload, if that is
 * stored as variable length data) and building the packet from it.
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_WIRETAP

#include "mdf.h"

#include <epan/dissectors/packet-socketcan.h>
#include <epan/dissectors/packet-flexray.h>
#include <epan/dissectors/packet-lin.h>
#include <math.h>
#include <string.h>

#include <wsutil/pint.h>
#include <wsutil/wslog.h>
#include <wsutil/zlib_compat.h>

#include "wtap_module.h"
#include "wtap-int.h"
#include "file_wrappers.h"

#define MDF_LEN_ID_BLOCK        64
#define MDF_LEN_MAGIC           8
#define MDF_LEN_BLOCK_HDR       24
#define MDF_MIN_VERSION         400

/* Limits that protect against corrupt or malicious files. */
#define MDF_MAX_META_BLOCK_LEN  (16U * 1024U * 1024U)
#define MDF_MAX_FRAGMENT_LEN    (256U * 1024U * 1024U)
#define MDF_MAX_VLSD_LEN        (16U * 1024U * 1024U)
#define MDF_MAX_BLOCKS_PER_LIST 1000000U
#define MDF_MAX_CHANNELS        65536U
#define MDF_MAX_DEPTH           16
#define MDF_MAX_INFLATE_RATIO   1032U
#define MDF_SCAN_WINDOW         (1024U * 1024U)

#define MDF_CN_TYPE_FIXED       0
#define MDF_CN_TYPE_VLSD        1
#define MDF_CN_TYPE_MASTER      2
#define MDF_CN_TYPE_MLSD        5
#define MDF_CN_TYPE_VIRTUAL     6
#define MDF_CN_SYNC_TIME        1
#define MDF_CN_FLAG_BUS_EVENT   0x00000400
#define MDF_CN_DT_BYTE_ARRAY    10

#define MDF_CG_FLAG_VLSD        0x0001
#define MDF_CG_FLAG_BUS_EVENT   0x0002

#define MDF_DZ_DEFLATE          0
#define MDF_DZ_TRANSPOSED       1

static const uint8_t mdf_magic_fin[MDF_LEN_MAGIC] = { 'M', 'D', 'F', ' ', ' ', ' ', ' ', ' ' };

static int mdf_file_type_subtype = -1;

void register_mdf(void);
static bool mdf_read(wtap *wth, wtap_rec *rec, int *err, char **err_info, int64_t *data_offset);
static bool mdf_seek_read(wtap *wth, int64_t seek_off, wtap_rec *rec, int *err, char **err_info);
static void mdf_close(wtap *wth);

/* ------------------------------------------------------------------------ */
/* Basic access to blocks                                                   */
/* ------------------------------------------------------------------------ */

typedef struct {
    uint8_t  *buf;          /* the complete block, header included */
    uint64_t  length;
    uint64_t  link_count;
} mdf_block_t;

static bool
mdf_read_at(FILE_T fh, int64_t pos, void *buf, unsigned len, int *err, char **err_info) {
    if (pos < 0 || file_seek(fh, pos, SEEK_SET, err) == -1) {
        if (pos < 0) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup("mdf: negative file position");
        }
        return false;
    }
    return wtap_read_bytes(fh, buf, len, err, err_info);
}

static bool
mdf_id_is(const uint8_t *buf, const char *id) {
    return memcmp(buf, id, 4) == 0;
}

/* Loads the (meta data) block at pos. The caller frees blk->buf. */
static bool
mdf_load_block(FILE_T fh, int64_t pos, mdf_block_t *blk, int *err, char **err_info) {
    uint8_t hdr[MDF_LEN_BLOCK_HDR];

    blk->buf = NULL;
    if (!mdf_read_at(fh, pos, hdr, sizeof(hdr), err, err_info)) {
        return false;
    }
    blk->length = pletohu64(hdr + 8);
    blk->link_count = pletohu64(hdr + 16);
    if (hdr[0] != '#' || hdr[1] != '#' || blk->length < MDF_LEN_BLOCK_HDR || blk->length > MDF_MAX_META_BLOCK_LEN ||
        blk->link_count > (blk->length - MDF_LEN_BLOCK_HDR) / 8) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("mdf: invalid block at offset %" PRId64, pos);
        return false;
    }

    blk->buf = (uint8_t *)g_try_malloc((size_t)blk->length);
    if (blk->buf == NULL) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup("mdf: cannot allocate memory for block");
        return false;
    }
    memcpy(blk->buf, hdr, sizeof(hdr));
    if (blk->length > MDF_LEN_BLOCK_HDR &&
        !wtap_read_bytes(fh, blk->buf + MDF_LEN_BLOCK_HDR, (unsigned)(blk->length - MDF_LEN_BLOCK_HDR), err, err_info)) {
        g_free(blk->buf);
        blk->buf = NULL;
        return false;
    }
    return true;
}

static void
mdf_free_block(mdf_block_t *blk) {
    g_free(blk->buf);
    blk->buf = NULL;
}

static int64_t
mdf_link(const mdf_block_t *blk, uint64_t idx) {
    if (idx >= blk->link_count) {
        return 0;
    }
    return (int64_t)pletohu64(blk->buf + MDF_LEN_BLOCK_HDR + 8 * idx);
}

static const uint8_t *
mdf_data(const mdf_block_t *blk) {
    return blk->buf + MDF_LEN_BLOCK_HDR + 8 * blk->link_count;
}

static uint64_t
mdf_data_len(const mdf_block_t *blk) {
    return blk->length - MDF_LEN_BLOCK_HDR - 8 * blk->link_count;
}

/* Returns the text of the TX block at pos, or NULL. Caller frees. */
static char *
mdf_load_text(FILE_T fh, int64_t pos) {
    mdf_block_t blk;
    char       *text = NULL;
    int         err = 0;
    char       *err_info = NULL;

    if (pos == 0 || !mdf_load_block(fh, pos, &blk, &err, &err_info)) {
        g_free(err_info);
        return NULL;
    }
    if (mdf_id_is(blk.buf, "##TX") && mdf_data_len(&blk) > 0) {
        const uint8_t *d = mdf_data(&blk);
        const uint8_t *end = (const uint8_t *)memchr(d, 0, (size_t)mdf_data_len(&blk));
        size_t         len = end ? (size_t)(end - d) : (size_t)mdf_data_len(&blk);

        text = g_strndup((const char *)d, len);
    }
    mdf_free_block(&blk);
    return text;
}

/* ------------------------------------------------------------------------ */
/* Data streams: the data of a data group (or of a signal data channel) can */
/* be one block or spread over lists of (compressed) blocks.                */
/* ------------------------------------------------------------------------ */

typedef struct {
    int64_t   file_pos;     /* start of the data (compressed data for DZ blocks) */
    uint64_t  stored_len;
    uint64_t  len;          /* length of the uncompressed data */
    uint64_t  stream_start;
    uint8_t   zip_type;     /* MDF_DZ_DEFLATE, MDF_DZ_TRANSPOSED or UINT8_MAX if not compressed */
    uint32_t  zip_param;
} mdf_frag_t;

#define MDF_READ_AHEAD      (32U * 1024U)
#define MDF_RA_SLOTS        16

/* Reading in time order moves through the data of a data group at several places
 * at once (one per channel group), so we keep a few pieces of it. */
typedef struct {
    uint8_t  *buf;
    uint64_t  start;        /* stream offset of buf */
    uint64_t  len;
    uint64_t  used;
} mdf_ra_slot_t;

typedef struct {
    GArray   *frags;        /* of mdf_frag_t */
    uint64_t  total;
    int       cached;       /* index of the fragment in cache, -1 if none */
    uint8_t  *cache;
    uint64_t  cache_len;
    mdf_ra_slot_t ra[MDF_RA_SLOTS]; /* read ahead for small reads of not compressed data */
    uint64_t  ra_tick;
} mdf_stream_t;

#define MDF_NOT_COMPRESSED  UINT8_MAX

static mdf_stream_t *
mdf_stream_new(void) {
    mdf_stream_t *s = g_new0(mdf_stream_t, 1);

    s->frags = g_array_new(false, false, sizeof(mdf_frag_t));
    s->cached = -1;
    return s;
}

static void
mdf_stream_free(mdf_stream_t *s) {
    unsigned i;

    if (s == NULL) {
        return;
    }
    g_array_free(s->frags, true);
    g_free(s->cache);
    for (i = 0; i < MDF_RA_SLOTS; i++) {
        g_free(s->ra[i].buf);
    }
    g_free(s);
}

/* Adds the data of the DT/SD/DZ/DL/HL block at pos. Returns false with err set
 * on errors; sets *unsupported (and returns true) for what we cannot handle.
 * The recursion is bounded by MDF_MAX_DEPTH. */
static bool
mdf_stream_add(mdf_stream_t *s, FILE_T fh, int64_t pos, int depth, bool *unsupported, int *err, char **err_info) { // NOLINT(misc-no-recursion)
    uint8_t     hdr[MDF_LEN_BLOCK_HDR];
    uint64_t    length, link_count, data_len;
    int64_t     data_pos;
    mdf_block_t blk;
    mdf_frag_t  frag;

    if (pos == 0) {
        return true;
    }
    if (depth > MDF_MAX_DEPTH) {
        *unsupported = true;
        return true;
    }
    /* Data blocks can be huge, so only look at their header. */
    if (!mdf_read_at(fh, pos, hdr, sizeof(hdr), err, err_info)) {
        return false;
    }
    length = pletohu64(hdr + 8);
    link_count = pletohu64(hdr + 16);
    if (hdr[0] != '#' || hdr[1] != '#' || length < MDF_LEN_BLOCK_HDR || link_count > (length - MDF_LEN_BLOCK_HDR) / 8) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("mdf: invalid block at offset %" PRId64, pos);
        return false;
    }
    data_len = length - MDF_LEN_BLOCK_HDR - 8 * link_count;
    data_pos = pos + MDF_LEN_BLOCK_HDR + 8 * (int64_t)link_count;

    memset(&frag, 0, sizeof(frag));
    frag.zip_type = MDF_NOT_COMPRESSED;
    frag.stream_start = s->total;

    if (mdf_id_is(hdr, "##DT") || mdf_id_is(hdr, "##SD") || mdf_id_is(hdr, "##DV") ||
        mdf_id_is(hdr, "##DI") || mdf_id_is(hdr, "##RD")) {
        frag.file_pos = data_pos;
        frag.stored_len = frag.len = data_len;
    } else if (mdf_id_is(hdr, "##DZ")) {
        uint8_t d[24];

        if (data_len < sizeof(d)) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup("mdf: DZ block too short");
            return false;
        }
        if (!mdf_read_at(fh, data_pos, d, sizeof(d), err, err_info)) {
            return false;
        }
        frag.zip_type = d[2];
        frag.zip_param = pletohu32(d + 4);
        frag.len = pletohu64(d + 8);
        frag.stored_len = pletohu64(d + 16);
        frag.file_pos = data_pos + (int64_t)sizeof(d);
        if (frag.stored_len > data_len - sizeof(d) || frag.len > MDF_MAX_FRAGMENT_LEN ||
            (frag.zip_type != MDF_DZ_DEFLATE && frag.zip_type != MDF_DZ_TRANSPOSED) ||
            (frag.zip_type == MDF_DZ_TRANSPOSED && frag.zip_param == 0)) {
            /* ZStd and the like */
            *unsupported = true;
            return true;
        }
    } else if (mdf_id_is(hdr, "##DL")) {
        /* links: next, data[...] */
        bool     ok = true;
        int64_t  next;
        uint64_t i;

        if (!mdf_load_block(fh, pos, &blk, err, err_info)) {
            return false;
        }
        next = mdf_link(&blk, 0);
        for (i = 1; ok && i < blk.link_count && !*unsupported; i++) {
            ok = mdf_stream_add(s, fh, mdf_link(&blk, i), depth + 1, unsupported, err, err_info);
        }
        mdf_free_block(&blk);
        if (ok && !*unsupported && next != 0) {
            if (s->frags->len > MDF_MAX_BLOCKS_PER_LIST) {
                *unsupported = true;
                return true;
            }
            /* the next block of the list of lists */
            return mdf_stream_add(s, fh, next, depth + 1, unsupported, err, err_info);
        }
        return ok;
    } else if (mdf_id_is(hdr, "##HL")) {
        int64_t first;

        if (!mdf_load_block(fh, pos, &blk, err, err_info)) {
            return false;
        }
        first = mdf_link(&blk, 0);
        mdf_free_block(&blk);
        return mdf_stream_add(s, fh, first, depth + 1, unsupported, err, err_info);
    } else {
        /* LD blocks (column oriented storage) and others */
        *unsupported = true;
        return true;
    }

    if (frag.len > 0) {
        g_array_append_val(s->frags, frag);
        s->total += frag.len;
    }
    return true;
}

#ifdef USE_ZLIB_OR_ZLIBNG
static uint8_t *
mdf_inflate(const uint8_t *in, uint64_t in_len, uint64_t out_len, int *err, char **err_info) {
    zlib_stream  z = {0};
    uint8_t     *out;
    int          ret;

    if (in_len == 0 || out_len == 0 || in_len > UINT32_MAX || out_len > MDF_MAX_FRAGMENT_LEN ||
        out_len / in_len > MDF_MAX_INFLATE_RATIO) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("mdf: implausible compressed block length");
        return NULL;
    }
    out = (uint8_t *)g_try_malloc((size_t)out_len);
    if (out == NULL) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup("mdf: cannot allocate memory for decompression");
        return NULL;
    }
    if (ZLIB_PREFIX(inflateInit)(&z) != Z_OK) {
        g_free(out);
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup("mdf: inflateInit failed");
        return NULL;
    }
    z.next_in = (uint8_t *)in;
    z.avail_in = (unsigned)in_len;
    z.next_out = out;
    z.avail_out = (unsigned)out_len;
    ret = ZLIB_PREFIX(inflate)(&z, Z_FINISH);
    ZLIB_PREFIX(inflateEnd)(&z);
    if (ret != Z_STREAM_END || z.avail_out != 0) {
        g_free(out);
        *err = WTAP_ERR_DECOMPRESS;
        *err_info = ws_strdup("mdf: could not decompress data block");
        return NULL;
    }
    return out;
}

/* Undoes the transposition of "Transposition + Deflate". */
static void
mdf_untranspose(uint8_t *out, const uint8_t *in, uint64_t len, uint32_t columns) {
    uint64_t rows = len / columns;
    uint64_t r, c;

    for (c = 0; c < columns; c++) {
        for (r = 0; r < rows; r++) {
            out[r * columns + c] = in[c * rows + r];
        }
    }
    memcpy(out + rows * columns, in + rows * columns, (size_t)(len - rows * columns));
}
#endif

/* Makes the uncompressed data of fragment idx available in the cache. */
static bool
mdf_stream_cache(mdf_stream_t *s, FILE_T fh, unsigned idx, int *err, char **err_info) {
#ifdef USE_ZLIB_OR_ZLIBNG
    const mdf_frag_t *f = &g_array_index(s->frags, mdf_frag_t, idx);
    uint8_t *in;
    uint8_t *out;
#endif

    if (s->cached == (int)idx) {
        return true;
    }
    g_free(s->cache);
    s->cache = NULL;
    s->cached = -1;

#ifdef USE_ZLIB_OR_ZLIBNG
    if (f->stored_len > MDF_MAX_FRAGMENT_LEN) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("mdf: compressed block too large");
        return false;
    }
    in = (uint8_t *)g_try_malloc((size_t)f->stored_len);
    if (in == NULL) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup("mdf: cannot allocate memory");
        return false;
    }
    if (!mdf_read_at(fh, f->file_pos, in, (unsigned)f->stored_len, err, err_info)) {
        g_free(in);
        return false;
    }
    out = mdf_inflate(in, f->stored_len, f->len, err, err_info);
    g_free(in);
    if (out == NULL) {
        return false;
    }
    if (f->zip_type == MDF_DZ_TRANSPOSED) {
        uint8_t *tmp = (uint8_t *)g_try_malloc((size_t)f->len);

        if (tmp == NULL) {
            g_free(out);
            *err = WTAP_ERR_INTERNAL;
            *err_info = ws_strdup("mdf: cannot allocate memory");
            return false;
        }
        mdf_untranspose(tmp, out, f->len, f->zip_param);
        g_free(out);
        out = tmp;
    }
    s->cache = out;
    s->cache_len = f->len;
    s->cached = (int)idx;
    return true;
#else
    (void)fh;
    *err = WTAP_ERR_UNSUPPORTED;
    *err_info = ws_strdup("mdf: compressed data blocks need zlib support");
    return false;
#endif
}

/* Reads len bytes at offset off of the stream. */
static bool
mdf_stream_read(mdf_stream_t *s, FILE_T fh, uint64_t off, uint8_t *buf, uint64_t len, int *err, char **err_info) {
    unsigned lo = 0, hi = s->frags->len;

    if (off > s->total || len > s->total - off) {
        *err = WTAP_ERR_SHORT_READ;
        return false;
    }
    if (len == 0) {
        return true;
    }

    /* find the last fragment starting at or before off */
    while (hi - lo > 1) {
        unsigned mid = lo + (hi - lo) / 2;

        if (g_array_index(s->frags, mdf_frag_t, mid).stream_start <= off) {
            lo = mid;
        } else {
            hi = mid;
        }
    }

    while (len > 0) {
        const mdf_frag_t *f;
        uint64_t          in_frag, chunk;

        if (lo >= s->frags->len) {
            *err = WTAP_ERR_SHORT_READ;
            return false;
        }
        f = &g_array_index(s->frags, mdf_frag_t, lo);
        in_frag = off - f->stream_start;
        chunk = MIN(len, f->len - in_frag);

        if (f->zip_type == MDF_NOT_COMPRESSED) {
            if (chunk >= MDF_READ_AHEAD) {
                if (!mdf_read_at(fh, f->file_pos + (int64_t)in_frag, buf, (unsigned)chunk, err, err_info)) {
                    return false;
                }
            } else {
                /* small reads: fetch a larger piece, the next read is most likely close by */
                mdf_ra_slot_t *slot = NULL;
                unsigned       k;

                for (k = 0; k < MDF_RA_SLOTS; k++) {
                    mdf_ra_slot_t *r = &s->ra[k];

                    if (r->buf != NULL && off >= r->start && off - r->start <= r->len && chunk <= r->len - (off - r->start)) {
                        slot = r;
                        break;
                    }
                }
                if (slot == NULL) {
                    uint64_t fill = MIN((uint64_t)MDF_READ_AHEAD, f->len - in_frag);

                    /* replace the slot that was used least recently */
                    slot = &s->ra[0];
                    for (k = 1; k < MDF_RA_SLOTS; k++) {
                        if (s->ra[k].used < slot->used) {
                            slot = &s->ra[k];
                        }
                    }
                    if (slot->buf == NULL) {
                        slot->buf = (uint8_t *)g_malloc(MDF_READ_AHEAD);
                    }
                    slot->len = 0;
                    if (!mdf_read_at(fh, f->file_pos + (int64_t)in_frag, slot->buf, (unsigned)fill, err, err_info)) {
                        return false;
                    }
                    slot->start = off;
                    slot->len = fill;
                }
                slot->used = ++s->ra_tick;
                memcpy(buf, slot->buf + (off - slot->start), (size_t)chunk);
            }
        } else {
            if (!mdf_stream_cache(s, fh, lo, err, err_info)) {
                return false;
            }
            memcpy(buf, s->cache + in_frag, (size_t)chunk);
        }
        buf += chunk;
        off += chunk;
        len -= chunk;
        lo++;
    }
    return true;
}

/* ------------------------------------------------------------------------ */
/* Channels                                                                 */
/* ------------------------------------------------------------------------ */

typedef struct {
    bool      present;
    uint8_t   cn_type;
    uint8_t   data_type;
    uint8_t   bit_offset;
    uint32_t  byte_offset;
    uint32_t  bit_count;
    uint32_t  flags;
    bool      linear;           /* conversion is p1 + p2 * x */
    bool      conv_unsupported;
    double    p1, p2;
    int64_t   data_link;
} mdf_chan_t;

typedef enum {
    MDF_EVT_ETH,
    MDF_EVT_CAN_DATA,
    MDF_EVT_CAN_REMOTE,
    MDF_EVT_CAN_ERROR,
    MDF_EVT_CAN_OVERLOAD,
    MDF_EVT_LIN_FRAME,
    MDF_EVT_LIN_CHECKSUM_ERROR,
    MDF_EVT_LIN_TRANSMISSION_ERROR,
    MDF_EVT_LIN_RECEIVE_ERROR,
    MDF_EVT_FLX_FRAME,
    MDF_EVT_FLX_NULL_FRAME
} mdf_evt_type_t;

typedef struct {
    int64_t   cg_pos;
    uint64_t  next_off;         /* offset of the next VLSD record */
    GArray   *entries;          /* of mdf_vlsd_entry_t */
} mdf_vlsd_t;

typedef struct {
    uint64_t  off;              /* offset as stored in the channel */
    uint64_t  pos;              /* position of the length field in the data of the data group */
} mdf_vlsd_entry_t;

typedef struct {
    mdf_evt_type_t  type;
    mdf_stream_t   *dg_stream;
    uint32_t        rec_id_size;
    uint32_t        rec_size;           /* data bytes + invalidation bytes */
    uint64_t        record_id;
    uint64_t        cycle_count;
    mdf_chan_t      time, bus, id, ide, dlc, data_length, data_bytes, dir, edl, brs, esi, src, dst, ethertype;
    mdf_chan_t      error_type;                         /* CAN error frame */
    mdf_chan_t      checksum, checksum_model, received_count, specified_count;    /* LIN */
    mdf_chan_t      cycle, flx_channel, payload_length, header_crc;               /* FlexRay */
    mdf_chan_t      reserved_bit, preamble, null_frame, sync_frame, startup_frame;
    mdf_stream_t   *sd_stream;          /* signal data of DataBytes, if separate */
    mdf_vlsd_t     *vlsd;               /* or VLSD channel group */
    int64_t         vlsd_cg_pos;
} mdf_group_t;

typedef struct {
    uint64_t  ts_ns;
    uint64_t  pos;              /* position of the data bytes of the record in the data of its data group */
    uint32_t  group;
    uint32_t  iface;            /* first the bus channel, then the interface ID */
} mdf_event_t;

typedef struct {
    GPtrArray   *groups;        /* of mdf_group_t */
    GPtrArray   *streams;       /* of mdf_stream_t (owned) */
    GPtrArray   *vlsds;         /* of mdf_vlsd_t (owned) */
    GArray      *events;        /* of mdf_event_t */
    GHashTable  *iface_ht;      /* (encap, bus channel) -> interface ID */
    uint64_t     start_ns;
    uint64_t     next_event;
    int64_t      file_size;     /* for the progress indication */
    bool         have_bus_cg;   /* at least one bus event channel group */
} mdf_t;

static double
mdf_get_double(const uint8_t *p) {
    uint64_t v = pletohu64(p);
    double   d;

    memcpy(&d, &v, sizeof(d));
    return d;
}

static bool
mdf_parse_conversion(FILE_T fh, int64_t pos, mdf_chan_t *c) {
    mdf_block_t blk;
    int         err = 0;
    char       *err_info = NULL;
    const uint8_t *d;

    if (pos == 0) {
        return true;
    }
    if (!mdf_load_block(fh, pos, &blk, &err, &err_info)) {
        g_free(err_info);
        return false;
    }
    d = mdf_data(&blk);
    if (!mdf_id_is(blk.buf, "##CC") || mdf_data_len(&blk) < 24) {
        c->conv_unsupported = true;
    } else {
        uint8_t  cc_type = d[0];
        unsigned val_count = pletohu16(d + 6);

        if (cc_type == 0) {
            /* 1:1 */
        } else if (cc_type == 1 && val_count >= 2 && mdf_data_len(&blk) >= 24 + 16) {
            c->linear = true;
            c->p1 = mdf_get_double(d + 24);
            c->p2 = mdf_get_double(d + 32);
        } else {
            c->conv_unsupported = true;
        }
    }
    mdf_free_block(&blk);
    return true;
}

/* Parses the CN block at pos. The name is returned in *name (caller frees),
 * the links to the next channel and to the composition in next/comp. */
static bool
mdf_parse_cn(FILE_T fh, int64_t pos, mdf_chan_t *c, char **name, int64_t *next, int64_t *comp) {
    mdf_block_t blk;
    int         err = 0;
    char       *err_info = NULL;
    const uint8_t *d;

    memset(c, 0, sizeof(*c));
    *name = NULL;
    *next = *comp = 0;

    if (!mdf_load_block(fh, pos, &blk, &err, &err_info)) {
        g_free(err_info);
        return false;
    }
    if (!mdf_id_is(blk.buf, "##CN") || blk.link_count < 8 || mdf_data_len(&blk) < 72) {
        mdf_free_block(&blk);
        return false;
    }
    d = mdf_data(&blk);

    *next = mdf_link(&blk, 0);
    *comp = mdf_link(&blk, 1);
    *name = mdf_load_text(fh, mdf_link(&blk, 2));

    c->present = true;
    c->cn_type = d[0];
    c->data_type = d[2];
    c->bit_offset = d[3];
    c->byte_offset = pletohu32(d + 4);
    c->bit_count = pletohu32(d + 8);
    c->flags = pletohu32(d + 12);
    c->data_link = mdf_link(&blk, 5);
    c->p1 = 0.0;
    c->p2 = 1.0;

    if (!mdf_parse_conversion(fh, mdf_link(&blk, 4), c)) {
        c->conv_unsupported = true;
    }
    mdf_free_block(&blk);
    return true;
}

/* The raw value of a channel, 0 for virtual channels. */
static bool
mdf_chan_raw(const mdf_chan_t *c, const uint8_t *rec, uint32_t rec_len, double *as_double, uint64_t *as_u64, bool *is_float) {
    uint32_t nbytes, i;
    uint64_t v = 0;

    *is_float = false;
    *as_double = 0.0;
    *as_u64 = 0;
    if (!c->present) {
        return false;
    }
    if (c->cn_type == MDF_CN_TYPE_VIRTUAL) {
        return true;
    }
    if (c->bit_count == 0 || c->bit_count > 64) {
        return false;
    }
    nbytes = (c->bit_offset + c->bit_count + 7) / 8;
    if ((uint64_t)c->byte_offset + nbytes > rec_len || nbytes > 9) {
        return false;
    }

    if (c->data_type == 1 || c->data_type == 3 || c->data_type == 5) {
        /* big endian, only whole bytes */
        if (c->bit_offset != 0 || c->bit_count % 8 != 0) {
            return false;
        }
        for (i = 0; i < nbytes; i++) {
            v = (v << 8) | rec[c->byte_offset + i];
        }
    } else {
        for (i = 0; i < nbytes && i < 8; i++) {
            v |= (uint64_t)rec[c->byte_offset + i] << (8 * i);
        }
        v >>= c->bit_offset;
        if (nbytes == 9 && c->bit_offset > 0) {
            v |= (uint64_t)rec[c->byte_offset + 8] << (64 - c->bit_offset);
        }
        if (c->bit_count < 64) {
            v &= (UINT64_C(1) << c->bit_count) - 1;
        }
    }

    if (c->data_type == 4 || c->data_type == 5) {
        if (c->bit_count == 64) {
            double dv;

            memcpy(&dv, &v, sizeof(dv));
            *as_double = dv;
        } else if (c->bit_count == 32) {
            float fv;
            uint32_t v32 = (uint32_t)v;

            memcpy(&fv, &v32, sizeof(fv));
            *as_double = fv;
        } else {
            return false;
        }
        *is_float = true;
        return true;
    }
    if (c->data_type == 2 || c->data_type == 3) {
        if (c->bit_count < 64 && (v & (UINT64_C(1) << (c->bit_count - 1)))) {
            v |= ~((UINT64_C(1) << c->bit_count) - 1);
        }
        *as_double = (double)(int64_t)v;
    } else {
        *as_double = (double)v;
    }
    *as_u64 = v;
    return true;
}

/* The physical value of a channel as double. */
static bool
mdf_chan_phys(const mdf_chan_t *c, const uint8_t *rec, uint32_t rec_len, double *out) {
    double   d;
    uint64_t u;
    bool     is_float;

    if (c->conv_unsupported || !mdf_chan_raw(c, rec, rec_len, &d, &u, &is_float)) {
        return false;
    }
    *out = c->linear ? c->p1 + c->p2 * d : d;
    return true;
}

/* The physical value of a channel as unsigned integer (rounded). Conversions
 * we do not support (for example text tables for bit signals like Dir) are
 * ignored, which gives the raw value. */
static bool
mdf_chan_uint(const mdf_chan_t *c, const uint8_t *rec, uint32_t rec_len, uint64_t *out) {
    double   d;
    uint64_t u;
    bool     is_float;

    if (!mdf_chan_raw(c, rec, rec_len, &d, &u, &is_float)) {
        return false;
    }
    if (!c->linear && !is_float) {
        *out = u;
        return true;
    }
    if (c->linear) {
        d = c->p1 + c->p2 * d;
    }
    if (d < 0.0 || d >= 18446744073709551615.0) {
        return false;
    }
    *out = (uint64_t)llround(d);
    return true;
}

/* ------------------------------------------------------------------------ */
/* Scanning the block tree                                                  */
/* ------------------------------------------------------------------------ */

typedef struct {
    int64_t       pos;
    uint64_t      record_id;
    uint32_t      rec_size;
    uint64_t      cycle_count;
    bool          vlsd;
    bool          bus_event;    /* bus event channel group flag */
    mdf_group_t  *group;        /* NULL if we are not interested in the records */
    bool          registered;   /* group is owned by mdf_t */
    uint32_t      group_idx;
    mdf_vlsd_t   *vlsd_data;
} mdf_cg_t;

static void
mdf_group_free(void *data) {
    g_free(data);
}

static void
mdf_vlsd_free(void *data) {
    mdf_vlsd_t *v = (mdf_vlsd_t *)data;

    g_array_free(v->entries, true);
    g_free(v);
}

static void
mdf_stream_free_cb(void *data) {
    mdf_stream_free((mdf_stream_t *)data);
}

static const char *
mdf_member_suffix(const char *name) {
    const char *dot = strrchr(name, '.');

    return dot ? dot + 1 : name;
}

static void
mdf_assign_member(mdf_group_t *g, const char *name, const mdf_chan_t *c) {
    const char *n = mdf_member_suffix(name);

    if (strcmp(n, "BusChannel") == 0) {
        g->bus = *c;
    } else if (strcmp(n, "ID") == 0) {
        g->id = *c;
    } else if (strcmp(n, "IDE") == 0) {
        g->ide = *c;
    } else if (strcmp(n, "DLC") == 0) {
        g->dlc = *c;
    } else if (strcmp(n, "DataLength") == 0) {
        g->data_length = *c;
    } else if (strcmp(n, "DataBytes") == 0) {
        g->data_bytes = *c;
    } else if (strcmp(n, "Dir") == 0) {
        g->dir = *c;
    } else if (strcmp(n, "EDL") == 0) {
        g->edl = *c;
    } else if (strcmp(n, "BRS") == 0) {
        g->brs = *c;
    } else if (strcmp(n, "ESI") == 0) {
        g->esi = *c;
    } else if (strcmp(n, "Source") == 0) {
        g->src = *c;
    } else if (strcmp(n, "Destination") == 0) {
        g->dst = *c;
    } else if (strcmp(n, "EtherType") == 0) {
        g->ethertype = *c;
    } else if (strcmp(n, "ErrorType") == 0) {
        g->error_type = *c;
    } else if (strcmp(n, "Checksum") == 0) {
        g->checksum = *c;
    } else if (strcmp(n, "ChecksumModel") == 0) {
        g->checksum_model = *c;
    } else if (strcmp(n, "ReceivedDataByteCount") == 0) {
        g->received_count = *c;
    } else if (strcmp(n, "SpecifiedDataByteCount") == 0) {
        g->specified_count = *c;
    } else if (strcmp(n, "Cycle") == 0) {
        g->cycle = *c;
    } else if (strcmp(n, "FlxChannel") == 0) {
        g->flx_channel = *c;
    } else if (strcmp(n, "PayloadLength") == 0) {
        g->payload_length = *c;
    } else if (strcmp(n, "HeaderCRC") == 0) {
        g->header_crc = *c;
    } else if (strcmp(n, "ReservedBitFlag") == 0) {
        g->reserved_bit = *c;
    } else if (strcmp(n, "PayloadPreambleFlag") == 0) {
        g->preamble = *c;
    } else if (strcmp(n, "NullFrameFlag") == 0) {
        g->null_frame = *c;
    } else if (strcmp(n, "SyncFrameFlag") == 0) {
        g->sync_frame = *c;
    } else if (strcmp(n, "StartUpFrameFlag") == 0) {
        g->startup_frame = *c;
    }
}

static bool
mdf_group_supported(const mdf_group_t *g) {
    if (!g->time.present || g->time.conv_unsupported || !g->bus.present) {
        return false;
    }
    switch (g->type) {
    case MDF_EVT_ETH:
        return g->data_bytes.present && g->src.present && g->dst.present && g->ethertype.present;
    case MDF_EVT_CAN_DATA:
        return g->data_bytes.present && g->id.present && g->dlc.present;
    case MDF_EVT_CAN_REMOTE:
        return g->id.present && g->dlc.present;
    case MDF_EVT_CAN_ERROR:
    case MDF_EVT_CAN_OVERLOAD:
        /* these can be nothing but a time stamp and a bus channel */
        return true;
    case MDF_EVT_LIN_FRAME:
        return g->data_bytes.present && g->id.present;
    case MDF_EVT_LIN_CHECKSUM_ERROR:
    case MDF_EVT_LIN_TRANSMISSION_ERROR:
    case MDF_EVT_LIN_RECEIVE_ERROR:
        /* errors may be reduced to a time stamp and a bus channel as well */
        return true;
    case MDF_EVT_FLX_FRAME:
        return g->data_bytes.present && g->id.present && g->cycle.present && g->payload_length.present;
    case MDF_EVT_FLX_NULL_FRAME:
        return g->id.present && g->cycle.present;
    }
    return false;
}

/* Looks at the channels of a channel group and returns a group if it contains a supported bus event. */
static mdf_group_t *
mdf_parse_cg_channels(FILE_T fh, int64_t first_cn) {
    mdf_group_t *g = g_new0(mdf_group_t, 1);
    bool         have_event = false;
    int64_t      cn = first_cn;
    unsigned     visited = 0;

    while (cn != 0 && visited++ < MDF_MAX_CHANNELS) {
        mdf_chan_t  c;
        char       *name;
        int64_t     next, comp;

        if (!mdf_parse_cn(fh, cn, &c, &name, &next, &comp)) {
            break;
        }

        if (c.cn_type == MDF_CN_TYPE_MASTER && !g->time.present) {
            /* the first master channel with sync type time */
            mdf_block_t blk;
            int         err = 0;
            char       *err_info = NULL;

            if (mdf_load_block(fh, cn, &blk, &err, &err_info)) {
                if (mdf_data_len(&blk) >= 2 && mdf_data(&blk)[1] == MDF_CN_SYNC_TIME) {
                    g->time = c;
                }
                mdf_free_block(&blk);
            } else {
                g_free(err_info);
            }
        } else if ((c.flags & MDF_CN_FLAG_BUS_EVENT) && c.data_type == MDF_CN_DT_BYTE_ARRAY && comp != 0 && name != NULL &&
                   !have_event) {
            mdf_evt_type_t type;
            bool           known = true;

            if (strcmp(name, "ETH_Frame") == 0) {
                type = MDF_EVT_ETH;
            } else if (strcmp(name, "CAN_DataFrame") == 0) {
                type = MDF_EVT_CAN_DATA;
            } else if (strcmp(name, "CAN_RemoteFrame") == 0) {
                type = MDF_EVT_CAN_REMOTE;
            } else if (strcmp(name, "CAN_ErrorFrame") == 0) {
                type = MDF_EVT_CAN_ERROR;
            } else if (strcmp(name, "CAN_OverloadFrame") == 0) {
                type = MDF_EVT_CAN_OVERLOAD;
            } else if (strcmp(name, "LIN_Frame") == 0) {
                type = MDF_EVT_LIN_FRAME;
            } else if (strcmp(name, "LIN_ChecksumError") == 0) {
                type = MDF_EVT_LIN_CHECKSUM_ERROR;
            } else if (strcmp(name, "LIN_TransmissionError") == 0) {
                type = MDF_EVT_LIN_TRANSMISSION_ERROR;
            } else if (strcmp(name, "LIN_ReceiveError") == 0) {
                type = MDF_EVT_LIN_RECEIVE_ERROR;
            } else if (strcmp(name, "FLX_Frame") == 0) {
                type = MDF_EVT_FLX_FRAME;
            } else if (strcmp(name, "FLX_NullFrame") == 0) {
                type = MDF_EVT_FLX_NULL_FRAME;
            } else {
                known = false;
                type = MDF_EVT_ETH;
            }

            if (known) {
                int64_t  m = comp;
                unsigned mvisited = 0;

                have_event = true;
                g->type = type;
                while (m != 0 && mvisited++ < MDF_MAX_CHANNELS) {
                    mdf_chan_t  mc;
                    char       *mname;
                    int64_t     mnext, mcomp;

                    if (!mdf_parse_cn(fh, m, &mc, &mname, &mnext, &mcomp)) {
                        break;
                    }
                    if (mname != NULL) {
                        mdf_assign_member(g, mname, &mc);
                    }
                    g_free(mname);
                    m = mnext;
                }
            }
        }
        g_free(name);
        cn = next;
    }

    if (!have_event || !mdf_group_supported(g)) {
        g_free(g);
        return NULL;
    }
    return g;
}

typedef struct {
    FILE_T        fh;
    mdf_stream_t *stream;
    uint8_t      *buf;
    uint64_t      start;
    uint64_t      len;
    uint64_t      cap;
} mdf_window_t;

/* Returns a pointer to len bytes at pos of the stream, valid until the next call. */
static const uint8_t *
mdf_window_get(mdf_window_t *w, uint64_t pos, uint64_t len, int *err, char **err_info) {
    uint64_t want;

    if (pos >= w->start && len <= w->len && pos - w->start <= w->len - len) {
        return w->buf + (pos - w->start);
    }
    if (pos > w->stream->total || len > w->stream->total - pos) {
        *err = WTAP_ERR_SHORT_READ;
        return NULL;
    }
    want = MIN(MAX(len, (uint64_t)MDF_SCAN_WINDOW), w->stream->total - pos);
    if (want > w->cap) {
        g_free(w->buf);
        w->buf = (uint8_t *)g_try_malloc((size_t)want);
        if (w->buf == NULL) {
            w->cap = 0;
            w->len = 0;
            *err = WTAP_ERR_INTERNAL;
            *err_info = ws_strdup("mdf: cannot allocate memory");
            return NULL;
        }
        w->cap = want;
    }
    if (!mdf_stream_read(w->stream, w->fh, pos, w->buf, want, err, err_info)) {
        w->len = 0;
        return NULL;
    }
    w->start = pos;
    w->len = want;
    return w->buf;
}

static bool
mdf_add_event(mdf_t *mdf, uint32_t group_idx, mdf_group_t *g, const uint8_t *rec, uint64_t pos) {
    mdf_event_t ev;
    double      t;
    uint64_t    bus = 0;
    double      ns;
    int64_t     abs_ns;

    if (!mdf_chan_phys(&g->time, rec, g->rec_size, &t)) {
        return false;
    }
    if (!mdf_chan_uint(&g->bus, rec, g->rec_size, &bus)) {
        bus = 0;
    }
    ns = t * 1e9;
    if (!(ns > -9.0e18 && ns < 9.0e18)) {
        /* out of range or not a number */
        return false;
    }
    abs_ns = (int64_t)mdf->start_ns + (int64_t)llround(ns);
    ev.ts_ns = abs_ns < 0 ? 0 : (uint64_t)abs_ns;
    ev.pos = pos;
    ev.group = group_idx;
    ev.iface = (uint32_t)MIN(bus, (uint64_t)UINT32_MAX);
    g_array_append_val(mdf->events, ev);
    return true;
}

static bool
mdf_scan_dg(mdf_t *mdf, FILE_T fh, int64_t dg_pos, int *err, char **err_info) {
    mdf_block_t    dg;
    mdf_stream_t  *stream = NULL;
    GArray        *cgs = NULL;
    mdf_window_t   win;
    bool           unsupported = false;
    bool           ok = true;
    uint32_t       rec_id_size;
    int64_t        cg_pos;
    unsigned       visited = 0;
    unsigned       i;
    bool           any_group = false;

    memset(&win, 0, sizeof(win));
    if (!mdf_load_block(fh, dg_pos, &dg, err, err_info)) {
        return false;
    }
    if (!mdf_id_is(dg.buf, "##DG") || dg.link_count < 4 || mdf_data_len(&dg) < 1) {
        mdf_free_block(&dg);
        return true;
    }
    rec_id_size = mdf_data(&dg)[0];
    cg_pos = mdf_link(&dg, 1);

    cgs = g_array_new(false, true, sizeof(mdf_cg_t));
    while (cg_pos != 0 && visited++ < MDF_MAX_CHANNELS) {
        mdf_block_t  cg;
        mdf_cg_t     info;
        int64_t      next;

        if (!mdf_load_block(fh, cg_pos, &cg, err, err_info)) {
            ok = false;
            break;
        }
        if (!mdf_id_is(cg.buf, "##CG") || cg.link_count < 6 || mdf_data_len(&cg) < 32) {
            mdf_free_block(&cg);
            break;
        }
        memset(&info, 0, sizeof(info));
        info.pos = cg_pos;
        info.record_id = pletohu64(mdf_data(&cg));
        info.cycle_count = pletohu64(mdf_data(&cg) + 8);
        info.vlsd = (pletohu16(mdf_data(&cg) + 16) & MDF_CG_FLAG_VLSD) != 0;
        info.bus_event = (pletohu16(mdf_data(&cg) + 16) & MDF_CG_FLAG_BUS_EVENT) != 0;
        if (info.bus_event) {
            mdf->have_bus_cg = true;
        }
        info.rec_size = pletohu32(mdf_data(&cg) + 24);
        if (pletohu32(mdf_data(&cg) + 28) > UINT32_MAX - info.rec_size) {
            mdf_free_block(&cg);
            break;
        }
        info.rec_size += pletohu32(mdf_data(&cg) + 28);
        next = mdf_link(&cg, 0);

        if (info.vlsd) {
            mdf_vlsd_t *v = g_new0(mdf_vlsd_t, 1);

            v->cg_pos = cg_pos;
            v->entries = g_array_new(false, false, sizeof(mdf_vlsd_entry_t));
            g_ptr_array_add(mdf->vlsds, v);
            info.vlsd_data = v;
        } else if (info.bus_event) {
            mdf_group_t *g = mdf_parse_cg_channels(fh, mdf_link(&cg, 1));

            if (g != NULL) {
                g->rec_id_size = rec_id_size;
                g->rec_size = info.rec_size;
                g->record_id = info.record_id;
                g->cycle_count = info.cycle_count;
                info.group = g;
            }
        }
        g_array_append_val(cgs, info);
        mdf_free_block(&cg);
        cg_pos = next;
    }
    mdf_free_block(&dg);
    if (!ok) {
        goto out;
    }

    for (i = 0; i < cgs->len; i++) {
        if (g_array_index(cgs, mdf_cg_t, i).group != NULL) {
            any_group = true;
        }
    }
    if (!any_group) {
        ws_debug("no channel group with supported bus events in data group at %" PRId64, dg_pos);
        goto out;
    }

    /* The data of the data group. */
    {
        mdf_block_t dgb;

        if (!mdf_load_block(fh, dg_pos, &dgb, err, err_info)) {
            ok = false;
            goto out;
        }
        stream = mdf_stream_new();
        ok = mdf_stream_add(stream, fh, mdf_link(&dgb, 2), 0, &unsupported, err, err_info);
        mdf_free_block(&dgb);
        if (!ok) {
            goto out;
        }
    }
    if (unsupported) {
        ws_debug("unsupported data storage in data group at %" PRId64, dg_pos);
        goto out;
    }

    /* Resolve the variable length payload of the groups and register them. */
    for (i = 0; i < cgs->len; i++) {
        mdf_cg_t    *info = &g_array_index(cgs, mdf_cg_t, i);
        mdf_group_t *g = info->group;

        if (g == NULL) {
            continue;
        }
        g->dg_stream = stream;
        if (g->data_bytes.cn_type == MDF_CN_TYPE_VLSD && g->data_bytes.data_link != 0) {
            unsigned j;

            for (j = 0; j < cgs->len; j++) {
                mdf_cg_t *other = &g_array_index(cgs, mdf_cg_t, j);

                if (other->vlsd && other->pos == g->data_bytes.data_link) {
                    g->vlsd = other->vlsd_data;
                }
            }
            if (g->vlsd == NULL) {
                bool          sd_unsupported = false;
                mdf_stream_t *sd = mdf_stream_new();

                ok = mdf_stream_add(sd, fh, g->data_bytes.data_link, 0, &sd_unsupported, err, err_info);
                if (!ok) {
                    mdf_stream_free(sd);
                    goto out;
                }
                if (sd_unsupported || sd->total == 0) {
                    mdf_stream_free(sd);
                    info->group = NULL;
                    g_free(g);
                    continue;
                }
                g->sd_stream = sd;
                g_ptr_array_add(mdf->streams, sd);
            }
        } else if (g->data_bytes.cn_type == 7 /* VLSC */) {
            info->group = NULL;
            g_free(g);
            continue;
        }
        info->group_idx = mdf->groups->len;
        info->registered = true;
        g_ptr_array_add(mdf->groups, g);
    }

    win.fh = fh;
    win.stream = stream;

    if (rec_id_size == 0) {
        /* sorted: a single channel group with fixed size records */
        mdf_cg_t *info = &g_array_index(cgs, mdf_cg_t, 0);
        uint64_t  n, k;

        if (cgs->len != 1 || info->group == NULL || info->vlsd || info->rec_size == 0) {
            goto out;
        }
        n = stream->total / info->rec_size;
        if (info->cycle_count > 0 && info->cycle_count < n) {
            n = info->cycle_count;
        }
        for (k = 0; k < n; k++) {
            uint64_t       pos = k * info->rec_size;
            const uint8_t *rec = mdf_window_get(&win, pos, info->rec_size, err, err_info);

            if (rec == NULL) {
                ok = false;
                goto out;
            }
            mdf_add_event(mdf, info->group_idx, info->group, rec, pos);
        }
    } else {
        uint64_t pos = 0;

        while (pos + rec_id_size <= stream->total) {
            const uint8_t *p = mdf_window_get(&win, pos, rec_id_size, err, err_info);
            uint64_t       id = 0;
            mdf_cg_t      *info = NULL;
            unsigned       j;
            uint32_t       k;

            if (p == NULL) {
                ok = false;
                goto out;
            }
            for (k = 0; k < rec_id_size; k++) {
                id |= (uint64_t)p[k] << (8 * k);
            }
            for (j = 0; j < cgs->len; j++) {
                if (g_array_index(cgs, mdf_cg_t, j).record_id == id) {
                    info = &g_array_index(cgs, mdf_cg_t, j);
                    break;
                }
            }
            if (info == NULL) {
                ws_debug("unknown record ID %" PRIu64 " at position %" PRIu64 ", stopping scan", id, pos);
                break;
            }

            if (info->vlsd) {
                mdf_vlsd_entry_t e;
                uint32_t         len;

                p = mdf_window_get(&win, pos + rec_id_size, 4, err, err_info);
                if (p == NULL) {
                    *err = 0;
                    break;
                }
                len = pletohu32(p);
                if (pos + rec_id_size + 4 + (uint64_t)len > stream->total) {
                    break;
                }
                e.off = info->vlsd_data->next_off;
                e.pos = pos + rec_id_size;
                g_array_append_val(info->vlsd_data->entries, e);
                info->vlsd_data->next_off += 4 + (uint64_t)len;
                pos += rec_id_size + 4 + (uint64_t)len;
            } else {
                if (pos + rec_id_size + info->rec_size > stream->total) {
                    break;
                }
                if (info->group != NULL) {
                    p = mdf_window_get(&win, pos + rec_id_size, info->rec_size, err, err_info);
                    if (p == NULL) {
                        ok = false;
                        goto out;
                    }
                    mdf_add_event(mdf, info->group_idx, info->group, p, pos + rec_id_size);
                }
                pos += rec_id_size + info->rec_size;
            }
        }
    }

out:
    g_free(win.buf);
    if (cgs != NULL) {
        /* groups that were not registered are released here */
        for (i = 0; i < cgs->len; i++) {
            mdf_cg_t *info = &g_array_index(cgs, mdf_cg_t, i);

            if (info->group != NULL && !info->registered) {
                g_free(info->group);
            }
        }
        g_array_free(cgs, true);
    }
    if (stream != NULL) {
        g_ptr_array_add(mdf->streams, stream);
    }
    return ok;
}

/* ------------------------------------------------------------------------ */
/* Reading packets                                                          */
/* ------------------------------------------------------------------------ */

static const uint8_t mdf_canfd_dlc_to_len[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64 };

/* Reads the payload of DataBytes into the buffer. Returns the number of bytes in *len. */
static bool
mdf_get_payload(mdf_group_t *g, FILE_T fh, const uint8_t *rec, uint64_t max_len, Buffer *buf, int *err, char **err_info) {
    const mdf_chan_t *c = &g->data_bytes;
    uint64_t          want = max_len;
    uint64_t          dl;

    if (!c->present) {
        return true;
    }

    if (c->cn_type == MDF_CN_TYPE_VLSD) {
        uint64_t off;
        uint64_t pos;
        uint8_t  lenbuf[4];
        uint32_t len;
        mdf_stream_t *s;

        if (!mdf_chan_uint(c, rec, g->rec_size, &off)) {
            return true;
        }
        if (g->vlsd != NULL) {
            GArray   *e = g->vlsd->entries;
            unsigned  lo = 0, hi = e->len;

            /* binary search for the offset */
            while (lo < hi) {
                unsigned mid = lo + (hi - lo) / 2;

                if (g_array_index(e, mdf_vlsd_entry_t, mid).off < off) {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            if (lo >= e->len || g_array_index(e, mdf_vlsd_entry_t, lo).off != off) {
                return true;
            }
            pos = g_array_index(e, mdf_vlsd_entry_t, lo).pos;
            s = g->dg_stream;
        } else {
            pos = off;
            s = g->sd_stream;
        }
        if (s == NULL || !mdf_stream_read(s, fh, pos, lenbuf, 4, err, err_info)) {
            if (s != NULL && *err == WTAP_ERR_SHORT_READ) {
                *err = 0;
                return true;
            }
            return s == NULL;
        }
        len = pletohu32(lenbuf);
        if (len > MDF_MAX_VLSD_LEN) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup("mdf: variable length payload too large");
            return false;
        }
        want = MIN(want, (uint64_t)len);
        if (g->data_length.present && mdf_chan_uint(&g->data_length, rec, g->rec_size, &dl)) {
            want = MIN(want, dl);
        }
        if (want > 0) {
            ws_buffer_assure_space(buf, (size_t)want);
            if (!mdf_stream_read(s, fh, pos + 4, ws_buffer_end_ptr(buf), want, err, err_info)) {
                return false;
            }
            ws_buffer_increase_length(buf, (size_t)want);
        }
        return true;
    }

    /* fixed length or maximum length data */
    want = MIN(want, (uint64_t)(c->bit_count / 8));
    if (g->data_length.present && mdf_chan_uint(&g->data_length, rec, g->rec_size, &dl)) {
        want = MIN(want, dl);
    }
    if ((uint64_t)c->byte_offset + want > g->rec_size) {
        want = g->rec_size > c->byte_offset ? g->rec_size - c->byte_offset : 0;
    }
    if (want > 0) {
        ws_buffer_append(buf, rec + c->byte_offset, (size_t)want);
    }
    return true;
}

static void
mdf_add_direction(wtap_rec *rec, const mdf_group_t *g, const uint8_t *rec_data) {
    uint64_t dir;

    if (g->dir.present && mdf_chan_uint(&g->dir, rec_data, g->rec_size, &dir)) {
        wtap_block_add_uint32_option(rec->block, OPT_PKT_FLAGS,
                                     dir ? PACK_FLAGS_DIRECTION_OUTBOUND : PACK_FLAGS_DIRECTION_INBOUND);
    }
}

static bool
mdf_build_ethernet(mdf_group_t *g, FILE_T fh, const uint8_t *rec_data, wtap_rec *rec, int *err, char **err_info) {
    uint8_t   hdr[14];
    uint64_t  ethertype = 0;
    uint64_t  data_len = MDF_MAX_VLSD_LEN;

    memset(hdr, 0, sizeof(hdr));
    if ((uint64_t)g->dst.byte_offset + 6 <= g->rec_size) {
        memcpy(hdr, rec_data + g->dst.byte_offset, 6);
    }
    if ((uint64_t)g->src.byte_offset + 6 <= g->rec_size) {
        memcpy(hdr + 6, rec_data + g->src.byte_offset, 6);
    }
    if (mdf_chan_uint(&g->ethertype, rec_data, g->rec_size, &ethertype)) {
        phtonu16(hdr + 12, (uint16_t)ethertype);
    }
    if (g->data_length.present && mdf_chan_uint(&g->data_length, rec_data, g->rec_size, &data_len)) {
        data_len = MIN(data_len, (uint64_t)MDF_MAX_VLSD_LEN);
    } else {
        data_len = MDF_MAX_VLSD_LEN;
    }

    ws_buffer_append(&rec->data, hdr, sizeof(hdr));
    if (!mdf_get_payload(g, fh, rec_data, data_len, &rec->data, err, err_info)) {
        return false;
    }
    rec->rec_header.packet_header.caplen = (uint32_t)ws_buffer_length(&rec->data);
    rec->rec_header.packet_header.len = rec->rec_header.packet_header.caplen;
    return true;
}

static bool
mdf_build_can(mdf_group_t *g, FILE_T fh, const uint8_t *rec_data, wtap_rec *rec, int *err, char **err_info) {
    uint8_t   hdr[8];
    uint64_t  id = 0, ide = 0, dlc = 0, edl = 0, brs = 0, esi = 0;
    uint32_t  canid;
    uint32_t  payload_len;
    bool      fd;
    bool      remote = (g->type == MDF_EVT_CAN_REMOTE);

    mdf_chan_uint(&g->id, rec_data, g->rec_size, &id);
    mdf_chan_uint(&g->dlc, rec_data, g->rec_size, &dlc);
    if (g->ide.present) {
        mdf_chan_uint(&g->ide, rec_data, g->rec_size, &ide);
    }
    if (g->edl.present) {
        mdf_chan_uint(&g->edl, rec_data, g->rec_size, &edl);
    }
    if (g->brs.present) {
        mdf_chan_uint(&g->brs, rec_data, g->rec_size, &brs);
    }
    if (g->esi.present) {
        mdf_chan_uint(&g->esi, rec_data, g->rec_size, &esi);
    }

    fd = edl != 0 && !remote;
    dlc &= 0x0f;
    if (ide != 0 || (id & 0x80000000U)) {
        canid = ((uint32_t)id & CAN_EFF_MASK) | CAN_EFF_FLAG;
    } else {
        canid = (uint32_t)id & CAN_SFF_MASK;
    }
    if (remote) {
        canid |= CAN_RTR_FLAG;
        payload_len = 0;
    } else {
        payload_len = fd ? mdf_canfd_dlc_to_len[dlc] : MIN((uint32_t)dlc, 8U);
    }

    phtonu32(hdr, canid);
    hdr[4] = (uint8_t)payload_len;
    hdr[5] = fd ? (uint8_t)(CANFD_FDF | (brs ? CANFD_BRS : 0) | (esi ? CANFD_ESI : 0)) : 0;
    hdr[6] = 0;
    hdr[7] = 0;
    ws_buffer_append(&rec->data, hdr, sizeof(hdr));

    if (!remote && !mdf_get_payload(g, fh, rec_data, payload_len, &rec->data, err, err_info)) {
        return false;
    }
    rec->rec_header.packet_header.caplen = (uint32_t)ws_buffer_length(&rec->data);
    rec->rec_header.packet_header.len = (uint32_t)sizeof(hdr) + payload_len;
    return true;
}

static int
mdf_encap_of_type(mdf_evt_type_t type) {
    switch (type) {
    case MDF_EVT_ETH:
        return WTAP_ENCAP_ETHERNET;
    case MDF_EVT_CAN_DATA:
    case MDF_EVT_CAN_REMOTE:
    case MDF_EVT_CAN_ERROR:
    case MDF_EVT_CAN_OVERLOAD:
        return WTAP_ENCAP_SOCKETCAN;
    case MDF_EVT_LIN_FRAME:
    case MDF_EVT_LIN_CHECKSUM_ERROR:
    case MDF_EVT_LIN_TRANSMISSION_ERROR:
    case MDF_EVT_LIN_RECEIVE_ERROR:
        return WTAP_ENCAP_LIN;
    case MDF_EVT_FLX_FRAME:
    case MDF_EVT_FLX_NULL_FRAME:
        return WTAP_ENCAP_FLEXRAY;
    }
    return WTAP_ENCAP_UNKNOWN;
}

/* A signed integer property, for example the checksum model, which can be -1. */
static bool
mdf_chan_int(const mdf_chan_t *c, const uint8_t *rec, uint32_t rec_len, int64_t *out) {
    double d;

    if (!mdf_chan_phys(c, rec, rec_len, &d) || !(d > -9.0e18 && d < 9.0e18)) {
        return false;
    }
    *out = (int64_t)llround(d);
    return true;
}

/* SocketCAN error frames carry what kind of error it was in the classes of the ID and in the data. */
static bool
mdf_build_can_error(mdf_group_t *g, const uint8_t *rec_data, wtap_rec *rec) {
    uint8_t   buf[16];
    uint32_t  canid = CAN_ERR_FLAG;
    uint64_t  error_type = 0;

    memset(buf, 0, sizeof(buf));
    if (g->type == MDF_EVT_CAN_OVERLOAD) {
        canid |= CAN_ERR_PROT;
        buf[8 + 2] = CAN_ERR_PROT_OVERLOAD;
    } else if (g->error_type.present && mdf_chan_uint(&g->error_type, rec_data, g->rec_size, &error_type)) {
        switch (error_type) {
        case 1:     /* bit error */
            canid |= CAN_ERR_PROT;
            buf[8 + 2] = CAN_ERR_PROT_BIT;
            break;
        case 2:     /* form error */
            canid |= CAN_ERR_PROT;
            buf[8 + 2] = CAN_ERR_PROT_FORM;
            break;
        case 3:     /* bit stuffing error */
            canid |= CAN_ERR_PROT;
            buf[8 + 2] = CAN_ERR_PROT_STUFF;
            break;
        case 4:     /* CRC error */
            canid |= CAN_ERR_PROT;
            buf[8 + 3] = CAN_ERR_PROT_LOC_CRC_SEQ;
            break;
        case 5:     /* acknowledgment error */
            canid |= CAN_ERR_ACK;
            break;
        default:
            break;
        }
    }
    phtonu32(buf, canid);
    buf[4] = CAN_ERR_DLC;
    ws_buffer_append(&rec->data, buf, sizeof(buf));
    rec->rec_header.packet_header.caplen = sizeof(buf);
    rec->rec_header.packet_header.len = sizeof(buf);
    return true;
}

static uint8_t
mdf_lin_pid(uint8_t id) {
    uint8_t p0, p1;

    id &= LIN_ID_MASK;
    p0 = ((id >> 0) ^ (id >> 1) ^ (id >> 2) ^ (id >> 4)) & 1;
    p1 = (~((id >> 1) ^ (id >> 3) ^ (id >> 4) ^ (id >> 5))) & 1;
    return (uint8_t)(id | (p0 << 6) | (p1 << 7));
}

static bool
mdf_build_lin(mdf_group_t *g, FILE_T fh, const uint8_t *rec_data, wtap_rec *rec, int *err, char **err_info) {
    uint8_t   hdr[8];
    uint64_t  id = 0, dlc = 0, checksum = 0;
    int64_t   model = -1;
    bool      has_payload = (g->type == MDF_EVT_LIN_FRAME || g->type == MDF_EVT_LIN_CHECKSUM_ERROR);
    unsigned  target, have;

    mdf_chan_uint(&g->id, rec_data, g->rec_size, &id);
    if (g->received_count.present && mdf_chan_uint(&g->received_count, rec_data, g->rec_size, &dlc)) {
        /* the number of bytes we got */
    } else if (g->specified_count.present && mdf_chan_uint(&g->specified_count, rec_data, g->rec_size, &dlc)) {
        /* the number of bytes that were expected */
    } else if (g->data_length.present) {
        mdf_chan_uint(&g->data_length, rec_data, g->rec_size, &dlc);
    }
    dlc = MIN(dlc, 8);
    if (g->checksum.present) {
        mdf_chan_uint(&g->checksum, rec_data, g->rec_size, &checksum);
    }
    if (g->checksum_model.present) {
        mdf_chan_int(&g->checksum_model, rec_data, g->rec_size, &model);
    }

    hdr[0] = 1;     /* message format revision */
    hdr[1] = 0;
    hdr[2] = 0;
    hdr[3] = 0;
    /* payload length (4 bits), message type (2 bits), checksum type (2 bits): none, classic or enhanced */
    hdr[4] = (uint8_t)((dlc << 4) | (LIN_MSG_TYPE_FRAME << 2) | (model == 0 ? 1 : (model == 1 ? 2 : 0)));
    hdr[5] = mdf_lin_pid((uint8_t)id);
    hdr[6] = (uint8_t)checksum;
    hdr[7] = 0;     /* errors */
    switch (g->type) {
    case MDF_EVT_LIN_CHECKSUM_ERROR:
        hdr[7] = LIN_ERROR_CHECKSUM_ERROR;
        break;
    case MDF_EVT_LIN_TRANSMISSION_ERROR:
        hdr[7] = LIN_ERROR_NO_SLAVE_RESPONSE;
        break;
    case MDF_EVT_LIN_RECEIVE_ERROR:
        hdr[7] = LIN_ERROR_FRAMING_ERROR;
        break;
    default:
        break;
    }
    ws_buffer_append(&rec->data, hdr, sizeof(hdr));

    if (has_payload && g->data_bytes.present && !mdf_get_payload(g, fh, rec_data, dlc, &rec->data, err, err_info)) {
        return false;
    }

    /* The payload of the packets is 4 or 8 bytes long. */
    target = dlc <= 4 ? 4 : 8;
    have = (unsigned)(ws_buffer_length(&rec->data) - sizeof(hdr));
    while (have < target) {
        const uint8_t zero = 0;

        ws_buffer_append(&rec->data, &zero, 1);
        have++;
    }
    rec->rec_header.packet_header.caplen = (uint32_t)ws_buffer_length(&rec->data);
    rec->rec_header.packet_header.len = rec->rec_header.packet_header.caplen;
    return true;
}

static bool
mdf_flag(const mdf_chan_t *c, const uint8_t *rec_data, uint32_t rec_len) {
    uint64_t v = 0;

    return c->present && mdf_chan_uint(c, rec_data, rec_len, &v) && v != 0;
}

static bool
mdf_build_flexray(mdf_group_t *g, FILE_T fh, const uint8_t *rec_data, wtap_rec *rec, int *err, char **err_info) {
    uint8_t   hdr[7];
    uint64_t  id = 0, cycle = 0, words = 0, hcrc = 0, channel = 0;
    uint32_t  payload_bytes;
    bool      null_frame = (g->type == MDF_EVT_FLX_NULL_FRAME);

    mdf_chan_uint(&g->id, rec_data, g->rec_size, &id);
    mdf_chan_uint(&g->cycle, rec_data, g->rec_size, &cycle);
    if (g->payload_length.present) {
        mdf_chan_uint(&g->payload_length, rec_data, g->rec_size, &words);
    }
    if (g->header_crc.present) {
        mdf_chan_uint(&g->header_crc, rec_data, g->rec_size, &hcrc);
    }
    if (g->flx_channel.present) {
        mdf_chan_uint(&g->flx_channel, rec_data, g->rec_size, &channel);
    }
    words &= 0x7f;
    payload_bytes = (uint32_t)words * 2;

    /* measurement header: type and channel, then the error flags */
    hdr[0] = (uint8_t)(FLEXRAY_FRAME | (channel == 1 ? FLEXRAY_CHANNEL_MASK : 0));
    hdr[1] = 0;
    /* frame header: indicators, ID, payload length in words, header CRC and cycle */
    hdr[2] = (uint8_t)((id >> 8) & 0x07);
    if (mdf_flag(&g->reserved_bit, rec_data, g->rec_size)) {
        hdr[2] |= FLEXRAY_RES_MASK;
    }
    if (mdf_flag(&g->preamble, rec_data, g->rec_size)) {
        hdr[2] |= FLEXRAY_PPI_MASK;
    }
    /* the indicator is cleared for a null frame, the file uses the same meaning */
    if (!null_frame && (!g->null_frame.present || mdf_flag(&g->null_frame, rec_data, g->rec_size))) {
        hdr[2] |= FLEXRAY_NFI_MASK;
    }
    if (mdf_flag(&g->sync_frame, rec_data, g->rec_size)) {
        hdr[2] |= FLEXRAY_SFI_MASK;
    }
    if (mdf_flag(&g->startup_frame, rec_data, g->rec_size)) {
        hdr[2] |= FLEXRAY_STFI_MASK;
    }
    hdr[3] = (uint8_t)(id & 0xff);
    hdr[4] = (uint8_t)(((words << 1) & FLEXRAY_LENGTH_MASK) | ((hcrc >> 10) & 0x01));
    hdr[5] = (uint8_t)((hcrc >> 2) & 0xff);
    hdr[6] = (uint8_t)(((hcrc & 0x03) << 6) | (cycle & FLEXRAY_CC_MASK));
    ws_buffer_append(&rec->data, hdr, sizeof(hdr));

    if (null_frame) {
        /* the payload of a null frame is all zeros */
        uint32_t i;

        for (i = 0; i < payload_bytes; i++) {
            const uint8_t zero = 0;

            ws_buffer_append(&rec->data, &zero, 1);
        }
        rec->rec_header.packet_header.caplen = (uint32_t)ws_buffer_length(&rec->data);
        rec->rec_header.packet_header.len = rec->rec_header.packet_header.caplen;
        return true;
    }

    if (!mdf_get_payload(g, fh, rec_data, payload_bytes, &rec->data, err, err_info)) {
        return false;
    }
    rec->rec_header.packet_header.caplen = (uint32_t)ws_buffer_length(&rec->data);
    rec->rec_header.packet_header.len = (uint32_t)sizeof(hdr) + payload_bytes;
    return true;
}

static bool
mdf_read_event(wtap *wth, FILE_T fh, uint64_t idx, wtap_rec *rec, int *err, char **err_info) {
    mdf_t       *mdf = (mdf_t *)wth->priv;
    mdf_event_t *ev;
    mdf_group_t *g;
    uint8_t     *rec_data;
    bool         ok;
    int          encap;

    if (idx >= mdf->events->len) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("mdf: invalid event index");
        return false;
    }
    ev = &g_array_index(mdf->events, mdf_event_t, idx);
    g = (mdf_group_t *)g_ptr_array_index(mdf->groups, ev->group);
    encap = mdf_encap_of_type(g->type);

    rec_data = (uint8_t *)g_try_malloc(MAX(g->rec_size, 1U));
    if (rec_data == NULL) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup("mdf: cannot allocate memory");
        return false;
    }
    if (!mdf_stream_read(g->dg_stream, fh, ev->pos, rec_data, g->rec_size, err, err_info)) {
        if (*err == WTAP_ERR_SHORT_READ) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup("mdf: record is beyond the end of the data");
        }
        g_free(rec_data);
        return false;
    }

    wtap_setup_packet_rec(rec, encap);
    rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
    rec->presence_flags = WTAP_HAS_TS | WTAP_HAS_CAP_LEN | WTAP_HAS_INTERFACE_ID;
    rec->tsprec = WTAP_TSPREC_NSEC;
    rec->ts.secs = (time_t)(ev->ts_ns / 1000000000U);
    rec->ts.nsecs = (int)(ev->ts_ns % 1000000000U);
    rec->rec_header.packet_header.interface_id = ev->iface;

    switch (g->type) {
    case MDF_EVT_ETH:
        ok = mdf_build_ethernet(g, fh, rec_data, rec, err, err_info);
        break;
    case MDF_EVT_CAN_DATA:
    case MDF_EVT_CAN_REMOTE:
        ok = mdf_build_can(g, fh, rec_data, rec, err, err_info);
        break;
    case MDF_EVT_CAN_ERROR:
    case MDF_EVT_CAN_OVERLOAD:
        ok = mdf_build_can_error(g, rec_data, rec);
        break;
    case MDF_EVT_LIN_FRAME:
    case MDF_EVT_LIN_CHECKSUM_ERROR:
    case MDF_EVT_LIN_TRANSMISSION_ERROR:
    case MDF_EVT_LIN_RECEIVE_ERROR:
        ok = mdf_build_lin(g, fh, rec_data, rec, err, err_info);
        break;
    case MDF_EVT_FLX_FRAME:
    case MDF_EVT_FLX_NULL_FRAME:
        ok = mdf_build_flexray(g, fh, rec_data, rec, err, err_info);
        break;
    default:
        ok = false;
        *err = WTAP_ERR_INTERNAL;
        *err_info = ws_strdup("mdf: unknown event type");
        break;
    }
    if (ok) {
        mdf_add_direction(rec, g, rec_data);
    }
    g_free(rec_data);
    return ok;
}

static bool
mdf_read(wtap *wth, wtap_rec *rec, int *err, char **err_info, int64_t *data_offset) {
    mdf_t *mdf = (mdf_t *)wth->priv;

    if (mdf->next_event >= mdf->events->len) {
        *err = 0;
        return false;
    }
    *data_offset = (int64_t)mdf->next_event;
    if (!mdf_read_event(wth, wth->fh, mdf->next_event++, rec, err, err_info)) {
        return false;
    }
    /*
     * Events are sorted by time but stored per channel group, so the
     * file position jumps around. The progress bar uses the position of
     * wth->fh, so move it in proportion to the events read instead.
     */
    if (mdf->file_size > 0) {
        int64_t pos = (int64_t)((double)mdf->file_size * ((double)mdf->next_event / (double)mdf->events->len));
        if (file_seek(wth->fh, pos, SEEK_SET, err) == -1) {
            return false;
        }
    }
    return true;
}

static bool
mdf_seek_read(wtap *wth, int64_t seek_off, wtap_rec *rec, int *err, char **err_info) {
    if (seek_off < 0) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup("mdf: invalid event index");
        return false;
    }
    return mdf_read_event(wth, wth->random_fh, (uint64_t)seek_off, rec, err, err_info);
}

static void
mdf_free(mdf_t *mdf) {
    if (mdf == NULL) {
        return;
    }
    if (mdf->groups != NULL) {
        g_ptr_array_free(mdf->groups, true);
    }
    if (mdf->streams != NULL) {
        g_ptr_array_free(mdf->streams, true);
    }
    if (mdf->vlsds != NULL) {
        g_ptr_array_free(mdf->vlsds, true);
    }
    if (mdf->events != NULL) {
        g_array_free(mdf->events, true);
    }
    if (mdf->iface_ht != NULL) {
        g_hash_table_destroy(mdf->iface_ht);
    }
    g_free(mdf);
}

static void
mdf_close(wtap *wth) {
    mdf_free((mdf_t *)wth->priv);
    wth->priv = NULL;
}

/* ------------------------------------------------------------------------ */
/* Opening                                                                  */
/* ------------------------------------------------------------------------ */

static int
mdf_event_cmp(const void *a, const void *b) {
    const mdf_event_t *ea = (const mdf_event_t *)a;
    const mdf_event_t *eb = (const mdf_event_t *)b;

    if (ea->ts_ns != eb->ts_ns) {
        return ea->ts_ns < eb->ts_ns ? -1 : 1;
    }
    /* keep the order of the file for equal time stamps */
    if (ea->group != eb->group) {
        return ea->group < eb->group ? -1 : 1;
    }
    return ea->pos < eb->pos ? -1 : (ea->pos > eb->pos ? 1 : 0);
}

static int
mdf_encap_of_group(const mdf_group_t *g) {
    return mdf_encap_of_type(g->type);
}

static const char *
mdf_encap_prefix(int encap) {
    switch (encap) {
    case WTAP_ENCAP_ETHERNET:
        return "ETH";
    case WTAP_ENCAP_SOCKETCAN:
        return "CAN";
    case WTAP_ENCAP_LIN:
        return "LIN";
    case WTAP_ENCAP_FLEXRAY:
        return "FR";
    }
    return "BUS";
}

static void
mdf_add_interface(wtap *wth, int encap, uint32_t channel) {
    wtap_block_t int_data = wtap_block_create(WTAP_BLOCK_IF_ID_AND_INFO);
    wtapng_if_descr_mandatory_t *if_descr_mand = (wtapng_if_descr_mandatory_t *)wtap_block_get_mandatory_data(int_data);

    if_descr_mand->wtap_encap = encap;
    wtap_block_add_string_option_format(int_data, OPT_IDB_NAME, "%s-%u", mdf_encap_prefix(encap), channel);
    if_descr_mand->time_units_per_second = 1000 * 1000 * 1000;
    if_descr_mand->tsprecision = WTAP_TSPREC_NSEC;
    wtap_block_add_uint8_option(int_data, OPT_IDB_TSRESOL, 9);
    if_descr_mand->snap_len = WTAP_MAX_PACKET_SIZE_STANDARD;
    if_descr_mand->num_stat_entries = 0;
    if_descr_mand->interface_statistics = NULL;
    wtap_add_idb(wth, int_data);

    if (wth->file_encap == WTAP_ENCAP_NONE) {
        wth->file_encap = encap;
    } else if (wth->file_encap != encap) {
        wth->file_encap = WTAP_ENCAP_PER_PACKET;
    }
}

wtap_open_return_val
mdf_open(wtap *wth, int *err, char **err_info) {
    uint8_t      idblock[MDF_LEN_ID_BLOCK];
    mdf_t       *mdf;
    mdf_block_t  hd;
    int64_t      dg;
    unsigned     visited = 0;
    unsigned     i;
    uint32_t     next_iface = 0;
    bool         ok = true;

    ws_debug("opening file");

    if (!wtap_read_bytes_or_eof(wth->fh, idblock, sizeof(idblock), err, err_info)) {
        if (*err == 0 || *err == WTAP_ERR_SHORT_READ) {
            /* Short read or EOF: too short to be an MDF file. */
            *err = 0;
            g_free(*err_info);
            *err_info = NULL;
            return WTAP_OPEN_NOT_MINE;
        }
        return WTAP_OPEN_ERROR;
    }

    if (memcmp(idblock, mdf_magic_fin, MDF_LEN_MAGIC) != 0) {
        /* Not an MDF file, or one that was not finalized. */
        return WTAP_OPEN_NOT_MINE;
    }
    if (pletohu16(idblock + 28) < MDF_MIN_VERSION || pletohu16(idblock + 60) != 0 || pletohu16(idblock + 62) != 0) {
        return WTAP_OPEN_NOT_MINE;
    }
    if (wth->ispipe) {
        /* we need random access */
        return WTAP_OPEN_NOT_MINE;
    }

    /* HD block directly behind the ID block */
    if (!mdf_load_block(wth->fh, MDF_LEN_ID_BLOCK, &hd, err, err_info)) {
        if (*err == WTAP_ERR_BAD_FILE || *err == WTAP_ERR_SHORT_READ) {
            *err = 0;
            g_free(*err_info);
            *err_info = NULL;
            return WTAP_OPEN_NOT_MINE;
        }
        return WTAP_OPEN_ERROR;
    }
    if (!mdf_id_is(hd.buf, "##HD") || hd.link_count < 1 || mdf_data_len(&hd) < 8) {
        ws_debug("invalid HD block");
        mdf_free_block(&hd);
        return WTAP_OPEN_NOT_MINE;
    }

    mdf = g_new0(mdf_t, 1);
    mdf->file_size = wtap_file_size(wth, err);
    if (mdf->file_size == -1) {
        mdf->file_size = 0;
        *err = 0;
    }
    mdf->groups = g_ptr_array_new_with_free_func(mdf_group_free);
    mdf->streams = g_ptr_array_new_with_free_func(mdf_stream_free_cb);
    mdf->vlsds = g_ptr_array_new_with_free_func(mdf_vlsd_free);
    mdf->events = g_array_new(false, false, sizeof(mdf_event_t));
    mdf->iface_ht = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, g_free);
    mdf->start_ns = pletohu64(mdf_data(&hd));
    dg = mdf_link(&hd, 0);
    mdf_free_block(&hd);

    while (dg != 0 && ok && visited++ < MDF_MAX_BLOCKS_PER_LIST) {
        mdf_block_t b;

        ok = mdf_scan_dg(mdf, wth->fh, dg, err, err_info);
        if (!ok) {
            break;
        }
        if (!mdf_load_block(wth->fh, dg, &b, err, err_info)) {
            ok = false;
            break;
        }
        dg = mdf_link(&b, 0);
        mdf_free_block(&b);
    }

    if (!ok) {
        mdf_free(mdf);
        if (*err == WTAP_ERR_BAD_FILE || *err == WTAP_ERR_SHORT_READ) {
            /* Looks like MDF, but we cannot make sense of it: leave it to the dissector. */
            ws_debug("cannot parse file: %s", *err_info ? *err_info : "short read");
            *err = 0;
            g_free(*err_info);
            *err_info = NULL;
            return WTAP_OPEN_NOT_MINE;
        }
        return WTAP_OPEN_ERROR;
    }

    if (!mdf->have_bus_cg) {
        mdf_free(mdf);
        *err = WTAP_ERR_UNSUPPORTED;
        *err_info = ws_strdup("mdf: the file contains no bus logging data, other MDF content is not supported yet");
        return WTAP_OPEN_ERROR;
    }
    if (mdf->events->len == 0) {
        /* bus logging groups without supported events: show an empty file */
        ws_debug("no supported bus events found");
    }

    g_array_sort(mdf->events, mdf_event_cmp);

    /* One interface per bus type and bus channel, in the order of appearance. */
    for (i = 0; i < mdf->events->len; i++) {
        mdf_event_t *ev = &g_array_index(mdf->events, mdf_event_t, i);
        int          encap = mdf_encap_of_group((mdf_group_t *)g_ptr_array_index(mdf->groups, ev->group));
        int64_t      key = ((int64_t)encap << 32) | ev->iface;
        uint32_t    *id = (uint32_t *)g_hash_table_lookup(mdf->iface_ht, &key);

        if (id == NULL) {
            int64_t *k = g_new(int64_t, 1);

            *k = key;
            id = g_new(uint32_t, 1);
            *id = next_iface++;
            g_hash_table_insert(mdf->iface_ht, k, id);
            mdf_add_interface(wth, encap, ev->iface);
        }
        ev->iface = *id;
    }

    wth->priv = mdf;
    wth->snapshot_length = 0;
    wth->file_tsprec = WTAP_TSPREC_NSEC;
    wth->subtype_read = mdf_read;
    wth->subtype_seek_read = mdf_seek_read;
    wth->subtype_close = mdf_close;
    wth->file_type_subtype = mdf_file_type_subtype;

    return WTAP_OPEN_MINE;
}

/* Options for interface blocks. */
static const struct supported_option_type interface_block_options_supported[] = {
    /* No comments, just an interface name. */
    { OPT_IDB_NAME, ONE_OPTION_SUPPORTED }
};

static const struct supported_block_type mdf_blocks_supported[] = {
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED },
    { WTAP_BLOCK_IF_ID_AND_INFO, MULTIPLE_BLOCKS_SUPPORTED, OPTION_TYPES_SUPPORTED(interface_block_options_supported) },
};

static const struct file_type_subtype_info mdf_info = {
    "MDF Logfile", "mdf", "mf4", NULL,
    false, BLOCKS_SUPPORTED(mdf_blocks_supported),
    NULL, NULL, NULL
};

void register_mdf(void)
{
    mdf_file_type_subtype = wtap_register_file_type_subtype(&mdf_info);

    /*
     * Register name for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("MDF", mdf_file_type_subtype);
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
