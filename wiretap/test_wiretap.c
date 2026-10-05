/*
 * Wiretap unit tests
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include <wsutil/file_compressed.h>
#include <wsutil/file_util.h>
#include <wsutil/pint.h>

#include "wtap.h"
#include "wtap_module.h"

#ifdef HAVE_LZ4FRAME_H
#include <lz4frame.h>
#include <lz4.h>

#define PACKET_SIZE 4096U
#define PACKET_COUNT 2300U
#define RECORD_SIZE (16U + PACKET_SIZE)
#define BLOCK_SIZE (4U * 1024U * 1024U)

static void
check_packet(const wtap_rec *rec, const uint8_t *capture, unsigned packet)
{
    g_assert_cmpuint(rec->rec_type, ==, REC_TYPE_PACKET);
    g_assert_cmpuint(rec->rec_header.packet_header.caplen, ==, PACKET_SIZE);
    g_assert_cmpint(rec->ts.secs, ==, packet + 1);
    g_assert_cmpmem(ws_buffer_start_ptr(&rec->data), PACKET_SIZE,
                    capture + 24 + packet * RECORD_SIZE + 16, PACKET_SIZE);
}

static void
check_seek(wtap *wth, wtap_rec *rec, const int64_t *offsets,
           const uint8_t *capture, unsigned packet)
{
    int err = 0;
    char *err_info = NULL;
    bool ok = wtap_seek_read(wth, offsets[packet], rec, &err, &err_info);
    if (!ok)
        g_test_message("seek packet %u error %d: %s", packet, err, err_info ? err_info : "");
    g_assert_true(ok);
    g_assert_cmpint(err, ==, 0);
    check_packet(rec, capture, packet);
    wtap_rec_reset(rec);
    g_free(err_info);
}

static void
test_lz4_seek(const void *data)
{
    unsigned mode = GPOINTER_TO_UINT(data);
    bool incompressible = mode == 1;
    bool linked = mode == 2;
    bool concatenated = mode >= 3;
    bool block_checksums = mode == 4;
    bool content_size = mode == 5;
    const size_t capture_size = 24 + PACKET_COUNT * RECORD_SIZE;
    uint8_t *capture = g_malloc0(capture_size);

    /* A little-endian pcap with records crossing 4 MiB block boundaries. */
    phtoleu32(capture, 0xa1b2c3d4);
    phtoleu16(capture + 4, 2);
    phtoleu16(capture + 6, 4);
    phtoleu32(capture + 16, PACKET_SIZE);
    phtoleu32(capture + 20, 1); /* Ethernet */
    uint32_t random = 1;
    for (unsigned packet = 0; packet < PACKET_COUNT; packet++) {
        uint8_t *record = capture + 24 + packet * RECORD_SIZE;
        phtoleu32(record, packet + 1);
        phtoleu32(record + 8, PACKET_SIZE);
        phtoleu32(record + 12, PACKET_SIZE);
        for (unsigned i = 0; i < PACKET_SIZE; i++) {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            record[16 + i] = incompressible ? (uint8_t)random : (uint8_t)(packet + i);
        }
    }

    char *path = NULL;
    int fd = g_file_open_tmp("wiretap-lz4-XXXXXX", &path, NULL);
    g_assert_cmpint(fd, >=, 0);
    if (linked || concatenated) {
        ws_close(fd);
        LZ4F_preferences_t prefs = { 0 };
        prefs.frameInfo.blockSizeID = LZ4F_max4MB;
        prefs.frameInfo.blockMode = linked ? LZ4F_blockLinked : LZ4F_blockIndependent;
        prefs.frameInfo.contentChecksumFlag = LZ4F_contentChecksumEnabled;
#if LZ4_VERSION_NUMBER >= 10800
        if (block_checksums)
            prefs.frameInfo.blockChecksumFlag = LZ4F_blockChecksumEnabled;
#endif
        size_t first_size = concatenated ? capture_size / 2 : capture_size;
        if (content_size)
            prefs.frameInfo.contentSize = first_size;
        size_t bound = LZ4F_compressFrameBound(capture_size, &prefs) * 2;
        uint8_t *compressed = g_malloc(bound);
        size_t written = LZ4F_compressFrame(compressed, bound, capture, first_size, &prefs);
        g_assert_false(LZ4F_isError(written));
        if (concatenated) {
            if (content_size)
                prefs.frameInfo.contentSize = capture_size - first_size;
            size_t more = LZ4F_compressFrame(compressed + written, bound - written,
                                           capture + first_size, capture_size - first_size, &prefs);
            g_assert_false(LZ4F_isError(more));
            written += more;
        }
        g_assert_true(g_file_set_contents(path, (const char *)compressed, written, NULL));
        g_free(compressed);
    } else {
        /* Exercise the same independent-block writer used by Save As. */
        LZ4WFILE_T writer = lz4wfile_fdopen(fd);
        g_assert_nonnull(writer);
        for (size_t pos = 0; pos < capture_size; ) {
            size_t chunk = MIN(capture_size - pos, 128U * 1024U);
            g_assert_cmpuint(lz4wfile_write(writer, capture + pos, chunk), ==, chunk);
            pos += chunk;
            /* Also exercise shorter, flushed blocks stored without compression. */
            if (incompressible && pos % (BLOCK_SIZE / 2) == 0)
                g_assert_cmpint(lz4wfile_flush(writer), ==, 0);
        }
        g_assert_cmpint(lz4wfile_close(writer), ==, 0);
    }

    /* First exercise a plain sequential reader with no fast-seek index. */
    for (unsigned pass = 0; pass < 2; pass++) {
        int err = 0;
        char *err_info = NULL;
        wtap *wth = wtap_open_offline(path, WTAP_TYPE_AUTO, &err, &err_info,
                                    pass != 0, "WIRESHARK");
        g_assert_nonnull(wth);
        int64_t *offsets = g_new(int64_t, PACKET_COUNT);
        wtap_rec rec;
        wtap_rec_init(&rec, PACKET_SIZE);
        unsigned packet = 0;
        int64_t offset;
        while (wtap_read(wth, &rec, &err, &err_info, &offset)) {
            g_assert_cmpuint(packet, <, PACKET_COUNT);
            offsets[packet] = offset;
            check_packet(&rec, capture, packet++);
            wtap_rec_reset(&rec);
        }
        g_assert_cmpint(err, ==, 0);
        g_assert_cmpuint(packet, ==, PACKET_COUNT);
        if (pass != 0) {
            g_assert_nonnull(wth->fast_seek);
            g_test_message("Seek checkpoints: %u", wth->fast_seek->len);
            /* A round trip alone also passes with the bug. Require actual
             * block checkpoints, not just the one/two frame-header points. */
            if (block_checksums || content_size) {
                /* Preserve frame-header seeking when block boundaries cannot
                 * be inferred safely from the decompressor's input hint. */
                g_assert_cmpuint(wth->fast_seek->len, ==, 2);
            } else {
#if LZ4_VERSION_NUMBER >= 11000
                g_assert_cmpuint(wth->fast_seek->len, >, concatenated ? 2U : 1U);
#elif LZ4_VERSION_NUMBER >= 10904
                if (!linked)
                    g_assert_cmpuint(wth->fast_seek->len, >, concatenated ? 2U : 1U);
#endif
            }
            check_seek(wth, &rec, offsets, capture, PACKET_COUNT - 1);
            check_seek(wth, &rec, offsets, capture, 0);
            for (unsigned i = 0; i < 64; i++) {
                unsigned selected = (i * 997U + 17U) % PACKET_COUNT;
                check_seek(wth, &rec, offsets, capture, selected);
            }
            /* Seek immediately before, across and after block boundaries. */
            unsigned block_size = incompressible ? BLOCK_SIZE / 2 : BLOCK_SIZE;
            for (unsigned boundary = block_size; boundary < capture_size; boundary += block_size) {
                unsigned crossing = (boundary - 24) / RECORD_SIZE;
                for (unsigned nearby = crossing - 1; nearby <= crossing + 1; nearby++)
                    check_seek(wth, &rec, offsets, capture, nearby);
            }
            if (concatenated) {
                /* Frame boundaries can fall in the middle of a packet too. */
                for (size_t boundary = capture_size / 2; boundary < capture_size; boundary += BLOCK_SIZE) {
                    unsigned crossing = (unsigned)((boundary - 24) / RECORD_SIZE);
                    for (unsigned nearby = crossing - 1; nearby <= crossing + 1; nearby++)
                        check_seek(wth, &rec, offsets, capture, nearby);
                }
            }
        }
        wtap_rec_cleanup(&rec);
        wtap_close(wth);
        g_free(offsets);
        g_free(err_info);
    }
    if (mode == 0) {
        /* Normal sequential reads must still reject a bad frame checksum. */
        char *compressed = NULL;
        size_t size = 0;
        g_assert_true(g_file_get_contents(path, &compressed, &size, NULL));
        compressed[size - 1] ^= 1;
        g_assert_true(g_file_set_contents(path, compressed, size, NULL));
        g_free(compressed);
        int err = 0;
        char *err_info = NULL;
        wtap *wth = wtap_open_offline(path, WTAP_TYPE_AUTO, &err, &err_info, false, "WIRESHARK");
        g_assert_nonnull(wth);
        wtap_rec rec;
        wtap_rec_init(&rec, PACKET_SIZE);
        int64_t offset;
        while (wtap_read(wth, &rec, &err, &err_info, &offset))
            wtap_rec_reset(&rec);
        g_assert_cmpint(err, ==, WTAP_ERR_DECOMPRESS);
        g_assert_nonnull(strstr(err_info, "contentChecksum"));
        wtap_rec_cleanup(&rec);
        wtap_close(wth);
        g_free(err_info);
    }
    ws_unlink(path);
    g_free(path);
    g_free(capture);
}
#endif /* HAVE_LZ4FRAME_H */

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    wtap_init(false, "WIRESHARK", NULL, 0);
#ifdef HAVE_LZ4FRAME_H
    g_test_add_data_func("/wiretap/lz4/native-compressed", GUINT_TO_POINTER(0), test_lz4_seek);
    g_test_add_data_func("/wiretap/lz4/native-incompressible", GUINT_TO_POINTER(1), test_lz4_seek);
    g_test_add_data_func("/wiretap/lz4/linked", GUINT_TO_POINTER(2), test_lz4_seek);
    g_test_add_data_func("/wiretap/lz4/concatenated", GUINT_TO_POINTER(3), test_lz4_seek);
    g_test_add_data_func("/wiretap/lz4/content-size", GUINT_TO_POINTER(5), test_lz4_seek);
#if LZ4_VERSION_NUMBER >= 10800
    g_test_add_data_func("/wiretap/lz4/block-checksums", GUINT_TO_POINTER(4), test_lz4_seek);
#endif
#endif
    int ret = g_test_run();
    wtap_cleanup();
    return ret;
}
