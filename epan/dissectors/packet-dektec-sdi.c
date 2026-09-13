/* packet-dektec-sdi.c
 * Routines for dissecting raw SDI frames from DekTec DTSDI files.
 *
 * File-format definitions are in Import/DtSdiFileFmt.h in the DekTec
 * DtPlay source package. SDI sample representations are documented by
 * the DtSdi class in the DekTec DTAPI documentation. Both are distributed
 * from:
 * https://www.dektec.com/downloads/SDK/
 *
 * Copyright (c) 2026, Devin Heitmueller <dheitmueller@ltnglobal.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <wiretap/wtap.h>
#include <wsutil/pint.h>

#include "packet-smpte-291-vanc.h"

#define DTSDI_FLAG_10B 0x0080
#define DTSDI_FLAG_16B 0x0100

static int proto_dektec_sdi;

static int hf_dektec_sdi_format_version;
static int hf_dektec_sdi_data_type;
static int hf_dektec_sdi_flags;
static int hf_dektec_sdi_storage;
static int hf_dektec_sdi_active_video_present;
static int hf_dektec_sdi_active_video_span;
static int hf_dektec_sdi_vanc_packet_count;
static int hf_dektec_sdi_hanc_packet_count;
static int hf_dektec_sdi_hanc_audio_packet_count;
static int hf_dektec_sdi_hanc_audio_span;
static int hf_dektec_sdi_anc_packet;
static int hf_dektec_sdi_anc_line;
static int hf_dektec_sdi_anc_stream;
static int hf_dektec_sdi_anc_adf;
static int hf_dektec_sdi_anc_data_count;
static int hf_dektec_sdi_anc_payload;
static int hf_dektec_sdi_anc_checksum;
static int hf_dektec_sdi_anc_checksum_good;

static int ett_dektec_sdi;
static int ett_dektec_sdi_anc;
static int ett_dektec_sdi_anc_payload;

static expert_field ei_dektec_sdi_8bit_anc;
static expert_field ei_dektec_sdi_bad_checksum;
static expert_field ei_dektec_sdi_bad_parity;
static expert_field ei_dektec_sdi_truncated_anc;

static bool pref_decode_hanc_audio;

static dissector_handle_t dektec_sdi_handle;

void proto_register_dektec_sdi(void);
void proto_reg_handoff_dektec_sdi(void);

static const value_string data_type_vals[] = {
    { 0x01, "625i50" },
    { 0x02, "525i59.94" },
    { 0x03, "720p23.98" },
    { 0x04, "720p24" },
    { 0x05, "720p25" },
    { 0x06, "720p29.97" },
    { 0x07, "720p30" },
    { 0x08, "720p50" },
    { 0x09, "720p59.94" },
    { 0x0a, "720p60" },
    { 0x0b, "1080p23.98" },
    { 0x0c, "1080p24" },
    { 0x0d, "1080p25" },
    { 0x0e, "1080p30" },
    { 0x0f, "1080p29.97" },
    { 0x10, "1080i50" },
    { 0x11, "1080i59.94" },
    { 0x12, "1080i60" },
    { 0x13, "1080p50" },
    { 0x14, "1080p59.94" },
    { 0x15, "1080p60" },
    { 0x16, "1080psf23.98" },
    { 0x17, "1080psf24" },
    { 0x18, "1080psf25" },
    { 0x19, "1080psf29.97" },
    { 0x1a, "1080psf30" },
    { 0,    NULL }
};

static const value_string storage_vals[] = {
    { 8, "8-bit (two least-significant bits discarded)" },
    { 10, "Packed 10-bit" },
    { 16, "10-bit words in little-endian 16-bit values" },
    { 0, NULL }
};

typedef enum {
    SDI_REGION_UNKNOWN,
    SDI_REGION_HANC,
    SDI_REGION_VANC,
    SDI_REGION_ACTIVE_VIDEO
} sdi_region_t;

typedef struct {
    tvbuff_t *tvb;
    const uint8_t *data;
    uint32_t byte_count;
    unsigned storage_bits;
    uint32_t word_count;
} sdi_words_t;

typedef struct {
    uint32_t vanc_packets;
    uint32_t hanc_packets;
    uint32_t hanc_audio_packets;
    bool active_video_present;
    bool active_video_range_valid;
    unsigned active_video_offset;
    unsigned active_video_end;
    bool hanc_audio_range_valid;
    unsigned hanc_audio_offset;
    unsigned hanc_audio_end;
} sdi_scan_result_t;

typedef struct {
    uint8_t first;
    uint8_t last;
} sdi_audio_did_range_t;

static const sdi_audio_did_range_t audio_did_ranges[] = {
    { 0xa0, 0xa7 }, /* SMPTE ST 299-2 audio groups 5 through 8. */
    { 0xe0, 0xe7 }, /* SMPTE ST 299 audio data and control packets. */
    { 0xec, 0xef }, /* SMPTE ST 272 audio data and control packets. */
    { 0xf8, 0xff }
};

static bool
sdi_get_word(const sdi_words_t *words, uint32_t word_index, uint16_t *word)
{
    uint64_t bit_offset;
    unsigned byte_offset;
    unsigned shift;
    uint32_t value;

    if (word_index >= words->word_count)
        return false;

    switch (words->storage_bits) {
    case 16:
        *word = pletohu16(words->data + word_index * 2) & 0x03ff;
        return true;
    case 10:
        /* DTAPI concatenates successive 10-bit symbols least-significant bit first. */
        bit_offset = (uint64_t)word_index * 10;
        byte_offset = (unsigned)(bit_offset / 8);
        shift = (unsigned)(bit_offset % 8);
        value = words->data[byte_offset];
        if (byte_offset + 1 < words->byte_count)
            value |= (uint32_t)words->data[byte_offset + 1] << 8;
        if (shift > 6 && byte_offset + 2 < words->byte_count)
            value |= (uint32_t)words->data[byte_offset + 2] << 16;
        *word = (value >> shift) & 0x03ff;
        return true;
    case 8:
        *word = (uint16_t)words->data[word_index] << 2;
        return true;
    default:
        return false;
    }
}

static void
sdi_word_range(const sdi_words_t *words, uint32_t first_word,
               uint32_t logical_word_count, uint32_t stride,
               unsigned *offset, unsigned *length)
{
    uint64_t first_bit = (uint64_t)first_word * words->storage_bits;
    uint64_t last_word = first_word + (uint64_t)(logical_word_count - 1) * stride;
    uint64_t end_bit = (last_word + 1) * words->storage_bits;

    *offset = (unsigned)(first_bit / 8);
    *length = (unsigned)((end_bit + 7) / 8 - *offset);
}

static bool
sdi_is_audio_did(uint16_t did)
{
    uint8_t did_value = did & 0x00ff;

    for (size_t i = 0; i < array_length(audio_did_ranges); i++) {
        if (did_value >= audio_did_ranges[i].first &&
            did_value <= audio_did_ranges[i].last)
            return true;
    }

    return false;
}

static void
sdi_add_anc_packet(const sdi_words_t *words, packet_info *pinfo,
                   proto_tree *top_tree, proto_tree *tree,
                   uint32_t first_word, uint32_t stride, uint32_t packet_words,
                   uint32_t line, unsigned stream, bool hanc, bool audio)
{
    proto_item *packet_item;
    proto_tree *anc_tree;
    proto_item *item;
    unsigned offset;
    unsigned length;
    uint16_t did;
    uint16_t sdid_dbn;
    uint16_t dc_word;
    uint8_t data_count;
    uint8_t did_value;
    uint8_t second_value;
    bool type1;
    uint16_t *st291_words;
    uint32_t st291_word_count;
    st291_vanc_packet_t st291_packet;
    proto_item *payload_item;
    proto_tree *payload_tree;
    proto_item *did_item;
    proto_item *second_item;
    proto_item *dc_item;

    if (!sdi_get_word(words, first_word + 3 * stride, &did) ||
        !sdi_get_word(words, first_word + 4 * stride, &sdid_dbn) ||
        !sdi_get_word(words, first_word + 5 * stride, &dc_word))
        return;
    data_count = dc_word & 0x00ff;
    did_value = did & 0x00ff;
    second_value = sdid_dbn & 0x00ff;
    type1 = (did_value & 0x80U) != 0;

    st291_word_count = packet_words - 3;
    st291_words = wmem_alloc_array(pinfo->pool, uint16_t, st291_word_count);
    for (uint32_t st291_index = 0; st291_index < st291_word_count;
         st291_index++) {
        if (!sdi_get_word(words, first_word + (3 + st291_index) * stride,
                          &st291_words[st291_index]))
            return;
    }
    if (!st291_vanc_packet_from_words(words->tvb, pinfo, st291_words,
                                      st291_word_count, &st291_packet))
        return;

    sdi_word_range(words, first_word, packet_words, stride, &offset, &length);
    packet_item = proto_tree_add_none_format(tree, hf_dektec_sdi_anc_packet,
                                             words->tvb, offset, length,
                                             "%s packet: DID 0x%02x, %s 0x%02x",
                                             hanc ? (audio ? "HANC audio" : "HANC") : "VANC",
                                             did_value, type1 ? "DBN" : "SDID",
                                             second_value);
    anc_tree = proto_item_add_subtree(packet_item, ett_dektec_sdi_anc);
    st291_append_packet_description(packet_item, did_value, second_value);
    item = proto_tree_add_uint(anc_tree, hf_dektec_sdi_anc_line, words->tvb, 0, 0, line);
    proto_item_set_generated(item);
    item = proto_tree_add_string(anc_tree, hf_dektec_sdi_anc_stream, words->tvb, 0, 0,
                                 stream == 0 ? "C" : stream == 1 ? "Y" : "SD");
    proto_item_set_generated(item);

    sdi_word_range(words, first_word, 3, stride, &offset, &length);
    proto_tree_add_item(anc_tree, hf_dektec_sdi_anc_adf, words->tvb, offset, length, ENC_NA);

    sdi_word_range(words, first_word + 3 * stride, 1, stride, &offset, &length);
    did_item = st291_tree_add_did(anc_tree, words->tvb, offset, length,
                                  did_value);
    sdi_word_range(words, first_word + 4 * stride, 1, stride, &offset, &length);
    if (type1)
        second_item = st291_tree_add_dbn(anc_tree, words->tvb, offset, length,
                                         second_value);
    else
        second_item = st291_tree_add_sdid(anc_tree, words->tvb, offset, length,
                                          did_value, second_value);
    sdi_word_range(words, first_word + 5 * stride, 1, stride, &offset, &length);
    dc_item = proto_tree_add_uint(anc_tree, hf_dektec_sdi_anc_data_count, words->tvb,
                                  offset, length, data_count);

    if (!st291_packet.did_parity_ok)
        expert_add_info_format(pinfo, did_item, &ei_dektec_sdi_bad_parity,
                               "Invalid ST 291 DID parity (raw word 0x%03x)",
                               did);
    if (!st291_packet.second_word_parity_ok)
        expert_add_info_format(pinfo, second_item, &ei_dektec_sdi_bad_parity,
                               "Invalid ST 291 %s parity (raw word 0x%03x)",
                               type1 ? "DBN" : "SDID", sdid_dbn);
    if (!st291_packet.data_count_parity_ok)
        expert_add_info_format(pinfo, dc_item, &ei_dektec_sdi_bad_parity,
                               "Invalid ST 291 DC parity (raw word 0x%03x)",
                               dc_word);

    if (data_count != 0) {
        sdi_word_range(words, first_word + 6 * stride, data_count, stride,
                       &offset, &length);
        payload_item = proto_tree_add_item(anc_tree, hf_dektec_sdi_anc_payload,
                                           words->tvb, offset, length, ENC_NA);
        payload_tree = proto_item_add_subtree(payload_item, ett_dektec_sdi_anc_payload);
    } else {
        payload_item = proto_tree_add_item(anc_tree, hf_dektec_sdi_anc_payload,
                                           words->tvb, 0, 0, ENC_NA);
        proto_item_set_generated(payload_item);
        payload_tree = proto_item_add_subtree(payload_item, ett_dektec_sdi_anc_payload);
    }

    sdi_word_range(words, first_word + (6 + data_count) * stride, 1, stride,
                   &offset, &length);
    item = proto_tree_add_uint(anc_tree, hf_dektec_sdi_anc_checksum, words->tvb,
                               offset, length, st291_packet.checksum);

    packet_item = proto_tree_add_boolean(anc_tree, hf_dektec_sdi_anc_checksum_good,
                                         words->tvb, 0, 0,
                                         st291_packet.checksum_ok);
    proto_item_set_generated(packet_item);

    if (!st291_packet.checksum_ok)
        expert_add_info_format(pinfo, item, &ei_dektec_sdi_bad_checksum,
                               "ANC checksum 0x%03x, expected 0x%03x",
                               st291_packet.checksum,
                               st291_packet.checksum_calculated);

    if (!audio) {
        st291_vanc_dissector_data_t st291_data = {
            .top_tree = top_tree,
            .payload_index = first_word,
        };

        st291_vanc_dissect_packet(&st291_packet, pinfo, payload_tree,
                                  payload_item, &st291_data);
    }
}

static void
sdi_scan_stream(const sdi_words_t *words, packet_info *pinfo,
                proto_tree *top_tree, proto_tree *tree, uint32_t first_word,
                uint32_t stride, unsigned stream, sdi_scan_result_t *result)
{
    sdi_region_t region = SDI_REGION_UNKNOWN;
    uint32_t word_index = first_word;
    uint32_t line = 0;
    uint16_t word0, word1, word2, word3;

    if (word_index + 3 * stride >= words->word_count)
        return;

    if (!sdi_get_word(words, word_index, &word0) ||
        !sdi_get_word(words, word_index + stride, &word1) ||
        !sdi_get_word(words, word_index + 2 * stride, &word2))
        return;

    while (true) {
        uint32_t next_word_index = word_index + stride;

        if (word0 == 0x03ff && word1 == 0 && word2 == 0) {
            if (!sdi_get_word(words, word_index + 3 * stride, &word3))
                return;
            if (word3 & 0x0200) {
                bool vertical_blank = (word3 & 0x0080) != 0;
                bool horizontal_blank = (word3 & 0x0040) != 0;

                if (horizontal_blank) {
                    if (region == SDI_REGION_ACTIVE_VIDEO &&
                        result->active_video_range_valid) {
                        unsigned offset;
                        unsigned length;

                        sdi_word_range(words, word_index, 1, stride,
                                       &offset, &length);
                        result->active_video_end = MAX(result->active_video_end,
                                                       offset);
                    }
                    if (stream != 2 &&
                        word_index + 7 * stride < words->word_count) {
                        uint16_t ln0;
                        uint16_t ln1;

                        if (!sdi_get_word(words, word_index + 4 * stride,
                                          &ln0) ||
                            !sdi_get_word(words, word_index + 5 * stride,
                                          &ln1))
                            return;
                        line = ((ln1 >> 2) & 0x0fU) << 7;
                        line |= (ln0 >> 2) & 0x7fU;

                        /* Skip EAV, LN0/LN1, and the two CRC words. */
                        next_word_index = word_index + 8 * stride;
                    } else {
                        /* SD-SDI does not carry line-number words. */
                        line++;
                        next_word_index = word_index + 4 * stride;
                    }
                    region = SDI_REGION_HANC;
                } else {
                    region = vertical_blank ? SDI_REGION_VANC :
                                              SDI_REGION_ACTIVE_VIDEO;
                    next_word_index = word_index + 4 * stride;
                    if (!vertical_blank) {
                        unsigned offset;
                        unsigned length;

                        result->active_video_present = true;
                        sdi_word_range(words, next_word_index, 1, stride,
                                       &offset, &length);
                        if (!result->active_video_range_valid) {
                            result->active_video_range_valid = true;
                            result->active_video_offset = offset;
                            result->active_video_end = offset + length;
                        } else {
                            result->active_video_offset =
                                MIN(result->active_video_offset, offset);
                        }
                    }
                }
                goto load_window;
            }
        }

        if ((region == SDI_REGION_VANC || region == SDI_REGION_HANC) &&
            word0 == 0 && word1 == 0x03ff && word2 == 0x03ff) {
            uint16_t did;
            uint16_t dc_word;
            uint32_t packet_words;
            bool audio;

            if (word_index + 6 * stride >= words->word_count) {
                if (tree)
                    proto_tree_add_expert_format(tree, pinfo, &ei_dektec_sdi_truncated_anc,
                                                 words->tvb, 0, 0,
                                                 "Truncated ANC packet header");
                return;
            }

            if (!sdi_get_word(words, word_index + 3 * stride, &did) ||
                !sdi_get_word(words, word_index + 5 * stride, &dc_word))
                return;
            packet_words = 7U + (dc_word & 0x00ff);
            if (word_index + (packet_words - 1) * stride >= words->word_count) {
                if (tree)
                    proto_tree_add_expert_format(tree, pinfo, &ei_dektec_sdi_truncated_anc,
                                                 words->tvb, 0, 0,
                                                 "Truncated ANC packet payload");
                return;
            }

            audio = sdi_is_audio_did(did);
            if (region == SDI_REGION_VANC) {
                result->vanc_packets++;
                if (tree)
                    sdi_add_anc_packet(words, pinfo, top_tree, tree, word_index,
                                       stride, packet_words, line, stream,
                                       false, false);
            } else if (audio) {
                unsigned offset;
                unsigned length;

                result->hanc_audio_packets++;
                sdi_word_range(words, word_index, packet_words, stride,
                               &offset, &length);
                if (!result->hanc_audio_range_valid) {
                    result->hanc_audio_range_valid = true;
                    result->hanc_audio_offset = offset;
                    result->hanc_audio_end = offset + length;
                } else {
                    result->hanc_audio_offset = MIN(result->hanc_audio_offset,
                                                    offset);
                    result->hanc_audio_end = MAX(result->hanc_audio_end,
                                                 offset + length);
                }
                if (tree && pref_decode_hanc_audio)
                    sdi_add_anc_packet(words, pinfo, top_tree, tree, word_index,
                                       stride, packet_words, line, stream,
                                       true, true);
            } else {
                result->hanc_packets++;
                if (tree)
                    sdi_add_anc_packet(words, pinfo, top_tree, tree, word_index,
                                       stride, packet_words, line, stream,
                                       true, false);
            }

            next_word_index = word_index + packet_words * stride;
            goto load_window;
        }

        word_index = next_word_index;
        if (word_index + 3 * stride >= words->word_count)
            break;
        word0 = word1;
        word1 = word2;
        if (!sdi_get_word(words, word_index + 2 * stride, &word2))
            return;
        continue;

load_window:
        word_index = next_word_index;
        if (word_index + 3 * stride >= words->word_count)
            break;
        if (!sdi_get_word(words, word_index, &word0) ||
            !sdi_get_word(words, word_index + stride, &word1) ||
            !sdi_get_word(words, word_index + 2 * stride, &word2))
            return;
    }
}

static int
dissect_dektec_sdi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                   void *data _U_)
{
    const struct dtsdi_phdr *phdr;
    sdi_words_t words;
    sdi_scan_result_t result = { 0 };
    proto_item *root_item = NULL;
    proto_tree *sdi_tree = NULL;
    const char *format;
    bool is_hd;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SDI");

    if (pinfo->pseudo_header == NULL) {
        col_set_str(pinfo->cinfo, COL_INFO, "DekTec SDI frame (missing metadata)");
        return tvb_captured_length(tvb);
    }

    phdr = &pinfo->pseudo_header->dtsdi;
    format = val_to_str_const(phdr->data_type, data_type_vals, "Unknown format");
    is_hd = phdr->data_type >= 0x03;

    if (phdr->flags & DTSDI_FLAG_16B)
        words.storage_bits = 16;
    else if (phdr->flags & DTSDI_FLAG_10B)
        words.storage_bits = 10;
    else
        words.storage_bits = 8;

    words.tvb = tvb;
    words.byte_count = tvb_captured_length(tvb);
    words.data = tvb_get_ptr(tvb, 0, words.byte_count);
    words.word_count = (uint32_t)(((uint64_t)words.byte_count * 8) /
                                  words.storage_bits);

    if (tree) {
        root_item = proto_tree_add_protocol_format(tree, proto_dektec_sdi, tvb,
                                                   0, -1,
                                                   "DekTec SDI frame: %s, %u-bit storage",
                                                   format, words.storage_bits);
        sdi_tree = proto_item_add_subtree(root_item, ett_dektec_sdi);
        proto_item_set_generated(
            proto_tree_add_uint(sdi_tree, hf_dektec_sdi_format_version,
                                tvb, 0, 0, phdr->format_version + 1));
        proto_item_set_generated(
            proto_tree_add_uint(sdi_tree, hf_dektec_sdi_data_type,
                                tvb, 0, 0, phdr->data_type));
        proto_item_set_generated(
            proto_tree_add_uint(sdi_tree, hf_dektec_sdi_flags,
                                tvb, 0, 0, phdr->flags));
        proto_item_set_generated(
            proto_tree_add_uint(sdi_tree, hf_dektec_sdi_storage,
                                tvb, 0, 0, words.storage_bits));
    }

    if (words.storage_bits == 8) {
        col_add_fstr(pinfo->cinfo, COL_INFO,
                     "%s, 8-bit storage (ANC detail unavailable)", format);
        if (sdi_tree)
            proto_tree_add_expert_format(sdi_tree, pinfo, &ei_dektec_sdi_8bit_anc,
                                         tvb, 0, 0,
                                         "The 8-bit representation discards two bits from every SDI word; ANC packets cannot be decoded reliably");
        return tvb_captured_length(tvb);
    }

    if (is_hd) {
        sdi_scan_stream(&words, pinfo, tree, sdi_tree, 0, 2, 0, &result);
        sdi_scan_stream(&words, pinfo, tree, sdi_tree, 1, 2, 1, &result);
    } else {
        sdi_scan_stream(&words, pinfo, tree, sdi_tree, 0, 1, 2, &result);
    }

    if (result.hanc_audio_packets != 0) {
        col_add_fstr(pinfo->cinfo, COL_INFO,
                     "%s, VANC: %u packet%s, HANC: %u non-audio packet%s, Audio: present (%u packet%s)",
                     format, result.vanc_packets,
                     result.vanc_packets == 1 ? "" : "s",
                     result.hanc_packets,
                     result.hanc_packets == 1 ? "" : "s",
                     result.hanc_audio_packets,
                     result.hanc_audio_packets == 1 ? "" : "s");
    } else {
        col_add_fstr(pinfo->cinfo, COL_INFO,
                     "%s, VANC: %u packet%s, HANC: %u non-audio packet%s, Audio: not found",
                     format, result.vanc_packets,
                     result.vanc_packets == 1 ? "" : "s",
                     result.hanc_packets,
                     result.hanc_packets == 1 ? "" : "s");
    }

    if (sdi_tree) {
        proto_item *item;

        item = proto_tree_add_boolean(sdi_tree, hf_dektec_sdi_active_video_present,
                                      tvb, 0, 0, result.active_video_present);
        proto_item_set_generated(item);
        proto_item_set_generated(
            proto_tree_add_uint(sdi_tree, hf_dektec_sdi_vanc_packet_count,
                                tvb, 0, 0, result.vanc_packets));
        proto_item_set_generated(
            proto_tree_add_uint(sdi_tree, hf_dektec_sdi_hanc_packet_count,
                                tvb, 0, 0, result.hanc_packets));
        proto_item_set_generated(
            proto_tree_add_uint(sdi_tree, hf_dektec_sdi_hanc_audio_packet_count,
                                tvb, 0, 0, result.hanc_audio_packets));
        if (result.active_video_range_valid) {
            proto_tree_add_item(sdi_tree, hf_dektec_sdi_active_video_span, tvb,
                                result.active_video_offset,
                                result.active_video_end - result.active_video_offset,
                                ENC_NA);
        }
        if (result.hanc_audio_range_valid && !pref_decode_hanc_audio) {
            proto_tree_add_item(sdi_tree, hf_dektec_sdi_hanc_audio_span, tvb,
                                result.hanc_audio_offset,
                                result.hanc_audio_end - result.hanc_audio_offset,
                                ENC_NA);
        }
        if (result.hanc_audio_packets != 0 && !pref_decode_hanc_audio) {
            proto_item_append_text(root_item,
                                   ", %u HANC audio packets (details disabled)",
                                   result.hanc_audio_packets);
        }
    }

    return tvb_captured_length(tvb);
}

void
proto_register_dektec_sdi(void)
{
    static hf_register_info hf[] = {
        { &hf_dektec_sdi_format_version,
          { "DTSDI format version", "dektec_sdi.format_version",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dektec_sdi_data_type,
          { "Video format", "dektec_sdi.data_type",
            FT_UINT8, BASE_HEX, VALS(data_type_vals), 0x0, NULL, HFILL } },
        { &hf_dektec_sdi_flags,
          { "DTSDI flags", "dektec_sdi.flags",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_dektec_sdi_storage,
          { "Sample storage", "dektec_sdi.storage",
            FT_UINT8, BASE_DEC, VALS(storage_vals), 0x0, NULL, HFILL } },
        { &hf_dektec_sdi_active_video_present,
          { "Active video present", "dektec_sdi.active_video_present",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dektec_sdi_active_video_span,
          { "Active video byte span", "dektec_sdi.active_video_span",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Byte span from the first through the last detected active-video sample",
            HFILL } },
        { &hf_dektec_sdi_vanc_packet_count,
          { "VANC packet count", "dektec_sdi.vanc.packet_count",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dektec_sdi_hanc_packet_count,
          { "Non-audio HANC packet count", "dektec_sdi.hanc.packet_count",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dektec_sdi_hanc_audio_packet_count,
          { "HANC audio packet count", "dektec_sdi.hanc.audio_packet_count",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dektec_sdi_hanc_audio_span,
          { "HANC audio byte span", "dektec_sdi.hanc.audio_span",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Byte span from the first through the last detected HANC audio packet",
            HFILL } },
        { &hf_dektec_sdi_anc_packet,
          { "Ancillary data packet", "dektec_sdi.anc.packet",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dektec_sdi_anc_line,
          { "Line", "dektec_sdi.anc.line",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dektec_sdi_anc_stream,
          { "Data stream", "dektec_sdi.anc.stream",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dektec_sdi_anc_adf,
          { "Ancillary data flag", "dektec_sdi.anc.adf",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dektec_sdi_anc_data_count,
          { "Data count", "dektec_sdi.anc.data_count",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_dektec_sdi_anc_payload,
          { "User data words", "dektec_sdi.anc.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_dektec_sdi_anc_checksum,
          { "Checksum", "dektec_sdi.anc.checksum",
            FT_UINT16, BASE_HEX, NULL, 0x03ff, NULL, HFILL } },
        { &hf_dektec_sdi_anc_checksum_good,
          { "Checksum good", "dektec_sdi.anc.checksum_good",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    };
    static int *ett[] = { &ett_dektec_sdi, &ett_dektec_sdi_anc, &ett_dektec_sdi_anc_payload };
    static ei_register_info ei[] = {
        { &ei_dektec_sdi_8bit_anc,
          { "dektec_sdi.anc.8bit_unavailable", PI_UNDECODED, PI_NOTE,
            "ANC detail is unavailable with 8-bit storage", EXPFILL } },
        { &ei_dektec_sdi_bad_checksum,
          { "dektec_sdi.anc.bad_checksum", PI_CHECKSUM, PI_WARN,
            "Bad ANC checksum", EXPFILL } },
        { &ei_dektec_sdi_bad_parity,
          { "dektec_sdi.anc.bad_parity", PI_CHECKSUM, PI_WARN,
            "Invalid ST 291 parity", EXPFILL } },
        { &ei_dektec_sdi_truncated_anc,
          { "dektec_sdi.anc.truncated", PI_MALFORMED, PI_ERROR,
            "Truncated ANC packet", EXPFILL } },
    };
    module_t *module;
    expert_module_t *expert_module;

    proto_dektec_sdi = proto_register_protocol("DekTec Serial Digital Interface",
                                               "DekTec SDI", "dektec_sdi");
    dektec_sdi_handle = register_dissector("dektec_sdi", dissect_dektec_sdi,
                                           proto_dektec_sdi);
    proto_register_field_array(proto_dektec_sdi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module = expert_register_protocol(proto_dektec_sdi);
    expert_register_field_array(expert_module, ei, array_length(ei));

    module = prefs_register_protocol(proto_dektec_sdi, NULL);
    prefs_register_bool_preference(module, "decode_hanc_audio",
        "Decode HANC audio packets",
        "Show individual embedded-audio ANC packets found in HANC. This can add many protocol-tree entries per SDI frame.",
        &pref_decode_hanc_audio);
}

void
proto_reg_handoff_dektec_sdi(void)
{
    dissector_add_uint("wtap_encap", WTAP_ENCAP_DEKTEC_SDI,
                       dektec_sdi_handle);
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
