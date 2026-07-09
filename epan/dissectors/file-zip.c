/* file-zip.c
 *
 * Routines for ZIP File dissection
 * Copyright 2026, John Thacker <johnthacker@gmail.com>.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
 * https://libzip.org/specifications/
 *
 * Most ZIP tools scan from the end of the file to find the central directory
 * listing, and indeed the specification only truly makes sense considering
 * this possibility. It also makes sense in the context of spanning archives
 * across multiple removable floppy disks or splitting them into files (where
 * the last disk would be the one inserted first for dearchiving, or the last
 * file would have the .zip extension), adding or removing files to an archive
 * without rewriting everything (which leaves gaps; cf. tar, where gaps are
 * not allowed and deletion is more work), etc.
 *
 * This streams from the beginning (see Mark Adler's sunzip for the approach),
 * which probably will fail on some files that other tools will handle,
 * although it has the advantage of inherently not falling prey to zip bombs
 * that use overlapping files:
 * https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf
 * https://github.com/madler/sunzip
 *
 * ISO/IEC 21320-1:2015 specifies a restricted subset of ZIP files, with
 * annotations specifically disallowing the spanning/splitting, encryption,
 * digital signatures, and patched data features, allowing only compression
 * methods 0 ("stored") and 8 ("deflated"), and recommending setting the
 * UTF-8 bit.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/crc32-tvb.h>
#include <epan/export_object.h>
#include <epan/tfs.h>
#include <epan/unit_strings.h>
#include <wsutil/array.h>

#include "packet-smb.h"

void proto_reg_handoff_zip(void);
void proto_register_zip(void);

static int proto_zip;

static dissector_handle_t zip_handle;

static dissector_table_t zip_record_dissector_table;
static dissector_table_t zip_extra_dissector_table;

static int zip_eo_tap;

// Header fields
static int hf_zip_file;
static int hf_zip_directory;
static int hf_zip_end_of_directory;
static int hf_zip64_end_of_directory;
static int hf_zip64_end_of_directory_locator;
static int hf_zip_record_signature;
static int hf_zip_made_by;
static int hf_zip_version_made_by;
static int hf_zip_host_made_by;
static int hf_zip_version_to_extract;

static int hf_zip_flags;
static int hf_zip_flag_encryption;
static int hf_zip_flag_deflate_opts;
static int hf_zip_flag_lzma_eos;
static int hf_zip_flag_data_descriptor;
static int hf_zip_flag_patched_data;
static int hf_zip_flag_strong_encryption;
static int hf_zip_flag_language_encoding;
static int hf_zip_flag_central_dir_encryption;

static int hf_zip_compression_method;
static int hf_zip_last_mod_file_date_time;
static int hf_zip_last_mod_file_time;
static int hf_zip_last_mod_file_date;
static int hf_zip_crc32;
static int hf_zip_crc32_status;
static int hf_zip_file_compressed_size;
static int hf_zip_file_uncompressed_size;
static int hf_zip_file_name_length;
static int hf_zip_extra_fields_length;
static int hf_zip_file_name;

static int hf_zip_extra_fields;
static int hf_zip_extra_field;
static int hf_zip_extra_id;
static int hf_zip_extra_data_size;
static int hf_zip_extra_data;
static int hf_zip_extra_version;

static int hf_zip_extra_ut_flags;
static int hf_zip_extra_ut_flag_mtime;
static int hf_zip_extra_ut_flag_atime;
static int hf_zip_extra_ut_flag_ctime;
static int hf_zip_extra_ut_mtime;
static int hf_zip_extra_ut_atime;
static int hf_zip_extra_ut_ctime;

static int hf_zip_extra_unix_uid_size;
static int hf_zip_extra_unix_uid;
static int hf_zip_extra_unix_gid_size;
static int hf_zip_extra_unix_gid;

static int hf_zip_encryption_header;
static int hf_zip_encrypted_file_data;
static int hf_zip_compressed_file_data;
static int hf_zip_file_data;

static int hf_zip_file_comment_length;
static int hf_zip_disk_start_number;
static int hf_zip_internal_file_attr;
static int hf_zip_external_file_attr;
static int hf_zip_local_header_offset;
static int hf_zip_file_comment;

static int hf_zip_disk_number;
static int hf_zip_directory_disk_start_number;
static int hf_zip_directory_entries_disk;
static int hf_zip_directory_entries;
static int hf_zip_directory_size;
static int hf_zip_directory_offset;
static int hf_zip_directory_end_size;
static int hf_zip_archive_comment;
static int hf_zip_extensible_data_sector;
static int hf_zip_zip64_directory_end_disk_start_number;
static int hf_zip_zip64_directory_end_offset;
static int hf_zip_total_disks;

static int ett_zip;
static int ett_zip_record;
static int ett_zip_made_by;
static int ett_zip_flags;
static int ett_zip_extras;
static int ett_zip_extra;
static int ett_zip_extra_ut_flags;

static expert_field ei_zip_crc32;
static expert_field ei_zip_overflow;
static expert_field ei_zip_underflow;
static expert_field ei_zip_unsupported;

// "PK" for Phil Katz; Big Endian for tvb_find_uint16_remaining
#define ZIP_MAGIC_UINT 0x504b

/* Officially, the header signatures are Little-Endian like everything
 * in the format, though they make more sense to read Big-Endian. */
#define ZIP_DIRECTORY_RECORD                    0x02014b50
#define ZIP_FILE_RECORD                         0x04034b50
#define ZIP_DIGITAL_SIGNATURE_RECORD            0x05054b50
#define ZIP_END_OF_DIRECTORY_RECORD             0x06054b50
#define ZIP64_END_OF_DIRECTORY_RECORD           0x06064b50
#define ZIP64_END_OF_DIRECTORY_LOCATOR_RECORD   0x07064b50
#define ZIP_DATA_DESCRIPTOR_RECORD              0x08074b50

static const value_string zip_record_vals[] = {
    { ZIP_DIRECTORY_RECORD, "Central Directory"},
    { ZIP_FILE_RECORD, "File"},
    { ZIP_DIGITAL_SIGNATURE_RECORD, "Digital Signature"},
    { ZIP_END_OF_DIRECTORY_RECORD, "End of Central Directory"},
    { ZIP64_END_OF_DIRECTORY_RECORD, "Zip64 End of Central Directory"},
    { ZIP64_END_OF_DIRECTORY_LOCATOR_RECORD, "Zip64 End of Central Directory Locator"},
    { ZIP_DATA_DESCRIPTOR_RECORD, "Data Descriptor"},
    { 0, NULL}
};

#define ZIP_FLAG_ENCRYPTION         0x01
#define ZIP_FLAG_LZMA_OPTS          0x02
#define ZIP_FLAG_DEFLATE_OPTS       0x06
#define ZIP_FLAG_DATA_DESCRIPTOR    0x08
#define ZIP_FLAG_PATCHED_DATA       0x20
#define ZIP_FLAG_STRONG_ENCRYPTION  0x40
#define ZIP_FLAG_LANGUAGE_ENCODING  0x0800
#define ZIP_FLAG_CENTRAL_DIR_CRYPT  0x2000

static const value_string zip_host_vals[] = {
    { 0, "MS-DOS and OS/2 (FAT/VFAT/FAT32)" },
    { 1, "Amiga" },
    { 2, "OpenVMS" },
    { 3, "UNIX" },
    { 4, "VM/CMS" },
    { 5, "Atari ST", },
    { 6, "OS/2 HPFS" },
    { 7, "Macintosh" },
    { 8, "Z-System" },
    { 9, "CP/M" },
    {10, "Windows NTFS" },
    {11, "MVS (OS/390 - Z/OS)" },
    {12, "VSE" },
    {13, "Acorn Risc" },
    {14, "VFAT" },
    {15, "Alternate MVS" },
    {16, "BeOS" },
    {17, "Tandem" },
    {18, "OS/400" },
    {19, "OS X (Darwin)" },
    { 0, NULL }
};

static const value_string zip_deflate_opts_vals[] = {
    { 0, "Normal (-en)"} ,
    { 1, "Maximum (-exx/-ex)"} ,
    { 2, "Fast (-ef)"} ,
    { 3, "Super Fast (-es)"} ,
    { 0, NULL}
};

static const value_string zip_method_vals[] = {
    { 0, "Store (no compression)" },
    { 1, "Shrink" },
    { 2, "Reduce (compression factor 1}" },
    { 3, "Reduce (compression factor 2}" },
    { 4, "Reduce (compression factor 3}" },
    { 5, "Reduce (compression factor 4}" },
    { 6, "Implode" },
    { 7, "Tokenize (reserved)" },
    { 8, "Deflate" },
    { 9, "Enhanced Deflating using Deflate64(tm)" },
    {10, "PKWARE Data Compression Library Imploding (old IBM TERSE)" },
    {11, "Reserved by PKWARE" },
    {12, "BZIP2" },
    {13, "Reserved by PKWARE" },
    {14, "LZMA" },
    {15, "Reserved by PKWARE" },
    {16, "IBM z/OS CMPSC" },
    {17, "Reserved by PKWARE" },
    {18, "IBM TERSE (new)" },
    {19, "IBM LZ77 z Architecture" },
    {20, "Deprecated (use 93 for zstd)" },
    {93, "Zstandard (zstd)" },
    {94, "MP3" },
    {95, "XZ" },
    {96, "JPEG variant" },
    {97, "WavPack" },
    {98, "PPMd version I, Rev 1" },
    {99, "AE-x encryption marker" },
    { 0, NULL }
};

#define ZIP_EXTRA_ZIP64 0x0001
#define ZIP_EXTRA_UT    0x5455
#define ZIP_EXTRA_UCOM  0x6375
#define ZIP_EXTRA_UPATH 0x7075
#define ZIP_EXTRA_UNIX2 0x7855
#define ZIP_EXTRA_UNIX3 0x7875

static const value_string zip_extra_id_vals[] = {
    { ZIP_EXTRA_ZIP64, "Zip64"},
    { ZIP_EXTRA_UT,    "Unix Time"},
    { ZIP_EXTRA_UCOM,  "UTF-8 Comment"},
    { ZIP_EXTRA_UPATH, "UTF-8 Path"},
    { ZIP_EXTRA_UNIX2, "Unix (type 2)"},
    { ZIP_EXTRA_UNIX3, "Unix (type 3)"},
    { 0, NULL }
};

static void
decode_zip_version(char *s, uint16_t value)
{
    snprintf(s, ITEM_LABEL_LENGTH, "%u.%u", value / 10, value % 10);
}

static int* const *
zip_get_flags_fields(uint16_t method) {
    static int* const generic_fields[] = { &hf_zip_flag_encryption,
                                         &hf_zip_flag_data_descriptor,
                                         &hf_zip_flag_patched_data,
                                         &hf_zip_flag_strong_encryption,
                                         &hf_zip_flag_language_encoding,
                                         &hf_zip_flag_central_dir_encryption,
                                         NULL };

    static int* const deflate_fields[] = { &hf_zip_flag_encryption,
                                         &hf_zip_flag_deflate_opts,
                                         &hf_zip_flag_data_descriptor,
                                         &hf_zip_flag_patched_data,
                                         &hf_zip_flag_strong_encryption,
                                         &hf_zip_flag_language_encoding,
                                         &hf_zip_flag_central_dir_encryption,
                                         NULL };

    static int* const lzma_fields[] = { &hf_zip_flag_encryption,
                                         &hf_zip_flag_lzma_eos,
                                         &hf_zip_flag_data_descriptor,
                                         &hf_zip_flag_patched_data,
                                         &hf_zip_flag_strong_encryption,
                                         &hf_zip_flag_language_encoding,
                                         &hf_zip_flag_central_dir_encryption,
                                         NULL };
    switch (method) {
    case 8:
    case 9:
        return deflate_fields;
    case 14:
        return lzma_fields;
    default:
        return generic_fields;
    }
}

static int* const made_by_fields[] = { &hf_zip_version_made_by,
                                       &hf_zip_host_made_by,
                                       NULL };

typedef struct _zip_eo_t {
    const char *filename;
    tvbuff_t *payload;
} zip_eo_t;

static tap_packet_status
zip_eo_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *data, tap_flags_t flags _U_)
{
        export_object_list_t *object_list = (export_object_list_t *)tapdata;
        const zip_eo_t *eo_info = (const zip_eo_t *)data;
        export_object_entry_t *entry;

        if(eo_info) { /* We have data waiting for us */
                /* These values will be freed when the Export Object window
                 * is closed. */
                entry = g_new0(export_object_entry_t, 1);

                entry->pkt_num = pinfo->num;

                /* We could try to preserve the directory structure (the
                 * E.O. code percent encodes various directory structures)
                 * and expect the user to clean it up, rather than flattening
                 * the directory structure. */
                entry->filename = eo_info->filename ? g_path_get_basename(eo_info->filename) : NULL;
                entry->payload_len = tvb_captured_length(eo_info->payload);
                entry->payload_data = (uint8_t *)tvb_memdup(NULL, eo_info->payload, 0, entry->payload_len);

                object_list->add_entry(object_list->gui_data, entry);

                return TAP_PACKET_REDRAW; /* State changed - window should be redrawn */
        } else {
                return TAP_PACKET_DONT_REDRAW; /* State unchanged - no window updates needed */
        }
}

typedef struct _zip_info_t {
    tvbuff_t *filename_tvb;
    tvbuff_t *comment_tvb;
    const uint8_t *filename;
    uint64_t uncompressed_size;
    uint64_t compressed_size;
    uint64_t local_header_offset;
    uint32_t disk_start_number;
    bool central_directory;
} zip_info_t;

static int
dissect_zip_extra_zip64(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
    zip_info_t *extra_info = (zip_info_t*)data;

    unsigned offset = 0;
    if (extra_info->uncompressed_size == UINT32_MAX) {
        proto_tree_add_item(tree, hf_zip_file_uncompressed_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
    }
    if (extra_info->compressed_size == UINT32_MAX) {
        proto_tree_add_item_ret_uint64(tree, hf_zip_file_compressed_size, tvb, offset, 8, ENC_LITTLE_ENDIAN, &extra_info->compressed_size);
        offset += 8;
    }
    if (extra_info->local_header_offset == UINT32_MAX) {
        proto_tree_add_item(tree, hf_zip_local_header_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
    }
    if (extra_info->disk_start_number == UINT16_MAX) {
        proto_tree_add_item(tree, hf_zip_disk_start_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    return offset;
}

static int
dissect_zip_extra_utf8_comment(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
    _U_ zip_info_t *extra_info = (zip_info_t*)data;

    unsigned offset = 0;
    uint8_t version;

    proto_tree_add_item_ret_uint8(tree, hf_zip_extra_version, tvb, offset, 1, ENC_NA, &version);
    offset += 1;
    if (version != 1) {
        return offset;
    }

    uint32_t computed_crc32 = crc32_ccitt_tvb(extra_info->comment_tvb, tvb_reported_length(extra_info->comment_tvb));
    proto_tree_add_checksum(tree, tvb, offset, hf_zip_crc32, hf_zip_crc32_status, &ei_zip_crc32, pinfo, computed_crc32, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
    offset += 4;
    proto_tree_add_item(tree, hf_zip_file_comment, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_UTF_8);

    return offset;
}

static int
dissect_zip_extra_utf8_path(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
    zip_info_t *extra_info = (zip_info_t*)data;

    unsigned offset = 0;
    uint32_t crc32;
    uint8_t version;

    proto_tree_add_item_ret_uint8(tree, hf_zip_extra_version, tvb, offset, 1, ENC_NA, &version);
    offset += 1;
    if (version != 1) {
        return offset;
    }

    uint32_t computed_crc32 = crc32_ccitt_tvb(extra_info->filename_tvb, tvb_reported_length(extra_info->filename_tvb));
    proto_tree_add_checksum(tree, tvb, offset, hf_zip_crc32, hf_zip_crc32_status, &ei_zip_crc32, pinfo, computed_crc32, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
    crc32 = tvb_get_letohl(tvb, offset);
    offset += 4;
    if (crc32 != computed_crc32) {
        proto_tree_add_item(tree, hf_zip_file_name, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_UTF_8);
    } else {
        proto_tree_add_item_ret_string(tree, hf_zip_file_name, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_UTF_8, pinfo->pool, &extra_info->filename);
    }

    return offset;
}

static int
dissect_zip_extra_unix_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
    static int* const ut_flags_fields[] = { &hf_zip_extra_ut_flag_mtime,
                                            &hf_zip_extra_ut_flag_atime,
                                            &hf_zip_extra_ut_flag_ctime,
                                            NULL };

    uint64_t flags;
    zip_info_t *extra_info = (zip_info_t*)data;

    unsigned offset = 0;
    proto_tree_add_bitmask_ret_uint64(tree, tvb, offset, hf_zip_extra_ut_flags, ett_zip_extra_ut_flags, ut_flags_fields, ENC_NA, &flags);
    if (extra_info->central_directory) {
        flags &= 0x1;
    }
    offset += 1;
    if (flags & 1) {
        proto_tree_add_item(tree, hf_zip_extra_ut_mtime, tvb, offset, 4, ENC_TIME_SECS|ENC_LITTLE_ENDIAN);
        offset += 4;
    }
    if (flags & 2) {
        proto_tree_add_item(tree, hf_zip_extra_ut_atime, tvb, offset, 4, ENC_TIME_SECS|ENC_LITTLE_ENDIAN);
        offset += 4;
    }
    if (flags & 4) {
        proto_tree_add_item(tree, hf_zip_extra_ut_ctime, tvb, offset, 4, ENC_TIME_SECS|ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    return offset;
}

static int
dissect_zip_extra_unix2(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
    zip_info_t *extra_info = (zip_info_t*)data;
    unsigned offset = 0;

    if (extra_info->central_directory) {
        return offset;
    }

    proto_tree_add_item(tree, hf_zip_extra_unix_uid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_zip_extra_unix_gid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

static int
dissect_zip_extra_unix3(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    unsigned offset = 0;
    uint8_t version, size;

    proto_tree_add_item_ret_uint8(tree, hf_zip_extra_version, tvb, offset, 1, ENC_NA, &version);
    offset += 1;
    if (version != 1) {
        return offset;
    }
    proto_tree_add_item_ret_uint8(tree, hf_zip_extra_unix_uid_size, tvb, offset, 1, ENC_NA, &size);
    offset += 1;
    proto_tree_add_item(tree, hf_zip_extra_unix_uid, tvb, offset, size, ENC_LITTLE_ENDIAN);
    offset += size;
    proto_tree_add_item_ret_uint8(tree, hf_zip_extra_unix_gid_size, tvb, offset, 1, ENC_NA, &size);
    offset += 1;
    proto_tree_add_item(tree, hf_zip_extra_unix_gid, tvb, offset, size, ENC_LITTLE_ENDIAN);
    offset += size;

    return offset;
}

static void
dissect_zip_extra_fields(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, zip_info_t *extra_info)
{
    proto_tree *extras_tree, *extra_tree;
    proto_item *ti, *extra_ti;

    tvbuff_t *next_tvb;
    unsigned offset = 0;
    uint16_t id, size;

    ti = proto_tree_add_item(tree, hf_zip_extra_fields, tvb, offset, tvb_reported_length(tvb), ENC_NA);
    extras_tree = proto_item_add_subtree(ti, ett_zip_extras);

    while (tvb_reported_length_remaining(tvb, offset)) {
        extra_ti = proto_tree_add_item(extras_tree, hf_zip_extra_field, tvb, offset, 4, ENC_NA);
        extra_tree = proto_item_add_subtree(extra_ti, ett_zip_extra);
        proto_tree_add_item_ret_uint16(extra_tree, hf_zip_extra_id, tvb, offset, 2, ENC_LITTLE_ENDIAN, &id);
        proto_item_append_text(extra_ti, ": %s", val_to_str_const(id, zip_extra_id_vals, "Unknown"));
        offset += 2;
        proto_tree_add_item_ret_uint16(extra_tree, hf_zip_extra_data_size, tvb, offset, 2, ENC_LITTLE_ENDIAN, &size);
        offset += 2;
        if (size) {
            next_tvb = tvb_new_subset_length(tvb, offset, size);
            if (!dissector_try_uint_with_data(zip_extra_dissector_table, id, next_tvb, pinfo, extra_tree, false, extra_info)) {
                proto_tree_add_item(extra_tree, hf_zip_extra_data, tvb, offset, size, ENC_NA);
            }
            offset += size;
        }
        proto_item_set_end(extra_ti, tvb, offset);
    }
}

static int
dissect_zip_file(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_tree *record_tree;
    proto_item *ti, *crc_ti, *crc_status_ti, *size_ti, *flags_ti;

    uint64_t flags;
    uint32_t crc32;
    uint16_t file_name_length, extra_fields_length;
    uint16_t method;
    unsigned offset = 0;
    int encoding;
    bool encrypted = false;
    zip_info_t extra_info = {0};

    ti = proto_tree_add_item(tree, hf_zip_file, tvb, offset, 50, ENC_NA);
    record_tree = proto_item_add_subtree(ti, ett_zip_record);

    proto_tree_add_item(record_tree, hf_zip_record_signature, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(record_tree, hf_zip_version_to_extract, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    /* The meaning of the flags depends on the compression method. */
    method = tvb_get_letohs(tvb, offset + 2);
    int* const *flags_fields = zip_get_flags_fields(method);
    flags_ti = proto_tree_add_bitmask_ret_uint64(record_tree, tvb, offset, hf_zip_flags, ett_zip_flags, flags_fields, ENC_LITTLE_ENDIAN, &flags);
    if (flags & ZIP_FLAG_LANGUAGE_ENCODING) {
        encoding = ENC_UTF_8;
    } else {
        /* According to the specification, if this bit is not set, the encoding
         * shall be ENC_CP437. In practice, it's more like the SSID element in
         * 802.11, viz., if the bit is absent the filename and comment are
         * opaque byte strings and the encoding is whatever was used by
         * the tool that made the archive. In such case, some tools will
         * include appropriate extra fields that are UTF-8 translations of
         * the filename and comment, at least if they contain octets which
         * are not in the ASCII/ISO/IEC 646 invariant set. So we could have
         * a pref here for default encoding. */
        encoding = ENC_CP437;
    }
    offset += 2;
    proto_tree_add_item(record_tree, hf_zip_compression_method, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    offset = dissect_smb_datetime(tvb, record_tree, offset, hf_zip_last_mod_file_date_time, hf_zip_last_mod_file_date, hf_zip_last_mod_file_time, true);
    crc_ti = proto_tree_add_item_ret_uint(record_tree, hf_zip_crc32, tvb, offset, 4, ENC_LITTLE_ENDIAN, &crc32);
    offset += 4;
    size_ti = proto_tree_add_item_ret_uint64(record_tree, hf_zip_file_compressed_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &extra_info.compressed_size);
    offset += 4;
    proto_tree_add_item_ret_uint64(record_tree, hf_zip_file_uncompressed_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &extra_info.uncompressed_size);
    offset += 4;
    proto_tree_add_item_ret_uint16(record_tree, hf_zip_file_name_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &file_name_length);
    offset += 2;
    proto_tree_add_item_ret_uint16(record_tree, hf_zip_extra_fields_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &extra_fields_length);
    offset += 2;
    proto_tree_add_item_ret_string(record_tree, hf_zip_file_name, tvb, offset, file_name_length, encoding, pinfo->pool, &extra_info.filename);
    extra_info.filename_tvb = tvb_new_subset_length(tvb, offset, file_name_length);
    offset += file_name_length;
    if (extra_fields_length) {
        dissect_zip_extra_fields(tvb_new_subset_length(tvb, offset, extra_fields_length), pinfo, record_tree, &extra_info);
        offset += extra_fields_length;
    }
    proto_item_append_text(ti, ": %s", extra_info.filename);
    /* The Zip64 extra info has the real size if the compressed size is
     * UINT32_MAX. For various reasons to do with streaming or writing to
     * pipes, it's possible that the Zip64 header is used but the size is
     * not larger than UINT32_MAX, so we check. */
    if (extra_info.compressed_size > UINT32_MAX) {
        expert_add_info_format(pinfo, size_ti, &ei_zip_overflow, "Compressed size unsupported (%" PRIu64 " bytes is too large)", extra_info.compressed_size);
        return tvb_reported_length(tvb);
    }
    if (flags & ZIP_FLAG_DATA_DESCRIPTOR) {
        /* Right now we don't handle the data descriptor. The standard way
         * many programs handle them is to read the central directory
         * listing first. If the file is not encrypted, and it's compressed
         * with deflate, then we could just throw everything that's left
         * in the tvb at zlib, and if that returned a success (Z_END_STREAM)
         * check how many total bytes were consumed. We'll need a version
         * of tvb_child_uncompress_zlib that returns how many bytes were
         * consumed (and possibly the return value, to distinguish between
         * end of stream and unexpected end) to do that.
         */
        expert_add_info_format(pinfo, flags_ti, &ei_zip_unsupported, "%s", "Data descriptors are not supported yet");
        return offset;
    }
    if (flags & ZIP_FLAG_ENCRYPTION) {
        if (!(flags & ZIP_FLAG_STRONG_ENCRYPTION)) {
            proto_tree_add_item(record_tree, hf_zip_encryption_header, tvb, offset, 12, ENC_NA);
            offset += 12;
            if (ckd_sub(&extra_info.compressed_size, extra_info.compressed_size, 12)) {
                expert_add_info_format(pinfo, size_ti, &ei_zip_underflow, "Compressed size is too small to include the indicated encryption header");
                return offset;
            }
        }
        proto_tree_add_item(record_tree, hf_zip_encrypted_file_data, tvb, offset, (uint32_t)extra_info.compressed_size, ENC_NA);
        encrypted = true;
    }

    tvbuff_t *decompr_tvb = NULL;
    if (!encrypted) {
        switch (method) {
        case 0:
            decompr_tvb = tvb_new_subset_length(tvb, offset, (uint32_t)extra_info.compressed_size);
            break;
        case 8:
            proto_tree_add_item(record_tree, hf_zip_compressed_file_data, tvb, offset, (uint32_t)extra_info.compressed_size, ENC_NA);
            if (flags & ZIP_FLAG_DATA_DESCRIPTOR) {
                decompr_tvb = tvb_child_uncompress_zlib(tvb, tvb, offset, tvb_captured_length_remaining(tvb, offset));
            } else {
                decompr_tvb = tvb_child_uncompress_zlib(tvb, tvb, offset, (uint32_t)extra_info.compressed_size);
            }
            break;
        }
    }
    /* We reconstruct what proto_tree_add_checksum does down here because the
     * checksum comes much earlier, and also the check is after the DOS date
     * and time in the tree, and the SMB function to compute that doesn't
     * return the proto_item, so it's harder to use proto_tree_move_item. */
    if (decompr_tvb) {
        add_new_data_source(pinfo, decompr_tvb, "Decompressed file");
        proto_tree_add_item(record_tree, hf_zip_file_data, decompr_tvb, 0, tvb_reported_length(decompr_tvb), ENC_NA);
        uint32_t computed_crc32 = crc32_ccitt_tvb(decompr_tvb, tvb_reported_length(decompr_tvb));
        if (crc32 == computed_crc32) {
            proto_item_append_text(crc_ti, " [correct]");
            crc_status_ti = proto_tree_add_uint(record_tree, hf_zip_crc32_status, tvb, 0, 0, PROTO_CHECKSUM_E_GOOD);
        } else {
            proto_item_append_text(crc_ti, " incorrect, should be 0x%08x", computed_crc32);
            crc_status_ti = proto_tree_add_uint(record_tree, hf_zip_crc32_status, tvb, 0, 0, PROTO_CHECKSUM_E_BAD);
            expert_add_info_format(pinfo, crc_ti, &ei_zip_crc32, "%s [should be 0x%08x]", expert_get_summary(&ei_zip_crc32), computed_crc32);
        }
        /* We could wait to actually tap until the central directory listing,
         * e.g. if we wanted to use the file comment if present as the
         * Export Objects "hostname" field. */
        if (have_tap_listener(zip_eo_tap)) {
            zip_eo_t *eo_info = wmem_new0(pinfo->pool, zip_eo_t);
            eo_info->filename = (const char*)extra_info.filename;
            eo_info->payload = decompr_tvb;

            tap_queue_packet(zip_eo_tap, pinfo, eo_info);
        }
        /* Theoretically we could send the decompressed file data to all the
         * media type heuristic dissectors, but that's how you get ZIP bombs. */
    } else {
        proto_item_append_text(crc_ti, " [unverified]");
        crc_status_ti = proto_tree_add_uint(record_tree, hf_zip_crc32_status, tvb, 0, 0, PROTO_CHECKSUM_E_UNVERIFIED);
    }
    proto_tree_move_item(record_tree, crc_ti, crc_status_ti);
    proto_item_set_generated(crc_status_ti);

    if (ckd_add(&offset, offset, extra_info.compressed_size)) {
        offset = tvb_reported_length(tvb);
    }
    proto_item_set_end(ti, tvb, offset);

#if 0
    // TODO
    if (flags & ZIP_FLAG_DATA_DESCRIPTOR) {

    }
#endif

    return offset;
}

static int
dissect_zip_directory(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *record_tree;

    uint64_t flags;
    uint16_t file_name_length, extra_fields_length, file_comment_length;
    unsigned offset = 0;
    int encoding;
    zip_info_t extra_info = {.central_directory = true};

    ti = proto_tree_add_item(tree, hf_zip_directory, tvb, offset, 50, ENC_NA);
    record_tree = proto_item_add_subtree(ti, ett_zip_record);

    proto_tree_add_item(record_tree, hf_zip_record_signature, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_bitmask(record_tree, tvb, offset, hf_zip_made_by, ett_zip_made_by, made_by_fields, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(record_tree, hf_zip_version_to_extract, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    int* const *flags_fields = zip_get_flags_fields(tvb_get_letohs(tvb, offset + 2));
    proto_tree_add_bitmask_ret_uint64(record_tree, tvb, offset, hf_zip_flags, ett_zip_flags, flags_fields, ENC_LITTLE_ENDIAN, &flags);
    if (flags & ZIP_FLAG_LANGUAGE_ENCODING) {
        encoding = ENC_UTF_8;
    } else {
        encoding = ENC_CP437;
    }
    offset += 2;
    proto_tree_add_item(record_tree, hf_zip_compression_method, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    offset = dissect_smb_datetime(tvb, record_tree, offset, hf_zip_last_mod_file_date_time, hf_zip_last_mod_file_date, hf_zip_last_mod_file_time, true);
    proto_tree_add_item(record_tree, hf_zip_crc32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint64(record_tree, hf_zip_file_compressed_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &extra_info.compressed_size);
    offset += 4;
    proto_tree_add_item_ret_uint64(record_tree, hf_zip_file_uncompressed_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &extra_info.uncompressed_size);
    offset += 4;
    proto_tree_add_item_ret_uint16(record_tree, hf_zip_file_name_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &file_name_length);
    offset += 2;
    proto_tree_add_item_ret_uint16(record_tree, hf_zip_extra_fields_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &extra_fields_length);
    offset += 2;
    proto_tree_add_item_ret_uint16(record_tree, hf_zip_file_comment_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &file_comment_length);
    offset += 2;
    proto_tree_add_item_ret_uint(record_tree, hf_zip_disk_start_number, tvb, offset, 2, ENC_LITTLE_ENDIAN, &extra_info.disk_start_number);
    offset += 2;
    proto_tree_add_item(record_tree, hf_zip_internal_file_attr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(record_tree, hf_zip_external_file_attr, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_uint64(record_tree, hf_zip_local_header_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &extra_info.local_header_offset);
    offset += 4;
    proto_tree_add_item_ret_string(record_tree, hf_zip_file_name, tvb, offset, file_name_length, encoding, pinfo->pool, &extra_info.filename);
    extra_info.filename_tvb = tvb_new_subset_length(tvb, offset, file_name_length);
    offset += file_name_length;
    if (extra_fields_length) {
        dissect_zip_extra_fields(tvb_new_subset_length(tvb, offset, extra_fields_length), pinfo, record_tree, &extra_info);
        offset += extra_fields_length;
    }
    proto_item_append_text(ti, ": %s", extra_info.filename);
    if (file_comment_length) {
        proto_tree_add_item(record_tree, hf_zip_file_comment, tvb, offset, file_comment_length, encoding);
        offset += file_comment_length;
    }

    proto_item_set_end(ti, tvb, offset);

    return offset;
}

static int
dissect_zip_end_of_directory(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *record_tree;

    unsigned offset = 0, comment_length;

    ti = proto_tree_add_item(tree, hf_zip_end_of_directory, tvb, offset, 50, ENC_NA);
    record_tree = proto_item_add_subtree(ti, ett_zip_record);

    proto_tree_add_item(record_tree, hf_zip_record_signature, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(record_tree, hf_zip_disk_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(record_tree, hf_zip_directory_disk_start_number, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(record_tree, hf_zip_directory_entries_disk, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(record_tree, hf_zip_directory_entries, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(record_tree, hf_zip_directory_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(record_tree, hf_zip_directory_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item_ret_length(record_tree, hf_zip_archive_comment, tvb, offset, 2, ENC_LITTLE_ENDIAN|ENC_CP437, &comment_length);
    offset += comment_length;
    proto_item_set_end(ti, tvb, offset);

    return offset;
}

static int
dissect_zip64_end_of_directory(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *ti, *size_ti;
    proto_tree *record_tree;

    unsigned offset = 0, end_offset;
    uint64_t size;

    ti = proto_tree_add_item(tree, hf_zip64_end_of_directory, tvb, offset, 50, ENC_NA);
    record_tree = proto_item_add_subtree(ti, ett_zip_record);

    proto_tree_add_item(record_tree, hf_zip_record_signature, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    size_ti = proto_tree_add_item_ret_uint64(record_tree, hf_zip_directory_end_size, tvb, offset, 8, ENC_LITTLE_ENDIAN, &size);
    offset += 8;
    if (ckd_add(&end_offset, offset, size)) {
        expert_add_info(pinfo, size_ti, &ei_zip_overflow);
        return tvb_reported_length(tvb);
    }
    proto_tree_add_bitmask(record_tree, tvb, offset, hf_zip_made_by, ett_zip_made_by, made_by_fields, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(record_tree, hf_zip_version_to_extract, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(record_tree, hf_zip_disk_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(record_tree, hf_zip_directory_disk_start_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(record_tree, hf_zip_directory_entries_disk, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(record_tree, hf_zip_directory_entries, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(record_tree, hf_zip_directory_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(record_tree, hf_zip_directory_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    if (offset < end_offset) {
        proto_tree_add_item(record_tree, hf_zip_extensible_data_sector, tvb, offset, end_offset - offset, ENC_NA);
        offset = end_offset;
    }
    proto_item_set_end(ti, tvb, offset);

    return offset;
}

static int
dissect_zip64_end_of_directory_locator(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *record_tree;

    unsigned offset = 0;

    ti = proto_tree_add_item(tree, hf_zip64_end_of_directory_locator, tvb, offset, 20, ENC_NA);
    record_tree = proto_item_add_subtree(ti, ett_zip_record);

    proto_tree_add_item(record_tree, hf_zip_record_signature, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(record_tree, hf_zip_zip64_directory_end_disk_start_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(record_tree, hf_zip_zip64_directory_end_offset, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_tree_add_item(record_tree, hf_zip_total_disks, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    return offset;
}

static int
dissect_zip(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_) {
    unsigned offset = 0;
    proto_tree *zip_tree;
    proto_item *ti;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ZIP_FILE");
    ti = proto_tree_add_item(tree, proto_zip, tvb, offset, -1, ENC_NA);
    zip_tree = proto_item_add_subtree(ti, ett_zip);

    int dissected;
    while (tvb_find_uint16_remaining(tvb, offset, ZIP_MAGIC_UINT, &offset) &&
           tvb_reported_length_remaining(tvb, offset) >= 4) {
        uint32_t signature = tvb_get_letohl(tvb, offset);
        tvbuff_t *next_tvb = tvb_new_subset_remaining(tvb, offset);
        if (!(dissected = dissector_try_uint_with_data(zip_record_dissector_table, signature, next_tvb, pinfo, zip_tree, false, data))) {
            proto_tree_add_item(zip_tree, hf_zip_record_signature, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        }
        offset += dissected;
    }

    return tvb_reported_length(tvb);
}

void
proto_register_zip(void)
{
    static hf_register_info hf[] = {
        { &hf_zip_file,
            { "Local File", "zipfile.file",
            FT_NONE, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_directory,
            { "Central Directory", "zipfile.directory",
            FT_NONE, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_end_of_directory,
            { "End of Central Directory", "zipfile.directory.end",
            FT_NONE, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip64_end_of_directory,
            { "Zip64 End of Central Directory", "zipfile.directory.end.zip64",
            FT_NONE, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip64_end_of_directory_locator,
            { "Zip64 End of Central Directory Locator", "zipfile.directory.end.zip64.locator",
            FT_NONE, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_record_signature,
            { "Signature", "zipfile.signature",
            FT_UINT32, BASE_HEX, VALS(zip_record_vals),
            0x0, NULL, HFILL }
        },
        { &hf_zip_made_by,
            { "Made By", "zipfile.made_by",
            FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_version_made_by,
            { "Version", "zipfile.made_by.version",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_zip_version),
            0x00FF, "Supposedly the ZIP specification version supported by the creating software, but often the software's own version", HFILL }
        },
        { &hf_zip_host_made_by,
            { "Host System", "zipfile.made_by.host",
            FT_UINT16, BASE_DEC, VALS(zip_host_vals),
            0xFF00, "Indicates compatibility of external file attributes", HFILL }
        },
        { &hf_zip_version_to_extract,
            { "Version to Extract", "zipfile.version_to_extract",
            FT_UINT16, BASE_CUSTOM, CF_FUNC(decode_zip_version),
            0x0, "Minimum supported ZIP specification version needed to extract", HFILL }
        },
        { &hf_zip_flags,
            { "Flags", "zipfile.flags",
            FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_flag_encryption,
            { "Encryption", "zipfile.flag.encryption",
            FT_BOOLEAN, 16, TFS(&tfs_used_notused),
            ZIP_FLAG_ENCRYPTION, NULL, HFILL }
        },
        { &hf_zip_flag_lzma_eos,
            { "LZMA EOS marker", "zipfile.flag.lzma.eos",
            FT_BOOLEAN, 16, TFS(&tfs_present_absent),
            ZIP_FLAG_LZMA_OPTS, NULL, HFILL }
        },
        { &hf_zip_flag_deflate_opts,
            { "DEFLATE options", "zipfile.flag.deflate_opts",
            FT_UINT16, BASE_HEX, VALS(zip_deflate_opts_vals),
            ZIP_FLAG_DEFLATE_OPTS, NULL, HFILL }
        },
        { &hf_zip_flag_data_descriptor,
            { "Data Descriptor", "zipfile.flag.data_descriptor",
            FT_BOOLEAN, 16, TFS(&tfs_present_absent),
            ZIP_FLAG_DATA_DESCRIPTOR,
            "Seeking was not possible when producing file; CRC-32 and sizes are zero in header", HFILL }
        },
        { &hf_zip_flag_patched_data,
            { "Patched Data", "zipfile.flag.patched_data",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset),
            ZIP_FLAG_PATCHED_DATA, NULL, HFILL }
        },
        { &hf_zip_flag_strong_encryption,
            { "Strong Encryption", "zipfile.flag.encrypted.strong",
            FT_BOOLEAN, 16, TFS(&tfs_used_notused),
            ZIP_FLAG_STRONG_ENCRYPTION, NULL, HFILL }
        },
        { &hf_zip_flag_language_encoding,
            { "UTF-8", "zipfile.flag.language_encoding",
            FT_BOOLEAN, 16, TFS(&tfs_used_notused),
            ZIP_FLAG_LANGUAGE_ENCODING,
            "Filename and comment fields for this file are in UTF-8", HFILL }
        },
        { &hf_zip_flag_central_dir_encryption,
            { "Central Directory Encryption", "zipfile.flag.encrypted.central_directory",
            FT_BOOLEAN, 16, TFS(&tfs_used_notused),
            ZIP_FLAG_CENTRAL_DIR_CRYPT, NULL, HFILL }
        },
        { &hf_zip_compression_method,
            { "Compression Method", "zipfile.file.compression_method",
            FT_UINT16, BASE_DEC, VALS(zip_method_vals),
            0x0, NULL, HFILL }
        },
        { &hf_zip_last_mod_file_date_time,
            { "Last Mod File Date and Time", "zipfile.file.last_mod_file_date_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_last_mod_file_time,
            { "Last Mod File Time", "zipfile.file.last_mod_file_time",
            FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_last_mod_file_date,
            { "Last Mod File Date", "zipfile.file.last_mod_file_date",
            FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_crc32,
            { "CRC", "zipfile.file.crc32",
            FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_crc32_status,
            { "CRC Status", "zipfile.file.crc32.status",
            FT_UINT8, BASE_NONE, VALS(proto_checksum_vals),
            0x0, NULL, HFILL }
        },
        { &hf_zip_file_compressed_size,
            { "File Compressed Size", "zipfile.file.size",
            FT_UINT64, BASE_DEC|BASE_UNIT_STRING, UNS(&units_byte_bytes),
            0x0, NULL, HFILL }
        },
        { &hf_zip_file_uncompressed_size,
            { "File Uncompressed Size", "zipfile.file.size.uncompressed",
            FT_UINT64, BASE_DEC|BASE_UNIT_STRING, UNS(&units_byte_bytes),
            0x0, NULL, HFILL }
        },
        { &hf_zip_file_name_length,
            { "File Name Length", "zipfile.file.name.length",
            FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_extra_fields_length,
            { "Extra Fields Length", "zipfile.extras.length",
            FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_extra_fields,
            { "Extra Fields", "zipfile.extras",
            FT_NONE, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_extra_field,
            { "Extra Field", "zipfile.extra",
            FT_NONE, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_extra_id,
            { "ID", "zipfile.extra.id",
            FT_UINT16, BASE_HEX, VALS(zip_extra_id_vals),
            0x0, NULL, HFILL }
        },
        { &hf_zip_extra_data_size,
            { "Data Size", "zipfile.extra.data.size",
            FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_extra_data,
            { "Data", "zipfile.extra.data",
            FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_extra_version,
            { "Version", "zipfile.extra.version",
            FT_UINT8, BASE_DEC, NULL,
            0x0, NULL, HFILL },
        },

        { &hf_zip_extra_ut_flags,
            { "Flags", "zipfile.extra.ut.flags",
            FT_UINT8, BASE_HEX, NULL,
            0x0, NULL, HFILL },
        },
        { &hf_zip_extra_ut_flag_mtime,
            { "Modification Time", "zipfile.extra.ut.flag.mtime",
            FT_BOOLEAN, 8, TFS(&tfs_present_absent),
            0x1, NULL, HFILL },
        },
        { &hf_zip_extra_ut_flag_atime,
            { "Access Time", "zipfile.extra.ut.flag.atime",
            FT_BOOLEAN, 8, TFS(&tfs_present_absent),
            0x2, NULL, HFILL },
        },
        { &hf_zip_extra_ut_flag_ctime,
            { "Creation Time", "zipfile.extra.ut.flag.ctime",
            FT_BOOLEAN, 8, TFS(&tfs_present_absent),
            0x4, NULL, HFILL },
        },
        { &hf_zip_extra_ut_mtime,
            { "Modification Time", "zipfile.extra.ut.mtime",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x0, NULL, HFILL },
        },
        { &hf_zip_extra_ut_atime,
            { "Access Time", "zipfile.extra.ut.atime",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x0, NULL, HFILL },
        },
        { &hf_zip_extra_ut_ctime,
            { "Creation Time", "zipfile.extra.ut.ctime",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
            0x0, NULL, HFILL },
        },
        { &hf_zip_extra_unix_uid_size,
            { "User ID size", "zipfile.extra.unix.uid_size",
            FT_UINT8, BASE_DEC|BASE_UNIT_STRING, UNS(&units_byte_bytes),
            0x0, NULL, HFILL },
        },
        { &hf_zip_extra_unix_uid,
            { "User ID", "zipfile.extra.unix.uid",
            FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL },
        },
        { &hf_zip_extra_unix_gid_size,
            { "Group ID size", "zipfile.extra.unix.gid_size",
            FT_UINT8, BASE_DEC|BASE_UNIT_STRING, UNS(&units_byte_bytes),
            0x0, NULL, HFILL },
        },
        { &hf_zip_extra_unix_gid,
            { "Group ID", "zipfile.extra.unix.gid",
            FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL },
        },

        { &hf_zip_file_comment_length,
            { "File Comment Length", "zipfile.file.file_comment.length",
            FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_disk_start_number,
            { "Disk Number Start", "zipfile.file.disk_start_number",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_internal_file_attr,
            { "Internal File Attributes", "zipfile.file.internal_file_attr",
            FT_UINT16, BASE_HEX, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_external_file_attr,
            { "External File Attributes", "zipfile.file.external_file_attr",
            FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_local_header_offset,
            { "Local Header Offset", "zipfile.file.local_header_offset",
            FT_UINT64, BASE_DEC_HEX, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_file_name,
            { "File Name", "zipfile.file.name",
            FT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_file_comment,
            { "File Comment", "zipfile.file.comment",
            FT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_encryption_header,
            { "Encryption Header", "zipfile.file.encryption_header",
            FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_encrypted_file_data,
            { "Encrypted File Data", "zipfile.file.data.encrypted",
            FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_compressed_file_data,
            { "Compressed File Data", "zipfile.file.data.compressed",
            FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_file_data,
            { "File Data", "zipfile.file.data",
            FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_disk_number,
            { "Disk Number", "zipfile.directory.disk_number",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_directory_disk_start_number,
            { "Start of Central Directory Disk Number", "zipfile.directory.disk_start_number",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_directory_entries_disk,
            { "Total Number of Entries on This Disk", "zipfile.directory.disk_entries",
            FT_UINT64, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_directory_entries,
            { "Total Number of Entries", "zipfile.directory.entries",
            FT_UINT64, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_directory_size,
            { "Central Directory Size", "zipfile.directory.size",
            FT_UINT64, BASE_DEC|BASE_UNIT_STRING, UNS(&units_byte_bytes),
            0x0, NULL, HFILL }
        },
        { &hf_zip_directory_offset,
            { "Central Directory Offset", "zipfile.directory.offset",
            FT_UINT64, BASE_DEC|BASE_UNIT_STRING, UNS(&units_byte_bytes),
            0x0, "Offset with respect to starting disk/file for spanned/split archives", HFILL }
        },
        { &hf_zip_directory_end_size,
            { "Zip64 End of Central Directory Size", "zipfile.zip64.directory.end.size",
            FT_UINT64, BASE_DEC|BASE_UNIT_STRING, UNS(&units_byte_bytes),
            0x0, NULL, HFILL }
        },
        { &hf_zip_archive_comment,
            { "ZIP Archive Comment", "zipfile.archive_comment",
            FT_UINT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_extensible_data_sector,
            { "Extensible Data Sector", "zipfile.zip64.directory.end.extensible_data_sector",
            FT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_zip64_directory_end_disk_start_number,
            { "Start of Zip64 End of Central Directory Disk Number", "zipfile.zip64.directory.end.disk_start_number",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
        { &hf_zip_zip64_directory_end_offset,
            { "Zip64 End of Central Directory Offset", "zipfile.zip64.directory.end.offset",
            FT_UINT64, BASE_DEC|BASE_UNIT_STRING, UNS(&units_byte_bytes),
            0x0, "Offset with respect to starting disk/file for spanned/split archives", HFILL }
        },
        { &hf_zip_total_disks,
            { "Total Number of Disks", "zipfile.total_disks",
            FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_zip,
        &ett_zip_record,
        &ett_zip_made_by,
        &ett_zip_flags,
        &ett_zip_extras,
        &ett_zip_extra,
        &ett_zip_extra_ut_flags,
    };

    proto_zip = proto_register_protocol("ZIP File Format", "ZIP_FILE", "zipfile");

    zip_handle = register_dissector("zipfile", dissect_zip, proto_zip);
    proto_register_field_array(proto_zip, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    static ei_register_info ei[] = {
        { &ei_zip_crc32, { "zipfile.file.crc32.bad", PI_CHECKSUM, PI_WARN, "Bad CRC32", EXPFILL }},
        { &ei_zip_unsupported, { "zipfile.unsupported", PI_UNDECODED, PI_WARN, "Unsupported feature", EXPFILL }},
        { &ei_zip_overflow, { "zipfile.overflow", PI_UNDECODED, PI_WARN, "Too large values are unsupported", EXPFILL }},
        { &ei_zip_underflow, { "zipfile.underflow", PI_MALFORMED, PI_ERROR, "Too small value is bogus", EXPFILL }},
    };

    expert_module_t *expert_zip = expert_register_protocol(proto_zip);
    expert_register_field_array(expert_zip, ei, array_length(ei));

    zip_record_dissector_table = register_dissector_table("zip.record",
        "ZIP Record", proto_zip, FT_UINT32, BASE_HEX);
    zip_extra_dissector_table = register_dissector_table("zip.extra",
        "ZIP Extra Field", proto_zip, FT_UINT16, BASE_HEX);

    zip_eo_tap = register_export_object(proto_zip, zip_eo_packet, NULL);
}

static bool
dissect_zip_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    // Reject if we don't have enough room for the heuristics
    if (tvb_captured_length(tvb) < 4) {
        return false;
    }

    // For heuristics, we're not going to try to handle self-extracting
    // archives with executable code at the beginning (or anything else
    // at the start); let some other Fileshark dissector take those.
    switch (tvb_get_letohl(tvb, 0)) {
    case ZIP_FILE_RECORD:
    case ZIP_END_OF_DIRECTORY_RECORD: // Degenerate empty case
        break;
    default:
        return false;
    }

    return dissect_zip(tvb, pinfo, tree, data) > 0;
}

void
proto_reg_handoff_zip(void)
{
    dissector_add_uint("zip.record", ZIP_FILE_RECORD, create_dissector_handle(dissect_zip_file, proto_zip));
    dissector_add_uint("zip.record", ZIP_DIRECTORY_RECORD, create_dissector_handle(dissect_zip_directory, proto_zip));
    dissector_add_uint("zip.record", ZIP_END_OF_DIRECTORY_RECORD, create_dissector_handle(dissect_zip_end_of_directory, proto_zip));
    dissector_add_uint("zip.record", ZIP64_END_OF_DIRECTORY_RECORD, create_dissector_handle(dissect_zip64_end_of_directory, proto_zip));
    dissector_add_uint("zip.record", ZIP64_END_OF_DIRECTORY_LOCATOR_RECORD, create_dissector_handle(dissect_zip64_end_of_directory_locator, proto_zip));

    dissector_add_uint("zip.extra", ZIP_EXTRA_ZIP64, create_dissector_handle(dissect_zip_extra_zip64, proto_zip));
    dissector_add_uint("zip.extra", ZIP_EXTRA_UT, create_dissector_handle(dissect_zip_extra_unix_time, proto_zip));
    dissector_add_uint("zip.extra", ZIP_EXTRA_UCOM, create_dissector_handle(dissect_zip_extra_utf8_comment, proto_zip));
    dissector_add_uint("zip.extra", ZIP_EXTRA_UPATH, create_dissector_handle(dissect_zip_extra_utf8_path, proto_zip));
    dissector_add_uint("zip.extra", ZIP_EXTRA_UT, create_dissector_handle(dissect_zip_extra_unix_time, proto_zip));
    dissector_add_uint("zip.extra", ZIP_EXTRA_UNIX2, create_dissector_handle(dissect_zip_extra_unix2, proto_zip));
    dissector_add_uint("zip.extra", ZIP_EXTRA_UNIX3, create_dissector_handle(dissect_zip_extra_unix3, proto_zip));

    // Register some media types to handle in a generic way
    dissector_add_string("media_type", "application/zip", zip_handle);
    dissector_add_string("media_type", "application/java-archive", zip_handle); // Unofficial types abound

    dissector_add_string("media_type.suffix", "zip", zip_handle);

    // Register the ZIP heuristic dissector
    heur_dissector_add("wtap_file", dissect_zip_heur, "ZIP file", "zip_wtap", proto_zip, HEURISTIC_ENABLE);
}
