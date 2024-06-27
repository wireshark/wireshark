/* mime_file.c
 *
 * MIME file format decoder for the Wiretap library.
 *
 * This is for use with Wireshark dissectors that handle file
 * formats (e.g., because they handle a particular MIME media type).
 * It breaks the file into chunks of at most WTAP_MAX_PACKET_SIZE_STANDARD,
 * each of which is reported as a packet, so that files larger than
 * WTAP_MAX_PACKET_SIZE_STANDARD can be handled by reassembly.
 *
 * The "MIME file" dissector does the reassembly, and hands the result
 * off to heuristic dissectors to try to identify the file's contents.
 *
 * Wiretap Library
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "mime_file.h"

#include <sys/types.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "wtap-int.h"
#include "file_wrappers.h"
#include <wsutil/buffer.h>

typedef struct {
	const uint8_t *magic;
	unsigned magic_len;
} mime_files_t;

/*
 * Written by Marton Nemeth <nm127@freemail.hu>
 * Copyright 2009 Marton Nemeth
 * The JPEG specification can be found at:
 *
 * https://www.w3.org/Graphics/JPEG/itu-t81.pdf
 * https://www.itu.int/rec/T-REC-T.81/en (but you have to pay for it)
 *
 * and the JFIF specification can be found at:
 *
 * https://www.itu.int/rec/T-REC-T.871-201105-I/en
 * https://www.w3.org/Graphics/JPEG/jfif3.pdf
 */
static const uint8_t jpeg_jfif_magic[] = { 0xFF, 0xD8, /* SOF */
					  0xFF        /* start of the next marker */
					};

/* <?xml */
static const uint8_t xml_magic[]    = { '<', '?', 'x', 'm', 'l' };
static const uint8_t png_magic[]    = { 0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n' };
static const uint8_t gif87a_magic[] = { 'G', 'I', 'F', '8', '7', 'a'};
static const uint8_t gif89a_magic[] = { 'G', 'I', 'F', '8', '9', 'a'};
static const uint8_t elf_magic[]    = { 0x7F, 'E', 'L', 'F'};
static const uint8_t tiff_le_magic[]    = { 'I', 'I', 42, 0 };
static const uint8_t tiff_be_magic[]    = { 'M', 'M', 0, 42 };
static const uint8_t btsnoop_magic[]    = { 'b', 't', 's', 'n', 'o', 'o', 'p', 0};
static const uint8_t pcap_magic[]           = { 0xA1, 0xB2, 0xC3, 0xD4 };
static const uint8_t pcap_swapped_magic[]   = { 0xD4, 0xC3, 0xB2, 0xA1 };
static const uint8_t pcap_nsec_magic[]           = { 0xA1, 0xB2, 0x3C, 0x4D };
static const uint8_t pcap_nsec_swapped_magic[]   = { 0x4D, 0x3C, 0xB2, 0xA1 };
static const uint8_t pcapng_premagic[]      = { 0x0A, 0x0D, 0x0D, 0x0A };
static const uint8_t blf_magic[]                 = { 'L', 'O', 'G', 'G' };
static const uint8_t autosar_dlt_magic[]         = { 'D', 'L', 'T', 0x01 };
static const uint8_t rtpdump_magic[]         = { '#', '!', 'r', 't', 'p', 'p', 'l', 'a', 'y', '1', '.', '0', ' ' };

/* File does not start with it */
static const uint8_t pcapng_xmagic[]         = { 0x1A, 0x2B, 0x3C, 0x4D };
static const uint8_t pcapng_swapped_xmagic[] = { 0x4D, 0x3C, 0x2B, 0x1A };

static const mime_files_t magic_files[] = {
	{ jpeg_jfif_magic, sizeof(jpeg_jfif_magic) },
	{ xml_magic, sizeof(xml_magic) },
	{ png_magic, sizeof(png_magic) },
	{ gif87a_magic, sizeof(gif87a_magic) },
	{ gif89a_magic, sizeof(gif89a_magic) },
	{ elf_magic, sizeof(elf_magic) },
	{ tiff_le_magic, sizeof(tiff_le_magic) },
	{ tiff_be_magic, sizeof(tiff_be_magic) },
	{ btsnoop_magic, sizeof(btsnoop_magic) },
	{ pcap_magic, sizeof(pcap_magic) },
	{ pcap_swapped_magic, sizeof(pcap_swapped_magic) },
	{ pcap_nsec_magic, sizeof(pcap_nsec_magic) },
	{ pcap_nsec_swapped_magic, sizeof(pcap_nsec_swapped_magic) },
	{ pcapng_premagic, sizeof(pcapng_premagic) },
	{ blf_magic, sizeof(blf_magic) },
	{ autosar_dlt_magic, sizeof(autosar_dlt_magic) },
	{ rtpdump_magic, sizeof(rtpdump_magic) },
};

#define	N_MAGIC_TYPES	array_length(magic_files)

static int mime_file_type_subtype = -1;

void register_mime(void);

wtap_open_return_val
mime_file_open(wtap *wth, int *err, char **err_info)
{
	char magic_buf[128]; /* increase buffer size when needed */
	int bytes_read;
	bool found_file;
	/* unsigned file_ok; */
	unsigned i;

	unsigned read_bytes = 12;

	for (i = 0; i < N_MAGIC_TYPES; i++)
		read_bytes = MAX(read_bytes, magic_files[i].magic_len);

	read_bytes = (unsigned)MIN(read_bytes, sizeof(magic_buf));
	bytes_read = file_read(magic_buf, read_bytes, wth->fh);

	if (bytes_read < 0) {
		*err = file_error(wth->fh, err_info);
		return WTAP_OPEN_ERROR;
	}
	if (bytes_read == 0)
		return WTAP_OPEN_NOT_MINE;

	found_file = false;
	for (i = 0; i < N_MAGIC_TYPES; i++) {
		if ((unsigned) bytes_read >= magic_files[i].magic_len && !memcmp(magic_buf, magic_files[i].magic, MIN(magic_files[i].magic_len, (unsigned) bytes_read))) {
			if (!found_file) {
				if (magic_files[i].magic == pcapng_premagic) {
					if (memcmp(magic_buf + 8, pcapng_xmagic, sizeof(pcapng_xmagic)) &&
							memcmp(magic_buf + 8, pcapng_swapped_xmagic, sizeof(pcapng_swapped_xmagic)))
						continue;
				}
				found_file = true;
			} else
				return WTAP_OPEN_NOT_MINE;	/* many files matched, bad file */
		}
	}

	if (!found_file)
		return WTAP_OPEN_NOT_MINE;

	if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
		return WTAP_OPEN_ERROR;

	wth->file_type_subtype = mime_file_type_subtype;
	wth->file_encap = WTAP_ENCAP_MIME;
	wth->file_tsprec = WTAP_TSPREC_SEC;
	wth->subtype_read = wtap_full_file_read;
	wth->subtype_seek_read = wtap_full_file_seek_read;
	wth->snapshot_length = 0;

	return WTAP_OPEN_MINE;
}

static const struct supported_block_type mime_blocks_supported[] = {
	/*
	 * This is a file format that we dissect, so we provide
	 * only one "packet" with the file's contents, and don't
	 * support any options.
	 */
	{ WTAP_BLOCK_PACKET, ONE_BLOCK_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info mime_info = {
	"MIME File Format", "mime", NULL, NULL,
	false, BLOCKS_SUPPORTED(mime_blocks_supported),
	NULL, NULL, NULL
};

/*
 * XXX - registered solely for the benefit of Lua scripts that
 * look for the file type "JPEG_JFIF"; it may be removed once
 * we get rid of wtap_filetypes.
 */
static const struct supported_block_type jpeg_jfif_blocks_supported[] = {
	/*
	 * This is a file format that we dissect, so we provide
	 * only one "packet" with the file's contents, and don't
	 * support any options.
	 */
	{ WTAP_BLOCK_PACKET, ONE_BLOCK_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info jpeg_jfif_info = {
	"JPEG/JFIF", "jpeg", "jpg", "jpeg;jfif",
	false, BLOCKS_SUPPORTED(jpeg_jfif_blocks_supported),
	NULL, NULL, NULL
};

void register_mime(void)
{
	int jpeg_jfif_file_type_subtype;

	mime_file_type_subtype = wtap_register_file_type_subtype(&mime_info);

	/*
	 * Obsoleted by "mime", but we want it for the backwards-
	 * compatibility table for Lua.
	 */
	jpeg_jfif_file_type_subtype = wtap_register_file_type_subtype(&jpeg_jfif_info);

	/*
	 * Register names for backwards compatibility with the
	 * wtap_filetypes table in Lua.
	 */
	wtap_register_backwards_compatibility_lua_name("MIME",
	    mime_file_type_subtype);
	wtap_register_backwards_compatibility_lua_name("JPEG_JFIF",
	    jpeg_jfif_file_type_subtype);
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
