/* packetlogger.c
 * Routines for opening Apple's (Bluetooth) PacketLogger file format captures
 * Copyright 2008-2009, Stephen Fisher (see AUTHORS file)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Based on commview.c, Linux's BlueZ-Gnome Analyzer program and hexdumps of
 * the output files from Apple's PacketLogger tool.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "packetlogger.h"

#include <stdlib.h>
#include <string.h>

#include "wtap-int.h"
#include "file_wrappers.h"

typedef struct {
	bool byte_swapped;
} packetlogger_t;

typedef struct packetlogger_header {
	uint32_t len;
	uint32_t ts_secs;
	uint32_t ts_usecs;
} packetlogger_header_t;

/* Packet types. */
#define PKT_HCI_COMMAND     0x00
#define PKT_HCI_EVENT       0x01
#define PKT_SENT_ACL_DATA   0x02
#define PKT_RECV_ACL_DATA   0x03
#define PKT_SENT_SCO_DATA   0x08
#define PKT_RECV_SCO_DATA   0x09
#define PKT_LMP_SEND        0x0A
#define PKT_LMP_RECV        0x0B
#define PKT_SYSLOG          0xF7
#define PKT_KERNEL          0xF8
#define PKT_KERNEL_DEBUG    0xF9
#define PKT_ERROR           0xFA
#define PKT_POWER           0xFB
#define PKT_NOTE            0xFC
#define PKT_CONFIG          0xFD
#define PKT_NEW_CONTROLLER  0xFE

static bool packetlogger_read(wtap *wth, wtap_rec *rec, Buffer *buf,
				  int *err, char **err_info,
				  int64_t *data_offset);
static bool packetlogger_seek_read(wtap *wth, int64_t seek_off,
				       wtap_rec *rec,
				       Buffer *buf, int *err, char **err_info);
static bool packetlogger_read_header(packetlogger_header_t *pl_hdr,
					 FILE_T fh, bool byte_swapped,
					 int *err, char **err_info);
static void packetlogger_byte_swap_header(packetlogger_header_t *pl_hdr);
static wtap_open_return_val packetlogger_check_record(wtap *wth,
						      packetlogger_header_t *pl_hdr,
						      int *err,
						      char **err_info);
static bool packetlogger_read_packet(wtap *wth, FILE_T fh, wtap_rec *rec,
					 Buffer *buf, int *err,
					 char **err_info);

static int packetlogger_file_type_subtype = -1;

void register_packetlogger(void);

/*
 * Number of packets to try reading.
 */
#define PACKETS_TO_CHECK	5

wtap_open_return_val packetlogger_open(wtap *wth, int *err, char **err_info)
{
	bool byte_swapped = false;
	packetlogger_header_t pl_hdr;
	wtap_open_return_val ret;
	packetlogger_t *packetlogger;

	/*
	 * Try to read the first record.
	 */
	if(!packetlogger_read_header(&pl_hdr, wth->fh, byte_swapped,
	    err, err_info)) {
		/*
		 * Either an immediate EOF or a short read indicates
		 * that the file is probably not a PacketLogger file.
		 */
		if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
		return WTAP_OPEN_NOT_MINE;
	}

	/*
	 * If the upper 16 bits of the length are non-zero and the lower
	 * 16 bits are zero, assume the file is byte-swapped from our
	 * byte order.
	 */
	if ((pl_hdr.len & 0x0000FFFF) == 0 &&
	    (pl_hdr.len & 0xFFFF0000) != 0) {
		/*
		 * Byte-swap the header.
		 */
		packetlogger_byte_swap_header(&pl_hdr);
		byte_swapped = true;
	}

	/*
	 * Check whether the first record looks like a PacketLogger
	 * record.
	 */
	ret = packetlogger_check_record(wth, &pl_hdr, err, err_info);
	if (ret != WTAP_OPEN_MINE) {
		/*
		 * Either we got an error or it's not valid.
		 */
		if (ret == WTAP_OPEN_NOT_MINE) {
			/*
			 * Not valid, so not a PacketLogger file.
			 */
			return WTAP_OPEN_NOT_MINE;
		}

		/*
		 * Error. If it failed with a short read, we don't fail,
		 * so we treat it as a valid file and can then report
		 * it as a truncated file.
		 */
		if (*err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
	} else {
		/*
		 * Now try reading a few more packets.
		 */
		for (int i = 1; i < PACKETS_TO_CHECK; i++) {
			/*
			 * Read and check the file header; we've already
			 * decided whether this would be a byte-swapped file
			 * or not, so we swap iff we decided it was.
			 */
			if (!packetlogger_read_header(&pl_hdr, wth->fh,
			    byte_swapped, err, err_info)) {
				if (*err == 0) {
					/* EOF; no more packets to try. */
					break;
				}

				/*
				 * A short read indicates that the file
				 * is probably not a PacketLogger file.
				 */
				if (*err != WTAP_ERR_SHORT_READ)
					return WTAP_OPEN_ERROR;
				return WTAP_OPEN_NOT_MINE;
			}

			/*
			 * Check whether this record looks like a PacketLogger
			 * record.
			 */
			ret = packetlogger_check_record(wth, &pl_hdr, err,
			    err_info);
			if (ret != WTAP_OPEN_MINE) {
				/*
				 * Either we got an error or it's not valid.
				 */
				if (ret == WTAP_OPEN_NOT_MINE) {
					/*
					 * Not valid, so not a PacketLogger
					 * file.
					 */
					return WTAP_OPEN_NOT_MINE;
				}

				/*
				 * Error. If it failed with a short read,
				 * we don't fail, we just stop checking
				 * records, so we treat it as a valid file
				 * and can then report it as a truncated file.
				 */
				if (*err != WTAP_ERR_SHORT_READ)
					return WTAP_OPEN_ERROR;
				break;
			}
		}
	}

	/* No file header. Reset the fh to 0 so we can read the first packet */
	if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
		return WTAP_OPEN_ERROR;

	/* This is a PacketLogger file */
	packetlogger = g_new(packetlogger_t, 1);
	packetlogger->byte_swapped = byte_swapped;
	wth->priv = (void *)packetlogger;

	/* Set up the pointers to the handlers for this file type */
	wth->subtype_read = packetlogger_read;
	wth->subtype_seek_read = packetlogger_seek_read;

	wth->file_type_subtype = packetlogger_file_type_subtype;
	wth->file_encap = WTAP_ENCAP_PACKETLOGGER;
	wth->file_tsprec = WTAP_TSPREC_USEC;

	/*
	 * Add an IDB; we don't know how many interfaces were
	 * involved, so we just say one interface, about which
	 * we only know the link-layer type, snapshot length,
	 * and time stamp resolution.
	 */
	wtap_add_generated_idb(wth);

	return WTAP_OPEN_MINE; /* Our kind of file */
}

static bool
packetlogger_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err,
		  char **err_info, int64_t *data_offset)
{
	*data_offset = file_tell(wth->fh);

	return packetlogger_read_packet(wth, wth->fh, rec, buf, err, err_info);
}

static bool
packetlogger_seek_read(wtap *wth, int64_t seek_off, wtap_rec *rec,
		       Buffer *buf, int *err, char **err_info)
{
	if(file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return false;

	if(!packetlogger_read_packet(wth, wth->random_fh, rec, buf, err, err_info)) {
		if(*err == 0)
			*err = WTAP_ERR_SHORT_READ;

		return false;
	}
	return true;
}

static bool
packetlogger_read_header(packetlogger_header_t *pl_hdr, FILE_T fh,
			 bool byte_swapped, int *err, char **err_info)
{
	if (!wtap_read_bytes_or_eof(fh, &pl_hdr->len, 4, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &pl_hdr->ts_secs, 4, err, err_info))
		return false;
	if (!wtap_read_bytes(fh, &pl_hdr->ts_usecs, 4, err, err_info))
		return false;

	/* Convert multi-byte values to host endian */
	if (byte_swapped)
		packetlogger_byte_swap_header(pl_hdr);

	return true;
}

static void
packetlogger_byte_swap_header(packetlogger_header_t *pl_hdr)
{
	pl_hdr->len = GUINT32_SWAP_LE_BE(pl_hdr->len);
	pl_hdr->ts_secs = GUINT32_SWAP_LE_BE(pl_hdr->ts_secs);
	pl_hdr->ts_usecs = GUINT32_SWAP_LE_BE(pl_hdr->ts_usecs);
}

static wtap_open_return_val
packetlogger_check_record(wtap *wth, packetlogger_header_t *pl_hdr, int *err,
    char **err_info)
{
	uint32_t length;
	uint8_t type;

	/* Is the header length valid?  If not, assume it's not ours. */
	if (pl_hdr->len < 8 || pl_hdr->len >= 65536)
		return WTAP_OPEN_NOT_MINE;

	/* Is the microseconds field of the time stap out of range? */
	if (pl_hdr->ts_usecs >= 1000000)
		return WTAP_OPEN_NOT_MINE;

	/*
	 * If we have any payload, it's a type field; read and check it.
	 */
	length = pl_hdr->len - 8;
	if (length != 0) {
		/*
		 * Check the type field.
		 */
		if (!wtap_read_bytes(wth->fh, &type, 1, err, err_info)) {
			if (*err != WTAP_ERR_SHORT_READ)
				return WTAP_OPEN_ERROR;
			return WTAP_OPEN_NOT_MINE;
		}

		/* Verify this file belongs to us */
		switch (type) {

		case PKT_HCI_COMMAND:
		case PKT_HCI_EVENT:
		case PKT_SENT_ACL_DATA:
		case PKT_RECV_ACL_DATA:
		case PKT_SENT_SCO_DATA:
		case PKT_RECV_SCO_DATA:
		case PKT_LMP_SEND:
		case PKT_LMP_RECV:
		case PKT_SYSLOG:
		case PKT_KERNEL:
		case PKT_KERNEL_DEBUG:
		case PKT_ERROR:
		case PKT_POWER:
		case PKT_NOTE:
		case PKT_CONFIG:
		case PKT_NEW_CONTROLLER:
			break;

		default:
			return WTAP_OPEN_NOT_MINE;
		}

		length--;

		if (length != 0) {
			/*
			 * Now try to read past the rest of the packet bytes;
			 * if that fails with a short read, we don't fail,
			 * so that we can report the file as a truncated
			 * PacketLogger file.
			 */
			if (!wtap_read_bytes(wth->fh, NULL, length,
			    err, err_info))
				return WTAP_OPEN_ERROR;
		}
	}
	return WTAP_OPEN_MINE;
}

static bool
packetlogger_read_packet(wtap *wth, FILE_T fh, wtap_rec *rec, Buffer *buf,
			 int *err, char **err_info)
{
	packetlogger_t *packetlogger = (packetlogger_t *)wth->priv;
	packetlogger_header_t pl_hdr;

	if(!packetlogger_read_header(&pl_hdr, fh, packetlogger->byte_swapped,
	    err, err_info))
		return false;

	if (pl_hdr.len < 8) {
		*err = WTAP_ERR_BAD_FILE;
		*err_info = ws_strdup_printf("packetlogger: record length %u is too small", pl_hdr.len);
		return false;
	}
	if (pl_hdr.len - 8 > WTAP_MAX_PACKET_SIZE_STANDARD) {
		/*
		 * Probably a corrupt capture file; don't blow up trying
		 * to allocate space for an immensely-large packet.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = ws_strdup_printf("packetlogger: File has %u-byte packet, bigger than maximum of %u",
		    pl_hdr.len - 8, WTAP_MAX_PACKET_SIZE_STANDARD);
		return false;
	}

	rec->rec_type = REC_TYPE_PACKET;
	rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
	rec->presence_flags = WTAP_HAS_TS;

	rec->rec_header.packet_header.len = pl_hdr.len - 8;
	rec->rec_header.packet_header.caplen = pl_hdr.len - 8;

	rec->ts.secs = (time_t)pl_hdr.ts_secs;
	rec->ts.nsecs = (int)(pl_hdr.ts_usecs * 1000);

	return wtap_read_packet_bytes(fh, buf, rec->rec_header.packet_header.caplen, err, err_info);
}

static const struct supported_block_type packetlogger_blocks_supported[] = {
	/*
	 * We support packet blocks, with no comments or other options.
	 */
	{ WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info packetlogger_info = {
	"macOS PacketLogger", "pklg", "pklg", NULL,
	false, BLOCKS_SUPPORTED(packetlogger_blocks_supported),
	NULL, NULL, NULL
};

void register_packetlogger(void)
{
	packetlogger_file_type_subtype = wtap_register_file_type_subtype(&packetlogger_info);

	/*
	 * Register name for backwards compatibility with the
	 * wtap_filetypes table in Lua.
	 */
	wtap_register_backwards_compatibility_lua_name("PACKETLOGGER",
	    packetlogger_file_type_subtype);
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
