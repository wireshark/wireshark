/* nettrace_3gpp_32_423.c
 *
 * Decoder for 3GPP TS 32.423 file format for the Wiretap library.
 * The main purpose is to have Wireshark decode raw message content (<rawMsg> tag).
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Ref: http://www.3gpp.org/DynaReport/32423.htm
 */

#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "wtap-int.h"
#include "file_wrappers.h"
#include "pcap-encap.h"

#include <wsutil/buffer.h>
#include "wsutil/tempfile.h"
#include "wsutil/os_version_info.h"
#include "wsutil/ws_version_info.h"
#include "wsutil/str_util.h"


#include "pcapng.h"
#include "nettrace_3gpp_32_423.h"

/*
* Impose a not-too-large limit on the maximum file size, to avoid eating
* up 99% of the (address space, swap partition, disk space for swap/page
* files); if we were to return smaller chunks and let the dissector do
* reassembly, it would *still* have to allocate a buffer the size of
* the file, so it's not as if we'd never try to allocate a buffer the
* size of the file. Laeve space for the exported PDU tag 12 bytes.
*/
#define MAX_FILE_SIZE	(G_MAXINT-12)

static const guint8 xml_magic[] = { '<', '?', 'x', 'm', 'l' };
static const guint8 Threegpp_doc_no[] = { '3', '2', '.', '4', '2', '3' };

typedef struct nettrace_3gpp_32_423_file_info {
	char *tmpname;
	wtap *wth_tmp_file;
} nettrace_3gpp_32_423_file_info_t;


static gboolean
nettrace_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
	struct Buffer               *frame_buffer_saved;
	gboolean result;

	nettrace_3gpp_32_423_file_info_t *file_info = (nettrace_3gpp_32_423_file_info_t *)wth->priv;

	frame_buffer_saved = file_info->wth_tmp_file->frame_buffer;
	file_info->wth_tmp_file->frame_buffer = wth->frame_buffer;
	/* we read the created pcapng file instead */
	result =  wtap_read(file_info->wth_tmp_file, err, err_info, data_offset);
	file_info->wth_tmp_file->frame_buffer = frame_buffer_saved;
	if (!result)
		return result;
	wth->phdr.rec_type = file_info->wth_tmp_file->phdr.rec_type;
	wth->phdr.presence_flags = file_info->wth_tmp_file->phdr.presence_flags;
	wth->phdr.ts = file_info->wth_tmp_file->phdr.ts;
	wth->phdr.caplen = file_info->wth_tmp_file->phdr.caplen;
	wth->phdr.len = file_info->wth_tmp_file->phdr.len;
	wth->phdr.pkt_encap = file_info->wth_tmp_file->phdr.pkt_encap;
	wth->phdr.pkt_tsprec = file_info->wth_tmp_file->phdr.pkt_tsprec;
	wth->phdr.interface_id = file_info->wth_tmp_file->phdr.interface_id;
	wth->phdr.opt_comment = file_info->wth_tmp_file->phdr.opt_comment;
	wth->phdr.drop_count = file_info->wth_tmp_file->phdr.drop_count;
	wth->phdr.pack_flags = file_info->wth_tmp_file->phdr.pack_flags;
	wth->phdr.ft_specific_data = file_info->wth_tmp_file->phdr.ft_specific_data;

	return result;
}

static gboolean
nettrace_seek_read(wtap *wth, gint64 seek_off, struct wtap_pkthdr *phdr, Buffer *buf, int *err, gchar **err_info)
{
	struct Buffer               *frame_buffer_saved;
	gboolean result;
	nettrace_3gpp_32_423_file_info_t *file_info = (nettrace_3gpp_32_423_file_info_t *)wth->priv;

	frame_buffer_saved = file_info->wth_tmp_file->frame_buffer;
	file_info->wth_tmp_file->frame_buffer = wth->frame_buffer;

	result = wtap_seek_read(file_info->wth_tmp_file, seek_off, phdr, buf, err, err_info);
	file_info->wth_tmp_file->frame_buffer = frame_buffer_saved;

	return result;
}

/* classic wtap: close capture file */
static void
nettrace_close(wtap *wth)
{
	nettrace_3gpp_32_423_file_info_t *file_info = (nettrace_3gpp_32_423_file_info_t *)wth->priv;

	wtap_close(file_info->wth_tmp_file);

	/*Clear the shb info, it's been freed by wtap_close*/
	wth->shb_hdr.opt_comment = NULL;
	wth->shb_hdr.shb_hardware = NULL;
	wth->shb_hdr.shb_os = NULL;
	wth->shb_hdr.shb_user_appl = NULL;

	/* delete the temp file */
	ws_unlink(file_info->tmpname);

}

/* Parsing something like
 * <rawMsg
 *   protocol="Diameter"
 *   version="1">
 *    [truncated]010001244000012C01000...
 * </rawMsg>
 */
static wtap_open_return_val
write_packet_data(wtap_dumper *wdh, struct wtap_pkthdr *phdr, int *err, gchar **err_info, guint8 *file_buf)
{
	char *curr_pos, *next_pos;
	char proto_name_str[16];
	int tag_str_len = 0;
	int proto_str_len, raw_data_len, pkt_data_len,  exp_pdu_tags_len, i, j;
	guint8 *packet_buf;
	gchar chr;
	gint val1, val2;

	memset(proto_name_str, 0, sizeof(proto_name_str));
	/* Extract the protocol name */
	curr_pos = strstr(file_buf, "protocol=\"");
	if (!curr_pos){
		return WTAP_OPEN_ERROR;
	}
	curr_pos = curr_pos + 10;
	next_pos = strstr(curr_pos, "\"");
	proto_str_len = (int)(next_pos - curr_pos);
	if (proto_str_len > 15){
		return WTAP_OPEN_ERROR;
	}

	g_strlcpy(proto_name_str, curr_pos, proto_str_len+1);
	ascii_strdown_inplace(proto_name_str);

	/* Do string matching and replace with Wiresharks protocol name */
	if (strcmp(proto_name_str, "gtpv2-c") == 0){
		/* Change to gtpv2 */
		proto_name_str[5] = '\0';
		proto_name_str[6] = '\0';
		proto_str_len = 5;
	}
	/* XXX Do we need to check for function="S1" */
	if (strcmp(proto_name_str, "nas") == 0){
		/* Change to nas-eps_plain */
		g_strlcpy(proto_name_str, "nas-eps_plain", 14);
		proto_name_str[13] = '\0';
		proto_str_len = 13;
	}
	/* Find the start of the raw data*/
	curr_pos = strstr(next_pos, ">") + 1;
	next_pos = strstr(next_pos, "<");

	raw_data_len = (int)(next_pos - curr_pos);

	/* Calculate the space needed for exp pdu tags*/
	tag_str_len = (proto_str_len + 3) & 0xfffffffc;
	exp_pdu_tags_len = tag_str_len + 4;


	/* Allocate the packet buf */
	pkt_data_len = raw_data_len / 2;
	packet_buf = (guint8 *)g_malloc0(pkt_data_len + exp_pdu_tags_len +4);

	/* Fill packet buff */
	packet_buf[0] = 0;
	packet_buf[1] = 12; /* EXP_PDU_TAG_PROTO_NAME */
	packet_buf[2] = 0;
	packet_buf[3] = tag_str_len;
	for (i = 4, j = 0; j < tag_str_len; i++, j++){
		packet_buf[i] = proto_name_str[j];
	}

	/* Add end of options */
	packet_buf[i] = 0;
	i++;
	packet_buf[i] = 0;
	i++;
	packet_buf[i] = 0;
	i++;
	packet_buf[i] = 0;
	i++;
	exp_pdu_tags_len = exp_pdu_tags_len + 4;

	/* Convert the hex raw msg data to binary and write to the packet buf*/
	for (; i < (pkt_data_len + exp_pdu_tags_len); i++){
		chr = *curr_pos;
		val1 = g_ascii_xdigit_value(chr);
		curr_pos++;
		chr = *curr_pos;
		val2 = g_ascii_xdigit_value(chr);
		if ((val1 != -1) && (val2 != -1)){
			packet_buf[i] = ((guint8)val1 * 16) + val2;
		}
		else{
			/* Something wrong, bail out */
			g_free(packet_buf);
			return WTAP_OPEN_ERROR;
		}
		curr_pos++;
	}
	/* Construct the phdr */
	memset(phdr, 0, sizeof(struct wtap_pkthdr));
	phdr->rec_type = REC_TYPE_PACKET;
	phdr->presence_flags = 0; /* yes, we have no bananas^Wtime stamp */

	phdr->caplen = pkt_data_len + exp_pdu_tags_len;
	phdr->len = pkt_data_len + exp_pdu_tags_len;

	phdr->ts.secs = 0;
	phdr->ts.nsecs = 0;

	if (!wtap_dump(wdh, phdr, packet_buf, err, err_info)) {
		switch (*err) {

		case WTAP_ERR_UNWRITABLE_REC_DATA:
			g_free(err_info);
			break;

		default:
			break;
		}
		g_free(packet_buf);
		return WTAP_OPEN_ERROR;
	}

	g_free(packet_buf);
	return WTAP_OPEN_MINE;
}

/*
 * Opens an .xml file with Trace data formated according to 3GPP TS 32.423 and converts it to
 * an "Exported PDU type file with the entire xml file as the first "packet" appending the
 * raw messages as subsequent packages to be dissected by wireshark.
 */
static wtap_open_return_val
create_temp_pcapng_file(wtap *wth, int *err, gchar **err_info, nettrace_3gpp_32_423_file_info_t *file_info)
{
	int import_file_fd;
	wtap_dumper* wdh_exp_pdu;
	int   exp_pdu_file_err;
	wtap_open_return_val result = WTAP_OPEN_MINE;

	/* pcapng defs */
	wtapng_section_t            *shb_hdr = NULL;
	wtapng_iface_descriptions_t *idb_inf = NULL;
	wtapng_if_descr_t            int_data;
	GString                     *os_info_str;
	gint64 file_size;
	int packet_size;
	guint8 *packet_buf = NULL;
	int wrt_err;
	gchar *wrt_err_info = NULL;
	struct wtap_pkthdr phdr;

	gboolean do_random = FALSE;
	char *curr_pos, *next_pos;

	import_file_fd = create_tempfile(&(file_info->tmpname), "Wireshark_PDU_");

	/* Now open a file and dump to it */
	/* Create data for SHB  */
	os_info_str = g_string_new("");
	get_os_version_info(os_info_str);

	shb_hdr = g_new(wtapng_section_t, 1);
	shb_hdr->section_length = -1;
	/* options */
	shb_hdr->opt_comment = g_strdup_printf("File converted to Exported PDU format during opening");
	/*
	* UTF-8 string containing the description of the hardware used to create
	* this section.
	*/
	shb_hdr->shb_hardware = NULL;
	/*
	* UTF-8 string containing the name of the operating system used to create
	* this section.
	*/
	shb_hdr->shb_os = g_string_free(os_info_str, FALSE);
	/*
	* UTF-8 string containing the name of the application used to create
	* this section.
	*/
	shb_hdr->shb_user_appl = g_strdup_printf("Wireshark %s", get_ws_vcs_version_info());

	/* Create fake IDB info */
	idb_inf = g_new(wtapng_iface_descriptions_t, 1);
	idb_inf->interface_data = g_array_new(FALSE, FALSE, sizeof(wtapng_if_descr_t));

	/* create the fake interface data */
	int_data.wtap_encap = WTAP_ENCAP_WIRESHARK_UPPER_PDU;
	int_data.time_units_per_second = 1000000; /* default microsecond resolution */
	int_data.link_type = wtap_wtap_encap_to_pcap_encap(WTAP_ENCAP_WIRESHARK_UPPER_PDU);
	int_data.snap_len = WTAP_MAX_PACKET_SIZE;
	int_data.if_name = g_strdup("Fake IF");
	int_data.opt_comment = NULL;
	int_data.if_description = NULL;
	int_data.if_speed = 0;
	int_data.if_tsresol = 6;
	int_data.if_filter_str = NULL;
	int_data.bpf_filter_len = 0;
	int_data.if_filter_bpf_bytes = NULL;
	int_data.if_os = NULL;
	int_data.if_fcslen = -1;
	int_data.num_stat_entries = 0;          /* Number of ISB:s */
	int_data.interface_statistics = NULL;

	g_array_append_val(idb_inf->interface_data, int_data);

	wdh_exp_pdu = wtap_dump_fdopen_ng(import_file_fd, WTAP_FILE_TYPE_SUBTYPE_PCAPNG, WTAP_ENCAP_WIRESHARK_UPPER_PDU,
					  WTAP_MAX_PACKET_SIZE, FALSE, shb_hdr, idb_inf, NULL, &exp_pdu_file_err);
	if (wdh_exp_pdu == NULL) {
		result = WTAP_OPEN_ERROR;
		goto end;
	}

	/* OK we've opend a new pcap-ng file and written the headers, time to do the packets, strt by finding the file size */

	if ((file_size = wtap_file_size(wth, err)) == -1) {
		result = WTAP_OPEN_ERROR;
		goto end;
	}

	if (file_size > MAX_FILE_SIZE) {
		/*
		* Don't blow up trying to allocate space for an
		* immensely-large file.
		*/
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("mime_file: File has %" G_GINT64_MODIFIER "d-byte packet, bigger than maximum of %u",
			file_size, MAX_FILE_SIZE);
		result = WTAP_OPEN_ERROR;
		goto end;
	}
	packet_size = (int)file_size;
	/* Allocate the packet buffer
	* (the whole file + Exported PDU tag "protocol" and
	* the string "xml" + 1 filler to end on 4 byte boundary for the tag
	* + End of options 4 bytes
	*/
	/* XXX add the length of exported bdu tag(s) here */
	packet_buf = (guint8 *)g_malloc(packet_size + 12);

	packet_buf[0] = 0;
	packet_buf[1] = 12; /* EXP_PDU_TAG_PROTO_NAME */
	packet_buf[2] = 0;
	packet_buf[3] = 4;
	packet_buf[4] = 0x78; /* "x" */
	packet_buf[5] = 0x6d; /* "m" */
	packet_buf[6] = 0x6c; /* "l" */
	packet_buf[7] = 0;
	/* End of options */
	packet_buf[8] = 0;
	packet_buf[9] = 0;
	packet_buf[10] = 0;
	packet_buf[11] = 0;


	if (!wtap_read_bytes(wth->fh, packet_buf + 12, packet_size, &wrt_err, &wrt_err_info)){
		result = WTAP_OPEN_ERROR;
		goto end;
	}

	/* Create the packet header */
	memset(&phdr, 0, sizeof(struct wtap_pkthdr));
	phdr.rec_type = REC_TYPE_PACKET;
	phdr.presence_flags = 0; /* yes, we have no bananas^Wtime stamp */

	phdr.caplen = packet_size + 12;
	phdr.len = packet_size + 12;

	phdr.ts.secs = 0;
	phdr.ts.nsecs = 0;

	/* XXX: report errors! */
	if (!wtap_dump(wdh_exp_pdu, &phdr, packet_buf, &wrt_err, &wrt_err_info)) {
		switch (wrt_err) {

		case WTAP_ERR_UNWRITABLE_REC_DATA:
			g_free(wrt_err_info);
			wrt_err_info = NULL;
			break;

		default:
			break;
		}
		result = WTAP_OPEN_ERROR;
		goto end;
	}

	/* Advance *packet_buf to point at the raw file data */
	curr_pos = packet_buf + 12;
	/* Lets add the raw messages as packets after the main "packet" with the whole file */
	while ((curr_pos = strstr(curr_pos, "<msg")) != NULL){
		wtap_open_return_val temp_val;

		curr_pos = curr_pos + 4;
		next_pos = strstr(curr_pos, "</msg>");
		if (!next_pos){
			/* Somethings wrong, bail out */
			break;
		}
		next_pos = next_pos + 6;
		/* Do we have a raw msg?) */
		curr_pos = strstr(curr_pos, "<rawMsg");
		if (!curr_pos){
			/* No rawMsg, continue */
			curr_pos = next_pos;
			continue;
		}
		curr_pos = curr_pos + 7;
		/* Add the raw msg*/
		temp_val = write_packet_data(wdh_exp_pdu, &phdr, &wrt_err, &wrt_err_info, curr_pos);
		if (temp_val != WTAP_OPEN_MINE){
			result = temp_val;
			goto end;
		}
		curr_pos = next_pos;
	}

	/* Close the written file*/
	if (!wtap_dump_close(wdh_exp_pdu, err)){
		result = WTAP_OPEN_ERROR;
		goto end;
	}

	/* Now open the file for reading */

	/* Find out if random read was requested */
	if (wth->random_fh){
		do_random = TRUE;
	}
	file_info->wth_tmp_file =
		wtap_open_offline(file_info->tmpname, WTAP_TYPE_AUTO, err, err_info, do_random);

	if (!file_info->wth_tmp_file){
		result = WTAP_OPEN_ERROR;
		goto end;
	}

end:
	g_free(wrt_err_info);
	g_free(packet_buf);
	wtap_free_shb(shb_hdr);
	wtap_free_idb_info(idb_inf);

	return result;
}

wtap_open_return_val
nettrace_3gpp_32_423_file_open(wtap *wth, int *err, gchar **err_info)
{
	char magic_buf[512]; /* increase buffer size when needed */
	int bytes_read;
	char *curr_pos;
	nettrace_3gpp_32_423_file_info_t *file_info;
	wtap_open_return_val temp_val;


	bytes_read = file_read(magic_buf, 512, wth->fh);

	if (bytes_read < 0) {
		*err = file_error(wth->fh, err_info);
		return WTAP_OPEN_ERROR;
	}
	if (bytes_read == 0){
		return WTAP_OPEN_NOT_MINE;
	}

	if (memcmp(magic_buf, xml_magic, sizeof(xml_magic)) != 0){
		return WTAP_OPEN_NOT_MINE;
	}
	/* File header should contain something like fileFormatVersion="32.423 V8.1.0" */
	curr_pos = strstr(magic_buf, "fileFormatVersion");

	if (!curr_pos){
		return WTAP_OPEN_NOT_MINE;
	}
	curr_pos += 19;
	if (memcmp(curr_pos, Threegpp_doc_no, sizeof(Threegpp_doc_no)) != 0){
		return WTAP_OPEN_NOT_MINE;
	}

	if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
		return WTAP_OPEN_ERROR;

	/* Ok it's our file, open a temp file and do the conversion */
	file_info = g_new0(nettrace_3gpp_32_423_file_info_t, 1);
	temp_val = create_temp_pcapng_file(wth, err, err_info, file_info);

	if (temp_val != WTAP_OPEN_MINE){
		return temp_val;
	}

	if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
		return WTAP_OPEN_ERROR;

	/* Copy data from the temp file wth */
	wth->shb_hdr.opt_comment = file_info->wth_tmp_file->shb_hdr.opt_comment;
	wth->shb_hdr.shb_hardware = file_info->wth_tmp_file->shb_hdr.shb_hardware;
	wth->shb_hdr.shb_os = file_info->wth_tmp_file->shb_hdr.shb_os;
	wth->shb_hdr.shb_user_appl = file_info->wth_tmp_file->shb_hdr.shb_user_appl;

	wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_NETTRACE_3GPP_32_423;
	wth->file_encap = file_info->wth_tmp_file->file_encap;
	wth->file_tsprec = file_info->wth_tmp_file->file_tsprec;
	wth->subtype_read = nettrace_read;
	wth->subtype_seek_read = nettrace_seek_read;
	wth->subtype_close = nettrace_close;
	wth->snapshot_length = 0;

	wth->priv = (void*)file_info;

	return WTAP_OPEN_MINE;

}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
