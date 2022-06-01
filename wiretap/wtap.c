/* wtap.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <string.h>
#include <errno.h>

#include <sys/types.h>

#include "wtap-int.h"
#include "wtap_opttypes.h"

#include "file_wrappers.h"
#include <wsutil/file_util.h>
#include <wsutil/buffer.h>
#include <wsutil/ws_assert.h>
#include <wsutil/wslog.h>
#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif

#ifdef HAVE_PLUGINS
static plugins_t *libwiretap_plugins = NULL;
#endif

static GSList *wtap_plugins = NULL;

#ifdef HAVE_PLUGINS
void
wtap_register_plugin(const wtap_plugin *plug)
{
	wtap_plugins = g_slist_prepend(wtap_plugins, (wtap_plugin *)plug);
}
#else /* HAVE_PLUGINS */
void
wtap_register_plugin(const wtap_plugin *plug _U_)
{
	ws_warning("wtap_register_plugin: built without support for binary plugins");
}
#endif /* HAVE_PLUGINS */

int
wtap_plugins_supported(void)
{
#ifdef HAVE_PLUGINS
	return g_module_supported() ? 0 : 1;
#else
	return -1;
#endif
}

static void
call_plugin_register_wtap_module(gpointer data, gpointer user_data _U_)
{
	wtap_plugin *plug = (wtap_plugin *)data;

	if (plug->register_wtap_module) {
		plug->register_wtap_module();
	}
}

/*
 * Return the size of the file, as reported by the OS.
 * (gint64, in case that's 64 bits.)
 */
gint64
wtap_file_size(wtap *wth, int *err)
{
	ws_statb64 statb;

	if (file_fstat((wth->fh == NULL) ? wth->random_fh : wth->fh,
	    &statb, err) == -1)
		return -1;
	return statb.st_size;
}

/*
 * Do an fstat on the file.
 */
int
wtap_fstat(wtap *wth, ws_statb64 *statb, int *err)
{
	if (file_fstat((wth->fh == NULL) ? wth->random_fh : wth->fh,
	    statb, err) == -1)
		return -1;
	return 0;
}

int
wtap_file_type_subtype(wtap *wth)
{
	return wth->file_type_subtype;
}

guint
wtap_snapshot_length(wtap *wth)
{
	return wth->snapshot_length;
}

int
wtap_file_encap(wtap *wth)
{
	return wth->file_encap;
}

int
wtap_file_tsprec(wtap *wth)
{
	return wth->file_tsprec;
}

guint
wtap_file_get_num_shbs(wtap *wth)
{
	return wth->shb_hdrs->len;
}

wtap_block_t
wtap_file_get_shb(wtap *wth, guint shb_num)
{
	if ((wth == NULL) || (wth->shb_hdrs == NULL) || (shb_num >= wth->shb_hdrs->len))
		return NULL;

	return g_array_index(wth->shb_hdrs, wtap_block_t, shb_num);
}

GArray*
wtap_file_get_shb_for_new_file(wtap *wth)
{
	guint shb_count;
	wtap_block_t shb_hdr_src, shb_hdr_dest;
	GArray* shb_hdrs;

	if ((wth == NULL) || (wth->shb_hdrs == NULL) || (wth->shb_hdrs->len == 0))
		return NULL;

	shb_hdrs = g_array_new(FALSE, FALSE, sizeof(wtap_block_t));

	for (shb_count = 0; shb_count < wth->shb_hdrs->len; shb_count++) {
		shb_hdr_src = g_array_index(wth->shb_hdrs, wtap_block_t, shb_count);
		shb_hdr_dest = wtap_block_make_copy(shb_hdr_src);
		g_array_append_val(shb_hdrs, shb_hdr_dest);
	}

	return shb_hdrs;
}

/*
 * XXX - replace with APIs that let us handle multiple comments.
 */
void
wtap_write_shb_comment(wtap *wth, gchar *comment)
{
	if ((wth != NULL) && (wth->shb_hdrs != NULL) && (wth->shb_hdrs->len > 0)) {
		wtap_block_set_nth_string_option_value(g_array_index(wth->shb_hdrs, wtap_block_t, 0), OPT_COMMENT, 0, comment, (gsize)(comment ? strlen(comment) : 0));
	}
}

wtapng_iface_descriptions_t *
wtap_file_get_idb_info(wtap *wth)
{
	wtapng_iface_descriptions_t *idb_info;

	idb_info = g_new(wtapng_iface_descriptions_t,1);

	idb_info->interface_data	= wth->interface_data;

	return idb_info;
}

wtap_block_t
wtap_get_next_interface_description(wtap *wth)
{
	if (wth->next_interface_data < wth->interface_data->len) {
		/*
		 * We have an IDB to return.  Advance to the next
		 * IDB, and return this one.
		 */
		wtap_block_t idb;

		idb = g_array_index(wth->interface_data, wtap_block_t,
		    wth->next_interface_data);
		wth->next_interface_data++;
		return idb;
	}

	/*
	 * We've returned all the interface descriptions we currently
	 * have.  (There may be more in the future, if we read more.)
	 */
	return NULL;
}

void
wtap_add_idb(wtap *wth, wtap_block_t idb)
{
	g_array_append_val(wth->interface_data, idb);
}

void
wtap_add_generated_idb(wtap *wth)
{
	wtap_block_t idb;
	wtapng_if_descr_mandatory_t *if_descr_mand;
	int snaplen;

	ws_assert(wth->file_encap != WTAP_ENCAP_UNKNOWN &&
	    wth->file_encap != WTAP_ENCAP_PER_PACKET);
	ws_assert(wth->file_tsprec != WTAP_TSPREC_UNKNOWN &&
	    wth->file_tsprec != WTAP_TSPREC_PER_PACKET);

	idb = wtap_block_create(WTAP_BLOCK_IF_ID_AND_INFO);

	if_descr_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(idb);
	if_descr_mand->wtap_encap = wth->file_encap;
	if_descr_mand->tsprecision = wth->file_tsprec;
	switch (wth->file_tsprec) {

	case WTAP_TSPREC_SEC:
		if_descr_mand->time_units_per_second = 1;
		wtap_block_add_uint8_option(idb, OPT_IDB_TSRESOL, 0);
		break;

	case WTAP_TSPREC_DSEC:
		if_descr_mand->time_units_per_second = 10;
		wtap_block_add_uint8_option(idb, OPT_IDB_TSRESOL, 1);
		break;

	case WTAP_TSPREC_CSEC:
		if_descr_mand->time_units_per_second = 100;
		wtap_block_add_uint8_option(idb, OPT_IDB_TSRESOL, 2);
		break;

	case WTAP_TSPREC_MSEC:
		if_descr_mand->time_units_per_second = 1000;
		wtap_block_add_uint8_option(idb, OPT_IDB_TSRESOL, 3);
		break;

	case WTAP_TSPREC_USEC:
		if_descr_mand->time_units_per_second = 1000000;
		/* This is the default, so no need to add an option */
		break;

	case WTAP_TSPREC_NSEC:
		if_descr_mand->time_units_per_second = 1000000000;
		wtap_block_add_uint8_option(idb, OPT_IDB_TSRESOL, 9);
		break;

	case WTAP_TSPREC_PER_PACKET:
	case WTAP_TSPREC_UNKNOWN:
	default:
		/*
		 * Don't do this.
		 */
		ws_assert_not_reached();
		break;
	}
	snaplen = wth->snapshot_length;
	if (snaplen == 0) {
		/*
		 * No snapshot length was specified.  Pick an
		 * appropriate snapshot length for this
		 * link-layer type.
		 *
		 * We use WTAP_MAX_PACKET_SIZE_STANDARD for everything except
		 * D-Bus, which has a maximum packet size of 128MB,
		 * and EBHSCR, which has a maximum packet size of 8MB,
		 * which is more than we want to put into files
		 * with other link-layer header types, as that
		 * might cause some software reading those files
		 * to allocate an unnecessarily huge chunk of
		 * memory for a packet buffer.
		 */
		if (wth->file_encap == WTAP_ENCAP_DBUS)
			snaplen = 128*1024*1024;
		else if (wth->file_encap == WTAP_ENCAP_EBHSCR)
			snaplen = 8*1024*1024;
		else
			snaplen = WTAP_MAX_PACKET_SIZE_STANDARD;
	}
	if_descr_mand->snap_len = snaplen;
	if_descr_mand->num_stat_entries = 0;          /* Number of ISBs */
	if_descr_mand->interface_statistics = NULL;

	/*
	 * Add this IDB.
	 */
	wtap_add_idb(wth, idb);
}

void
wtap_free_idb_info(wtapng_iface_descriptions_t *idb_info)
{
	if (idb_info == NULL)
		return;

	wtap_block_array_free(idb_info->interface_data);
	g_free(idb_info);
}

gchar *
wtap_get_debug_if_descr(const wtap_block_t if_descr,
                        const int indent,
                        const char* line_end)
{
	char* tmp_content;
	wtapng_if_descr_mandatory_t* if_descr_mand;
	GString *info = g_string_new("");
	guint64 tmp64;
	gint8 itmp8;
	guint8 tmp8;
	if_filter_opt_t if_filter;

	ws_assert(if_descr);

	if_descr_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(if_descr);
	if (wtap_block_get_string_option_value(if_descr, OPT_IDB_NAME, &tmp_content) == WTAP_OPTTYPE_SUCCESS) {
		g_string_printf(info,
				"%*cName = %s%s", indent, ' ',
				tmp_content ? tmp_content : "UNKNOWN",
				line_end);
	}

	if (wtap_block_get_string_option_value(if_descr, OPT_IDB_DESCRIPTION, &tmp_content) == WTAP_OPTTYPE_SUCCESS) {
		g_string_append_printf(info,
				"%*cDescription = %s%s", indent, ' ',
				tmp_content ? tmp_content : "NONE",
				line_end);
	}

	g_string_append_printf(info,
			"%*cEncapsulation = %s (%d - %s)%s", indent, ' ',
			wtap_encap_description(if_descr_mand->wtap_encap),
			if_descr_mand->wtap_encap,
			wtap_encap_name(if_descr_mand->wtap_encap),
			line_end);

	if (wtap_block_get_string_option_value(if_descr, OPT_IDB_HARDWARE, &tmp_content) == WTAP_OPTTYPE_SUCCESS) {
		g_string_append_printf(info,
				"%*cHardware = %s%s", indent, ' ',
				tmp_content ? tmp_content : "NONE",
				line_end);
	}

	if (wtap_block_get_uint64_option_value(if_descr, OPT_IDB_SPEED, &tmp64) == WTAP_OPTTYPE_SUCCESS) {
		g_string_append_printf(info,
				"%*cSpeed = %" PRIu64 "%s", indent, ' ',
				tmp64,
				line_end);
	}

	g_string_append_printf(info,
			"%*cCapture length = %u%s", indent, ' ',
			if_descr_mand->snap_len,
			line_end);

	if (wtap_block_get_uint8_option_value(if_descr, OPT_IDB_FCSLEN, &itmp8) == WTAP_OPTTYPE_SUCCESS) {
		g_string_append_printf(info,
				"%*cFCS length = %d%s", indent, ' ',
				itmp8,
				line_end);
	}

	g_string_append_printf(info,
			"%*cTime precision = %s (%d)%s", indent, ' ',
			wtap_tsprec_string(if_descr_mand->tsprecision),
			if_descr_mand->tsprecision,
			line_end);

	g_string_append_printf(info,
			"%*cTime ticks per second = %" PRIu64 "%s", indent, ' ',
			if_descr_mand->time_units_per_second,
			line_end);

	if (wtap_block_get_uint8_option_value(if_descr, OPT_IDB_TSRESOL, &tmp8) == WTAP_OPTTYPE_SUCCESS) {
		g_string_append_printf(info,
				"%*cTime resolution = 0x%.2x%s", indent, ' ',
				tmp8,
				line_end);
	}

	if (wtap_block_get_if_filter_option_value(if_descr, OPT_IDB_FILTER, &if_filter) == WTAP_OPTTYPE_SUCCESS) {
		switch (if_filter.type) {

		case if_filter_pcap:
			g_string_append_printf(info,
					"%*cFilter string = %s%s", indent, ' ',
					if_filter.data.filter_str,
					line_end);
			break;

		case if_filter_bpf:
			g_string_append_printf(info,
					"%*cBPF filter length = %u%s", indent, ' ',
					if_filter.data.bpf_prog.bpf_prog_len,
					line_end);
			break;

		default:
			g_string_append_printf(info,
					"%*cUnknown filter type %u%s", indent, ' ',
					if_filter.type,
					line_end);
			break;
		}
	}

	if (wtap_block_get_string_option_value(if_descr, OPT_IDB_OS, &tmp_content) == WTAP_OPTTYPE_SUCCESS) {
		g_string_append_printf(info,
				"%*cOperating system = %s%s", indent, ' ',
				tmp_content ? tmp_content : "UNKNOWN",
				line_end);
	}

	/*
	 * XXX - support multiple comments.
	 */
	if (wtap_block_get_nth_string_option_value(if_descr, OPT_COMMENT, 0, &tmp_content) == WTAP_OPTTYPE_SUCCESS) {
		g_string_append_printf(info,
				"%*cComment = %s%s", indent, ' ',
				tmp_content ? tmp_content : "NONE",
				line_end);
	}

	g_string_append_printf(info,
			"%*cNumber of stat entries = %u%s", indent, ' ',
			if_descr_mand->num_stat_entries,
			line_end);

	return g_string_free(info, FALSE);
}

wtap_block_t
wtap_file_get_nrb(wtap *wth)
{
	if ((wth == NULL) || (wth->nrb_hdrs == NULL) || (wth->nrb_hdrs->len == 0))
		return NULL;

	return g_array_index(wth->nrb_hdrs, wtap_block_t, 0);
}

GArray*
wtap_file_get_nrb_for_new_file(wtap *wth)
{
	guint nrb_count;
	wtap_block_t nrb_hdr_src, nrb_hdr_dest;
	GArray* nrb_hdrs;

	if ((wth == NULL || wth->nrb_hdrs == NULL) || (wth->nrb_hdrs->len == 0))
		return NULL;

	nrb_hdrs = g_array_new(FALSE, FALSE, sizeof(wtap_block_t));

	for (nrb_count = 0; nrb_count < wth->nrb_hdrs->len; nrb_count++) {
		nrb_hdr_src = g_array_index(wth->nrb_hdrs, wtap_block_t, nrb_count);
		nrb_hdr_dest = wtap_block_make_copy(nrb_hdr_src);
		g_array_append_val(nrb_hdrs, nrb_hdr_dest);
	}

	return nrb_hdrs;
}

void
wtap_dump_params_init(wtap_dump_params *params, wtap *wth)
{
	memset(params, 0, sizeof(*params));
	if (wth == NULL)
		return;

	params->encap = wtap_file_encap(wth);
	params->snaplen = wtap_snapshot_length(wth);
	params->tsprec = wtap_file_tsprec(wth);
	params->shb_hdrs = wtap_file_get_shb_for_new_file(wth);
	params->idb_inf = wtap_file_get_idb_info(wth);
	params->nrb_hdrs = wtap_file_get_nrb_for_new_file(wth);
	/* Assume that the input handle remains open until the dumper is closed.
	 * Refer to the DSBs from the input file, wtap_dump will then copy DSBs
	 * as they become available. */
	params->dsbs_growing = wth->dsbs;
	params->dont_copy_idbs = FALSE;
}

/*
 * XXX - eventually, we should make this wtap_dump_params_init(),
 * and have everything copy IDBs as they're read.
 */
void
wtap_dump_params_init_no_idbs(wtap_dump_params *params, wtap *wth)
{
	memset(params, 0, sizeof(*params));
	if (wth == NULL)
		return;

	params->encap = wtap_file_encap(wth);
	params->snaplen = wtap_snapshot_length(wth);
	params->tsprec = wtap_file_tsprec(wth);
	params->shb_hdrs = wtap_file_get_shb_for_new_file(wth);
	params->idb_inf = wtap_file_get_idb_info(wth);
	params->nrb_hdrs = wtap_file_get_nrb_for_new_file(wth);
	/* Assume that the input handle remains open until the dumper is closed.
	 * Refer to the DSBs from the input file, wtap_dump will then copy DSBs
	 * as they become available. */
	params->dsbs_growing = wth->dsbs;
	params->dont_copy_idbs = TRUE;
}

void
wtap_dump_params_discard_decryption_secrets(wtap_dump_params *params)
{
	params->dsbs_initial = NULL;
	params->dsbs_growing = NULL;
}

void
wtap_dump_params_cleanup(wtap_dump_params *params)
{
	wtap_block_array_free(params->shb_hdrs);
	/* params->idb_inf is currently expected to be freed by the caller. */
	wtap_block_array_free(params->nrb_hdrs);

	memset(params, 0, sizeof(*params));
}

/* Table of the encapsulation types we know about. */
struct encap_type_info {
	const char *name;
	const char *description;
};

static struct encap_type_info encap_table_base[] = {
	/* WTAP_ENCAP_UNKNOWN */
	{ "unknown", "Unknown" },

	/* WTAP_ENCAP_ETHERNET */
	{ "ether", "Ethernet" },

	/* WTAP_ENCAP_TOKEN_RING */
	{ "tr", "Token Ring" },

	/* WTAP_ENCAP_SLIP */
	{ "slip", "SLIP" },

	/* WTAP_ENCAP_PPP */
	{ "ppp", "PPP" },

	/* WTAP_ENCAP_FDDI */
	{ "fddi", "FDDI" },

	/* WTAP_ENCAP_FDDI_BITSWAPPED */
	{ "fddi-swapped", "FDDI with bit-swapped MAC addresses" },

	/* WTAP_ENCAP_RAW_IP */
	{ "rawip", "Raw IP" },

	/* WTAP_ENCAP_ARCNET */
	{ "arcnet", "ARCNET" },

	/* WTAP_ENCAP_ARCNET_LINUX */
	{ "arcnet_linux", "Linux ARCNET" },

	/* WTAP_ENCAP_ATM_RFC1483 */
	{ "atm-rfc1483", "RFC 1483 ATM" },

	/* WTAP_ENCAP_LINUX_ATM_CLIP */
	{ "linux-atm-clip", "Linux ATM CLIP" },

	/* WTAP_ENCAP_LAPB */
	{ "lapb", "LAPB" },

	/* WTAP_ENCAP_ATM_PDUS */
	{ "atm-pdus", "ATM PDUs" },

	/* WTAP_ENCAP_ATM_PDUS_UNTRUNCATED */
	{ "atm-pdus-untruncated", "ATM PDUs - untruncated" },

	/* WTAP_ENCAP_NULL */
	{ "null", "NULL/Loopback" },

	/* WTAP_ENCAP_ASCEND */
	{ "ascend", "Lucent/Ascend access equipment" },

	/* WTAP_ENCAP_ISDN */
	{ "isdn", "ISDN" },

	/* WTAP_ENCAP_IP_OVER_FC */
	{ "ip-over-fc", "RFC 2625 IP-over-Fibre Channel" },

	/* WTAP_ENCAP_PPP_WITH_PHDR */
	{ "ppp-with-direction", "PPP with Directional Info" },

	/* WTAP_ENCAP_IEEE_802_11 */
	{ "ieee-802-11", "IEEE 802.11 Wireless LAN" },

	/* WTAP_ENCAP_IEEE_802_11_PRISM */
	{ "ieee-802-11-prism", "IEEE 802.11 plus Prism II monitor mode radio header" },

	/* WTAP_ENCAP_IEEE_802_11_WITH_RADIO */
	{ "ieee-802-11-radio", "IEEE 802.11 Wireless LAN with radio information" },

	/* WTAP_ENCAP_IEEE_802_11_RADIOTAP */
	{ "ieee-802-11-radiotap", "IEEE 802.11 plus radiotap radio header" },

	/* WTAP_ENCAP_IEEE_802_11_AVS */
	{ "ieee-802-11-avs", "IEEE 802.11 plus AVS radio header" },

	/* WTAP_ENCAP_SLL */
	{ "linux-sll", "Linux cooked-mode capture v1" },

	/* WTAP_ENCAP_FRELAY */
	{ "frelay", "Frame Relay" },

	/* WTAP_ENCAP_FRELAY_WITH_PHDR */
	{ "frelay-with-direction", "Frame Relay with Directional Info" },

	/* WTAP_ENCAP_CHDLC */
	{ "chdlc", "Cisco HDLC" },

	/* WTAP_ENCAP_CISCO_IOS */
	{ "ios", "Cisco IOS internal" },

	/* WTAP_ENCAP_LOCALTALK */
	{ "ltalk", "Localtalk" },

	/* WTAP_ENCAP_OLD_PFLOG  */
	{ "pflog-old", "OpenBSD PF Firewall logs, pre-3.4" },

	/* WTAP_ENCAP_HHDLC */
	{ "hhdlc", "HiPath HDLC" },

	/* WTAP_ENCAP_DOCSIS */
	{ "docsis", "Data Over Cable Service Interface Specification" },

	/* WTAP_ENCAP_COSINE */
	{ "cosine", "CoSine L2 debug log" },

	/* WTAP_ENCAP_WFLEET_HDLC */
	{ "whdlc", "Wellfleet HDLC" },

	/* WTAP_ENCAP_SDLC */
	{ "sdlc", "SDLC" },

	/* WTAP_ENCAP_TZSP */
	{ "tzsp", "Tazmen sniffer protocol" },

	/* WTAP_ENCAP_ENC */
	{ "enc", "OpenBSD enc(4) encapsulating interface" },

	/* WTAP_ENCAP_PFLOG  */
	{ "pflog", "OpenBSD PF Firewall logs" },

	/* WTAP_ENCAP_CHDLC_WITH_PHDR */
	{ "chdlc-with-direction", "Cisco HDLC with Directional Info" },

	/* WTAP_ENCAP_BLUETOOTH_H4 */
	{ "bluetooth-h4", "Bluetooth H4" },

	/* WTAP_ENCAP_MTP2 */
	{ "mtp2", "SS7 MTP2" },

	/* WTAP_ENCAP_MTP3 */
	{ "mtp3", "SS7 MTP3" },

	/* WTAP_ENCAP_IRDA */
	{ "irda", "IrDA" },

	/* WTAP_ENCAP_USER0 */
	{ "user0", "USER 0" },

	/* WTAP_ENCAP_USER1 */
	{ "user1", "USER 1" },

	/* WTAP_ENCAP_USER2 */
	{ "user2", "USER 2" },

	/* WTAP_ENCAP_USER3 */
	{ "user3", "USER 3" },

	/* WTAP_ENCAP_USER4 */
	{ "user4", "USER 4" },

	/* WTAP_ENCAP_USER5 */
	{ "user5", "USER 5" },

	/* WTAP_ENCAP_USER6 */
	{ "user6", "USER 6" },

	/* WTAP_ENCAP_USER7 */
	{ "user7", "USER 7" },

	/* WTAP_ENCAP_USER8 */
	{ "user8", "USER 8" },

	/* WTAP_ENCAP_USER9 */
	{ "user9", "USER 9" },

	/* WTAP_ENCAP_USER10 */
	{ "user10", "USER 10" },

	/* WTAP_ENCAP_USER11 */
	{ "user11", "USER 11" },

	/* WTAP_ENCAP_USER12 */
	{ "user12", "USER 12" },

	/* WTAP_ENCAP_USER13 */
	{ "user13", "USER 13" },

	/* WTAP_ENCAP_USER14 */
	{ "user14", "USER 14" },

	/* WTAP_ENCAP_USER15 */
	{ "user15", "USER 15" },

	/* WTAP_ENCAP_SYMANTEC */
	{ "symantec", "Symantec Enterprise Firewall" },

	/* WTAP_ENCAP_APPLE_IP_OVER_IEEE1394 */
	{ "ap1394", "Apple IP-over-IEEE 1394" },

	/* WTAP_ENCAP_BACNET_MS_TP */
	{ "bacnet-ms-tp", "BACnet MS/TP" },

	/* WTAP_ENCAP_NETTL_RAW_ICMP */
	{ "raw-icmp-nettl", "Raw ICMP with nettl headers" },

	/* WTAP_ENCAP_NETTL_RAW_ICMPV6 */
	{ "raw-icmpv6-nettl", "Raw ICMPv6 with nettl headers" },

	/* WTAP_ENCAP_GPRS_LLC */
	{ "gprs-llc", "GPRS LLC" },

	/* WTAP_ENCAP_JUNIPER_ATM1 */
	{ "juniper-atm1", "Juniper ATM1" },

	/* WTAP_ENCAP_JUNIPER_ATM2 */
	{ "juniper-atm2", "Juniper ATM2" },

	/* WTAP_ENCAP_REDBACK */
	{ "redback", "Redback SmartEdge" },

	/* WTAP_ENCAP_NETTL_RAW_IP */
	{ "rawip-nettl", "Raw IP with nettl headers" },

	/* WTAP_ENCAP_NETTL_ETHERNET */
	{ "ether-nettl", "Ethernet with nettl headers" },

	/* WTAP_ENCAP_NETTL_TOKEN_RING */
	{ "tr-nettl", "Token Ring with nettl headers" },

	/* WTAP_ENCAP_NETTL_FDDI */
	{ "fddi-nettl", "FDDI with nettl headers" },

	/* WTAP_ENCAP_NETTL_UNKNOWN */
	{ "unknown-nettl", "Unknown link-layer type with nettl headers" },

	/* WTAP_ENCAP_MTP2_WITH_PHDR */
	{ "mtp2-with-phdr", "MTP2 with pseudoheader" },

	/* WTAP_ENCAP_JUNIPER_PPPOE */
	{ "juniper-pppoe", "Juniper PPPoE" },

	/* WTAP_ENCAP_GCOM_TIE1 */
	{ "gcom-tie1", "GCOM TIE1" },

	/* WTAP_ENCAP_GCOM_SERIAL */
	{ "gcom-serial", "GCOM Serial" },

	/* WTAP_ENCAP_NETTL_X25 */
	{ "x25-nettl", "X.25 with nettl headers" },

	/* WTAP_ENCAP_K12 */
	{ "k12", "K12 protocol analyzer" },

	/* WTAP_ENCAP_JUNIPER_MLPPP */
	{ "juniper-mlppp", "Juniper MLPPP" },

	/* WTAP_ENCAP_JUNIPER_MLFR */
	{ "juniper-mlfr", "Juniper MLFR" },

	/* WTAP_ENCAP_JUNIPER_ETHER */
	{ "juniper-ether", "Juniper Ethernet" },

	/* WTAP_ENCAP_JUNIPER_PPP */
	{ "juniper-ppp", "Juniper PPP" },

	/* WTAP_ENCAP_JUNIPER_FRELAY */
	{ "juniper-frelay", "Juniper Frame-Relay" },

	/* WTAP_ENCAP_JUNIPER_CHDLC */
	{ "juniper-chdlc", "Juniper C-HDLC" },

	/* WTAP_ENCAP_JUNIPER_GGSN */
	{ "juniper-ggsn", "Juniper GGSN" },

	/* WTAP_ENCAP_LINUX_LAPD */
	{ "linux-lapd", "LAPD with Linux pseudo-header" },

	/* WTAP_ENCAP_CATAPULT_DCT2000 */
	{ "dct2000", "Catapult DCT2000" },

	/* WTAP_ENCAP_BER */
	{ "ber", "ASN.1 Basic Encoding Rules" },

	/* WTAP_ENCAP_JUNIPER_VP */
	{ "juniper-vp", "Juniper Voice PIC" },

	/* WTAP_ENCAP_USB_FREEBSD */
	{ "usb-freebsd", "USB packets with FreeBSD header" },

	/* WTAP_ENCAP_IEEE802_16_MAC_CPS */
	{ "ieee-802-16-mac-cps", "IEEE 802.16 MAC Common Part Sublayer" },

	/* WTAP_ENCAP_NETTL_RAW_TELNET */
	{ "raw-telnet-nettl", "Raw telnet with nettl headers" },

	/* WTAP_ENCAP_USB_LINUX */
	{ "usb-linux", "USB packets with Linux header" },

	/* WTAP_ENCAP_MPEG */
	{ "mpeg", "MPEG" },

	/* WTAP_ENCAP_PPI */
	{ "ppi", "Per-Packet Information header" },

	/* WTAP_ENCAP_ERF */
	{ "erf", "Extensible Record Format" },

	/* WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR */
	{ "bluetooth-h4-linux", "Bluetooth H4 with linux header" },

	/* WTAP_ENCAP_SITA */
	{ "sita-wan", "SITA WAN packets" },

	/* WTAP_ENCAP_SCCP */
	{ "sccp", "SS7 SCCP" },

	/* WTAP_ENCAP_BLUETOOTH_HCI */
	{ "bluetooth-hci", "Bluetooth without transport layer" },

	/* WTAP_ENCAP_IPMB_KONTRON */
	{ "ipmb-kontron", "Intelligent Platform Management Bus with Kontron pseudo-header" },

	/* WTAP_ENCAP_IEEE802_15_4 */
	{ "wpan", "IEEE 802.15.4 Wireless PAN" },

	/* WTAP_ENCAP_X2E_XORAYA */
	{ "x2e-xoraya", "X2E Xoraya" },

	/* WTAP_ENCAP_FLEXRAY */
	{ "flexray", "FlexRay" },

	/* WTAP_ENCAP_LIN */
	{ "lin", "Local Interconnect Network" },

	/* WTAP_ENCAP_MOST */
	{ "most", "Media Oriented Systems Transport" },

	/* WTAP_ENCAP_CAN20B */
	{ "can20b", "Controller Area Network 2.0B" },

	/* WTAP_ENCAP_LAYER1_EVENT */
	{ "layer1-event", "EyeSDN Layer 1 event" },

	/* WTAP_ENCAP_X2E_SERIAL */
	{ "x2e-serial", "X2E serial line capture" },

	/* WTAP_ENCAP_I2C_LINUX */
	{ "i2c-linux", "I2C with Linux-specific pseudo-header" },

	/* WTAP_ENCAP_IEEE802_15_4_NONASK_PHY */
	{ "wpan-nonask-phy", "IEEE 802.15.4 Wireless PAN non-ASK PHY" },

	/* WTAP_ENCAP_TNEF */
	{ "tnef", "Transport-Neutral Encapsulation Format" },

	/* WTAP_ENCAP_USB_LINUX_MMAPPED */
	{ "usb-linux-mmap", "USB packets with Linux header and padding" },

	/* WTAP_ENCAP_GSM_UM */
	{ "gsm_um", "GSM Um Interface" },

	/* WTAP_ENCAP_DPNSS */
	{ "dpnss_link", "Digital Private Signalling System No 1 Link Layer" },

	/* WTAP_ENCAP_PACKETLOGGER */
	{ "packetlogger", "Apple Bluetooth PacketLogger" },

	/* WTAP_ENCAP_NSTRACE_1_0 */
	{ "nstrace10", "NetScaler Encapsulation 1.0 of Ethernet" },

	/* WTAP_ENCAP_NSTRACE_2_0 */
	{ "nstrace20", "NetScaler Encapsulation 2.0 of Ethernet" },

	/* WTAP_ENCAP_FIBRE_CHANNEL_FC2 */
	{ "fc2", "Fibre Channel FC-2" },

	/* WTAP_ENCAP_FIBRE_CHANNEL_FC2_WITH_FRAME_DELIMS */
	{ "fc2sof", "Fibre Channel FC-2 With Frame Delimiter" },

	/* WTAP_ENCAP_JPEG_JFIF */
	{ "jfif", "JPEG/JFIF" },

	/* WTAP_ENCAP_IPNET */
	{ "ipnet", "Solaris IPNET" },

	/* WTAP_ENCAP_SOCKETCAN */
	{ "socketcan", "SocketCAN" },

	/* WTAP_ENCAP_IEEE_802_11_NETMON */
	{ "ieee-802-11-netmon", "IEEE 802.11 plus Network Monitor radio header" },

	/* WTAP_ENCAP_IEEE802_15_4_NOFCS */
	{ "wpan-nofcs", "IEEE 802.15.4 Wireless PAN with FCS not present" },

	/* WTAP_ENCAP_RAW_IPFIX */
	{ "ipfix", "RFC 5655/RFC 5101 IPFIX" },

	/* WTAP_ENCAP_RAW_IP4 */
	{ "rawip4", "Raw IPv4" },

	/* WTAP_ENCAP_RAW_IP6 */
	{ "rawip6", "Raw IPv6" },

	/* WTAP_ENCAP_LAPD */
	{ "lapd", "LAPD" },

	/* WTAP_ENCAP_DVBCI */
	{ "dvbci", "DVB-CI (Common Interface)" },

	/* WTAP_ENCAP_MUX27010 */
	{ "mux27010", "MUX27010" },

	/* WTAP_ENCAP_MIME */
	{ "mime", "MIME" },

	/* WTAP_ENCAP_NETANALYZER */
	{ "netanalyzer", "Hilscher netANALYZER" },

	/* WTAP_ENCAP_NETANALYZER_TRANSPARENT */
	{ "netanalyzer-transparent", "Hilscher netANALYZER-Transparent" },

	/* WTAP_ENCAP_IP_OVER_IB */
	{ "ip-over-ib", "IP over InfiniBand" },

	/* WTAP_ENCAP_MPEG_2_TS */
	{ "mp2ts", "ISO/IEC 13818-1 MPEG2-TS" },

	/* WTAP_ENCAP_PPP_ETHER */
	{ "pppoes", "PPP-over-Ethernet session" },

	/* WTAP_ENCAP_NFC_LLCP */
	{ "nfc-llcp", "NFC LLCP" },

	/* WTAP_ENCAP_NFLOG */
	{ "nflog", "NFLOG" },

	/* WTAP_ENCAP_V5_EF */
	{ "v5-ef", "V5 Envelope Function" },

	/* WTAP_ENCAP_BACNET_MS_TP_WITH_PHDR */
	{ "bacnet-ms-tp-with-direction", "BACnet MS/TP with Directional Info" },

	/* WTAP_ENCAP_IXVERIWAVE */
	{ "ixveriwave", "IxVeriWave header and stats block" },

	/* WTAP_ENCAP_SDH */
	{ "sdh", "SDH" },

	/* WTAP_ENCAP_DBUS */
	{ "dbus", "D-Bus" },

	/* WTAP_ENCAP_AX25_KISS */
	{ "ax25-kiss", "AX.25 with KISS header" },

	/* WTAP_ENCAP_AX25 */
	{ "ax25", "Amateur Radio AX.25" },

	/* WTAP_ENCAP_SCTP */
	{ "sctp", "SCTP" },

	/* WTAP_ENCAP_INFINIBAND */
	{ "infiniband", "InfiniBand" },

	/* WTAP_ENCAP_JUNIPER_SVCS */
	{ "juniper-svcs", "Juniper Services" },

	/* WTAP_ENCAP_USBPCAP */
	{ "usb-usbpcap", "USB packets with USBPcap header" },

	/* WTAP_ENCAP_RTAC_SERIAL */
	{ "rtac-serial", "RTAC serial-line" },

	/* WTAP_ENCAP_BLUETOOTH_LE_LL */
	{ "bluetooth-le-ll", "Bluetooth Low Energy Link Layer" },

	/* WTAP_ENCAP_WIRESHARK_UPPER_PDU */
	{ "wireshark-upper-pdu", "Wireshark Upper PDU export" },

	/* WTAP_ENCAP_STANAG_4607 */
	{ "s4607", "STANAG 4607" },

	/* WTAP_ENCAP_STANAG_5066_D_PDU */
	{ "s5066-dpdu", "STANAG 5066 Data Transfer Sublayer PDUs(D_PDU)" },

	/* WTAP_ENCAP_NETLINK */
	{ "netlink", "Linux Netlink" },

	/* WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR */
	{ "bluetooth-linux-monitor", "Bluetooth Linux Monitor" },

	/* WTAP_ENCAP_BLUETOOTH_BREDR_BB */
	{ "bluetooth-bredr-bb-rf", "Bluetooth BR/EDR Baseband RF" },

	/* WTAP_ENCAP_BLUETOOTH_LE_LL_WITH_PHDR */
	{ "bluetooth-le-ll-rf", "Bluetooth Low Energy Link Layer RF" },

	/* WTAP_ENCAP_NSTRACE_3_0 */
	{ "nstrace30", "NetScaler Encapsulation 3.0 of Ethernet" },

	/* WTAP_ENCAP_LOGCAT */
	{ "logcat", "Android Logcat Binary format" },

	/* WTAP_ENCAP_LOGCAT_BRIEF */
	{ "logcat_brief", "Android Logcat Brief text format" },

	/* WTAP_ENCAP_LOGCAT_PROCESS */
	{ "logcat_process", "Android Logcat Process text format" },

	/* WTAP_ENCAP_LOGCAT_TAG */
	{ "logcat_tag", "Android Logcat Tag text format" },

	/* WTAP_ENCAP_LOGCAT_THREAD */
	{ "logcat_thread", "Android Logcat Thread text format" },

	/* WTAP_ENCAP_LOGCAT_TIME */
	{ "logcat_time", "Android Logcat Time text format" },

	/* WTAP_ENCAP_LOGCAT_THREADTIME */
	{ "logcat_threadtime", "Android Logcat Threadtime text format" },

	/* WTAP_ENCAP_LOGCAT_LONG */
	{ "logcat_long", "Android Logcat Long text format" },

	/* WTAP_ENCAP_PKTAP */
	{ "pktap", "Apple PKTAP" },

	/* WTAP_ENCAP_EPON */
	{ "epon", "Ethernet Passive Optical Network" },

	/* WTAP_ENCAP_IPMI_TRACE */
	{ "ipmi-trace", "IPMI Trace Data Collection" },

	/* WTAP_ENCAP_LOOP */
	{ "loop", "OpenBSD loopback" },

	/* WTAP_ENCAP_JSON */
	{ "json", "JavaScript Object Notation" },

	/* WTAP_ENCAP_NSTRACE_3_5 */
	{ "nstrace35", "NetScaler Encapsulation 3.5 of Ethernet" },

	/* WTAP_ENCAP_ISO14443 */
	{ "iso14443", "ISO 14443 contactless smartcard standards" },

	/* WTAP_ENCAP_GFP_T */
	{ "gfp-t", "ITU-T G.7041/Y.1303 Generic Framing Procedure Transparent mode" },

	/* WTAP_ENCAP_GFP_F */
	{ "gfp-f", "ITU-T G.7041/Y.1303 Generic Framing Procedure Frame-mapped mode" },

	/* WTAP_ENCAP_IP_OVER_IB_PCAP */
	{ "ip-ib", "IP over IB" },

	/* WTAP_ENCAP_JUNIPER_VN */
	{ "juniper-vn", "Juniper VN" },

	/* WTAP_ENCAP_USB_DARWIN */
	{ "usb-darwin", "USB packets with Darwin (macOS, etc.) headers" },

	/* WTAP_ENCAP_LORATAP */
	{ "loratap", "LoRaTap" },

	/* WTAP_ENCAP_3MB_ETHERNET */
	{ "xeth", "Xerox 3MB Ethernet" },

	/* WTAP_ENCAP_VSOCK */
	{ "vsock", "Linux vsock" },

	/* WTAP_ENCAP_NORDIC_BLE */
	{ "nordic_ble", "nRF Sniffer for Bluetooth LE" },

	/* WTAP_ENCAP_NETMON_NET_NETEVENT */
	{ "netmon_event", "Network Monitor Network Event" },

	/* WTAP_ENCAP_NETMON_HEADER */
	{ "netmon_header", "Network Monitor Header" },

	/* WTAP_ENCAP_NETMON_NET_FILTER */
	{ "netmon_filter", "Network Monitor Filter" },

	/* WTAP_ENCAP_NETMON_NETWORK_INFO_EX */
	{ "netmon_network_info", "Network Monitor Network Info" },

	/* WTAP_ENCAP_MA_WFP_CAPTURE_V4 */
	{ "message_analyzer_wfp_capture_v4", "Message Analyzer WFP Capture v4" },

	/* WTAP_ENCAP_MA_WFP_CAPTURE_V6 */
	{ "message_analyzer_wfp_capture_v6", "Message Analyzer WFP Capture v6" },

	/* WTAP_ENCAP_MA_WFP_CAPTURE_2V4 */
	{ "message_analyzer_wfp_capture2_v4", "Message Analyzer WFP Capture2 v4" },

	/* WTAP_ENCAP_MA_WFP_CAPTURE_2V6 */
	{ "message_analyzer_wfp_capture2_v6", "Message Analyzer WFP Capture2 v6" },

	/* WTAP_ENCAP_MA_WFP_CAPTURE_AUTH_V4 */
	{ "message_analyzer_wfp_capture_auth_v4", "Message Analyzer WFP Capture Auth v4" },

	/* WTAP_ENCAP_MA_WFP_CAPTURE_AUTH_V6 */
	{ "message_analyzer_wfp_capture_auth_v6", "Message Analyzer WFP Capture Auth v6" },

	/* WTAP_ENCAP_JUNIPER_ST */
	{ "juniper-st", "Juniper Secure Tunnel Information" },

	/* WTAP_ENCAP_ETHERNET_MPACKET */
	{ "ether-mpacket", "IEEE 802.3br mPackets" },

	/* WTAP_ENCAP_DOCSIS31_XRA31 */
	{ "docsis31_xra31", "DOCSIS with Excentis XRA pseudo-header" },

	/* WTAP_ENCAP_DPAUXMON */
	{ "dpauxmon", "DisplayPort AUX channel with Unigraf pseudo-header" },

	/* WTAP_ENCAP_RUBY_MARSHAL */
	{ "ruby_marshal", "Ruby marshal object" },

	/* WTAP_ENCAP_RFC7468 */
	{ "rfc7468", "RFC 7468 file" },

	/* WTAP_ENCAP_SYSTEMD_JOURNAL */
	{ "sdjournal", "systemd journal" },

	/* WTAP_ENCAP_EBHSCR */
	{ "ebhscr", "Elektrobit High Speed Capture and Replay" },

	/* WTAP_ENCAP_VPP */
	{ "vpp", "Vector Packet Processing graph dispatch trace" },

	/* WTAP_ENCAP_IEEE802_15_4_TAP */
	{ "wpan-tap", "IEEE 802.15.4 Wireless with TAP pseudo-header" },

	/* WTAP_ENCAP_LOG_3GPP */
	{ "log_3GPP", "3GPP Phone Log" },

	/* WTAP_ENCAP_USB_2_0 */
	{ "usb-20", "USB 2.0/1.1/1.0 packets" },

	/* WTAP_ENCAP_MP4 */
	{ "mp4", "MP4 files" },

	/* WTAP_ENCAP_SLL2 */
	{ "linux-sll2", "Linux cooked-mode capture v2" },

	/* WTAP_ENCAP_ZWAVE_SERIAL */
	{ "zwave-serial", "Z-Wave Serial API packets" },

	/* WTAP_ENCAP_ETW */
	{ "etw", "Event Tracing for Windows messages" },

	/* WTAP_ENCAP_ERI_ENB_LOG */
	{ "eri_enb_log", "Ericsson eNode-B raw log" },

	/* WTAP_ENCAP_ZBNCP */
	{ "zbncp", "ZBOSS NCP" },

	/* WTAP_ENCAP_USB_2_0_LOW_SPEED */
	{ "usb-20-low", "Low-Speed USB 2.0/1.1/1.0 packets" },

	/* WTAP_ENCAP_USB_2_0_FULL_SPEED */
	{ "usb-20-full", "Full-Speed USB 2.0/1.1/1.0 packets" },

	/* WTAP_ENCAP_USB_2_0_HIGH_SPEED */
	{ "usb-20-high", "High-Speed USB 2.0 packets" },
};

WS_DLL_LOCAL
gint wtap_num_encap_types = sizeof(encap_table_base) / sizeof(struct encap_type_info);
static GArray* encap_table_arr = NULL;

#define encap_table_entry(encap)	\
	g_array_index(encap_table_arr, struct encap_type_info, encap)

static void wtap_init_encap_types(void) {

	if (encap_table_arr) return;

	encap_table_arr = g_array_new(FALSE,TRUE,sizeof(struct encap_type_info));

	g_array_append_vals(encap_table_arr,encap_table_base,wtap_num_encap_types);
}

static void wtap_cleanup_encap_types(void) {
	if (encap_table_arr) {
		g_array_free(encap_table_arr, TRUE);
		encap_table_arr = NULL;
	}
}

int wtap_get_num_encap_types(void) {
	return wtap_num_encap_types;
}


int
wtap_register_encap_type(const char *description, const char *name)
{
	struct encap_type_info e;

	e.name = g_strdup(name);
	e.description = g_strdup(description);

	g_array_append_val(encap_table_arr,e);

	return wtap_num_encap_types++;
}

/* Name to use in, say, a command-line flag specifying the type. */
const char *
wtap_encap_name(int encap)
{
	if (encap < WTAP_ENCAP_PER_PACKET || encap >= WTAP_NUM_ENCAP_TYPES)
		return "illegal";
	else if (encap == WTAP_ENCAP_PER_PACKET)
		return "per-packet";
	else
		return encap_table_entry(encap).name;
}

/* Description to show to users. */
const char *
wtap_encap_description(int encap)
{
	if (encap < WTAP_ENCAP_PER_PACKET || encap >= WTAP_NUM_ENCAP_TYPES)
		return "Illegal";
	else if (encap == WTAP_ENCAP_PER_PACKET)
		return "Per packet";
	else
		return encap_table_entry(encap).description;
}

/* Translate a name to a capture file type. */
int
wtap_name_to_encap(const char *name)
{
	int encap;

	for (encap = 0; encap < WTAP_NUM_ENCAP_TYPES; encap++) {
		if (encap_table_entry(encap).name != NULL &&
		    strcmp(name, encap_table_entry(encap).name) == 0)
			return encap;
	}
	return -1;	/* no such encapsulation type */
}

const char*
wtap_tsprec_string(int tsprec)
{
	const char* s;
	switch (tsprec) {
		case WTAP_TSPREC_PER_PACKET:
			s = "per-packet";
			break;
		case WTAP_TSPREC_SEC:
			s = "seconds";
			break;
		case WTAP_TSPREC_DSEC:
			s = "deciseconds";
			break;
		case WTAP_TSPREC_CSEC:
			s = "centiseconds";
			break;
		case WTAP_TSPREC_MSEC:
			s = "milliseconds";
			break;
		case WTAP_TSPREC_USEC:
			s = "microseconds";
			break;
		case WTAP_TSPREC_NSEC:
			s = "nanoseconds";
			break;
		case WTAP_TSPREC_UNKNOWN:
		default:
			s = "UNKNOWN";
			break;
	}
	return s;
}

static const char *wtap_errlist[] = {
	/* WTAP_ERR_NOT_REGULAR_FILE */
	"The file isn't a plain file or pipe",

	/* WTAP_ERR_RANDOM_OPEN_PIPE */
	"The file is being opened for random access but is a pipe",

	/* WTAP_ERR_FILE_UNKNOWN_FORMAT */
	"The file isn't a capture file in a known format",

	/* WTAP_ERR_UNSUPPORTED */
	"File contains record data we don't support",

	/* WTAP_ERR_CANT_WRITE_TO_PIPE */
	"That file format cannot be written to a pipe",

	/* WTAP_ERR_CANT_OPEN */
	NULL,

	/* WTAP_ERR_UNWRITABLE_FILE_TYPE */
	"Files can't be saved in that format",

	/* WTAP_ERR_UNWRITABLE_ENCAP */
	"Packets with that network type can't be saved in that format",

	/* WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED */
	"That file format doesn't support per-packet encapsulations",

	/* WTAP_ERR_CANT_WRITE */
	"A write failed for some unknown reason",

	/* WTAP_ERR_CANT_CLOSE */
	NULL,

	/* WTAP_ERR_SHORT_READ */
	"Less data was read than was expected",

	/* WTAP_ERR_BAD_FILE */
	"The file appears to be damaged or corrupt",

	/* WTAP_ERR_SHORT_WRITE */
	"Less data was written than was requested",

	/* WTAP_ERR_UNC_OVERFLOW */
	"Uncompression error: data would overflow buffer",

	/* WTAP_ERR_RANDOM_OPEN_STDIN */
	"The standard input cannot be opened for random access",

	/* WTAP_ERR_COMPRESSION_NOT_SUPPORTED */
	"That file format doesn't support compression",

	/* WTAP_ERR_CANT_SEEK */
	NULL,

	/* WTAP_ERR_CANT_SEEK_COMPRESSED */
	NULL,

	/* WTAP_ERR_DECOMPRESS */
	"Uncompression error",

	/* WTAP_ERR_INTERNAL */
	"Internal error",

	/* WTAP_ERR_PACKET_TOO_LARGE */
	"The packet being written is too large for that format",

	/* WTAP_ERR_CHECK_WSLUA */
	NULL,

	/* WTAP_ERR_UNWRITABLE_REC_TYPE */
	"That record type cannot be written in that format",

	/* WTAP_ERR_UNWRITABLE_REC_DATA */
	"That record can't be written in that format",

	/* WTAP_ERR_DECOMPRESSION_NOT_SUPPORTED */
	"We don't support decompressing that type of compressed file",
};
#define	WTAP_ERRLIST_SIZE	(sizeof wtap_errlist / sizeof wtap_errlist[0])

const char *
wtap_strerror(int err)
{
	static char errbuf[128];
	unsigned int wtap_errlist_index;

	if (err < 0) {
		wtap_errlist_index = -1 - err;
		if (wtap_errlist_index >= WTAP_ERRLIST_SIZE) {
			snprintf(errbuf, 128, "Error %d", err);
			return errbuf;
		}
		if (wtap_errlist[wtap_errlist_index] == NULL)
			return "Unknown reason";
		return wtap_errlist[wtap_errlist_index];
	} else
		return g_strerror(err);
}

/* Close only the sequential side, freeing up memory it uses.

   Note that we do *not* want to call the subtype's close function,
   as it would free any per-subtype data, and that data may be
   needed by the random-access side.

   Instead, if the subtype has a "sequential close" function, we call it,
   to free up stuff used only by the sequential side. */
void
wtap_sequential_close(wtap *wth)
{
	if (wth->subtype_sequential_close != NULL)
		(*wth->subtype_sequential_close)(wth);

	if (wth->fh != NULL) {
		file_close(wth->fh);
		wth->fh = NULL;
	}
}

static void
g_fast_seek_item_free(gpointer data, gpointer user_data _U_)
{
	g_free(data);
}

/*
 * Close the file descriptors for the sequential and random streams, but
 * don't discard any information about those streams.  Used on Windows if
 * we need to rename a file that we have open or if we need to rename on
 * top of a file we have open.
 */
void
wtap_fdclose(wtap *wth)
{
	if (wth->fh != NULL)
		file_fdclose(wth->fh);
	if (wth->random_fh != NULL)
		file_fdclose(wth->random_fh);
}

void
wtap_close(wtap *wth)
{
	wtap_sequential_close(wth);

	if (wth->subtype_close != NULL)
		(*wth->subtype_close)(wth);

	if (wth->random_fh != NULL)
		file_close(wth->random_fh);

	g_free(wth->priv);

	g_free(wth->pathname);

	if (wth->fast_seek != NULL) {
		g_ptr_array_foreach(wth->fast_seek, g_fast_seek_item_free, NULL);
		g_ptr_array_free(wth->fast_seek, TRUE);
	}

	wtap_block_array_free(wth->shb_hdrs);
	wtap_block_array_free(wth->nrb_hdrs);
	wtap_block_array_free(wth->interface_data);
	wtap_block_array_free(wth->dsbs);

	g_free(wth);
}

void
wtap_cleareof(wtap *wth) {
	/* Reset EOF */
	file_clearerr(wth->fh);
}

void wtap_set_cb_new_ipv4(wtap *wth, wtap_new_ipv4_callback_t add_new_ipv4) {
	if (wth)
		wth->add_new_ipv4 = add_new_ipv4;
}

void wtap_set_cb_new_ipv6(wtap *wth, wtap_new_ipv6_callback_t add_new_ipv6) {
	if (wth)
		wth->add_new_ipv6 = add_new_ipv6;
}

void wtap_set_cb_new_secrets(wtap *wth, wtap_new_secrets_callback_t add_new_secrets) {
	/* Is a valid wth given that supports DSBs? */
	if (!wth || !wth->dsbs)
		return;

	wth->add_new_secrets = add_new_secrets;
	/*
	 * Send all DSBs that were read so far to the new callback. file.c
	 * relies on this to support redissection (during redissection, the
	 * previous secrets are lost and has to be resupplied).
	 */
	for (guint i = 0; i < wth->dsbs->len; i++) {
		wtap_block_t dsb = g_array_index(wth->dsbs, wtap_block_t, i);
		wtapng_process_dsb(wth, dsb);
	}
}

void
wtapng_process_dsb(wtap *wth, wtap_block_t dsb)
{
	const wtapng_dsb_mandatory_t *dsb_mand = (wtapng_dsb_mandatory_t*)wtap_block_get_mandatory_data(dsb);

	if (wth->add_new_secrets)
		wth->add_new_secrets(dsb_mand->secrets_type, dsb_mand->secrets_data, dsb_mand->secrets_len);
}

/* Perform per-packet initialization */
static void
wtap_init_rec(wtap *wth, wtap_rec *rec)
{
	/*
	 * Set the packet encapsulation to the file's encapsulation
	 * value; if that's not WTAP_ENCAP_PER_PACKET, it's the
	 * right answer (and means that the read routine for this
	 * capture file type doesn't have to set it), and if it
	 * *is* WTAP_ENCAP_PER_PACKET, the caller needs to set it
	 * anyway.
	 *
	 * Do the same for the packet time stamp resolution.
	 */
	rec->rec_header.packet_header.pkt_encap = wth->file_encap;
	rec->tsprec = wth->file_tsprec;
	rec->block = NULL;
	rec->block_was_modified = FALSE;

	/*
	 * Assume the file has only one section; the module for the
	 * file type needs to indicate the section number if there's
	 * more than one section.
	 */
	rec->section_number = 0;
}

gboolean
wtap_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err,
	gchar **err_info, gint64 *offset)
{
	/*
	 * Initialize the record to default values.
	 */
	wtap_init_rec(wth, rec);

	*err = 0;
	*err_info = NULL;
	if (!wth->subtype_read(wth, rec, buf, err, err_info, offset)) {
		/*
		 * If we didn't get an error indication, we read
		 * the last packet.  See if there's any deferred
		 * error, as might, for example, occur if we're
		 * reading a compressed file, and we got an error
		 * reading compressed data from the file, but
		 * got enough compressed data to decompress the
		 * last packet of the file.
		 */
		if (*err == 0)
			*err = file_error(wth->fh, err_info);
		if (rec->block != NULL) {
			/*
			 * Unreference any block created for this record.
			 */
			wtap_block_unref(rec->block);
			rec->block = NULL;
		}
		return FALSE;	/* failure */
	}

	/*
	 * Is this a packet record?
	 */
	if (rec->rec_type == REC_TYPE_PACKET) {
		/*
		 * Make sure that it's not WTAP_ENCAP_PER_PACKET, as that
		 * probably means the file has that encapsulation type
		 * but the read routine didn't set this packet's
		 * encapsulation type.
		 */
		ws_assert(rec->rec_header.packet_header.pkt_encap != WTAP_ENCAP_PER_PACKET);
	}

	return TRUE;	/* success */
}

/*
 * Read a given number of bytes from a file into a buffer or, if
 * buf is NULL, just discard them.
 *
 * If we succeed, return TRUE.
 *
 * If we get an EOF, return FALSE with *err set to 0, reporting this
 * as an EOF.
 *
 * If we get fewer bytes than the specified number, return FALSE with
 * *err set to WTAP_ERR_SHORT_READ, reporting this as a short read
 * error.
 *
 * If we get a read error, return FALSE with *err and *err_info set
 * appropriately.
 */
gboolean
wtap_read_bytes_or_eof(FILE_T fh, void *buf, unsigned int count, int *err,
    gchar **err_info)
{
	int	bytes_read;

	bytes_read = file_read(buf, count, fh);
	if (bytes_read < 0 || (guint)bytes_read != count) {
		*err = file_error(fh, err_info);
		if (*err == 0 && bytes_read > 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	return TRUE;
}

/*
 * Read a given number of bytes from a file into a buffer or, if
 * buf is NULL, just discard them.
 *
 * If we succeed, return TRUE.
 *
 * If we get fewer bytes than the specified number, including getting
 * an EOF, return FALSE with *err set to WTAP_ERR_SHORT_READ, reporting
 * this as a short read error.
 *
 * If we get a read error, return FALSE with *err and *err_info set
 * appropriately.
 */
gboolean
wtap_read_bytes(FILE_T fh, void *buf, unsigned int count, int *err,
    gchar **err_info)
{
	int	bytes_read;

	bytes_read = file_read(buf, count, fh);
	if (bytes_read < 0 || (guint)bytes_read != count) {
		*err = file_error(fh, err_info);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	return TRUE;
}

/*
 * Read packet data into a Buffer, growing the buffer as necessary.
 *
 * This returns an error on a short read, even if the short read hit
 * the EOF immediately.  (The assumption is that each packet has a
 * header followed by raw packet data, and that we've already read the
 * header, so if we get an EOF trying to read the packet data, the file
 * has been cut short, even if the read didn't read any data at all.)
 */
gboolean
wtap_read_packet_bytes(FILE_T fh, Buffer *buf, guint length, int *err,
    gchar **err_info)
{
	ws_buffer_assure_space(buf, length);
	return wtap_read_bytes(fh, ws_buffer_start_ptr(buf), length, err,
	    err_info);
}

/*
 * Return an approximation of the amount of data we've read sequentially
 * from the file so far.  (gint64, in case that's 64 bits.)
 */
gint64
wtap_read_so_far(wtap *wth)
{
	return file_tell_raw(wth->fh);
}

/* Perform global/initial initialization */
void
wtap_rec_init(wtap_rec *rec)
{
	memset(rec, 0, sizeof *rec);
	ws_buffer_init(&rec->options_buf, 0);
	/* In the future, see if we can create rec->block here once
	 * and have it be reused like the rest of rec.
	 * Currently it's recreated for each packet.
	 */
}

/* re-initialize record */
void
wtap_rec_reset(wtap_rec *rec)
{
	wtap_block_unref(rec->block);
	rec->block = NULL;
	rec->block_was_modified = FALSE;
}

/* clean up record metadata */
void
wtap_rec_cleanup(wtap_rec *rec)
{
	wtap_rec_reset(rec);
	ws_buffer_free(&rec->options_buf);
}

gboolean
wtap_seek_read(wtap *wth, gint64 seek_off, wtap_rec *rec, Buffer *buf,
    int *err, gchar **err_info)
{
	/*
	 * Initialize the record to default values.
	 */
	wtap_init_rec(wth, rec);

	*err = 0;
	*err_info = NULL;
	if (!wth->subtype_seek_read(wth, seek_off, rec, buf, err, err_info)) {
		if (rec->block != NULL) {
			/*
			 * Unreference any block created for this record.
			 */
			wtap_block_unref(rec->block);
			rec->block = NULL;
		}
		return FALSE;
	}

	/*
	 * Is this a packet record?
	 */
	if (rec->rec_type == REC_TYPE_PACKET) {
		/*
		 * Make sure that it's not WTAP_ENCAP_PER_PACKET, as that
		 * probably means the file has that encapsulation type
		 * but the read routine didn't set this packet's
		 * encapsulation type.
		 */
		ws_assert(rec->rec_header.packet_header.pkt_encap != WTAP_ENCAP_PER_PACKET);
	}

	return TRUE;
}

static gboolean
wtap_full_file_read_file(wtap *wth, FILE_T fh, wtap_rec *rec, Buffer *buf, int *err, gchar **err_info)
{
	gint64 file_size;
	int packet_size = 0;
	const int block_size = 1024 * 1024;

	if ((file_size = wtap_file_size(wth, err)) == -1)
		return FALSE;

	if (file_size > G_MAXINT) {
		/*
		 * Avoid allocating space for an immensely-large file.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = ws_strdup_printf("%s: File has %" PRId64 "-byte packet, bigger than maximum of %u",
				wtap_encap_name(wth->file_encap), file_size, G_MAXINT);
		return FALSE;
	}

	/*
	 * Compressed files might expand to a larger size than the actual file
	 * size. Try to read the full size and then read in smaller increments
	 * to avoid frequent memory reallocations.
	 */
	int buffer_size = block_size * (1 + (int)file_size / block_size);
	for (;;) {
		if (buffer_size <= 0) {
			*err = WTAP_ERR_BAD_FILE;
			*err_info = ws_strdup_printf("%s: Uncompressed file is bigger than maximum of %u",
					wtap_encap_name(wth->file_encap), G_MAXINT);
			return FALSE;
		}
		ws_buffer_assure_space(buf, buffer_size);
		int nread = file_read(ws_buffer_start_ptr(buf) + packet_size, buffer_size - packet_size, fh);
		if (nread < 0) {
			*err = file_error(fh, err_info);
			if (*err == 0)
				*err = WTAP_ERR_BAD_FILE;
			return FALSE;
		}
		packet_size += nread;
		if (packet_size != buffer_size) {
			/* EOF */
			break;
		}
		buffer_size += block_size;
	}

	rec->rec_type = REC_TYPE_PACKET;
	rec->presence_flags = 0; /* yes, we have no bananas^Wtime stamp */
	rec->ts.secs = 0;
	rec->ts.nsecs = 0;
	rec->rec_header.packet_header.caplen = packet_size;
	rec->rec_header.packet_header.len = packet_size;

	return TRUE;
}

gboolean
wtap_full_file_read(wtap *wth, wtap_rec *rec, Buffer *buf,
                    int *err, gchar **err_info, gint64 *data_offset)
{
	gint64 offset = file_tell(wth->fh);

	/* There is only one packet with the full file contents. */
	if (offset != 0) {
		*err = 0;
		return FALSE;
	}

	*data_offset = offset;
	return wtap_full_file_read_file(wth, wth->fh, rec, buf, err, err_info);
}

gboolean
wtap_full_file_seek_read(wtap *wth, gint64 seek_off, wtap_rec *rec, Buffer *buf, int *err, gchar **err_info)
{
	/* There is only one packet with the full file contents. */
	if (seek_off > 0) {
		*err = 0;
		return FALSE;
	}

	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	return wtap_full_file_read_file(wth, wth->random_fh, rec, buf, err, err_info);
}

/*
 * Initialize the library.
 */
void
wtap_init(gboolean load_wiretap_plugins)
{
	init_open_routines();
	wtap_opttypes_initialize();
	wtap_init_encap_types();
	wtap_init_file_type_subtypes();
	if (load_wiretap_plugins) {
#ifdef HAVE_PLUGINS
		libwiretap_plugins = plugins_init(WS_PLUGIN_WIRETAP);
#endif
		g_slist_foreach(wtap_plugins, call_plugin_register_wtap_module, NULL);
	}
}

/*
 * Cleanup the library
 */
void
wtap_cleanup(void)
{
	wtap_cleanup_encap_types();
	wtap_opttypes_cleanup();
	ws_buffer_cleanup();
	cleanup_open_routines();
	g_slist_free(wtap_plugins);
	wtap_plugins = NULL;
#ifdef HAVE_PLUGINS
	plugins_cleanup(libwiretap_plugins);
	libwiretap_plugins = NULL;
#endif
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
