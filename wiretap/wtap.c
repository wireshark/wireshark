/* wtap.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <config.h>

#include <string.h>
#include <errno.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include "wtap-int.h"
#include "wtap_opttypes.h"
#include "pcapng.h"

#include "file_wrappers.h"
#include <wsutil/file_util.h>
#include <wsutil/buffer.h>

#ifdef HAVE_PLUGINS

#include <wsutil/plugins.h>

/*
 * List of wiretap plugins.
 */
typedef struct {
	void (*register_wtap_module)(void);  /* routine to call to register a wiretap module */
} wtap_plugin;

static GSList *wtap_plugins = NULL;

/*
 * Callback for each plugin found.
 */
static gboolean
check_for_wtap_plugin(GModule *handle)
{
	gpointer gp;
	wtap_plugin *plugin;

	/*
	 * Do we have a register_wtap_module routine?
	 */
	if (!g_module_symbol(handle, "register_wtap_module", &gp)) {
		/* No, so this isn't a wiretap module plugin. */
		return FALSE;
	}

	/*
	 * Yes - this plugin includes one or more wiretap modules.
	 * Add this one to the list of wiretap module plugins.
	 */
	plugin = (wtap_plugin *)g_malloc(sizeof (wtap_plugin));
DIAG_OFF(pedantic)
	plugin->register_wtap_module = (void (*)(void))gp;
DIAG_ON(pedantic)
	wtap_plugins = g_slist_append(wtap_plugins, plugin);
	return TRUE;
}

void
wtap_register_plugin_types(void)
{
	add_plugin_type("libwiretap", check_for_wtap_plugin);
}

static void
register_wtap_module_plugin(gpointer data, gpointer user_data _U_)
{
	wtap_plugin *plugin = (wtap_plugin *)data;

	(plugin->register_wtap_module)();
}

/*
 * For all wiretap module plugins, call their register routines.
 */
void
register_all_wiretap_modules(void)
{
	g_slist_foreach(wtap_plugins, register_wtap_module_plugin, NULL);
}
#endif /* HAVE_PLUGINS */

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

gboolean
wtap_iscompressed(wtap *wth)
{
	return file_iscompressed((wth->fh == NULL) ? wth->random_fh : wth->fh);
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

wtap_block_t
wtap_file_get_shb(wtap *wth)
{
	if ((wth == NULL) || (wth->shb_hdrs == NULL) || (wth->shb_hdrs->len == 0))
		return NULL;

	return g_array_index(wth->shb_hdrs, wtap_block_t, 0);
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
		shb_hdr_dest = wtap_block_create(WTAP_BLOCK_NG_SECTION);
		wtap_block_copy(shb_hdr_dest, shb_hdr_src);
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
	wtapng_if_descr_filter_t* if_filter;

	g_assert(if_descr);

	if_descr_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(if_descr);
	if (wtap_block_get_string_option_value(if_descr, OPT_IDB_NAME, &tmp_content) == WTAP_OPTTYPE_SUCCESS) {
		g_string_printf(info,
				"%*cName = %s%s", indent, ' ',
				tmp_content ? tmp_content : "UNKNOWN",
				line_end);
	}

	if (wtap_block_get_string_option_value(if_descr, OPT_IDB_DESCR, &tmp_content) == WTAP_OPTTYPE_SUCCESS) {
		g_string_append_printf(info,
				"%*cDescription = %s%s", indent, ' ',
				tmp_content ? tmp_content : "NONE",
				line_end);
	}

	g_string_append_printf(info,
			"%*cEncapsulation = %s (%d/%u - %s)%s", indent, ' ',
			wtap_encap_string(if_descr_mand->wtap_encap),
			if_descr_mand->wtap_encap,
			if_descr_mand->link_type,
			wtap_encap_short_string(if_descr_mand->wtap_encap),
			line_end);

	if (wtap_block_get_uint64_option_value(if_descr, OPT_IDB_SPEED, &tmp64) == WTAP_OPTTYPE_SUCCESS) {
		g_string_append_printf(info,
				"%*cSpeed = %" G_GINT64_MODIFIER "u%s", indent, ' ',
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
			"%*cTime ticks per second = %" G_GINT64_MODIFIER "u%s", indent, ' ',
			if_descr_mand->time_units_per_second,
			line_end);

	if (wtap_block_get_uint8_option_value(if_descr, OPT_IDB_TSRESOL, &tmp8) == WTAP_OPTTYPE_SUCCESS) {
		g_string_append_printf(info,
				"%*cTime resolution = 0x%.2x%s", indent, ' ',
				tmp8,
				line_end);
	}

	if (wtap_block_get_custom_option_value(if_descr, OPT_IDB_FILTER, (void**)&if_filter) == WTAP_OPTTYPE_SUCCESS) {
		g_string_append_printf(info,
				"%*cFilter string = %s%s", indent, ' ',
				if_filter->if_filter_str ? if_filter->if_filter_str : "NONE",
				line_end);

		g_string_append_printf(info,
				"%*cBPF filter length = %u%s", indent, ' ',
				if_filter->bpf_filter_len,
				line_end);
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
		nrb_hdr_dest = wtap_block_create(WTAP_BLOCK_NG_NRB);
		wtap_block_copy(nrb_hdr_dest, nrb_hdr_src);
		g_array_append_val(nrb_hdrs, nrb_hdr_dest);
	}

	return nrb_hdrs;
}

/* Table of the encapsulation types we know about. */
struct encap_type_info {
	const char *name;
	const char *short_name;
};

static struct encap_type_info encap_table_base[] = {
	/* WTAP_ENCAP_UNKNOWN */
	{ "Unknown", "unknown" },

	/* WTAP_ENCAP_ETHERNET */
	{ "Ethernet", "ether" },

	/* WTAP_ENCAP_TOKEN_RING */
	{ "Token Ring", "tr" },

	/* WTAP_ENCAP_SLIP */
	{ "SLIP", "slip" },

	/* WTAP_ENCAP_PPP */
	{ "PPP", "ppp" },

	/* WTAP_ENCAP_FDDI */
	{ "FDDI", "fddi" },

	/* WTAP_ENCAP_FDDI_BITSWAPPED */
	{ "FDDI with bit-swapped MAC addresses", "fddi-swapped" },

	/* WTAP_ENCAP_RAW_IP */
	{ "Raw IP", "rawip" },

	/* WTAP_ENCAP_ARCNET */
	{ "ARCNET", "arcnet" },

	/* WTAP_ENCAP_ARCNET_LINUX */
	{ "Linux ARCNET", "arcnet_linux" },

	/* WTAP_ENCAP_ATM_RFC1483 */
	{ "RFC 1483 ATM", "atm-rfc1483" },

	/* WTAP_ENCAP_LINUX_ATM_CLIP */
	{ "Linux ATM CLIP", "linux-atm-clip" },

	/* WTAP_ENCAP_LAPB */
	{ "LAPB", "lapb" },

	/* WTAP_ENCAP_ATM_PDUS */
	{ "ATM PDUs", "atm-pdus" },

	/* WTAP_ENCAP_ATM_PDUS_UNTRUNCATED */
	{ "ATM PDUs - untruncated", "atm-pdus-untruncated" },

	/* WTAP_ENCAP_NULL */
	{ "NULL/Loopback", "null" },

	/* WTAP_ENCAP_ASCEND */
	{ "Lucent/Ascend access equipment", "ascend" },

	/* WTAP_ENCAP_ISDN */
	{ "ISDN", "isdn" },

	/* WTAP_ENCAP_IP_OVER_FC */
	{ "RFC 2625 IP-over-Fibre Channel", "ip-over-fc" },

	/* WTAP_ENCAP_PPP_WITH_PHDR */
	{ "PPP with Directional Info", "ppp-with-direction" },

	/* WTAP_ENCAP_IEEE_802_11 */
	{ "IEEE 802.11 Wireless LAN", "ieee-802-11" },

	/* WTAP_ENCAP_IEEE_802_11_PRISM */
	{ "IEEE 802.11 plus Prism II monitor mode radio header", "ieee-802-11-prism" },

	/* WTAP_ENCAP_IEEE_802_11_WITH_RADIO */
	{ "IEEE 802.11 Wireless LAN with radio information", "ieee-802-11-radio" },

	/* WTAP_ENCAP_IEEE_802_11_RADIOTAP */
	{ "IEEE 802.11 plus radiotap radio header", "ieee-802-11-radiotap" },

	/* WTAP_ENCAP_IEEE_802_11_AVS */
	{ "IEEE 802.11 plus AVS radio header", "ieee-802-11-avs" },

	/* WTAP_ENCAP_SLL */
	{ "Linux cooked-mode capture", "linux-sll" },

	/* WTAP_ENCAP_FRELAY */
	{ "Frame Relay", "frelay" },

	/* WTAP_ENCAP_FRELAY_WITH_PHDR */
	{ "Frame Relay with Directional Info", "frelay-with-direction" },

	/* WTAP_ENCAP_CHDLC */
	{ "Cisco HDLC", "chdlc" },

	/* WTAP_ENCAP_CISCO_IOS */
	{ "Cisco IOS internal", "ios" },

	/* WTAP_ENCAP_LOCALTALK */
	{ "Localtalk", "ltalk" },

	/* WTAP_ENCAP_OLD_PFLOG  */
	{ "OpenBSD PF Firewall logs, pre-3.4", "pflog-old" },

	/* WTAP_ENCAP_HHDLC */
	{ "HiPath HDLC", "hhdlc" },

	/* WTAP_ENCAP_DOCSIS */
	{ "Data Over Cable Service Interface Specification", "docsis" },

	/* WTAP_ENCAP_COSINE */
	{ "CoSine L2 debug log", "cosine" },

	/* WTAP_ENCAP_WFLEET_HDLC */
	{ "Wellfleet HDLC", "whdlc" },

	/* WTAP_ENCAP_SDLC */
	{ "SDLC", "sdlc" },

	/* WTAP_ENCAP_TZSP */
	{ "Tazmen sniffer protocol", "tzsp" },

	/* WTAP_ENCAP_ENC */
	{ "OpenBSD enc(4) encapsulating interface", "enc" },

	/* WTAP_ENCAP_PFLOG  */
	{ "OpenBSD PF Firewall logs", "pflog" },

	/* WTAP_ENCAP_CHDLC_WITH_PHDR */
	{ "Cisco HDLC with Directional Info", "chdlc-with-direction" },

	/* WTAP_ENCAP_BLUETOOTH_H4 */
	{ "Bluetooth H4", "bluetooth-h4" },

	/* WTAP_ENCAP_MTP2 */
	{ "SS7 MTP2", "mtp2" },

	/* WTAP_ENCAP_MTP3 */
	{ "SS7 MTP3", "mtp3" },

	/* WTAP_ENCAP_IRDA */
	{ "IrDA", "irda" },

	/* WTAP_ENCAP_USER0 */
	{ "USER 0", "user0" },

	/* WTAP_ENCAP_USER1 */
	{ "USER 1", "user1" },

	/* WTAP_ENCAP_USER2 */
	{ "USER 2", "user2" },

	/* WTAP_ENCAP_USER3 */
	{ "USER 3", "user3" },

	/* WTAP_ENCAP_USER4 */
	{ "USER 4", "user4" },

	/* WTAP_ENCAP_USER5 */
	{ "USER 5", "user5" },

	/* WTAP_ENCAP_USER6 */
	{ "USER 6", "user6" },

	/* WTAP_ENCAP_USER7 */
	{ "USER 7", "user7" },

	/* WTAP_ENCAP_USER8 */
	{ "USER 8", "user8" },

	/* WTAP_ENCAP_USER9 */
	{ "USER 9", "user9" },

	/* WTAP_ENCAP_USER10 */
	{ "USER 10", "user10" },

	/* WTAP_ENCAP_USER11 */
	{ "USER 11", "user11" },

	/* WTAP_ENCAP_USER12 */
	{ "USER 12", "user12" },

	/* WTAP_ENCAP_USER13 */
	{ "USER 13", "user13" },

	/* WTAP_ENCAP_USER14 */
	{ "USER 14", "user14" },

	/* WTAP_ENCAP_USER15 */
	{ "USER 15", "user15" },

	/* WTAP_ENCAP_SYMANTEC */
	{ "Symantec Enterprise Firewall", "symantec" },

	/* WTAP_ENCAP_APPLE_IP_OVER_IEEE1394 */
	{ "Apple IP-over-IEEE 1394", "ap1394" },

	/* WTAP_ENCAP_BACNET_MS_TP */
	{ "BACnet MS/TP", "bacnet-ms-tp" },

	/* WTAP_ENCAP_NETTL_RAW_ICMP */
	{ "Raw ICMP with nettl headers", "raw-icmp-nettl" },

	/* WTAP_ENCAP_NETTL_RAW_ICMPV6 */
	{ "Raw ICMPv6 with nettl headers", "raw-icmpv6-nettl" },

	/* WTAP_ENCAP_GPRS_LLC */
	{ "GPRS LLC", "gprs-llc" },

	/* WTAP_ENCAP_JUNIPER_ATM1 */
	{ "Juniper ATM1", "juniper-atm1" },

	/* WTAP_ENCAP_JUNIPER_ATM2 */
	{ "Juniper ATM2", "juniper-atm2" },

	/* WTAP_ENCAP_REDBACK */
	{ "Redback SmartEdge", "redback" },

	/* WTAP_ENCAP_NETTL_RAW_IP */
	{ "Raw IP with nettl headers", "rawip-nettl" },

	/* WTAP_ENCAP_NETTL_ETHERNET */
	{ "Ethernet with nettl headers", "ether-nettl" },

	/* WTAP_ENCAP_NETTL_TOKEN_RING */
	{ "Token Ring with nettl headers", "tr-nettl" },

	/* WTAP_ENCAP_NETTL_FDDI */
	{ "FDDI with nettl headers", "fddi-nettl" },

	/* WTAP_ENCAP_NETTL_UNKNOWN */
	{ "Unknown link-layer type with nettl headers", "unknown-nettl" },

	/* WTAP_ENCAP_MTP2_WITH_PHDR */
	{ "MTP2 with pseudoheader", "mtp2-with-phdr" },

	/* WTAP_ENCAP_JUNIPER_PPPOE */
	{ "Juniper PPPoE", "juniper-pppoe" },

	/* WTAP_ENCAP_GCOM_TIE1 */
	{ "GCOM TIE1", "gcom-tie1" },

	/* WTAP_ENCAP_GCOM_SERIAL */
	{ "GCOM Serial", "gcom-serial" },

	/* WTAP_ENCAP_NETTL_X25 */
	{ "X.25 with nettl headers", "x25-nettl" },

	/* WTAP_ENCAP_K12 */
	{ "K12 protocol analyzer", "k12" },

	/* WTAP_ENCAP_JUNIPER_MLPPP */
	{ "Juniper MLPPP", "juniper-mlppp" },

	/* WTAP_ENCAP_JUNIPER_MLFR */
	{ "Juniper MLFR", "juniper-mlfr" },

	/* WTAP_ENCAP_JUNIPER_ETHER */
	{ "Juniper Ethernet", "juniper-ether" },

	/* WTAP_ENCAP_JUNIPER_PPP */
	{ "Juniper PPP", "juniper-ppp" },

	/* WTAP_ENCAP_JUNIPER_FRELAY */
	{ "Juniper Frame-Relay", "juniper-frelay" },

	/* WTAP_ENCAP_JUNIPER_CHDLC */
	{ "Juniper C-HDLC", "juniper-chdlc" },

	/* WTAP_ENCAP_JUNIPER_GGSN */
	{ "Juniper GGSN", "juniper-ggsn" },

	/* WTAP_ENCAP_LINUX_LAPD */
	{ "LAPD with Linux pseudo-header", "linux-lapd" },

	/* WTAP_ENCAP_CATAPULT_DCT2000 */
	{ "Catapult DCT2000", "dct2000" },

	/* WTAP_ENCAP_BER */
	{ "ASN.1 Basic Encoding Rules", "ber" },

	/* WTAP_ENCAP_JUNIPER_VP */
	{ "Juniper Voice PIC", "juniper-vp" },

	/* WTAP_ENCAP_USB */
	{ "Raw USB packets", "usb" },

	/* WTAP_ENCAP_IEEE802_16_MAC_CPS */
	{ "IEEE 802.16 MAC Common Part Sublayer", "ieee-802-16-mac-cps" },

	/* WTAP_ENCAP_NETTL_RAW_TELNET */
	{ "Raw telnet with nettl headers", "raw-telnet-nettl" },

	/* WTAP_ENCAP_USB_LINUX */
	{ "USB packets with Linux header", "usb-linux" },

	/* WTAP_ENCAP_MPEG */
	{ "MPEG", "mpeg" },

	/* WTAP_ENCAP_PPI */
	{ "Per-Packet Information header", "ppi" },

	/* WTAP_ENCAP_ERF */
	{ "Extensible Record Format", "erf" },

	/* WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR */
	{ "Bluetooth H4 with linux header", "bluetooth-h4-linux" },

	/* WTAP_ENCAP_SITA */
	{ "SITA WAN packets", "sita-wan" },

	/* WTAP_ENCAP_SCCP */
	{ "SS7 SCCP", "sccp" },

	/* WTAP_ENCAP_BLUETOOTH_HCI */
	{ "Bluetooth without transport layer", "bluetooth-hci" },

	/* WTAP_ENCAP_IPMB */
	{ "Intelligent Platform Management Bus", "ipmb" },

	/* WTAP_ENCAP_IEEE802_15_4 */
	{ "IEEE 802.15.4 Wireless PAN", "wpan" },

	/* WTAP_ENCAP_X2E_XORAYA */
	{ "X2E Xoraya", "x2e-xoraya" },

	/* WTAP_ENCAP_FLEXRAY */
	{ "FlexRay", "flexray" },

	/* WTAP_ENCAP_LIN */
	{ "Local Interconnect Network", "lin" },

	/* WTAP_ENCAP_MOST */
	{ "Media Oriented Systems Transport", "most" },

	/* WTAP_ENCAP_CAN20B */
	{ "Controller Area Network 2.0B", "can20b" },

	/* WTAP_ENCAP_LAYER1_EVENT */
	{ "EyeSDN Layer 1 event", "layer1-event" },

	/* WTAP_ENCAP_X2E_SERIAL */
	{ "X2E serial line capture", "x2e-serial" },

	/* WTAP_ENCAP_I2C */
	{ "I2C", "i2c" },

	/* WTAP_ENCAP_IEEE802_15_4_NONASK_PHY */
	{ "IEEE 802.15.4 Wireless PAN non-ASK PHY", "wpan-nonask-phy" },

	/* WTAP_ENCAP_TNEF */
	{ "Transport-Neutral Encapsulation Format", "tnef" },

	/* WTAP_ENCAP_USB_LINUX_MMAPPED */
	{ "USB packets with Linux header and padding", "usb-linux-mmap" },

	/* WTAP_ENCAP_GSM_UM */
	{ "GSM Um Interface", "gsm_um" },

	/* WTAP_ENCAP_DPNSS */
	{ "Digital Private Signalling System No 1 Link Layer", "dpnss_link" },

	/* WTAP_ENCAP_PACKETLOGGER */
	{ "PacketLogger", "packetlogger" },

	/* WTAP_ENCAP_NSTRACE_1_0 */
	{ "NetScaler Encapsulation 1.0 of Ethernet", "nstrace10" },

	/* WTAP_ENCAP_NSTRACE_2_0 */
	{ "NetScaler Encapsulation 2.0 of Ethernet", "nstrace20" },

	/* WTAP_ENCAP_FIBRE_CHANNEL_FC2 */
	{ "Fibre Channel FC-2", "fc2" },

	/* WTAP_ENCAP_FIBRE_CHANNEL_FC2_WITH_FRAME_DELIMS */
	{ "Fibre Channel FC-2 With Frame Delimiter", "fc2sof"},

	/* WTAP_ENCAP_JPEG_JFIF */
	{ "JPEG/JFIF", "jfif" },

	/* WTAP_ENCAP_IPNET */
	{ "Solaris IPNET", "ipnet" },

	/* WTAP_ENCAP_SOCKETCAN */
	{ "SocketCAN", "socketcan" },

	/* WTAP_ENCAP_IEEE_802_11_NETMON */
	{ "IEEE 802.11 plus Network Monitor radio header", "ieee-802-11-netmon" },

	/* WTAP_ENCAP_IEEE802_15_4_NOFCS */
	{ "IEEE 802.15.4 Wireless PAN with FCS not present", "wpan-nofcs" },

	/* WTAP_ENCAP_RAW_IPFIX */
	{ "IPFIX", "ipfix" },

	/* WTAP_ENCAP_RAW_IP4 */
	{ "Raw IPv4", "rawip4" },

	/* WTAP_ENCAP_RAW_IP6 */
	{ "Raw IPv6", "rawip6" },

	/* WTAP_ENCAP_LAPD */
	{ "LAPD", "lapd" },

	/* WTAP_ENCAP_DVBCI */
	{ "DVB-CI (Common Interface)", "dvbci"},

	/* WTAP_ENCAP_MUX27010 */
	{ "MUX27010", "mux27010"},

	/* WTAP_ENCAP_MIME */
	{ "MIME", "mime" },

	/* WTAP_ENCAP_NETANALYZER */
	{ "netANALYZER", "netanalyzer" },

	/* WTAP_ENCAP_NETANALYZER_TRANSPARENT */
	{ "netANALYZER-Transparent", "netanalyzer-transparent" },

	/* WTAP_ENCAP_IP_OVER_IB */
	{ "IP over Infiniband", "ip-over-ib" },

	/* WTAP_ENCAP_MPEG_2_TS */
	{ "ISO/IEC 13818-1 MPEG2-TS", "mp2ts" },

	/* WTAP_ENCAP_PPP_ETHER */
	{ "PPP-over-Ethernet session", "pppoes" },

	/* WTAP_ENCAP_NFC_LLCP */
	{ "NFC LLCP", "nfc-llcp" },

	/* WTAP_ENCAP_NFLOG */
	{ "NFLOG", "nflog" },

	/* WTAP_ENCAP_V5_EF */
	{ "V5 Envelope Function", "v5-ef" },

	/* WTAP_ENCAP_BACNET_MS_TP_WITH_PHDR */
	{ "BACnet MS/TP with Directional Info", "bacnet-ms-tp-with-direction" },

	/* WTAP_ENCAP_IXVERIWAVE */
	{ "IxVeriWave header and stats block", "ixveriwave" },

	/* WTAP_ENCAP_SDH */
	{ "SDH", "sdh" },

	/* WTAP_ENCAP_DBUS */
	{ "D-Bus", "dbus" },

	/* WTAP_ENCAP_AX25_KISS */
	{ "AX.25 with KISS header", "ax25-kiss" },

	/* WTAP_ENCAP_AX25 */
	{ "Amateur Radio AX.25", "ax25" },

	/* WTAP_ENCAP_SCTP */
	{ "SCTP", "sctp" },

	/* WTAP_ENCAP_INFINIBAND */
	{ "InfiniBand", "infiniband" },

	/* WTAP_ENCAP_JUNIPER_SVCS */
	{ "Juniper Services", "juniper-svcs" },

	/* WTAP_ENCAP_USBPCAP */
	{ "USB packets with USBPcap header", "usb-usbpcap" },

	/* WTAP_ENCAP_RTAC_SERIAL */
	{ "RTAC serial-line", "rtac-serial" },

	/* WTAP_ENCAP_BLUETOOTH_LE_LL */
	{ "Bluetooth Low Energy Link Layer", "bluetooth-le-ll" },

	/* WTAP_ENCAP_WIRESHARK_UPPER_PDU */
	{ "Wireshark Upper PDU export", "wireshark-upper-pdu" },

	/* WTAP_ENCAP_STANAG_4607 */
	{ "STANAG 4607", "s4607" },

	/* WTAP_ENCAP_STANAG_5066_D_PDU */
	{ "STANAG 5066 Data Transfer Sublayer PDUs(D_PDU)", "s5066-dpdu"},

	/* WTAP_ENCAP_NETLINK */
	{ "Linux Netlink", "netlink" },

	/* WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR */
	{ "Bluetooth Linux Monitor", "bluetooth-linux-monitor" },

	/* WTAP_ENCAP_BLUETOOTH_BREDR_BB */
	{ "Bluetooth BR/EDR Baseband RF", "bluetooth-bredr-bb-rf" },

	/* WTAP_ENCAP_BLUETOOTH_LE_LL_WITH_PHDR */
	{ "Bluetooth Low Energy Link Layer RF", "bluetooth-le-ll-rf" },

	/* WTAP_ENCAP_NSTRACE_3_0 */
	{ "NetScaler Encapsulation 3.0 of Ethernet", "nstrace30" },

	/* WTAP_ENCAP_LOGCAT */
	{ "Android Logcat Binary format", "logcat" },

	/* WTAP_ENCAP_LOGCAT_BRIEF */
	{ "Android Logcat Brief text format", "logcat_brief" },

	/* WTAP_ENCAP_LOGCAT_PROCESS */
	{ "Android Logcat Process text format", "logcat_process" },

	/* WTAP_ENCAP_LOGCAT_TAG */
	{ "Android Logcat Tag text format", "logcat_tag" },

	/* WTAP_ENCAP_LOGCAT_THREAD */
	{ "Android Logcat Thread text format", "logcat_thread" },

	/* WTAP_ENCAP_LOGCAT_TIME */
	{ "Android Logcat Time text format", "logcat_time" },

	/* WTAP_ENCAP_LOGCAT_THREADTIME */
	{ "Android Logcat Threadtime text format", "logcat_threadtime" },

	/* WTAP_ENCAP_LOGCAT_LONG */
	{ "Android Logcat Long text format", "logcat_long" },

	/* WTAP_ENCAP_PKTAP */
	{ "Apple PKTAP", "pktap" },

	/* WTAP_ENCAP_EPON */
	{ "Ethernet Passive Optical Network", "epon" },

	/* WTAP_ENCAP_IPMI_TRACE */
	{ "IPMI Trace Data Collection", "ipmi-trace" },

	/* WTAP_ENCAP_LOOP */
	{ "OpenBSD loopback", "loop" },

	/* WTAP_ENCAP_JSON */
	{ "JavaScript Object Notation", "json" },

	/* WTAP_ENCAP_NSTRACE_3_5 */
	{ "NetScaler Encapsulation 3.5 of Ethernet", "nstrace35" },

	/* WTAP_ENCAP_ISO14443 */
	{ "ISO 14443 contactless smartcard standards", "iso14443" },

	/* WTAP_ENCAP_GFP_T */
	{ "ITU-T G.7041/Y.1303 Generic Framing Procedure Transparent mode", "gfp-t" },

	/* WTAP_ENCAP_GFP_F */
	{ "ITU-T G.7041/Y.1303 Generic Framing Procedure Frame-mapped mode", "gfp-f" },

	/* WTAP_ENCAP_IP_OVER_IB_PCAP */
	{ "IP over IB", "ip-ib" },

	/* WTAP_ENCAP_JUNIPER_VN */
	{ "Juniper VN", "juniper-vn" },
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

int wtap_get_num_encap_types(void) {
	return wtap_num_encap_types;
}


int wtap_register_encap_type(const char* name, const char* short_name) {
	struct encap_type_info e;

	e.name = g_strdup(name);
	e.short_name = g_strdup(short_name);

	g_array_append_val(encap_table_arr,e);

	return wtap_num_encap_types++;
}


/* Name that should be somewhat descriptive. */
const char *
wtap_encap_string(int encap)
{
	if (encap < WTAP_ENCAP_PER_PACKET || encap >= WTAP_NUM_ENCAP_TYPES)
		return "Illegal";
	else if (encap == WTAP_ENCAP_PER_PACKET)
		return "Per packet";
	else
		return encap_table_entry(encap).name;
}

/* Name to use in, say, a command-line flag specifying the type. */
const char *
wtap_encap_short_string(int encap)
{
	if (encap < WTAP_ENCAP_PER_PACKET || encap >= WTAP_NUM_ENCAP_TYPES)
		return "illegal";
	else if (encap == WTAP_ENCAP_PER_PACKET)
		return "per-packet";
	else
		return encap_table_entry(encap).short_name;
}

/* Translate a short name to a capture file type. */
int
wtap_short_string_to_encap(const char *short_name)
{
	int encap;

	for (encap = 0; encap < WTAP_NUM_ENCAP_TYPES; encap++) {
		if (encap_table_entry(encap).short_name != NULL &&
		    strcmp(short_name, encap_table_entry(encap).short_name) == 0)
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
	"That record can't be written in that format"
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
			g_snprintf(errbuf, 128, "Error %d", err);
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

	if (wth->frame_buffer) {
		ws_buffer_free(wth->frame_buffer);
		g_free(wth->frame_buffer);
		wth->frame_buffer = NULL;
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

	if (wth->priv != NULL)
		g_free(wth->priv);

	if (wth->fast_seek != NULL) {
		g_ptr_array_foreach(wth->fast_seek, g_fast_seek_item_free, NULL);
		g_ptr_array_free(wth->fast_seek, TRUE);
	}

	wtap_block_array_free(wth->shb_hdrs);
	wtap_block_array_free(wth->nrb_hdrs);
	wtap_block_array_free(wth->interface_data);

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

gboolean
wtap_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
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
	wth->phdr.pkt_encap = wth->file_encap;
	wth->phdr.pkt_tsprec = wth->file_tsprec;

	*err = 0;
	*err_info = NULL;
	if (!wth->subtype_read(wth, err, err_info, data_offset)) {
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
		return FALSE;	/* failure */
	}

	/*
	 * It makes no sense for the captured data length to be bigger
	 * than the actual data length.
	 */
	if (wth->phdr.caplen > wth->phdr.len)
		wth->phdr.caplen = wth->phdr.len;

	/*
	 * Make sure that it's not WTAP_ENCAP_PER_PACKET, as that
	 * probably means the file has that encapsulation type
	 * but the read routine didn't set this packet's
	 * encapsulation type.
	 */
	g_assert(wth->phdr.pkt_encap != WTAP_ENCAP_PER_PACKET);

	return TRUE;	/* success */
}

/*
 * Read a given number of bytes from a file.
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
 * Read a given number of bytes from a file.
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

struct wtap_pkthdr *
wtap_phdr(wtap *wth)
{
	return &wth->phdr;
}

guint8 *
wtap_buf_ptr(wtap *wth)
{
	return ws_buffer_start_ptr(wth->frame_buffer);
}

void
wtap_phdr_init(struct wtap_pkthdr *phdr)
{
	memset(phdr, 0, sizeof(struct wtap_pkthdr));
	ws_buffer_init(&phdr->ft_specific_data, 0);
}

void
wtap_phdr_cleanup(struct wtap_pkthdr *phdr)
{
	ws_buffer_free(&phdr->ft_specific_data);
}

gboolean
wtap_seek_read(wtap *wth, gint64 seek_off,
	struct wtap_pkthdr *phdr, Buffer *buf, int *err, gchar **err_info)
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
	phdr->pkt_encap = wth->file_encap;
	phdr->pkt_tsprec = wth->file_tsprec;

	if (!wth->subtype_seek_read(wth, seek_off, phdr, buf, err, err_info))
		return FALSE;

	/*
	 * It makes no sense for the captured data length to be bigger
	 * than the actual data length.
	 */
	if (phdr->caplen > phdr->len)
		phdr->caplen = phdr->len;

	/*
	 * Make sure that it's not WTAP_ENCAP_PER_PACKET, as that
	 * probably means the file has that encapsulation type
	 * but the read routine didn't set this packet's
	 * encapsulation type.
	 */
	g_assert(phdr->pkt_encap != WTAP_ENCAP_PER_PACKET);

	return TRUE;
}

/*
 * Initialize the library.
 */
void
wtap_init(void)
{
	init_open_routines();
	wtap_opttypes_initialize();
	wtap_init_encap_types();
#ifdef HAVE_PLUGINS
	wtap_register_plugin_types();
#endif
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
