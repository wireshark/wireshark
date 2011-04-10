/* wtap.c
 *
 * $Id$
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <errno.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_LIBZ
#include <zlib.h>
#endif

#include "wtap-int.h"

#include "file_wrappers.h"
#include <wsutil/file_util.h>
#include "buffer.h"

/*
 * Return the size of the file, as reported by the OS.
 * (gint64, in case that's 64 bits.)
 */
gint64
wtap_file_size(wtap *wth, int *err)
{
	struct stat statb;

	if (fstat(wth->fd, &statb) == -1) {
		if (err != NULL)
			*err = errno;
		return -1;
	}
	return statb.st_size;
}

int
wtap_file_type(wtap *wth)
{
	return wth->file_type;
}

int
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
wtap_file_tsprecision(wtap *wth)
{
	return wth->tsprecision;
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
	{ "NULL", "null" },

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

	/* WTAP_ENCAP_PRISM_HEADER */
	{ "IEEE 802.11 plus Prism II monitor mode header", "prism" },

	/* WTAP_ENCAP_IEEE_802_11_WITH_RADIO */
	{ "IEEE 802.11 Wireless LAN with radio information", "ieee-802-11-radio" },

	/* WTAP_ENCAP_IEEE_802_11_WLAN_RADIOTAP */
	{ "IEEE 802.11 plus radiotap WLAN header", "ieee-802-11-radiotap" },

	/* WTAP_ENCAP_IEEE_802_11_WLAN_AVS */
	{ "IEEE 802.11 plus AVS WLAN header", "ieee-802-11-avs" },

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
	{ "X25 with nettl headers", "x25-nettl" },

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
	{ "LAPD", "lapd" },

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
	{ "Endace Record File", "erf" },

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

	/* WTAP_ENCAP_IEEE802_11_NETMON_RADIO */
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
	{ "Lapd header", "lapd" },

	/* WTAP_ENCAP_DVBCI */
	{ "DVB-CI (Common Interface)", "dvbci"}
};

gint wtap_num_encap_types = sizeof(encap_table_base) / sizeof(struct encap_type_info);
static GArray* encap_table_arr = NULL;
static const struct encap_type_info* encap_table = NULL;

static void wtap_init_encap_types(void) {

	if (encap_table_arr) return;

	encap_table_arr = g_array_new(FALSE,TRUE,sizeof(struct encap_type_info));

	g_array_append_vals(encap_table_arr,encap_table_base,wtap_num_encap_types);

	encap_table = (void*)encap_table_arr->data;
}

int wtap_get_num_encap_types(void) {
	wtap_init_encap_types();
	return wtap_num_encap_types;
}


int wtap_register_encap_type(char* name, char* short_name) {
	struct encap_type_info e;
	wtap_init_encap_types();

	e.name = g_strdup(name);
	e.short_name = g_strdup(short_name);

	g_array_append_val(encap_table_arr,e);

	encap_table = (void*)encap_table_arr->data;

	return wtap_num_encap_types++;
}


/* Name that should be somewhat descriptive. */
const char
*wtap_encap_string(int encap)
{
	if (encap < WTAP_ENCAP_PER_PACKET || encap >= WTAP_NUM_ENCAP_TYPES)
		return "Illegal";
	else if (encap == WTAP_ENCAP_PER_PACKET)
		return "Per packet";
	else
		return encap_table[encap].name;
}

/* Name to use in, say, a command-line flag specifying the type. */
const char
*wtap_encap_short_string(int encap)
{
	if (encap < WTAP_ENCAP_PER_PACKET || encap >= WTAP_NUM_ENCAP_TYPES)
		return "illegal";
	else if (encap == WTAP_ENCAP_PER_PACKET)
		return "per-packet";
	else
		return encap_table[encap].short_name;
}

/* Translate a short name to a capture file type. */
int
wtap_short_string_to_encap(const char *short_name)
{
	int encap;

	for (encap = 0; encap < WTAP_NUM_ENCAP_TYPES; encap++) {
		if (encap_table[encap].short_name != NULL &&
		    strcmp(short_name, encap_table[encap].short_name) == 0)
			return encap;
	}
	return -1;	/* no such encapsulation type */
}

static const char *wtap_errlist[] = {
	"The file isn't a plain file or pipe",
	"The file is being opened for random access but is a pipe",
	"The file isn't a capture file in a known format",
	"File contains record data we don't support",
	"That file format cannot be written to a pipe",
	NULL,
	"Files can't be saved in that format",
	"Files from that network type can't be saved in that format",
	"That file format doesn't support per-packet encapsulations",
	NULL,
	NULL,
	"Less data was read than was expected",
	"File contains a record that's not valid",
	"Less data was written than was requested",
	"Uncompression error: data oddly truncated",
	"Uncompression error: data would overflow buffer",
	"Uncompression error: bad LZ77 offset",
	"The standard input cannot be opened for random access"
};
#define	WTAP_ERRLIST_SIZE	(sizeof wtap_errlist / sizeof wtap_errlist[0])

const char
*wtap_strerror(int err)
{
	static char errbuf[128];
	unsigned int wtap_errlist_index;

	if (err < 0) {
#ifdef HAVE_LIBZ
		if (err >= WTAP_ERR_ZLIB_MIN && err <= WTAP_ERR_ZLIB_MAX) {
			/* Assume it's a zlib error. */
			g_snprintf(errbuf, 128, "Uncompression error: %s",
			    zError(err - WTAP_ERR_ZLIB));
			return errbuf;
		}
#endif
		wtap_errlist_index = -1 - err;
		if (wtap_errlist_index >= WTAP_ERRLIST_SIZE) {
			g_snprintf(errbuf, 128, "Error %d", err);
			return errbuf;
		}
		if (wtap_errlist[wtap_errlist_index] == NULL)
			return "Unknown reason";
		return wtap_errlist[wtap_errlist_index];
	} else
		return strerror(err);
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
		buffer_free(wth->frame_buffer);
		g_free(wth->frame_buffer);
		wth->frame_buffer = NULL;
	}
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

	g_free(wth);
}

void
wtap_cleareof(wtap *wth _U_) {
	/* Reset EOF */
	if (file_eof(wth->fh))
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
	 */
	wth->phdr.pkt_encap = wth->file_encap;

	if (!wth->subtype_read(wth, err, err_info, data_offset))
		return FALSE;	/* failure */

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
 * Return an approximation of the amount of data we've read sequentially
 * from the file so far.  (gint64, in case that's 64 bits.)
 */
gint64
wtap_read_so_far(wtap *wth, int *err)
{
	gint64 file_pos;

	file_pos = ws_lseek64(wth->fd, 0, SEEK_CUR);
	if (file_pos == -1) {
		if (err != NULL)
			*err = errno;
		return -1;
	}
	return file_pos;
}

struct wtap_pkthdr*
wtap_phdr(wtap *wth)
{
	return &wth->phdr;
}

union wtap_pseudo_header*
wtap_pseudoheader(wtap *wth)
{
	return &wth->pseudo_header;
}

guint8*
wtap_buf_ptr(wtap *wth)
{
	return buffer_start_ptr(wth->frame_buffer);
}

gboolean
wtap_seek_read(wtap *wth, gint64 seek_off,
	union wtap_pseudo_header *pseudo_header, guint8 *pd, int len,
	int *err, gchar **err_info)
{
	return wth->subtype_seek_read(wth, seek_off, pseudo_header, pd, len,
		err, err_info);
}
