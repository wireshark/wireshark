/* libpcap.c
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "atm.h"
#include "erf.h"
#include "libpcap.h"

/*
 * Various pseudo-headers that appear at the beginning of packet data.
 *
 * We represent them as sets of offsets, as they might not be aligned on
 * an appropriate structure boundary in the buffer, and as that makes them
 * independent of the way the compiler might align fields.
 */

/*
 * The link-layer header on SunATM packets.
 */
#define SUNATM_FLAGS	0	/* destination and traffic type - 1 byte */
#define SUNATM_VPI	1	/* VPI - 1 byte */
#define SUNATM_VCI	2	/* VCI - 2 bytes */
#define SUNATM_LEN	4	/* length of the header */

/*
 * The link-layer header on Nokia IPSO ATM packets.
 */
#define NOKIAATM_FLAGS	0	/* destination - 1 byte */
#define NOKIAATM_VPI	1	/* VPI - 1 byte */
#define NOKIAATM_VCI	2	/* VCI - 2 bytes */
#define NOKIAATM_LEN	4	/* length of the header */

/*
 * The fake link-layer header of IrDA packets as introduced by Jean Tourrilhes
 * to libpcap.
 */
#define IRDA_SLL_PKTTYPE_OFFSET		0	/* packet type - 2 bytes */
/* 12 unused bytes */
#define IRDA_SLL_PROTOCOL_OFFSET	14	/* protocol, should be ETH_P_LAPD - 2 bytes */
#define IRDA_SLL_LEN			16	/* length of the header */

/*
 * A header containing additional MTP information.
 */
#define MTP2_SENT_OFFSET		0	/* 1 byte */
#define MTP2_ANNEX_A_USED_OFFSET	1	/* 1 byte */
#define MTP2_LINK_NUMBER_OFFSET		2	/* 2 bytes */
#define MTP2_HDR_LEN			4	/* length of the header */

/*
 * A header containing additional SITA WAN information.
 */
#define SITA_FLAGS_OFFSET		0	/* 1 byte */
#define SITA_SIGNALS_OFFSET		1	/* 1 byte */
#define SITA_ERRORS1_OFFSET		2	/* 1 byte */
#define SITA_ERRORS2_OFFSET		3	/* 1 byte */
#define SITA_PROTO_OFFSET		4	/* 1 byte */
#define SITA_HDR_LEN			5	/* length of the header */

/*
 * The fake link-layer header of LAPD packets.
 */
#ifndef ETH_P_LAPD
#define ETH_P_LAPD 0x0030
#endif

#define LAPD_SLL_PKTTYPE_OFFSET		0	/* packet type - 2 bytes */
#define LAPD_SLL_HATYPE_OFFSET		2	/* hardware address type - 2 bytes */
#define LAPD_SLL_HALEN_OFFSET		4	/* hardware address length - 2 bytes */
#define LAPD_SLL_ADDR_OFFSET		6	/* address - 8 bytes */
#define LAPD_SLL_PROTOCOL_OFFSET	14	/* protocol, should be ETH_P_LAPD - 2 bytes */
#define LAPD_SLL_LEN			16	/* length of the header */

/*
 * I2C link-layer on-disk format
 */
struct i2c_file_hdr {
    guint8 bus;
    guint8 flags[4];
};

/* See source to the "libpcap" library for information on the "libpcap"
   file format. */

/* On some systems, the FDDI MAC addresses are bit-swapped. */
#if !defined(ultrix) && !defined(__alpha) && !defined(__bsdi__)
#define BIT_SWAPPED_MAC_ADDRS
#endif

/* Try to read the first two records of the capture file. */
typedef enum {
	THIS_FORMAT,		/* the reads succeeded, assume it's this format */
	BAD_READ,		/* the file is probably not valid */
	OTHER_FORMAT		/* the file may be valid, but not in this format */
} libpcap_try_t;
static libpcap_try_t libpcap_try(wtap *wth, int *err);

static gboolean libpcap_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset);
static gboolean libpcap_seek_read(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guchar *pd, int length,
    int *err, gchar **err_info);
static int libpcap_read_header(wtap *wth, int *err, gchar **err_info,
    struct pcaprec_ss990915_hdr *hdr);
static void adjust_header(wtap *wth, struct pcaprec_hdr *hdr);
static void libpcap_get_sunatm_pseudoheader(const guint8 *atm_phdr,
    union wtap_pseudo_header *pseudo_header);
static gboolean libpcap_read_sunatm_pseudoheader(FILE_T fh,
    union wtap_pseudo_header *pseudo_header, int *err);
static gboolean libpcap_read_nokiaatm_pseudoheader(FILE_T fh,
    union wtap_pseudo_header *pseudo_header, int *err);
static gboolean libpcap_get_irda_pseudoheader(const guint8 *irda_phdr,
    union wtap_pseudo_header *pseudo_header, int *err, gchar **err_info);
static gboolean libpcap_read_irda_pseudoheader(FILE_T fh,
    union wtap_pseudo_header *pseudo_header, int *err, gchar **err_info);
static gboolean libpcap_get_mtp2_pseudoheader(const guint8 *mtp2_hdr,
    union wtap_pseudo_header *pseudo_header);
static gboolean libpcap_read_mtp2_pseudoheader(FILE_T fh,
    union wtap_pseudo_header *pseudo_header, int *err, gchar **err_info);
static gboolean libpcap_get_sita_pseudoheader(const guint8 *sita_phdr,
    union wtap_pseudo_header *pseudo_header);
static gboolean libpcap_read_sita_pseudoheader(FILE_T fh,
    union wtap_pseudo_header *pseudo_header, int *err, gchar **err_info);
static gboolean libpcap_get_lapd_pseudoheader(const guint8 *lapd_phdr,
    union wtap_pseudo_header *pseudo_header, int *err, gchar **err_info);
static gboolean libpcap_read_lapd_pseudoheader(FILE_T fh,
    union wtap_pseudo_header *pseudo_header, int *err, gchar **err_info);
static gboolean libpcap_read_linux_usb_pseudoheader(wtap *wth, FILE_T fh,
    union wtap_pseudo_header *pseudo_header, int *err);
static gboolean libpcap_read_bt_pseudoheader(FILE_T fh,
    union wtap_pseudo_header *pseudo_header, int *err);
static gboolean libpcap_get_erf_pseudoheader(const guint8 *erf_hdr, struct wtap_pkthdr *whdr,
    union wtap_pseudo_header *pseudo_header);
static gboolean libpcap_read_erf_pseudoheader(FILE_T fh, struct wtap_pkthdr *whdr,
    union wtap_pseudo_header *pseudo_header, int *err, gchar **err_info);
static gboolean libpcap_get_erf_subheader(const guint8 *erf_subhdr,
    union wtap_pseudo_header *pseudo_header, guint * size);
static gboolean libpcap_read_erf_subheader(FILE_T fh,
    union wtap_pseudo_header *pseudo_header, int *err, gchar **err_info _U_, guint * size);
static gboolean libpcap_read_erf_exheader(FILE_T fh,
    union wtap_pseudo_header *pseudo_header, int *err, gchar **err_info _U_, guint * size);
static gboolean libpcap_get_i2c_pseudoheader(const struct i2c_file_hdr *i2c_hdr,
    union wtap_pseudo_header *pseudo_header);
static gboolean libpcap_read_i2c_pseudoheader(FILE_T fh,
    union wtap_pseudo_header *pseudo_header, int *err, gchar **err_info);
static gboolean libpcap_read_rec_data(FILE_T fh, guchar *pd, int length,
    int *err);
static void libpcap_close(wtap *wth);
static gboolean libpcap_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
    const union wtap_pseudo_header *pseudo_header, const guchar *pd, int *err);

/*
 * Either LBL NRG wasn't an adequate central registry (e.g., because of
 * the slow rate of releases from them), or nobody bothered using them
 * as a central registry, as many different groups have patched libpcap
 * (and BPF, on the BSDs) to add new encapsulation types, and have ended
 * up using the same DLT_ values for different encapsulation types.
 *
 * For those numerical encapsulation type values that everybody uses for
 * the same encapsulation type (which inclues those that some platforms
 * specify different DLT_ names for but don't appear to use), we map
 * those values to the appropriate Wiretap values.
 *
 * For those numerical encapsulation type values that different libpcap
 * variants use for different encapsulation types, we check what
 * <pcap.h> defined to determine how to interpret them, so that we
 * interpret them the way the libpcap with which we're building
 * Wireshark/Wiretap interprets them (which, if it doesn't support
 * them at all, means we don't support them either - any capture files
 * using them are foreign, and we don't hazard a guess as to which
 * platform they came from; we could, I guess, choose the most likely
 * platform).
 *
 * Note: if you need a new encapsulation type for libpcap files, do
 * *N*O*T* use *ANY* of the values listed here!  I.e., do *NOT*
 * add a new encapsulation type by changing an existing entry;
 * leave the existing entries alone.
 *
 * Instead, send mail to tcpdump-workers@lists.tcpdump.org, asking for
 * a new DLT_ value, and specifying the purpose of the new value.  When
 * you get the new DLT_ value, use that numerical value in the "dlt_value"
 * field of "pcap_to_wtap_map[]".
 */

static const struct {
	int	dlt_value;
	int	wtap_encap_value;
} pcap_to_wtap_map[] = {
	/*
	 * These are the values that are almost certainly the same
	 * in all libpcaps (I've yet to find one where the values
	 * in question are used for some purpose other than the
	 * one below, but...), and that Wiretap and Wireshark
	 * currently support.
	 */
	{ 0,		WTAP_ENCAP_NULL },	/* null encapsulation */
	{ 1,		WTAP_ENCAP_ETHERNET },
	{ 6,		WTAP_ENCAP_TOKEN_RING },	/* IEEE 802 Networks - assume token ring */
	{ 7,		WTAP_ENCAP_ARCNET },
	{ 8,		WTAP_ENCAP_SLIP },
	{ 9,		WTAP_ENCAP_PPP },
#ifdef BIT_SWAPPED_MAC_ADDRS
	{ 10,		WTAP_ENCAP_FDDI_BITSWAPPED },
#else
	{ 10,		WTAP_ENCAP_FDDI },
#endif

	{ 32,		WTAP_ENCAP_REDBACK },

	/*
	 * 50 is DLT_PPP_SERIAL in NetBSD; it appears that DLT_PPP
	 * on BSD (at least according to standard tcpdump) has, as
	 * the first octet, an indication of whether the packet was
	 * transmitted or received (rather than having the standard
	 * PPP address value of 0xff), but that DLT_PPP_SERIAL puts
	 * a real live PPP header there, or perhaps a Cisco PPP header
	 * as per section 4.3.1 of RFC 1547 (implementations of this
	 * exist in various BSDs in "sys/net/if_spppsubr.c", and
	 * I think also exist either in standard Linux or in
	 * various Linux patches; the implementations show how to handle
	 * Cisco keepalive packets).
	 *
	 * However, I don't see any obvious place in FreeBSD "if_ppp.c"
	 * where anything other than the standard PPP header would be
	 * passed up.  I see some stuff that sets the first octet
	 * to 0 for incoming and 1 for outgoing packets before applying
	 * a BPF filter to see whether to drop packets whose protocol
	 * field has the 0x8000 bit set, i.e. network control protocols -
	 * those are handed up to userland - but that code puts the
	 * address field back before passing the packet up.
	 *
	 * I also don't see anything immediately obvious that munges
	 * the address field for sync PPP, either.
	 *
	 * Wireshark currently assumes that if the first octet of a
	 * PPP frame is 0xFF, it's the address field and is followed
	 * by a control field and a 2-byte protocol, otherwise the
	 * address and control fields are absent and the frame begins
	 * with a protocol field.  If we ever see a BSD/OS PPP
	 * capture, we'll have to handle it differently, and we may
	 * have to handle standard BSD captures differently if, in fact,
	 * they don't have 0xff 0x03 as the first two bytes - but, as per
	 * the two paragraphs preceding this, it's not clear that
	 * the address field *is* munged into an incoming/outgoing
	 * field when the packet is handed to the BPF device.
	 *
	 * For now, we just map DLT_PPP_SERIAL to WTAP_ENCAP_PPP, as
	 * we treat WTAP_ENCAP_PPP packets as if those beginning with
	 * 0xff have the standard RFC 1662 "PPP in HDLC-like Framing"
	 * 0xff 0x03 address/control header, and DLT_PPP_SERIAL frames
	 * appear to contain that unless they're Cisco frames (if we
	 * ever see a capture with them, we'd need to implement the
	 * RFC 1547 stuff, and the keepalive protocol stuff).
	 *
	 * We may have to distinguish between "PPP where if it doesn't
	 * begin with 0xff there's no HDLC encapsulation and the frame
	 * begins with the protocol field" (which is how we handle
	 * WTAP_ENCAP_PPP now) and "PPP where there's either HDLC
	 * encapsulation or Cisco PPP" (which is what DLT_PPP_SERIAL
	 * is) at some point.
	 *
	 * XXX - NetBSD has DLT_HDLC, which appears to be used for
	 * Cisco HDLC.  Ideally, they should use DLT_PPP_SERIAL
	 * only for real live HDLC-encapsulated PPP, not for Cisco
	 * HDLC.
	 */
	{ 50,		WTAP_ENCAP_PPP },

	/*
	 * Apparently used by the Axent Raptor firewall (now Symantec
	 * Enterprise Firewall).
	 * Thanks, Axent, for not reserving that type with tcpdump.org
	 * and not telling anybody about it.
	 */
	{ 99,		WTAP_ENCAP_SYMANTEC },

	/*
	 * These are the values that libpcap 0.5 and later use in
	 * capture file headers, in an attempt to work around the
	 * confusion decried above, and that Wiretap and Wireshark
	 * currently support.
	 */
	{ 100,		WTAP_ENCAP_ATM_RFC1483 },
	{ 101,		WTAP_ENCAP_RAW_IP },
#if 0
	/*
	 * More values used by libpcap 0.5 as DLT_ values and used by the
	 * current CVS version of libpcap in capture file headers.
	 * They are not yet handled in Wireshark.
	 * If we get a capture that contains them, we'll implement them.
	 */
	{ 102,		WTAP_ENCAP_SLIP_BSDOS },
	{ 103,		WTAP_ENCAP_PPP_BSDOS },
#endif

	/*
	 * These ones are handled in Wireshark, though.
	 */
	{ 104,		WTAP_ENCAP_CHDLC },	/* Cisco HDLC */
	{ 105,		WTAP_ENCAP_IEEE_802_11 }, /* IEEE 802.11 */
	{ 106,		WTAP_ENCAP_LINUX_ATM_CLIP },
	{ 107,		WTAP_ENCAP_FRELAY },	/* Frame Relay */
	{ 108,		WTAP_ENCAP_NULL },	/* OpenBSD loopback */
	{ 109,		WTAP_ENCAP_ENC },	/* OpenBSD IPSEC enc */
#if 0
	{ 110,		WTAP_ENCAP_LANE_802_3 },/* ATM LANE 802.3 */
	{ 111,		WTAP_ENCAP_HIPPI },	/* NetBSD HIPPI */
#endif
	{ 112,		WTAP_ENCAP_CHDLC },	/* NetBSD HDLC framing */

	/*
	 * Linux "cooked mode" captures, used by the current CVS version
	 * of libpcap
         * OR
         * it could be a packet in Cisco's ERSPAN encapsulation which uses
         * this number as well (why can't people stick to protocols when it
         * comes to allocating/using DLT types).
	 */
	{ 113,		WTAP_ENCAP_SLL },	/* Linux cooked capture */

	{ 114,		WTAP_ENCAP_LOCALTALK },	/* Localtalk */

	/*
	 * The tcpdump.org version of libpcap uses 117, rather than 17,
	 * for OpenBSD packet filter logging, so as to avoid conflicting
	 * with DLT_LANE8023 in SuSE 6.3 libpcap.
	 */
	{ 117,		WTAP_ENCAP_PFLOG },

	{ 118,		WTAP_ENCAP_CISCO_IOS },
	{ 119,		WTAP_ENCAP_PRISM_HEADER }, /* Prism monitor mode hdr */
	{ 121,		WTAP_ENCAP_HHDLC },	/* HiPath HDLC */
	{ 122,		WTAP_ENCAP_IP_OVER_FC },   /* RFC 2625 IP-over-FC */
	{ 123,		WTAP_ENCAP_ATM_PDUS },  /* SunATM */
	{ 127,		WTAP_ENCAP_IEEE_802_11_WLAN_RADIOTAP },  /* 802.11 plus radiotap WLAN header */
	{ 128,		WTAP_ENCAP_TZSP },	/* Tazmen Sniffer Protocol */
	{ 129,		WTAP_ENCAP_ARCNET_LINUX },
        { 130,          WTAP_ENCAP_JUNIPER_MLPPP }, /* Juniper MLPPP on ML-, LS-, AS- PICs */
        { 131,          WTAP_ENCAP_JUNIPER_MLFR }, /* Juniper MLFR (FRF.15) on ML-, LS-, AS- PICs */
        { 133,          WTAP_ENCAP_JUNIPER_GGSN},
	/*
	 * Values 132-134, 136 not listed here are reserved for use
	 * in Juniper hardware.
	 */
	{ 135,		WTAP_ENCAP_JUNIPER_ATM2 }, /* various encapsulations captured on the ATM2 PIC */
	{ 137,		WTAP_ENCAP_JUNIPER_ATM1 }, /* various encapsulations captured on the ATM1 PIC */

	{ 138,		WTAP_ENCAP_APPLE_IP_OVER_IEEE1394 },
						/* Apple IP-over-IEEE 1394 */

	{ 139,		WTAP_ENCAP_MTP2_WITH_PHDR },
	{ 140,		WTAP_ENCAP_MTP2 },
	{ 141,		WTAP_ENCAP_MTP3 },
	{ 142,		WTAP_ENCAP_SCCP },
	{ 143,		WTAP_ENCAP_DOCSIS },
	{ 144,		WTAP_ENCAP_IRDA },	/* IrDA capture */

	/* Reserved for private use. */
	{ 147,		WTAP_ENCAP_USER0 },
	{ 148,		WTAP_ENCAP_USER1 },
	{ 149,		WTAP_ENCAP_USER2 },
	{ 150,		WTAP_ENCAP_USER3 },
	{ 151,		WTAP_ENCAP_USER4 },
	{ 152,		WTAP_ENCAP_USER5 },
	{ 153,		WTAP_ENCAP_USER6 },
	{ 154,		WTAP_ENCAP_USER7 },
	{ 155,		WTAP_ENCAP_USER8 },
	{ 156,		WTAP_ENCAP_USER9 },
	{ 157,		WTAP_ENCAP_USER10 },
	{ 158,		WTAP_ENCAP_USER11 },
	{ 159,		WTAP_ENCAP_USER12 },
	{ 160,		WTAP_ENCAP_USER13 },
	{ 161,		WTAP_ENCAP_USER14 },
	{ 162,		WTAP_ENCAP_USER15 },

	{ 163,		WTAP_ENCAP_IEEE_802_11_WLAN_AVS },  /* 802.11 plus AVS WLAN header */

	/*
	 * 164 is reserved for Juniper-private chassis-internal
	 * meta-information such as QoS profiles, etc..
	 */

	{ 165,		WTAP_ENCAP_BACNET_MS_TP },

	/*
	 * 166 is reserved for a PPP variant in which the first byte
	 * of the 0xff03 header, the 0xff, is replaced by a direction
	 * byte.  I don't know whether any captures look like that,
	 * but it is used for some Linux IP filtering (ipfilter?).
	 */

        /* Ethernet PPPoE frames captured on a service PIC */
        { 167,          WTAP_ENCAP_JUNIPER_PPPOE },

        /*
	 * 168 is reserved for more Juniper private-chassis-
	 * internal meta-information.
	 */

	{ 169,		WTAP_ENCAP_GPRS_LLC },

	/*
	 * 170 and 171 are reserved for ITU-T G.7041/Y.1303 Generic
	 * Framing Procedure.
	 */

	/* Registered by Gcom, Inc. */
	{ 172,		WTAP_GCOM_TIE1 },
	{ 173,		WTAP_GCOM_SERIAL },

	{ 177,		WTAP_ENCAP_LINUX_LAPD },

        /* Ethernet frames prepended with meta-information */
        { 178,          WTAP_ENCAP_JUNIPER_ETHER },
        /* PPP frames prepended with meta-information */
        { 179,          WTAP_ENCAP_JUNIPER_PPP },
        /* Frame-Relay frames prepended with meta-information */
        { 180,          WTAP_ENCAP_JUNIPER_FRELAY },
        /* C-HDLC frames prepended with meta-information */
        { 181,          WTAP_ENCAP_JUNIPER_CHDLC },
        /* VOIP Frames prepended with meta-information */
        { 183,          WTAP_ENCAP_JUNIPER_VP },
	/* raw USB packets */
	{ 186, 		WTAP_ENCAP_USB },
	/* Bluetooth HCI UART transport (part H:4) frames, like hcidump */
	{ 187, 		WTAP_ENCAP_BLUETOOTH_H4 },
	/* IEEE 802.16 MAC Common Part Sublayer */
	{ 188,		WTAP_ENCAP_IEEE802_16_MAC_CPS },
	/* USB packets with Linux-specified header */
	{ 189, 		WTAP_ENCAP_USB_LINUX },
	/* CAN 2.0b frame */
	{ 190, 		WTAP_ENCAP_CAN20B },
        /* Per-Packet Information header */
        { 192,          WTAP_ENCAP_PPI },
	/* IEEE 802.15.4 Wireless PAN */
	{ 195,		WTAP_ENCAP_IEEE802_15_4 },
	/* SITA File Encapsulation */
	{ 196,	        WTAP_ENCAP_SITA },
	/* Endace Record File Encapsulation */
	{ 197,	        WTAP_ENCAP_ERF },
	/* IPMB */
	{ 199,		WTAP_ENCAP_IPMB },
	/* Bluetooth HCI UART transport (part H:4) frames, like hcidump */
	{ 201, 		WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR },
	/* IPMB/I2C */
	{ 209,		WTAP_ENCAP_I2C },
	/* FlexRay frame */
	{ 210, 		WTAP_ENCAP_FLEXRAY },
	/* MOST frame */
	{ 211, 		WTAP_ENCAP_MOST },
	/* LIN frame */
	{ 212, 		WTAP_ENCAP_LIN },
	/* X2E Xoraya serial frame */
	{ 213, 		WTAP_ENCAP_X2E_SERIAL },
	/* X2E Xoraya frame */
	{ 214, 		WTAP_ENCAP_X2E_XORAYA },
	/* IEEE 802.15.4 Wireless PAN non-ASK PHY */
	{ 215,		WTAP_ENCAP_IEEE802_15_4_NONASK_PHY },

	/*
	 * To repeat:
	 *
	 * If you need a new encapsulation type for libpcap files, do
	 * *N*O*T* use *ANY* of the values listed here!  I.e., do *NOT*
	 * add a new encapsulation type by changing an existing entry;
	 * leave the existing entries alone.
	 *
	 * Instead, send mail to tcpdump-workers@lists.tcpdump.org, asking
	 * for a new DLT_ value, and specifying the purpose of the new value.
	 * When you get the new DLT_ value, use that numerical value in
	 * the "dlt_value" field of "pcap_to_wtap_map[]".
	 */

	/*
	 * The following are entries for libpcap type values that have
	 * different meanings on different OSes.
	 *
	 * We put these *after* the entries for the platform-independent
	 * libpcap type values for those Wiretap encapsulation types, so
	 * that Wireshark chooses the platform-independent libpcap type
	 * value for those encapsulatioin types, not the platform-dependent
	 * one.
	 */

	/*
	 * 11 is DLT_ATM_RFC1483 on most platforms; the only libpcaps I've
	 * seen that define anything other than DLT_ATM_RFC1483 as 11 are
	 * the BSD/OS one, which defines DLT_FR as 11, and libpcap 0.5,
	 * which define it as 100, mapping the kernel's value to 100, in
	 * an attempt to hide the different values used on different
	 * platforms.
	 *
	 * If this is a platform where DLT_FR is defined as 11, we
	 * don't handle 11 at all; otherwise, we handle it as
	 * DLT_ATM_RFC1483 (this means we'd misinterpret Frame Relay
	 * captures from BSD/OS if running on platforms other than BSD/OS,
	 * but
	 *
	 *	1) we don't yet support DLT_FR
	 *
	 * and
	 *
	 *	2) nothing short of a heuristic would let us interpret
	 *	   them correctly).
	 */
#if defined(DLT_FR) && (DLT_FR == 11)
	{ 11,		WTAP_ENCAP_FRELAY },
#else
	{ 11,		WTAP_ENCAP_ATM_RFC1483 },
#endif

	/*
	 * 12 is DLT_RAW on most platforms, but it's DLT_C_HDLC on
	 * BSD/OS, and DLT_LOOP on OpenBSD.
	 *
	 * We don't yet handle DLT_C_HDLC, but we can handle DLT_LOOP
	 * (it's just like DLT_NULL, only with the AF_ value in network
	 * rather than host byte order - Wireshark figures out the
	 * byte order from the data, so we don't care what byte order
	 * it's in), so if DLT_LOOP is defined as 12, interpret 12
	 * as WTAP_ENCAP_NULL, otherwise, unless DLT_C_HDLC is defined
	 * as 12, interpret it as WTAP_ENCAP_RAW_IP.
	 */
#if defined(DLT_LOOP) && (DLT_LOOP == 12)
	{ 12,		WTAP_ENCAP_NULL },
#elif defined(DLT_C_HDLC) && (DLT_C_HDLC == 12)
	/*
	 * Put entry for Cisco HDLC here.
	 * XXX - is this just WTAP_ENCAP_CHDLC, i.e. does the frame
	 * start with a 4-byte Cisco HDLC header?
	 */
#else
	{ 12,		WTAP_ENCAP_RAW_IP },
#endif

	/*
	 * 13 is DLT_SLIP_BSDOS on FreeBSD and NetBSD, but those OSes
	 * don't actually generate it.  I infer that BSD/OS translates
	 * DLT_SLIP from the kernel BPF code to DLT_SLIP_BSDOS in
	 * libpcap, as the BSD/OS link-layer header is different;
	 * however, in BSD/OS, DLT_SLIP_BSDOS is 15.
	 *
	 * From this, I infer that there's no point in handling 13
	 * as DLT_SLIP_BSDOS.
	 *
	 * 13 is DLT_ATM_RFC1483 on BSD/OS.
	 *
	 * 13 is DLT_ENC in OpenBSD, which is, I suspect, some kind
	 * of decrypted IPSEC traffic.
	 */
#if defined(DLT_ATM_RFC1483) && (DLT_ATM_RFC1483 == 13)
	{ 13,		WTAP_ENCAP_ATM_RFC1483 },
#elif defined(DLT_ENC) && (DLT_ENC == 13)
	{ 13,		WTAP_ENCAP_ENC },
#endif

	/*
	 * 14 is DLT_PPP_BSDOS on FreeBSD and NetBSD, but those OSes
	 * don't actually generate it.  I infer that BSD/OS translates
	 * DLT_PPP from the kernel BPF code to DLT_PPP_BSDOS in
	 * libpcap, as the BSD/OS link-layer header is different;
	 * however, in BSD/OS, DLT_PPP_BSDOS is 16.
	 *
	 * From this, I infer that there's no point in handling 14
	 * as DLT_PPP_BSDOS.
	 *
	 * 14 is DLT_RAW on BSD/OS and OpenBSD.
	 */
	{ 14,		WTAP_ENCAP_RAW_IP },

	/*
	 * 15 is:
	 *
	 *	DLT_SLIP_BSDOS on BSD/OS;
	 *
	 *	DLT_HIPPI on NetBSD;
	 *
	 *	DLT_LANE8023 with Alexey Kuznetzov's patches for
	 *	Linux libpcap;
	 *
	 *	DLT_I4L_RAWIP with the ISDN4Linux patches for libpcap
	 *	(and on SuSE 6.3);
	 *
	 * but we don't currently handle any of those.
	 */

	/*
	 * 16 is:
	 *
	 *	DLT_PPP_BSDOS on BSD/OS;
	 *
	 *	DLT_HDLC on NetBSD (Cisco HDLC);
	 *
	 *	DLT_CIP with Alexey Kuznetzov's patches for
	 *	Linux libpcap - this is WTAP_ENCAP_LINUX_ATM_CLIP;
	 *
	 *	DLT_I4L_IP with the ISDN4Linux patches for libpcap
	 *	(and on SuSE 6.3).
	 */
#if defined(DLT_CIP) && (DLT_CIP == 16)
	{ 16,		WTAP_ENCAP_LINUX_ATM_CLIP },
#endif
#if defined(DLT_HDLC) && (DLT_HDLC == 16)
	{ 16,		WTAP_ENCAP_CHDLC },
#endif

	/*
	 * 17 is DLT_LANE8023 in SuSE 6.3 libpcap; we don't currently
	 * handle it.
	 * It is also used as the PF (Packet Filter) logging format beginning
	 * with OpenBSD 3.0; we use 17 for PF logs unless DLT_LANE8023 is
	 * defined with the value 17.
	 */
#if !defined(DLT_LANE8023) || (DLT_LANE8023 != 17)
	{ 17,		WTAP_ENCAP_OLD_PFLOG },
#endif

	/*
	 * 18 is DLT_CIP in SuSE 6.3 libpcap; if it's the same as the
	 * DLT_CIP of 16 that the Alexey Kuznetzov patches for
	 * libpcap/tcpdump define, it's WTAP_ENCAP_LINUX_ATM_CLIP.
	 * I've not found any libpcap that uses it for any other purpose -
	 * hopefully nobody will do so in the future.
	 */
	{ 18,		WTAP_ENCAP_LINUX_ATM_CLIP },

	/*
	 * 19 is DLT_ATM_CLIP in the libpcap/tcpdump patches in the
	 * recent versions I've seen of the Linux ATM distribution;
	 * I've not yet found any libpcap that uses it for any other
	 * purpose - hopefully nobody will do so in the future.
	 */
	{ 19,		WTAP_ENCAP_LINUX_ATM_CLIP },

	/*
	 * nettl (HP-UX) mappings to standard DLT values
         */

	{ 1,		WTAP_ENCAP_NETTL_ETHERNET },
	{ 6,		WTAP_ENCAP_NETTL_TOKEN_RING },
	{ 10,		WTAP_ENCAP_NETTL_FDDI },
	{ 70,		WTAP_ENCAP_RAW_IP },
	{ 101,		WTAP_ENCAP_NETTL_RAW_IP },

	/*
	 * To repeat:
	 *
	 * If you need a new encapsulation type for libpcap files, do
	 * *N*O*T* use *ANY* of the values listed here!  I.e., do *NOT*
	 * add a new encapsulation type by changing an existing entry;
	 * leave the existing entries alone.
	 *
	 * Instead, send mail to tcpdump-workers@lists.tcpdump.org, asking
	 * for a new DLT_ value, and specifying the purpose of the new value.
	 * When you get the new DLT_ value, use that numerical value in
	 * the "dlt_value" field of "pcap_to_wtap_map[]".
	 */

};
#define NUM_PCAP_ENCAPS (sizeof pcap_to_wtap_map / sizeof pcap_to_wtap_map[0])

int wtap_pcap_encap_to_wtap_encap(int encap)
{
	unsigned int i;

	for (i = 0; i < NUM_PCAP_ENCAPS; i++) {
		if (pcap_to_wtap_map[i].dlt_value == encap)
			return pcap_to_wtap_map[i].wtap_encap_value;
	}
	return WTAP_ENCAP_UNKNOWN;
}


int libpcap_open(wtap *wth, int *err, gchar **err_info)
{
	int bytes_read;
	guint32 magic;
	struct pcap_hdr hdr;
	gboolean byte_swapped;
	gboolean modified;
	gboolean aix;
	int file_encap;

	/* Read in the number that should be at the start of a "libpcap" file */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&magic, 1, sizeof magic, wth->fh);
	if (bytes_read != sizeof magic) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}
	wth->data_offset += sizeof magic;

	switch (magic) {

	case PCAP_MAGIC:
		/* Host that wrote it has our byte order, and was running
		   a program using either standard or ss990417 libpcap. */
		byte_swapped = FALSE;
		modified = FALSE;
		wth->tsprecision = WTAP_FILE_TSPREC_USEC;
		break;

	case PCAP_MODIFIED_MAGIC:
		/* Host that wrote it has our byte order, and was running
		   a program using either ss990915 or ss991029 libpcap. */
		byte_swapped = FALSE;
		modified = TRUE;
		wth->tsprecision = WTAP_FILE_TSPREC_USEC;
		break;

	case PCAP_SWAPPED_MAGIC:
		/* Host that wrote it has a byte order opposite to ours,
		   and was running a program using either standard or
		   ss990417 libpcap. */
		byte_swapped = TRUE;
		modified = FALSE;
		wth->tsprecision = WTAP_FILE_TSPREC_USEC;
		break;

	case PCAP_SWAPPED_MODIFIED_MAGIC:
		/* Host that wrote it out has a byte order opposite to
		   ours, and was running a program using either ss990915
		   or ss991029 libpcap. */
		byte_swapped = TRUE;
		modified = TRUE;
		wth->tsprecision = WTAP_FILE_TSPREC_USEC;
		break;

	case PCAP_NSEC_MAGIC:
		/* Host that wrote it has our byte order, and was running
		   a program using either standard or ss990417 libpcap. */
		byte_swapped = FALSE;
		modified = FALSE;
		wth->tsprecision = WTAP_FILE_TSPREC_NSEC;
		break;

	case PCAP_SWAPPED_NSEC_MAGIC:
		/* Host that wrote it out has a byte order opposite to
		   ours, and was running a program using either ss990915
		   or ss991029 libpcap. */
		byte_swapped = TRUE;
		modified = FALSE;
		wth->tsprecision = WTAP_FILE_TSPREC_NSEC;
		break;

	default:
		/* Not a "libpcap" type we know about. */
		return 0;
	}

	/* Read the rest of the header. */
	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&hdr, 1, sizeof hdr, wth->fh);
	if (bytes_read != sizeof hdr) {
		*err = file_error(wth->fh);
		if (*err != 0)
			return -1;
		return 0;
	}
	wth->data_offset += sizeof hdr;

	if (byte_swapped) {
		/* Byte-swap the header fields about which we care. */
		hdr.version_major = BSWAP16(hdr.version_major);
		hdr.version_minor = BSWAP16(hdr.version_minor);
		hdr.snaplen = BSWAP32(hdr.snaplen);
		hdr.network = BSWAP32(hdr.network);
	}
	if (hdr.version_major < 2) {
		/* We only support version 2.0 and later. */
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = g_strdup_printf("pcap: major version %u unsupported",
		    hdr.version_major);
		return -1;
	}

	/*
	 * AIX's non-standard tcpdump uses a minor version number of 2.
	 * Unfortunately, older versions of libpcap might have used
	 * that as well.
	 *
	 * The AIX libpcap uses RFC 1573 ifType values rather than
	 * DLT_ values in the header; the ifType values for LAN devices
	 * are:
	 *
	 *	Ethernet	6
	 *	Token Ring	9
	 *	FDDI		15
	 *
	 * which correspond to DLT_IEEE802 (used for Token Ring),
	 * DLT_PPP, and DLT_SLIP_BSDOS, respectively.  The ifType value
	 * for a loopback interface is 24, which currently isn't
	 * used by any version of libpcap I know about (and, as
	 * tcpdump.org are assigning DLT_ values above 100, and
	 * NetBSD started assigning values starting at 50, and
	 * the values chosen by other libpcaps appear to stop at
	 * 19, it's probably not going to be used by any libpcap
	 * in the future).
	 *
	 * We shall assume that if the minor version number is 2, and
	 * the network type is 6, 9, 15, or 24, that it's AIX libpcap.
	 *
	 * I'm assuming those older versions of libpcap didn't
	 * use DLT_IEEE802 for Token Ring, and didn't use DLT_SLIP_BSDOS
	 * as that came later.  It may have used DLT_PPP, however, in
	 * which case we're out of luck; we assume it's Token Ring
	 * in AIX libpcap rather than PPP in standard libpcap, as
	 * you're probably more likely to be handing an AIX libpcap
	 * token-ring capture than an old (pre-libpcap 0.4) PPP capture
	 * to Wireshark.
	 */
	aix = FALSE;	/* assume it's not AIX */
	if (hdr.version_major == 2 && hdr.version_minor == 2) {
		switch (hdr.network) {

		case 6:
			hdr.network = 1;	/* DLT_EN10MB, Ethernet */
			aix = TRUE;
			break;

		case 9:
			hdr.network = 6;	/* DLT_IEEE802, Token Ring */
			aix = TRUE;
			break;

		case 15:
			hdr.network = 10;	/* DLT_FDDI, FDDI */
			aix = TRUE;
			break;

		case 24:
			hdr.network = 0;	/* DLT_NULL, loopback */
			aix = TRUE;
			break;
		}
	}

	/*
	 * We treat a DLT_ value of 13 specially - it appears that in
	 * Nokia libpcap format, it's some form of ATM with what I
	 * suspect is a pseudo-header (even though Nokia's IPSO is
	 * based on FreeBSD, which #defines DLT_SLIP_BSDOS as 13).
	 *
	 * We don't yet know whether this is a Nokia capture, so if
	 * "wtap_pcap_encap_to_wtap_encap()" returned WTAP_ENCAP_UNKNOWN
	 * but "hdr.network" is 13, we don't treat that as an error yet.
	 */
	file_encap = wtap_pcap_encap_to_wtap_encap(hdr.network);
	if (file_encap == WTAP_ENCAP_UNKNOWN && hdr.network != 13) {
		*err = WTAP_ERR_UNSUPPORTED_ENCAP;
		*err_info = g_strdup_printf("pcap: network type %u unknown or unsupported",
		    hdr.network);
		return -1;
	}

	/* This is a libpcap file */
	wth->capture.pcap = g_malloc(sizeof(libpcap_t));
	wth->capture.pcap->byte_swapped = byte_swapped;
	wth->capture.pcap->version_major = hdr.version_major;
	wth->capture.pcap->version_minor = hdr.version_minor;
	wth->subtype_read = libpcap_read;
	wth->subtype_seek_read = libpcap_seek_read;
	wth->subtype_close = libpcap_close;
	wth->file_encap = file_encap;
	wth->snapshot_length = hdr.snaplen;

	/* In file format version 2.3, the order of the "incl_len" and
	   "orig_len" fields in the per-packet header was reversed,
	   in order to match the BPF header layout.

	   Therefore, in files with versions prior to that, we must swap
	   those two fields.

	   Unfortunately, some files were, according to a comment in the
	   "libpcap" source, written with version 2.3 in their headers
	   but without the interchanged fields, so if "incl_len" is
	   greater than "orig_len" - which would make no sense - we
	   assume that we need to swap them in version 2.3 files
	   as well.

	   In addition, DG/UX's tcpdump uses version 543.0, and writes
	   the two fields in the pre-2.3 order. */
	switch (hdr.version_major) {

	case 2:
		if (hdr.version_minor < 3)
			wth->capture.pcap->lengths_swapped = SWAPPED;
		else if (hdr.version_minor == 3)
			wth->capture.pcap->lengths_swapped = MAYBE_SWAPPED;
		else
			wth->capture.pcap->lengths_swapped = NOT_SWAPPED;
		break;

	case 543:
		wth->capture.pcap->lengths_swapped = SWAPPED;
		break;

	default:
		wth->capture.pcap->lengths_swapped = NOT_SWAPPED;
		break;
	}

	/*
	 * Is this AIX format?
	 */
	if (aix) {
		/*
		 * Yes.  Skip all the tests for other mutant formats,
		 * and set the precision to nanosecond precision.
		 */
		wth->file_type = WTAP_FILE_PCAP_AIX;
		wth->tsprecision = WTAP_FILE_TSPREC_NSEC;
		return 1;
	}

	/*
	 * No.  Let's look at the header for the first record,
	 * and see if, interpreting it as a standard header (if the
	 * magic number was standard) or a modified header (if the
	 * magic number was modified), the position where it says the
	 * header for the *second* record is contains a corrupted header.
	 *
	 * If so, then:
	 *
	 *	If this file had the standard magic number, it may be
	 *	an ss990417 capture file - in that version of Alexey's
	 *	patch, the packet header format was changed but the
	 *	magic number wasn't, and, alas, Red Hat appear to have
	 *	picked up that version of the patch for RH 6.1, meaning
	 *	RH 6.1 has a tcpdump that writes out files that can't
	 *	be read by any software that expects non-modified headers
	 *	if the magic number isn't the modified magic number (e.g.,
	 *	any normal version of tcpdump, and Wireshark if we don't
	 *	do this gross heuristic).
	 *
	 *	If this file had the modified magic number, it may be
	 *	an ss990915 capture file - in that version of Alexey's
	 *	patch, the magic number was changed, but the record
	 *	header had some extra fields, and, alas, SuSE appear
	 *	to have picked up that version of the patch for SuSE
	 *	6.3, meaning that programs expecting the standard per-
	 *	packet header in captures with the modified magic number
	 *	can't read dumps from its tcpdump.
	 *
	 * Oh, and if it has the standard magic number, it might, instead,
	 * be a Nokia libpcap file, so we may need to try that if
	 * neither normal nor ss990417 headers work.
	 */
	if (modified) {
		/*
		 * Well, we have the magic number from Alexey's
		 * later two patches.
		 *
		 * Try ss991029, the last of his patches, first.
		 */
		wth->file_type = WTAP_FILE_PCAP_SS991029;
		switch (libpcap_try(wth, err)) {

		case BAD_READ:
			/*
			 * Well, we couldn't even read it.
			 * Give up.
			 */
			g_free(wth->capture.pcap);
			return -1;

		case THIS_FORMAT:
			/*
			 * Well, it looks as if it might be 991029.
			 * Put the seek pointer back, and return success.
			 */
			if (file_seek(wth->fh, wth->data_offset, SEEK_SET, err) == -1) {
				g_free(wth->capture.pcap);
				return -1;
			}
			return 1;

		case OTHER_FORMAT:
			/*
			 * Try the next format.
			 */
			break;
		}

		/*
		 * Well, it's not completely unreadable,
		 * but it's not ss991029.  Try ss990915;
		 * there are no other types to try after that,
		 * so we put the seek pointer back and treat
		 * it as 990915.
		 */
		wth->file_type = WTAP_FILE_PCAP_SS990915;
		if (file_seek(wth->fh, wth->data_offset, SEEK_SET, err) == -1) {
			g_free(wth->capture.pcap);
			return -1;
		}
	} else {
		/*
		 * Well, we have the standard magic number.
		 *
		 * Try the standard format first.
		 */
		if(wth->tsprecision == WTAP_FILE_TSPREC_NSEC) {
			wth->file_type = WTAP_FILE_PCAP_NSEC;
		} else {
			wth->file_type = WTAP_FILE_PCAP;
		}
		switch (libpcap_try(wth, err)) {

		case BAD_READ:
			/*
			 * Well, we couldn't even read it.
			 * Give up.
			 */
			g_free(wth->capture.pcap);
			return -1;

		case THIS_FORMAT:
			/*
			 * Well, it looks as if it might be a standard
			 * libpcap file.
			 * Put the seek pointer back, and return success.
			 */
			if (file_seek(wth->fh, wth->data_offset, SEEK_SET, err) == -1) {
				g_free(wth->capture.pcap);
				return -1;
			}
			return 1;

		case OTHER_FORMAT:
			/*
			 * Try the next format.
			 */
			break;
		}

		/*
		 * Well, it's not completely unreadable, but it's not
		 * a standard file.  Put the seek pointer back and try
		 * ss990417.
		 */
		wth->file_type = WTAP_FILE_PCAP_SS990417;
		if (file_seek(wth->fh, wth->data_offset, SEEK_SET, err) == -1) {
			g_free(wth->capture.pcap);
			return -1;
		}
		switch (libpcap_try(wth, err)) {

		case BAD_READ:
			/*
			 * Well, we couldn't even read it.
			 * Give up.
			 */
			g_free(wth->capture.pcap);
			return -1;

		case THIS_FORMAT:
			/*
			 * Well, it looks as if it might be ss990417.
			 * Put the seek pointer back, and return success.
			 */
			if (file_seek(wth->fh, wth->data_offset, SEEK_SET, err) == -1) {
				g_free(wth->capture.pcap);
				return -1;
			}
			return 1;

		case OTHER_FORMAT:
			/*
			 * Try the next format.
			 */
			break;
		}

		/*
		 * Well, it's not completely unreadable,
		 * but it's not a standard file *nor* is it ss990417.
		 * Try it as a Nokia file; there are no other types
		 * to try after that, so we put the seek pointer back
		 * and treat it as a Nokia file.
		 */
		wth->file_type = WTAP_FILE_PCAP_NOKIA;
		if (file_seek(wth->fh, wth->data_offset, SEEK_SET, err) == -1) {
			g_free(wth->capture.pcap);
			return -1;
		}
	}

	if (hdr.network == 13) {
		/*
		 * OK, if this was a Nokia capture, make it
		 * WTAP_ENCAP_ATM_PDUS, otherwise return
		 * an error.
		 */
		if (wth->file_type == WTAP_FILE_PCAP_NOKIA)
			wth->file_encap = WTAP_ENCAP_ATM_PDUS;
		else {
			*err = WTAP_ERR_UNSUPPORTED_ENCAP;
			*err_info = g_strdup_printf("pcap: network type %u unknown or unsupported",
			    hdr.network);
			g_free(wth->capture.pcap);
			return -1;
		}
	}

	return 1;
}

/* Try to read the first two records of the capture file. */
static libpcap_try_t libpcap_try(wtap *wth, int *err)
{
	/*
	 * pcaprec_ss990915_hdr is the largest header type.
	 */
	struct pcaprec_ss990915_hdr first_rec_hdr, second_rec_hdr;


	/*
	 * Attempt to read the first record's header.
	 */
	if (libpcap_read_header(wth, err, NULL, &first_rec_hdr) == -1) {
		if (*err == 0 || *err == WTAP_ERR_SHORT_READ) {
			/*
			 * EOF or short read - assume the file is in this
			 * format.
			 * When our client tries to read the first packet
			 * they will presumably get the same EOF or short
			 * read.
			 */
			return THIS_FORMAT;
		}

		if (*err == WTAP_ERR_BAD_RECORD) {
			/*
			 * The first record is bogus, so this is probably
			 * a corrupt file.  Assume the file is in this
			 * format.  When our client tries to read the
			 * first packet they will presumably get the
			 * same bogus record.
			 */
			return THIS_FORMAT;
		}

		/*
		 * Some other error, e.g. an I/O error; just give up.
		 */
		return BAD_READ;
	}

	/*
	 * Now skip over the first record's data, under the assumption
	 * that the header is sane.
	 */
	if (file_seek(wth->fh, first_rec_hdr.hdr.incl_len, SEEK_CUR, err) == -1)
		return BAD_READ;

	/*
	 * Now attempt to read the second record's header.
	 */
	if (libpcap_read_header(wth, err, NULL, &second_rec_hdr) == -1) {
		if (*err == 0 || *err == WTAP_ERR_SHORT_READ) {
			/*
			 * EOF or short read - assume the file is in this
			 * format.
			 * When our client tries to read the second packet
			 * they will presumably get the same EOF or short
			 * read.
			 */
			return THIS_FORMAT;
		}

		if (*err == WTAP_ERR_BAD_RECORD) {
			/*
			 * The second record is bogus; maybe it's a
			 * Capture File From Hell, and what looks like
			 * the "header" of the next packet is actually
			 * random junk from the middle of a packet.
			 * Try the next format; if we run out of formats,
			 * it probably *is* a corrupt file.
			 */
			return OTHER_FORMAT;
		}

		/*
		 * Some other error, e.g. an I/O error; just give up.
		 */
		return BAD_READ;
	}

	/*
	 * OK, the first two records look OK; assume this is the
	 * right format.
	 */
	return THIS_FORMAT;
}

/* Read the next packet */
static gboolean libpcap_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset)
{
	struct pcaprec_ss990915_hdr hdr;
	guint packet_size;
	guint orig_size, size;
	int bytes_read;
	guchar fddi_padding[3];

	bytes_read = libpcap_read_header(wth, err, err_info, &hdr);
	if (bytes_read == -1) {
		/*
		 * We failed to read the header.
		 */
		return FALSE;
	}

	wth->data_offset += bytes_read;
	packet_size = hdr.hdr.incl_len;
	orig_size = hdr.hdr.orig_len;

	/*
	 * AIX appears to put 3 bytes of padding in front of FDDI
	 * frames; strip that crap off.
	 */
	if (wth->file_type == WTAP_FILE_PCAP_AIX &&
	    (wth->file_encap == WTAP_ENCAP_FDDI ||
	     wth->file_encap == WTAP_ENCAP_FDDI_BITSWAPPED)) {
		/*
		 * The packet size is really a record size and includes
		 * the padding.
		 */
		packet_size -= 3;
		orig_size -= 3;
		wth->data_offset += 3;

		/*
		 * Read the padding.
		 */
		if (!libpcap_read_rec_data(wth->fh, fddi_padding, 3, err))
			return FALSE;	/* Read error */
	}

	*data_offset = wth->data_offset;

	/*
	 * If this is an ATM packet, the first four bytes are the
	 * direction of the packet (transmit/receive), the VPI, and
	 * the VCI; read them and generate the pseudo-header from
	 * them.
	 */
	switch (wth->file_encap) {

	case WTAP_ENCAP_ATM_PDUS:
		if (wth->file_type == WTAP_FILE_PCAP_NOKIA) {
			/*
			 * Nokia IPSO ATM.
			 */
			if (packet_size < NOKIAATM_LEN) {
				/*
				 * Uh-oh, the packet isn't big enough to even
				 * have a pseudo-header.
				 */
				*err = WTAP_ERR_BAD_RECORD;
				*err_info = g_strdup_printf("libpcap: Nokia IPSO ATM file has a %u-byte packet, too small to have even an ATM pseudo-header\n",
				    packet_size);
				return FALSE;
			}
			if (!libpcap_read_nokiaatm_pseudoheader(wth->fh,
			    &wth->pseudo_header, err))
				return FALSE;	/* Read error */

			/*
			 * Don't count the pseudo-header as part of the
			 * packet.
			 */
			orig_size -= NOKIAATM_LEN;
			packet_size -= NOKIAATM_LEN;
			wth->data_offset += NOKIAATM_LEN;
		} else {
			/*
			 * SunATM.
			 */
			if (packet_size < SUNATM_LEN) {
				/*
				 * Uh-oh, the packet isn't big enough to even
				 * have a pseudo-header.
				 */
				*err = WTAP_ERR_BAD_RECORD;
				*err_info = g_strdup_printf("libpcap: SunATM file has a %u-byte packet, too small to have even an ATM pseudo-header\n",
				    packet_size);
				return FALSE;
			}
			if (!libpcap_read_sunatm_pseudoheader(wth->fh,
			    &wth->pseudo_header, err))
				return FALSE;	/* Read error */

			/*
			 * Don't count the pseudo-header as part of the
			 * packet.
			 */
			orig_size -= SUNATM_LEN;
			packet_size -= SUNATM_LEN;
			wth->data_offset += SUNATM_LEN;
		}
		break;

	case WTAP_ENCAP_ETHERNET:
		/*
		 * We don't know whether there's an FCS in this frame or not.
		 */
		wth->pseudo_header.eth.fcs_len = -1;
		break;

	case WTAP_ENCAP_IEEE_802_11:
	case WTAP_ENCAP_PRISM_HEADER:
	case WTAP_ENCAP_IEEE_802_11_WLAN_RADIOTAP:
	case WTAP_ENCAP_IEEE_802_11_WLAN_AVS:
		/*
		 * We don't know whether there's an FCS in this frame or not.
		 * XXX - are there any OSes where the capture mechanism
		 * supplies an FCS?
		 */
		wth->pseudo_header.ieee_802_11.fcs_len = -1;
		wth->pseudo_header.ieee_802_11.channel = 0;
		wth->pseudo_header.ieee_802_11.data_rate = 0;
		wth->pseudo_header.ieee_802_11.signal_level = 0;
		break;

	case WTAP_ENCAP_IRDA:
		if (packet_size < IRDA_SLL_LEN) {
			/*
			 * Uh-oh, the packet isn't big enough to even
			 * have a pseudo-header.
			 */
			*err = WTAP_ERR_BAD_RECORD;
			*err_info = g_strdup_printf("libpcap: IrDA file has a %u-byte packet, too small to have even an IrDA pseudo-header\n",
			    packet_size);
			return FALSE;
		}
		if (!libpcap_read_irda_pseudoheader(wth->fh, &wth->pseudo_header,
		    err, err_info))
			return FALSE;	/* Read error */

		/*
		 * Don't count the pseudo-header as part of the packet.
		 */
		orig_size -= IRDA_SLL_LEN;
		packet_size -= IRDA_SLL_LEN;
		wth->data_offset += IRDA_SLL_LEN;
		break;

	case WTAP_ENCAP_MTP2_WITH_PHDR:
		if (packet_size < MTP2_HDR_LEN) {
			/*
			 * Uh-oh, the packet isn't big enough to even
			 * have a pseudo-header.
			 */
			*err = WTAP_ERR_BAD_RECORD;
			*err_info = g_strdup_printf("libpcap: MTP2 file has a %u-byte packet, too small to have even an MTP2 pseudo-header\n",
			    packet_size);
			return FALSE;
		}
		if (!libpcap_read_mtp2_pseudoheader(wth->fh, &wth->pseudo_header,
		    err, err_info))
			return FALSE;	/* Read error */

		/*
		 * Don't count the pseudo-header as part of the packet.
		 */
		orig_size -= MTP2_HDR_LEN;
		packet_size -= MTP2_HDR_LEN;
		wth->data_offset += MTP2_HDR_LEN;
		break;

	case WTAP_ENCAP_LINUX_LAPD:
		if (packet_size < LAPD_SLL_LEN) {
			/*
			 * Uh-oh, the packet isn't big enough to even
			 * have a pseudo-header.
			 */
			*err = WTAP_ERR_BAD_RECORD;
			*err_info = g_strdup_printf("libpcap: LAPD file has a %u-byte packet, too small to have even a LAPD pseudo-header\n",
			    packet_size);
			return FALSE;
		}
		if (!libpcap_read_lapd_pseudoheader(wth->fh, &wth->pseudo_header,
		    err, err_info))
			return FALSE;	/* Read error */

		/*
		 * Don't count the pseudo-header as part of the packet.
		 */
		orig_size -= LAPD_SLL_LEN;
		packet_size -= LAPD_SLL_LEN;
		wth->data_offset += LAPD_SLL_LEN;
		break;

	case WTAP_ENCAP_SITA:
		if (packet_size < SITA_HDR_LEN) {
			/*
			 * Uh-oh, the packet isn't big enough to even
			 * have a pseudo-header.
			 */
			*err = WTAP_ERR_BAD_RECORD;
			*err_info = g_strdup_printf("libpcap: SITA file has a %u-byte packet, too small to have even a SITA pseudo-header\n",
			    packet_size);
			return FALSE;
		}
		if (!libpcap_read_sita_pseudoheader(wth->fh, &wth->pseudo_header,
		    err, err_info))
			return FALSE;	/* Read error */

		/*
		 * Don't count the pseudo-header as part of the packet.
		 */
		orig_size -= SITA_HDR_LEN;
		packet_size -= SITA_HDR_LEN;
		wth->data_offset += SITA_HDR_LEN;
		break;

	case WTAP_ENCAP_USB_LINUX:
		if (packet_size < sizeof (struct linux_usb_phdr)) {
			/*
			 * Uh-oh, the packet isn't big enough to even
			 * have a pseudo-header.
			 */
			*err = WTAP_ERR_BAD_RECORD;
			*err_info = g_strdup_printf("libpcap: Linux USB file has a %u-byte packet, too small to have even a Linux USB pseudo-header\n",
			    packet_size);
			return FALSE;
		}
		if (!libpcap_read_linux_usb_pseudoheader(wth, wth->fh,
		    &wth->pseudo_header, err))
			return FALSE;	/* Read error */

		/*
		 * Don't count the pseudo-header as part of the packet.
		 */
		orig_size -= sizeof (struct linux_usb_phdr);
		packet_size -= sizeof (struct linux_usb_phdr);
		wth->data_offset += sizeof (struct linux_usb_phdr);
		break;

	case WTAP_ENCAP_BLUETOOTH_H4:
		/* We don't have pseudoheader, so just pretend we received everything. */
		wth->pseudo_header.p2p.sent = FALSE;
		break;

	case WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR:
		if (packet_size < sizeof (struct libpcap_bt_phdr)) {
			/*
			 * Uh-oh, the packet isn't big enough to even
			 * have a pseudo-header.
			 */
			*err = WTAP_ERR_BAD_RECORD;
			*err_info = g_strdup_printf("libpcap: lipcap bluetooth file has a %u-byte packet, too small to have even a pseudo-header\n",
			    packet_size);
			return FALSE;
		}
		if (!libpcap_read_bt_pseudoheader(wth->fh,
		    &wth->pseudo_header, err))
			return FALSE;	/* Read error */

		/*
		 * Don't count the pseudo-header as part of the packet.
		 */
		orig_size -= sizeof (struct libpcap_bt_phdr);
		packet_size -= sizeof (struct libpcap_bt_phdr);
		wth->data_offset += sizeof (struct libpcap_bt_phdr);
		break;

	case WTAP_ENCAP_ERF:
		if (packet_size < sizeof(struct erf_phdr) ) {
			/*
			 * Uh-oh, the packet isn't big enough to even
			 * have a pseudo-header.
			 */
			*err = WTAP_ERR_BAD_RECORD;
			*err_info = g_strdup_printf("libpcap: ERF file has a %u-byte packet, too small to have even an ERF pseudo-header\n",
			    packet_size);
			return FALSE;
		}
		if (!libpcap_read_erf_pseudoheader(wth->fh, &wth->phdr, &wth->pseudo_header,
						   err, err_info))
			return FALSE;	/* Read error */

		/*
		 * Don't count the pseudo-header as part of the packet.
		 */
		orig_size -= sizeof(struct erf_phdr);
		packet_size -= sizeof(struct erf_phdr);
		wth->data_offset += sizeof(struct erf_phdr);

		if (!libpcap_read_erf_exheader(wth->fh, &wth->pseudo_header,
					       err, err_info, &size))
		  return FALSE;	/* Read error */

		/* Do not count also the extension headers as part of the packet */
		orig_size -= size;
		packet_size -= size;
		wth->data_offset += size;

		if (!libpcap_read_erf_subheader(wth->fh, &wth->pseudo_header,
					       err, err_info, &size)){
		  return FALSE;	/* Read error */
		}

		/*
		 * Don't count the optional mc-header as part of the packet.
		 */
		orig_size -= size;
		packet_size -= size;
		wth->data_offset += size;

		break;

	case WTAP_ENCAP_I2C:
		if (packet_size < sizeof (struct i2c_file_hdr)) {
			/*
			 * Uh-oh, the packet isn't big enough to even
			 * have a pseudo-header.
			 */
			*err = WTAP_ERR_BAD_RECORD;
			*err_info = g_strdup_printf("libpcap: I2C file has a %u-byte packet, too small to have even a I2C pseudo-header\n",
			    packet_size);
			return FALSE;
		}
		if (!libpcap_read_i2c_pseudoheader(wth->fh, &wth->pseudo_header,
		    err, err_info))
			return FALSE;	/* Read error */

		/*
		 * Don't count the pseudo-header as part of the packet.
		 */
		orig_size -= sizeof (struct i2c_file_hdr);
		packet_size -= sizeof (struct i2c_file_hdr);
		wth->data_offset += sizeof (struct i2c_file_hdr);
		break;

	}

	buffer_assure_space(wth->frame_buffer, packet_size);
	if (!libpcap_read_rec_data(wth->fh, buffer_start_ptr(wth->frame_buffer),
	    packet_size, err))
		return FALSE;	/* Read error */
	wth->data_offset += packet_size;

	/* Update the Timestamp, if not already done */
	if (wth->file_encap != WTAP_ENCAP_ERF) {
	  wth->phdr.ts.secs = hdr.hdr.ts_sec;
	  if(wth->tsprecision == WTAP_FILE_TSPREC_NSEC) {
	    wth->phdr.ts.nsecs = hdr.hdr.ts_usec;
	  } else {
	    wth->phdr.ts.nsecs = hdr.hdr.ts_usec * 1000;
	  }
	}
	wth->phdr.caplen = packet_size;
	wth->phdr.len = orig_size;

	if (wth->file_encap == WTAP_ENCAP_ATM_PDUS) {
		if (wth->file_type == WTAP_FILE_PCAP_NOKIA) {
			/*
			 * Nokia IPSO ATM.
			 *
			 * Guess the traffic type based on the packet
			 * contents.
			 */
			atm_guess_traffic_type(buffer_start_ptr(wth->frame_buffer),
			    wth->phdr.caplen, &wth->pseudo_header);
		} else {
			/*
			 * SunATM.
			 *
			 * If this is ATM LANE traffic, try to guess what
			 * type of LANE traffic it is based on the packet
			 * contents.
			 */
			if (wth->pseudo_header.atm.type == TRAF_LANE) {
				atm_guess_lane_type(buffer_start_ptr(wth->frame_buffer),
				    wth->phdr.caplen, &wth->pseudo_header);
			}
		}
	}

	return TRUE;
}

static gboolean
libpcap_seek_read(wtap *wth, gint64 seek_off,
    union wtap_pseudo_header *pseudo_header, guchar *pd, int length,
    int *err, gchar **err_info)
{
  guint size;
	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	switch (wth->file_encap) {

	case WTAP_ENCAP_ATM_PDUS:
		if (wth->file_type == WTAP_FILE_PCAP_NOKIA) {
			/*
			 * Nokia IPSO ATM.
			 */
			if (!libpcap_read_nokiaatm_pseudoheader(wth->random_fh,
			    pseudo_header, err)) {
				/* Read error */
				return FALSE;
			}
		} else {
			/*
			 * SunATM.
			 */
			if (!libpcap_read_sunatm_pseudoheader(wth->random_fh,
			    pseudo_header, err)) {
				/* Read error */
				return FALSE;
			}
		}
		break;

	case WTAP_ENCAP_ETHERNET:
		/*
		 * We don't know whether there's an FCS in this frame or not.
		 */
		pseudo_header->eth.fcs_len = -1;
		break;

	case WTAP_ENCAP_IEEE_802_11:
	case WTAP_ENCAP_PRISM_HEADER:
	case WTAP_ENCAP_IEEE_802_11_WLAN_RADIOTAP:
	case WTAP_ENCAP_IEEE_802_11_WLAN_AVS:
		/*
		 * We don't know whether there's an FCS in this frame or not.
		 * XXX - are there any OSes where the capture mechanism
		 * supplies an FCS?
		 */
		pseudo_header->ieee_802_11.fcs_len = -1;
		break;

	case WTAP_ENCAP_IRDA:
		if (!libpcap_read_irda_pseudoheader(wth->random_fh, pseudo_header,
		    err, err_info)) {
			/* Read error */
			return FALSE;
		}
		break;

	case WTAP_ENCAP_MTP2_WITH_PHDR:
		if (!libpcap_read_mtp2_pseudoheader(wth->random_fh, pseudo_header,
		    err, err_info)) {
			/* Read error */
			return FALSE;
		}
		break;

	case WTAP_ENCAP_LINUX_LAPD:
		if (!libpcap_read_lapd_pseudoheader(wth->random_fh, pseudo_header,
		    err, err_info)) {
			/* Read error */
			return FALSE;
		}
		break;

	case WTAP_ENCAP_SITA:
		if (!libpcap_read_sita_pseudoheader(wth->random_fh, pseudo_header,
		    err, err_info)) {
			/* Read error */
			return FALSE;
		}
		break;

	case WTAP_ENCAP_USB_LINUX:
		if (!libpcap_read_linux_usb_pseudoheader(wth, wth->random_fh,
		    pseudo_header, err))
			return FALSE;	/* Read error */
		break;

	case WTAP_ENCAP_BLUETOOTH_H4:
		/* We don't have pseudoheader, so just pretend we received everything. */
		wth->pseudo_header.p2p.sent = FALSE;
		break;

	case WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR:
		if (!libpcap_read_bt_pseudoheader(wth->random_fh,
		    pseudo_header, err))
			return FALSE;	/* Read error */
		break;

	case WTAP_ENCAP_ERF:
	  if (!libpcap_read_erf_pseudoheader(wth->random_fh, NULL, pseudo_header,
					     err, err_info)) {
	    return FALSE;
	  }

	  /* check the optional Extension header */
	  if (!libpcap_read_erf_exheader(wth->random_fh, pseudo_header,
					       err, err_info, &size)){

		  /* Read error */
		  return FALSE;
	  }

	  /* check the optional Multi Channel header */
	  if (!libpcap_read_erf_subheader(wth->random_fh, pseudo_header,
					 err, err_info, &size)) {
	    /* Read error */
	    return FALSE;
	  }
	  break;

	case WTAP_ENCAP_I2C:
		if (!libpcap_read_i2c_pseudoheader(wth->random_fh, pseudo_header,
		    err, err_info)) {
			/* Read error */
			return FALSE;
		}
		break;
	}

	/*
	 * Read the packet data.
	 */
	if (!libpcap_read_rec_data(wth->random_fh, pd, length, err))
		return FALSE;	/* failed */

	if (wth->file_encap == WTAP_ENCAP_ATM_PDUS) {
		if (wth->file_type == WTAP_FILE_PCAP_NOKIA) {
			/*
			 * Nokia IPSO ATM.
			 *
			 * Guess the traffic type based on the packet
			 * contents.
			 */
			atm_guess_traffic_type(pd, length, pseudo_header);
		} else {
			/*
			 * SunATM.
			 *
			 * If this is ATM LANE traffic, try to guess what
			 * type of LANE traffic it is based on the packet
			 * contents.
			 */
			if (pseudo_header->atm.type == TRAF_LANE)
				atm_guess_lane_type(pd, length, pseudo_header);
		}
	}
	return TRUE;
}

/* Read the header of the next packet.

   Return -1 on an error, or the number of bytes of header read on success. */
static int libpcap_read_header(wtap *wth, int *err, gchar **err_info,
    struct pcaprec_ss990915_hdr *hdr)
{
	int	bytes_to_read, bytes_read;

	/* Read record header. */
	errno = WTAP_ERR_CANT_READ;
	switch (wth->file_type) {

	case WTAP_FILE_PCAP:
	case WTAP_FILE_PCAP_AIX:
	case WTAP_FILE_PCAP_NSEC:
		bytes_to_read = sizeof (struct pcaprec_hdr);
		break;

	case WTAP_FILE_PCAP_SS990417:
	case WTAP_FILE_PCAP_SS991029:
		bytes_to_read = sizeof (struct pcaprec_modified_hdr);
		break;

	case WTAP_FILE_PCAP_SS990915:
		bytes_to_read = sizeof (struct pcaprec_ss990915_hdr);
		break;

	case WTAP_FILE_PCAP_NOKIA:
		bytes_to_read = sizeof (struct pcaprec_nokia_hdr);
		break;

	default:
		g_assert_not_reached();
		bytes_to_read = 0;
	}
	bytes_read = file_read(hdr, 1, bytes_to_read, wth->fh);
	if (bytes_read != bytes_to_read) {
		*err = file_error(wth->fh);
		if (*err == 0 && bytes_read != 0) {
			*err = WTAP_ERR_SHORT_READ;
		}
		return -1;
	}

	adjust_header(wth, &hdr->hdr);

	if (hdr->hdr.incl_len > WTAP_MAX_PACKET_SIZE) {
		/*
		 * Probably a corrupt capture file; return an error,
		 * so that our caller doesn't blow up trying to allocate
		 * space for an immensely-large packet, and so that
		 * the code to try to guess what type of libpcap file
		 * this is can tell when it's not the type we're guessing
		 * it is.
		 */
		*err = WTAP_ERR_BAD_RECORD;
		if (err_info != NULL) {
			*err_info = g_strdup_printf("pcap: File has %u-byte packet, bigger than maximum of %u",
			    hdr->hdr.incl_len, WTAP_MAX_PACKET_SIZE);
		}
		return -1;
	}

	if (hdr->hdr.orig_len > WTAP_MAX_PACKET_SIZE) {
		/*
		 * Probably a corrupt capture file; return an error,
		 * so that our caller doesn't blow up trying to
		 * cope with a huge "real" packet length, and so that
		 * the code to try to guess what type of libpcap file
		 * this is can tell when it's not the type we're guessing
		 * it is.
		 */
		*err = WTAP_ERR_BAD_RECORD;
		if (err_info != NULL) {
			*err_info = g_strdup_printf("pcap: File has %u-byte packet, bigger than maximum of %u",
			    hdr->hdr.orig_len, WTAP_MAX_PACKET_SIZE);
		}
		return -1;
	}

	return bytes_read;
}

static void
adjust_header(wtap *wth, struct pcaprec_hdr *hdr)
{
	guint32 temp;

	if (wth->capture.pcap->byte_swapped) {
		/* Byte-swap the record header fields. */
		hdr->ts_sec = BSWAP32(hdr->ts_sec);
		hdr->ts_usec = BSWAP32(hdr->ts_usec);
		hdr->incl_len = BSWAP32(hdr->incl_len);
		hdr->orig_len = BSWAP32(hdr->orig_len);
	}

	/* Swap the "incl_len" and "orig_len" fields, if necessary. */
	switch (wth->capture.pcap->lengths_swapped) {

	case NOT_SWAPPED:
		break;

	case MAYBE_SWAPPED:
		if (hdr->incl_len <= hdr->orig_len) {
			/*
			 * The captured length is <= the actual length,
			 * so presumably they weren't swapped.
			 */
			break;
		}
		/* FALLTHROUGH */

	case SWAPPED:
		temp = hdr->orig_len;
		hdr->orig_len = hdr->incl_len;
		hdr->incl_len = temp;
		break;
	}
}

static void
libpcap_get_sunatm_pseudoheader(const guint8 *atm_phdr,
    union wtap_pseudo_header *pseudo_header)
{
	guint8	vpi;
	guint16	vci;

	vpi = atm_phdr[SUNATM_VPI];
	vci = pntohs(&atm_phdr[SUNATM_VCI]);

	switch (atm_phdr[SUNATM_FLAGS] & 0x0F) {

	case 0x01:	/* LANE */
		pseudo_header->atm.aal = AAL_5;
		pseudo_header->atm.type = TRAF_LANE;
		break;

	case 0x02:	/* RFC 1483 LLC multiplexed traffic */
		pseudo_header->atm.aal = AAL_5;
		pseudo_header->atm.type = TRAF_LLCMX;
		break;

	case 0x05:	/* ILMI */
		pseudo_header->atm.aal = AAL_5;
		pseudo_header->atm.type = TRAF_ILMI;
		break;

	case 0x06:	/* Q.2931 */
		pseudo_header->atm.aal = AAL_SIGNALLING;
		pseudo_header->atm.type = TRAF_UNKNOWN;
		break;

	case 0x03:	/* MARS (RFC 2022) */
		pseudo_header->atm.aal = AAL_5;
		pseudo_header->atm.type = TRAF_UNKNOWN;
		break;

	case 0x04:	/* IFMP (Ipsilon Flow Management Protocol; see RFC 1954) */
		pseudo_header->atm.aal = AAL_5;
		pseudo_header->atm.type = TRAF_UNKNOWN;	/* XXX - TRAF_IPSILON? */
		break;

	default:
		/*
		 * Assume it's AAL5, unless it's VPI 0 and VCI 5, in which
		 * case assume it's AAL_SIGNALLING; we know nothing more
		 * about it.
		 *
		 * XXX - is this necessary?  Or are we guaranteed that
		 * all signalling traffic has a type of 0x06?
		 *
		 * XXX - is this guaranteed to be AAL5?  Or, if the type is
		 * 0x00 ("raw"), might it be non-AAL5 traffic?
		 */
		if (vpi == 0 && vci == 5)
			pseudo_header->atm.aal = AAL_SIGNALLING;
		else
			pseudo_header->atm.aal = AAL_5;
		pseudo_header->atm.type = TRAF_UNKNOWN;
		break;
	}
	pseudo_header->atm.subtype = TRAF_ST_UNKNOWN;

	pseudo_header->atm.vpi = vpi;
	pseudo_header->atm.vci = vci;
	pseudo_header->atm.channel = (atm_phdr[SUNATM_FLAGS] & 0x80) ? 0 : 1;

	/* We don't have this information */
	pseudo_header->atm.flags = 0;
	pseudo_header->atm.cells = 0;
	pseudo_header->atm.aal5t_u2u = 0;
	pseudo_header->atm.aal5t_len = 0;
	pseudo_header->atm.aal5t_chksum = 0;
}

static gboolean
libpcap_read_sunatm_pseudoheader(FILE_T fh,
    union wtap_pseudo_header *pseudo_header, int *err)
{
	guint8	atm_phdr[SUNATM_LEN];
	int	bytes_read;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(atm_phdr, 1, SUNATM_LEN, fh);
	if (bytes_read != SUNATM_LEN) {
		*err = file_error(fh);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}

	libpcap_get_sunatm_pseudoheader(atm_phdr, pseudo_header);

	return TRUE;
}

static gboolean
libpcap_read_nokiaatm_pseudoheader(FILE_T fh,
    union wtap_pseudo_header *pseudo_header, int *err)
{
	guint8	atm_phdr[NOKIAATM_LEN];
	int	bytes_read;
	guint8	vpi;
	guint16	vci;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(atm_phdr, 1, NOKIAATM_LEN, fh);
	if (bytes_read != NOKIAATM_LEN) {
		*err = file_error(fh);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}

	vpi = atm_phdr[NOKIAATM_VPI];
	vci = pntohs(&atm_phdr[NOKIAATM_VCI]);

	pseudo_header->atm.vpi = vpi;
	pseudo_header->atm.vci = vci;
	pseudo_header->atm.channel = (atm_phdr[NOKIAATM_FLAGS] & 0x80) ? 0 : 1;

	/* We don't have this information */
	pseudo_header->atm.flags = 0;
	pseudo_header->atm.cells = 0;
	pseudo_header->atm.aal5t_u2u = 0;
	pseudo_header->atm.aal5t_len = 0;
	pseudo_header->atm.aal5t_chksum = 0;

	return TRUE;
}

static gboolean
libpcap_get_irda_pseudoheader(const guint8 *irda_phdr,
    union wtap_pseudo_header *pseudo_header, int *err, gchar **err_info)
{
	if (pntohs(&irda_phdr[IRDA_SLL_PROTOCOL_OFFSET]) != 0x0017) {
		*err = WTAP_ERR_BAD_RECORD;
		if (err_info != NULL)
			*err_info = g_strdup("libpcap: IrDA capture has a packet with an invalid sll_protocol field\n");
		return FALSE;
	}

	pseudo_header->irda.pkttype = pntohs(&irda_phdr[IRDA_SLL_PKTTYPE_OFFSET]);

	return TRUE;
}

static gboolean
libpcap_read_irda_pseudoheader(FILE_T fh, union wtap_pseudo_header *pseudo_header,
    int *err, gchar **err_info)
{
	guint8	irda_phdr[IRDA_SLL_LEN];
	int	bytes_read;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(irda_phdr, 1, IRDA_SLL_LEN, fh);
	if (bytes_read != IRDA_SLL_LEN) {
		*err = file_error(fh);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}

	return libpcap_get_irda_pseudoheader(irda_phdr, pseudo_header, err,
	    err_info);
}

static gboolean
libpcap_get_mtp2_pseudoheader(const guint8 *mtp2_hdr, union wtap_pseudo_header *pseudo_header)
{
	pseudo_header->mtp2.sent         = mtp2_hdr[MTP2_SENT_OFFSET];
	pseudo_header->mtp2.annex_a_used = mtp2_hdr[MTP2_ANNEX_A_USED_OFFSET];
	pseudo_header->mtp2.link_number  = pntohs(&mtp2_hdr[MTP2_LINK_NUMBER_OFFSET]);

	return TRUE;
}

static gboolean
libpcap_read_mtp2_pseudoheader(FILE_T fh, union wtap_pseudo_header *pseudo_header, int *err, gchar **err_info _U_)
{
	guint8 mtp2_hdr[MTP2_HDR_LEN];
	int    bytes_read;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(mtp2_hdr, 1, MTP2_HDR_LEN, fh);
	if (bytes_read != MTP2_HDR_LEN) {
		*err = file_error(fh);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}

	return libpcap_get_mtp2_pseudoheader(mtp2_hdr, pseudo_header);

}

static gboolean
libpcap_get_lapd_pseudoheader(const guint8 *lapd_phdr,
    union wtap_pseudo_header *pseudo_header, int *err, gchar **err_info)
{
	if (pntohs(&lapd_phdr[LAPD_SLL_PROTOCOL_OFFSET]) != ETH_P_LAPD) {
		*err = WTAP_ERR_BAD_RECORD;
		if (err_info != NULL)
			*err_info = g_strdup("libpcap: LAPD capture has a packet with an invalid sll_protocol field\n");
		return FALSE;
	}

	pseudo_header->lapd.pkttype = pntohs(&lapd_phdr[LAPD_SLL_PKTTYPE_OFFSET]);
	pseudo_header->lapd.we_network = !!lapd_phdr[LAPD_SLL_ADDR_OFFSET+0];

	return TRUE;
}

static gboolean
libpcap_read_lapd_pseudoheader(FILE_T fh, union wtap_pseudo_header *pseudo_header,
    int *err, gchar **err_info)
{
	guint8	lapd_phdr[LAPD_SLL_LEN];
	int	bytes_read;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(lapd_phdr, 1, LAPD_SLL_LEN, fh);
	if (bytes_read != LAPD_SLL_LEN) {
		*err = file_error(fh);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}

	return libpcap_get_lapd_pseudoheader(lapd_phdr, pseudo_header, err,
	    err_info);
}

static gboolean
libpcap_get_sita_pseudoheader(const guint8 *sita_phdr,
    union wtap_pseudo_header *pseudo_header)
{
	pseudo_header->sita.flags   = sita_phdr[SITA_FLAGS_OFFSET];
	pseudo_header->sita.signals = sita_phdr[SITA_SIGNALS_OFFSET];
	pseudo_header->sita.errors1 = sita_phdr[SITA_ERRORS1_OFFSET];
	pseudo_header->sita.errors2 = sita_phdr[SITA_ERRORS2_OFFSET];
	pseudo_header->sita.proto   = sita_phdr[SITA_PROTO_OFFSET];
	return TRUE;
}

static gboolean
libpcap_read_sita_pseudoheader(FILE_T fh, union wtap_pseudo_header *pseudo_header, int *err, gchar **err_info _U_)
{
	guint8	sita_phdr[SITA_HDR_LEN];
	int	bytes_read;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(sita_phdr, 1, SITA_HDR_LEN, fh);
	if (bytes_read != SITA_HDR_LEN) {
		*err = file_error(fh);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}

	return libpcap_get_sita_pseudoheader(sita_phdr, pseudo_header);
}

static void
libpcap_swap_linux_usb_pseudoheader(struct linux_usb_phdr *phdr)
{
	phdr->id = GUINT64_SWAP_LE_BE(phdr->id);
	phdr->bus_id = GUINT16_SWAP_LE_BE(phdr->bus_id);
	phdr->ts_sec = GUINT64_SWAP_LE_BE(phdr->ts_sec);
	phdr->ts_usec = GUINT32_SWAP_LE_BE(phdr->ts_usec);
	phdr->status = GUINT32_SWAP_LE_BE(phdr->status);
	phdr->urb_len = GUINT32_SWAP_LE_BE(phdr->urb_len);
	phdr->data_len = GUINT32_SWAP_LE_BE(phdr->data_len);
}

static gboolean
libpcap_read_linux_usb_pseudoheader(wtap *wth, FILE_T fh,
    union wtap_pseudo_header *pseudo_header, int *err)
{
	int	bytes_read;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&pseudo_header->linux_usb, 1,
	    sizeof (struct linux_usb_phdr), fh);
	if (bytes_read != sizeof (struct linux_usb_phdr)) {
		*err = file_error(fh);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	if (wth->capture.pcap->byte_swapped)
		libpcap_swap_linux_usb_pseudoheader(&pseudo_header->linux_usb);
	return TRUE;
}

static gboolean
libpcap_read_bt_pseudoheader(FILE_T fh,
    union wtap_pseudo_header *pseudo_header, int *err)
{
	int	bytes_read;
	struct libpcap_bt_phdr phdr;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&phdr, 1,
	    sizeof (struct libpcap_bt_phdr), fh);
	if (bytes_read != sizeof (struct libpcap_bt_phdr)) {
		*err = file_error(fh);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	pseudo_header->p2p.sent = ((g_ntohl(phdr.direction) & 0x1) == 0)? TRUE: FALSE;
	return TRUE;
}


static gboolean
libpcap_get_erf_pseudoheader(const guint8 *erf_hdr, struct wtap_pkthdr *whdr,
			     union wtap_pseudo_header *pseudo_header)
{
  pseudo_header->erf.phdr.ts = pletohll(&erf_hdr[0]); /* timestamp */
  pseudo_header->erf.phdr.type =  erf_hdr[8];
  pseudo_header->erf.phdr.flags = erf_hdr[9];
  pseudo_header->erf.phdr.rlen = pntohs(&erf_hdr[10]);
  pseudo_header->erf.phdr.lctr = pntohs(&erf_hdr[12]);
  pseudo_header->erf.phdr.wlen = pntohs(&erf_hdr[14]);

  /* The high 32 bits of the timestamp contain the integer number of seconds
   * while the lower 32 bits contain the binary fraction of the second.
   * This allows an ultimate resolution of 1/(2^32) seconds, or approximately 233 picoseconds */
  if (whdr) {
    guint64 ts = pseudo_header->erf.phdr.ts;
    whdr->ts.secs = (guint32) (ts >> 32);
    ts = ((ts & 0xffffffff) * 1000 * 1000 * 1000);
    ts += (ts & 0x80000000) << 1; /* rounding */
    whdr->ts.nsecs = ((guint32) (ts >> 32));
    if ( whdr->ts.nsecs >= 1000000000) {
      whdr->ts.nsecs -= 1000000000;
      whdr->ts.secs += 1;
    }
  }
  return TRUE;
}

static gboolean
libpcap_read_erf_pseudoheader(FILE_T fh, struct wtap_pkthdr *whdr,
			      union wtap_pseudo_header *pseudo_header, int *err, gchar **err_info _U_)
{
  guint8 erf_hdr[sizeof(struct erf_phdr)];
  int    bytes_read;

  errno = WTAP_ERR_CANT_READ;
  bytes_read = file_read(erf_hdr, 1, sizeof(struct erf_phdr), fh);
  if (bytes_read != sizeof(struct erf_phdr)) {
    *err = file_error(fh);
    if (*err == 0)
      *err = WTAP_ERR_SHORT_READ;
    return FALSE;
  }
  return libpcap_get_erf_pseudoheader(erf_hdr, whdr, pseudo_header);
}

static gboolean
libpcap_get_erf_subheader(const guint8 *erf_subhdr,
			  union wtap_pseudo_header *pseudo_header, guint * psize)
{
  *psize=0;
  switch(pseudo_header->erf.phdr.type & 0x7F) {
  case ERF_TYPE_MC_HDLC:
  case ERF_TYPE_MC_RAW:
  case ERF_TYPE_MC_ATM:
  case ERF_TYPE_MC_RAW_CHANNEL:
  case ERF_TYPE_MC_AAL5:
  case ERF_TYPE_MC_AAL2:
  case ERF_TYPE_COLOR_MC_HDLC_POS:
    /* Extract the Multi Channel header to include it in the pseudo header part */
    pseudo_header->erf.subhdr.mc_hdr = pntohl(&erf_subhdr[0]);
    *psize = sizeof(erf_mc_header_t);
    break;
  case ERF_TYPE_ETH:
  case ERF_TYPE_COLOR_ETH:
  case ERF_TYPE_DSM_COLOR_ETH:
    /* Extract the Ethernet additional header to include it in the pseudo header part */
    pseudo_header->erf.subhdr.eth_hdr = pntohs(&erf_subhdr[0]);
    *psize = sizeof(erf_eth_header_t);
    break;
  default:
    /* No optional pseudo header for this ERF type */
    break;
  }
  return TRUE;
}

/*
 * If the type of record given in the pseudo header indicate the presence of an extension
 * header then, read all the extension headers
 */
static gboolean
libpcap_read_erf_exheader(FILE_T fh, union wtap_pseudo_header *pseudo_header,
			   int *err, gchar **err_info _U_, guint * psize)
{
  int bytes_read = 0;
  guint8 erf_exhdr[8];
  guint64 erf_exhdr_sw;
  int i = 0, max = sizeof(pseudo_header->erf.ehdr_list)/sizeof(struct erf_ehdr);
  guint8 type = pseudo_header->erf.phdr.type;
  *psize = 0;
  if (pseudo_header->erf.phdr.type & 0x80){
    do{
      errno = WTAP_ERR_CANT_READ;
      bytes_read = file_read(erf_exhdr, 1, 8, fh);
      if (bytes_read != 8 ) {
	*err = file_error(fh);
	if (*err == 0)
	  *err = WTAP_ERR_SHORT_READ;
	return FALSE;
      }
      type = erf_exhdr[0];
      erf_exhdr_sw = pntohll((guint64*) &(erf_exhdr[0]));
      if (i < max)
	memcpy(&pseudo_header->erf.ehdr_list[i].ehdr, &erf_exhdr_sw, sizeof(erf_exhdr_sw));
      *psize += 8;
      i++;
    } while (type & 0x80);
  }
  return TRUE;
}

/*
 * If the type of record given in the pseudo header indicate the precense of a subheader
 * then, read this optional subheader
 */
static gboolean
libpcap_read_erf_subheader(FILE_T fh, union wtap_pseudo_header *pseudo_header,
			   int *err, gchar **err_info _U_, guint * psize)
{
  guint8 erf_subhdr[sizeof(union erf_subhdr)];
  int    bytes_read;

  *psize=0;
  switch(pseudo_header->erf.phdr.type & 0x7F) {
  case ERF_TYPE_MC_HDLC:
  case ERF_TYPE_MC_RAW:
  case ERF_TYPE_MC_ATM:
  case ERF_TYPE_MC_RAW_CHANNEL:
  case ERF_TYPE_MC_AAL5:
  case ERF_TYPE_MC_AAL2:
  case ERF_TYPE_COLOR_MC_HDLC_POS:
    /* Extract the Multi Channel header to include it in the pseudo header part */
    errno = WTAP_ERR_CANT_READ;
    bytes_read = file_read(erf_subhdr, 1, sizeof(erf_mc_header_t), fh);
    if (bytes_read != sizeof(erf_mc_header_t) ) {
      *err = file_error(fh);
      if (*err == 0)
	*err = WTAP_ERR_SHORT_READ;
      return FALSE;
    }
    *psize = sizeof(erf_mc_header_t);
    break;
  case ERF_TYPE_ETH:
  case ERF_TYPE_COLOR_ETH:
  case ERF_TYPE_DSM_COLOR_ETH:
    /* Extract the Ethernet additional header to include it in the pseudo header part */
    errno = WTAP_ERR_CANT_READ;
    bytes_read = file_read(erf_subhdr, 1, sizeof(erf_eth_header_t), fh);
    if (bytes_read != sizeof(erf_eth_header_t) ) {
      *err = file_error(fh);
      if (*err == 0)
	*err = WTAP_ERR_SHORT_READ;
      return FALSE;
    }
    *psize = sizeof(erf_eth_header_t);
    break;
  default:
    /* No optional pseudo header for this ERF type */
    break;
  }
  return libpcap_get_erf_subheader(erf_subhdr, pseudo_header, psize);
}

static gboolean
libpcap_get_i2c_pseudoheader(const struct i2c_file_hdr *i2c_hdr, union wtap_pseudo_header *pseudo_header)
{
	pseudo_header->i2c.is_event = i2c_hdr->bus & 0x80 ? 1 : 0;
	pseudo_header->i2c.bus = i2c_hdr->bus & 0x7f;
	pseudo_header->i2c.flags = pntohl(&i2c_hdr->flags);

	return TRUE;
}

static gboolean
libpcap_read_i2c_pseudoheader(FILE_T fh, union wtap_pseudo_header *pseudo_header, int *err, gchar **err_info _U_)
{
	struct i2c_file_hdr i2c_hdr;
	int    bytes_read;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(&i2c_hdr, 1, sizeof (i2c_hdr), fh);
	if (bytes_read != sizeof (i2c_hdr)) {
		*err = file_error(fh);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}

	return libpcap_get_i2c_pseudoheader(&i2c_hdr, pseudo_header);

}

static gboolean
libpcap_read_rec_data(FILE_T fh, guchar *pd, int length, int *err)
{
	int	bytes_read;

	errno = WTAP_ERR_CANT_READ;
	bytes_read = file_read(pd, 1, length, fh);

	if (bytes_read != length) {
		*err = file_error(fh);
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}
	return TRUE;
}

static void
libpcap_close(wtap *wth)
{
	g_free(wth->capture.pcap);
}

static int wtap_wtap_encap_to_pcap_encap(int encap)
{
	unsigned int i;

	switch (encap) {

	case WTAP_ENCAP_FDDI:
	case WTAP_ENCAP_FDDI_BITSWAPPED:
	case WTAP_ENCAP_NETTL_FDDI:
		/*
		 * Special-case WTAP_ENCAP_FDDI and
		 * WTAP_ENCAP_FDDI_BITSWAPPED; both of them get mapped
		 * to DLT_FDDI (even though that may mean that the bit
		 * order in the FDDI MAC addresses is wrong; so it goes
		 * - libpcap format doesn't record the byte order,
		 * so that's not fixable).
		 */
		return 10;	/* that's DLT_FDDI */

	case WTAP_ENCAP_PPP_WITH_PHDR:
		/*
		 * Also special-case PPP with direction bits; map it to
		 * PPP, even though that means that the direction of the
		 * packet is lost.
		 */
		return 9;

	case WTAP_ENCAP_FRELAY_WITH_PHDR:
		/*
		 * Do the same with Frame Relay.
		 */
		return 107;

	case WTAP_ENCAP_IEEE_802_11_WITH_RADIO:
		/*
		 * Map this to DLT_IEEE802_11, for now, even though
		 * that means the radio information will be lost.
		 * Once tcpdump support for the BSD radiotap header
		 * is sufficiently widespread, we should probably
		 * use that, instead - although we should probably
		 * ultimately just have WTAP_ENCAP_IEEE_802_11
		 * as the only Wiretap encapsulation for 802.11,
		 * and have the pseudo-header include a radiotap-style
		 * list of attributes.  If we do that, though, we
		 * should probably bypass the regular Wiretap code
		 * when writing out packets during a capture, and just
		 * do the equivalent of a libpcap write (unfortunately,
		 * libpcap doesn't have an "open dump by file descriptor"
		 * function, so we can't just use "pcap_dump()"), so
		 * that we don't spend cycles mapping from libpcap to
		 * Wiretap and then back to libpcap.  (There are other
		 * reasons to do that, e.g. to handle AIX libpcap better.)
		 */
		return 105;
	}

	for (i = 0; i < NUM_PCAP_ENCAPS; i++) {
		if (pcap_to_wtap_map[i].wtap_encap_value == encap)
			return pcap_to_wtap_map[i].dlt_value;
	}
	return -1;
}

/* Returns 0 if we could write the specified encapsulation type,
   an error indication otherwise. */
int libpcap_dump_can_write_encap(int encap)
{
	/* Per-packet encapsulations aren't supported. */
	if (encap == WTAP_ENCAP_PER_PACKET)
		return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

	if (wtap_wtap_encap_to_pcap_encap(encap) == -1)
		return WTAP_ERR_UNSUPPORTED_ENCAP;

	return 0;
}

/* Returns TRUE on success, FALSE on failure; sets "*err" to an error code on
   failure */
gboolean libpcap_dump_open(wtap_dumper *wdh, gboolean cant_seek _U_, int *err)
{
	guint32 magic;
	struct pcap_hdr file_hdr;
	size_t nwritten;

	/* This is a libpcap file */
	wdh->subtype_write = libpcap_dump;
	wdh->subtype_close = NULL;

	/* Write the file header. */
	switch (wdh->file_type) {

	case WTAP_FILE_PCAP:
	case WTAP_FILE_PCAP_SS990417:	/* modified, but with the old magic, sigh */
	case WTAP_FILE_PCAP_NOKIA:	/* Nokia libpcap of some sort */
		magic = PCAP_MAGIC;
		wdh->tsprecision = WTAP_FILE_TSPREC_USEC;
		break;

	case WTAP_FILE_PCAP_SS990915:	/* new magic, extra crap */
	case WTAP_FILE_PCAP_SS991029:
		magic = PCAP_MODIFIED_MAGIC;
		wdh->tsprecision = WTAP_FILE_TSPREC_USEC;
		break;

	case WTAP_FILE_PCAP_NSEC:		/* same as WTAP_FILE_PCAP, but nsec precision */
		magic = PCAP_NSEC_MAGIC;
		wdh->tsprecision = WTAP_FILE_TSPREC_NSEC;
		break;

	default:
		/* We should never get here - our open routine
		   should only get called for the types above. */
		*err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
		return FALSE;
	}

	nwritten = wtap_dump_file_write(wdh, &magic, sizeof magic);
	if (nwritten != sizeof magic) {
		if (nwritten == 0 && wtap_dump_file_ferror(wdh))
			*err = wtap_dump_file_ferror(wdh);
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return FALSE;
	}
	wdh->bytes_dumped += sizeof magic;

	/* current "libpcap" format is 2.4 */
	file_hdr.version_major = 2;
	file_hdr.version_minor = 4;
	file_hdr.thiszone = 0;	/* XXX - current offset? */
	file_hdr.sigfigs = 0;	/* unknown, but also apparently unused */
	/*
	 * Tcpdump cannot handle capture files with a snapshot length of 0,
	 * as BPF filters return either 0 if they fail or the snapshot length
	 * if they succeed, and a snapshot length of 0 means success is
	 * indistinguishable from failure and the filter expression would
	 * reject all packets.
	 *
	 * A snapshot length of 0, inside Wiretap, means "snapshot length
	 * unknown"; if the snapshot length supplied to us is 0, we make
	 * the snapshot length in the header file WTAP_MAX_PACKET_SIZE.
	 */
	file_hdr.snaplen = (wdh->snaplen != 0) ? wdh->snaplen :
						 WTAP_MAX_PACKET_SIZE;
	file_hdr.network = wtap_wtap_encap_to_pcap_encap(wdh->encap);
	nwritten = wtap_dump_file_write(wdh, &file_hdr, sizeof file_hdr);
	if (nwritten != sizeof file_hdr) {
		if (nwritten == 0 && wtap_dump_file_ferror(wdh))
			*err = wtap_dump_file_ferror(wdh);
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return FALSE;
	}
	wdh->bytes_dumped += sizeof file_hdr;

	return TRUE;
}

/* Write a record for a packet to a dump file.
   Returns TRUE on success, FALSE on failure. */
static gboolean libpcap_dump(wtap_dumper *wdh,
	const struct wtap_pkthdr *phdr,
	const union wtap_pseudo_header *pseudo_header _U_,
	const guchar *pd, int *err)
{
	struct pcaprec_ss990915_hdr rec_hdr;
	size_t hdr_size;
	size_t nwritten;
	guint8 atm_hdr[SUNATM_LEN];
	guint8 irda_hdr[IRDA_SLL_LEN];
	guint8 lapd_hdr[LAPD_SLL_LEN];
	guint8 mtp2_hdr[MTP2_HDR_LEN];
	guint8 sita_hdr[SITA_HDR_LEN];
	guint8 erf_hdr[ sizeof(struct erf_mc_phdr)];
	struct i2c_file_hdr i2c_hdr;
	int hdrsize, size;

	switch (wdh->encap) {

	case WTAP_ENCAP_ATM_PDUS:
		hdrsize = SUNATM_LEN;
		break;

	case WTAP_ENCAP_IRDA:
		hdrsize = IRDA_SLL_LEN;
		break;

	case WTAP_ENCAP_MTP2_WITH_PHDR:
		hdrsize = MTP2_HDR_LEN;
		break;

	case WTAP_ENCAP_LINUX_LAPD:
		hdrsize = LAPD_SLL_LEN;
		break;

	case WTAP_ENCAP_SITA:
		hdrsize = SITA_HDR_LEN;
		break;

	case WTAP_ENCAP_USB_LINUX:
		hdrsize = sizeof (struct linux_usb_phdr);
		break;

	case WTAP_ENCAP_ERF:
	        hdrsize = sizeof (struct erf_phdr);
		if (pseudo_header->erf.phdr.type & 0x80) hdrsize += 8;
		switch(pseudo_header->erf.phdr.type & 0x7F) {
		case ERF_TYPE_MC_HDLC:
		case ERF_TYPE_MC_RAW:
		case ERF_TYPE_MC_ATM:
		case ERF_TYPE_MC_RAW_CHANNEL:
		case ERF_TYPE_MC_AAL5:
		case ERF_TYPE_MC_AAL2:
		case ERF_TYPE_COLOR_MC_HDLC_POS:
		  hdrsize += sizeof(struct erf_mc_hdr);
		  break;
		case ERF_TYPE_ETH:
		case ERF_TYPE_COLOR_ETH:
		case ERF_TYPE_DSM_COLOR_ETH:
		  hdrsize += sizeof(struct erf_eth_hdr);
		  break;
		default:
		  break;
		}
		break;

	case WTAP_ENCAP_I2C:
		hdrsize = sizeof (struct i2c_file_hdr);
		break;

	default:
		hdrsize = 0;
		break;
	}

	rec_hdr.hdr.ts_sec = (guint32) phdr->ts.secs;
	if(wdh->tsprecision == WTAP_FILE_TSPREC_NSEC) {
		rec_hdr.hdr.ts_usec = phdr->ts.nsecs;
	} else {
		rec_hdr.hdr.ts_usec = phdr->ts.nsecs / 1000;
	}
	rec_hdr.hdr.incl_len = phdr->caplen + hdrsize;
	rec_hdr.hdr.orig_len = phdr->len + hdrsize;
	switch (wdh->file_type) {

	case WTAP_FILE_PCAP:
	case WTAP_FILE_PCAP_NSEC:
		hdr_size = sizeof (struct pcaprec_hdr);
		break;

	case WTAP_FILE_PCAP_SS990417:	/* modified, but with the old magic, sigh */
	case WTAP_FILE_PCAP_SS991029:
		/* XXX - what should we supply here?

		   Alexey's "libpcap" looks up the interface in the system's
		   interface list if "ifindex" is non-zero, and prints
		   the interface name.  It ignores "protocol", and uses
		   "pkt_type" to tag the packet as "host", "broadcast",
		   "multicast", "other host", "outgoing", or "none of the
		   above", but that's it.

		   If the capture we're writing isn't a modified or
		   RH 6.1 capture, we'd have to do some work to
		   generate the packet type and interface index - and
		   we can't generate the interface index unless we
		   just did the capture ourselves in any case.

		   I'm inclined to continue to punt; systems other than
		   those with the older patch can read standard "libpcap"
		   files, and systems with the older patch, e.g. RH 6.1,
		   will just have to live with this. */
		rec_hdr.ifindex = 0;
		rec_hdr.protocol = 0;
		rec_hdr.pkt_type = 0;
		hdr_size = sizeof (struct pcaprec_modified_hdr);
		break;

	case WTAP_FILE_PCAP_SS990915:	/* new magic, extra crap at the end */
		rec_hdr.ifindex = 0;
		rec_hdr.protocol = 0;
		rec_hdr.pkt_type = 0;
		rec_hdr.cpu1 = 0;
		rec_hdr.cpu2 = 0;
		hdr_size = sizeof (struct pcaprec_ss990915_hdr);
		break;

	case WTAP_FILE_PCAP_NOKIA:	/* old magic, extra crap at the end */
		rec_hdr.ifindex = 0;
		rec_hdr.protocol = 0;
		rec_hdr.pkt_type = 0;
		rec_hdr.cpu1 = 0;
		rec_hdr.cpu2 = 0;
		hdr_size = sizeof (struct pcaprec_nokia_hdr);
		break;

	default:
		/* We should never get here - our open routine
		   should only get called for the types above. */
		g_assert_not_reached();
		*err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
		return FALSE;
	}

	nwritten = wtap_dump_file_write(wdh, &rec_hdr, hdr_size);
	if (nwritten != hdr_size) {
		if (nwritten == 0 && wtap_dump_file_ferror(wdh))
			*err = wtap_dump_file_ferror(wdh);
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return FALSE;
	}
	wdh->bytes_dumped += hdr_size;

	switch (wdh->encap) {

	case WTAP_ENCAP_ATM_PDUS:
		/*
		 * Write the ATM header.
		 */
		atm_hdr[SUNATM_FLAGS] =
		    (pseudo_header->atm.channel == 0) ? 0x80 : 0x00;
		switch (pseudo_header->atm.aal) {

		case AAL_SIGNALLING:
			/* Q.2931 */
			atm_hdr[SUNATM_FLAGS] |= 0x06;
			break;

		case AAL_5:
			switch (pseudo_header->atm.type) {

			case TRAF_LANE:
				/* LANE */
				atm_hdr[SUNATM_FLAGS] |= 0x01;
				break;

			case TRAF_LLCMX:
				/* RFC 1483 LLC multiplexed traffic */
				atm_hdr[SUNATM_FLAGS] |= 0x02;
				break;

			case TRAF_ILMI:
				/* ILMI */
				atm_hdr[SUNATM_FLAGS] |= 0x05;
				break;
			}
			break;
		}
		atm_hdr[SUNATM_VPI] = (guint8)pseudo_header->atm.vpi;
		phtons(&atm_hdr[SUNATM_VCI], pseudo_header->atm.vci);
		nwritten = wtap_dump_file_write(wdh, atm_hdr, sizeof atm_hdr);
		if (nwritten != sizeof atm_hdr) {
			if (nwritten == 0 && wtap_dump_file_ferror(wdh))
				*err = wtap_dump_file_ferror(wdh);
			else
				*err = WTAP_ERR_SHORT_WRITE;
			return FALSE;
		}
		wdh->bytes_dumped += sizeof atm_hdr;
		break;

	case WTAP_ENCAP_IRDA:
		/*
		 * Write the IrDA header.
		 */
		memset(irda_hdr, 0, sizeof(irda_hdr));
		phtons(&irda_hdr[IRDA_SLL_PKTTYPE_OFFSET],
		    pseudo_header->irda.pkttype);
		phtons(&irda_hdr[IRDA_SLL_PROTOCOL_OFFSET], 0x0017);
		nwritten = wtap_dump_file_write(wdh, irda_hdr, sizeof(irda_hdr));
		if (nwritten != sizeof(irda_hdr)) {
			if (nwritten == 0 && wtap_dump_file_ferror(wdh))
				*err = wtap_dump_file_ferror(wdh);
			else
				*err = WTAP_ERR_SHORT_WRITE;
			return FALSE;
		}
		wdh->bytes_dumped += sizeof(irda_hdr);
		break;

	case WTAP_ENCAP_MTP2_WITH_PHDR:
		/*
		 * Write the MTP2 header.
		 */
		memset(&mtp2_hdr, 0, sizeof(mtp2_hdr));
		mtp2_hdr[MTP2_SENT_OFFSET] = pseudo_header->mtp2.sent;
		mtp2_hdr[MTP2_ANNEX_A_USED_OFFSET] = pseudo_header->mtp2.annex_a_used;
		phtons(&mtp2_hdr[MTP2_LINK_NUMBER_OFFSET],
		    pseudo_header->mtp2.link_number);
		nwritten = wtap_dump_file_write(wdh, mtp2_hdr, sizeof(mtp2_hdr));
		if (nwritten != sizeof(mtp2_hdr)) {
			if (nwritten == 0 && wtap_dump_file_ferror(wdh))
				*err = wtap_dump_file_ferror(wdh);
			else
				*err = WTAP_ERR_SHORT_WRITE;
			return FALSE;
		}
		wdh->bytes_dumped += sizeof(mtp2_hdr);
		break;

	case WTAP_ENCAP_LINUX_LAPD:
		/*
		 * Write the LAPD header.
		 */
		memset(&lapd_hdr, 0, sizeof(lapd_hdr));
		phtons(&lapd_hdr[LAPD_SLL_PKTTYPE_OFFSET],
		    pseudo_header->lapd.pkttype);
		phtons(&lapd_hdr[LAPD_SLL_PROTOCOL_OFFSET], ETH_P_LAPD);
		lapd_hdr[LAPD_SLL_ADDR_OFFSET + 0] =
		    pseudo_header->lapd.we_network?0x01:0x00;
		nwritten = fwrite(&lapd_hdr, 1, sizeof(lapd_hdr), wdh->fh);
		if (nwritten != sizeof(lapd_hdr)) {
			if (nwritten == 0 && ferror(wdh->fh))
				*err = errno;
			else
				*err = WTAP_ERR_SHORT_WRITE;
			return FALSE;
		}
		wdh->bytes_dumped += sizeof(lapd_hdr);
		break;

	case WTAP_ENCAP_SITA:
		/*
		 * Write the SITA header.
		 */
		memset(&sita_hdr, 0, sizeof(sita_hdr));
		sita_hdr[SITA_FLAGS_OFFSET]   = pseudo_header->sita.flags;
		sita_hdr[SITA_SIGNALS_OFFSET] = pseudo_header->sita.signals;
		sita_hdr[SITA_ERRORS1_OFFSET] = pseudo_header->sita.errors1;
		sita_hdr[SITA_ERRORS2_OFFSET] = pseudo_header->sita.errors2;
		sita_hdr[SITA_PROTO_OFFSET]   = pseudo_header->sita.proto;
		nwritten = fwrite(&sita_hdr, 1, sizeof(sita_hdr), wdh->fh);
		if (nwritten != sizeof(sita_hdr)) {
			if (nwritten == 0 && ferror(wdh->fh))
				*err = errno;
			else
				*err = WTAP_ERR_SHORT_WRITE;
			return FALSE;
		}
		wdh->bytes_dumped += sizeof(sita_hdr);
		break;

	case WTAP_ENCAP_USB_LINUX:
		/*
		 * Write out the pseudo-header; it has the same format
		 * as the Linux USB header, and that header is supposed
		 * to be written in the host byte order of the machine
		 * writing the file.
		 */
		nwritten = fwrite(&pseudo_header->linux_usb, 1,
		    sizeof(pseudo_header->linux_usb), wdh->fh);
		if (nwritten != sizeof(pseudo_header->linux_usb)) {
			if (nwritten == 0 && ferror(wdh->fh))
				*err = errno;
			else
				*err = WTAP_ERR_SHORT_WRITE;
			return FALSE;
		}
		wdh->bytes_dumped += sizeof(lapd_hdr);
		break;

	case WTAP_ENCAP_ERF:
	         /*
		 * Write the ERF header.
		 */
	        memset(&erf_hdr, 0, sizeof(erf_hdr));
		pletonll(&erf_hdr[0], pseudo_header->erf.phdr.ts);
		erf_hdr[8] = pseudo_header->erf.phdr.type;
		erf_hdr[9] = pseudo_header->erf.phdr.flags;
		phtons(&erf_hdr[10], pseudo_header->erf.phdr.rlen);
		phtons(&erf_hdr[12], pseudo_header->erf.phdr.lctr);
		phtons(&erf_hdr[14], pseudo_header->erf.phdr.wlen);
		size = sizeof(struct erf_phdr);

		switch(pseudo_header->erf.phdr.type & 0x7F) {
		case ERF_TYPE_MC_HDLC:
		case ERF_TYPE_MC_RAW:
		case ERF_TYPE_MC_ATM:
		case ERF_TYPE_MC_RAW_CHANNEL:
		case ERF_TYPE_MC_AAL5:
		case ERF_TYPE_MC_AAL2:
		case ERF_TYPE_COLOR_MC_HDLC_POS:
		  phtonl(&erf_hdr[16], pseudo_header->erf.subhdr.mc_hdr);
		  size += sizeof(struct erf_mc_hdr);
		  break;
		case ERF_TYPE_ETH:
		case ERF_TYPE_COLOR_ETH:
		case ERF_TYPE_DSM_COLOR_ETH:
		  phtons(&erf_hdr[16], pseudo_header->erf.subhdr.eth_hdr);
		  size += sizeof(struct erf_eth_hdr);
		  break;
		default:
		  break;
		}
		nwritten = wtap_dump_file_write(wdh, erf_hdr, size);
		if (nwritten != (guint) size) {
			if (nwritten == 0 && wtap_dump_file_ferror(wdh))
				*err = wtap_dump_file_ferror(wdh);
			else
				*err = WTAP_ERR_SHORT_WRITE;
			return FALSE;
		}
		wdh->bytes_dumped += size;
		break;

	case WTAP_ENCAP_I2C:
		/*
		 * Write the I2C header.
		 */
		memset(&i2c_hdr, 0, sizeof(i2c_hdr));
		i2c_hdr.bus = pseudo_header->i2c.bus |
			(pseudo_header->i2c.is_event ? 0x80 : 0x00);
		phtonl((guint8 *)&i2c_hdr.flags, pseudo_header->i2c.flags);
		nwritten = fwrite(&i2c_hdr, 1, sizeof(i2c_hdr), wdh->fh);
		if (nwritten != sizeof(i2c_hdr)) {
			if (nwritten == 0 && ferror(wdh->fh))
				*err = errno;
			else
				*err = WTAP_ERR_SHORT_WRITE;
			return FALSE;
		}
		wdh->bytes_dumped += sizeof(i2c_hdr);
		break;
	}

	nwritten = wtap_dump_file_write(wdh, pd, phdr->caplen);
	if (nwritten != phdr->caplen) {
		if (nwritten == 0 && wtap_dump_file_ferror(wdh))
			*err = wtap_dump_file_ferror(wdh);
		else
			*err = WTAP_ERR_SHORT_WRITE;
		return FALSE;
	}
        wdh->bytes_dumped += phdr->caplen;
	return TRUE;
}
