/* packet-gsmtap.h
 * Routines for GSMTAP packet disassembly
 *
 * (C) 2008-2016 Harald Welte <laforge@gnumonks.org>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _PACKET_GSMTAP_H
#define _PACKET_GSMTAP_H

/* ====== DO NOT MAKE UNAPPROVED MODIFICATIONS HERE ===== */
/* The following types and definitions are imported from libosmocore,
 * the original source of the GSMTAP format.
 *
 * prior to getting them accepted/included into the official Osmocom
 * GSMTAP definition, available from
 * http://cgit.osmocom.org/libosmocore/tree/include/osmocom/core/gsmtap.h
 *
 * The GSMTAP maintainer can be contacted via the
 * openbsc@lists.osmocom.org mailing list, or by private e-mail
 * to laforge@gnumonks.org
 */
/* ====== DO NOT MAKE UNAPPROVED MODIFICATIONS HERE ===== */
#define GSMTAP_TYPE_UM			0x01
#define GSMTAP_TYPE_ABIS		0x02
#define GSMTAP_TYPE_UM_BURST		0x03	/* raw burst bits */
#define GSMTAP_TYPE_SIM			0x04
#define GSMTAP_TYPE_TETRA_I1		0x05	/* tetra air interface */
#define GSMTAP_TTPE_TETRA_I1_BURST	0x06	/* tetra air interface */
#define GSMTAP_TYPE_WMX_BURST		0x07	/* WiMAX burst */
#define GSMTAP_TYPE_GB_LLC		0x08 /* GPRS Gb interface: LLC */
#define GSMTAP_TYPE_GB_SNDCP		0x09 /* GPRS Gb interface: SNDCP */
#define GSMTAP_TYPE_GMR1_UM		0x0a	/* GMR-1 L2 packets */
#define GSMTAP_TYPE_UMTS_RLC_MAC	0x0b
#define GSMTAP_TYPE_UMTS_RRC		0x0c
#define GSMTAP_TYPE_LTE_RRC		0x0d	/* LTE interface */
#define GSMTAP_TYPE_LTE_MAC		0x0e	/* LTE MAC interface */
#define GSMTAP_TYPE_LTE_MAC_FRAMED	0x0f	/* LTE MAC with context hdr */
#define GSMTAP_TYPE_OSMOCORE_LOG	0x10	/* libosmocore logging */
#define GSMTAP_TYPE_QC_DIAG		0x11	/* Qualcomm DIAG frame */
#define GSMTAP_TYPE_LTE_NAS		0x12	/* LTE Non-Access Stratum */
#define GSMTAP_TYPE_E1T1		0x13	/* E1/T1 line traces */

/* ====== DO NOT MAKE UNAPPROVED MODIFICATIONS HERE ===== */
#define GSMTAP_BURST_UNKNOWN		0x00
#define GSMTAP_BURST_FCCH		0x01
#define GSMTAP_BURST_PARTIAL_SCH	0x02
#define GSMTAP_BURST_SCH		0x03
#define GSMTAP_BURST_CTS_SCH		0x04
#define GSMTAP_BURST_COMPACT_SCH	0x05
#define GSMTAP_BURST_NORMAL		0x06
#define GSMTAP_BURST_DUMMY		0x07
#define GSMTAP_BURST_ACCESS		0x08
#define GSMTAP_BURST_NONE		0x09
/* WiMAX bursts */
#define GSMTAP_BURST_CDMA_CODE		0x10	/* WiMAX CDMA Code Attribute burst */
#define GSMTAP_BURST_FCH		0x11	/* WiMAX FCH burst */
#define GSMTAP_BURST_FFB		0x12	/* WiMAX Fast Feedback burst */
#define GSMTAP_BURST_PDU		0x13	/* WiMAX PDU burst */
#define GSMTAP_BURST_HACK		0x14	/* WiMAX HARQ ACK burst */
#define GSMTAP_BURST_PHY_ATTRIBUTES	0x15	/* WiMAX PHY Attributes burst */

/* ====== DO NOT MAKE UNAPPROVED MODIFICATIONS HERE ===== */
/* sub-types for TYPE_UM */
#define GSMTAP_CHANNEL_UNKNOWN		0x00
#define GSMTAP_CHANNEL_BCCH		0x01
#define GSMTAP_CHANNEL_CCCH		0x02
#define GSMTAP_CHANNEL_RACH		0x03
#define GSMTAP_CHANNEL_AGCH		0x04
#define GSMTAP_CHANNEL_PCH		0x05
#define GSMTAP_CHANNEL_SDCCH		0x06
#define GSMTAP_CHANNEL_SDCCH4		0x07
#define GSMTAP_CHANNEL_SDCCH8		0x08
#define GSMTAP_CHANNEL_TCH_F		0x09
#define GSMTAP_CHANNEL_TCH_H		0x0a
#define GSMTAP_CHANNEL_PACCH		0x0b
#define GSMTAP_CHANNEL_CBCH52		0x0c
#define GSMTAP_CHANNEL_PDTCH		0x0d
#define GSMTAP_CHANNEL_PTCCH		0x0e
#define GSMTAP_CHANNEL_CBCH51		0x0f
#define GSMTAP_CHANNEL_VOICE_F		0x10
#define GSMTAP_CHANNEL_VOICE_H		0x11

/* GPRS Coding Scheme CS1..4 */
#define GSMTAP_GPRS_CS_BASE	0x20
#define GSMTAP_GPRS_CS(N)	(GSMTAP_GPRS_CS_BASE + N)
/* (E) GPRS Coding Scheme MCS0..9 */
#define GSMTAP_GPRS_MCS_BASE	0x30
#define GSMTAP_GPRS_MCS(N)	(GSMTAP_GPRS_MCS_BASE + N)

#define GSMTAP_CHANNEL_ACCH	0x80

/* ====== DO NOT MAKE UNAPPROVED MODIFICATIONS HERE ===== */
/* sub-types for TYPE_TETRA_AIR */
#define GSMTAP_TETRA_BSCH			0x01
#define GSMTAP_TETRA_AACH			0x02
#define GSMTAP_TETRA_SCH_HU			0x03
#define GSMTAP_TETRA_SCH_HD			0x04
#define GSMTAP_TETRA_SCH_F			0x05
#define GSMTAP_TETRA_BNCH			0x06
#define GSMTAP_TETRA_STCH			0x07
#define GSMTAP_TETRA_TCH_F			0x08

/* ====== DO NOT MAKE UNAPPROVED MODIFICATIONS HERE ===== */
/* sub-types for TYPE_GMR1 */
#define GSMTAP_GMR1_UNKNOWN			0x00
#define GSMTAP_GMR1_BCCH			0x01
#define GSMTAP_GMR1_CCCH			0x02	/* either AGCH or PCH */
#define GSMTAP_GMR1_PCH				0x03
#define GSMTAP_GMR1_AGCH			0x04
#define GSMTAP_GMR1_BACH			0x05
#define GSMTAP_GMR1_RACH			0x06
#define GSMTAP_GMR1_CBCH			0x07
#define GSMTAP_GMR1_SDCCH			0x08
#define GSMTAP_GMR1_TACCH			0x09
#define GSMTAP_GMR1_GBCH			0x0a

#define GSMTAP_GMR1_SACCH			0x01	/* to be combined with _TCH{6,9}   */
#define GSMTAP_GMR1_FACCH			0x02	/* to be combines with _TCH{3,6,9} */
#define GSMTAP_GMR1_DKAB			0x03	/* to be combined with _TCH3 */
#define GSMTAP_GMR1_TCH3			0x10
#define GSMTAP_GMR1_TCH6			0x14
#define GSMTAP_GMR1_TCH9			0x18

/* ====== DO NOT MAKE UNAPPROVED MODIFICATIONS HERE ===== */
/* sub-types for TYPE_E1T1 */
#define GSMTAP_E1T1_LAPD			0x01	/* Q.921 LAPD */
#define GSMTAP_E1T1_FR				0x02	/* Frame Relay */
#define GSMTAP_E1T1_RAW				0x03	/* raw/transparent B-channel */
#define GSMTAP_E1T1_TRAU16			0x04	/* 16k TRAU frames; sub-slot 0-3 */
#define GSMTAP_E1T1_TRAU8			0x05	/* 8k TRAU frames; sub-slot 0-7 */

#define GSMTAP_ARFCN_F_PCS			0x8000
#define GSMTAP_ARFCN_F_UPLINK			0x4000
#define GSMTAP_ARFCN_MASK			0x3fff

#define GSMTAP_UDP_PORT				4729

/* This is the header as it is used by gsmtap-generating software.
 * It is not used by the wireshark dissector and provided for reference only.
struct gsmtap_hdr {
	guint8 version;		// version, set to 0x01 currently
	guint8 hdr_len;		// length in number of 32bit words
	guint8 type;		// see GSMTAP_TYPE_*
	guint8 timeslot;	// timeslot (0..7 on Um)

	guint16 arfcn;		// ARFCN (frequency)
	gint8 signal_dbm;	// signal level in dBm
	gint8 snr_db;		// signal/noise ratio in dB

	guint32 frame_number;	// GSM Frame Number (FN)

	guint8 sub_type;	// Type of burst/channel, see above
	guint8 antenna_nr;	// Antenna Number
	guint8 sub_slot;	// sub-slot within timeslot
	guint8 res;		// reserved for future use (RFU)
}
 */

#endif /* _PACKET_GSMTAP_H */

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
