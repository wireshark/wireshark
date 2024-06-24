/** @file
 *
 * Declarations of ARP address types.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __ARPTYPES_H__
#define __ARPTYPES_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Definitions taken from Linux "linux/if_arp.h" header file, and from


 */

/*
 * ARP protocol HARDWARE identifiers.
 *
 * From
 *
 *	https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-2
 *
 * XXX - ARPHRD_NETROM is from Linux linux/if_arp.h file; 0 is reserved,
 * probably permanently, by RFC 5494.
 */
#define ARPHRD_NETROM			0	/* from KA9Q: NET/ROM pseudo	*/
#define ARPHRD_ETHER			1	/* Ethernet 10Mbps		*/
#define	ARPHRD_EETHER			2	/* Experimental Ethernet	*/
#define	ARPHRD_AX25			3	/* AX.25 Level 2		*/
#define	ARPHRD_PRONET			4	/* PROnet token ring		*/
#define	ARPHRD_CHAOS			5	/* Chaosnet			*/
#define	ARPHRD_IEEE802			6	/* IEEE 802.2 Ethernet/TR/TB	*/
#define	ARPHRD_ARCNET			7	/* ARCnet			*/
#define	ARPHRD_HYPERCH			8	/* Hyperchannel			*/
#define	ARPHRD_LANSTAR			9	/* Lanstar			*/
#define	ARPHRD_AUTONET			10	/* Autonet Short Address	*/
#define	ARPHRD_LOCALTLK			11	/* Localtalk			*/
#define	ARPHRD_LOCALNET			12	/* LocalNet (IBM PCNet/Sytek LocalNET) */
#define	ARPHRD_ULTRALNK			13	/* Ultra link			*/
#define	ARPHRD_SMDS			14	/* SMDS				*/
#define ARPHRD_DLCI			15	/* Frame Relay DLCI		*/
#define ARPHRD_ATM			16	/* ATM				*/
#define ARPHRD_HDLC			17	/* HDLC				*/
#define ARPHRD_FIBREC			18	/* Fibre Channel		*/
#define ARPHRD_ATM2225			19	/* ATM (RFC 2225)		*/
#define ARPHRD_SERIAL			20	/* Serial Line			*/
#define ARPHRD_ATM2			21	/* ATM				*/
#define ARPHRD_MS188220			22	/* MIL-STD-188-220		*/
#define ARPHRD_METRICOM			23	/* Metricom STRIP		*/
#define ARPHRD_IEEE1394			24	/* IEEE 1394.1995		*/
#define ARPHRD_MAPOS			25	/* MAPOS			*/
#define ARPHRD_TWINAX			26	/* Twinaxial			*/
#define ARPHRD_EUI_64			27	/* EUI-64			*/
#define ARPHRD_HIPARP			28	/* HIPARP			*/
#define ARPHRD_IP_ARP_ISO_7816_3	29	/* IP and ARP over ISO 7816-3	*/
#define ARPHRD_ARPSEC			30	/* ARPSec			*/
#define ARPHRD_IPSEC_TUNNEL		31	/* IPsec tunnel			*/
#define ARPHRD_INFINIBAND		32	/* InfiniBand			*/
#define ARPHRD_TIA_102_PRJ_25_CAI	33	/* TIA-102 Project 25 CAI	*/
#define ARPHRD_WIEGAND_INTERFACE	34	/* Wiegand Interface		*/
#define ARPHRD_PURE_IP			35	/* Pure IP			*/
#define ARPHRD_HW_EXP1			36	/* HW_EXP1			*/
#define ARPHRD_HFI			37	/* HFI				*/
#define ARPHRD_UB			38	/* Unified Bus (UB)		*/
#define ARPHRD_HW_EXP2			256	/* HW_EXP2			*/
#define ARPHRD_AETHERNET		257	/* AEthernet			*/

/*
 * Virtual ARP types for non ARP hardware used in Linux cooked mode,
 * from Linux linux/if_arp.h file.
 *
 * XXX - note that these values already have eaten into the values
 * registered in the IANA documentation.  Should there be separate sets
 * of values, and separate value_string tables, one solely for ARP
 * hardware values, and the other with the Linux values, to use with,
 * for example, Linux cooked capture headers?  The values 512 and
 * above are probably *less* likely to collide.
 */
/*#define ARPHRD_SLIP			256*/
/*#define ARPHRD_CSLIP			257 */
#define ARPHRD_SLIP6			258
#define ARPHRD_CSLIP6			259
#define ARPHRD_RSRVD			260	/* Notional KISS type		*/
#define ARPHRD_ADAPT			264
#define ARPHRD_ROSE			270
#define ARPHRD_X25			271	/* CCITT X.25			*/
#define ARPHRD_HWX25			272	/* Boards with X.25 in firmware	*/
#define ARPHRD_CAN			280	/* Controller Area Network	*/

#define ARPHRD_PPP			512
#define ARPHRD_CISCO			513	/* Cisco HDLC			*/
#define ARPHRD_LAPB			516	/* LAPB				*/
#define ARPHRD_DDCMP			517	/* Digital's DDCMP protocol	*/
#define ARPHRD_RAWHDLC			518	/* Raw HDLC			*/
#define ARPHRD_RAWIP			519	/* Raw IP			*/

#define ARPHRD_TUNNEL			768	/* IPIP tunnel			*/
#define ARPHRD_TUNNEL6			769	/* IP6IP6 tunnel		*/
#define ARPHRD_FRAD			770	/* Frame Relay Access Device	*/
#define ARPHRD_SKIP			771	/* SKIP vif			*/
#define ARPHRD_LOOPBACK			772	/* Loopback */
#define ARPHRD_FDDI			774	/* Fiber Distributed Data Interface */
#define ARPHRD_BIF			775	/* AP1000 BIF			*/
#define ARPHRD_SIT			776	/* sit0 device - IPv6-in-IPv4	*/
#define ARPHRD_IPDDP			777	/* IP over DDP tunneller	*/
#define ARPHRD_IPGRE			778	/* GRE over IP */
#define ARPHRD_PIMREG			779	/* PIMSM register interface	*/
#define ARPHRD_HIPPI			780	/* High Performance Parallel Interface */
#define ARPHRD_ASH			781	/* Nexus 64Mbps Ash		*/
#define ARPHRD_ECONET			782	/* Acorn Econet			*/
#define ARPHRD_IRDA			783	/* Linux-IrDA			*/
/* ARP works differently on different FC media .. so  */
#define ARPHRD_FCPP			784	/* Point to point fibrechannel	*/
#define ARPHRD_FCAL			785	/* Fibrechannel arbitrated loop */
#define ARPHRD_FCPL			786	/* Fibrechannel public loop	*/
#define ARPHRD_FCFABRIC			787	/* Fibrechannel fabric		*/
	/* 787->799 reserved for fibrechannel media types */
#define ARPHRD_IEEE802_TR		800	/* Magic type ident for TR	*/
#define ARPHRD_IEEE80211		801	/* IEEE 802.11			*/
#define ARPHRD_IEEE80211_PRISM		802	/* IEEE 802.11 + Prism2 header  */
#define ARPHRD_IEEE80211_RADIOTAP	803	/* IEEE 802.11 + radiotap header */
#define ARPHRD_IEEE802154		804
#define ARPHRD_IEEE802154_MONITOR	805	/* IEEE 802.15.4 network monitor */

#define ARPHRD_PHONET			820	/* PhoNet media type		*/
#define ARPHRD_PHONET_PIPE		821	/* PhoNet pipe header		*/
#define ARPHRD_CAIF			822	/* CAIF media type		*/
#define ARPHRD_IP6GRE			823	/* GRE over IPv6		*/
#define ARPHRD_NETLINK			824	/* netlink */
#define ARPHRD_6LOWPAN			825	/* IPv6 over LoWPAN		*/
#define ARPHRD_VSOCKMON			826	/* Vsock monitor header		*/

#define ARPHRD_VOID			0xFFFF	/* Void type, nothing is known	*/
#define ARPHRD_NONE			0xFFFE	/* zero header length		*/

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* arptypes.h */
