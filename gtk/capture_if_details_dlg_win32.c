/* capture_if_details_dlg.c
 * Routines for capture interface details window (only Win32!)
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
# include "config.h"
#endif


#if defined HAVE_LIBPCAP && defined _WIN32

#include <time.h>
#include <string.h>

#include <gtk/gtk.h>

#include <epan/value_string.h>
#include <epan/addr_resolv.h>

#include "../file.h"
#include "../capture.h"
#include "../simple_dialog.h"

#include "gtk/main.h"
#include "gtk/dlg_utils.h"
#include "gtk/gui_utils.h"
#include "gtk/help_dlg.h"
#include "gtk/capture_if_details_dlg_win32.h"

#include <winsock2.h>    /* Needed here to force a definition of WINVER           */
                         /* for some (all ?) Microsoft compilers newer than vc6.  */
                         /* (If windows.h were used instead, there might be       */
                         /*  issues re winsock.h included before winsock2.h )     */
#include <windowsx.h>

#ifdef HAVE_NTDDNDIS_H
#include <Ntddndis.h>
/* VC 6.0 with SDK has the same Ntddndis.h as MSVC2003 */
# if (_MSC_VER <= 1200)
# undef _MSC_VER
# define _MSC_VER 1310
# endif
#endif

#include "../capture_wpcap_packet.h"

/* packet32.h requires sockaddr_storage
 * whether sockaddr_storage is defined or not depends on the Platform SDK
 * version installed. The only one not defining it is the SDK that comes
 * with MSVC 6.0 (WINVER 0x0400).
 *
 * copied from RFC2553 (and slightly modified because of datatypes) ...
 * XXX - defined more than once, move this to a header file */
#ifndef WINVER
#error WINVER not defined ...
#endif
#if (WINVER <= 0x0400) && defined(_MSC_VER)
typedef unsigned short eth_sa_family_t;

/*
 * Desired design of maximum size and alignment
 */
#define ETH_SS_MAXSIZE    128  /* Implementation specific max size */
#define ETH_SS_ALIGNSIZE  (sizeof (gint64 /*int64_t*/))
                         /* Implementation specific desired alignment */
/*
 * Definitions used for sockaddr_storage structure paddings design.
 */
#define ETH_SS_PAD1SIZE   (ETH_SS_ALIGNSIZE - sizeof (eth_sa_family_t))
#define ETH_SS_PAD2SIZE   (ETH_SS_MAXSIZE - (sizeof (eth_sa_family_t) + \
                              ETH_SS_PAD1SIZE + ETH_SS_ALIGNSIZE))

struct sockaddr_storage {
    eth_sa_family_t  __ss_family;     /* address family */
    /* Following fields are implementation specific */
    char      __ss_pad1[ETH_SS_PAD1SIZE];
              /* 6 byte pad, this is to make implementation */
              /* specific pad up to alignment field that */
              /* follows explicit in the data structure */
    gint64 /*int64_t*/   __ss_align;     /* field to force desired structure */
               /* storage alignment */
    char      __ss_pad2[ETH_SS_PAD2SIZE];
              /* 112 byte pad to achieve desired size, */
              /* _SS_MAXSIZE value minus size of ss_family */
              /* __ss_pad1, __ss_align fields is 112 */
};
/* ... copied from RFC2553 */
#endif /* WINVER */

#include <Packet32.h>

#define DETAILS_STR_MAX     1024


/* The informations and definitions used here are coming from various places on the web:
 *
 * ndiswrapper (various NDIS related definitions)
 *  http://cvs.sourceforge.net/viewcvs.py/ndiswrapper/ndiswrapper/driver/
 *
 * ReactOS (various NDIS related definitions)
 *  http://www.reactos.org/generated/doxygen/d2/d6d/ndis_8h-source.html
 *
 * IEEE802.11 "Detailed NDIS OID Log for a 802.11b Miniport"
 *  http://www.ndis.com/papers/ieee802_11_log.htm
 *
 * FreeBSD (various NDIS related definitions)
 *  http://lists.freebsd.org/pipermail/p4-projects/2004-January/003433.html
 *
 * MS WHDC "Network Drivers and Windows"
 *  http://www.microsoft.com/whdc/archive/netdrv_up.mspx
 *
 * IEEE "Get IEEE 802" (the various 802.11 docs)
 *  http://standards.ieee.org/getieee802/802.11.html
 *
 * MS MSDN "Network Devices: Windows Driver Kit"
 *  http://msdn.microsoft.com/library/default.asp?url=/library/en-us/NetXP_r/hh/NetXP_r/netref_4c297a96-2ba5-41ed-ab21-b7a9cfaa9b4d.xml.asp
 *
 * MS MSDN "Microsoft Windows CE .NET 4.2 Network Driver Reference"
 *  http://msdn.microsoft.com/library/default.asp?url=/library/en-us/wceddk40/html/cxgrfNetworkDriverReference.asp
 *
 * MS MSDN (some explanations of a special MS 802.11 Information Element)
 *  http://msdn.microsoft.com/library/default.asp?url=/library/en-us/randz/protocol/securing_public_wi-fi_hotspots.asp
 *
 * "WLANINFO fuer Windows XP"
 *  http://www-pc.uni-regensburg.de/systemsw/TOOLS/wlaninfo.htm
 */

/********************************************************************************/
/* definitions that would usually come from the windows DDK (device driver kit) */
/* and are not part of the ntddndis.h file delivered with WinPcap */

/* Required OIDs */
#define OID_GEN_VLAN_ID				0x0001021C

/* Optional OIDs */
#define OID_GEN_MEDIA_CAPABILITIES		0x00010201
#define OID_GEN_PHYSICAL_MEDIUM			0x00010202

/* Optional OIDs */
#define OID_GEN_NETWORK_LAYER_ADDRESSES 0x00010118
#define OID_GEN_TRANSPORT_HEADER_OFFSET 0x00010119


/* This will probably break if you're using VC++ 6 _and_ have a newer SDK. */
#if (_MSC_VER <= 1200) || (_MSC_VER == 1310)
#if (_MSC_VER <= 1200)
/* Physical medium (OID_GEN_PHYSICAL_MEDIUM) */
typedef enum ndis_phys_medium {
	NdisPhysicalMediumUnspecified,
	NdisPhysicalMediumWirelessLan,
	NdisPhysicalMediumCableModem,
	NdisPhysicalMediumPhoneLine,
	NdisPhysicalMediumPowerLine,
	NdisPhysicalMediumDSL,
	NdisPhysicalMediumFibreChannel,
	NdisPhysicalMedium1394,
	NdisPhysicalMediumWirelessWan,
	NdisPhysicalMediumMax
};

/* flag definitions for OID_GEN_MAC_OPTIONS */
#define NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA     0x00000001
#define NDIS_MAC_OPTION_RECEIVE_SERIALIZED      0x00000002
#define NDIS_MAC_OPTION_TRANSFERS_NOT_PEND      0x00000004
#define NDIS_MAC_OPTION_NO_LOOPBACK             0x00000008
#define NDIS_MAC_OPTION_FULL_DUPLEX             0x00000010
#define NDIS_MAC_OPTION_EOTX_INDICATION         0x00000020
#define NDIS_MAC_OPTION_8021P_PRIORITY          0x00000040
#define NDIS_MAC_OPTION_8021Q_VLAN              0x00000080

/* 802.11 OIDs */
#define OID_802_11_BSSID			0x0D010101
#define OID_802_11_SSID				0x0D010102
#define OID_802_11_NETWORK_TYPES_SUPPORTED	0x0D010203
#define OID_802_11_NETWORK_TYPE_IN_USE		0x0D010204
#define OID_802_11_TX_POWER_LEVEL		0x0D010205
#define OID_802_11_RSSI				0x0D010206
#define OID_802_11_RSSI_TRIGGER			0x0D010207
#define OID_802_11_INFRASTRUCTURE_MODE		0x0D010108
#define OID_802_11_FRAGMENTATION_THRESHOLD	0x0D010209
#define OID_802_11_RTS_THRESHOLD		0x0D01020A
#define OID_802_11_NUMBER_OF_ANTENNAS		0x0D01020B
#define OID_802_11_RX_ANTENNA_SELECTED		0x0D01020C
#define OID_802_11_TX_ANTENNA_SELECTED		0x0D01020D
#define OID_802_11_SUPPORTED_RATES		0x0D01020E
#define OID_802_11_DESIRED_RATES		0x0D010210
#define OID_802_11_CONFIGURATION		0x0D010211
#define OID_802_11_STATISTICS			0x0D020212
#define OID_802_11_ADD_WEP			0x0D010113
#define OID_802_11_REMOVE_WEP			0x0D010114
#define OID_802_11_DISASSOCIATE			0x0D010115
#define OID_802_11_POWER_MODE			0x0D010216
#define OID_802_11_BSSID_LIST			0x0D010217
#define OID_802_11_AUTHENTICATION_MODE		0x0D010118
#define OID_802_11_PRIVACY_FILTER		0x0D010119
#define OID_802_11_BSSID_LIST_SCAN		0x0D01011A
#define OID_802_11_WEP_STATUS			0x0D01011B

#endif /*(_MSC_VER <= 1200)*/

#define OID_802_11_ENCRYPTION_STATUS		OID_802_11_WEP_STATUS
#define OID_802_11_RELOAD_DEFAULTS		0x0D01011C
#define OID_802_11_ADD_KEY			0x0D01011D
#define OID_802_11_REMOVE_KEY			0x0D01011E
#define OID_802_11_ASSOCIATION_INFORMATION	0x0D01011F
#define OID_802_11_TEST				0x0D010120
#define OID_802_11_CAPABILITY			0x0D010122
#define OID_802_11_PMKID			0x0D010123

#if (_MSC_VER <= 1200)

/* PnP and power management OIDs */
#define OID_PNP_CAPABILITIES			0xFD010100
#define OID_PNP_SET_POWER			0xFD010101
#define OID_PNP_QUERY_POWER			0xFD010102
#define OID_PNP_ADD_WAKE_UP_PATTERN		0xFD010103
#define OID_PNP_REMOVE_WAKE_UP_PATTERN		0xFD010104
#define OID_PNP_WAKE_UP_PATTERN_LIST		0xFD010105
#define OID_PNP_ENABLE_WAKE_UP			0xFD010106

/* Current infrastructure mode (OID_802_11_INFRASTRUCTURE_MODE) */
enum network_infrastructure {
	Ndis802_11IBSS,
	Ndis802_11Infrastructure,
	Ndis802_11AutoUnknown,
	Ndis802_11InfrastructureMax
};

/* Current authentication mode (OID_802_11_AUTHENTICATION_MODE) */
enum authentication_mode {
	Ndis802_11AuthModeOpen,
	Ndis802_11AuthModeShared,
	Ndis802_11AuthModeAutoSwitch,
	Ndis802_11AuthModeWPA,
	Ndis802_11AuthModeWPAPSK,
	Ndis802_11AuthModeWPANone,
	Ndis802_11AuthModeWPA2,
	Ndis802_11AuthModeWPA2PSK,
	Ndis802_11AuthModeMax
};

/* Current network type (OID_802_11_NETWORK_TYPES_SUPPORTED / OID_802_11_NETWORK_TYPE_IN_USE) */
enum network_type {
	Ndis802_11FH,
	Ndis802_11DS,
	Ndis802_11OFDM5,
	Ndis802_11OFDM24,
	/* MSDN site uses Ndis802_11Automode, which is not mentioned
	 * in DDK, so add one and assign it to
	 * Ndis802_11NetworkTypeMax */
	Ndis802_11Automode,
	Ndis802_11NetworkTypeMax = Ndis802_11Automode
};

/* Current encryption status (OID_802_11_ENCRYPTION_STATUS) */
enum encryption_status {
	Ndis802_11WEPEnabled,
	Ndis802_11Encryption1Enabled = Ndis802_11WEPEnabled,
	Ndis802_11WEPDisabled,
	Ndis802_11EncryptionDisabled = Ndis802_11WEPDisabled,
	Ndis802_11WEPKeyAbsent,
	Ndis802_11Encryption1KeyAbsent = Ndis802_11WEPKeyAbsent,
	Ndis802_11WEPNotSupported,
	Ndis802_11EncryptionNotSupported = Ndis802_11WEPNotSupported,
	Ndis802_11Encryption2Enabled,
	Ndis802_11Encryption2KeyAbsent,
	Ndis802_11Encryption3Enabled,
	Ndis802_11Encryption3KeyAbsent
};

#endif /*(_MSC_VER <= 1200)*/

typedef struct _NDIS_802_11_FIXED_IEs
{
  UCHAR  Timestamp[8];
  USHORT  BeaconInterval;
  USHORT  Capabilities;
} NDIS_802_11_FIXED_IEs, *PNDIS_802_11_FIXED_IEs;

#endif /* (_MSC_VER <= 1200) || (_MSC_VER == 1310) */


/* Currently associated SSID (OID_802_11_SSID) */
#define NDIS_ESSID_MAX_SIZE 32
struct ndis_essid {
	ULONG length;
	UCHAR essid[NDIS_ESSID_MAX_SIZE+1];
};


/* some definitions needed for the following structs */
#define NDIS_MAX_RATES_EX 16
typedef UCHAR mac_address[/* ETH_ALEN */ 6];
typedef UCHAR ndis_rates[NDIS_MAX_RATES_EX];

/* configuration, e.g. frequency (OID_802_11_CONFIGURATION / OID_802_11_BSSID_LIST) */
struct /*packed*/ ndis_configuration {
	ULONG length;
	ULONG beacon_period;
	ULONG atim_window;
	ULONG ds_config;
	struct ndis_configuration_fh {
		ULONG length;
		ULONG hop_pattern;
		ULONG hop_set;
		ULONG dwell_time;
	} fh_config;
};

/* bssid list item (OID_802_11_BSSID_LIST) */
struct ndis_ssid_item {
	ULONG length;
	mac_address mac;
	UCHAR reserved[2];
	struct ndis_essid ssid;
	ULONG privacy;
	LONG rssi;
	UINT net_type;
	struct ndis_configuration config;
	UINT mode;
	ndis_rates rates;
	ULONG ie_length;
	UCHAR ies[1];
};


/* bssid list (OID_802_11_BSSID_LIST) */
struct ndis_bssid_list {
	ULONG num_items;
	struct ndis_ssid_item items[1];
};


/******************************************************************************/
/* OID_TCP_TASK_OFFLOAD specific definitions that would usually come from the */
/* windows DDK (device driver kit) and are not part of the ntddndis.h file */
/* delivered with WinPcap */

/* optional OID */
#define OID_TCP_TASK_OFFLOAD    0xFC010201

/* task id's */
typedef enum _NDIS_TASK {
  TcpIpChecksumNdisTask,
  IpSecNdisTask,
  TcpLargeSendNdisTask,
  MaxNdisTask
} NDIS_TASK, *PNDIS_TASK;

/* TaskBuffer content on TcpIpChecksumNdisTask */
typedef struct _NDIS_TASK_TCP_IP_CHECKSUM
{
  struct
  {
    ULONG    IpOptionsSupported:1;
    ULONG    TcpOptionsSupported:1;
    ULONG    TcpChecksum:1;
    ULONG    UdpChecksum:1;
    ULONG    IpChecksum:1;
  } V4Transmit;

  struct
  {
    ULONG    IpOptionsSupported:1;
    ULONG    TcpOptionsSupported:1;
    ULONG    TcpChecksum:1;
    ULONG    UdpChecksum:1;
    ULONG    IpChecksum:1;
  } V4Receive;

  struct
  {
    ULONG    IpOptionsSupported:1;
    ULONG    TcpOptionsSupported:1;
    ULONG    TcpChecksum:1;
    ULONG    UdpChecksum:1;
  } V6Transmit;

  struct
  {
    ULONG    IpOptionsSupported:1;
    ULONG    TcpOptionsSupported:1;
    ULONG    TcpChecksum:1;
    ULONG    UdpChecksum:1;
  } V6Receive;
} NDIS_TASK_TCP_IP_CHECKSUM, *PNDIS_TASK_TCP_IP_CHECKSUM;

/* TaskBuffer content on TcpLargeSendNdisTask */
typedef struct _NDIS_TASK_TCP_LARGE_SEND
{
  ULONG  Version;
  ULONG  MaxOffLoadSize;
  ULONG  MinSegmentCount;
  BOOLEAN  TcpOptions;
  BOOLEAN  IpOptions;
} NDIS_TASK_TCP_LARGE_SEND, *PNDIS_TASK_TCP_LARGE_SEND;

/* Encapsulations */
typedef enum _NDIS_ENCAPSULATION {
  UNSPECIFIED_Encapsulation,
  NULL_Encapsulation,
  IEEE_802_3_Encapsulation,
  IEEE_802_5_Encapsulation,
  LLC_SNAP_ROUTED_Encapsulation,
  LLC_SNAP_BRIDGED_Encapsulation
} NDIS_ENCAPSULATION;

/* Encapsulation format */
typedef struct _NDIS_ENCAPSULATION_FORMAT {
  NDIS_ENCAPSULATION  Encapsulation;
  struct {
    ULONG  FixedHeaderSize : 1;
    ULONG  Reserved : 31;
  } Flags;
  ULONG  EncapsulationHeaderSize;
} NDIS_ENCAPSULATION_FORMAT, *PNDIS_ENCAPSULATION_FORMAT;

/* request struct */
typedef struct _NDIS_TASK_OFFLOAD_HEADER
{
  ULONG  Version;
  ULONG  Size;
  ULONG  Reserved;
  UCHAR  OffsetFirstTask;
  NDIS_ENCAPSULATION_FORMAT  EncapsulationFormat;
} NDIS_TASK_OFFLOAD_HEADER, *PNDIS_TASK_OFFLOAD_HEADER;

/* response struct */
#define NDIS_TASK_OFFLOAD_VERSION 1
typedef struct _NDIS_TASK_OFFLOAD
{
  ULONG  Version;
  ULONG  Size;
  NDIS_TASK  Task;
  ULONG  OffsetNextTask;
  ULONG  TaskBufferLength;
  UCHAR  TaskBuffer[1];
} NDIS_TASK_OFFLOAD, *PNDIS_TASK_OFFLOAD;


/***********************************************************************/
/* value_string's for info functions */


/* NDIS driver medium (OID_GEN_MEDIA_SUPPORTED / OID_GEN_MEDIA_IN_USE) */
static const value_string win32_802_3_medium_vals[] = {
	{ NdisMedium802_3,      "802.3 (Ethernet)" },    /* might as well be WLAN, ... (see NDIS_PHYSICAL_MEDIUM) */
	{ NdisMedium802_5,      "802.5 (Token Ring)" },
	{ NdisMediumFddi,       "FDDI" },
	{ NdisMediumWan,        "WAN" },
	{ NdisMediumLocalTalk,  "Local Talk" },
	{ NdisMediumDix,        "Dix" },
	{ NdisMediumArcnetRaw,  "Arcnet Raw" },
	{ NdisMediumArcnet878_2,"Arcnet 878_2" },
	{ NdisMediumAtm,        "ATM" },
	{ NdisMediumWirelessWan,"Wireless WAN" },
	{ NdisMediumIrda,       "Irda" },
    { 0, NULL }
};

/* NDIS physical driver medium (OID_GEN_PHYSICAL_MEDIUM) */
static const value_string win32_802_3_physical_medium_vals[] = {
	{ NdisPhysicalMediumUnspecified,    "Unspecified" },
	{ NdisPhysicalMediumWirelessLan,    "Wireless LAN" },
	{ NdisPhysicalMediumCableModem,     "Cable Modem (DOCSIS)" },
	{ NdisPhysicalMediumPhoneLine,      "Phone Line" },
	{ NdisPhysicalMediumPowerLine,      "Power Line" },
	{ NdisPhysicalMediumDSL,            "DSL" },
	{ NdisPhysicalMediumFibreChannel,   "Fibre Channel" },
	{ NdisPhysicalMedium1394,           "IEEE 1394" },
	{ NdisPhysicalMediumWirelessWan,    "Wireless WAN" },
    { 0, NULL }
};

static const value_string win32_802_11_infra_mode_vals[] = {
	{ Ndis802_11IBSS,           "Ad Hoc" },
	{ Ndis802_11Infrastructure, "Access Point" },
	{ Ndis802_11AutoUnknown,    "Auto or unknown" },
    { 0, NULL }
};

static const value_string win32_802_11_auth_mode_vals[] = {
	{ Ndis802_11AuthModeOpen,       "Open System" },
	{ Ndis802_11AuthModeShared,     "Shared Key" },
	{ Ndis802_11AuthModeAutoSwitch, "Auto Switch" },
#if (_MSC_VER != 1310)
	{ Ndis802_11AuthModeWPA,        "WPA" },
	{ Ndis802_11AuthModeWPAPSK,     "WPA-PSK (pre shared key)" },
	{ Ndis802_11AuthModeWPANone,    "WPA (ad hoc)" },
#if (_MSC_VER != 1400) /* These are not defined in Ntddndis.h in MSVC2005/MSVC2005EE PSDK */
	{ Ndis802_11AuthModeWPA2,       "WPA2" },
	{ Ndis802_11AuthModeWPA2PSK,    "WPA2-PSK (pre shared key)" },
#endif
#endif
    { 0, NULL }
};

static const value_string win32_802_11_network_type_vals[] = {
	{ Ndis802_11FH,         "FH (frequency-hopping spread-spectrum)" },
	{ Ndis802_11DS,         "DS (direct-sequence spread-spectrum)" },
#if (_MSC_VER != 1310)
	{ Ndis802_11OFDM5,      "5-GHz OFDM" },
	{ Ndis802_11OFDM24,     "2.4-GHz OFDM" },
#if (_MSC_VER != 1400) /* These are not defined in Ntddndis.h in MSVC2005/MSVC2005EE PSDK */
	{ Ndis802_11Automode,   "Auto" },
#endif
#endif
    { 0, NULL }
};

static const value_string win32_802_11_encryption_status_vals[] = {
#if (_MSC_VER != 1310)
	{ Ndis802_11Encryption1Enabled,     "WEP enabled, TKIP & AES disabled, transmit key available" },
	{ Ndis802_11EncryptionDisabled,     "WEP & TKIP & AES disabled, transmit key available" },
	{ Ndis802_11Encryption1KeyAbsent,   "WEP enabled, TKIP & AES disabled, transmit key unavailable" },
	{ Ndis802_11EncryptionNotSupported, "WEP & TKIP & AES not supported" },
	{ Ndis802_11Encryption2Enabled,     "WEP & TKIP enabled, AES disabled, transmit key available" },
	{ Ndis802_11Encryption2KeyAbsent,   "WEP & TKIP enabled, AES disabled, transmit key unavailable" },
	{ Ndis802_11Encryption3Enabled,     "WEP & TKIP & AES enabled, transmit key available" },
	{ Ndis802_11Encryption3KeyAbsent,   "WEP & TKIP & AES enabled, transmit key unavailable" },
#endif
    { 0, NULL }
};

/* frequency to channel mapping (OID_802_11_CONFIGURATION) */
static const value_string win32_802_11_channel_freq_vals[] = {
	{ 2412000, "1 (2412 MHz)" },
	{ 2417000, "2 (2417 MHz)" },
	{ 2422000, "3 (2422 MHz)" },
	{ 2427000, "4 (2427 MHz)" },
	{ 2432000, "5 (2432 MHz)" },
	{ 2437000, "6 (2437 MHz)" },
	{ 2442000, "7 (2442 MHz)" },
	{ 2447000, "8 (2447 MHz)" },
	{ 2452000, "9 (2452 MHz)" },
	{ 2457000, "10 (2457 MHz)" },
	{ 2462000, "11 (2462 MHz)" },
	{ 2467000, "12 (2467 MHz)" },
	{ 2472000, "13 (2472 MHz)" },
	{ 2484000, "14 (2484 MHz)" },
    { 0, NULL }
};

/* frequency to channel mapping (OID_802_11_CONFIGURATION) */
static const value_string win32_802_11_channel_vals[] = {
	{ 2412000, "1" },
	{ 2417000, "2" },
	{ 2422000, "3" },
	{ 2427000, "4" },
	{ 2432000, "5" },
	{ 2437000, "6" },
	{ 2442000, "7" },
	{ 2447000, "8" },
	{ 2452000, "9" },
	{ 2457000, "10" },
	{ 2462000, "11" },
	{ 2467000, "12" },
	{ 2472000, "13" },
	{ 2484000, "14" },
    { 0, NULL }
};


/* Information Element IDs (802.11 Spec: "7.3.2 Information elements") */
#define IE_ID_SSID				0
#define IE_ID_SUPPORTED_RATES	1
#define IE_ID_DS_PARAMETER_SET	3
#define IE_ID_TIM				5
#define IE_ID_COUNTRY			7
#define IE_ID_ERP_INFORMATION	42
#define IE_ID_WPA2				48
#define IE_ID_EXTENDED_SUPPORT_RATES	50
#define IE_ID_VENDOR_SPECIFIC	221

/* ElementID in NDIS_802_11_VARIABLE_IEs */
static const value_string ie_id_vals[] = {
	{ IE_ID_SSID,					"SSID, 802.11" },
	{ IE_ID_SUPPORTED_RATES,		"Supported Rates, 802.11" },
	{ 2,							"FH Parameter Set, 802.11" },
	{ IE_ID_DS_PARAMETER_SET,		"DS Parameter Set, 802.11" },
	{ 4,							"CF Parameter Set, 802.11" },
	{ IE_ID_TIM,					"TIM, 802.11" },
	{ 6,							"IBSS Parameter Set, 802.11" },
	{ IE_ID_COUNTRY,				"Country, 802.11d" },
	{ 8,							"Hopping Pattern Parameters, 802.11d" },
	{ 9,							"Hopping Pattern Table, 802.11d" },
	{ 10,							"Request, 802.11d" },
    /* 11-15 reserved, 802.11d */
	{ 16,							"Challenge text, 802.11" },
    /* 17-31 reserved, 802.11h */
	{ 32,							"Power Constraint, 802.11h" },
	{ 33,							"Power Capability, 802.11h" },
	{ 34,							"TPC Request, 802.11h" },
	{ 35,							"TPC Report, 802.11h" },
	{ 36,							"Supported Channels, 802.11h" },
	{ 37,							"Channel Switch Announcement, 802.11h" },
	{ 38,							"Measurement Request, 802.11h" },
	{ 39,							"Measurement Report, 802.11h" },
	{ 40,							"Quiet, 802.11h" },
	{ 41,							"IBSS DFS, 802.11h" },
	{ IE_ID_ERP_INFORMATION,		"ERP information, 802.11g" },
    /* 43-47 reserved, 802.11i */
	{ IE_ID_WPA2,					"WPA2/RSN (Robust Secure Network), 802.11i" },
    /* 49 reserved, 802.11i */
	{ IE_ID_EXTENDED_SUPPORT_RATES,	"Extended Supported Rates, 802.11g" },
    /* 51-255 reserved, 802.11g */
	{ IE_ID_VENDOR_SPECIFIC,		"WPA, (not 802.11!)" },
    { 0, NULL }
};


static const value_string oid_vals[] = {
	{ OID_GEN_SUPPORTED_LIST, "OID_GEN_SUPPORTED_LIST" },
	{ OID_GEN_HARDWARE_STATUS, "OID_GEN_HARDWARE_STATUS (only internally interesting)" },
	{ OID_GEN_MEDIA_SUPPORTED, "OID_GEN_MEDIA_SUPPORTED" },
	{ OID_GEN_MEDIA_IN_USE, "OID_GEN_MEDIA_IN_USE" },
    { OID_GEN_MAXIMUM_LOOKAHEAD, "OID_GEN_MAXIMUM_LOOKAHEAD (unused)" },
	{ OID_GEN_MAXIMUM_FRAME_SIZE, "OID_GEN_MAXIMUM_FRAME_SIZE (unused)" },
	{ OID_GEN_LINK_SPEED, "OID_GEN_LINK_SPEED" },
	{ OID_GEN_TRANSMIT_BUFFER_SPACE, "OID_GEN_TRANSMIT_BUFFER_SPACE" },
	{ OID_GEN_RECEIVE_BUFFER_SPACE, "OID_GEN_RECEIVE_BUFFER_SPACE" },
	{ OID_GEN_TRANSMIT_BLOCK_SIZE, "OID_GEN_TRANSMIT_BLOCK_SIZE" },
	{ OID_GEN_RECEIVE_BLOCK_SIZE, "OID_GEN_RECEIVE_BLOCK_SIZE" },
	{ OID_GEN_VENDOR_ID, "OID_GEN_VENDOR_ID" },
	{ OID_GEN_VENDOR_DESCRIPTION, "OID_GEN_VENDOR_DESCRIPTION" },
	{ OID_GEN_CURRENT_PACKET_FILTER, "OID_GEN_CURRENT_PACKET_FILTER (info seems to be constant)" },
	{ OID_GEN_CURRENT_LOOKAHEAD, "OID_GEN_CURRENT_LOOKAHEAD (only internally interesting)" },
	{ OID_GEN_DRIVER_VERSION, "OID_GEN_DRIVER_VERSION" },
	{ OID_GEN_MAXIMUM_TOTAL_SIZE, "OID_GEN_MAXIMUM_TOTAL_SIZE" },
	{ OID_GEN_PROTOCOL_OPTIONS, "OID_GEN_PROTOCOL_OPTIONS (info not interesting)" },
    { OID_GEN_MAC_OPTIONS, "OID_GEN_MAC_OPTIONS" },
	{ OID_GEN_MEDIA_CONNECT_STATUS, "OID_GEN_MEDIA_CONNECT_STATUS" },
	{ OID_GEN_MAXIMUM_SEND_PACKETS, "OID_GEN_MAXIMUM_SEND_PACKETS (only internally interesting)" },
	{ OID_GEN_VENDOR_DRIVER_VERSION, "OID_GEN_VENDOR_DRIVER_VERSION" },
	{ OID_GEN_XMIT_OK, "OID_GEN_XMIT_OK" },
	{ OID_GEN_RCV_OK, "OID_GEN_RCV_OK" },
	{ OID_GEN_XMIT_ERROR, "OID_GEN_XMIT_ERROR" },
	{ OID_GEN_RCV_ERROR, "OID_GEN_RCV_ERROR" },
	{ OID_GEN_RCV_NO_BUFFER, "OID_GEN_RCV_NO_BUFFER" },
	{ OID_GEN_DIRECTED_BYTES_XMIT, "OID_GEN_DIRECTED_BYTES_XMIT" },
	{ OID_GEN_DIRECTED_FRAMES_XMIT, "OID_GEN_DIRECTED_FRAMES_XMIT" },
	{ OID_GEN_MULTICAST_BYTES_XMIT, "OID_GEN_MULTICAST_BYTES_XMIT" },
	{ OID_GEN_MULTICAST_FRAMES_XMIT, "OID_GEN_MULTICAST_FRAMES_XMIT" },
	{ OID_GEN_BROADCAST_BYTES_XMIT, "OID_GEN_BROADCAST_BYTES_XMIT" },
	{ OID_GEN_BROADCAST_FRAMES_XMIT, "OID_GEN_BROADCAST_FRAMES_XMIT" },
	{ OID_GEN_DIRECTED_BYTES_RCV, "OID_GEN_DIRECTED_BYTES_RCV" },
	{ OID_GEN_DIRECTED_FRAMES_RCV, "OID_GEN_DIRECTED_FRAMES_RCV" },
	{ OID_GEN_MULTICAST_BYTES_RCV, "OID_GEN_MULTICAST_BYTES_RCV" },
	{ OID_GEN_MULTICAST_FRAMES_RCV, "OID_GEN_MULTICAST_FRAMES_RCV" },
	{ OID_GEN_BROADCAST_BYTES_RCV, "OID_GEN_BROADCAST_BYTES_RCV" },
    { OID_GEN_BROADCAST_FRAMES_RCV, "OID_GEN_BROADCAST_FRAMES_RCV" },
	{ OID_GEN_RCV_CRC_ERROR, "OID_GEN_RCV_CRC_ERROR" },
	{ OID_GEN_TRANSMIT_QUEUE_LENGTH, "OID_GEN_TRANSMIT_QUEUE_LENGTH" },
	{ OID_GEN_GET_TIME_CAPS, "OID_GEN_GET_TIME_CAPS (unsupp, unused)" },
	{ OID_GEN_GET_NETCARD_TIME, "OID_GEN_GET_NETCARD_TIME (unsupp, unused)" },

    { OID_GEN_PHYSICAL_MEDIUM, "OID_GEN_PHYSICAL_MEDIUM" },
	/*{ OID_GEN_MACHINE_NAME, "OID_GEN_MACHINE_NAME (unsupp, unused)" },*/
	{ OID_GEN_VLAN_ID, "OID_GEN_VLAN_ID" },
	{ OID_GEN_MEDIA_CAPABILITIES, "OID_GEN_MEDIA_CAPABILITIES (unsupp, unused)" },

    { OID_GEN_NETWORK_LAYER_ADDRESSES, "OID_GEN_NETWORK_LAYER_ADDRESSES (write only)" },
    { OID_GEN_TRANSPORT_HEADER_OFFSET, "OID_GEN_TRANSPORT_HEADER_OFFSET (write only)" },

	{ OID_802_3_PERMANENT_ADDRESS, "OID_802_3_PERMANENT_ADDRESS" },
	{ OID_802_3_CURRENT_ADDRESS, "OID_802_3_CURRENT_ADDRESS" },
    { OID_802_3_MAXIMUM_LIST_SIZE, "OID_802_3_MAXIMUM_LIST_SIZE (unused)" },
    { OID_802_3_MULTICAST_LIST, "OID_802_3_MULTICAST_LIST (unused)" }, /* XXX */
    { OID_802_3_MAC_OPTIONS, "OID_802_3_MAC_OPTIONS (unsupp, unused)" },

    { OID_802_3_RCV_ERROR_ALIGNMENT, "OID_802_3_RCV_ERROR_ALIGNMENT" },
    { OID_802_3_XMIT_ONE_COLLISION, "OID_802_3_XMIT_ONE_COLLISION" },
    { OID_802_3_XMIT_MORE_COLLISIONS, "OID_802_3_XMIT_MORE_COLLISIONS" },
    { OID_802_3_XMIT_DEFERRED, "OID_802_3_XMIT_DEFERRED" },
    { OID_802_3_XMIT_MAX_COLLISIONS, "OID_802_3_XMIT_MAX_COLLISIONS" },
    { OID_802_3_RCV_OVERRUN, "OID_802_3_RCV_OVERRUN" },
    { OID_802_3_XMIT_UNDERRUN, "OID_802_3_XMIT_UNDERRUN" },
    { OID_802_3_XMIT_HEARTBEAT_FAILURE, "OID_802_3_XMIT_HEARTBEAT_FAILURE (unsupp, used)" },
    { OID_802_3_XMIT_TIMES_CRS_LOST, "OID_802_3_XMIT_TIMES_CRS_LOST (unsupp, used)" },
    { OID_802_3_XMIT_LATE_COLLISIONS, "OID_802_3_XMIT_LATE_COLLISIONS" },

    { OID_802_11_BSSID, "OID_802_11_BSSID" },
	{ OID_802_11_SSID, "OID_802_11_SSID" },
	{ OID_802_11_NETWORK_TYPES_SUPPORTED, "OID_802_11_NETWORK_TYPES_SUPPORTED (info not interesting)" },
	{ OID_802_11_NETWORK_TYPE_IN_USE, "OID_802_11_NETWORK_TYPE_IN_USE" },
	{ OID_802_11_TX_POWER_LEVEL, "OID_802_11_TX_POWER_LEVEL (unsupp, used)" },
	{ OID_802_11_RSSI, "OID_802_11_RSSI" },
	{ OID_802_11_RSSI_TRIGGER, "OID_802_11_RSSI_TRIGGER (unsupp, unused)" },
    { OID_802_11_INFRASTRUCTURE_MODE, "OID_802_11_INFRASTRUCTURE_MODE" },
	{ OID_802_11_FRAGMENTATION_THRESHOLD, "OID_802_11_FRAGMENTATION_THRESHOLD (unused)" },
	{ OID_802_11_RTS_THRESHOLD, "OID_802_11_RTS_THRESHOLD (unused)" },
	{ OID_802_11_NUMBER_OF_ANTENNAS, "OID_802_11_NUMBER_OF_ANTENNAS (unsupp, unused)" },
	{ OID_802_11_RX_ANTENNA_SELECTED, "OID_802_11_RX_ANTENNA_SELECTED (unsupp, unused)" },
	{ OID_802_11_TX_ANTENNA_SELECTED, "OID_802_11_TX_ANTENNA_SELECTED (unsupp, unused)" },
	{ OID_802_11_SUPPORTED_RATES, "OID_802_11_SUPPORTED_RATES" },
	{ OID_802_11_DESIRED_RATES, "OID_802_11_DESIRED_RATES (unsupp, used)" },
	{ OID_802_11_CONFIGURATION, "OID_802_11_CONFIGURATION" },
	{ OID_802_11_STATISTICS, "OID_802_11_STATISTICS (unsupp, unused)" },
	{ OID_802_11_ADD_WEP, "OID_802_11_ADD_WEP (write only)" },
	{ OID_802_11_REMOVE_WEP, "OID_802_11_REMOVE_WEP (write only)" },
	{ OID_802_11_DISASSOCIATE, "OID_802_11_DISASSOCIATE (write only)" },
	{ OID_802_11_POWER_MODE, "OID_802_11_POWER_MODE (info not interesting)" },
	{ OID_802_11_BSSID_LIST, "OID_802_11_BSSID_LIST" },
	{ OID_802_11_AUTHENTICATION_MODE, "OID_802_11_AUTHENTICATION_MODE" },
	{ OID_802_11_PRIVACY_FILTER, "OID_802_11_PRIVACY_FILTER (info not interesting)" },
	{ OID_802_11_BSSID_LIST_SCAN, "OID_802_11_BSSID_LIST_SCAN" },
	{ OID_802_11_WEP_STATUS, "OID_802_11_WEP_STATUS (info not interesting?)" },
	{ OID_802_11_ENCRYPTION_STATUS, "OID_802_11_ENCRYPTION_STATUS (unsupp, used)" },
	{ OID_802_11_RELOAD_DEFAULTS, "OID_802_11_RELOAD_DEFAULTS (write only)" },
	{ OID_802_11_ADD_KEY, "OID_802_11_ADD_KEY (write only)" },
	{ OID_802_11_REMOVE_KEY, "OID_802_11_REMOVE_KEY (write only)" },
	{ OID_802_11_ASSOCIATION_INFORMATION, "OID_802_11_ASSOCIATION_INFORMATION (unused)" }, /* XXX */
	{ OID_802_11_TEST, "OID_802_11_TEST (write only)" },
#if (_MSC_VER != 1400) /* These are not defined in Ntddndis.h in MSVC2005/MSVC2005EE PSDK */
	{ OID_802_11_CAPABILITY, "OID_802_11_CAPABILITY (unsupp, unused)" },
	{ OID_802_11_PMKID, "OID_802_11_PMKID (unsupp, unused)" },
#endif

    /* Token-Ring list is utterly incomplete (contains only the values for MS Loopback Driver) */
    { OID_802_5_PERMANENT_ADDRESS, "OID_802_5_PERMANENT_ADDRESS (unused)" },
    { OID_802_5_CURRENT_ADDRESS, "OID_802_5_CURRENT_ADDRESS (unused)" },
    { OID_802_5_CURRENT_FUNCTIONAL, "OID_802_5_CURRENT_FUNCTIONAL (unused)" },
    { OID_802_5_CURRENT_GROUP, "OID_802_5_CURRENT_GROUP (unused)" },
    { OID_802_5_LAST_OPEN_STATUS, "OID_802_5_LAST_OPEN_STATUS (unused)" },
    { OID_802_5_CURRENT_RING_STATUS, "OID_802_5_CURRENT_RING_STATUS (unused)" },
    { OID_802_5_CURRENT_RING_STATE, "OID_802_5_CURRENT_RING_STATE (unused)" },
    { OID_802_5_LINE_ERRORS, "OID_802_5_LINE_ERRORS (unused)" },
    { OID_802_5_LOST_FRAMES, "OID_802_5_LOST_FRAMES (unused)" },

    /* FDDI list is utterly incomplete (contains only the values for MS Loopback Driver) */
    { OID_FDDI_LONG_PERMANENT_ADDR, "OID_FDDI_LONG_PERMANENT_ADDR (unused)" },
    { OID_FDDI_LONG_CURRENT_ADDR, "OID_FDDI_LONG_CURRENT_ADDR (unused)" },
    { OID_FDDI_LONG_MULTICAST_LIST, "OID_FDDI_LONG_MULTICAST_LIST (unused)" },
    { OID_FDDI_LONG_MAX_LIST_SIZE, "OID_FDDI_LONG_MAX_LIST_SIZE (unused)" },
    { OID_FDDI_SHORT_PERMANENT_ADDR, "OID_FDDI_SHORT_PERMANENT_ADDR (unused)" },
    { OID_FDDI_SHORT_CURRENT_ADDR, "OID_FDDI_SHORT_CURRENT_ADDR (unused)" },
    { OID_FDDI_SHORT_MULTICAST_LIST, "OID_FDDI_SHORT_MULTICAST_LIST (unused)" },
    { OID_FDDI_SHORT_MAX_LIST_SIZE, "OID_FDDI_SHORT_MAX_LIST_SIZE (unused)" },

    /* LocalTalk list is utterly incomplete (contains only the values for MS Loopback Driver) */
    { OID_LTALK_CURRENT_NODE_ID, "OID_LTALK_CURRENT_NODE_ID (unused)" },

    /* Arcnet list is utterly incomplete (contains only the values for MS Loopback Driver) */
    { OID_ARCNET_PERMANENT_ADDRESS, "OID_ARCNET_PERMANENT_ADDRESS (unused)" },
    { OID_ARCNET_CURRENT_ADDRESS, "OID_ARCNET_CURRENT_ADDRESS (unused)" },

    { OID_TCP_TASK_OFFLOAD, "OID_TCP_TASK_OFFLOAD" },

    /* PnP and power management OIDs */
    { OID_PNP_CAPABILITIES, "OID_PNP_CAPABILITIES (unused)" },
    { OID_PNP_SET_POWER, "OID_PNP_SET_POWER (write only)" },
    { OID_PNP_QUERY_POWER, "OID_PNP_QUERY_POWER (unused)" },
    { OID_PNP_ADD_WAKE_UP_PATTERN, "OID_PNP_ADD_WAKE_UP_PATTERN (write only)" },
    { OID_PNP_REMOVE_WAKE_UP_PATTERN, "OID_PNP_REMOVE_WAKE_UP_PATTERN (write only)" },
    { OID_PNP_WAKE_UP_PATTERN_LIST, "OID_PNP_WAKE_UP_PATTERN_LIST (unused)" },
    { OID_PNP_ENABLE_WAKE_UP, "OID_PNP_ENABLE_WAKE_UP (unused)" },

    /* Unknown OID's (seen on an "Intel(R) PRO/Wireless 2200BG" 802.11 interface) */
    { 0xFF100000, "Unknown 0xFF100000 (unused)" },
    { 0xFF100002, "Unknown 0xFF100002 (unused)" },
    { 0xFF100003, "Unknown 0xFF100003 (unused)" },
    { 0xFF100004, "Unknown 0xFF100004 (unused)" },
    { 0xFF100005, "Unknown 0xFF100005 (unused)" },
    { 0xFF100006, "Unknown 0xFF100006 (unused)" },
    { 0xFF100007, "Unknown 0xFF100007 (unused)" },
    { 0xFF100009, "Unknown 0xFF100009 (unused)" },
    { 0xFF10000b, "Unknown 0xFF10000b (unused)" },
    { 0xFF10000c, "Unknown 0xFF10000c (unused)" },
    { 0xFF10000e, "Unknown 0xFF10000e (unused)" },
    { 0xFF10000f, "Unknown 0xFF10000f (unused)" },
    /* continued by a lot more 0xFF... values */

    { 0, NULL }
};


/***************************************************************************/
/* debug functions, query or list supported NDIS OID's */


static void
supported_list(LPADAPTER adapter)
{
    unsigned char       values[10000];
    int                 length;


    g_warning("supported_list_unhandled");
    length = sizeof(values);
    if (wpcap_packet_request(adapter, OID_GEN_SUPPORTED_LIST, FALSE /* !set */, values, &length)) {
        guint32 *value = (guint32 *) values;

        while (length>=4) {
            printf("OID: 0x%08X %s\n", *value, val_to_str(*value, oid_vals, "unknown"));

            value++;
            length-=4;
        }
    }
}


static gboolean
supported_query_oid(LPADAPTER adapter, guint32 oid)
{
    unsigned char       values[10000];
    int                 length;


    length = sizeof(values);
    if (wpcap_packet_request(adapter, OID_GEN_SUPPORTED_LIST, FALSE /* !set */, values, &length)) {
        guint32 *value = (guint32 *) values;

        while (length>=4) {
            if(*value == oid) {
                return TRUE;
            }
            value++;
            length-=4;
        }
    }

    return FALSE;
}


/******************************************************************************/
/* info functions, get and display various NDIS driver values */


#if 0
    GtkWidget *meter;
    GtkWidget *val_lb;

static GtkWidget *
add_meter_to_table(GtkWidget *list, guint *row, gchar *title,
                 int value, gchar *value_title,
                 int min, int max,
                 int yellow_level,
                 GList *scale)
{
    GtkWidget *label;
    gchar     *indent;
    GtkWidget *main_hb;


    /* the label */
    indent = g_strdup_printf("   %s", title);
    label = gtk_label_new(indent);
    g_free(indent);
    gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.5);
    gtk_table_attach(GTK_TABLE(list), label, 0, 1, *row, *row+1, GTK_EXPAND|GTK_FILL, 0, 0,0);

    /* the level meter */
    main_hb = gtk_hbox_new(FALSE, 6);

    meter = gtk_vumeter_new ();

    gtk_vumeter_set_orientation(GTK_VUMETER(meter), GTK_VUMETER_LEFT_TO_RIGHT);

    gtk_vumeter_set_min_max(GTK_VUMETER(meter), &min, &max);
    gtk_vumeter_set_yellow_level (GTK_VUMETER(meter), yellow_level);
    gtk_vumeter_set_thickness (GTK_VUMETER(meter), 10);
    gtk_vumeter_set_thickness_reduction (GTK_VUMETER(meter), 2);
    gtk_vumeter_set_scale_hole_size (GTK_VUMETER(meter), 2);
    gtk_vumeter_set_colors_inverted (GTK_VUMETER(meter), TRUE);

    if(scale) {
        gtk_vumeter_set_scale_items(GTK_VUMETER(meter), scale);
    }

    gtk_vumeter_set_level(GTK_VUMETER(meter), value);

    gtk_box_pack_start                (GTK_BOX(main_hb),
                                             meter,
                                             TRUE /*expand*/,
                                             TRUE /*fill*/,
                                             0 /* padding */);

    val_lb = gtk_label_new(value_title);
    gtk_widget_set_size_request(val_lb, 50, -1);
    gtk_misc_set_alignment(GTK_MISC(val_lb), 1.0, 0.5);

    gtk_box_pack_start                (GTK_BOX(main_hb),
                                             val_lb,
                                             FALSE /*expand*/,
                                             FALSE /*fill*/,
                                             0 /* padding */);

    gtk_table_attach(GTK_TABLE(list), main_hb, 1, 2, *row, *row+1, GTK_EXPAND|GTK_FILL, 0, 0,0);

    *row = *row + 1;

    return meter;
}

#endif

static void
add_row_to_table(GtkWidget *list, guint *row, gchar *title, const gchar *value, gboolean sensitive)
{
    GtkWidget *label;
    gchar     *indent;

    if(strlen(value) != 0) {
        indent = g_strdup_printf("   %s", title);
    } else {
        indent = g_strdup(title);
    }
    label = gtk_label_new(indent);
    g_free(indent);
    gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.5);
    gtk_widget_set_sensitive(label, sensitive);
    gtk_table_attach(GTK_TABLE(list), label, 0, 1, *row, *row+1, GTK_EXPAND | GTK_FILL, 0, 0,0);

    label = gtk_label_new(value);
    gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.5);
    gtk_widget_set_sensitive(label, sensitive);
    gtk_table_attach(GTK_TABLE(list), label, 1, 2, *row, *row+1, GTK_EXPAND | GTK_FILL, 0, 0,0);

    *row = *row + 1;
}


static void
add_string_to_table_sensitive(GtkWidget *list, guint *row, gchar *title, gchar *value, gboolean sensitive)
{
    add_row_to_table(list, row, title, value, sensitive);
}


static void
add_string_to_table(GtkWidget *list, guint *row, gchar *title, const gchar *value)
{
    add_row_to_table(list, row, title, value, TRUE);
}


static void
ssid_details(GtkWidget *table, guint *row, struct ndis_essid *ssid_in) {
    struct ndis_essid   ssid[2]; /* prevent an off by one error */


    ssid[0] = *ssid_in;
    g_assert(ssid->length <= NDIS_ESSID_MAX_SIZE);

    if(ssid->length != 0) {
        ssid->essid[ssid->length] = '\0';
        add_string_to_table(table, row, "SSID (Service Set IDentifier)", ssid->essid);
    } else {
        add_string_to_table(table, row, "SSID (Service Set IDentifier)", "(currently not associated with an SSID)");
    }
}


static GString *
rates_details(unsigned char *values, int length) {
    int                 i;
    GString             *Rates;
    float               float_value;
    int                 int_value;


    Rates = g_string_new("");

    if(length != 0) {
        i = 0;
        while(length--) {
            if(values[i]) {
                if(i != 0) {
                    g_string_append(Rates, "/");
                }

                float_value = ((float) (values[i] & 0x7F)) / 2;

                /* reduce the screen estate by showing fractions only where required */
                int_value = (int)float_value;
                if(float_value == (float)int_value) {
                    g_string_append_printf(Rates, "%.0f", float_value);
                } else {
                    g_string_append_printf(Rates, "%.1f", float_value);
                }
            }
            i++;
        }
        Rates = g_string_append(Rates, " MBits/s");
    } else {
        Rates = g_string_append(Rates, "-");
    }

    return Rates;
}


#if 0
static GList *
rates_vu_list(unsigned char *values, int length, int *max)
{
    int                 i;
    GList               *Rates = NULL;
    GtkVUMeterScaleItem * item;


    *max = 0;

    if(length == 0) {
        return NULL;
    }

    /* add a zero scale point */
    item = g_malloc(sizeof(GtkVUMeterScaleItem));
    item->level = 0;
    item->large = TRUE;
    item->label = "0";
    Rates = g_list_append(Rates, item);

    /* get the maximum rate */
    for(i=0; i<length; i++) {
        gint level;

        if(values[i]) {
            level = (values[i] & 0x7F) / 2;

            if(level > *max) {
                *max = level;
            }
        }
    }

    /* debug: fake the 108MBit entry (I don't own one :-) */
    *max = 108;

    item = g_malloc(sizeof(GtkVUMeterScaleItem));
    item->level = 108;
    item->large = TRUE;
    item->label = "108";
    Rates = g_list_append(Rates, item);

    for(i=0; i<length; i++) {
        if(values[i]) {
            /* reduce the screen estate by showing fractions only where required */
            item = g_malloc(sizeof(GtkVUMeterScaleItem));

            item->level = (values[i] & 0x7F) / 2;

            /* common data rates: */
            /* 802.11  (15.1)  : mandatory: 2, 1 */
            /* 802.11a (17.1)  : mandatory: 24, 12, 6 optional: 54, 48, 36, 18, 9 */
            /* 802.11b (18.1)  : mandatory: 11, 5.5 (+ 2, 1) */
            /* 802.11g (19.1.1): mandatory: 24, 12, 11, 6, 5.5, 2, 1 optional: 54, 48, 36, 33, 22, 18, 9 */
            /* 802.11n: ? */
            /* proprietary: 108 */

            switch(item->level) {
            case 2:
                if(*max >= 108) {
                    item->large = FALSE;
                    item->label = NULL;
                } else {
                    item->large = TRUE;
                    item->label = "2";
                }
                break;
            case 5:
                item->large = TRUE;
                item->label = "5.5";
                break;
            case 11:
                item->large = TRUE;
                item->label = "11";
                break;
            case 18:
                item->large = TRUE;
                item->label = "18";
                break;
            case 24:
                item->large = TRUE;
                item->label = "24";
                break;
            case 36:
                item->large = TRUE;
                item->label = "36";
                break;
            case 48:
                item->large = TRUE;
                item->label = "48";
                break;
            case 54:
                item->large = TRUE;
                item->label = "54";
                break;
            case 72: /* XXX */
                item->large = TRUE;
                item->label = "72";
                break;
            case 96: /* XXX */
                item->large = TRUE;
                item->label = "96";
                break;
            case 108:
                item->large = TRUE;
                item->label = "108";
                break;
            default:
                item->large = FALSE;
                item->label = NULL;
            }

            Rates = g_list_append(Rates, item);
        }
    }

    return Rates;
}
#endif


/* debugging only */
static void
hex(unsigned char *p, int len) {
    int i = 0;
    while(len) {
        g_warning("%u: 0x%x (%u) '%c'", i, *p, *p,
            isprint(*p) ? *p : '.');

        i++;
        p++;
        len--;
    }
}


static void
capture_if_details_802_11_bssid_list(GtkWidget *main_vb, struct ndis_bssid_list *bssid_list)
{
    struct ndis_ssid_item   *bssid_item;
    unsigned char           mac[6];
    const gchar             *manuf_name;
    GString                 *Rates;


    if(bssid_list->num_items != 0) {
        char *titles[] = { "SSID", "MAC", "Vendor", "Privacy", "RSSI" , "Network Type" , "Infra. Mode" , "Ch." , "Rates", "Country" };
        GtkWidget   *list;
        gboolean    privacy_required;
        gboolean    privacy_wpa;
        gboolean    privacy_wpa2;

        gchar ssid_buff[DETAILS_STR_MAX];
        gchar mac_buff[DETAILS_STR_MAX];
        gchar vendor_buff[DETAILS_STR_MAX];
        gchar privacy_buff[DETAILS_STR_MAX];
        gchar rssi_buff[DETAILS_STR_MAX];
        gchar nettype_buff[DETAILS_STR_MAX];
        gchar infra_buff[DETAILS_STR_MAX];
        gchar freq_buff[DETAILS_STR_MAX];
        gchar country_buff[DETAILS_STR_MAX] = "";

        list = simple_list_new(10, titles);
        gtk_box_pack_start(GTK_BOX(main_vb), list, TRUE /*expand*/, TRUE /*fill*/, 0 /* padding */);

        bssid_item = &bssid_list->items[0];

        while(bssid_list->num_items--) {
            privacy_required = FALSE;
            privacy_wpa = FALSE;
            privacy_wpa2 = FALSE;

            /* SSID */
            if(bssid_item->ssid.length > DETAILS_STR_MAX-1) {
                bssid_item->ssid.length = DETAILS_STR_MAX-1;
            }
            memcpy(ssid_buff, bssid_item->ssid.essid, bssid_item->ssid.length);
            ssid_buff[bssid_item->ssid.length] = '\0';

            /* MAC */
            memcpy(mac, &bssid_item->mac, sizeof(mac));
            g_snprintf(mac_buff, DETAILS_STR_MAX, "%02X:%02X:%02X:%02X:%02X:%02X",
                mac[0], mac[1], mac[2],
                mac[3], mac[4], mac[5]);

            /* Vendor */
            manuf_name = get_manuf_name_if_known(mac);
            if(manuf_name != NULL) {
                g_strlcpy(vendor_buff, manuf_name, DETAILS_STR_MAX);
            } else {
                vendor_buff[0] = '\0';
            }

            /* Supported Rates */
            Rates = rates_details(bssid_item->rates, NDIS_MAX_RATES_EX);

            /* RSSI */
            g_snprintf(rssi_buff, DETAILS_STR_MAX, "%d dBm", bssid_item->rssi);

            /* Privacy */
            /* (flag is set, if WEP (or higher) privacy is required) */
            if(bssid_item->privacy) {
                privacy_required = TRUE;
            }

            /* Network Type */
            g_snprintf(nettype_buff, sizeof(nettype_buff), "%s",
                val_to_str(bssid_item->net_type, win32_802_11_network_type_vals, "(0x%x)"));

            /* Infrastructure Mode */
            g_snprintf(infra_buff, sizeof(infra_buff), "%s",
                val_to_str(bssid_item->mode, win32_802_11_infra_mode_vals, "(0x%x)"));

            /* Channel */
            g_snprintf(freq_buff, sizeof(freq_buff), "%s",
                val_to_str(bssid_item->config.ds_config, win32_802_11_channel_vals, "(%u kHz)"));

            /* XXX - IE Length is currently not really supported here */
            {
                int len = bssid_item->ie_length;
                unsigned char *iep = bssid_item->ies;
                unsigned char id;
                unsigned el_len;
                NDIS_802_11_FIXED_IEs *fixed_ies;
/*#define DEBUG_IE*/
#ifdef DEBUG_IE
                const gchar     *manuf_name;
                gchar           string_buff[DETAILS_STR_MAX];
#endif


                fixed_ies = (NDIS_802_11_FIXED_IEs *) iep;

#if 0
                  UCHAR  Timestamp[8];
  USHORT  BeaconInterval;
  USHORT  Capabilities;
} NDIS_802_11_FIXED_IEs, *PNDIS_802_11_FIXED_IEs;
#endif

                iep += sizeof(NDIS_802_11_FIXED_IEs);
                len = bssid_item->ie_length - sizeof(NDIS_802_11_FIXED_IEs);

                while(len >= 2) {
                    id = *iep;
                    iep++;
                    el_len = *iep;
                    iep++;
                    len-=2;

#ifdef DEBUG_IE
                    g_warning("ID: %s (%u) Len: %u",
                        val_to_str(id, ie_id_vals, "0x%x"), id, el_len);
#endif

					switch(id) {
						case(IE_ID_COUNTRY):
							if(el_len >= 6)
							g_snprintf(country_buff, sizeof(country_buff), "%c%c: Ch: %u-%u Max: %ddBm",
								iep[0], iep[1], iep[3], iep[4], iep[5]);
							break;
						case(IE_ID_WPA2):
							privacy_wpa2 = TRUE;
							break;
						case(IE_ID_VENDOR_SPECIFIC):	/* WPA */
							privacy_wpa = TRUE;

#ifdef DEBUG_IE
							/* include information from epan/packet-ieee80211.c dissect_vendor_ie_wpawme() */
							manuf_name = get_manuf_name_if_known(iep);
							if(manuf_name != NULL) {
								g_snprintf(string_buff, DETAILS_STR_MAX, "%02X:%02X:%02X (%s) Type: %02X",
									*(iep), *(iep+1), *(iep+2), manuf_name, *(iep+3));
							} else {
								g_snprintf(string_buff, DETAILS_STR_MAX, "%02X:%02X:%02X Type: %02X",
									*(iep), *(iep+1), *(iep+2), *(iep+3));
							}

							g_warning("%s", string_buff);
							iep += 4;
							el_len-= 4;
							len -= 4;

							g_warning("WPA IE: %u", id);
							hex(iep, el_len);
#endif
							break;

						case(IE_ID_SSID):
						case(IE_ID_SUPPORTED_RATES):
						case(IE_ID_DS_PARAMETER_SET):
						case(IE_ID_TIM):
						case(IE_ID_ERP_INFORMATION):
						case(IE_ID_EXTENDED_SUPPORT_RATES):
							/* we already have that data, do nothing */
							break;
						default:
							/* unexpected IE_ID, print out hexdump */
							g_warning("Unknown IE ID: %u Len: %u", id, el_len);
							hex(iep, el_len);
                    }

                    iep += el_len;
                    len -= el_len;
                }
            }

            if(privacy_required) {
                if(privacy_wpa2) {
                    /* XXX - how to detect data encryption (TKIP and AES)? */
                    /* XXX - how to detect authentication (PSK or not)? */
                    g_snprintf(privacy_buff, DETAILS_STR_MAX, "WPA2");
                } else {
                    if(privacy_wpa) {
                        /* XXX - how to detect data encryption (TKIP and AES)? */
                        /* XXX - how to detect authentication (PSK or not)? */
                        g_snprintf(privacy_buff, DETAILS_STR_MAX, "WPA");
                    } else {
                        /* XXX - how to detect authentication (Open System and Shared Key)? */
                        g_snprintf(privacy_buff, DETAILS_STR_MAX, "WEP");
                    }
                }
            } else {
                g_snprintf(privacy_buff, DETAILS_STR_MAX, "None");
            }

            simple_list_append(list,
                0, ssid_buff,
                1, mac_buff,
                2, vendor_buff,
                3, privacy_buff,
                4, rssi_buff,
                5, nettype_buff,
                6, infra_buff,
                7, freq_buff,
                8, Rates->str,
                9, country_buff,
                -1);

            g_string_free(Rates, TRUE /* free_segment */);

            /* the bssid_list isn't an array, but a sequence of variable length items */
            bssid_item = (struct ndis_ssid_item *) (((char *) bssid_item) + bssid_item->length);
        }
    }
}

static int
capture_if_details_802_11(GtkWidget *table, GtkWidget *main_vb, guint *row, LPADAPTER adapter) {
    ULONG               ulong_value;
    LONG                rssi = -100;
    unsigned int        uint_value;
    unsigned char       values[100];
    struct ndis_essid   ssid;
    int                 length;
    struct ndis_bssid_list      *bssid_list;
    struct ndis_configuration   *configuration;
    gchar               string_buff[DETAILS_STR_MAX];
    GString             *Rates;
    int                 entries = 0;
    const gchar         *manuf_name;


    add_string_to_table(table, row, "Current network", "");

    /* SSID */
    length = sizeof(struct ndis_essid);
    memset(&ssid, 0, length);
    if (wpcap_packet_request(adapter, OID_802_11_SSID, FALSE /* !set */, (char *) &ssid, &length)) {
        ssid_details(table, row, &ssid);
        entries++;
    } else {
        add_string_to_table(table, row, "SSID (Service Set IDentifier)", "-");
    }

    /* BSSID */
    length = sizeof(values);
    memset(values, 0, 6);
    if (wpcap_packet_request(adapter, OID_802_11_BSSID, FALSE /* !set */, values, &length)) {
        manuf_name = get_manuf_name_if_known(values);
        if(manuf_name != NULL) {
            g_snprintf(string_buff, DETAILS_STR_MAX, "%02X:%02X:%02X:%02X:%02X:%02X (%s)",
                values[0], values[1], values[2],
                values[3], values[4], values[5],
                manuf_name);
        } else {
            g_snprintf(string_buff, DETAILS_STR_MAX, "%02X:%02X:%02X:%02X:%02X:%02X",
                values[0], values[1], values[2],
                values[3], values[4], values[5]);
        }
        entries++;
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "BSSID (Basic Service Set IDentifier)", string_buff);

    /* Network type in use */
    if (wpcap_packet_request_uint(adapter, OID_802_11_NETWORK_TYPE_IN_USE, &uint_value)) {
        add_string_to_table(table, row, "Network type used",
            val_to_str(uint_value, win32_802_11_network_type_vals, "(0x%x)"));
        entries++;
    } else {
        add_string_to_table(table, row, "Network type used", "-");
    }

    /* Infrastructure mode */
    if (wpcap_packet_request_ulong(adapter, OID_802_11_INFRASTRUCTURE_MODE, &uint_value)) {
        add_string_to_table(table, row, "Infrastructure mode",
            val_to_str(uint_value, win32_802_11_infra_mode_vals, "(0x%x)"));
        entries++;
    } else {
        add_string_to_table(table, row, "Infrastructure mode", "-");
    }

    /* Authentication mode */
    if (wpcap_packet_request_ulong(adapter, OID_802_11_AUTHENTICATION_MODE, &uint_value)) {
        add_string_to_table(table, row, "Authentication mode",
            val_to_str(uint_value, win32_802_11_auth_mode_vals, "(0x%x)"));
        entries++;
    } else {
        add_string_to_table(table, row, "Authentication mode", "-");
    }

    /* Encryption (WEP) status */
    if (wpcap_packet_request_ulong(adapter, OID_802_11_ENCRYPTION_STATUS, &uint_value)) {
        add_string_to_table(table, row, "Encryption status",
            val_to_str(uint_value, win32_802_11_encryption_status_vals, "(0x%x)"));
        entries++;
    } else {
        add_string_to_table(table, row, "Encryption status", "-");
    }

    /* TX power */
    if (wpcap_packet_request_ulong(adapter, OID_802_11_TX_POWER_LEVEL, &ulong_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%ld mW", ulong_value);
        add_string_to_table(table, row, "TX power", string_buff);
        entries++;
    } else {
        add_string_to_table(table, row, "TX power", "-");
    }

    /* RSSI */
    if (wpcap_packet_request_ulong(adapter, OID_802_11_RSSI, &rssi)) {
#if 0
        int i;
        GList * scale_items = NULL;
        GList * current;
        GtkVUMeterScaleItem *item;


        for (i = 0; i <= 100; i++) {
            item = g_malloc(sizeof(GtkVUMeterScaleItem));

            item->level = i;
            item->large = !(i%5);
            item->label = NULL;

            switch(item->level) {
            case 0:
                item->label = "-100 ";
                break;
            case 20:
                item->label = "-80 ";
                break;
            case 40:
                item->label = "-60 ";
                break;
            case 60:
                item->label = "-40 ";
                break;
            case 80:
                item->label = "-20 ";
                break;
            case 100:
                item->label = "0";
                break;
            default:
                item->label = NULL;
            }

            scale_items = g_list_append(scale_items, item);
        }

        if(rssi < -100) {
            rssi = -100;
        }
        g_snprintf(string_buff, DETAILS_STR_MAX, "%ld dBm", rssi);

        add_meter_to_table(table, row, "RSSI (Received Signal Strength Indication)",
            rssi+100 , string_buff, -100+100, 0+100, -80+100, scale_items);
        current = scale_items;
        while (current != NULL) {
            g_free(current->data);

            current = g_list_next(current);
        }
        g_list_free(scale_items);
        entries++;
#endif
    } else {
        add_string_to_table(table, row, "RSSI (Received Signal Strength Indication)", "-");
    }

    /* Supported Rates */
    length = sizeof(values);
    if (!wpcap_packet_request(adapter, OID_802_11_SUPPORTED_RATES, FALSE /* !set */, values, &length)) {
        length = 0;
    } else {
        entries++;
    }

    /* if we can get the link speed, show Supported Rates in level meter format */
    if (length != 0 && wpcap_packet_request_uint(adapter, OID_GEN_LINK_SPEED, &uint_value)) {
#if 0
        int max;
        int yellow;
        GList *rates_list;

		GList * current;


		rates_list = rates_vu_list(values, length, &max);

        /* if we don't have a signal, we might not have a valid link speed */
        if(rssi == -100) {
            uint_value = 0;
        }

        uint_value /= 10 * 1000;
        g_snprintf(string_buff, DETAILS_STR_MAX, "%u MBits/s", uint_value);

        if(max >= 54) {
            yellow = 2;
        } else {
            yellow = 1;
        }

        add_meter_to_table(table, row, "Link Speed",
                uint_value, string_buff, 0, max, yellow, rates_list);
        current = rates_list;
        while (current != NULL) {
            g_free(current->data);

            current = g_list_next(current);
        }
        g_list_free(rates_list);
#endif
    }

    /* Supported Rates in String format */
    Rates = rates_details(values, length);
    add_string_to_table(table, row, "Supported Rates", Rates->str);
    g_string_free(Rates, TRUE /* free_segment */);

    /* Desired Rates */
    length = sizeof(values);
    if (!wpcap_packet_request(adapter, OID_802_11_DESIRED_RATES, FALSE /* !set */, values, &length)) {
        length = 0;
    } else {
        entries++;
    }

    Rates = rates_details(values, length);
    add_string_to_table(table, row, "Desired Rates", Rates->str);
    g_string_free(Rates, TRUE /* free_segment */);

    /* Configuration (e.g. frequency) */
    length = sizeof(values);
    if (wpcap_packet_request(adapter, OID_802_11_CONFIGURATION, FALSE /* !set */, (char *) values, &length)) {
        configuration = (struct ndis_configuration *) values;

        add_string_to_table(table, row, "Channel",
            val_to_str(configuration->ds_config, win32_802_11_channel_freq_vals, "(%u kHz)"));
        entries++;
    } else {
        add_string_to_table(table, row, "Channel", "-");
    }

    /* BSSID list: first trigger a scan */
    length = sizeof(uint_value);
    if (wpcap_packet_request(adapter, OID_802_11_BSSID_LIST_SCAN, TRUE /* set */, (char *) &uint_value, &length)) {
#if 0
        g_warning("BSSID list scan done");
    } else {
        g_warning("BSSID list scan failed");
#endif
    }

    /* BSSID list: get scan results */
    /* XXX - we might have to wait up to 7 seconds! */
	length = sizeof(ULONG) + sizeof(struct ndis_ssid_item) * 16;
	bssid_list = g_malloc(length);
	/* some drivers don't set bssid_list->num_items to 0 if
	   OID_802_11_BSSID_LIST returns no items (prism54 driver, e.g.,) */
	memset(bssid_list, 0, length);

    if (wpcap_packet_request(adapter, OID_802_11_BSSID_LIST, FALSE /* !set */, (char *) bssid_list, &length)) {
        add_string_to_table(table, row, "", "");
        add_string_to_table(table, row, "Available networks (BSSID list)", "");

        capture_if_details_802_11_bssid_list(main_vb, bssid_list);
        entries += bssid_list->num_items;
    } else {
        add_string_to_table(table, row, "Available networks (BSSID list)", "-");
    }

    g_free(bssid_list);

    return entries;
}


static int
capture_if_details_802_3(GtkWidget *table, GtkWidget *main_vb, guint *row, LPADAPTER adapter) {
    unsigned int    uint_value;
    unsigned char   values[100];
    int             length;
    gchar           string_buff[DETAILS_STR_MAX];
    const gchar     *manuf_name;
    int             entries = 0;


    add_string_to_table(table, row, "Characteristics", "");

    length = sizeof(values);
    if (wpcap_packet_request(adapter, OID_802_3_PERMANENT_ADDRESS, FALSE /* !set */, values, &length)) {
        manuf_name = get_manuf_name_if_known(values);
        if(manuf_name != NULL) {
            g_snprintf(string_buff, DETAILS_STR_MAX, "%02X:%02X:%02X:%02X:%02X:%02X (%s)",
                values[0], values[1], values[2],
                values[3], values[4], values[5],
                manuf_name);
        } else {
            g_snprintf(string_buff, DETAILS_STR_MAX, "%02X:%02X:%02X:%02X:%02X:%02X",
                values[0], values[1], values[2],
                values[3], values[4], values[5]);
        }
        entries++;
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Permanent station address", string_buff);

    length = sizeof(values);
    if (wpcap_packet_request(adapter, OID_802_3_CURRENT_ADDRESS, FALSE /* !set */, values, &length)) {
        manuf_name = get_manuf_name_if_known(values);
        if(manuf_name != NULL) {
            g_snprintf(string_buff, DETAILS_STR_MAX, "%02X:%02X:%02X:%02X:%02X:%02X (%s)",
                values[0], values[1], values[2],
                values[3], values[4], values[5],
                manuf_name);
        } else {
            g_snprintf(string_buff, DETAILS_STR_MAX, "%02X:%02X:%02X:%02X:%02X:%02X",
                values[0], values[1], values[2],
                values[3], values[4], values[5]);
        }
        entries++;
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Current station address", string_buff);


    add_string_to_table(table, row, "", "");
    add_string_to_table(table, row, "Statistics", "");

    if (wpcap_packet_request_uint(adapter, OID_802_3_RCV_ERROR_ALIGNMENT, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
        entries++;
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Packets received with alignment error", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_802_3_XMIT_ONE_COLLISION, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
        entries++;
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Packets transmitted with one collision", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_802_3_XMIT_MORE_COLLISIONS, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
        entries++;
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Packets transmitted with more than one collision", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_802_3_RCV_OVERRUN, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
        entries++;
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Packets not received due to overrun", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_802_3_XMIT_DEFERRED, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
        entries++;
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Packets transmitted after deferred", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_802_3_XMIT_MAX_COLLISIONS, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
        entries++;
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Packets not transmitted due to collisions", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_802_3_XMIT_UNDERRUN, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
        entries++;
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Packets not transmitted due to underrun", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_802_3_XMIT_HEARTBEAT_FAILURE, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
        entries++;
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Packets transmitted with heartbeat failure", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_802_3_XMIT_TIMES_CRS_LOST, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
        entries++;
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Times carrier sense signal lost during transmission", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_802_3_XMIT_LATE_COLLISIONS, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
        entries++;
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Times late collisions detected", string_buff);

    return entries;
}

static int
capture_if_details_task_offload(GtkWidget *table, GtkWidget *main_vb, guint *row, LPADAPTER adapter) {
    NDIS_TASK_OFFLOAD_HEADER *offload;
    unsigned char   values[10000];
    int             length;
    gchar           string_buff[DETAILS_STR_MAX];
    int             entries = 0;
    int             TcpIpChecksumSupported = 0;
    int             IpSecSupported = 0;
    int             TcpLargeSendSupported = 0;


    /* Task Offload */
    offload = (NDIS_TASK_OFFLOAD_HEADER *) values;
    offload->Version = NDIS_TASK_OFFLOAD_VERSION;
    offload->Size = sizeof(NDIS_TASK_OFFLOAD_HEADER);
    offload->Reserved = 0;
    offload->OffsetFirstTask = 0;
    /* the EncapsulationFormat seems to be ignored on a query (using Ethernet values) */
    offload->EncapsulationFormat.Encapsulation = IEEE_802_3_Encapsulation;
    offload->EncapsulationFormat.Flags.FixedHeaderSize = 1;
    offload->EncapsulationFormat.Flags.Reserved = 0;
    offload->EncapsulationFormat.EncapsulationHeaderSize = 14; /* sizeof(struct ether_header) */;

    length = sizeof(values);
    if (wpcap_packet_request(adapter, OID_TCP_TASK_OFFLOAD, FALSE /* !set */, values, &length)) {
        NDIS_TASK_OFFLOAD *of;
        /* XXX - hmmm, using a tvb for this? */
        unsigned char *valuep = values + offload->OffsetFirstTask;
        length -= offload->OffsetFirstTask;

        do {
            of = (NDIS_TASK_OFFLOAD *) valuep;

            switch(of->Task) {
            case TcpIpChecksumNdisTask:
                {
                    NDIS_TASK_TCP_IP_CHECKSUM *tic = (NDIS_TASK_TCP_IP_CHECKSUM *) (of->TaskBuffer);

                    entries++;
                    TcpIpChecksumSupported++;

                    add_string_to_table(table, row, "TCP/IP Checksum", "");

                    g_snprintf(string_buff, DETAILS_STR_MAX, "");
                    add_string_to_table(table, row, "V4 transmit checksum", "");

                    g_snprintf(string_buff, DETAILS_STR_MAX, "TCP: %s, UDP: %s, IP: %s",
                        tic->V4Transmit.TcpChecksum ? "Yes" : "No",
                        tic->V4Transmit.UdpChecksum ? "Yes" : "No",
                        tic->V4Transmit.IpChecksum ? "Yes" : "No");
                    add_string_to_table(table, row, "Calculation supported", string_buff);

                    g_snprintf(string_buff, DETAILS_STR_MAX, "TCP: %s, IP: %s",
                        tic->V4Transmit.TcpOptionsSupported ? "Yes" : "No",
                        tic->V4Transmit.IpOptionsSupported ? "Yes" : "No");
                    add_string_to_table(table, row, "Options fields supported", string_buff);

                    g_snprintf(string_buff, DETAILS_STR_MAX, "");
                    add_string_to_table(table, row, "V4 receive checksum", "");

                    g_snprintf(string_buff, DETAILS_STR_MAX, "TCP: %s, UDP: %s, IP: %s",
                        tic->V4Receive.TcpChecksum ? "Yes" : "No",
                        tic->V4Receive.UdpChecksum ? "Yes" : "No",
                        tic->V4Receive.IpChecksum ? "Yes" : "No");
                    add_string_to_table(table, row, "Validation supported", string_buff);

                    g_snprintf(string_buff, DETAILS_STR_MAX, "TCP: %s, IP: %s",
                        tic->V4Receive.TcpOptionsSupported ? "Yes" : "No",
                        tic->V4Receive.IpOptionsSupported ? "Yes" : "No");
                    add_string_to_table(table, row, "Options fields supported", string_buff);

                    g_snprintf(string_buff, DETAILS_STR_MAX, "");
                    add_string_to_table(table, row, "V6 transmit checksum", "");

                    g_snprintf(string_buff, DETAILS_STR_MAX, "TCP: %s, UDP: %s",
                        tic->V6Transmit.TcpChecksum ? "Yes" : "No",
                        tic->V6Transmit.UdpChecksum ? "Yes" : "No");
                    add_string_to_table(table, row, "Calculation supported", string_buff);

                    g_snprintf(string_buff, DETAILS_STR_MAX, "TCP: %s, IP: %s",
                        tic->V6Transmit.TcpOptionsSupported ? "Yes" : "No",
                        tic->V6Transmit.IpOptionsSupported ? "Yes" : "No");
                    add_string_to_table(table, row, "Options fields supported", string_buff);

                    g_snprintf(string_buff, DETAILS_STR_MAX, "");
                    add_string_to_table(table, row, "V6 receive checksum", "");

                    g_snprintf(string_buff, DETAILS_STR_MAX, "TCP: %s, UDP: %s",
                        tic->V6Receive.TcpChecksum ? "Yes" : "No",
                        tic->V6Receive.UdpChecksum ? "Yes" : "No");
                    add_string_to_table(table, row, "Validation supported", string_buff);

                    g_snprintf(string_buff, DETAILS_STR_MAX, "TCP: %s, IP: %s",
                        tic->V6Receive.TcpOptionsSupported ? "Yes" : "No",
                        tic->V6Receive.IpOptionsSupported ? "Yes" : "No");
                    add_string_to_table(table, row, "Options fields supported", string_buff);
                }
                break;
            case IpSecNdisTask:
                entries++;
                IpSecSupported++;

                add_string_to_table(table, row, "IPSEC", "");
                g_snprintf(string_buff, DETAILS_STR_MAX, "IPSEC (TaskID 1) not decoded yet");
                add_string_to_table(table, row, "Task", string_buff);
                break;
            case TcpLargeSendNdisTask:
                {
                    NDIS_TASK_TCP_LARGE_SEND *tls = (NDIS_TASK_TCP_LARGE_SEND *) (of->TaskBuffer);

                    entries++;
                    TcpLargeSendSupported++;

                    add_string_to_table(table, row, "TCP large send", "");
                    /* XXX - while MSDN tells about version 0, we see version 1?!? */
                    if(tls->Version == 1) {
                        g_snprintf(string_buff, DETAILS_STR_MAX, "%u", tls->MaxOffLoadSize);
                        add_string_to_table(table, row, "Max Offload Size", string_buff);
                        g_snprintf(string_buff, DETAILS_STR_MAX, "%u", tls->MinSegmentCount);
                        add_string_to_table(table, row, "Min Segment Count", string_buff);
                        g_snprintf(string_buff, DETAILS_STR_MAX, "%s", tls->TcpOptions ? "Yes" : "No");
                        add_string_to_table(table, row, "TCP option fields", string_buff);
                        g_snprintf(string_buff, DETAILS_STR_MAX, "%s", tls->IpOptions ? "Yes" : "No");
                        add_string_to_table(table, row, "IP option fields", string_buff);
                    } else {
                        g_snprintf(string_buff, DETAILS_STR_MAX, "%u (unknown)", tls->Version);
                        add_string_to_table(table, row, "Version", string_buff);
                    }
                }
                break;
            default:
                g_snprintf(string_buff, DETAILS_STR_MAX, "Unknown task %u", of->Task);
                add_string_to_table(table, row, "Task", string_buff);

            }

            add_string_to_table(table, row, "", "");

            valuep += of->OffsetNextTask;
            length -= of->OffsetNextTask;
        } while(of->OffsetNextTask != 0);
    }

    if(TcpIpChecksumSupported == 0) {
        add_string_to_table(table, row, "TCP/IP Checksum", "");
        add_string_to_table(table, row, "Offload not supported", "-");
    }

    if(IpSecSupported == 0) {
        add_string_to_table(table, row, "IpSec", "");
        add_string_to_table(table, row, "Offload not supported", "-");
    }

    if(TcpLargeSendSupported == 0) {
        add_string_to_table(table, row, "TCP Large Send", "");
        add_string_to_table(table, row, "Offload not supported", "-");
    }

    return entries;
}

static int
capture_if_details_general(GtkWidget *table, GtkWidget *main_vb, guint *row, LPADAPTER adapter, gchar *iface) {
    gchar           string_buff[DETAILS_STR_MAX];
    const gchar     *manuf_name;
    unsigned int    uint_value;
    unsigned int    uint_array[50];
    int             uint_array_size;
    unsigned int    physical_medium;
    int             i;
    unsigned char   values[100];
    int             length;
    unsigned short  ushort_value;
    int             entries = 0;


    /* general */
    add_string_to_table(table, row, "Characteristics", "");

    /* Vendor description */
    length = sizeof(values);
    if (wpcap_packet_request(adapter, OID_GEN_VENDOR_DESCRIPTION, FALSE /* !set */, values, &length)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%s", values);
        entries++;
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Vendor description", string_buff);

    /* Interface */
    add_string_to_table(table, row, "Interface", iface);

    /* link status (connected/disconnected) */
    if (wpcap_packet_request_uint(adapter, OID_GEN_MEDIA_CONNECT_STATUS, &uint_value)) {
        entries++;
        if(uint_value == 0) {
            add_string_to_table(table, row, "Link status", "Connected");
        } else {
            add_string_to_table(table, row, "Link status", "Disconnected");
        }
    } else {
        add_string_to_table(table, row, "Link status", "-");
    }

    /* link speed */
    if (wpcap_packet_request_uint(adapter, OID_GEN_LINK_SPEED, &uint_value)) {
        entries++;
        uint_value *= 100;
        if(uint_value >= 1000 * 1000) {
            g_snprintf(string_buff, DETAILS_STR_MAX, "%d MBits/s", uint_value / 1000 / 1000);
        } else {
            if(uint_value >= 1000) {
                g_snprintf(string_buff, DETAILS_STR_MAX, "%d KBits/s", uint_value / 1000);
            } else {
                g_snprintf(string_buff, DETAILS_STR_MAX, "%d Bits/s", uint_value);
            }
        }
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Link speed", string_buff);



    uint_array_size = sizeof(uint_array);
    if (wpcap_packet_request(adapter, OID_GEN_MEDIA_SUPPORTED, FALSE /* !set */, (char *) uint_array, &uint_array_size)) {
        entries++;
        uint_array_size /= sizeof(unsigned int);
        i=0;
        while(uint_array_size--) {
            add_string_to_table(table, row, "Media supported",
                val_to_str(uint_array[i], win32_802_3_medium_vals, "(0x%x)"));
            i++;
        }
    } else {
        add_string_to_table(table, row, "Media supported", "-");
    }

    uint_array_size = sizeof(uint_array);
    if (wpcap_packet_request(adapter, OID_GEN_MEDIA_IN_USE, FALSE /* !set */, (char *) uint_array, &uint_array_size)) {
        entries++;
        uint_array_size /= sizeof(unsigned int);
        i=0;
        while(uint_array_size--) {
            add_string_to_table(table, row, "Medium in use",
                  val_to_str(uint_array[i], win32_802_3_medium_vals, "(0x%x)"));
            i++;
        }
    } else {
        add_string_to_table(table, row, "Medium in use", "-");
    }

    if (wpcap_packet_request_uint(adapter, OID_GEN_PHYSICAL_MEDIUM, &physical_medium)) {
        entries++;
        add_string_to_table(table, row, "Physical medium",
            val_to_str(physical_medium, win32_802_3_physical_medium_vals, "(0x%x)"));
    } else {
        add_string_to_table(table, row, "Physical medium", "-");
    }

    length = sizeof(ushort_value);
    if (wpcap_packet_request(adapter, OID_GEN_DRIVER_VERSION, FALSE /* !set */, (char *) &ushort_value, &length)) {
        entries++;
        g_snprintf(string_buff, DETAILS_STR_MAX, "%u.%u", ushort_value / 0x100, ushort_value % 0x100);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "NDIS Driver Version", string_buff);

    length = sizeof(uint_value);
    if (wpcap_packet_request(adapter, OID_GEN_VENDOR_DRIVER_VERSION, FALSE /* !set */, (char *) &uint_value, &length)) {
        entries++;
        /* XXX - what's the correct output format? */
        g_snprintf(string_buff, DETAILS_STR_MAX, "%u.%u (Hex: %X.%X)",
            (uint_value / 0x10000  ) % 0x10000,
             uint_value              % 0x10000,
            (uint_value / 0x10000  ) % 0x10000,
             uint_value              % 0x10000);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Vendor Driver Version", string_buff);

    length = sizeof(values);
    if (wpcap_packet_request(adapter, OID_GEN_VENDOR_ID, FALSE /* !set */, values, &length)) {
        entries++;
        manuf_name = get_manuf_name_if_known(values);
        if(manuf_name != NULL) {
            g_snprintf(string_buff, DETAILS_STR_MAX, "%02X:%02X:%02X (%s) NIC: %02X",
                values[0], values[1], values[2], manuf_name, values[3]);
        } else {
            g_snprintf(string_buff, DETAILS_STR_MAX, "%02X:%02X:%02X NIC: %02X",
                values[0], values[1], values[2], values[3]);
        }
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Vendor ID", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_MAC_OPTIONS, &uint_value)) {
        entries++;
        g_snprintf(string_buff, DETAILS_STR_MAX,
            "802.1P Priority: %s, 802.1Q VLAN: %s",
            (uint_value & NDIS_MAC_OPTION_8021P_PRIORITY) ? "Supported" : "Unsupported",
            (uint_value & NDIS_MAC_OPTION_8021Q_VLAN) ? "Supported" : "Unsupported" );
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "MAC Options", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_VLAN_ID, &uint_value)) {
        entries++;
        g_snprintf(string_buff, DETAILS_STR_MAX, "%u", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "VLAN ID", string_buff);

#if 0
    /* value seems to be constant */
    if (wpcap_packet_request_uint(adapter, OID_GEN_CURRENT_PACKET_FILTER, &uint_value)) {
        entries++;
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Packet filter", string_buff);
#endif

    if (wpcap_packet_request_uint(adapter, OID_GEN_TRANSMIT_BUFFER_SPACE, &uint_value)) {
        entries++;
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Transmit Buffer Space", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_RECEIVE_BUFFER_SPACE, &uint_value)) {
        entries++;
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Receive Buffer Space", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_TRANSMIT_BLOCK_SIZE , &uint_value)) {
        entries++;
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Transmit Block Size", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_RECEIVE_BLOCK_SIZE, &uint_value)) {
        entries++;
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Receive Block Size", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_MAXIMUM_TOTAL_SIZE, &uint_value)) {
        entries++;
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Maximum Packet Size", string_buff);

    return entries;
}


static int
capture_if_details_stats(GtkWidget *table, GtkWidget *main_vb, guint *row, LPADAPTER adapter) {
    gchar           string_buff[DETAILS_STR_MAX];
    unsigned int    uint_value;
    int             entries = 0;


    add_string_to_table(table, row, "Statistics", "");

    if (wpcap_packet_request_uint(adapter, OID_GEN_XMIT_OK, &uint_value)) {
        entries++;
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Transmit OK", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_XMIT_ERROR, &uint_value)) {
        entries++;
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Transmit Error", string_buff);


    if (wpcap_packet_request_uint(adapter, OID_GEN_RCV_OK, &uint_value)) {
        entries++;
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Receive OK", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_RCV_ERROR, &uint_value)) {
        entries++;
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Receive Error", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_RCV_NO_BUFFER, &uint_value)) {
        entries++;
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Receive but no Buffer", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_DIRECTED_BYTES_XMIT, &uint_value)) {
        entries++;
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Directed bytes transmitted w/o errors", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_DIRECTED_FRAMES_XMIT, &uint_value)) {
        entries++;
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Directed packets transmitted w/o errors", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_MULTICAST_BYTES_XMIT, &uint_value)) {
        entries++;
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Multicast bytes transmitted w/o errors", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_MULTICAST_FRAMES_XMIT, &uint_value)) {
        entries++;
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Multicast packets transmitted w/o errors", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_BROADCAST_BYTES_XMIT, &uint_value)) {
        entries++;
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Broadcast bytes transmitted w/o errors", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_BROADCAST_FRAMES_XMIT, &uint_value)) {
        entries++;
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Broadcast packets transmitted w/o errors", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_DIRECTED_BYTES_RCV, &uint_value)) {
        entries++;
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Directed bytes received w/o errors", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_DIRECTED_FRAMES_RCV, &uint_value)) {
        entries++;
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Directed packets received w/o errors", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_MULTICAST_BYTES_RCV, &uint_value)) {
        entries++;
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Multicast bytes received w/o errors", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_MULTICAST_FRAMES_RCV, &uint_value)) {
        entries++;
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Multicast packets received w/o errors", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_BROADCAST_BYTES_RCV, &uint_value)) {
        entries++;
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Broadcast bytes received w/o errors", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_BROADCAST_FRAMES_RCV, &uint_value)) {
        entries++;
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Broadcast packets received w/o errors", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_RCV_CRC_ERROR, &uint_value)) {
        entries++;
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Packets received with CRC or FCS errors", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_TRANSMIT_QUEUE_LENGTH, &uint_value)) {
        entries++;
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Packets queued for transmission", string_buff);

    return entries;
}


static GtkWidget *
capture_if_details_page_new(GtkWidget **table)
{
    GtkWidget *main_vb;

    main_vb = gtk_vbox_new(FALSE, 6);
    gtk_container_set_border_width(GTK_CONTAINER(main_vb), 12);

    /* table */
    *table = gtk_table_new(1, 2, FALSE);
    gtk_table_set_col_spacings(GTK_TABLE(*table), 6);
    gtk_table_set_row_spacings(GTK_TABLE(*table), 3);
    gtk_container_add(GTK_CONTAINER(main_vb), *table);

    return main_vb;
}


static void
capture_if_details_open_win(char *iface)
{
    GtkWidget   *details_open_w,
                *main_vb, *bbox, *close_bt, *help_bt;
    GtkWidget   *page_general, *page_stats, *page_802_3, *page_802_11, *page_task_offload;
    GtkWidget   *page_lb;
    GtkWidget   *table, *notebook, *label;
    guint       row;
    LPADAPTER   adapter;
    int         entries;


    /* open the network adapter */
    adapter = wpcap_packet_open(iface);
    if(adapter == NULL) {
        /*
         * We have an adapter that is not exposed through normal APIs (e.g. TurboCap)
         * or an adapter that isn't plugged in.
         *
         * XXX - We should use the TurboCap API to get info about TurboCap adapters.
         */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "%sCould not open adapter %s!%s"
            "\n\nHas it been unplugged?",
            simple_dialog_primary_start(), iface, simple_dialog_primary_end());
        return;
    }

    /* open a new window */
	details_open_w = dlg_window_new("Wireshark: Interface Details");  /* transient_for top_level */
	gtk_window_set_destroy_with_parent (GTK_WINDOW(details_open_w), TRUE);

    /* Container for the window contents */
    main_vb = gtk_vbox_new(FALSE, 12);
    gtk_container_set_border_width(GTK_CONTAINER(main_vb), 12);
    gtk_container_add(GTK_CONTAINER(details_open_w), main_vb);

    /* notebook */
    notebook = gtk_notebook_new();
    gtk_box_pack_start(GTK_BOX(main_vb), notebook, TRUE /*expand*/, TRUE /*fill*/, 0 /*padding*/);

    /* General page */
    page_general = capture_if_details_page_new(&table);
    page_lb = gtk_label_new("Characteristics");
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), page_general, page_lb);
    row = 0;
    entries = capture_if_details_general(table, page_general, &row, adapter, iface);
    if(entries == 0) {
        gtk_widget_set_sensitive(page_lb, FALSE);
    }

    /* Statistics page */
    page_stats = capture_if_details_page_new(&table);
    page_lb = gtk_label_new("Statistics");
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), page_stats, page_lb);
    row = 0;
    entries = capture_if_details_stats(table, page_stats, &row, adapter);
    if(entries == 0) {
        gtk_widget_set_sensitive(page_lb, FALSE);
    }

    /* 802.3 (Ethernet) page */
    page_802_3 = capture_if_details_page_new(&table);
    page_lb = gtk_label_new("802.3 (Ethernet)");
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), page_802_3, page_lb);
    row = 0;
    entries = capture_if_details_802_3(table, page_802_3, &row, adapter);
    if(entries == 0) {
        gtk_widget_set_sensitive(page_lb, FALSE);
    }

    /* 802_11 (WI-FI) page */
    page_802_11 = capture_if_details_page_new(&table);
    page_lb = gtk_label_new("802.11 (WLAN)");
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), page_802_11, page_lb);
    row = 0;
    entries = capture_if_details_802_11(table, page_802_11, &row, adapter);
    if(entries == 0) {
        gtk_widget_set_sensitive(page_lb, FALSE);
    }

    /* Task offload page */
    page_task_offload = capture_if_details_page_new(&table);
    page_lb = gtk_label_new("Task Offload");
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), page_task_offload, page_lb);
    row = 0;
    entries = capture_if_details_task_offload(table, page_task_offload, &row, adapter);
    if(entries == 0) {
        gtk_widget_set_sensitive(page_lb, FALSE);
    }

    wpcap_packet_close(adapter);

    label = gtk_label_new("Note: the accuracy of all of these values relies only on the network card driver!");
    gtk_box_pack_start(GTK_BOX(main_vb), label, FALSE /*expand*/, FALSE /*fill*/, 0 /*padding*/);

    /* Button row. */
    bbox = dlg_button_row_new(GTK_STOCK_CLOSE, GTK_STOCK_HELP, NULL);
    gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE /*expand*/, FALSE /*fill*/, 0 /*padding*/);

    close_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
    window_set_cancel_button(details_open_w, close_bt, window_cancel_button_cb);

    help_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
    g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer) (HELP_CAPTURE_INTERFACES_DETAILS_DIALOG));

    gtk_widget_grab_focus(close_bt);

    g_signal_connect(details_open_w, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);

    gtk_widget_show_all(details_open_w);
    window_present(details_open_w);
}


static void capture_if_details_open_answered_cb(gpointer dialog _U_, gint btn, gpointer data)
{
    switch(btn) {
    case(ESD_BTN_OK):
        capture_if_details_open_win(data);
        break;
    case(ESD_BTN_CANCEL):
        break;
    default:
        g_assert_not_reached();
    }
}


void
capture_if_details_open(char *iface)
{
    char        *version;
    gboolean    version_ok = FALSE;
    gpointer    dialog;


    /* check packet.dll version */
    version = wpcap_packet_get_version();

    if(version == NULL) {
        /* couldn't even get the packet.dll version, must be a very old one or just not existing -> give up */
        /* (this seems to be the case for 2.3 beta and all previous releases) */
        simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
            "%sCouldn't obtain WinPcap packet.dll version!%s"
            "\n\nThe WinPcap packet.dll is not installed or the version you use seems to be very old!"
            "\n\nPlease update/install WinPcap.",
            simple_dialog_primary_start(), simple_dialog_primary_end());
        return;
    }

    /* XXX - add more known DLL versions here */
    /* (all versions since the 2.3 release seems to be working (although the 2.3 beta did not) */
    if(
        /*
         * 4.0 version strings:
         * 4.0.0.703:  4.0 beta 3
         * 4.0.0.655:  4.0 beta 2
         * 4.0.0.592:  4.0 beta 1
         */
        strcmp(version, "3"          ) >  0 ||       /* 4.0 and above (including betas) */
        strcmp(version, "3, 2, 0, 29") == 0 ||       /* 3.2 beta 1 */
        strcmp(version, "3, 1, 0, 27") == 0 ||       /* 3.1 release */
        strcmp(version, "3, 1, 0, 24") == 0 ||       /* 3.1 beta 4 */
        strcmp(version, "3, 1, 0, 23") == 0 ||       /* 3.1 beta 3 */
        strcmp(version, "3, 1, 0, 22") == 0 ||       /* 3.1 beta 2 */
        strcmp(version, "3, 1, 0, 20") == 0 ||       /* 3.1 beta */
        strcmp(version, "3.0 alpha3" ) == 0 ||       /* 3.0 release or 3.0 beta (yes, both versions report alpha3!) */
        strcmp(version, "2.3"        ) == 0          /* 2.3 release */
        ) {
	    version_ok = TRUE;
    }

    if(!version_ok) {
        /* packet.dll version not known to us, warn user but try to continue */
        dialog = simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK | ESD_BTN_CANCEL,
            "%sUnknown WinPcap version might crash or fail!%s"
            "\n\nThe WinPcap packet.dll version \"%s\" is unknown if it supports required functions!"
            "\n\nOnly WinPcap versions 3.0 and 3.1 are known to work with this feature."
            "\n\nCrashes or unexpected behaviour might occur, you have been warned!"
            "\n\nContinue anyway?",
            simple_dialog_primary_start(), simple_dialog_primary_end(), version);
        simple_dialog_set_cb(dialog, capture_if_details_open_answered_cb, iface);
    } else {
        capture_if_details_open_win(iface);
    }
}

gboolean
capture_if_has_details(char *iface) {
    LPADAPTER   adapter;

    if (!iface) {
	return FALSE;
    }

    adapter = wpcap_packet_open(iface);
    if (adapter) {
	wpcap_packet_close(adapter);
	return TRUE;
    }

    return FALSE;
}

#endif /* HAVE_LIBPCAP && _WIN32 */
