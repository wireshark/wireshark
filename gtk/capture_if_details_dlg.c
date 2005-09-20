/* capture_if_details_dlg.c
 * Routines for capture interface details window (only Win32!)
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include <string.h>

#include <gtk/gtk.h>

#include <wtap.h>
#include <time.h>

#include "globals.h"
#include "file.h"
#include <pcap.h>
#include "capture.h"
#include "main.h"
#include "dlg_utils.h"
#include "gui_utils.h"
#include "compat_macros.h"
#include "help_dlg.h"

#include <epan/value_string.h>
#include <epan/addr_resolv.h>

#ifndef HAVE_SOCKADDR_STORAGE
/* packet32.h requires sockaddr_storage (usually defined in Platform SDK)
 * copied from RFC2553 (and slightly modified because of datatypes) ...
 * XXX - defined more than once, move this to a header file */
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
              /* 6 byte pad, this is to make implementation
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
#endif


#include <Packet32.h>
#include <windows.h>
#include <windowsx.h>
#include <Ntddndis.h>

#include "capture_wpcap_packet.h"
#include "capture_if_details_dlg.h"

#include "simple_dialog.h"

#define DETAILS_STR_MAX     1024



/******************************************************************************************************************************/
/* definitions that would usually come from the windows DDK (device driver kit) */
/* and are not part of the ntddndis.h file delivered with WinPcap */

/* Required OIDs (from ndiswrapper) */
#define OID_GEN_VLAN_ID				0x0001021C

/* Optional OIDs (from ndiswrapper) */
#define OID_GEN_MEDIA_CAPABILITIES		0x00010201
#define OID_GEN_PHYSICAL_MEDIUM			0x00010202


/* Physical medium (OID_GEN_PHYSICAL_MEDIUM) (from ndiswrapper) */
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


/* 802.11 OIDs (from ndiswrapper), see also: */
/* http://www.ndis.com/papers/ieee802_11_log.htm */
/* http://lists.freebsd.org/pipermail/p4-projects/2004-January/003433.html */
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
#define OID_802_11_ENCRYPTION_STATUS		OID_802_11_WEP_STATUS
#define OID_802_11_RELOAD_DEFAULTS		0x0D01011C
#define OID_802_11_ADD_KEY			0x0D01011D
#define OID_802_11_REMOVE_KEY			0x0D01011E
#define OID_802_11_ASSOCIATION_INFORMATION	0x0D01011F
#define OID_802_11_TEST				0x0D010120
#define OID_802_11_CAPABILITY			0x0D010122
#define OID_802_11_PMKID			0x0D010123

/* Currently associated SSID (OID_802_11_SSID) (from ndiswrapper) */
#define NDIS_ESSID_MAX_SIZE 32
struct ndis_essid {
	ULONG length;
	UCHAR essid[NDIS_ESSID_MAX_SIZE];
};

/* Current infrastructure mode (OID_802_11_INFRASTRUCTURE_MODE) (from ndiswrapper) */
enum network_infrastructure {
	Ndis802_11IBSS,
	Ndis802_11Infrastructure,
	Ndis802_11AutoUnknown,
	Ndis802_11InfrastructureMax
};

/* Current authentication mode (OID_802_11_AUTHENTICATION_MODE) (from ndiswrapper) */
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

/* Current network type (OID_802_11_NETWORK_TYPES_SUPPORTED / OID_802_11_NETWORK_TYPE_IN_USE) (from ndiswrapper) */
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

/* Current encryption status (OID_802_11_ENCRYPTION_STATUS) (from ndiswrapper) */
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


/* some definitions needed for the following structs (from ndiswrapper) */
#define NDIS_MAX_RATES_EX 16
typedef UCHAR mac_address[/* ETH_ALEN */ 6];
typedef UCHAR ndis_rates[NDIS_MAX_RATES_EX];

/* configuration, e.g. frequency (OID_802_11_CONFIGURATION / OID_802_11_BSSID_LIST) (from ndiswrapper) */
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

/* bssid list item (OID_802_11_BSSID_LIST) (from ndiswrapper) */
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


/* bssid list (OID_802_11_BSSID_LIST) (from ndiswrapper) */
struct ndis_bssid_list {
	ULONG num_items;
	struct ndis_ssid_item items[1];
};


/******************************************************************************************************************************/
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
	{ NdisPhysicalMediumCableModem,     "Cable Modem" },
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
	{ Ndis802_11AuthModeWPA,        "WPA" },
	{ Ndis802_11AuthModeWPAPSK,     "WPA (pre shared key)" },
	{ Ndis802_11AuthModeWPANone,    "WPA (ad hoc)" },
	{ Ndis802_11AuthModeWPA2,       "WPA2" },
	{ Ndis802_11AuthModeWPA2PSK,    "WPA2 (pre shared key)" },
    { 0, NULL }
};

static const value_string win32_802_11_network_type_vals[] = {
	{ Ndis802_11FH,         "FH (frequency-hopping spread-spectrum)" },
	{ Ndis802_11DS,         "DS (direct-sequence spread-spectrum)" },
	{ Ndis802_11OFDM5,      "5-GHz OFDM" },
	{ Ndis802_11OFDM24,     "2.4-GHz OFDM" },
	{ Ndis802_11Automode,   "Auto" },
    { 0, NULL }
};

/* XXX - add some explanations */
static const value_string win32_802_11_encryption_status_vals[] = {
	{ Ndis802_11Encryption1Enabled,     "Encryption 1 Enabled" },
	{ Ndis802_11EncryptionDisabled,     "Encryption Disabled" },
	{ Ndis802_11Encryption1KeyAbsent,   "Encryption 1 Key Absent" },
	{ Ndis802_11EncryptionNotSupported, "Encryption Not Supported" },
	{ Ndis802_11Encryption2Enabled,     "Encryption 2 Enabled" },
	{ Ndis802_11Encryption2KeyAbsent,   "Encryption 2 Key Absent" },
	{ Ndis802_11Encryption3Enabled,     "Encryption 3 Enabled" },
	{ Ndis802_11Encryption3KeyAbsent,   "Encryption 3 Key Absent" },
    { 0, NULL }
};

/* frequency to channel mapping (OID_802_11_CONFIGURATION) */
static const value_string win32_802_11_channel_vals[] = {
	{ 2412000, "1 (2412000 kHz)" },
	{ 2417000, "2 (2417000 kHz)" },
	{ 2422000, "3 (2422000 kHz)" },
	{ 2427000, "4 (2427000 kHz)" },
	{ 2432000, "5 (2432000 kHz)" },
	{ 2437000, "6 (2437000 kHz)" },
	{ 2442000, "7 (2442000 kHz)" },
	{ 2447000, "8 (2447000 kHz)" },
	{ 2452000, "9 (2452000 kHz)" },
	{ 2457000, "10 (2457000 kHz)" },
	{ 2462000, "11 (2462000 kHz)" },
	{ 2467000, "12 (2467000 kHz)" },
	{ 2472000, "13 (2472000 kHz)" },
	{ 2484000, "14 (2484000 kHz)" },
    { 0, NULL }
};


/******************************************************************************************************************************/
/* info functions, get and display various NDIS driver values */


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
    gtk_table_attach_defaults(GTK_TABLE(list), label, 0, 1, *row, *row+1);

    label = gtk_label_new(value);
    gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.5);
    gtk_widget_set_sensitive(label, sensitive);
    gtk_table_attach_defaults(GTK_TABLE(list), label, 1, 2, *row, *row+1);

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
        add_string_to_table(table, row, "SSID", ssid->essid);
    } else {
        add_string_to_table(table, row, "SSID", "(currently not associated with an SSID)");
    }
}


static GString *
rates_details(unsigned char *values, int length) {
    int                 i;
    GString             *Rates;
    float               float_value;


    Rates = g_string_new("");

    if(length != 0) {
        i = 0;
        while(length--) {
            if(values[i]) {
                float_value = (float) ((values[i] & 0x7F) / 2);
                if(i == 0) {
                    g_string_sprintfa(Rates, "%.1f", float_value);
                } else {
                    g_string_sprintfa(Rates, " / %.1f", float_value);
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


static void
capture_if_details_802_11_bssid_list(GtkWidget *main_vb, struct ndis_bssid_list *bssid_list)
{
    struct ndis_ssid_item   *bssid_item;
    unsigned char           mac[6];
    const gchar             *manuf_name;
    GString                 *Rates;


    if(bssid_list->num_items != 0) {
        char *titles[] = { "SSID", "MAC", "Vendor", "RSSI" , "Network Type" , "Infra. Mode" , "Channel" , "Rates" };
        GtkWidget     *list;

        gchar ssid_buff[DETAILS_STR_MAX];
        gchar mac_buff[DETAILS_STR_MAX];
        gchar vendor_buff[DETAILS_STR_MAX];
        gchar rssi_buff[DETAILS_STR_MAX];
        gchar nettype_buff[DETAILS_STR_MAX];
        gchar infra_buff[DETAILS_STR_MAX];
        gchar freq_buff[DETAILS_STR_MAX];

        list = simple_list_new(8, titles);
        gtk_container_add(GTK_CONTAINER(main_vb), list);

        bssid_item = &bssid_list->items[0];

        while(bssid_list->num_items--) {

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
                strcpy(vendor_buff, manuf_name);
            } else {
                strcpy(vendor_buff, "");
            }

            /* Supported Rates */
            Rates = rates_details(bssid_item->rates, NDIS_MAX_RATES_EX);

            /* RSSI */
            g_snprintf(rssi_buff, DETAILS_STR_MAX, "%d dBm", bssid_item->rssi);

            /* Network Type */
            g_snprintf(nettype_buff, sizeof(nettype_buff), "%s",
                val_to_str(bssid_item->net_type, win32_802_11_network_type_vals, "(0x%x)"));

            /* Infrastructure Mode */
            g_snprintf(infra_buff, sizeof(infra_buff), "%s",
                val_to_str(bssid_item->mode, win32_802_11_infra_mode_vals, "(0x%x)"));

            /* Channel */
            g_snprintf(freq_buff, sizeof(freq_buff), "%s",
                val_to_str(bssid_item->config.ds_config, win32_802_11_channel_vals, "(%u kHz)"));

            /* IE Length  (XXX - add decoding) */
            /* g_warning ("802.11 IE Length          : %u", bssid_item->ie_length); */

            simple_list_append(list, 
                0, ssid_buff,
                1, mac_buff,
                2, vendor_buff,
                3, rssi_buff,
                4, nettype_buff,
                5, infra_buff, 
                6, freq_buff, 
                7, Rates->str,
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
    LONG                long_value;
    unsigned int        uint_value;
    unsigned char       values[100];
    struct ndis_essid   ssid;
    int                 length;
    struct ndis_bssid_list      *bssid_list;
    struct ndis_configuration   *configuration;
    gchar               string_buff[DETAILS_STR_MAX];
    GString             *Rates;
    int                 entries = 0;


    add_string_to_table(table, row, "Characteristics", "");

    /* BSSID */
    length = sizeof(values);
    memset(values, 0, 6);
    if (wpcap_packet_request(adapter, OID_802_11_BSSID, FALSE /* !set */, values, &length)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%02X:%02X:%02X:%02X:%02X:%02X",
            values[0], values[1], values[2], 
            values[3], values[4], values[5]);
        entries++;
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "BSSID", string_buff);

    /* SSID */
    length = sizeof(struct ndis_essid);
    memset(&ssid, 0, length);
    if (wpcap_packet_request(adapter, OID_802_11_SSID, FALSE /* !set */, (char *) &ssid, &length)) {
        ssid_details(table, row, &ssid);
        entries++;
    } else {
        add_string_to_table(table, row, "SSID", "-");
    }

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
    if (wpcap_packet_request_ulong(adapter, OID_802_11_RSSI, &long_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%ld dBm", long_value);
        add_string_to_table(table, row, "RSSI", string_buff);
        entries++;
    } else {
        add_string_to_table(table, row, "RSSI", "-");
    }

    /* Supported Rates */
    length = sizeof(values);
    if (!wpcap_packet_request(adapter, OID_802_11_SUPPORTED_RATES, FALSE /* !set */, values, &length)) {
        length = 0;
    } else {
        entries++;
    }

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
            val_to_str(configuration->ds_config, win32_802_11_channel_vals, "(%u kHz)"));
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
        add_string_to_table(table, row, "BSSID list", "");

        capture_if_details_802_11_bssid_list(main_vb, bssid_list);
        entries += bssid_list->num_items;
    } else {
        add_string_to_table(table, row, "802.11 BSSID list", "-");
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


static void
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


    /* general */
    add_string_to_table(table, row, "Characteristics", "");

    /* Vendor description */
    length = sizeof(values);
    if (wpcap_packet_request(adapter, OID_GEN_VENDOR_DESCRIPTION, FALSE /* !set */, values, &length)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%s", values);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Vendor description", string_buff);

    /* Interface */
    add_string_to_table(table, row, "Interface", iface);

    /* link status (connected/disconnected) */
    if (wpcap_packet_request_uint(adapter, OID_GEN_MEDIA_CONNECT_STATUS, &uint_value)) {
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
        add_string_to_table(table, row, "Physical medium", 
            val_to_str(physical_medium, win32_802_3_physical_medium_vals, "(0x%x)"));
    } else {
        add_string_to_table(table, row, "Physical medium", "-");
    }

    length = sizeof(ushort_value);
    if (wpcap_packet_request(adapter, OID_GEN_DRIVER_VERSION, FALSE /* !set */, (char *) &ushort_value, &length)) {
        g_assert(length == 2);
        g_snprintf(string_buff, DETAILS_STR_MAX, "%u.%u", ushort_value / 0x100, ushort_value % 0x100);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "NDIS Driver Version", string_buff);

    length = sizeof(uint_value);
    if (wpcap_packet_request(adapter, OID_GEN_VENDOR_DRIVER_VERSION, FALSE /* !set */, (char *) &uint_value, &length)) {
        g_assert(length == 4);
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

    if (wpcap_packet_request_uint(adapter, OID_GEN_VLAN_ID, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%u", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "VLAN ID", string_buff);


    /* XXX - OID_GEN_MAC_OPTIONS (bitfield, VLAN, ...) */
    
    if (wpcap_packet_request_uint(adapter, OID_GEN_TRANSMIT_BUFFER_SPACE, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Transmit Buffer Space", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_RECEIVE_BUFFER_SPACE, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Receive Buffer Space", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_TRANSMIT_BLOCK_SIZE , &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Transmit Block Size", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_RECEIVE_BLOCK_SIZE, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Receive Block Size", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_MAXIMUM_TOTAL_SIZE, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Maximum Packet Size", string_buff);


    /* Statistics */
    add_string_to_table(table, row, "", "");
    add_string_to_table(table, row, "Statistics", "");

    if (wpcap_packet_request_uint(adapter, OID_GEN_XMIT_OK, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Transmit OK", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_XMIT_ERROR, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Transmit Error", string_buff);


    if (wpcap_packet_request_uint(adapter, OID_GEN_RCV_OK, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Receive OK", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_RCV_ERROR, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Receive Error", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_RCV_NO_BUFFER, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Receive but no Buffer", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_DIRECTED_BYTES_XMIT, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Directed bytes transmitted w/o errors", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_DIRECTED_FRAMES_XMIT, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Directed packets transmitted w/o errors", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_MULTICAST_BYTES_XMIT, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Multicast bytes transmitted w/o errors", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_MULTICAST_FRAMES_XMIT, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Multicast packets transmitted w/o errors", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_BROADCAST_BYTES_XMIT, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Broadcast bytes transmitted w/o errors", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_BROADCAST_FRAMES_XMIT, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Broadcast packets transmitted w/o errors", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_DIRECTED_BYTES_RCV, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Directed bytes received w/o errors", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_DIRECTED_FRAMES_RCV, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Directed packets received w/o errors", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_MULTICAST_BYTES_RCV, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Multicast bytes received w/o errors", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_MULTICAST_FRAMES_RCV, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Multicast packets received w/o errors", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_BROADCAST_BYTES_RCV, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Broadcast bytes received w/o errors", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_BROADCAST_FRAMES_RCV, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Broadcast packets received w/o errors", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_RCV_CRC_ERROR, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Packets received with CRC or FCS errors", string_buff);

    if (wpcap_packet_request_uint(adapter, OID_GEN_TRANSMIT_QUEUE_LENGTH, &uint_value)) {
        g_snprintf(string_buff, DETAILS_STR_MAX, "%d", uint_value);
    } else {
        g_snprintf(string_buff, DETAILS_STR_MAX, "-");
    }
    add_string_to_table(table, row, "Packets queued for transmission", string_buff);

}


static GtkWidget *
capture_if_details_page_new(GtkWidget **table)
{
    GtkWidget *main_vb;

    main_vb = gtk_vbox_new(FALSE, 6);
    gtk_container_border_width(GTK_CONTAINER(main_vb), 12);

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
    GtkWidget   *page_general, *page_802_3, *page_802_11;
    GtkWidget   *page_lb;
    GtkWidget   *table, *notebook, *label;
    guint       row;
    LPADAPTER   adapter;
    int         entries;


    /* open the network adapter */
    adapter = wpcap_packet_open(iface);

    /* open a new window */
    details_open_w = window_new(GTK_WINDOW_TOPLEVEL, "Ethereal: Interface Details");

    /* Container for the window contents */
    main_vb = gtk_vbox_new(FALSE, 12);
    gtk_container_border_width(GTK_CONTAINER(main_vb), 12);
    gtk_container_add(GTK_CONTAINER(details_open_w), main_vb);

    /* notebook */
    notebook = gtk_notebook_new();
    gtk_container_add(GTK_CONTAINER(main_vb), notebook);

    /* General page */
    page_general = capture_if_details_page_new(&table);
    page_lb = gtk_label_new("General");
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), page_general, page_lb);
    row = 0;
    capture_if_details_general(table, page_general, &row, adapter, iface);

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

    wpcap_packet_close(adapter);

    label = gtk_label_new("Note: accuracy of all of these values are only relying on the network card driver!");
    gtk_container_add(GTK_CONTAINER(main_vb), label);

    /* Button row. */
    if(topic_available(HELP_STATS_SUMMARY_DIALOG)) {
        bbox = dlg_button_row_new(GTK_STOCK_CLOSE, GTK_STOCK_HELP, NULL);
    } else {
        bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
    }
    gtk_container_add(GTK_CONTAINER(main_vb), bbox);

    close_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_CLOSE);
    window_set_cancel_button(details_open_w, close_bt, window_cancel_button_cb);

    if(topic_available(HELP_STATS_SUMMARY_DIALOG)) {
        help_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_HELP);
        SIGNAL_CONNECT(help_bt, "clicked", topic_cb, HELP_STATS_SUMMARY_DIALOG);
    }

    gtk_widget_grab_focus(close_bt);

    SIGNAL_CONNECT(details_open_w, "delete_event", window_delete_event_cb, NULL);

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
            PRIMARY_TEXT_START "Couldn't optain WinPcap packet.dll version!" PRIMARY_TEXT_END
            "\n\nThe WinPcap packet.dll is not installed or the version you use seems to be very old!"
            "\n\nPlease update/install WinPcap.");
        return;
    }

    /* XXX - add more known DLL versions here */
    /* (all versions since the 2.3 release seems to be working (although the 2.3 beta did not) */
    if( strcmp(version, "3, 1, 0, 27") == 0 ||       /* 3.1 release */
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
            PRIMARY_TEXT_START "Unknown WinPcap version might crash or fail!" PRIMARY_TEXT_END
            "\n\nThe WinPcap packet.dll version \"%s\" is unknown if it supports required functions!"
            "\n\nOnly WinPcap versions 3.0 and 3.1 are known to work with this feature."
            "\n\nCrashes or unexpected behaviour might occur, you have been warned!"
            "\n\nContinue anyway?",
            version);
        simple_dialog_set_cb(dialog, capture_if_details_open_answered_cb, iface);
    } else {
        capture_if_details_open_win(iface);
    }
}


#endif /* HAVE_LIBPCAP && _WIN32 */
