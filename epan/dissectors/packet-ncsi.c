/* packet-ncsi.c
 *
 * Extends NCSI dissection based on DMTF Document Identifier: DSP0222 Version: 1.2.0_2b
 * Copyright 2019-2021, Caleb Chiu <caleb.chiu@macnica.com>
 *
 * Routines for NCSI dissection
 * Copyright 2017-2019, Jeremy Kerr <jk@ozlabs.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Network Controller Sideband Interface (NCSI) protocol support.
 * Specs at http://www.dmtf.org/sites/default/files/standards/documents/DSP0222_1.0.1.pdf
 */


#include <config.h>

#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/expert.h>
#include <epan/addr_resolv.h>
#include <epan/pci-ids.h>

void proto_reg_handoff_ncsi(void);
void proto_register_ncsi(void);

static int proto_ncsi = -1;
static dissector_handle_t ncsi_handle;

/* Common header fields */
static int hf_ncsi_mc_id = -1;
static int hf_ncsi_revision = -1;
static int hf_ncsi_iid = -1;
static int hf_ncsi_type = -1;
static int hf_ncsi_type_code = -1;
static int hf_ncsi_type_code_masked = -1;
static int hf_ncsi_type_resp = -1;
static int hf_ncsi_chan = -1;
static int hf_ncsi_plen = -1;

/* Decode the Package# and internal channel# */
static int hf_ncsi_pkg = -1;
static int hf_ncsi_ichan = -1;

/* Response generics */
static int hf_ncsi_resp = -1;
static int hf_ncsi_reason = -1;

/* Select package */
static int hf_ncsi_sp_hwarb = -1;

/* Disable channel */
static int hf_ncsi_dc_ald = -1;

/* AEN enable */
static int hf_ncsi_aene_mc = -1;

/* Set MAC Address */
static int hf_ncsi_sm_mac = -1;
static int hf_ncsi_sm_macno = -1;
static int hf_ncsi_sm_at = -1;
static int hf_ncsi_sm_e = -1;

/* Broadcast filter */
static int hf_ncsi_bf = -1;
static int hf_ncsi_bf_arp = -1;
static int hf_ncsi_bf_dhcpc = -1;
static int hf_ncsi_bf_dhcps = -1;
static int hf_ncsi_bf_netbios = -1;

/* AEN payload fields */
static int hf_ncsi_aen_type = -1;
static int hf_ncsi_aen_lsc_oemstat = -1;
static int hf_ncsi_aen_hcds = -1;
static int hf_ncsi_aen_drr_orig_type = -1;
static int hf_ncsi_aen_drr_orig_iid = -1;

/* generic link status */
static int hf_ncsi_lstat = -1;
static int hf_ncsi_lstat_flag = -1;
static int hf_ncsi_lstat_speed_duplex = -1;
static int hf_ncsi_lstat_autoneg = -1;
static int hf_ncsi_lstat_autoneg_complete = -1;
static int hf_ncsi_lstat_parallel_detection = -1;
static int hf_ncsi_lstat_1000TFD = -1;
static int hf_ncsi_lstat_1000THD = -1;
static int hf_ncsi_lstat_100T4 = -1;
static int hf_ncsi_lstat_100TXFD = -1;
static int hf_ncsi_lstat_100TXHD = -1;
static int hf_ncsi_lstat_10TFD = -1;
static int hf_ncsi_lstat_10THD = -1;
static int hf_ncsi_lstat_tx_flow = -1;
static int hf_ncsi_lstat_rx_flow = -1;
static int hf_ncsi_lstat_partner_flow = -1;
static int hf_ncsi_lstat_serdes = -1;
static int hf_ncsi_lstat_oem_speed_valid = -1;

/* Set Link command (0x09) */
static int hf_ncsi_ls = -1;
static int hf_ncsi_ls_an = -1;
static int hf_ncsi_ls_10m = -1;
static int hf_ncsi_ls_100m = -1;
static int hf_ncsi_ls_1g = -1;
static int hf_ncsi_ls_10g = -1;
static int hf_ncsi_ls_20g = -1;
static int hf_ncsi_ls_25g = -1;
static int hf_ncsi_ls_40g = -1;
static int hf_ncsi_ls_hd = -1;
static int hf_ncsi_ls_fd = -1;
static int hf_ncsi_ls_pc = -1;
static int hf_ncsi_ls_apc = -1;
static int hf_ncsi_ls_50g = -1;
static int hf_ncsi_ls_100g = -1;
static int hf_ncsi_ls_2_5g = -1;
static int hf_ncsi_ls_5g = -1;
static int hf_ncsi_ls_rsv = -1;
static int hf_ncsi_ls_oemls = -1;

/*Get Capabilities*/
static int hf_ncsi_cap_flag = -1;        /* Offset 20..23 Capabilities Flags */
static int hf_ncsi_cap_flag_ha = -1;     /* bit 0 Hardware Arbitration  */
static int hf_ncsi_cap_flag_op = -1;     /* bit 1 OS Presence  */
static int hf_ncsi_cap_flag_n2mfc = -1;  /* bit 2 Network Controller to Management Controller Flow Control Support */
static int hf_ncsi_cap_flag_m2nfc = -1;  /* bit 3 Management Controller to Network Controller Flow Control Support */
static int hf_ncsi_cap_flag_ama = -1;    /* bit 4 All multicast addresses support */

static int hf_ncsi_cap_bf = -1;          /* Offset 24..27 Broadcast Packet Filter Capabilities, the variable names are align with Broadcast filter above */
static int hf_ncsi_cap_bf_arp = -1;
static int hf_ncsi_cap_bf_dhcpc = -1;
static int hf_ncsi_cap_bf_dhcps = -1;
static int hf_ncsi_cap_bf_netbios = -1;

static int hf_ncsi_cap_mf = -1;          /* Offset 28..31 Multicast Packet Filter Capabilities */
static int hf_ncsi_cap_mf_v6na = -1;
static int hf_ncsi_cap_mf_v6ra = -1;
static int hf_ncsi_cap_mf_dhcpv6 = -1;

static int hf_ncsi_cap_buf = -1;         /* Offset 32..35 Buffering Capability */

static int hf_ncsi_cap_aen = -1;         /* Offset 36..39 AEN Control Support  */
static int hf_ncsi_cap_aen_lstat = -1;   /* bit 0 Link Status Change AEN control */
static int hf_ncsi_cap_aen_cfg = -1;     /* bit 1 Configuration Required AEN control */
static int hf_ncsi_cap_aen_drv = -1;     /* bit 2 Host NC Driver Status Change AEN control */
static int hf_ncsi_cap_aen_resv = -1;    /* bit 3..15 Reserved Reserved */
static int hf_ncsi_cap_aen_oem = -1;     /* bit 16..31 OEM-specific AEN control OEM */

static int hf_ncsi_cap_vcnt = -1;        /* VLAN Filter Count */
static int hf_ncsi_cap_mixcnt = -1;      /* Mixed Filter Count */
static int hf_ncsi_cap_mccnt = -1;       /* Multicast Filter Count */
static int hf_ncsi_cap_uccnt = -1;       /* Unicast Filter Count */

static int hf_ncsi_cap_vmode = -1;       /* VLAN Mode Support */
static int hf_ncsi_cap_vmode_vo = -1;    /* bit 0 VLAN only  */
static int hf_ncsi_cap_vmode_both = -1;  /* bit 1 VLAN + non-VLAN  */
static int hf_ncsi_cap_vmode_any = -1;  /* bit 2 Any VLAN + non-VLAN  */
static int hf_ncsi_cap_chcnt = -1;    /* Channel Count */

/*Get Version ID*/
static int hf_ncsi_ver = -1;
static int hf_ncsi_fw_name = -1;
static int hf_ncsi_fw_ver = -1;
static int hf_ncsi_pci_did = -1;
static int hf_ncsi_pci_vid = -1;
static int hf_ncsi_pci_ssid = -1;
static int hf_ncsi_iana = -1;

/* OEM ID */
static int hf_ncsi_oem_id = -1;
/* OEM Mellanox Command, Parameter, Host number */
static int hf_ncsi_mlnx_cmd = -1;
static int hf_ncsi_mlnx_parm = -1;
static int hf_ncsi_mlnx_host = -1;
/* OEM Mellanox Set MC Affinity (Command = 0x1, parameter 0x7) */
static int hf_ncsi_mlnx_rbt = -1; /* MC RBT address */
static int hf_ncsi_mlnx_sms = -1;  /* Supported Medias Status */
static int hf_ncsi_mlnx_sms_rbt = -1;
static int hf_ncsi_mlnx_sms_smbus = -1;
static int hf_ncsi_mlnx_sms_pcie = -1;
static int hf_ncsi_mlnx_sms_rbts = -1;
static int hf_ncsi_mlnx_sms_smbuss = -1;
static int hf_ncsi_mlnx_sms_pcies = -1;

static int hf_ncsi_mlnx_beid = -1; /* MC SMBus EID */
static int hf_ncsi_mlnx_bidx = -1; /* SMBus INDX */
static int hf_ncsi_mlnx_baddr = -1; /* MC SMBus Address */
static int hf_ncsi_mlnx_peid = -1; /* MC PCIe EID */
static int hf_ncsi_mlnx_pidx = -1; /* PCIe INDX */
static int hf_ncsi_mlnx_paddr = -1; /* MC PCIe Address */
static int hf_ncsi_mlnx_ifm = -1; /* IP Filter Mode */
static int hf_ncsi_mlnx_ifm_byip = -1; /* Bits 1-0 - Filter by IP Address */
static int hf_ncsi_mlnx_ifm_v4en = -1; /* Bit 2 - IPv4 Enable */
static int hf_ncsi_mlnx_ifm_v6len = -1; /* Bit 3 - IPv6 Link Local Address Enable */
static int hf_ncsi_mlnx_ifm_v6gen = -1; /* Bit 4 - IPv6 Global Address Enable */
static int hf_ncsi_mlnx_v4addr = -1; /* MC IPv4 Address */
static int hf_ncsi_mlnx_v6local = -1; /* MC IPv6 Link Local Address */
static int hf_ncsi_mlnx_v6gbl = -1; /* MC IPv6 Global Address */

/* Get Allocated Management Address (Command = 0x0, Parameter 0x1B) */
static int hf_ncsi_mlnx_gama_st = -1;  /*Get Allocated Management Address Status */
static int hf_ncsi_mlnx_gama_mac = -1; /*Allocated MC MAC address */



static gint ett_ncsi = -1;
static gint ett_ncsi_type = -1;
static gint ett_ncsi_chan = -1;
static gint ett_ncsi_payload = -1;
static gint ett_ncsi_lstat = -1;
static gint ett_ncsi_cap_flag = -1;
static gint ett_ncsi_cap_bf = -1;
static gint ett_ncsi_cap_mf = -1;
static gint ett_ncsi_cap_aen = -1;
static gint ett_ncsi_cap_vmode = -1;
static gint ett_ncsi_ls = -1;
static gint ett_ncsi_mlnx = -1;
static gint ett_ncsi_mlnx_sms = -1;
static gint ett_ncsi_mlnx_ifm = -1;

#define NCSI_MIN_LENGTH 8

/* DMTF Document Identifier: DSP0222 Version: 1.2.0_2b */
enum ncsi_type {
    NCSI_TYPE_CLS = 0x00,           /* Clear Initial State */
    NCSI_TYPE_SEL = 0x01,           /* Select Package */
    NCSI_TYPE_DSL = 0x02,           /* Deselect Package */
    NCSI_TYPE_ECH = 0x03,           /* Enable Channel */
    NCSI_TYPE_DCH = 0x04,           /* Disable Channel */
    NCSI_TYPE_RCH = 0x05,           /* Reset Channel */
    NCSI_TYPE_ETX = 0x06,           /* Enable Channel Network TX */
    NCSI_TYPE_DTX = 0x07,           /* Disable Channel Network TX */
    NCSI_TYPE_ANE = 0x08,           /* AEN Enable */
    NCSI_TYPE_SLK = 0x09,           /* Set Link */
    NCSI_TYPE_GLS = 0x0a,           /* Get Link Status */
    NCSI_TYPE_SVF = 0x0b,           /* Set VLAN Filter */
    NCSI_TYPE_EVL = 0x0c,           /* Enable VLAN */
    NCSI_TYPE_DVL = 0x0d,           /* Disable VLAN */
    NCSI_TYPE_MAC = 0x0e,           /* Set MAC Address */
    NCSI_TYPE_EBF = 0x10,           /* Enable Broadcast Filter */
    NCSI_TYPE_DBF = 0x11,           /* Disable Broadcast Filter */
    NCSI_TYPE_EMF = 0x12,           /* Enable Global Multicast Filter */
    NCSI_TYPE_DMF = 0x13,           /* Disable Global Multicast Filter */
    NCSI_TYPE_SFC = 0x14,           /* Set NC-SI Flow Control */
    NCSI_TYPE_VER = 0x15,           /* Get Version ID */
    NCSI_TYPE_CAP = 0x16,           /* Get Capabilities */
    NCSI_TYPE_PAR = 0x17,           /* Get Parameters */
    NCSI_TYPE_CPS = 0x18,           /* Get Controller Packet Statistics */
    NCSI_TYPE_GST = 0x19,           /* Get NC-SI Statistics */
    NCSI_TYPE_PST = 0x1a,           /* Get NC-SI Pass- through Statistics */
    NCSI_TYPE_GPS = 0x1b,           /* Get Package Status */
    NCSI_TYPE_GPA = 0x1c,           /* Get PF Assignment */
    NCSI_TYPE_SPA = 0x1d,           /* Set PF Assignment */
    NCSI_TYPE_GBC = 0x1e,           /* Get Boot Config */
    NCSI_TYPE_SBC = 0x1f,           /* Set Boot Config */
    NCSI_TYPE_IOS = 0x20,           /* Get iSCSI Offload Statistics */
    NCSI_TYPE_GPB = 0x21,           /* Get Partition TX Bandwidth */
    NCSI_TYPE_SPB = 0x22,           /* Set Partition TX Bandwidth */
    NCSI_TYPE_GIT = 0x23,           /* Get ASIC Temperature */
    NCSI_TYPE_GAT = 0x24,           /* Get Ambient Temperature */
    NCSI_TYPE_GMT = 0x25,           /* Get SFF Module Temp */
    NCSI_TYPE_OEM = 0x50,           /* OEM Command */
    NCSI_TYPE_PLDM = 0x51,          /* PLDM */
    NCSI_TYPE_UUID = 0x52,          /* Get Package UUID */
    NCSI_TYPE_AEN = 0xff,
};


enum ncsi_oem_id {
    NCSI_OEM_MLX  = 0x8119,
    NCSI_OEM_BCM  = 0x113d,
};

static const value_string ncsi_resp_code_vals[] = {
    { 0x0000, "Command Completed" },
    { 0x0001, "Command Failed" },
    { 0x0002, "Command Unavailable" },
    { 0x0003, "Command Unsupported" },
    { 0x0004, "Delayed" },
    { 0, NULL },
};

static const value_string ncsi_resp_reason_vals[] = {
    { 0x0000, "No Error/No Reason Code" },
    { 0x0001, "Interface Initialization Required" },
    { 0x0002, "Parameter Is Invalid, Unsupported, or Out-of-Range" },
    { 0x0003, "Channel Not Ready" },
    { 0x0004, "Package Not Ready" },
    { 0x0005, "Invalid payload length" },
    { 0x0006, "Information not available" },
    { 0x0901, "Set Link Host OS/ Driver Conflict" },
    { 0x0902, "Set Link Media Conflict" },
    { 0x0903, "Set Link Parameter Conflict" },
    { 0x0904, "Set Link Power Mode Conflict" },
    { 0x0905, "Set Link Speed Conflict" },
    { 0x0906, "Link Command Failed-Hardware Access Error" },
    { 0x0a06, "Link Command Failed-Hardware Access Error" },
    { 0x0b07, "VLAN Tag Is Invalid"},
    { 0x0e08, "MAC Address Is Zero"},
    { 0x1409, "Independent transmit and receive enable/disable control is not supported"},
    { 0x800c, "Link Command Failed-Hardware Access Error"},
    { 0, NULL },
};



static const value_string ncsi_type_vals[] = {
    { NCSI_TYPE_CLS, "Clear Initial State" },
    { NCSI_TYPE_SEL, "Select Package" },
    { NCSI_TYPE_DSL, "Deselect Package" },
    { NCSI_TYPE_ECH, "Enable Channel" },
    { NCSI_TYPE_DCH, "Disable Channel" },
    { NCSI_TYPE_RCH, "Reset Channel" },
    { NCSI_TYPE_ETX, "Enable Channel Network TX" },
    { NCSI_TYPE_DTX, "Disable Channel Network TX" },
    { NCSI_TYPE_ANE, "AEN Enable" },
    { NCSI_TYPE_SLK, "Set Link" },
    { NCSI_TYPE_GLS, "Get Link Status" },
    { NCSI_TYPE_SVF, "Set VLAN Filter" },
    { NCSI_TYPE_EVL, "Enable VLAN" },
    { NCSI_TYPE_DVL, "Disable VLAN" },
    { NCSI_TYPE_MAC, "Set MAC Address" },
    { NCSI_TYPE_EBF, "Enable Broadcast Filter" },
    { NCSI_TYPE_DBF, "Disable Broadcast Filter" },
    { NCSI_TYPE_EMF, "Enable Global Multicast Filter" },
    { NCSI_TYPE_DMF, "Disable Global Multicast Filter" },
    { NCSI_TYPE_SFC, "Set NC-SI Flow Control" },
    { NCSI_TYPE_VER, "Get Version ID" },
    { NCSI_TYPE_CAP, "Get Capabilities" },
    { NCSI_TYPE_PAR, "Get Parameters" },
    { NCSI_TYPE_CPS, "Get Controller Packet Statistics" },
    { NCSI_TYPE_GST, "Get NC-SI Statistics" },
    { NCSI_TYPE_PST, "Get NC-SI Pass- through Statistics" },
    { NCSI_TYPE_GPS, "Get Package Status" },
    { NCSI_TYPE_GPA, "Get PF Assignment" },
    { NCSI_TYPE_SPA, "Set PF Assignment" },
    { NCSI_TYPE_GBC, "Get Boot Config" },
    { NCSI_TYPE_SBC, "Set Boot Config" },
    { NCSI_TYPE_IOS, "Get iSCSI Offload Statistics" },
    { NCSI_TYPE_GPB, "Get Partition TX Bandwidth" },
    { NCSI_TYPE_SPB, "Set Partition TX Bandwidth" },
    { NCSI_TYPE_GIT, "Get ASIC Temperature" },
    { NCSI_TYPE_GAT, "Get Ambient Temperature" },
    { NCSI_TYPE_GMT, "Get SFF Module Temp" },
    { NCSI_TYPE_OEM, "OEM Command" },
    { NCSI_TYPE_PLDM, "PLDM" },
    { NCSI_TYPE_UUID, "Get Package UUID" },
    { NCSI_TYPE_AEN, "Async Event Notification" },
    { 0, NULL },
};

static const value_string ncsi_oem_id_vals[] = {
    { NCSI_OEM_MLX, "Mellanox" },
    { NCSI_OEM_BCM, "Broadcom" },
    { 0, NULL },
};

static const value_string ncsi_type_resp_vals[] = {
    { 0x00, "request" },
    { 0x01, "response" },
    { 0, NULL },
};

static const value_string ncsi_aen_type_vals[] = {
    { 0x00, "Link status change" },
    { 0x01, "Configuration required" },
    { 0x02, "Host NC driver status change" },
    { 0x03, "Delayed Response Ready" },
    { 0, NULL },
};

static const true_false_string tfs_linkup_linkdown = { "Link up", "Link down" };

static const value_string ncsi_lstat_speed_duplex_vals[] = {
    { 0x00, "Auto-negotiate not complete" },
    { 0x01, "10BaseT half duplex" },
    { 0x02, "10BaseT full duplex" },
    { 0x03, "100BaseT half duplex" },
    { 0x04, "100BaseT4" },
    { 0x05, "100BaseTX full duplex" },
    { 0x06, "1000BaseT half duplex" },
    { 0x07, "1000BaseT full duplex" },
    { 0x08, "10GBaseT support" },
    { 0, NULL },
};

/* Mellanox MC IP Filter Mode */
static const value_string ncsi_mlnx_ifm_byip_vals[] = {
    { 0x00, "MAC address is used and IP address is ignored on pass-through" },
    { 0x01, "MAC address is used and IP address is used on pass-through" },
    { 0x02, "MAC address is ignored and IP address is used on pass-through" },
    { 0x03, "Reserved" },
    { 0, NULL },
};

static const true_false_string tfs_complete_disable_inprog = { "Complete", "Disabled/In-progress" };

static const value_string ncsi_partner_flow_vals[] = {
    { 0x00, "Not pause capable" },
    { 0x01, "Symmetric pause" },
    { 0x02, "Asymmetric pause" },
    { 0x03, "Symmetric & Assymetric pause" },
    { 0, NULL },
};


static const value_string ncsi_mlnx_gama_st_vals[] = {
    { 0x00, "No MAC address was allocated for the requested BMC channel" },
    { 0x01, "An address was allocated for the requested BMC channel" },
    { 0, NULL },
};

static const true_false_string tfs_running_not_running = { "Running", "Not running" };

static const value_string ncsi_sm_at_vals[] = {
    { 0x00, "unicast" },
    { 0x01, "multicast" },
    { 0, NULL },
};

static const value_string ncsi_bf_filter_vals[] = {
    { 0x00, "drop" },
    { 0x01, "forward" },
    { 0, NULL },
};


static void
ncsi_proto_tree_add_lstat(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    static int * const lstat_fields[] = {
        &hf_ncsi_lstat_flag,
        &hf_ncsi_lstat_speed_duplex,
        &hf_ncsi_lstat_autoneg,
        &hf_ncsi_lstat_autoneg_complete,
        &hf_ncsi_lstat_parallel_detection,
        &hf_ncsi_lstat_1000TFD,
        &hf_ncsi_lstat_1000THD,
        &hf_ncsi_lstat_100T4,
        &hf_ncsi_lstat_100TXFD,
        &hf_ncsi_lstat_100TXHD,
        &hf_ncsi_lstat_10TFD,
        &hf_ncsi_lstat_10THD,
        &hf_ncsi_lstat_tx_flow,
        &hf_ncsi_lstat_rx_flow,
        &hf_ncsi_lstat_partner_flow,
        &hf_ncsi_lstat_serdes,
        &hf_ncsi_lstat_oem_speed_valid,
        NULL,
    };

    proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_ncsi_lstat,
            ett_ncsi_lstat, lstat_fields, ENC_BIG_ENDIAN, BMT_NO_APPEND);
}

static void
dissect_ncsi_aen(tvbuff_t *tvb, proto_tree *tree)
{
    guint8 type = tvb_get_guint8(tvb, 19);
	proto_item *pi;

    pi = proto_tree_add_item(tree, hf_ncsi_aen_type, tvb, 19, 1, ENC_NA);

    if(type >= 0x4 && type <= 0x6f)
	{
	    proto_item_set_text(pi, "Reserved (0x%02x)", type);
	}
	else
    if(type >= 0x70 && type <= 0x7f)
	{
	    proto_item_set_text(pi, "Transport-specific AENs (0x%02x)", type);
	}
	else
    if(type >= 0x80)
	{
	    proto_item_set_text(pi, "OEM-specific AENs (0x%02x)", type);
	}

    switch (type) {
    case 0x00: //Link Status Change
        ncsi_proto_tree_add_lstat(tvb, tree, 20);
        proto_tree_add_item(tree, hf_ncsi_aen_lsc_oemstat, tvb, 24, 4, ENC_NA);
        break;
    case 0x02: //Host Network Controller Driver Status
        proto_tree_add_item(tree, hf_ncsi_aen_hcds, tvb, 20, 4, ENC_NA);
        break;
    case 0x03: //Delayed Response Ready
		proto_tree_add_item(tree, hf_ncsi_aen_drr_orig_type, tvb, 20, 1, ENC_NA);
		proto_tree_add_item(tree, hf_ncsi_aen_drr_orig_iid, tvb, 21, 1, ENC_NA);

        break;
    }
}



/* NC-SI Version encoding
 *
 * EXAMPLE: Version 3.7.10a      0xF3F7104100
 *          Version 10.01.7      0x1001F70000
 *          Version 3.1          0xF3F1FF0000
 *          Version 1.0a         0xF1F0FF4100
 *          Version 1.0ab        0xF1F0FF4142 (Alpha1 = 0x41, Alpha2 = 0x42)
 */

#define HEXSTR(x) (((x) < 10)? '0' + (x): 'A' + ((x) - 10))

static const gchar *
ncsi_bcd_dig_to_str(tvbuff_t *tvb, const gint offset)
{
    int     length = 16; /* MM.mm.uu.aa.bb */
    guint8  octet;
    int     i;
    char   *digit_str;
    int     str_offset = 0;


    digit_str = (char *)wmem_alloc(wmem_packet_scope(), length);

    for (i = 0 ; i < 3; i++) {
        octet = tvb_get_guint8(tvb, offset + i);

        if (octet == 0xff) {
            break;
        }

        if (i != 0) {
            digit_str[str_offset++] = '.';
        }

        digit_str[str_offset++] = HEXSTR((octet >> 4) & 0x0f);
        digit_str[str_offset++] = HEXSTR(octet & 0x0f);

    }

    octet = tvb_get_guint8(tvb, offset + 3);
    if (octet) {
        digit_str[str_offset++] = '.';
        digit_str[str_offset++] = octet;

        octet = tvb_get_guint8(tvb, offset + 7);
        if (octet) {
            digit_str[str_offset++] = '.';
            digit_str[str_offset++] = octet;
        }

    }

    digit_str[str_offset] = '\0';
    return digit_str;

}


static const gchar *
ncsi_fw_version(tvbuff_t *tvb, const gint offset)
{
    int     length = 16; /* hh.hh.hh.hh */
    guint8  octet;
    int     i;
    char   *ver_str;
    int     str_offset = 0;


    ver_str = (char *)wmem_alloc(wmem_packet_scope(), length);

    for (i = 0 ; i < 4; i++) {
        octet = tvb_get_guint8(tvb, offset + i);

        if (i != 0) {
            ver_str[str_offset++] = '.';
        }

        ver_str[str_offset++] = HEXSTR((octet >> 4) & 0x0f);
        ver_str[str_offset++] = HEXSTR(octet & 0x0f);

    }
    ver_str[str_offset++] = 0;
    return ver_str;
}


static void
ncsi_proto_tree_add_cap(tvbuff_t *tvb, proto_tree *tree, int offset)
{
    static int * const cap_fields[] = {
        &hf_ncsi_cap_flag_ha,
        &hf_ncsi_cap_flag_op,
        &hf_ncsi_cap_flag_n2mfc,
        &hf_ncsi_cap_flag_m2nfc,
        &hf_ncsi_cap_flag_ama,
        NULL,
    };

    static int * const cap_bf_fields[] = {
        &hf_ncsi_cap_bf_arp,
        &hf_ncsi_cap_bf_dhcpc,
        &hf_ncsi_cap_bf_dhcps,
        &hf_ncsi_cap_bf_netbios,
        NULL,
    };

    static int * const cap_mf_fields[] = {
        &hf_ncsi_cap_mf_v6na,
        &hf_ncsi_cap_mf_v6ra,
        &hf_ncsi_cap_mf_dhcpv6,
        NULL,
    };

    static int * const cap_aen_fields[] = {
        &hf_ncsi_cap_aen_lstat,
        &hf_ncsi_cap_aen_cfg,
        &hf_ncsi_cap_aen_drv,
        &hf_ncsi_cap_aen_resv,
        &hf_ncsi_cap_aen_oem,
        NULL,
    };

    static int * const cap_vmode_fields[] = {
        &hf_ncsi_cap_vmode_vo,
        &hf_ncsi_cap_vmode_both,
        &hf_ncsi_cap_vmode_any,
        NULL,
    };

    proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_ncsi_cap_flag,
            ett_ncsi_cap_flag, cap_fields, ENC_BIG_ENDIAN, BMT_NO_APPEND);

    proto_tree_add_bitmask_with_flags(tree, tvb, offset += 4, hf_ncsi_cap_bf,
            ett_ncsi_cap_bf, cap_bf_fields, ENC_BIG_ENDIAN, BMT_NO_APPEND);

    proto_tree_add_bitmask_with_flags(tree, tvb, offset += 4, hf_ncsi_cap_mf,
            ett_ncsi_cap_mf, cap_mf_fields, ENC_BIG_ENDIAN, BMT_NO_APPEND);

    proto_tree_add_item(tree, hf_ncsi_cap_buf, tvb, offset += 4, 4, ENC_NA);

    proto_tree_add_bitmask_with_flags(tree, tvb, offset += 4, hf_ncsi_cap_aen,
            ett_ncsi_cap_aen, cap_aen_fields, ENC_BIG_ENDIAN, BMT_NO_APPEND);

    proto_tree_add_item(tree, hf_ncsi_cap_vcnt, tvb, offset += 4, 1, ENC_NA);
    proto_tree_add_item(tree, hf_ncsi_cap_mixcnt, tvb, offset += 1, 1, ENC_NA);
    proto_tree_add_item(tree, hf_ncsi_cap_mccnt, tvb, offset += 1, 1, ENC_NA);
    proto_tree_add_item(tree, hf_ncsi_cap_uccnt, tvb, offset += 1, 1, ENC_NA);
    proto_tree_add_bitmask_with_flags(tree, tvb, offset += 3, hf_ncsi_cap_vmode,
            ett_ncsi_cap_vmode, cap_vmode_fields, ENC_BIG_ENDIAN, BMT_NO_APPEND);
    proto_tree_add_item(tree, hf_ncsi_cap_chcnt, tvb, offset, 1, ENC_NA);

}


static void
ncsi_proto_tree_add_setlink(tvbuff_t *tvb, proto_tree *tree, int offset)
{

    static int * const ls_fields[] = {
        &hf_ncsi_ls_an,
        &hf_ncsi_ls_10m,
        &hf_ncsi_ls_100m,
        &hf_ncsi_ls_1g,
        &hf_ncsi_ls_10g,
        &hf_ncsi_ls_20g,
        &hf_ncsi_ls_25g,
        &hf_ncsi_ls_40g,
        &hf_ncsi_ls_hd,
        &hf_ncsi_ls_fd,
        &hf_ncsi_ls_pc,
        &hf_ncsi_ls_apc,
        &hf_ncsi_ls_50g,
        &hf_ncsi_ls_100g,
        &hf_ncsi_ls_2_5g,
        &hf_ncsi_ls_5g,
        &hf_ncsi_ls_rsv,
        NULL,
    };



    proto_tree_add_bitmask_with_flags(tree, tvb, offset, hf_ncsi_ls,
            ett_ncsi_ls, ls_fields, ENC_BIG_ENDIAN, BMT_NO_APPEND);

    proto_tree_add_item(tree, hf_ncsi_ls_oemls, tvb, offset + 4, 4, ENC_NA);


}

/* Code to actually dissect the packets */
static int
dissect_ncsi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_tree *ncsi_tree, *ncsi_payload_tree;
    proto_item *ti, *pti;
    guint8 type, plen, poffset;

    static int * const type_masked_fields[] = {
        &hf_ncsi_type_code_masked,
        &hf_ncsi_type_resp,
        NULL,
    };

    static int * const chan_fields[] = {
        &hf_ncsi_pkg,
        &hf_ncsi_ichan,
        NULL,
    };

    /* Check that the packet is long enough for it to belong to us. */
    if (tvb_reported_length(tvb) < NCSI_MIN_LENGTH)
        return 0;


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NCSI");

    type = tvb_get_guint8(tvb, 4);
    plen = tvb_get_guint8(tvb, 7);

    col_clear(pinfo->cinfo, COL_INFO);
    if (type == 0xff) {
        col_add_fstr(pinfo->cinfo, COL_INFO,
                "Async Event Notification, chan 0x%02x",
                tvb_get_guint8(tvb, 5));
    } else {
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s, id 0x%02x, chan 0x%02x",
                val_to_str(type & 0x7f, ncsi_type_vals, "Unknown type 0x%02x"),
                type & 0x80 ? "response" : "request ",
                tvb_get_guint8(tvb, 3),
                tvb_get_guint8(tvb, 5));
    }


    /* Top-level NCSI protocol item & tree */
    ti = proto_tree_add_item(tree, proto_ncsi, tvb, 0, -1, ENC_NA);
    ncsi_tree = proto_item_add_subtree(ti, ett_ncsi);
    /* Standard header fields */
    proto_tree_add_item(ncsi_tree, hf_ncsi_mc_id, tvb, 0, 1, ENC_NA);
    proto_tree_add_item(ncsi_tree, hf_ncsi_revision, tvb, 1, 1, ENC_NA);
    proto_tree_add_item(ncsi_tree, hf_ncsi_iid, tvb, 3, 1, ENC_NA);
    if (type == NCSI_TYPE_AEN)
	    proto_tree_add_uint(ncsi_tree, hf_ncsi_type_code, tvb, 4, 1, type);
	else
        proto_tree_add_bitmask(ncsi_tree, tvb, 4, hf_ncsi_type,
            ett_ncsi_type, type_masked_fields, ENC_NA);
    /* Package# and internal channel id */
    proto_tree_add_bitmask(ncsi_tree, tvb, 5, hf_ncsi_chan,
            ett_ncsi_chan, chan_fields, ENC_NA);
    proto_tree_add_item(ncsi_tree, hf_ncsi_plen, tvb, 7, 1, ENC_NA);
    if (!plen)
        return 16;

    /* Payload tree */
    ncsi_payload_tree = proto_tree_add_subtree(ncsi_tree, tvb, 16,
            plen, ett_ncsi_payload, &pti, "Payload");

    /* All responses start with response code & reason data */
    if (type != 0xff && type & 0x80) {
        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_resp, tvb,
                16, 2, ENC_NA);
        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_reason, tvb,
                18, 2, ENC_NA);
    }

    if (type == NCSI_TYPE_AEN) {
        proto_item_set_text(pti, "Async Event Notification");
    } else {
        proto_item_set_text(pti,"%s", val_to_str((type & 0x7f), ncsi_type_vals, "Unknown type 0x%02x"));
        proto_item_append_text(pti, type & 0x80 ? " response" : " request");
    }

    switch (type) {
    case 0x01:
        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_sp_hwarb, tvb,
                19, 1, ENC_NA);
        break;
    case 0x04:
        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_dc_ald, tvb,
                19, 1, ENC_NA);
        break;
    case 0x08:
        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_aene_mc, tvb,
                19, 1, ENC_NA);
        break;

    case 0x09:
        ncsi_proto_tree_add_setlink(tvb, ncsi_payload_tree, 16);
        break;

    case 0x0e:
        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_sm_mac, tvb,
                16, 6, ENC_NA);
        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_sm_macno, tvb,
                22, 1, ENC_NA);
        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_sm_at, tvb,
                23, 1, ENC_NA);
        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_sm_e, tvb,
                23, 1, ENC_NA);
        break;
    case 0x10:
        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_bf, tvb,
                16, 4, ENC_NA);
        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_bf_arp, tvb,
                16, 4, ENC_NA);
        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_bf_dhcpc, tvb,
                16, 4, ENC_NA);
        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_bf_dhcps, tvb,
                16, 4, ENC_NA);
        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_bf_netbios, tvb,
                16, 4, ENC_NA);
        break;
    case NCSI_TYPE_OEM:
    case NCSI_TYPE_OEM | 0x80:
        poffset = 0;
        if (type == (NCSI_TYPE_OEM | 0x80)) {
            poffset = 4;
        }

        proto_tree_add_item(ncsi_payload_tree, hf_ncsi_oem_id, tvb,
                16 + poffset, 4, ENC_NA);

        if (tvb_get_guint32(tvb, 16 + poffset, ENC_BIG_ENDIAN) == NCSI_OEM_MLX) {
            proto_item *opti;
            proto_tree *oem_payload_tree;
            guint mlnx_cmd, mlnx_param;

            mlnx_cmd = tvb_get_guint8(tvb, 16 + poffset + 5);
            mlnx_param = tvb_get_guint8(tvb, 16 + poffset + 6);
            /* OEM payload tree */
            oem_payload_tree = proto_tree_add_subtree(ncsi_payload_tree, tvb, 16 + poffset + 4, plen - poffset - 4, ett_ncsi_mlnx, &opti, "Mellanox OEM");

            proto_tree_add_item(oem_payload_tree, hf_ncsi_mlnx_cmd, tvb, 16 + poffset + 5, 1, ENC_NA);
            proto_tree_add_item(oem_payload_tree, hf_ncsi_mlnx_parm, tvb, 16 + poffset + 6, 1, ENC_NA);
            proto_tree_add_item(oem_payload_tree, hf_ncsi_mlnx_host, tvb, 16 + poffset + 7, 1, ENC_NA);


            if (type == (NCSI_TYPE_OEM | 0x80)) { /* Reply */

                if (mlnx_cmd == 0x0 && mlnx_param == 0x1b) { /* Get Allocated Management Address (Command = 0x0, Parameter 0x1B) */
                    proto_item_set_text(opti, "Get Allocated Management Address reply");
                    proto_tree_add_item(oem_payload_tree, hf_ncsi_mlnx_gama_st, tvb, 28, 1, ENC_NA);
                    proto_tree_add_item(oem_payload_tree, hf_ncsi_mlnx_gama_mac, tvb, 32, 6, ENC_NA);
                } else if (mlnx_cmd == 0x1 && mlnx_param == 0x7) { /* Set MC Affinity (Command = 0x1, parameter 0x7) */
                    proto_item_set_text(opti, "Set MC Affinity reply");
                } else {
                    proto_item_set_text(opti, "Unknown OEM reply");
                }
                break;
            }

            /* Request */

            if (mlnx_cmd == 0x0 && mlnx_param == 0x1b) { /* Get Allocated Management Address (Command = 0x0, Parameter 0x1B) */
                proto_item_set_text(opti, "Get Allocated Management Address request");
            } else if (mlnx_cmd == 0x1 && mlnx_param == 0x7) { /* Set MC Affinity (Command = 0x1, parameter 0x7) */
                static int * const mlnx_sms_fields[] = {
                    &hf_ncsi_mlnx_sms_rbt,
                    &hf_ncsi_mlnx_sms_smbus,
                    &hf_ncsi_mlnx_sms_pcie,
                    &hf_ncsi_mlnx_sms_rbts,
                    &hf_ncsi_mlnx_sms_smbuss,
                    &hf_ncsi_mlnx_sms_pcies,
                    NULL,
                };

                static int * const mlnx_ifm_fields[] = {
                    &hf_ncsi_mlnx_ifm_byip,
                    &hf_ncsi_mlnx_ifm_v4en,
                    &hf_ncsi_mlnx_ifm_v6len,
                    &hf_ncsi_mlnx_ifm_v6gen,
                    NULL,
                };

                proto_item_set_text(opti, "Set MC Affinity request");
                proto_tree_add_item(oem_payload_tree, hf_ncsi_mlnx_rbt, tvb, 24, 6, ENC_NA);
                proto_tree_add_bitmask_with_flags(oem_payload_tree, tvb, 30, hf_ncsi_mlnx_sms, ett_ncsi_mlnx_sms, mlnx_sms_fields, ENC_BIG_ENDIAN, BMT_NO_APPEND);
                proto_tree_add_item(oem_payload_tree, hf_ncsi_mlnx_beid, tvb, 31, 1, ENC_NA);
                proto_tree_add_item(oem_payload_tree, hf_ncsi_mlnx_bidx, tvb, 32, 1, ENC_NA);
                proto_tree_add_item(oem_payload_tree, hf_ncsi_mlnx_baddr, tvb, 33, 1, ENC_NA);
                proto_tree_add_item(oem_payload_tree, hf_ncsi_mlnx_peid, tvb, 34, 1, ENC_NA);
                proto_tree_add_item(oem_payload_tree, hf_ncsi_mlnx_pidx, tvb, 35, 1, ENC_NA);
                proto_tree_add_item(oem_payload_tree, hf_ncsi_mlnx_paddr, tvb, 36, 2, ENC_NA);

                proto_tree_add_bitmask_with_flags(oem_payload_tree, tvb, 30, hf_ncsi_mlnx_ifm, ett_ncsi_mlnx_ifm, mlnx_ifm_fields, ENC_BIG_ENDIAN, BMT_NO_APPEND);

                /* IP Filter Mode */

                proto_tree_add_item(oem_payload_tree, hf_ncsi_mlnx_v4addr, tvb, 40, 4, ENC_NA);
                proto_tree_add_item(oem_payload_tree, hf_ncsi_mlnx_v6local, tvb, 44, 16, ENC_NA);
                proto_tree_add_item(oem_payload_tree, hf_ncsi_mlnx_v6gbl, tvb, 60, 16, ENC_NA);
            } else {
                proto_item_set_text(opti, "Unknown OEM request");
            }

        } /* NCSI_OEM_MLX */

        break;
    case NCSI_TYPE_GLS | 0x80:
        ncsi_proto_tree_add_lstat(tvb, ncsi_payload_tree, 20);
        break;
    case NCSI_TYPE_AEN:
        dissect_ncsi_aen(tvb, ncsi_payload_tree);
        break;
    case NCSI_TYPE_VER | 0x80:
        if (plen >= 40) { /*  We got complete payload*/
            const gchar *ver_str;
            proto_tree  *ncsi_ver_tree;
            gchar fw_name[13];
            guint16 vid, did, svid, ssid;

            ncsi_ver_tree = proto_tree_add_subtree(ncsi_payload_tree, tvb, 20,
                            plen - 4, ett_ncsi_payload, NULL, "Version ID");
            ver_str = ncsi_bcd_dig_to_str(tvb, 20);
            proto_tree_add_string(ncsi_ver_tree, hf_ncsi_ver, tvb, 20, 8, ver_str);

            tvb_memcpy(tvb, fw_name, 28, 12);
            fw_name[12] = 0;
            proto_tree_add_string(ncsi_ver_tree, hf_ncsi_fw_name, tvb, 28, 12, fw_name);
            proto_tree_add_string(ncsi_ver_tree, hf_ncsi_fw_ver, tvb, 40, 4, ncsi_fw_version(tvb, 40));

            vid = tvb_get_guint16(tvb, 46, ENC_BIG_ENDIAN);
            did = tvb_get_guint16(tvb, 44, ENC_BIG_ENDIAN);
            svid = tvb_get_guint16(tvb, 50, ENC_BIG_ENDIAN);
            ssid = tvb_get_guint16(tvb, 48, ENC_BIG_ENDIAN);

            proto_tree_add_string(ncsi_ver_tree, hf_ncsi_pci_vid, tvb,  46, 2, pci_id_str(vid, 0xffff, 0xffff, 0xffff));
            proto_tree_add_string(ncsi_ver_tree, hf_ncsi_pci_did, tvb,  44, 2, pci_id_str(vid, did, 0xffff, 0xffff));
            proto_tree_add_string(ncsi_ver_tree, hf_ncsi_pci_ssid, tvb,  48, 4, pci_id_str(vid, did, svid, ssid));
            proto_tree_add_item(ncsi_ver_tree, hf_ncsi_iana, tvb, 52, 4, ENC_BIG_ENDIAN);
        }
        break;
    case NCSI_TYPE_CAP | 0x80:
        if (plen >= 32) { /*  We got complete payload */
            ncsi_proto_tree_add_cap(tvb, ncsi_payload_tree, 20);
        }
        break;
    }

    return tvb_captured_length(tvb);
}

void
proto_register_ncsi(void)
{
    /* *INDENT-OFF* */
    /* Field definitions */
    static hf_register_info hf[] = {
        { &hf_ncsi_mc_id,
          { "MC ID", "ncsi.mc_id",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Management controller ID", HFILL },
        },
        { &hf_ncsi_revision,
          { "Revision", "ncsi.revision",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Header revision", HFILL },
        },
        { &hf_ncsi_iid,
          { "IID", "ncsi.iid",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Instance ID", HFILL },
        },
        { &hf_ncsi_type,
          { "Type", "ncsi.type",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Packet type", HFILL },
        },
        { &hf_ncsi_type_code,
          { "Type code", "ncsi.type.code",
			FT_UINT8, BASE_HEX, VALS(ncsi_type_vals), 0,
            "Packet type code", HFILL },
        },
        { &hf_ncsi_type_code_masked,
          { "Type code", "ncsi.type.code_masked",
            FT_UINT8, BASE_HEX, VALS(ncsi_type_vals), 0x7f,
            "Packet type code (masked)", HFILL },
        },
        { &hf_ncsi_type_resp,
          { "Type req/resp", "ncsi.type.resp",
            FT_UINT8, BASE_HEX, VALS(ncsi_type_resp_vals), 0x80,
            "Packet type request/response", HFILL },
        },

        { &hf_ncsi_chan,
          { "Channel", "ncsi.chan",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "NCSI Channel", HFILL },
        },
        { &hf_ncsi_pkg,
          { "Package ID", "ncsi.pkg",
            FT_UINT8, BASE_HEX, NULL, 0xe0, /* bits 7..5 */
            "NCSI Internal Channel", HFILL },
        },
        { &hf_ncsi_ichan,
          { "Internal Channel ID", "ncsi.ichan", /* bits 4..0 */
            FT_UINT8, BASE_HEX, NULL, 0x1f,
            "NCSI Internal Channel", HFILL },
        },
        { &hf_ncsi_plen,
          { "Payload Length", "ncsi.plen",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_resp,
          { "Response", "ncsi.resp",
            FT_UINT16, BASE_HEX, VALS(ncsi_resp_code_vals), 0x0,
            "Response code", HFILL },
        },
        { &hf_ncsi_reason,
          { "Reason", "ncsi.reason",
            FT_UINT16, BASE_HEX, VALS(ncsi_resp_reason_vals), 0x0,
            "Reason code", HFILL },
        },
        { &hf_ncsi_sp_hwarb,
          { "Hardware arbitration disable", "ncsi.sp.hwarb",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_dc_ald,
          { "Allow link down", "ncsi.dc.ald",
            FT_UINT8, BASE_HEX, NULL, 0x1,
            NULL, HFILL },
        },
        { &hf_ncsi_aene_mc,
          { "Management controller ID", "ncsi.aene.mc",
            FT_UINT8, BASE_HEX, NULL, 0x1,
            NULL, HFILL },
        },
        { &hf_ncsi_sm_mac,
          { "MAC address", "ncsi.sm.mac",
            FT_ETHER, BASE_NONE, NULL, 0,
            NULL, HFILL },
        },
        { &hf_ncsi_sm_macno,
          { "MAC address number", "ncsi.sm.macno",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL },
        },
        { &hf_ncsi_sm_at,
          { "Address type", "ncsi.sm.at",
            FT_UINT8, BASE_HEX, VALS(ncsi_sm_at_vals), 0xe0,
            NULL, HFILL },
        },
        { &hf_ncsi_sm_e,
          { "Enabled", "ncsi.sm.e",
			FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x1,
            NULL, HFILL },
        },
        { &hf_ncsi_aen_type,
          { "AEN type", "ncsi.aen_type",
            FT_UINT8, BASE_HEX, VALS(ncsi_aen_type_vals), 0,
            NULL, HFILL },
        },
        { &hf_ncsi_aen_lsc_oemstat,
          { "AEN link OEM status", "ncsi.aen_lsc_oemstat",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_aen_hcds,
          { "AEN Host Network Controller Driver Status", "ncsi.aen_hcds",
			FT_BOOLEAN, 32, TFS(&tfs_running_not_running), 1 << 0,
            NULL, HFILL },
        },
        { &hf_ncsi_aen_drr_orig_type,
          { "Original Command Type", "ncsi.aen_drr.otype",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_aen_drr_orig_iid,
          { "Original Command IID", "ncsi.aen_drr.oiid",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        /* Broadcast filter */
        { &hf_ncsi_bf,
          { "Broadcast filter settings", "ncsi.bf.settings",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_bf_arp,
          { "ARP", "ncsi.bf.settings.arp",
            FT_UINT32, BASE_HEX, VALS(ncsi_bf_filter_vals), 1 << 0,
            NULL, HFILL },
        },
        { &hf_ncsi_bf_dhcpc,
          { "DHCP Client", "ncsi.bf.settings.dhcpc",
            FT_UINT32, BASE_HEX, VALS(ncsi_bf_filter_vals), 1 << 1,
            NULL, HFILL },
        },
        { &hf_ncsi_bf_dhcps,
          { "DHCP Server", "ncsi.bf.settings.dhcps",
            FT_UINT32, BASE_HEX, VALS(ncsi_bf_filter_vals), 1 << 2,
            NULL, HFILL },
        },
        { &hf_ncsi_bf_netbios,
          { "NetBIOS", "ncsi.bf.settings.netbios",
            FT_UINT32, BASE_HEX, VALS(ncsi_bf_filter_vals), 1 << 3,
            NULL, HFILL },
        },
       /* Link settings */
        { &hf_ncsi_ls,
          { "Link Settings", "ncsi.ls",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_ls_an,
          { "Auto Negotiation", "ncsi.ls.an",
			FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 1 << 0,
            NULL, HFILL },
        },
        { &hf_ncsi_ls_10m,
          { "enable 10 Mbps", "ncsi.ls.10m",
			FT_BOOLEAN, 32, TFS(&tfs_set_notset), 1 << 1,
            NULL, HFILL },
        },
        { &hf_ncsi_ls_100m,
          { "enable 100 Mbps", "ncsi.ls.100m",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 1 << 2,
            NULL, HFILL },
        },
        { &hf_ncsi_ls_1g,
          { "enable 1000 Mbps (1 Gbps)", "ncsi.ls.1g",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 1 << 3,
            NULL, HFILL },
        },
        { &hf_ncsi_ls_10g,
          { "enable 10 Gbps", "ncsi.ls.10g",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 1 << 4,
            NULL, HFILL },
        },
        { &hf_ncsi_ls_20g,
          { "enable 20 Gbps", "ncsi.ls.20g",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 1 << 5,
            NULL, HFILL },
        },
        { &hf_ncsi_ls_25g,
          { "enable 25 Gbps", "ncsi.ls.25g",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 1 << 6,
            NULL, HFILL },
        },
        { &hf_ncsi_ls_40g,
          { "enable 40 Gbps", "ncsi.ls.40g",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 1 << 7,
            NULL, HFILL },
        },
        { &hf_ncsi_ls_hd,
          { "enable half-duplex", "ncsi.ls.hd",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 1 << 8,
            NULL, HFILL },
        },
        { &hf_ncsi_ls_fd,
          { "enable full-duplex", "ncsi.ls.fd",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 1 << 9,
            NULL, HFILL },
        },
        { &hf_ncsi_ls_pc,
          { "Pause Capability", "ncsi.ls.pc",
			FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 1 << 10,
            NULL, HFILL },
        },
        { &hf_ncsi_ls_apc,
          { "Asymmetric Pause Capability", "ncsi.ls.apc",
			FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 1 << 11,
            NULL, HFILL },
        },
        { &hf_ncsi_ls_50g,
          { "enable 50 Gbps", "ncsi.ls.50g",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 1 << 13,
            NULL, HFILL },
        },
        { &hf_ncsi_ls_100g,
          { "enable 100 Gbps", "ncsi.ls.100g",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 1 << 14,
            NULL, HFILL },
        },
        { &hf_ncsi_ls_2_5g,
          { "enable 2.5 Gbps", "ncsi.ls.2_5g",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 1 << 15,
            NULL, HFILL },
        },
        { &hf_ncsi_ls_5g,
          { "enable 2.5 Gbps", "ncsi.ls.5g",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 1 << 16,
            NULL, HFILL },
        },
        { &hf_ncsi_ls_rsv,
          { "Reserved", "ncsi.ls.rsv",
            FT_UINT32, BASE_HEX, NULL, 0xfffe0000, /* bits 17..31 */
            NULL, HFILL },
        },
        { &hf_ncsi_ls_oemls,
          { "OEM Link Settings", "ncsi.ls.oemls",
            FT_UINT32, BASE_HEX, NULL, 0x0 ,
            NULL, HFILL },
        },

        /* generic link status */
        { &hf_ncsi_lstat,
          { "Link status", "ncsi.lstat",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_lstat_flag,
          { "Link flag", "ncsi.lstat.flag",
			FT_BOOLEAN, 32, TFS(&tfs_linkup_linkdown), 0x1,
            NULL, HFILL },
        },
        { &hf_ncsi_lstat_speed_duplex,
          { "Speed & duplex", "ncsi.lstat.speed_duplex",
            FT_UINT32, BASE_HEX, VALS(ncsi_lstat_speed_duplex_vals), 0x1e,
            NULL, HFILL },
        },
        { &hf_ncsi_lstat_autoneg,
          { "Autonegotiation", "ncsi.lstat.autoneg",
	    FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 1 << 5,
            NULL, HFILL },
        },
        { &hf_ncsi_lstat_autoneg_complete,
          { "Autonegotiation complete", "ncsi.lstat.autoneg_complete",
			FT_BOOLEAN, 32, TFS(&tfs_complete_disable_inprog), 1 << 6,
            NULL, HFILL },
        },
        { &hf_ncsi_lstat_parallel_detection,
          { "Parallel detection", "ncsi.lstat.parallel_detection",
			FT_BOOLEAN, 32, TFS(&tfs_used_notused), 1 << 7,
            NULL, HFILL },
        },
        { &hf_ncsi_lstat_1000TFD,
          { "1000TFD", "ncsi.lstat.1000tfd",
			FT_BOOLEAN, 32, TFS(&tfs_capable_not_capable), 1 << 9,
            "Partner advertised 1000TFD", HFILL },
        },
        { &hf_ncsi_lstat_1000THD,
          { "1000THD", "ncsi.lstat.1000thd",
			FT_BOOLEAN, 32, TFS(&tfs_capable_not_capable), 1 << 10,
            "Partner advertised 1000THD", HFILL },
        },
        { &hf_ncsi_lstat_100T4,
          { "100T4", "ncsi.lstat.100t4",
			FT_BOOLEAN, 32, TFS(&tfs_capable_not_capable), 1 << 11,
            "Partner advertised 100T4", HFILL },
        },
        { &hf_ncsi_lstat_100TXFD,
          { "100TXFD", "ncsi.lstat.100txfd",
			FT_BOOLEAN, 32, TFS(&tfs_capable_not_capable), 1 << 12,
            "Partner advertised 100TXFD", HFILL },
        },
        { &hf_ncsi_lstat_100TXHD,
          { "100TXHD", "ncsi.lstat.100txhd",
			FT_BOOLEAN, 32, TFS(&tfs_capable_not_capable), 1 << 13,
            "Partner advertised 100TXHD", HFILL },
        },
        { &hf_ncsi_lstat_10TFD,
          { "10TFD", "ncsi.lstat.10tfd",
	    FT_BOOLEAN, 32, TFS(&tfs_capable_not_capable), 1 << 14,
            "Partner advertised 10TFD", HFILL },
        },
        { &hf_ncsi_lstat_10THD,
          { "10THD", "ncsi.lstat.10thd",
	    FT_BOOLEAN, 32, TFS(&tfs_capable_not_capable), 1 << 15,
            "Partner advertised 10THD", HFILL },
        },
        { &hf_ncsi_lstat_tx_flow,
          { "TX flow", "ncsi.lstat.tx_flow",
	    FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 1 << 16,
            "TX flow control", HFILL },
        },
        { &hf_ncsi_lstat_rx_flow,
          { "RX flow", "ncsi.lstat.rx_flow",
	    FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 1 << 17,
            "RX flow control", HFILL },
        },
        { &hf_ncsi_lstat_partner_flow,
          { "Partner flow", "ncsi.lstat.partner_flow",
            FT_UINT32, BASE_HEX, VALS(ncsi_partner_flow_vals), 3<<18,
            "Partner-advertised flow control", HFILL },
        },
        { &hf_ncsi_lstat_serdes,
          { "SerDes", "ncsi.lstat.serdes",
			FT_BOOLEAN, 32, TFS(&tfs_used_notused), 1 << 20,
            NULL, HFILL },
        },
        { &hf_ncsi_lstat_oem_speed_valid,
          { "OEM Speed", "ncsi.lstat.oem_speed_valid",
			FT_BOOLEAN, 32, TFS(&tfs_valid_invalid), 1 << 21,
            NULL, HFILL },
        },

        /* Get Verison ID */
        { &hf_ncsi_ver,
          { "NC-SI version", "ncsi.ver",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL },
        },

        { &hf_ncsi_fw_name,
          { "Firmware name", "ncsi.fw.name",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL },
        },
        { &hf_ncsi_fw_ver,
          { "Firmware version", "ncsi.fw.ver",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL },
        },
        { &hf_ncsi_pci_did,
          { "PCI DID", "ncsi.pci.did",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL },
        },
        { &hf_ncsi_pci_vid,
          { "PCI VID", "ncsi.pci.vid",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL },
        },
        { &hf_ncsi_pci_ssid,
          { "PCI SVID-SSID", "ncsi.pci.ssid",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL },
        },
        { &hf_ncsi_iana,
          { "IANA Enterprise Number", "ncsi.iana",
            FT_UINT32, BASE_ENTERPRISES, STRINGS_ENTERPRISES, 0,
            NULL, HFILL },
        },

        /* Get Capabilities */
        { &hf_ncsi_cap_flag,
          { "Capabilities Flags", "ncsi.cap",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_cap_flag_ha,
          { "Hardware Arbitration", "ncsi.cap.ha",
			FT_BOOLEAN, 32, TFS(&tfs_capable_not_capable), 1 << 0,
            NULL, HFILL },
        },
        { &hf_ncsi_cap_flag_op,
          { "OS Presence", "ncsi.cap.op",
			FT_BOOLEAN, 32, TFS(&tfs_capable_not_capable), 1 << 1,
            NULL, HFILL },
        },
        { &hf_ncsi_cap_flag_n2mfc,
          { "Network Controller to Management Controller Flow Control Support", "ncsi.cap.n2mfc",
			FT_BOOLEAN, 32, TFS(&tfs_capable_not_capable), 1 << 2,
            NULL, HFILL },
        },
        { &hf_ncsi_cap_flag_m2nfc,
          { "Management Controller to Network Controller Flow Control Support", "ncsi.cap.m2nfc",
			FT_BOOLEAN, 32, TFS(&tfs_capable_not_capable), 1 << 3,
            NULL, HFILL },
        },
        { &hf_ncsi_cap_flag_ama,
          { "All multicast addresses support", "ncsi.cap.ama",
			FT_BOOLEAN, 32, TFS(&tfs_capable_not_capable), 1 << 4,
            NULL, HFILL },
        },
        /* Broadcast Packet Filter Capabilities*/
        { &hf_ncsi_cap_bf,
          { "Broadcast Packet Filter Capabilities", "ncsi.cap.bf",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_cap_bf_arp,
          { "ARP", "ncsi.cap.bf.arp",
			FT_BOOLEAN, 32, TFS(&tfs_capable_not_capable), 1 << 0,
            NULL, HFILL },
        },
        { &hf_ncsi_cap_bf_dhcpc,
          { "DHCP Client", "ncsi.cap.bf.dhcpc",
			FT_BOOLEAN, 32, TFS(&tfs_capable_not_capable), 1 << 1,
            NULL, HFILL },
        },
        { &hf_ncsi_cap_bf_dhcps,
          { "DHCP Server", "ncsi.cap.bf.dhcps",
			FT_BOOLEAN, 32, TFS(&tfs_capable_not_capable), 1 << 2,
            NULL, HFILL },
        },
        { &hf_ncsi_cap_bf_netbios,
          { "NetBIOS", "ncsi.cap.bf.netbios",
			FT_BOOLEAN, 32, TFS(&tfs_capable_not_capable), 1 << 3,
            NULL, HFILL },
        },
        /*Multicast Packet Filter Capabilities*/
        { &hf_ncsi_cap_mf,
          { "Multicast Packet Filter Capabilities", "ncsi.cap.mf",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_cap_mf_v6na,
          { "IPv6 Neighbor Advertisement", "ncsi.cap.mf.v6na",
			FT_BOOLEAN, 32, TFS(&tfs_capable_not_capable), 1 << 0,
            NULL, HFILL },
        },
        { &hf_ncsi_cap_mf_v6ra,
          { "IPv6 Router Advertisement", "ncsi.cap.mf.v6ra",
			FT_BOOLEAN, 32, TFS(&tfs_capable_not_capable), 1 << 1,
            NULL, HFILL },
        },
        { &hf_ncsi_cap_mf_dhcpv6,
          { "DHCPv6 relay and server multicast", "ncsi.cap.mf.v6na",
			FT_BOOLEAN, 32, TFS(&tfs_capable_not_capable), 1 << 2,
            NULL, HFILL },
        },
        /*Buffering Capability*/
        { &hf_ncsi_cap_buf,
          { "Buffering Capability (bytes)", "ncsi.cap.buf",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        /*AEN Control Support*/
        { &hf_ncsi_cap_aen,
          { "AEN Control Support", "ncsi.cap.aen",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_cap_aen_lstat,
          { "Link Status Change AEN control", "ncsi.cap.aen.lstat",
			FT_BOOLEAN, 32, TFS(&tfs_capable_not_capable), 1 << 0,
            NULL, HFILL },
        },
        { &hf_ncsi_cap_aen_cfg,
          { "Configuration Required AEN control", "ncsi.cap.aen.cfg",
			FT_BOOLEAN, 32, TFS(&tfs_capable_not_capable), 1 << 1,
            NULL, HFILL },
        },
        { &hf_ncsi_cap_aen_drv,
          { "Host NC Driver Status Change AEN control", "ncsi.cap.mf.drv",
			FT_BOOLEAN, 32, TFS(&tfs_capable_not_capable), 1 << 2,
            NULL, HFILL },
        },
        { &hf_ncsi_cap_aen_resv, /* bit 3..15 Reserved Reserved */
          { "Reserved", "ncsi.cap.mf.resv",
            FT_UINT32, BASE_HEX, NULL,  0xfff8,
            NULL, HFILL },
        },
        { &hf_ncsi_cap_aen_oem,
          { "OEM-specific AEN control", "ncsi.cap.mf.oem",
            FT_UINT32, BASE_HEX, NULL,  0xffff0000,
            NULL, HFILL },
        },

        { &hf_ncsi_cap_vcnt,
          { "VLAN Filter Count", "ncsi.cap.vcnt",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_cap_mixcnt,
          { "Mixed Filter Count", "ncsi.cap.mixcnt",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_cap_mccnt,
          { "Multicast Filter Count", "ncsi.cap.mccnt",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_cap_uccnt,
          { "Unicast Filter Count", "ncsi.cap.uccnt",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        /*VLAN mode*/
        { &hf_ncsi_cap_vmode,
          { "VLAN Mode Support", "ncsi.cap.vmode",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_cap_vmode_vo,
          { "VLAN only", "ncsi.cap.aen.vmode.vo",
			FT_BOOLEAN, 8, TFS(&tfs_capable_not_capable), 1 << 0,
            NULL, HFILL },
        },
        { &hf_ncsi_cap_vmode_both,
          { "VLAN + non-VLAN", "ncsi.cap.aen.vmode.both",
			FT_BOOLEAN, 8, TFS(&tfs_capable_not_capable), 1 << 1,
            NULL, HFILL },
        },
        { &hf_ncsi_cap_vmode_any,
          { "Any VLAN + non-VLAN", "ncsi.cap.aen.vmode.any",
			FT_BOOLEAN, 8, TFS(&tfs_capable_not_capable), 1 << 2,
            NULL, HFILL },
        },
        { &hf_ncsi_cap_chcnt,
          { "Channel Count", "ncsi.cap.chcnt",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        /* OEM command */
        { &hf_ncsi_oem_id,
          { "OEM ID", "ncsi.oem.id",
            FT_UINT32, BASE_HEX, VALS(ncsi_oem_id_vals), 0x0,
            "Manufacturer ID (IANA)", HFILL },
        },
        /* OEM Mellanox Command, Parameter, Host number */
        { &hf_ncsi_mlnx_cmd,
          { "Command ID", "ncsi.mlnx.cmd",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Mellanox command id", HFILL },
        },
        { &hf_ncsi_mlnx_parm,
          { "Parameter", "ncsi.mlnx.parm",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Mellanox parameter", HFILL },
        },
        { &hf_ncsi_mlnx_host,
          { "Host number", "ncsi.mlnx.host",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Mellanox host number", HFILL },
        },
        /* OEM Mellanox Set MC Affinity (Command = 0x1, parameter 0x7) */
        { &hf_ncsi_mlnx_rbt,
          { "MC RBT address", "ncsi.mlnx.rbt",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL },
        },

        { &hf_ncsi_mlnx_sms,
          { "Supported Medias Status", "ncsi.mlx.sms",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_mlnx_sms_rbt,
          { "RBT", "ncsi.mlx.sms.rbt",
			FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 1 << 0,
            "When set the MC supports RBT", HFILL },
        },
        { &hf_ncsi_mlnx_sms_smbus,
          { "SMBus", "ncsi.mlx.sms.smbus",
			FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 1 << 1,
            "When set, the MC supports MCTP over SMBus", HFILL },
        },
        { &hf_ncsi_mlnx_sms_pcie,
          { "PCIe", "ncsi.mlx.sms.pcie",
			FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 1 << 2,
            "When set, the MC supports MCTP over PCIe", HFILL },
        },
        { &hf_ncsi_mlnx_sms_rbts,
          { "RBT medium status", "ncsi.mlx.sms.rbts",
			FT_BOOLEAN, 8, TFS(&tfs_available_not_available), 1 << 3,
            NULL, HFILL },
        },
        { &hf_ncsi_mlnx_sms_smbuss,
          { "SMBus medium status", "ncsi.mlx.sms.smbuss",
			FT_BOOLEAN, 8, TFS(&tfs_available_not_available), 1 << 4,
            NULL, HFILL },
        },
        { &hf_ncsi_mlnx_sms_pcies,
          { "PCIe medium status", "ncsi.mlx.sms.pcies",
			FT_BOOLEAN, 8, TFS(&tfs_available_not_available), 1 << 5,
            NULL, HFILL },
        },
        { &hf_ncsi_mlnx_beid,
          { "MC SMBus EID", "ncsi.mlx.beid",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_mlnx_bidx,
          { "SMBus index", "ncsi.mlx.bidx",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_mlnx_baddr,
          { "MC SMBus address", "ncsi.mlx.baddr",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_mlnx_peid,
          { "MC PCIe EID", "ncsi.mlx.peid",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_mlnx_pidx,
          { "PCIe index", "ncsi.mlx.pidx",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_mlnx_paddr,
          { "MC PCIe Address", "ncsi.mlx.paddr",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_mlnx_ifm,
          { "MC IP Filter Mode", "ncsi.mlx.ifm",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_mlnx_ifm_byip,
          { "Filter by IP Address", "ncsi.mlx.ifm.byip",
            FT_UINT8, BASE_HEX, VALS(ncsi_mlnx_ifm_byip_vals), 0x3,
            NULL, HFILL },
        },
        { &hf_ncsi_mlnx_ifm_v4en,
          { "IPv4", "ncsi.mlx.ifm.v4en",
			FT_BOOLEAN, 8, TFS(&tfs_used_notused), 1 << 2,
            NULL, HFILL },
        },
        { &hf_ncsi_mlnx_ifm_v6len,
          { "IPv6 Link Local Address", "ncsi.mlx.ifm.v6len",
			FT_BOOLEAN, 8, TFS(&tfs_used_notused), 1 << 3,
            NULL, HFILL },
        },
        { &hf_ncsi_mlnx_ifm_v6gen,
          { "IPv6 Global Address", "ncsi.mlx.ifm.v6gen",
			FT_BOOLEAN, 8, TFS(&tfs_used_notused), 1 << 4,
            NULL, HFILL },
        },
        { &hf_ncsi_mlnx_v4addr,
          { "MC IPv4 Address", "ncsi.mlnx.v4addr",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_mlnx_v6local,
          { "MC IPv6 Link Local Address", "ncsi.mlnx.v6local",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_mlnx_v6gbl,
          { "MC IPv6 Global Address", "ncsi.mlnx.v6gbl",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL },
        },
        /* Get Allocated Management Address (Command = 0x0, Parameter 0x1B) */
        { &hf_ncsi_mlnx_gama_st,
          { "Status", "ncsi.mlx.gama.st",
            FT_UINT8, BASE_HEX, VALS(ncsi_mlnx_gama_st_vals), 0x0,
            NULL, HFILL },
        },
        { &hf_ncsi_mlnx_gama_mac,
          { "Allocated MC MAC address", "ncsi.mlx.gama.mac",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL },
        },



    };

	/* *INDENT-ON* */

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_ncsi,
        &ett_ncsi_type,
        &ett_ncsi_chan,
        &ett_ncsi_payload,
        &ett_ncsi_lstat,
        &ett_ncsi_cap_flag,
        &ett_ncsi_cap_bf,
        &ett_ncsi_cap_mf,
        &ett_ncsi_cap_aen,
        &ett_ncsi_cap_vmode,
        &ett_ncsi_ls,
        &ett_ncsi_mlnx,
        &ett_ncsi_mlnx_sms,
        &ett_ncsi_mlnx_ifm
    };

    /* Register the protocol name and description */
    proto_ncsi = proto_register_protocol("NCSI", "NCSI", "ncsi");
    ncsi_handle = register_dissector("ncsi", dissect_ncsi, proto_ncsi);

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_ncsi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ncsi(void)
{
    dissector_add_uint("ethertype", ETHERTYPE_NCSI, ncsi_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */

/*
 * Formatted by AStyle (3.1) -A10YcHjk3pUxUxBxt2 if under Windows
 */
