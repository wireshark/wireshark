/** @file
 *
 * Definitions of OUIs
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 - 2000 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __OUI_H__
#define __OUI_H__

/*
 * See
 *
 * http://standards.ieee.org/regauth/oui/oui.txt
 *
 * http://docstore.mik.ua/univercd/cc/td/doc/product/lan/trsrb/vlan.htm
 *
 * for the PIDs for VTP and DRiP that go with an OUI of OUI_CISCO.
 */

#define OUI_ENCAP_ETHER     0x000000    /* encapsulated Ethernet */
#define OUI_XEROX           0x000006    /* Xerox */
#define OUI_CISCO           0x00000C    /* Cisco (future use) */
#define OUI_IANA            0x00005E    /* the IANA */
#define OUI_NORTEL          0x000081    /* Nortel SONMP */
#define OUI_CISCO_90        0x0000F8    /* Cisco (IOS 9.0 and above?) */
#define OUI_CISCO_2         0x000142    /* Cisco */
#define OUI_CISCO_3         0x000143    /* Cisco */
#define OUI_FORCE10         0x0001E8    /* Force10 */
#define OUI_ERICSSON        0x0001EC    /* Ericsson Group */
#define OUI_CATENA          0x00025A    /* Catena Networks */
#define OUI_ATHEROS         0x00037F    /* Atheros Communications */
#define OUI_ORACLE          0x0003BA    /* Oracle */
#define OUI_AVAYA_EXTREME   0x00040D    /* Avaya Extreme access point */
#define OUI_EXTREME_MESH    0x000512    /* Extreme MESH */
#define OUI_SONY_ERICSSON   0x000AD9    /* Sony Ericsson Mobile Communications AB */
#define OUI_ARUBA           0x000B86    /* Aruba Networks */
#define OUI_ROUTERBOARD     0x000C42    /* Formerly listed as Mikrotik, however this OUI is owned by Routerboard*/
#define OUI_MERU            0x000CE6    /* Meru Network (Fortinet) */
#define OUI_SONY_ERICSSON_2 0x000E07    /* Sony Ericsson Mobile Communications AB */
#define OUI_PROFINET        0x000ECF    /* PROFIBUS Nutzerorganisation e.V. */
#define OUI_RSN             0x000FAC    /* Wi-Fi : RSN */
#define OUI_SONY_ERICSSON_3 0x000FDE    /* Sony Ericsson Mobile Communications AB */
#define OUI_FORTINET        0x00090F    /* Fortinet */
#define OUI_CIMETRICS       0x001090    /* Cimetrics, Inc. */
#define OUI_IEEE_802_3      0x00120F    /* IEEE 802.3 */
#define OUI_MEDIA_ENDPOINT  0x0012BB    /* Media (TIA TR-41 Committee) */
#define OUI_SONY_ERICSSON_4 0x0012EE    /* Sony Ericsson Mobile Communications AB */
#define OUI_ERICSSON_MOBILE 0x0015E0    /* Ericsson Mobile Platforms */
#define OUI_SONY_ERICSSON_5 0x001620    /* Sony Ericsson Mobile Communications AB */
#define OUI_SONY_ERICSSON_6 0x0016B8    /* Sony Ericsson Mobile Communications AB */
#define OUI_APPLE_AWDL      0x0017F2    /* Apple AWDL */
#define OUI_SONY_ERICSSON_7 0x001813    /* Sony Ericsson Mobile Communications AB */
#define OUI_BLUETOOTH       0x001958    /* Bluetooth SIG */
#define OUI_SONY_ERICSSON_8 0x001963    /* Sony Ericsson Mobile Communications AB */
#define OUI_AEROHIVE        0x001977    /* Aerohive AP to AP communication */
#define OUI_ITU_T           0x0019a7    /* International Telecommunication Union (ITU) Telecommunication Standardization Sector */
#define OUI_DCBX            0x001B21    /* Data Center Bridging Capabilities Exchange Protocol */
#define OUI_CISCO_UBI       0x001B67    /* Cisco/Ubiquisys */
#define OUI_IEEE_802_1QBG   0x001B3F    /* IEEE 802.1 Qbg */
#define OUI_NINTENDO        0x001F32
#define OUI_TURBOCELL       0x0020F6    /* KarlNet, who brought you Turbocell */
#define OUI_ODVA            0x00216C    /* ODVA */
#define OUI_AVAYA           0x00400D    /* Avaya */
#define OUI_CISCOWL         0x004096    /* Cisco Wireless (Aironet) */
#define OUI_MARVELL         0x005043    /* Marvell Semiconductor */
#define OUI_WPAWME          0x0050F2    /* Wi-Fi : WPA / WME */
#define OUI_ERICSSON_2      0x008037    /* Ericsson Group */
#define OUI_HP_2            0x00805F    /* Hewlett-Packard */
#define OUI_IEEE_802_1      0x0080C2    /* IEEE 802.1 Committee */
#define OUI_PRE11N          0x00904C    /* Wi-Fi : 802.11 Pre-N */
#define OUI_ATM_FORUM       0x00A03E    /* ATM Forum */
#define OUI_ZEBRA_EXTREME   0x00A0F8    /* Extreme/WING (Zebra) */
#define OUI_EXTREME         0x00E02B    /* Extreme EDP/ESRP */
#define OUI_CABLE_BPDU      0x00E02F    /* DOCSIS spanning tree BPDU */
#define OUI_FOUNDRY         0x00E052    /* Foundry */
#define OUI_SIEMENS         0x080006    /* Siemens AG */
#define OUI_APPLE_ATALK     0x080007    /* Appletalk */
#define OUI_HP              0x080009    /* Hewlett-Packard */
#define OUI_CERN            0x080030    /* CERN, The European Organization for Nuclear Research */
#define OUI_IEEE_C37_238    0x1C129D    /* IEEE PES PSRC/SUB Working Group H7/Sub C7 (IEEE PC37.238) */
#define OUI_HYTEC_GER       0x30B216    /* Hytec Geraetebau GmbH */
#define OUI_ZIGBEE          0x4A191B    /* ZigBee Alliance */
#define OUI_WFA             0x506F9A    /* Wi-Fi Alliance */
#define OUI_MIST            0x5C5B35    /* Mist Systems */
#define OUI_RUCKUS          0x001392    /* Ruckus Networks */
#define OUI_SMPTE           0x6897E8    /* Society of Motion Picture and Television Engineers */
#define OUI_SGDSN           0x6A5C35    /* Secrétariat Général de la Défense et de la Sécurité Nationale http://www.sgdsn.gouv.fr */
#define OUI_ONOS            0xA42305    /* Open Networking Laboratory (ONOS) */
#define OUI_3GPP2           0xCF0002    /* 3GPP2 */
#define OUI_AVAYA_EXTREME2  0xD88466    /* Avaya Extreme Fabric */

#endif

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
