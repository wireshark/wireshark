/* packet-zbee.h
 * Dissector routines for the ZigBee protocol stack.
 * By Owen Kirby <osk@exegin.com>
 * Copyright 2009 Exegin Technologies Limited
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
#ifndef PACKET_ZBEE_H
#define PACKET_ZBEE_H

/* IEEE 802.15.4 definitions. */
#include <epan/dissectors/packet-ieee802154.h>

/* The ZigBee Broadcast Address */
#define ZBEE_BCAST_ALL                  0xffff
#define ZBEE_BCAST_ACTIVE               0xfffd
#define ZBEE_BCAST_ROUTERS              0xfffc
#define ZBEE_BCAST_LOW_POWER_ROUTERS    0xfffb

/* Capability Information fields. */
#define ZBEE_CINFO_ALT_COORD        IEEE802154_CMD_CINFO_ALT_PAN_COORD
#define ZBEE_CINFO_FFD              IEEE802154_CMD_CINFO_DEVICE_TYPE
#define ZBEE_CINFO_POWER            IEEE802154_CMD_CINFO_POWER_SRC
#define ZBEE_CINFO_IDLE_RX          IEEE802154_CMD_CINFO_IDLE_RX
#define ZBEE_CINFO_SECURITY         IEEE802154_CMD_CINFO_SEC_CAPABLE
#define ZBEE_CINFO_ALLOC            IEEE802154_CMD_CINFO_ALLOC_ADDR

/* ZigBee version numbers. */
#define ZBEE_VERSION_PROTOTYPE      0 /* Does this even exist? */
#define ZBEE_VERSION_2004           1 /* Re: 053474r06ZB_TSC-ZigBeeSpecification.pdf */
#define ZBEE_VERSION_2007           2 /* Re: 053474r17ZB_TSC-ZigBeeSpecification.pdf */

/* ZigBee version macro. */
#define ZBEE_HAS_2003(x)            ((x) >= ZBEE_VERSION_2003)
#define ZBEE_HAS_2006(x)            ((x) >= ZBEE_VERSION_2007)
#define ZBEE_HAS_2007(x)            ((x) >= ZBEE_VERSION_2007)

/* ZigBee Application Profile IDs */
#define ZBEE_DEVICE_PROFILE                 0x0000

#define ZBEE_PROFILE_IPM                    0x0101

#define ZBEE_PROFILE_T1                     0x0103
#define ZBEE_PROFILE_HA                     0x0104
#define ZBEE_PROFILE_CBA                    0x0105
#define ZBEE_PROFILE_WSN                    0x0106
#define ZBEE_PROFILE_TA                     0x0107
#define ZBEE_PROFILE_HC                     0x0108
#define ZBEE_PROFILE_SE                     0x0109

#define ZBEE_PROFILE_STD_MIN                0x0000
#define ZBEE_PROFILE_STD_MAX                0x7eff

/* ZigBee Reserved */
#define ZBEE_PROFILE_T2                     0x7f01

/* Application Profile ID Ranges */
#define ZBEE_PROFILE_RSVD0_MIN              0x7f00
#define ZBEE_PROFILE_RSVD0_MAX              0x7fff

#define ZBEE_PROFILE_RSVD1_MIN              0x8000
#define ZBEE_PROFILE_RSVD1_MAX              0xbeff

/* Organization Profile IDs */
#define ZBEE_PROFILE_IEEE_1451_5            0xbf00

#define ZBEE_PROFILE_MFR_SPEC_ORG_MIN       0xbf00
#define ZBEE_PROFILE_MFR_SPEC_ORG_MAX       0xbfff

/* Manufacturer Profile ID Allocations */
#define ZBEE_PROFILE_CIRRONET_0_MIN         0xc000
#define ZBEE_PROFILE_CIRRONET_0_MAX         0xc002
#define ZBEE_PROFILE_CHIPCON_MIN            0xc003
#define ZBEE_PROFILE_CHIPCON_MAX            0xc00c
#define ZBEE_PROFILE_EMBER_MIN              0xc00d
#define ZBEE_PROFILE_EMBER_MAX              0xc016
#define ZBEE_PROFILE_NTS_MIN                0xc017
#define ZBEE_PROFILE_NTS_MAX                0xc020
#define ZBEE_PROFILE_FREESCALE_MIN          0xc021
#define ZBEE_PROFILE_FREESCALE_MAX          0xc02a
#define ZBEE_PROFILE_IPCOM_MIN              0xc02b
#define ZBEE_PROFILE_IPCOM_MAX              0xc034
#define ZBEE_PROFILE_SAN_JUAN_MIN           0xc035
#define ZBEE_PROFILE_SAN_JUAN_MAX           0xc036
#define ZBEE_PROFILE_TUV_MIN                0xc037
#define ZBEE_PROFILE_TUV_MAX                0xc040
#define ZBEE_PROFILE_COMPXS_MIN             0xc041
#define ZBEE_PROFILE_COMPXS_MAX             0xc04a
#define ZBEE_PROFILE_BM_MIN                 0xc04b
#define ZBEE_PROFILE_BM_MAX                 0xc04d
#define ZBEE_PROFILE_AWAREPOINT_MIN         0xc04e
#define ZBEE_PROFILE_AWAREPOINT_MAX         0xc057
#define ZBEE_PROFILE_SAN_JUAN_1_MIN         0xc058
#define ZBEE_PROFILE_SAN_JUAN_1_MAX         0xc05d
#define ZBEE_PROFILE_PHILIPS_MIN            0xc05e
#define ZBEE_PROFILE_PHILIPS_MAX            0xc067
#define ZBEE_PROFILE_LUXOFT_MIN             0xc068
#define ZBEE_PROFILE_LUXOFT_MAX             0xc071
#define ZBEE_PROFILE_KORWIN_MIN             0xc072
#define ZBEE_PROFILE_KORWIN_MAX             0xc07b
#define ZBEE_PROFILE_1_RF_MIN               0xc07c
#define ZBEE_PROFILE_1_RF_MAX               0xc085
#define ZBEE_PROFILE_STG_MIN                0xc086
#define ZBEE_PROFILE_STG_MAX                0xc08f
#define ZBEE_PROFILE_TELEGESIS_MIN          0xc090
#define ZBEE_PROFILE_TELEGESIS_MAX          0xc099
#define ZBEE_PROFILE_CIRRONET_1_MIN         0xc09a
#define ZBEE_PROFILE_CIRRONET_1_MAX         0xc0a0
#define ZBEE_PROFILE_VISIONIC_MIN           0xc0a1
#define ZBEE_PROFILE_VISIONIC_MAX           0xc0aa
#define ZBEE_PROFILE_INSTA_MIN              0xc0ab
#define ZBEE_PROFILE_INSTA_MAX              0xc0b4
#define ZBEE_PROFILE_ATALUM_MIN             0xc0b5
#define ZBEE_PROFILE_ATALUM_MAX             0xc0be
#define ZBEE_PROFILE_ATMEL_MIN              0xc0bf
#define ZBEE_PROFILE_ATMEL_MAX              0xc0c8
#define ZBEE_PROFILE_DEVELCO_MIN            0xc0c9
#define ZBEE_PROFILE_DEVELCO_MAX            0xc0d2
#define ZBEE_PROFILE_HONEYWELL_MIN          0xc0d3
#define ZBEE_PROFILE_HONEYWELL_MAX          0xc0dc
#define ZBEE_PROFILE_NEC_MIN                0xc0dd
#define ZBEE_PROFILE_NEC_MAX                0xc0e6
#define ZBEE_PROFILE_YAMATAKE_MIN           0xc0e7
#define ZBEE_PROFILE_YAMATAKE_MAX           0xc0f0
#define ZBEE_PROFILE_TENDRIL_MIN            0xc0f1
#define ZBEE_PROFILE_TENDRIL_MAX            0xc0fa
#define ZBEE_PROFILE_ASSA_MIN               0xc0fb
#define ZBEE_PROFILE_ASSA_MAX               0xc104
#define ZBEE_PROFILE_MAXSTREAM_MIN          0xc105
#define ZBEE_PROFILE_MAXSTREAM_MAX          0xc10e
#define ZBEE_PROFILE_XANADU_MIN             0xc10f
#define ZBEE_PROFILE_XANADU_MAX             0xc118
#define ZBEE_PROFILE_NEUROCOM_MIN           0xc119
#define ZBEE_PROFILE_NEUROCOM_MAX           0xc122
#define ZBEE_PROFILE_III_MIN                0xc123
#define ZBEE_PROFILE_III_MAX                0xc12c
#define ZBEE_PROFILE_VANTAGE_MIN            0xc12d
#define ZBEE_PROFILE_VANTAGE_MAX            0xc12f
#define ZBEE_PROFILE_ICONTROL_MIN           0xc130
#define ZBEE_PROFILE_ICONTROL_MAX           0xc139
#define ZBEE_PROFILE_RAYMARINE_MIN          0xc13a
#define ZBEE_PROFILE_RAYMARINE_MAX          0xc143
#define ZBEE_PROFILE_RENESAS_MIN            0xc144
#define ZBEE_PROFILE_RENESAS_MAX            0xc14d
#define ZBEE_PROFILE_LSR_MIN                0xc14e
#define ZBEE_PROFILE_LSR_MAX                0xc157
#define ZBEE_PROFILE_ONITY_MIN              0xc158
#define ZBEE_PROFILE_ONITY_MAX              0xc161
#define ZBEE_PROFILE_MONO_MIN               0xc162
#define ZBEE_PROFILE_MONO_MAX               0xc16b
#define ZBEE_PROFILE_RFT_MIN                0xc16c
#define ZBEE_PROFILE_RFT_MAX                0xc175
#define ZBEE_PROFILE_ITRON_MIN              0xc176
#define ZBEE_PROFILE_ITRON_MAX              0xc17f
#define ZBEE_PROFILE_TRITECH_MIN            0xc180
#define ZBEE_PROFILE_TRITECH_MAX            0xc189
#define ZBEE_PROFILE_EMBEDIT_MIN            0xc18a
#define ZBEE_PROFILE_EMBEDIT_MAX            0xc193
#define ZBEE_PROFILE_S3C_MIN                0xc194
#define ZBEE_PROFILE_S3C_MAX                0xc19d
#define ZBEE_PROFILE_SIEMENS_MIN            0xc19e
#define ZBEE_PROFILE_SIEMENS_MAX            0xc1a7
#define ZBEE_PROFILE_MINDTECH_MIN           0xc1a8
#define ZBEE_PROFILE_MINDTECH_MAX           0xc1b1
#define ZBEE_PROFILE_LGE_MIN                0xc1b2
#define ZBEE_PROFILE_LGE_MAX                0xc1bb
#define ZBEE_PROFILE_MITSUBISHI_MIN         0xc1bc
#define ZBEE_PROFILE_MITSUBISHI_MAX         0xc1c5
#define ZBEE_PROFILE_JOHNSON_MIN            0xc1c6
#define ZBEE_PROFILE_JOHNSON_MAX            0xc1cf
#define ZBEE_PROFILE_PRI_MIN                0xc1d0
#define ZBEE_PROFILE_PRI_MAX                0xc1d9
#define ZBEE_PROFILE_KNICK_MIN              0xc1da
#define ZBEE_PROFILE_KNICK_MAX              0xc1e3
#define ZBEE_PROFILE_VICONICS_MIN           0xc1e4
#define ZBEE_PROFILE_VICONICS_MAX           0xc1ed
#define ZBEE_PROFILE_FLEXIPANEL_MIN         0xc1ee
#define ZBEE_PROFILE_FLEXIPANEL_MAX         0xc1f7
#define ZBEE_PROFILE_TRANE_MIN              0xc1f8
#define ZBEE_PROFILE_TRANE_MAX              0xc201
#define ZBEE_PROFILE_JENNIC_MIN             0xc202
#define ZBEE_PROFILE_JENNIC_MAX             0xc20b
#define ZBEE_PROFILE_LIG_MIN                0xc20c
#define ZBEE_PROFILE_LIG_MAX                0xc215
#define ZBEE_PROFILE_ALERTME_MIN            0xc216
#define ZBEE_PROFILE_ALERTME_MAX            0xc21f
#define ZBEE_PROFILE_DAINTREE_MIN           0xc220
#define ZBEE_PROFILE_DAINTREE_MAX           0xc229
#define ZBEE_PROFILE_AIJI_MIN               0xc22a
#define ZBEE_PROFILE_AIJI_MAX               0xc233
#define ZBEE_PROFILE_TEL_ITALIA_MIN         0xc234
#define ZBEE_PROFILE_TEL_ITALIA_MAX         0xc23d
#define ZBEE_PROFILE_MIKROKRETS_MIN         0xc23e
#define ZBEE_PROFILE_MIKROKRETS_MAX         0xc247
#define ZBEE_PROFILE_OKI_MIN                0xc248
#define ZBEE_PROFILE_OKI_MAX                0xc251
#define ZBEE_PROFILE_NEWPORT_MIN            0xc252
#define ZBEE_PROFILE_NEWPORT_MAX            0xc25b

#define ZBEE_PROFILE_C4_CL                  0xc25d
#define ZBEE_PROFILE_C4_MIN                 0xc25c
#define ZBEE_PROFILE_C4_MAX                 0xc265

#define ZBEE_PROFILE_STM_MIN                0xc266
#define ZBEE_PROFILE_STM_MAX                0xc26f
#define ZBEE_PROFILE_ASN_MIN                0xc270
#define ZBEE_PROFILE_ASN_MAX                0xc270
#define ZBEE_PROFILE_DCSI_MIN               0xc271
#define ZBEE_PROFILE_DCSI_MAX               0xc27a
#define ZBEE_PROFILE_FRANCE_TEL_MIN         0xc27b
#define ZBEE_PROFILE_FRANCE_TEL_MAX         0xc284
#define ZBEE_PROFILE_MUNET_MIN              0xc285
#define ZBEE_PROFILE_MUNET_MAX              0xc28e
#define ZBEE_PROFILE_AUTANI_MIN             0xc28f
#define ZBEE_PROFILE_AUTANI_MAX             0xc298
#define ZBEE_PROFILE_COL_VNET_MIN           0xc299
#define ZBEE_PROFILE_COL_VNET_MAX           0xc2a2
#define ZBEE_PROFILE_AEROCOMM_MIN           0xc2a3
#define ZBEE_PROFILE_AEROCOMM_MAX           0xc2ac
#define ZBEE_PROFILE_SI_LABS_MIN            0xc2ad
#define ZBEE_PROFILE_SI_LABS_MAX            0xc2b6
#define ZBEE_PROFILE_INNCOM_MIN             0xc2b7
#define ZBEE_PROFILE_INNCOM_MAX             0xc2c0
#define ZBEE_PROFILE_CANNON_MIN             0xc2c1
#define ZBEE_PROFILE_CANNON_MAX             0xc2ca
#define ZBEE_PROFILE_SYNAPSE_MIN            0xc2cb
#define ZBEE_PROFILE_SYNAPSE_MAX            0xc2d4
#define ZBEE_PROFILE_FPS_MIN                0xc2d5
#define ZBEE_PROFILE_FPS_MAX                0xc2de
#define ZBEE_PROFILE_CLS_MIN                0xc2df
#define ZBEE_PROFILE_CLS_MAX                0xc2e8
#define ZBEE_PROFILE_CRANE_MIN              0xc2e9
#define ZBEE_PROFILE_CRANE_MAX              0xc2f2
#define ZBEE_PROFILE_ASN_1_MIN              0xc2f3
#define ZBEE_PROFILE_ASN_1_MAX              0xc2fb
#define ZBEE_PROFILE_MOBILARM_MIN           0xc2fc
#define ZBEE_PROFILE_MOBILARM_MAX           0xc305
#define ZBEE_PROFILE_IMONITOR_MIN           0xc306
#define ZBEE_PROFILE_IMONITOR_MAX           0xc30f
#define ZBEE_PROFILE_BARTECH_MIN            0xc310
#define ZBEE_PROFILE_BARTECH_MAX            0xc319
#define ZBEE_PROFILE_MESHNETICS_MIN         0xc31a
#define ZBEE_PROFILE_MESHNETICS_MAX         0xc323
#define ZBEE_PROFILE_LS_IND_MIN             0xc324
#define ZBEE_PROFILE_LS_IND_MAX             0xc32d
#define ZBEE_PROFILE_CASON_MIN              0xc32e
#define ZBEE_PROFILE_CASON_MAX              0xc337
#define ZBEE_PROFILE_WLESS_GLUE_MIN         0xc338
#define ZBEE_PROFILE_WLESS_GLUE_MAX         0xc341
#define ZBEE_PROFILE_ELSTER_MIN             0xc342
#define ZBEE_PROFILE_ELSTER_MAX             0xc34b
#define ZBEE_PROFILE_ONSET_MIN              0xc34c
#define ZBEE_PROFILE_ONSET_MAX              0xc355
#define ZBEE_PROFILE_RIGA_MIN               0xc356
#define ZBEE_PROFILE_RIGA_MAX               0xc35f
#define ZBEE_PROFILE_ENERGATE_MIN           0xc360
#define ZBEE_PROFILE_ENERGATE_MAX           0xc369
#define ZBEE_PROFILE_VANTAGE_1_MIN          0xc36a
#define ZBEE_PROFILE_VANTAGE_1_MAX          0xc370
#define ZBEE_PROFILE_CONMED_MIN             0xc371
#define ZBEE_PROFILE_CONMED_MAX             0xc37a
#define ZBEE_PROFILE_SMS_TEC_MIN            0xc37b
#define ZBEE_PROFILE_SMS_TEC_MAX            0xc384
#define ZBEE_PROFILE_POWERMAND_MIN          0xc385
#define ZBEE_PROFILE_POWERMAND_MAX          0xc38e
#define ZBEE_PROFILE_SCHNEIDER_MIN          0xc38f
#define ZBEE_PROFILE_SCHNEIDER_MAX          0xc398
#define ZBEE_PROFILE_EATON_MIN              0xc399
#define ZBEE_PROFILE_EATON_MAX              0xc3a2
#define ZBEE_PROFILE_TELULAR_MIN            0xc3a3
#define ZBEE_PROFILE_TELULAR_MAX            0xc3ac
#define ZBEE_PROFILE_DELPHI_MIN             0xc3ad
#define ZBEE_PROFILE_DELPHI_MAX             0xc3b6
#define ZBEE_PROFILE_EPISENSOR_MIN          0xc3b7
#define ZBEE_PROFILE_EPISENSOR_MAX          0xc3c0
#define ZBEE_PROFILE_LANDIS_GYR_MIN         0xc3c1
#define ZBEE_PROFILE_LANDIS_GYR_MAX         0xc3ca
#define ZBEE_PROFILE_SHURE_MIN              0xc3cb
#define ZBEE_PROFILE_SHURE_MAX              0xc3d4
#define ZBEE_PROFILE_COMVERGE_MIN           0xc3d5
#define ZBEE_PROFILE_COMVERGE_MAX           0xc3df
#define ZBEE_PROFILE_KABA_MIN               0xc3e0
#define ZBEE_PROFILE_KABA_MAX               0xc3e9
#define ZBEE_PROFILE_HIDALGO_MIN            0xc3ea
#define ZBEE_PROFILE_HIDALGO_MAX            0xc3f3
#define ZBEE_PROFILE_AIR2APP_MIN            0xc3f4
#define ZBEE_PROFILE_AIR2APP_MAX            0xc3fd
#define ZBEE_PROFILE_AMX_MIN                0xc3fe
#define ZBEE_PROFILE_AMX_MAX                0xc407
#define ZBEE_PROFILE_EDMI_MIN               0xc408
#define ZBEE_PROFILE_EDMI_MAX               0xc411
#define ZBEE_PROFILE_CYAN_MIN               0xc412
#define ZBEE_PROFILE_CYAN_MAX               0xc41b
#define ZBEE_PROFILE_SYS_SPA_MIN            0xc41c
#define ZBEE_PROFILE_SYS_SPA_MAX            0xc425
#define ZBEE_PROFILE_TELIT_MIN              0xc426
#define ZBEE_PROFILE_TELIT_MAX              0xc42f
#define ZBEE_PROFILE_KAGA_MIN               0xc430
#define ZBEE_PROFILE_KAGA_MAX               0xc439
#define ZBEE_PROFILE_4_NOKS_MIN             0xc43a
#define ZBEE_PROFILE_4_NOKS_MAX             0xc443

/* Unallocated Manufacturer IDs */
#define ZBEE_PROFILE_UNALLOCATED_MIN        0xc000
#define ZBEE_PROFILE_UNALLOCATED_MAX        0xffff


/* Frame Control Field */
#define ZBEE_ZCL_FCF_FRAME_TYPE             0x03
#define ZBEE_ZCL_FCF_MFR_SPEC               0x04
#define ZBEE_ZCL_FCF_DIRECTION              0x08
#define ZBEE_ZCL_FCF_DISABLE_DEFAULT_RESP   0x10

#define ZBEE_ZCL_FCF_PROFILE_WIDE           0x00
#define ZBEE_ZCL_FCF_CLUSTER_SPEC           0x01

/* Manufacturer Codes */
#define ZBEE_MFG_CODE_CIRRONET          0x1000
#define ZBEE_MFG_CODE_CHIPCON           0x1001
#define ZBEE_MFG_CODE_EMBER             0x1002
#define ZBEE_MFG_CODE_NTS               0x1003
#define ZBEE_MFG_CODE_FREESCALE         0x1004
#define ZBEE_MFG_CODE_IPCOM             0x1005
#define ZBEE_MFG_CODE_SAN_JUAN          0x1006
#define ZBEE_MFG_CODE_TUV               0x1007
#define ZBEE_MFG_CODE_COMPXS            0x1008
#define ZBEE_MFG_CODE_BM                0x1009
#define ZBEE_MFG_CODE_AWAREPOINT        0x100a
#define ZBEE_MFG_CODE_PHILIPS           0x100b
#define ZBEE_MFG_CODE_LUXOFT            0x100c
#define ZBEE_MFG_CODE_KORWIN            0x100d
#define ZBEE_MFG_CODE_1_RF              0x100e
#define ZBEE_MFG_CODE_STG               0x101f

#define ZBEE_MFG_CODE_TELEGESIS         0x1010
#define ZBEE_MFG_CODE_VISIONIC          0x1011
#define ZBEE_MFG_CODE_INSTA             0x1012
#define ZBEE_MFG_CODE_ATALUM            0x1013
#define ZBEE_MFG_CODE_ATMEL             0x1014
#define ZBEE_MFG_CODE_DEVELCO           0x1015
#define ZBEE_MFG_CODE_HONEYWELL         0x1016
/**/
#define ZBEE_MFG_CODE_RENESAS           0x1018
#define ZBEE_MFG_CODE_XANADU            0x1019
#define ZBEE_MFG_CODE_NEC               0x101a
#define ZBEE_MFG_CODE_YAMATAKE          0x101b
#define ZBEE_MFG_CODE_TENDRIL           0x101c
#define ZBEE_MFG_CODE_ASSA              0x101d
#define ZBEE_MFG_CODE_MAXSTREAM         0x101e
#define ZBEE_MFG_CODE_NEUROCOM          0x101f

#define ZBEE_MFG_CODE_III               0x1020
#define ZBEE_MFG_CODE_VANTAGE           0x1021
#define ZBEE_MFG_CODE_ICONTROL          0x1022
#define ZBEE_MFG_CODE_RAYMARINE         0x1023
#define ZBEE_MFG_CODE_LSR               0x1024
#define ZBEE_MFG_CODE_ONITY             0x1025
#define ZBEE_MFG_CODE_MONO              0x1026
#define ZBEE_MFG_CODE_RFT               0x1027
#define ZBEE_MFG_CODE_ITRON             0x1028
#define ZBEE_MFG_CODE_TRITECH           0x1029
#define ZBEE_MFG_CODE_EMBEDIT           0x102a
#define ZBEE_MFG_CODE_S3C               0x102b
#define ZBEE_MFG_CODE_SIEMENS           0x102c
#define ZBEE_MFG_CODE_MINDTECH          0x102d
#define ZBEE_MFG_CODE_LGE               0x102e
#define ZBEE_MFG_CODE_MITSUBISHI        0x102f

#define ZBEE_MFG_CODE_JOHNSON           0x1030
#define ZBEE_MFG_CODE_PRI               0x1031
#define ZBEE_MFG_CODE_KNICK             0x1032
#define ZBEE_MFG_CODE_VICONICS          0x1033
#define ZBEE_MFG_CODE_FLEXIPANEL        0x1034
/**/
#define ZBEE_MFG_CODE_TRANE             0x1036
#define ZBEE_MFG_CODE_JENNIC            0x1037
#define ZBEE_MFG_CODE_LIG               0x1038
#define ZBEE_MFG_CODE_ALERTME           0x1039
#define ZBEE_MFG_CODE_DAINTREE          0x103a
#define ZBEE_MFG_CODE_AIJI              0x103b
#define ZBEE_MFG_CODE_TEL_ITALIA        0x103c
#define ZBEE_MFG_CODE_MIKROKRETS        0x103d
#define ZBEE_MFG_CODE_OKI               0x103e
#define ZBEE_MFG_CODE_NEWPORT           0x103f

#define ZBEE_MFG_CODE_C4                0x1040
#define ZBEE_MFG_CODE_STM               0x1041
#define ZBEE_MFG_CODE_ASN               0x1042
#define ZBEE_MFG_CODE_DCSI              0x1043
#define ZBEE_MFG_CODE_FRANCE_TEL        0x1044
#define ZBEE_MFG_CODE_MUNET             0x1045
#define ZBEE_MFG_CODE_AUTANI            0x1046
#define ZBEE_MFG_CODE_COL_VNET          0x1047
#define ZBEE_MFG_CODE_AEROCOMM          0x1048
#define ZBEE_MFG_CODE_SI_LABS           0x1049
#define ZBEE_MFG_CODE_INNCOM            0x104a
#define ZBEE_MFG_CODE_CANNON            0x104b
#define ZBEE_MFG_CODE_SYNAPSE           0x104c
#define ZBEE_MFG_CODE_FPS               0x104d
#define ZBEE_MFG_CODE_CLS               0x104e
#define ZBEE_MFG_CODE_CRANE             0x104F

#define ZBEE_MFG_CODE_MOBILARM          0x1050
#define ZBEE_MFG_CODE_IMONITOR          0x1051
#define ZBEE_MFG_CODE_BARTECH           0x1052
#define ZBEE_MFG_CODE_MESHNETICS        0x1053
#define ZBEE_MFG_CODE_LS_IND            0x1054
#define ZBEE_MFG_CODE_CASON             0x1055
#define ZBEE_MFG_CODE_WLESS_GLUE        0x1056
#define ZBEE_MFG_CODE_ELSTER            0x1057
#define ZBEE_MFG_CODE_SMS_TEC           0x1058
#define ZBEE_MFG_CODE_ONSET             0x1059
#define ZBEE_MFG_CODE_RIGA              0x105a
#define ZBEE_MFG_CODE_ENERGATE          0x105b
#define ZBEE_MFG_CODE_CONMED            0x105c
#define ZBEE_MFG_CODE_POWERMAND         0x105d
#define ZBEE_MFG_CODE_SCHNEIDER         0x105e
#define ZBEE_MFG_CODE_EATON             0x105f

#define ZBEE_MFG_CODE_TELULAR           0x1060
#define ZBEE_MFG_CODE_DELPHI            0x1061
#define ZBEE_MFG_CODE_EPISENSOR         0x1062
#define ZBEE_MFG_CODE_LANDIS_GYR        0x1063
#define ZBEE_MFG_CODE_KABA              0x1064
#define ZBEE_MFG_CODE_SHURE             0x1065
#define ZBEE_MFG_CODE_COMVERGE          0x1066
/**/
#define ZBEE_MFG_CODE_HIDALGO           0x1069
#define ZBEE_MFG_CODE_AIR2APP           0x106a
#define ZBEE_MFG_CODE_AMX               0x106b
#define ZBEE_MFG_CODE_EDMI              0x106c
#define ZBEE_MFG_CODE_CYAN              0x106d
#define ZBEE_MFG_CODE_SYS_SPA           0x106e
#define ZBEE_MFG_CODE_TELIT             0x106f

#define ZBEE_MFG_CODE_KAGA              0x1070
#define ZBEE_MFG_CODE_4_NOKS            0x1071

/* Manufacturer Names */
#define ZBEE_MFG_CIRRONET       "Cirronet"
#define ZBEE_MFG_CHIPCON        "Chipcon"
#define ZBEE_MFG_EMBER          "Ember"
#define ZBEE_MFG_NTS            "National Tech"
#define ZBEE_MFG_FREESCALE      "Freescale"
#define ZBEE_MFG_IPCOM          "IPCom"
#define ZBEE_MFG_SAN_JUAN       "San Juan Software"
#define ZBEE_MFG_TUV            "TUV"
#define ZBEE_MFG_COMPXS         "CompXs"
#define ZBEE_MFG_BM             "BM SpA"
#define ZBEE_MFG_AWAREPOINT     "AwarePoint"
#define ZBEE_MFG_PHILIPS        "Philips"
#define ZBEE_MFG_LUXOFT         "Luxoft"
#define ZBEE_MFG_KORWIN         "Korvin"
#define ZBEE_MFG_1_RF           "One RF"
#define ZBEE_MFG_STG            "Software Technology Group"

#define ZBEE_MFG_TELEGESIS      "Telegesis"
#define ZBEE_MFG_VISIONIC       "Visionic"
#define ZBEE_MFG_INSTA          "Insta"
#define ZBEE_MFG_ATALUM         "Atalum"
#define ZBEE_MFG_ATMEL          "Atmel"
#define ZBEE_MFG_DEVELCO        "Develco"
#define ZBEE_MFG_HONEYWELL      "Honeywell"
/**/
#define ZBEE_MFG_RENESAS        "NEC Engineering"
#define ZBEE_MFG_XANADU         "Yamatake"
#define ZBEE_MFG_NEC            "Tendril"
#define ZBEE_MFG_YAMATAKE       "Assa Abloy"
#define ZBEE_MFG_TENDRIL        "MaxStream"
#define ZBEE_MFG_ASSA           "Xanadu Wireless"
#define ZBEE_MFG_MAXSTREAM      "Neurocom"
#define ZBEE_MFG_NEUROCOM       "Institute for Information Industry"

#define ZBEE_MFG_III            "Vantage Controls"
#define ZBEE_MFG_VANTAGE        "iControl"
#define ZBEE_MFG_ICONTROL       "Raymarine"
#define ZBEE_MFG_RAYMARINE      "Renesas"
#define ZBEE_MFG_LSR            "LS Research"
#define ZBEE_MFG_ONITY          "Onity"
#define ZBEE_MFG_MONO           "Mono Products"
#define ZBEE_MFG_RFT            "RF Tech"
#define ZBEE_MFG_ITRON          "Itron"
#define ZBEE_MFG_TRITECH        "Tritech"
#define ZBEE_MFG_EMBEDIT        "Embedit"
#define ZBEE_MFG_S3C            "S3C"
#define ZBEE_MFG_SIEMENS        "Siemens"
#define ZBEE_MFG_MINDTECH       "Mindtech"
#define ZBEE_MFG_LGE            "LG Electronics"
#define ZBEE_MFG_MITSUBISHI     "Mitsubishi"

#define ZBEE_MFG_JOHNSON        "Johnson Controls"
#define ZBEE_MFG_PRI            "PRI"
#define ZBEE_MFG_KNICK          "Knick"
#define ZBEE_MFG_VICONICS       "Viconics"
#define ZBEE_MFG_FLEXIPANEL     "Flexipanel"
/**/
#define ZBEE_MFG_TRANE          "Trane"
#define ZBEE_MFG_JENNIC         "Jennic"
#define ZBEE_MFG_LIG            "Living Independently"
#define ZBEE_MFG_ALERTME        "AlertMe"
#define ZBEE_MFG_DAINTREE       "Daintree"
#define ZBEE_MFG_AIJI           "Aiji"
#define ZBEE_MFG_TEL_ITALIA     "Telecom Italia"
#define ZBEE_MFG_MIKROKRETS     "Mikrokrets"
#define ZBEE_MFG_OKI            "Oki Semi"
#define ZBEE_MFG_NEWPORT        "Newport Electronics"

#define ZBEE_MFG_C4             "Control4"
#define ZBEE_MFG_STM            "STMicro"
#define ZBEE_MFG_ASN            "Ad-Sol Nissin"
#define ZBEE_MFG_DCSI           "DCSI"
#define ZBEE_MFG_FRANCE_TEL     "France Telecom"
#define ZBEE_MFG_MUNET          "muNet"
#define ZBEE_MFG_AUTANI         "Autani"
#define ZBEE_MFG_COL_VNET       "Colorado vNet"
#define ZBEE_MFG_AEROCOMM       "Aerocomm"
#define ZBEE_MFG_SI_LABS        "Silicon Labs"
#define ZBEE_MFG_INNCOM         "Inncom"
#define ZBEE_MFG_CANNON         "Cannon"
#define ZBEE_MFG_SYNAPSE        "Synapse"
#define ZBEE_MFG_FPS            "Fisher Pierce/Sunrise"
#define ZBEE_MFG_CLS            "CentraLite"
#define ZBEE_MFG_CRANE          "Crane"

#define ZBEE_MFG_MOBILARM       "Mobilarm"
#define ZBEE_MFG_IMONITOR       "iMonitor"
#define ZBEE_MFG_BARTECH        "Bartech"
#define ZBEE_MFG_MESHNETICS     "Meshnetics"
#define ZBEE_MFG_LS_IND         "LS Industrial"
#define ZBEE_MFG_CASON          "Cason"
#define ZBEE_MFG_WLESS_GLUE     "Wireless Glue"
#define ZBEE_MFG_ELSTER         "Elster"
#define ZBEE_MFG_SMS_TEC        "SMS Tec"
#define ZBEE_MFG_ONSET          "Onset Computer"
#define ZBEE_MFG_RIGA           "Riga Development"
#define ZBEE_MFG_ENERGATE       "Energate"
#define ZBEE_MFG_CONMED         "ConMed Linvatec"
#define ZBEE_MFG_POWERMAND      "PowerMand"
#define ZBEE_MFG_SCHNEIDER      "Schneider Electric"
#define ZBEE_MFG_EATON          "Eaton"

#define ZBEE_MFG_TELULAR        "Telular"
#define ZBEE_MFG_DELPHI         "Delphi Medical"
#define ZBEE_MFG_EPISENSOR      "EpiSensor"
#define ZBEE_MFG_LANDIS_GYR     "Landis+Gyr"
#define ZBEE_MFG_KABA           "Kaba Group"
#define ZBEE_MFG_SHURE          "Shure"
#define ZBEE_MFG_COMVERGE       "Comverge"
/**/
#define ZBEE_MFG_HIDALGO        "Hidalgo"
#define ZBEE_MFG_AIR2APP        "Air2App"
#define ZBEE_MFG_AMX            "AMX"
#define ZBEE_MFG_EDMI           "EDMI"
#define ZBEE_MFG_CYAN           "Cyan Ltd."
#define ZBEE_MFG_SYS_SPA        "System SPA"
#define ZBEE_MFG_TELIT          "Telit"

#define ZBEE_MFG_KAGA           "Kaga Electronics"
#define ZBEE_MFG_4_NOKS         "4-noks s.r.l."

/* Helper Functions */
extern proto_item *proto_tree_add_eui64(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
                gint length, gint64 value);
extern guint zbee_get_bit_field(guint input, guint mask);

#endif /* PACKET_ZBEE_H */

