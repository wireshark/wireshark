/* packet-zbee.h
 * Dissector routines for the ZigBee protocol stack.
 * By Owen Kirby <osk@exegin.com>
 * Copyright 2009 Exegin Technologies Limited
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef PACKET_ZBEE_H
#define PACKET_ZBEE_H

/* IEEE 802.15.4 definitions. */
#include "packet-ieee802154.h"

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
#define ZBEE_VERSION_GREEN_POWER    3 /* ZigBee Green Power */

/* ZigBee version macro. */
#define ZBEE_HAS_2003(x)            ((x) >= ZBEE_VERSION_2003)
#define ZBEE_HAS_2006(x)            ((x) >= ZBEE_VERSION_2007)
#define ZBEE_HAS_2007(x)            ((x) >= ZBEE_VERSION_2007)

/* ZigBee Application Profile IDs */
/* Per: 053298r19, December 2011 */
#define ZBEE_DEVICE_PROFILE                 0x0000

#define ZBEE_PROFILE_IPM                    0x0101

#define ZBEE_PROFILE_T1                     0x0103
#define ZBEE_PROFILE_HA                     0x0104
#define ZBEE_PROFILE_CBA                    0x0105
#define ZBEE_PROFILE_WSN                    0x0106
#define ZBEE_PROFILE_TA                     0x0107
#define ZBEE_PROFILE_HC                     0x0108
#define ZBEE_PROFILE_SE                     0x0109
#define ZBEE_PROFILE_RS                     0x010a

#define ZBEE_PROFILE_STD_MIN                0x0000
#define ZBEE_PROFILE_STD_MAX                0x7eff

/* ZigBee Reserved */
#define ZBEE_PROFILE_T2                     0x7f01

/* Application Profile ID Ranges */
#define ZBEE_PROFILE_RSVD0_MIN              0x7f00
#define ZBEE_PROFILE_RSVD0_MAX              0x7fff

#define ZBEE_PROFILE_RSVD1_MIN              0x8000
#define ZBEE_PROFILE_RSVD1_MAX              0xbeff

#define ZBEE_PROFILE_GP                     0xa1e0

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
#define ZBEE_PROFILE_ZLL                    0xc05e
#define ZBEE_PROFILE_PHILIPS_MIN            0xc05f
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
#define ZBEE_PROFILE_ASN_0_MIN              0xc270
#define ZBEE_PROFILE_ASN_0_MAX              0xc270
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
#define ZBEE_PROFILE_PROFILE_SYS_MIN        0xc444
#define ZBEE_PROFILE_PROFILE_SYS_MAX        0xc44d
#define ZBEE_PROFILE_FREESTYLE_MIN          0xc44e
#define ZBEE_PROFILE_FREESTYLE_MAX          0xc457
#define ZBEE_PROFILE_REMOTE_MIN             0xc458
#define ZBEE_PROFILE_REMOTE_MAX             0xc461
#define ZBEE_PROFILE_TRANE_RES_MIN          0xc462
#define ZBEE_PROFILE_TRANE_RES_MAX          0xc46b
#define ZBEE_PROFILE_WAVECOM_MIN            0xc46c
#define ZBEE_PROFILE_WAVECOM_MAX            0xc475
#define ZBEE_PROFILE_GE_MIN                 0xc476
#define ZBEE_PROFILE_GE_MAX                 0xc47f
#define ZBEE_PROFILE_MESHWORKS_MIN          0xc480
#define ZBEE_PROFILE_MESHWORKS_MAX          0xc489
#define ZBEE_PROFILE_ENERGY_OPT_MIN         0xc48a
#define ZBEE_PROFILE_ENERGY_OPT_MAX         0xc493
#define ZBEE_PROFILE_ELLIPS_MIN             0xc494
#define ZBEE_PROFILE_ELLIPS_MAX             0xc49d
#define ZBEE_PROFILE_CEDO_MIN               0xc49e
#define ZBEE_PROFILE_CEDO_MAX               0xc4a7
#define ZBEE_PROFILE_A_D_MIN                0xc4a8
#define ZBEE_PROFILE_A_D_MAX                0xc4b1
#define ZBEE_PROFILE_CARRIER_MIN            0xc4b2
#define ZBEE_PROFILE_CARRIER_MAX            0xc4bb
#define ZBEE_PROFILE_PASSIVESYS_MIN         0xc4bc
#define ZBEE_PROFILE_PASSIVESYS_MAX         0xc4bd
#define ZBEE_PROFILE_G4S_JUSTICE_MIN        0xc4be
#define ZBEE_PROFILE_G4S_JUSTICE_MAX        0xc4bf
#define ZBEE_PROFILE_SYCHIP_MIN             0xc4c0
#define ZBEE_PROFILE_SYCHIP_MAX             0xc4c1
#define ZBEE_PROFILE_MMB_MIN                0xc4c2
#define ZBEE_PROFILE_MMB_MAX                0xc4c3
#define ZBEE_PROFILE_SUNRISE_MIN            0xc4c4
#define ZBEE_PROFILE_SUNRISE_MAX            0xc4c5
#define ZBEE_PROFILE_MEMTEC_MIN             0xc4c6
#define ZBEE_PROFILE_MEMTEC_MAX             0xc4c7
#define ZBEE_PROFILE_HOME_AUTO_MIN          0xc4c8
#define ZBEE_PROFILE_HOME_AUTO_MAX          0xc4c9
#define ZBEE_PROFILE_BRITISH_GAS_MIN        0xc4ca
#define ZBEE_PROFILE_BRITISH_GAS_MAX        0xc4cb
#define ZBEE_PROFILE_SENTEC_MIN             0xc4cc
#define ZBEE_PROFILE_SENTEC_MAX             0xc4cd
#define ZBEE_PROFILE_NAVETAS_MIN            0xc4ce
#define ZBEE_PROFILE_NAVETAS_MAX            0xc4cf
#define ZBEE_PROFILE_ENERNOC_MIN            0xc4d0
#define ZBEE_PROFILE_ENERNOC_MAX            0xc4d1
#define ZBEE_PROFILE_ELTAV_MIN              0xc4d2
#define ZBEE_PROFILE_ELTAV_MAX              0xc4d3
#define ZBEE_PROFILE_XSTREAMHD_MIN          0xc4d4
#define ZBEE_PROFILE_XSTREAMHD_MAX          0xc4d5
#define ZBEE_PROFILE_GREEN_MIN              0xc4d6
#define ZBEE_PROFILE_GREEN_MAX              0xc4d7
#define ZBEE_PROFILE_OMRON_MIN              0xc4d8
#define ZBEE_PROFILE_OMRON_MAX              0xc4d9
/**/
#define ZBEE_PROFILE_NEC_TOKIN_MIN          0xc4e0
#define ZBEE_PROFILE_NEC_TOKIN_MAX          0xc4e1
#define ZBEE_PROFILE_PEEL_MIN               0xc4e2
#define ZBEE_PROFILE_PEEL_MAX               0xc4e3
#define ZBEE_PROFILE_ELECTROLUX_MIN         0xc4e4
#define ZBEE_PROFILE_ELECTROLUX_MAX         0xc4e5
#define ZBEE_PROFILE_SAMSUNG_MIN            0xc4e6
#define ZBEE_PROFILE_SAMSUNG_MAX            0xc4e7
#define ZBEE_PROFILE_MAINSTREAM_MIN         0xc4e8
#define ZBEE_PROFILE_MAINSTREAM_MAX         0xc4e9

#define ZBEE_PROFILE_DIGI_MIN               0xc4f0
#define ZBEE_PROFILE_DIGI_MAX               0xc4f1
#define ZBEE_PROFILE_RADIOCRAFTS_MIN        0xc4f2
#define ZBEE_PROFILE_RADIOCRAFTS_MAX        0xc4f3
#define ZBEE_PROFILE_SCHNEIDER2_MIN         0xc4f4
#define ZBEE_PROFILE_SCHNEIDER2_MAX         0xc4f5
#define ZBEE_PROFILE_HUAWEI_MIN             0xc4f6
#define ZBEE_PROFILE_HUAWEI_MAX             0xc4ff
#define ZBEE_PROFILE_BGLOBAL_MIN            0xc500
#define ZBEE_PROFILE_BGLOBAL_MAX            0xc505
#define ZBEE_PROFILE_ABB_MIN                0xc506
#define ZBEE_PROFILE_ABB_MAX                0xc507
#define ZBEE_PROFILE_GENUS_MIN              0xc508
#define ZBEE_PROFILE_GENUS_MAX              0xc509
#define ZBEE_PROFILE_UBISYS_MIN             0xc50a
#define ZBEE_PROFILE_UBISYS_MAX             0xc50b
#define ZBEE_PROFILE_CRESTRON_MIN           0xc50c
#define ZBEE_PROFILE_CRESTRON_MAX           0xc50d
#define ZBEE_PROFILE_AAC_TECH_MIN           0xc50e
#define ZBEE_PROFILE_AAC_TECH_MAX           0xc50f
#define ZBEE_PROFILE_STEELCASE_MIN          0xc510
#define ZBEE_PROFILE_STEELCASE_MAX          0xc511

/* Unallocated Manufacturer IDs */
#define ZBEE_PROFILE_UNALLOCATED_MIN        0xc000
#define ZBEE_PROFILE_UNALLOCATED_MAX        0xffff


/* Frame Control Field */
#define ZBEE_ZCL_FCF_FRAME_TYPE               0x03
#define ZBEE_ZCL_FCF_MFR_SPEC                 0x04
#define ZBEE_ZCL_FCF_DIRECTION                0x08
#define ZBEE_ZCL_FCF_DISABLE_DEFAULT_RESP     0x10

#define ZBEE_ZCL_FCF_PROFILE_WIDE             0x00
#define ZBEE_ZCL_FCF_CLUSTER_SPEC             0x01

#define ZBEE_ZCL_FCF_TO_SERVER                0x00
#define ZBEE_ZCL_FCF_TO_CLIENT                0x01

/* Manufacturer Codes */
/* Codes less than 0x1000 were issued for RF4CE */
#define ZBEE_MFG_CODE_PANASONIC_RF4CE       0x0001
#define ZBEE_MFG_CODE_SONY_RF4CE            0x0002
#define ZBEE_MFG_CODE_SAMSUNG_RF4CE         0x0003
#define ZBEE_MFG_CODE_PHILIPS_RF4CE         0x0004
#define ZBEE_MFG_CODE_FREESCALE_RF4CE       0x0005
#define ZBEE_MFG_CODE_OKI_SEMI_RF4CE        0x0006
#define ZBEE_MFG_CODE_TI_RF4CE              0x0007

/* Manufacturer Codes for non RF4CE devices */
#define ZBEE_MFG_CODE_CIRRONET              0x1000
#define ZBEE_MFG_CODE_CHIPCON               0x1001
#define ZBEE_MFG_CODE_EMBER                 0x1002
#define ZBEE_MFG_CODE_NTS                   0x1003
#define ZBEE_MFG_CODE_FREESCALE             0x1004
#define ZBEE_MFG_CODE_IPCOM                 0x1005
#define ZBEE_MFG_CODE_SAN_JUAN              0x1006
#define ZBEE_MFG_CODE_TUV                   0x1007
#define ZBEE_MFG_CODE_COMPXS                0x1008
#define ZBEE_MFG_CODE_BM                    0x1009
#define ZBEE_MFG_CODE_AWAREPOINT            0x100a
#define ZBEE_MFG_CODE_PHILIPS               0x100b
#define ZBEE_MFG_CODE_LUXOFT                0x100c
#define ZBEE_MFG_CODE_KORWIN                0x100d
#define ZBEE_MFG_CODE_1_RF                  0x100e
#define ZBEE_MFG_CODE_STG                   0x100f

#define ZBEE_MFG_CODE_TELEGESIS             0x1010
#define ZBEE_MFG_CODE_VISIONIC              0x1011
#define ZBEE_MFG_CODE_INSTA                 0x1012
#define ZBEE_MFG_CODE_ATALUM                0x1013
#define ZBEE_MFG_CODE_ATMEL                 0x1014
#define ZBEE_MFG_CODE_DEVELCO               0x1015
#define ZBEE_MFG_CODE_HONEYWELL1            0x1016
#define ZBEE_MFG_CODE_RADIO_PULSE           0x1017
#define ZBEE_MFG_CODE_RENESAS               0x1018
#define ZBEE_MFG_CODE_XANADU                0x1019
#define ZBEE_MFG_CODE_NEC                   0x101a
#define ZBEE_MFG_CODE_YAMATAKE              0x101b
#define ZBEE_MFG_CODE_TENDRIL               0x101c
#define ZBEE_MFG_CODE_ASSA                  0x101d
#define ZBEE_MFG_CODE_MAXSTREAM             0x101e
#define ZBEE_MFG_CODE_NEUROCOM              0x101f

#define ZBEE_MFG_CODE_III                   0x1020
#define ZBEE_MFG_CODE_VANTAGE               0x1021
#define ZBEE_MFG_CODE_ICONTROL              0x1022
#define ZBEE_MFG_CODE_RAYMARINE             0x1023
#define ZBEE_MFG_CODE_LSR                   0x1024
#define ZBEE_MFG_CODE_ONITY                 0x1025
#define ZBEE_MFG_CODE_MONO                  0x1026
#define ZBEE_MFG_CODE_RFT                   0x1027
#define ZBEE_MFG_CODE_ITRON                 0x1028
#define ZBEE_MFG_CODE_TRITECH               0x1029
#define ZBEE_MFG_CODE_EMBEDIT               0x102a
#define ZBEE_MFG_CODE_S3C                   0x102b
#define ZBEE_MFG_CODE_SIEMENS               0x102c
#define ZBEE_MFG_CODE_MINDTECH              0x102d
#define ZBEE_MFG_CODE_LGE                   0x102e
#define ZBEE_MFG_CODE_MITSUBISHI            0x102f

#define ZBEE_MFG_CODE_JOHNSON               0x1030
#define ZBEE_MFG_CODE_PRI                   0x1031
#define ZBEE_MFG_CODE_KNICK                 0x1032
#define ZBEE_MFG_CODE_VICONICS              0x1033
#define ZBEE_MFG_CODE_FLEXIPANEL            0x1034
#define ZBEE_MFG_CODE_PIASIM                0x1035
#define ZBEE_MFG_CODE_TRANE                 0x1036
#define ZBEE_MFG_CODE_JENNIC                0x1037
#define ZBEE_MFG_CODE_LIG                   0x1038
#define ZBEE_MFG_CODE_ALERTME               0x1039
#define ZBEE_MFG_CODE_DAINTREE              0x103a
#define ZBEE_MFG_CODE_AIJI                  0x103b
#define ZBEE_MFG_CODE_TEL_ITALIA            0x103c
#define ZBEE_MFG_CODE_MIKROKRETS            0x103d
#define ZBEE_MFG_CODE_OKI_SEMI              0x103e
#define ZBEE_MFG_CODE_NEWPORT               0x103f

#define ZBEE_MFG_CODE_C4                    0x1040
#define ZBEE_MFG_CODE_STM                   0x1041
#define ZBEE_MFG_CODE_ASN                   0x1042
#define ZBEE_MFG_CODE_DCSI                  0x1043
#define ZBEE_MFG_CODE_FRANCE_TEL            0x1044
#define ZBEE_MFG_CODE_MUNET                 0x1045
#define ZBEE_MFG_CODE_AUTANI                0x1046
#define ZBEE_MFG_CODE_COL_VNET              0x1047
#define ZBEE_MFG_CODE_AEROCOMM              0x1048
#define ZBEE_MFG_CODE_SI_LABS               0x1049
#define ZBEE_MFG_CODE_INNCOM                0x104a
#define ZBEE_MFG_CODE_CANNON                0x104b
#define ZBEE_MFG_CODE_SYNAPSE               0x104c
#define ZBEE_MFG_CODE_FPS                   0x104d
#define ZBEE_MFG_CODE_CLS                   0x104e
#define ZBEE_MFG_CODE_CRANE                 0x104F

#define ZBEE_MFG_CODE_MOBILARM              0x1050
#define ZBEE_MFG_CODE_IMONITOR              0x1051
#define ZBEE_MFG_CODE_BARTECH               0x1052
#define ZBEE_MFG_CODE_MESHNETICS            0x1053
#define ZBEE_MFG_CODE_LS_IND                0x1054
#define ZBEE_MFG_CODE_CASON                 0x1055
#define ZBEE_MFG_CODE_WLESS_GLUE            0x1056
#define ZBEE_MFG_CODE_ELSTER                0x1057
#define ZBEE_MFG_CODE_SMS_TEC               0x1058
#define ZBEE_MFG_CODE_ONSET                 0x1059
#define ZBEE_MFG_CODE_RIGA                  0x105a
#define ZBEE_MFG_CODE_ENERGATE              0x105b
#define ZBEE_MFG_CODE_CONMED                0x105c
#define ZBEE_MFG_CODE_POWERMAND             0x105d
#define ZBEE_MFG_CODE_SCHNEIDER             0x105e
#define ZBEE_MFG_CODE_EATON                 0x105f

#define ZBEE_MFG_CODE_TELULAR               0x1060
#define ZBEE_MFG_CODE_DELPHI                0x1061
#define ZBEE_MFG_CODE_EPISENSOR             0x1062
#define ZBEE_MFG_CODE_LANDIS_GYR            0x1063
#define ZBEE_MFG_CODE_KABA                  0x1064
#define ZBEE_MFG_CODE_SHURE                 0x1065
#define ZBEE_MFG_CODE_COMVERGE              0x1066
#define ZBEE_MFG_CODE_DBS_LODGING           0x1067
#define ZBEE_MFG_CODE_ENERGY_AWARE          0x1068
#define ZBEE_MFG_CODE_HIDALGO               0x1069
#define ZBEE_MFG_CODE_AIR2APP               0x106a
#define ZBEE_MFG_CODE_AMX                   0x106b
#define ZBEE_MFG_CODE_EDMI                  0x106c
#define ZBEE_MFG_CODE_CYAN                  0x106d
#define ZBEE_MFG_CODE_SYS_SPA               0x106e
#define ZBEE_MFG_CODE_TELIT                 0x106f

#define ZBEE_MFG_CODE_KAGA                  0x1070
#define ZBEE_MFG_CODE_4_NOKS                0x1071
#define ZBEE_MFG_CODE_CERTICOM              0x1072
#define ZBEE_MFG_CODE_GRIDPOINT             0x1073
#define ZBEE_MFG_CODE_PROFILE_SYS           0x1074
#define ZBEE_MFG_CODE_COMPACTA              0x1075
#define ZBEE_MFG_CODE_FREESTYLE             0x1076
#define ZBEE_MFG_CODE_ALEKTRONA             0x1077
#define ZBEE_MFG_CODE_COMPUTIME             0x1078
#define ZBEE_MFG_CODE_REMOTE_TECH           0x1079
#define ZBEE_MFG_CODE_WAVECOM               0x107a
#define ZBEE_MFG_CODE_ENERGY                0x107b
#define ZBEE_MFG_CODE_GE                    0x107c
#define ZBEE_MFG_CODE_JETLUN                0x107d
#define ZBEE_MFG_CODE_CIPHER                0x107e
#define ZBEE_MFG_CODE_CORPORATE             0x107f

#define ZBEE_MFG_CODE_ECOBEE                0x1080
#define ZBEE_MFG_CODE_SMK                   0x1081
#define ZBEE_MFG_CODE_MESHWORKS             0x1082
#define ZBEE_MFG_CODE_ELLIPS                0x1083
#define ZBEE_MFG_CODE_SECURE                0x1084
#define ZBEE_MFG_CODE_CEDO                  0x1085
#define ZBEE_MFG_CODE_TOSHIBA               0x1086
#define ZBEE_MFG_CODE_DIGI                  0x1087
#define ZBEE_MFG_CODE_UBILOGIX              0x1088
#define ZBEE_MFG_CODE_ECHELON               0x1089
/* */

#define ZBEE_MFG_CODE_GREEN_ENERGY          0x1090
#define ZBEE_MFG_CODE_SILVER_SPRING         0x1091
#define ZBEE_MFG_CODE_BLACK                 0x1092
#define ZBEE_MFG_CODE_AZTECH_ASSOC          0x1093
#define ZBEE_MFG_CODE_A_AND_D               0x1094
#define ZBEE_MFG_CODE_RAINFOREST            0x1095
#define ZBEE_MFG_CODE_CARRIER               0x1096
#define ZBEE_MFG_CODE_SYCHIP                0x1097
#define ZBEE_MFG_CODE_OPEN_PEAK             0x1098
#define ZBEE_MFG_CODE_PASSIVE               0x1099
#define ZBEE_MFG_CODE_MMB                   0x109a
#define ZBEE_MFG_CODE_LEVITON               0x109b
#define ZBEE_MFG_CODE_KOREA_ELEC            0x109c
#define ZBEE_MFG_CODE_COMCAST1              0x109d
#define ZBEE_MFG_CODE_NEC_ELEC              0x109e
#define ZBEE_MFG_CODE_NETVOX                0x109f

#define ZBEE_MFG_CODE_UCONTROL              0x10a0
#define ZBEE_MFG_CODE_EMBEDIA               0x10a1
#define ZBEE_MFG_CODE_SENSUS                0x10a2
#define ZBEE_MFG_CODE_SUNRISE               0x10a3
#define ZBEE_MFG_CODE_MEMTECH               0x10a4
#define ZBEE_MFG_CODE_FREEBOX               0x10a5
#define ZBEE_MFG_CODE_M2_LABS               0x10a6
#define ZBEE_MFG_CODE_BRITISH_GAS           0x10a7
#define ZBEE_MFG_CODE_SENTEC                0x10a8
#define ZBEE_MFG_CODE_NAVETAS               0x10a9
#define ZBEE_MFG_CODE_LIGHTSPEED            0x10aa
#define ZBEE_MFG_CODE_OKI                   0x10ab
#define ZBEE_MFG_CODE_SISTEMAS              0x10ac
#define ZBEE_MFG_CODE_DOMETIC               0x10ad
#define ZBEE_MFG_CODE_APLS                  0x10ae
#define ZBEE_MFG_CODE_ENERGY_HUB            0x10af

#define ZBEE_MFG_CODE_KAMSTRUP              0x10b0
#define ZBEE_MFG_CODE_ECHOSTAR              0x10b1
#define ZBEE_MFG_CODE_ENERNOC               0x10b2
#define ZBEE_MFG_CODE_ELTAV                 0x10b3
#define ZBEE_MFG_CODE_BELKIN                0x10b4
#define ZBEE_MFG_CODE_XSTREAMHD             0x10b5
#define ZBEE_MFG_CODE_SATURN_SOUTH          0x10b6
#define ZBEE_MFG_CODE_GREENTRAP             0x10b7
#define ZBEE_MFG_CODE_SMARTSYNCH            0x10b8
#define ZBEE_MFG_CODE_NYCE                  0x10b9
#define ZBEE_MFG_CODE_ICM_CONTROLS          0x10ba
#define ZBEE_MFG_CODE_MILLENNIUM            0x10bb
#define ZBEE_MFG_CODE_MOTOROLA              0x10bc
#define ZBEE_MFG_CODE_EMERSON               0x10bd
#define ZBEE_MFG_CODE_RADIO_THERMOSTAT      0x10be
#define ZBEE_MFG_CODE_OMRON                 0x10bf

#define ZBEE_MFG_CODE_GIINII                0x10c0
#define ZBEE_MFG_CODE_FUJITSU               0x10c1
#define ZBEE_MFG_CODE_PEEL                  0x10c2
#define ZBEE_MFG_CODE_ACCENT                0x10c3
#define ZBEE_MFG_CODE_BYTESNAP              0x10c4
#define ZBEE_MFG_CODE_NEC_TOKIN             0x10c5
#define ZBEE_MFG_CODE_G4S_JUSTICE           0x10c6
#define ZBEE_MFG_CODE_TRILLIANT             0x10c7
#define ZBEE_MFG_CODE_ELECTROLUX            0x10c8
#define ZBEE_MFG_CODE_ONZO                  0x10c9
#define ZBEE_MFG_CODE_ENTEK                 0x10ca
#define ZBEE_MFG_CODE_PHILIPS2              0x10cb
#define ZBEE_MFG_CODE_MAINSTREAM            0x10cc
#define ZBEE_MFG_CODE_INDESIT               0x10cd
#define ZBEE_MFG_CODE_THINKECO              0x10ce
#define ZBEE_MFG_CODE_2D2C                  0x10cf

#define ZBEE_MFG_CODE_GREENPEAK             0x10d0
#define ZBEE_MFG_CODE_INTERCEL              0x10d1
#define ZBEE_MFG_CODE_LG                    0x10d2
#define ZBEE_MFG_CODE_MITSUMI1              0x10d3
#define ZBEE_MFG_CODE_MITSUMI2              0x10d4
#define ZBEE_MFG_CODE_ZENTRUM               0x10d5
#define ZBEE_MFG_CODE_NEST                  0x10d6
#define ZBEE_MFG_CODE_EXEGIN                0x10d7
#define ZBEE_MFG_CODE_HONEYWELL2            0x10d8
#define ZBEE_MFG_CODE_TAKAHATA              0x10d9
#define ZBEE_MFG_CODE_SUMITOMO              0x10da
#define ZBEE_MFG_CODE_GE_ENERGY             0x10db
#define ZBEE_MFG_CODE_GE_APPLIANCES         0x10dc
#define ZBEE_MFG_CODE_RADIOCRAFTS           0x10dd
#define ZBEE_MFG_CODE_CEIVA                 0x10de
#define ZBEE_MFG_CODE_TEC_CO                0x10df

#define ZBEE_MFG_CODE_CHAMELEON             0x10e0
#define ZBEE_MFG_CODE_SAMSUNG               0x10e1
#define ZBEE_MFG_CODE_RUWIDO                0x10e2
#define ZBEE_MFG_CODE_HUAWEI_1              0x10e3
#define ZBEE_MFG_CODE_HUAWEI_2              0x10e4
#define ZBEE_MFG_CODE_GREENWAVE             0x10e5
#define ZBEE_MFG_CODE_BGLOBAL               0x10e6
#define ZBEE_MFG_CODE_MINDTECK              0x10e7
#define ZBEE_MFG_CODE_INGERSOLL_RAND        0x10e8
#define ZBEE_MFG_CODE_DIUS                  0x10e9
#define ZBEE_MFG_CODE_EMBEDDED              0x10ea
#define ZBEE_MFG_CODE_ABB                   0x10eb
#define ZBEE_MFG_CODE_SONY                  0x10ec
#define ZBEE_MFG_CODE_GENUS                 0x10ed
#define ZBEE_MFG_CODE_UNIVERSAL1            0x10ee
#define ZBEE_MFG_CODE_UNIVERSAL2            0x10ef
#define ZBEE_MFG_CODE_METRUM                0x10f0
#define ZBEE_MFG_CODE_CISCO                 0x10f1
#define ZBEE_MFG_CODE_UBISYS                0x10f2
#define ZBEE_MFG_CODE_CONSERT               0x10f3
#define ZBEE_MFG_CODE_CRESTRON              0x10f4
#define ZBEE_MFG_CODE_ENPHASE               0x10f5
#define ZBEE_MFG_CODE_INVENSYS              0x10f6
#define ZBEE_MFG_CODE_MUELLER               0x10f7
#define ZBEE_MFG_CODE_AAC_TECH              0x10f8
#define ZBEE_MFG_CODE_U_NEXT                0x10f9
#define ZBEE_MFG_CODE_STEELCASE             0x10fa
#define ZBEE_MFG_CODE_TELEMATICS            0x10fb
#define ZBEE_MFG_CODE_SAMIL                 0x10fc
#define ZBEE_MFG_CODE_PACE                  0x10fd
#define ZBEE_MFG_CODE_OSBORNE               0x10fe
#define ZBEE_MFG_CODE_POWERWATCH            0x10ff
#define ZBEE_MFG_CODE_CANDELED              0x1100
#define ZBEE_MFG_CODE_FLEXGRID              0x1101
#define ZBEE_MFG_CODE_HUMAX                 0x1102
#define ZBEE_MFG_CODE_UNIVERSAL             0x1103
#define ZBEE_MFG_CODE_ADVANCED_ENERGY       0x1104
#define ZBEE_MFG_CODE_BEGA                  0x1105
#define ZBEE_MFG_CODE_BRUNEL                0x1106
#define ZBEE_MFG_CODE_PANASONIC             0x1107
#define ZBEE_MFG_CODE_ESYSTEMS              0x1108
#define ZBEE_MFG_CODE_PANAMAX               0x1109
#define ZBEE_MFG_CODE_PHYSICAL              0x110a
#define ZBEE_MFG_CODE_EM_LITE               0x110b
#define ZBEE_MFG_CODE_OSRAM                 0x110c
#define ZBEE_MFG_CODE_2_SAVE                0x110d
#define ZBEE_MFG_CODE_PLANET                0x110e
#define ZBEE_MFG_CODE_AMBIENT               0x110f
#define ZBEE_MFG_CODE_PROFALUX              0x1110
#define ZBEE_MFG_CODE_BILLION               0x1111
#define ZBEE_MFG_CODE_EMBERTEC              0x1112
#define ZBEE_MFG_CODE_IT_WATCHDOGS          0x1113
#define ZBEE_MFG_CODE_RELOC                 0x1114
#define ZBEE_MFG_CODE_INTEL                 0x1115
#define ZBEE_MFG_CODE_TREND                 0x1116
#define ZBEE_MFG_CODE_MOXA                  0x1117
#define ZBEE_MFG_CODE_QEES                  0x1118
#define ZBEE_MFG_CODE_SAYME                 0x1119
#define ZBEE_MFG_CODE_PENTAIR               0x111a
#define ZBEE_MFG_CODE_ORBIT                 0x111b
#define ZBEE_MFG_CODE_CALIFORNIA            0x111c
#define ZBEE_MFG_CODE_COMCAST2              0x111d
#define ZBEE_MFG_CODE_IDT                   0x111e
#define ZBEE_MFG_CODE_PIXELA                0x111f
#define ZBEE_MFG_CODE_TIVO                  0x1120
#define ZBEE_MFG_CODE_FIDURE                0x1121
#define ZBEE_MFG_CODE_MARVELL               0x1122
#define ZBEE_MFG_CODE_WASION                0x1123
#define ZBEE_MFG_CODE_JASCO                 0x1124
#define ZBEE_MFG_CODE_SHENZHEN              0x1125
#define ZBEE_MFG_CODE_NETCOMM               0x1126
#define ZBEE_MFG_CODE_DEFINE                0x1127
#define ZBEE_MFG_CODE_IN_HOME_DISP          0x1128
#define ZBEE_MFG_CODE_MIELE                 0x1129
#define ZBEE_MFG_CODE_TELEVES               0x112a
#define ZBEE_MFG_CODE_LABELEC               0x112b
#define ZBEE_MFG_CODE_CHINA_ELEC            0x112c
#define ZBEE_MFG_CODE_VECTORFORM            0x112d
#define ZBEE_MFG_CODE_BUSCH_JAEGER          0x112e
#define ZBEE_MFG_CODE_REDPINE               0x112f
#define ZBEE_MFG_CODE_BRIDGES               0x1130
#define ZBEE_MFG_CODE_SERCOMM               0x1131
#define ZBEE_MFG_CODE_WSH                   0x1132
#define ZBEE_MFG_CODE_BOSCH                 0x1133
#define ZBEE_MFG_CODE_EZEX                  0x1134
#define ZBEE_MFG_CODE_DRESDEN               0x1135
#define ZBEE_MFG_CODE_MEAZON                0x1136
#define ZBEE_MFG_CODE_CROW                  0x1137
#define ZBEE_MFG_CODE_HARVARD               0x1138
#define ZBEE_MFG_CODE_ANDSON                0x1139
#define ZBEE_MFG_CODE_ADHOCO                0x113a
#define ZBEE_MFG_CODE_WAXMAN                0x113b
#define ZBEE_MFG_CODE_OWON                  0x113c
#define ZBEE_MFG_CODE_HITRON                0x113d
#define ZBEE_MFG_CODE_SCEMTEC               0x113e
#define ZBEE_MFG_CODE_WEBEE                 0x113f
#define ZBEE_MFG_CODE_GRID2HOME             0x1140
#define ZBEE_MFG_CODE_TELINK                0x1141
#define ZBEE_MFG_CODE_JASMINE               0x1142
#define ZBEE_MFG_CODE_BIDGELY               0x1143
#define ZBEE_MFG_CODE_LUTRON                0x1144
#define ZBEE_MFG_CODE_IJENKO                0x1145
#define ZBEE_MFG_CODE_STARFIELD             0x1146
#define ZBEE_MFG_CODE_TCP                   0x1147
#define ZBEE_MFG_CODE_ROGERS                0x1148
#define ZBEE_MFG_CODE_CREE                  0x1149
#define ZBEE_MFG_CODE_ROBERT_BOSCH          0x114a
#define ZBEE_MFG_CODE_IBIS                  0x114b
#define ZBEE_MFG_CODE_QUIRKY                0x114c
#define ZBEE_MFG_CODE_EFERGY                0x114d
#define ZBEE_MFG_CODE_SMARTLABS             0x114e
#define ZBEE_MFG_CODE_EVERSPRING            0x114f
#define ZBEE_MFG_CODE_SWANN                 0x1150

/* Manufacturer Names */
#define ZBEE_MFG_CIRRONET                   "Cirronet"
#define ZBEE_MFG_CHIPCON                    "Chipcon"
#define ZBEE_MFG_EMBER                      "Ember"
#define ZBEE_MFG_NTS                        "National Tech"
#define ZBEE_MFG_FREESCALE                  "Freescale"
#define ZBEE_MFG_IPCOM                      "IPCom"
#define ZBEE_MFG_SAN_JUAN                   "San Juan Software"
#define ZBEE_MFG_TUV                        "TUV"
#define ZBEE_MFG_COMPXS                     "CompXs"
#define ZBEE_MFG_BM                         "BM SpA"
#define ZBEE_MFG_AWAREPOINT                 "AwarePoint"
#define ZBEE_MFG_PHILIPS                    "Philips"
#define ZBEE_MFG_LUXOFT                     "Luxoft"
#define ZBEE_MFG_KORWIN                     "Korvin"
#define ZBEE_MFG_1_RF                       "One RF"
#define ZBEE_MFG_STG                        "Software Technology Group"
#define ZBEE_MFG_TELEGESIS                  "Telegesis"
#define ZBEE_MFG_VISIONIC                   "Visionic"
#define ZBEE_MFG_INSTA                      "Insta"
#define ZBEE_MFG_ATALUM                     "Atalum"
#define ZBEE_MFG_ATMEL                      "Atmel"
#define ZBEE_MFG_DEVELCO                    "Develco"
#define ZBEE_MFG_HONEYWELL                  "Honeywell"
#define ZBEE_MFG_RADIO_PULSE                "RadioPulse"
#define ZBEE_MFG_RENESAS                    "Renesas"
#define ZBEE_MFG_XANADU                     "Xanadu Wireless"
#define ZBEE_MFG_NEC                        "NEC Engineering"
#define ZBEE_MFG_YAMATAKE                   "Yamatake"
#define ZBEE_MFG_TENDRIL                    "Tendril"
#define ZBEE_MFG_ASSA                       "Assa Abloy"
#define ZBEE_MFG_MAXSTREAM                  "Maxstream"
#define ZBEE_MFG_NEUROCOM                   "Neurocom"

#define ZBEE_MFG_III                        "Institute for Information Industry"
#define ZBEE_MFG_VANTAGE                    "Vantage Controls"
#define ZBEE_MFG_ICONTROL                   "iControl"
#define ZBEE_MFG_RAYMARINE                  "Raymarine"
#define ZBEE_MFG_LSR                        "LS Research"
#define ZBEE_MFG_ONITY                      "Onity"
#define ZBEE_MFG_MONO                       "Mono Products"
#define ZBEE_MFG_RFT                        "RF Tech"
#define ZBEE_MFG_ITRON                      "Itron"
#define ZBEE_MFG_TRITECH                    "Tritech"
#define ZBEE_MFG_EMBEDIT                    "Embedit"
#define ZBEE_MFG_S3C                        "S3C"
#define ZBEE_MFG_SIEMENS                    "Siemens"
#define ZBEE_MFG_MINDTECH                   "Mindtech"
#define ZBEE_MFG_LGE                        "LG Electronics"
#define ZBEE_MFG_MITSUBISHI                 "Mitsubishi"
#define ZBEE_MFG_JOHNSON                    "Johnson Controls"
#define ZBEE_MFG_PRI                        "PRI"
#define ZBEE_MFG_KNICK                      "Knick"
#define ZBEE_MFG_VICONICS                   "Viconics"
#define ZBEE_MFG_FLEXIPANEL                 "Flexipanel"
#define ZBEE_MFG_PIASIM                     "Piasim Corporation"
#define ZBEE_MFG_TRANE                      "Trane"
#define ZBEE_MFG_JENNIC                     "Jennic"
#define ZBEE_MFG_LIG                        "Living Independently"
#define ZBEE_MFG_ALERTME                    "AlertMe"
#define ZBEE_MFG_DAINTREE                   "Daintree"
#define ZBEE_MFG_AIJI                       "Aiji"
#define ZBEE_MFG_TEL_ITALIA                 "Telecom Italia"
#define ZBEE_MFG_MIKROKRETS                 "Mikrokrets"
#define ZBEE_MFG_OKI_SEMI                   "Oki Semi"
#define ZBEE_MFG_NEWPORT                    "Newport Electronics"
#define ZBEE_MFG_C4                         "Control4"
#define ZBEE_MFG_STM                        "STMicro"
#define ZBEE_MFG_ASN                        "Ad-Sol Nissin"
#define ZBEE_MFG_DCSI                       "DCSI"
#define ZBEE_MFG_FRANCE_TEL                 "France Telecom"
#define ZBEE_MFG_MUNET                      "muNet"
#define ZBEE_MFG_AUTANI                     "Autani"
#define ZBEE_MFG_COL_VNET                   "Colorado vNet"
#define ZBEE_MFG_AEROCOMM                   "Aerocomm"
#define ZBEE_MFG_SI_LABS                    "Silicon Labs"
#define ZBEE_MFG_INNCOM                     "Inncom"
#define ZBEE_MFG_CANNON                     "Cannon"
#define ZBEE_MFG_SYNAPSE                    "Synapse"
#define ZBEE_MFG_FPS                        "Fisher Pierce/Sunrise"
#define ZBEE_MFG_CLS                        "CentraLite"
#define ZBEE_MFG_CRANE                      "Crane"
#define ZBEE_MFG_MOBILARM                   "Mobilarm"
#define ZBEE_MFG_IMONITOR                   "iMonitor"
#define ZBEE_MFG_BARTECH                    "Bartech"
#define ZBEE_MFG_MESHNETICS                 "Meshnetics"
#define ZBEE_MFG_LS_IND                     "LS Industrial"
#define ZBEE_MFG_CASON                      "Cason"
#define ZBEE_MFG_WLESS_GLUE                 "Wireless Glue"
#define ZBEE_MFG_ELSTER                     "Elster"
#define ZBEE_MFG_SMS_TEC                    "SMS Tec"
#define ZBEE_MFG_ONSET                      "Onset Computer"
#define ZBEE_MFG_RIGA                       "Riga Development"
#define ZBEE_MFG_ENERGATE                   "Energate"
#define ZBEE_MFG_CONMED                     "ConMed Linvatec"
#define ZBEE_MFG_POWERMAND                  "PowerMand"
#define ZBEE_MFG_SCHNEIDER                  "Schneider Electric"
#define ZBEE_MFG_EATON                      "Eaton"
#define ZBEE_MFG_TELULAR                    "Telular"
#define ZBEE_MFG_DELPHI                     "Delphi Medical"
#define ZBEE_MFG_EPISENSOR                  "EpiSensor"
#define ZBEE_MFG_LANDIS_GYR                 "Landis+Gyr"
#define ZBEE_MFG_KABA                       "Kaba Group"
#define ZBEE_MFG_SHURE                      "Shure"
#define ZBEE_MFG_COMVERGE                   "Comverge"
#define ZBEE_MFG_DBS_LODGING                "DBS Lodging"
#define ZBEE_MFG_ENERGY_AWARE               "Energy Aware"
#define ZBEE_MFG_HIDALGO                    "Hidalgo"
#define ZBEE_MFG_AIR2APP                    "Air2App"
#define ZBEE_MFG_AMX                        "AMX"
#define ZBEE_MFG_EDMI                       "EDMI Pty"
#define ZBEE_MFG_CYAN                       "Cyan Ltd"
#define ZBEE_MFG_SYS_SPA                    "System SPA"
#define ZBEE_MFG_TELIT                      "Telit"
#define ZBEE_MFG_KAGA                       "Kaga Electronics"
#define ZBEE_MFG_4_NOKS                     "4-noks s.r.l."
#define ZBEE_MFG_CERTICOM                   "Certicom"
#define ZBEE_MFG_GRIDPOINT                  "Gridpoint"
#define ZBEE_MFG_PROFILE_SYS                "Profile Systems"
#define ZBEE_MFG_COMPACTA                   "Compacta International"
#define ZBEE_MFG_FREESTYLE                  "Freestyle Technology"
#define ZBEE_MFG_ALEKTRONA                  "Alektrona"
#define ZBEE_MFG_COMPUTIME                  "Computime"
#define ZBEE_MFG_REMOTE_TECH                "Remote Technologies"
#define ZBEE_MFG_WAVECOM                    "Wavecom"
#define ZBEE_MFG_ENERGY                     "Energy Optimizers"
#define ZBEE_MFG_GE                         "GE"
#define ZBEE_MFG_JETLUN                     "Jetlun"
#define ZBEE_MFG_CIPHER                     "Cipher Systems"
#define ZBEE_MFG_CORPORATE                  "Corporate Systems Eng"
#define ZBEE_MFG_ECOBEE                     "ecobee"
#define ZBEE_MFG_SMK                        "SMK"
#define ZBEE_MFG_MESHWORKS                  "Meshworks Wireless"
#define ZBEE_MFG_ELLIPS                     "Ellips B.V."
#define ZBEE_MFG_SECURE                     "Secure electrans"
#define ZBEE_MFG_CEDO                       "CEDO"
#define ZBEE_MFG_TOSHIBA                    "Toshiba"
#define ZBEE_MFG_DIGI                       "Digi International"
#define ZBEE_MFG_UBILOGIX                   "Ubilogix"
#define ZBEE_MFG_ECHELON                    "Echelon"
#define ZBEE_MFG_GREEN_ENERGY               "Green Energy Options"
#define ZBEE_MFG_SILVER_SPRING              "Silver Spring Networks"
#define ZBEE_MFG_BLACK                      "Black & Decker"
#define ZBEE_MFG_AZTECH_ASSOC               "Aztech AssociatesInc."
#define ZBEE_MFG_A_AND_D                    "A&D Co"
#define ZBEE_MFG_RAINFOREST                 "Rainforest Automation"
#define ZBEE_MFG_CARRIER                    "Carrier Electronics"
#define ZBEE_MFG_SYCHIP                     "SyChip/Murata"
#define ZBEE_MFG_OPEN_PEAK                  "OpenPeak"
#define ZBEE_MFG_PASSIVE                    "Passive Systems"
#define ZBEE_MFG_G4S_JUSTICE                "G4S JusticeServices"
#define ZBEE_MFG_MMB                        "MMBResearch"
#define ZBEE_MFG_LEVITON                    "Leviton"
#define ZBEE_MFG_KOREA_ELEC                 "Korea Electric Power Data Network"
#define ZBEE_MFG_COMCAST                    "Comcast"
#define ZBEE_MFG_NEC_ELEC                   "NEC Electronics"
#define ZBEE_MFG_NETVOX                     "Netvox"
#define ZBEE_MFG_UCONTROL                   "U-Control"
#define ZBEE_MFG_EMBEDIA                    "Embedia Technologies"
#define ZBEE_MFG_SENSUS                     "Sensus"
#define ZBEE_MFG_SUNRISE                    "SunriseTechnologies"
#define ZBEE_MFG_MEMTECH                    "MemtechCorp"
#define ZBEE_MFG_FREEBOX                    "Freebox"
#define ZBEE_MFG_M2_LABS                    "M2 Labs"
#define ZBEE_MFG_BRITISH_GAS                "BritishGas"
#define ZBEE_MFG_SENTEC                     "Sentec"
#define ZBEE_MFG_NAVETAS                    "Navetas"
#define ZBEE_MFG_LIGHTSPEED                 "Lightspeed Technologies"
#define ZBEE_MFG_OKI                        "Oki Electric"
#define ZBEE_MFG_SISTEMAS                   "Sistemas Inteligentes"
#define ZBEE_MFG_DOMETIC                    "Dometic"
#define ZBEE_MFG_APLS                       "Alps"
#define ZBEE_MFG_ENERGY_HUB                 "EnergyHub"
#define ZBEE_MFG_KAMSTRUP                   "Kamstrup"
#define ZBEE_MFG_ECHOSTAR                   "EchoStar"
#define ZBEE_MFG_ENERNOC                    "EnerNOC"
#define ZBEE_MFG_ELTAV                      "Eltav"
#define ZBEE_MFG_BELKIN                     "Belkin"
#define ZBEE_MFG_XSTREAMHD                  "XStreamHD Wireless"
#define ZBEE_MFG_SATURN_SOUTH               "Saturn South"
#define ZBEE_MFG_GREENTRAP                  "GreenTrapOnline"
#define ZBEE_MFG_SMARTSYNCH                 "SmartSynch"
#define ZBEE_MFG_NYCE                       "Nyce Control"
#define ZBEE_MFG_ICM_CONTROLS               "ICM Controls"
#define ZBEE_MFG_MILLENNIUM                 "Millennium Electronics"
#define ZBEE_MFG_MOTOROLA                   "Motorola"
#define ZBEE_MFG_EMERSON                    "EmersonWhite-Rodgers"
#define ZBEE_MFG_RADIO_THERMOSTAT           "Radio Thermostat"
#define ZBEE_MFG_OMRON                      "OMRONCorporation"
#define ZBEE_MFG_GIINII                     "GiiNii GlobalLimited"
#define ZBEE_MFG_FUJITSU                    "Fujitsu GeneralLimited"
#define ZBEE_MFG_PEEL                       "Peel Technologies"
#define ZBEE_MFG_ACCENT                     "Accent"
#define ZBEE_MFG_BYTESNAP                   "ByteSnap Design"
#define ZBEE_MFG_NEC_TOKIN                  "NEC TOKIN Corporation"
#define ZBEE_MFG_TRILLIANT                  "Trilliant Networks"
#define ZBEE_MFG_ELECTROLUX                 "Electrolux Italia"
#define ZBEE_MFG_ONZO                       "OnzoLtd"
#define ZBEE_MFG_ENTEK                      "EnTekSystems"
/**/
#define ZBEE_MFG_MAINSTREAM                 "MainstreamEngineering"
#define ZBEE_MFG_INDESIT                    "IndesitCompany"
#define ZBEE_MFG_THINKECO                   "THINKECO"
#define ZBEE_MFG_2D2C                       "2D2C"
#define ZBEE_MFG_GREENPEAK                  "GreenPeak"
#define ZBEE_MFG_INTERCEL                   "InterCEL"
#define ZBEE_MFG_LG                         "LG Electronics"
#define ZBEE_MFG_MITSUMI1                   "Mitsumi Electric"
#define ZBEE_MFG_MITSUMI2                   "Mitsumi Electric"
#define ZBEE_MFG_ZENTRUM                    "Zentrum Mikroelektronik Dresden"
#define ZBEE_MFG_NEST                       "Nest Labs"
#define ZBEE_MFG_EXEGIN                     "Exegin Technologies"
#define ZBEE_MFG_HONEYWELL                  "Honeywell"
#define ZBEE_MFG_TAKAHATA                   "Takahata Precision"
#define ZBEE_MFG_SUMITOMO                   "Sumitomo Electric Networks"
#define ZBEE_MFG_GE_ENERGY                  "GE Energy"
#define ZBEE_MFG_GE_APPLIANCES              "GE Appliances"
#define ZBEE_MFG_RADIOCRAFTS                "Radiocrafts AS"
#define ZBEE_MFG_CEIVA                      "Ceiva"
#define ZBEE_MFG_TEC_CO                     "TEC CO Co., Ltd"
#define ZBEE_MFG_CHAMELEON                  "Chameleon Technology (UK) Ltd"
#define ZBEE_MFG_SAMSUNG                    "Samsung"
#define ZBEE_MFG_RUWIDO                     "ruwido austria gmbh"
#define ZBEE_MFG_HUAWEI                     "Huawei Technologies Co., Ltd."
#define ZBEE_MFG_GREENWAVE                  "Greenwave Reality"
#define ZBEE_MFG_BGLOBAL                    "BGlobal Metering Ltd"
#define ZBEE_MFG_MINDTECK                   "Mindteck"
#define ZBEE_MFG_INGERSOLL_RAND             "Ingersoll-Rand"
#define ZBEE_MFG_DIUS                       "Dius Computing Pty Ltd"
#define ZBEE_MFG_EMBEDDED                   "Embedded Automation, Inc."
#define ZBEE_MFG_ABB                        "ABB"
#define ZBEE_MFG_SONY                       "Sony"
#define ZBEE_MFG_GENUS                      "Genus Power Infrastructures Limited"
#define ZBEE_MFG_UNIVERSA L                 "Universal Electronics, Inc."
#define ZBEE_MFG_METRUM                     "Metrum Technologies, LLC"
#define ZBEE_MFG_CISCO                      "Cisco"
#define ZBEE_MFG_UBISYS                     "Ubisys technologies GmbH"
#define ZBEE_MFG_CONSERT                    "Consert"
#define ZBEE_MFG_CRESTRON                   "Crestron Electronics"
#define ZBEE_MFG_ENPHASE                    "Enphase Energy"
#define ZBEE_MFG_INVENSYS                   "Invensys Controls"
#define ZBEE_MFG_MUELLER                    "Mueller Systems, LLC"
#define ZBEE_MFG_AAC_TECH                   "AAC Technologies Holding"
#define ZBEE_MFG_U_NEXT                     "U-NEXT Co., Ltd"
#define ZBEE_MFG_STEELCASE                  "Steelcase Inc."
#define ZBEE_MFG_TELEMATICS                 "Telematics Wireless"
#define ZBEE_MFG_SAMIL                      "Samil Power Co., Ltd"
#define ZBEE_MFG_PACE                       "Pace Plc"
#define ZBEE_MFG_OSBORNE                    "Osborne Coinage Co."
#define ZBEE_MFG_POWERWATCH                 "Powerwatch"
#define ZBEE_MFG_CANDELED                   "CANDELED GmbH"
#define ZBEE_MFG_FLEXGRID                   "FlexGrid S.R.L"
#define ZBEE_MFG_HUMAX                      "Humax"
#define ZBEE_MFG_UNIVERSAL                  "Universal Devices"
#define ZBEE_MFG_ADVANCED_ENERGY            "Advanced Energy"
#define ZBEE_MFG_BEGA                       "BEGA Gantenbrink-Leuchten"
#define ZBEE_MFG_BRUNEL                     "Brunel University"
#define ZBEE_MFG_PANASONIC                  "Panasonic R&D Center Singapore"
#define ZBEE_MFG_ESYSTEMS                   "eSystems Research"
#define ZBEE_MFG_PANAMAX                    "Panamax"
#define ZBEE_MFG_PHYSICAL                   "Physical Graph Corporation"
#define ZBEE_MFG_EM_LITE                    "EM-Lite Ltd."
#define ZBEE_MFG_OSRAM                      "Osram Sylvania"
#define ZBEE_MFG_2_SAVE                     "2 Save Energy Ltd."
#define ZBEE_MFG_PLANET                     "Planet Innovation Products Pty Ltd"
#define ZBEE_MFG_AMBIENT                    "Ambient Devices, Inc."
#define ZBEE_MFG_PROFALUX                   "Profalux"
#define ZBEE_MFG_BILLION                    "Billion Electric Company (BEC)"
#define ZBEE_MFG_EMBERTEC                   "Embertec Pty Ltd"
#define ZBEE_MFG_IT_WATCHDOGS               "IT Watchdogs"
#define ZBEE_MFG_RELOC                      "Reloc"
#define ZBEE_MFG_INTEL                      "Intel Corporation"
#define ZBEE_MFG_TREND                      "Trend Electronics Limited"
#define ZBEE_MFG_MOXA                       "Moxa"
#define ZBEE_MFG_QEES                       "QEES"
#define ZBEE_MFG_SAYME                      "SAYME Wireless Sensor Networks"
#define ZBEE_MFG_PENTAIR                    "Pentair Aquatic Systems"
#define ZBEE_MFG_ORBIT                      "Orbit Irrigation"
#define ZBEE_MFG_CALIFORNIA                 "California Eastern Laboratories"
#define ZBEE_MFG_COMCAST                    "Comcast"
#define ZBEE_MFG_IDT                        "IDT Technology Limited"
#define ZBEE_MFG_PIXELA                     "Pixela"
#define ZBEE_MFG_TIVO                       "TiVo"
#define ZBEE_MFG_FIDURE                     "Fidure"
#define ZBEE_MFG_MARVELL                    "Marvell Semiconductor"
#define ZBEE_MFG_WASION                     "Wasion Group"
#define ZBEE_MFG_JASCO                      "Jasco Products"
#define ZBEE_MFG_SHENZHEN                   "Shenzhen Kaifa Technology"
#define ZBEE_MFG_NETCOMM                    "Netcomm Wireless"
#define ZBEE_MFG_DEFINE                     "Define Instruments"
#define ZBEE_MFG_IN_HOME_DISP               "In Home Displays"
#define ZBEE_MFG_MIELE                      "Miele & Cie. KG"
#define ZBEE_MFG_TELEVES                    "Televes S.A."
#define ZBEE_MFG_LABELEC                    "Labelec"
#define ZBEE_MFG_CHINA_ELEC                 "China Electronics Standardization Institute"
#define ZBEE_MFG_VECTORFORM                 "Vectorform"
#define ZBEE_MFG_BUSCH_JAEGER               "Busch-Jaeger Elektro"
#define ZBEE_MFG_REDPINE                    "Redpine Signals"
#define ZBEE_MFG_BRIDGES                    "Bridges Electronic Technology"
#define ZBEE_MFG_SERCOMM                    "Sercomm"
#define ZBEE_MFG_WSH                        "WSH GmbH wirsindheller"
#define ZBEE_MFG_BOSCH                      "Bosch Security Systems"
#define ZBEE_MFG_EZEX                       "eZEX Corporation"
#define ZBEE_MFG_DRESDEN                    "Dresden Elektronik Ingenieurtechnik GmbH"
#define ZBEE_MFG_MEAZON                     "MEAZON S.A."
#define ZBEE_MFG_CROW                       "Crow Electronic Engineering"
#define ZBEE_MFG_HARVARD                    "Harvard Engineering"
#define ZBEE_MFG_ANDSON                     "Andson(Beijing) Technology"
#define ZBEE_MFG_ADHOCO                     "Adhoco AG"
#define ZBEE_MFG_WAXMAN                     "Waxman Consumer Products Group"
#define ZBEE_MFG_OWON                       "Owon Technology"
#define ZBEE_MFG_HITRON                     "Hitron Technologies"
#define ZBEE_MFG_SCEMTEC                    "Scemtec Steuerungstechnik GmbH"
#define ZBEE_MFG_WEBEE                      "Webee"
#define ZBEE_MFG_GRID2HOME                  "Grid2Home"
#define ZBEE_MFG_TELINK                     "Telink Micro"
#define ZBEE_MFG_JASMINE                    "Jasmine Systems"
#define ZBEE_MFG_BIDGELY                    "Bidgely"
#define ZBEE_MFG_LUTRON                     "Lutron"
#define ZBEE_MFG_IJENKO                     "IJENKO"
#define ZBEE_MFG_STARFIELD                  "Starfield Electronic"
#define ZBEE_MFG_TCP                        "TCP"
#define ZBEE_MFG_ROGERS                     "Rogers Communications Partnership"
#define ZBEE_MFG_CREE                       "Cree"
#define ZBEE_MFG_ROBERT_BOSCH               "Robert Bosch"
#define ZBEE_MFG_IBIS                       "Ibis Networks"
#define ZBEE_MFG_QUIRKY                     "Quirky"
#define ZBEE_MFG_EFERGY                     "Efergy Technologies"
#define ZBEE_MFG_SMARTLABS                  "Smartlabs"
#define ZBEE_MFG_EVERSPRING                 "Everspring Industry"
#define ZBEE_MFG_SWANN                      "Swann Communications"
#define ZBEE_MFG_TI                         "Texas Instruments"

/* Protocol Abbreviations */
#define ZBEE_PROTOABBREV_NWK                "zbee_nwk"
#define ZBEE_PROTOABBREV_NWK_GP             "zbee_nwk_gp"
#define ZBEE_PROTOABBREV_NWK_GP_CMD         "zbee_nwk_gp_cmd"
#define ZBEE_PROTOABBREV_APS                "zbee_aps"
#define ZBEE_PROTOABBREV_ZCL                "zbee_zcl"
#define ZBEE_PROTOABBREV_ZCL_APPLCTRL       "zbee_zcl_general.applctrl"
#define ZBEE_PROTOABBREV_ZCL_BASIC          "zbee_zcl_general.basic"
#define ZBEE_PROTOABBREV_ZCL_POWER_CONFIG   "zbee_zcl_general.power_config"
#define ZBEE_PROTOABBREV_ZCL_DEVICE_TEMP_CONFIG   "zbee_zcl_general.device_temperature_config"
#define ZBEE_PROTOABBREV_ZCL_IDENTIFY       "zbee_zcl_general.identify"
#define ZBEE_PROTOABBREV_ZCL_GROUPS         "zbee_zcl_general.groups"
#define ZBEE_PROTOABBREV_ZCL_SCENES         "zbee_zcl_general.scenes"
#define ZBEE_PROTOABBREV_ZCL_ALARMS         "zbee_zcl_general.alarms"
#define ZBEE_PROTOABBREV_ZCL_TIME           "zbee_zcl_general.time"
#define ZBEE_PROTOABBREV_ZCL_PUMP_CONFIG_CTRL            "zbee_zcl_hvac.pump_config_ctrl"
#define ZBEE_PROTOABBREV_ZCL_THERMOSTAT     "zbee_zcl_hvac.thermostat"
#define ZBEE_PROTOABBREV_ZCL_FAN_CONTROL                 "zbee_zcl_hvac.fan_ctrl"
#define ZBEE_PROTOABBREV_ZCL_DEHUMIDIFICATION_CONTROL    "zbee_zcl_hvac.dehum_ctrl"
#define ZBEE_PROTOABBREV_ZCL_THERMOSTAT_UI_CONFIG        "zbee_zcl_hvac.thermo_ui_config"
#define ZBEE_PROTOABBREV_ZCL_APPLEVTALT     "zbee_zcl_ha.applevtalt"
#define ZBEE_PROTOABBREV_ZCL_APPLIDT        "zbee_zcl_ha.applident"
#define ZBEE_PROTOABBREV_ZCL_APPLSTATS      "zbee_zcl_ha.applstats"
#define ZBEE_PROTOABBREV_ZCL_METIDT         "zbee_zcl_ha.metidt"
#define ZBEE_PROTOABBREV_ZCL_IAS_ZONE       "zbee_zcl_ias.zone"
#define ZBEE_PROTOABBREV_ZCL_IAS_ACE        "zbee_zcl_ias.ace"
#define ZBEE_PROTOABBREV_ZCL_IAS_WD         "zbee_zcl_ias.wd"
#define ZBEE_PROTOABBREV_ZCL_ONOFF          "zbee_zcl_general.onoff"
#define ZBEE_PROTOABBREV_ZCL_ONOFF_SWITCH_CONFIG              "zbee_zcl_general.onoff.switch.configuration"
#define ZBEE_PROTOABBREV_ZCL_LEVEL_CONTROL  "zbee_zcl_general.level_control"
#define ZBEE_PROTOABBREV_ZCL_RSSI_LOCATION  "zbee_zcl_general.rssi_location"
#define ZBEE_PROTOABBREV_ZCL_OTA            "zbee_zcl_general.ota"
#define ZBEE_PROTOABBREV_ZCL_PART           "zbee_zcl_general.part"
#define ZBEE_PROTOABBREV_ZCL_POLL           "zbee_zcl_general.poll"
#define ZBEE_PROTOABBREV_ZCL_PWRPROF        "zbee_zcl_general.pwrprof"
#define ZBEE_PROTOABBREV_ZCL_COMMISSIONING  "zbee_zcl_general.commissioning"
#define ZBEE_PROTOABBREV_ZCL_MULTISTATE_VALUE_BASIC           "zbee_zcl_general.multistate.value.basic"
#define ZBEE_PROTOABBREV_ZCL_MULTISTATE_INPUT_BASIC           "zbee_zcl_general.multistate.input.basic"
#define ZBEE_PROTOABBREV_ZCL_MULTISTATE_OUTPUT_BASIC          "zbee_zcl_general.multistate.output.basic"
#define ZBEE_PROTOABBREV_ZCL_BINARY_INPUT_BASIC               "zbee_zcl_general.binary_input_basic"               /* Newly Added by SRIB */
#define ZBEE_PROTOABBREV_ZCL_BINARY_OUTPUT_BASIC              "zbee_zcl_general.binary_output_basic"              /* Newly Added by SRIB */
#define ZBEE_PROTOABBREV_ZCL_BINARY_VALUE_BASIC               "zbee_zcl_general.binary_value_basic"               /* Newly Added by SRIB */
#define ZBEE_PROTOABBREV_ZCL_ANALOG_VALUE_BASIC               "zbee_zcl_general.analog.value.basic"
#define ZBEE_PROTOABBREV_ZCL_ANALOG_INPUT_BASIC               "zbee_zcl_general.analog.input.basic"
#define ZBEE_PROTOABBREV_ZCL_ANALOG_OUTPUT_BASIC              "zbee_zcl_general.analog.output.basic"
#define ZBEE_PROTOABBREV_ZCL_ILLUMMEAS      "zbee_zcl_meas_sensing.illummeas"
#define ZBEE_PROTOABBREV_ZCL_ILLUMLEVELSEN  "zbee_zcl_meas_sensing.illumlevelsen"
#define ZBEE_PROTOABBREV_ZCL_PRESSMEAS      "zbee_zcl_meas_sensing.pressmeas"
#define ZBEE_PROTOABBREV_ZCL_FLOWMEAS       "zbee_zcl_meas_sensing.flowmeas"
#define ZBEE_PROTOABBREV_ZCL_RELHUMMEAS     "zbee_zcl_meas_sensing.relhummeas"
#define ZBEE_PROTOABBREV_ZCL_TEMPMEAS       "zbee_zcl_meas_sensing.tempmeas"
#define ZBEE_PROTOABBREV_ZCL_OCCSEN         "zbee_zcl_meas_sensing.occsen"
#define ZBEE_PROTOABBREV_ZCL_CAL            "zbee_zcl_se.cal"
#define ZBEE_PROTOABBREV_ZCL_KE             "zbee_zcl_se.ke"
#define ZBEE_PROTOABBREV_ZCL_MSG            "zbee_zcl_se.msg"
#define ZBEE_PROTOABBREV_ZCL_TUN            "zbee_zcl_se.tun"
#define ZBEE_PROTOABBREV_ZCL_SHADE_CONFIG   "zbee_zcl_closures.shade_config"
#define ZBEE_PROTOABBREV_ZCL_DOOR_LOCK      "zbee_zcl_closures.door_lock"
#define ZBEE_PROTOABBREV_ZCL_COLOR_CONTROL  "zbee_zcl_lighting.color_ctrl"
#define ZBEE_PROTOABBREV_ZCL_BALLAST_CONFIG "zbee_zcl_lighting.ballast_ctrl"
#define ZBEE_PROTOABBREV_ZCL_GP             "zbee_zcl_general.gp"

/* ZigBee Vendor Sub IE Fields */
#define ZBEE_ZIGBEE_IE_ID_MASK                      0xFFC0
#define ZBEE_ZIGBEE_IE_LENGTH_MASK                  0x003F
#define ZBEE_ZIGBEE_IE_REJOIN                         0x00
#define ZBEE_ZIGBEE_IE_TX_POWER                       0x01
#define ZBEE_ZIGBEE_IE_BEACON_PAYLOAD                 0x02

/* ZigBee PRO beacons */
#define ZBEE_ZIGBEE_BEACON_PROTOCOL_ID                0x00
#define ZBEE_ZIGBEE_BEACON_STACK_PROFILE              0x0f
#define ZBEE_ZIGBEE_BEACON_PROTOCOL_VERSION           0xf0
#define ZBEE_ZIGBEE_BEACON_ROUTER_CAPACITY            0x04
#define ZBEE_ZIGBEE_BEACON_NETWORK_DEPTH              0x78
#define ZBEE_ZIGBEE_BEACON_END_DEVICE_CAPACITY        0x80

/* Helper Functions */
extern guint zbee_get_bit_field(guint input, guint mask);

#endif /* PACKET_ZBEE_H */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
