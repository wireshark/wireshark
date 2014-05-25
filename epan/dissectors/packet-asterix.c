/* packet-asterix.c
 * Routines for ASTERIX decoding
 * By Marko Hrastovec <marko.hrastovec@sloveniacontrol.si>
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

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include "wmem/wmem.h"
#include <stdio.h>

void proto_register_asterix(void);
void proto_reg_handoff_asterix(void);

#define PROTO_TAG_ASTERIX   "ASTERIX"
#define ASTERIX_PORT        8600

#define MAX_DISSECT_STR     1024
#define MAX_BUFFER           256

static int proto_asterix = -1;

static gint hf_asterix_category = -1;
static gint hf_asterix_length = -1;
static gint hf_asterix_message = -1;
static gint hf_asterix_fspec = -1;
static gint hf_re_field_len = -1;
static gint hf_spare = -1;
static gint hf_counter = -1;
static gint hf_XXX_SAC = -1;
static gint hf_XXX_SIC = -1;
static gint hf_XXX_FX = -1;
/*static gint hf_XXX_2FX = -1;*/
static gint hf_XXX_3FX = -1;
static gint hf_XXX_TOD = -1;
static gint hf_XXX_AA = -1;
static gint hf_XXX_AI = -1;
static gint hf_XXX_MB_DATA = -1;
static gint hf_XXX_BDS1 = -1;
static gint hf_XXX_BDS2 = -1;
static gint hf_XXX_TN_16 = -1;
/* Category 001 */
static gint hf_001_010 = -1;
static gint hf_001_020 = -1;
static gint hf_001_020_TYP = -1;
static gint hf_001_020_SIM = -1;
static gint hf_001_020_SSR_PSR = -1;
static gint hf_001_020_ANT = -1;
static gint hf_001_020_SPI = -1;
static gint hf_001_020_RAB = -1;
static gint hf_001_020_TST = -1;
static gint hf_001_020_DS12 = -1;
static gint hf_001_020_ME = -1;
static gint hf_001_020_MI = -1;
static gint hf_001_030 = -1;
static gint hf_001_030_WE = -1;
static gint hf_001_040 = -1;
static gint hf_001_040_RHO = -1;
static gint hf_001_040_THETA = -1;
static gint hf_001_042 = -1;
static gint hf_001_042_X = -1;
static gint hf_001_042_Y = -1;
static gint hf_001_050 = -1;
static gint hf_001_060 = -1;
static gint hf_001_070 = -1;
static gint hf_001_070_V = -1;
static gint hf_001_070_G = -1;
static gint hf_001_070_L = -1;
static gint hf_001_070_SQUAWK = -1;
static gint hf_001_080 = -1;
static gint hf_001_080_QA4 = -1;
static gint hf_001_080_QA2 = -1;
static gint hf_001_080_QA1 = -1;
static gint hf_001_080_QB4 = -1;
static gint hf_001_080_QB2 = -1;
static gint hf_001_080_QB1 = -1;
static gint hf_001_080_QC4 = -1;
static gint hf_001_080_QC2 = -1;
static gint hf_001_080_QC1 = -1;
static gint hf_001_080_QD4 = -1;
static gint hf_001_080_QD2 = -1;
static gint hf_001_080_QD1 = -1;
static gint hf_001_090 = -1;
static gint hf_001_090_V = -1;
static gint hf_001_090_G = -1;
static gint hf_001_090_FL = -1;
static gint hf_001_100 = -1;
static gint hf_001_120 = -1;
static gint hf_001_130 = -1;
static gint hf_001_131 = -1;
static gint hf_001_141 = -1;
static gint hf_001_141_TTOD = -1;
static gint hf_001_150 = -1;
static gint hf_001_161 = -1;
static gint hf_001_161_TPN = -1;
static gint hf_001_170 = -1;
static gint hf_001_170_CON = -1;
static gint hf_001_170_RAD = -1;
static gint hf_001_170_MAN = -1;
static gint hf_001_170_DOU = -1;
static gint hf_001_170_RDPC = -1;
static gint hf_001_170_GHO = -1;
static gint hf_001_170_TRE = -1;
static gint hf_001_200 = -1;
static gint hf_001_210 = -1;
static gint hf_001_RE = -1;
static gint hf_001_SP = -1;
/* Category 002 */
static gint hf_002_000 = -1;
static gint hf_002_000_MT = -1;
static gint hf_002_010 = -1;
static gint hf_002_020 = -1;
static gint hf_002_020_SN = -1;
static gint hf_002_030 = -1;
static gint hf_002_041 = -1;
static gint hf_002_041_ARS = -1;
static gint hf_002_050 = -1;
static gint hf_002_060 = -1;
static gint hf_002_070 = -1;
static gint hf_002_070_A = -1;
static gint hf_002_070_IDENT = -1;
static gint hf_002_070_COUNTER = -1;
static gint hf_002_080 = -1;
static gint hf_002_080_WE = -1;
static gint hf_002_090 = -1;
static gint hf_002_090_RE = -1;
static gint hf_002_090_AE = -1;
static gint hf_002_100 = -1;
static gint hf_002_100_RHOS = -1;
static gint hf_002_100_RHOE = -1;
static gint hf_002_100_THETAS = -1;
static gint hf_002_100_THETAE = -1;
static gint hf_002_RE = -1;
static gint hf_002_SP = -1;
/* Category 008 */
static gint hf_008_000 = -1;
static gint hf_008_000_MT = -1;
static gint hf_008_010 = -1;
static gint hf_008_020 = -1;
static gint hf_008_020_ORG = -1;
static gint hf_008_020_INT = -1;
static gint hf_008_020_DIR = -1;
static gint hf_008_020_TST = -1;
static gint hf_008_020_ER = -1;
static gint hf_008_034 = -1;
static gint hf_008_034_START_RANGE = -1;
static gint hf_008_034_END_RANGE = -1;
static gint hf_008_034_AZIMUTH = -1;
static gint hf_008_036 = -1;
static gint hf_008_036_X = -1;
static gint hf_008_036_Y = -1;
static gint hf_008_036_VL = -1;
static gint hf_008_038 = -1;
static gint hf_008_038_X1 = -1;
static gint hf_008_038_Y1 = -1;
static gint hf_008_038_X2 = -1;
static gint hf_008_038_Y2 = -1;
static gint hf_008_040 = -1;
static gint hf_008_040_ORG = -1;
static gint hf_008_040_INT = -1;
static gint hf_008_040_FST_LST = -1;
static gint hf_008_040_CSN = -1;
static gint hf_008_050 = -1;
static gint hf_008_050_X1 = -1;
static gint hf_008_050_Y1 = -1;
static gint hf_008_090 = -1;
static gint hf_008_100 = -1;
static gint hf_008_100_f = -1;
static gint hf_008_100_R = -1;
static gint hf_008_100_Q = -1;
static gint hf_008_110 = -1;
static gint hf_008_110_HW = -1;
static gint hf_008_120 = -1;
static gint hf_008_120_COUNT = -1;
static gint hf_008_SP = -1;
static gint hf_008_RFS = -1;
/* Category 009 */
static gint hf_009_000 = -1;
static gint hf_009_000_MT = -1;
static gint hf_009_010 = -1;
static gint hf_009_020 = -1;
static gint hf_009_020_ORG = -1;
static gint hf_009_020_INT = -1;
static gint hf_009_020_DIR = -1;
static gint hf_009_030 = -1;
static gint hf_009_030_X = -1;
static gint hf_009_030_Y = -1;
static gint hf_009_030_VL = -1;
static gint hf_009_060 = -1;
static gint hf_009_060_STEP = -1;
static gint hf_009_070 = -1;
static gint hf_009_080 = -1;
static gint hf_009_080_SCALE = -1;
static gint hf_009_080_R = -1;
static gint hf_009_080_Q = -1;
static gint hf_009_090 = -1;
static gint hf_009_090_CP = -1;
static gint hf_009_090_WO = -1;
static gint hf_009_090_RS = -1;
static gint hf_009_100 = -1;
static gint hf_009_100_VC = -1;
/* Category 021 */
static gint hf_021_008 = -1;
static gint hf_021_008_RA = -1;
static gint hf_021_008_TC = -1;
static gint hf_021_008_TS = -1;
static gint hf_021_008_ARV = -1;
static gint hf_021_008_CDTIA = -1;
static gint hf_021_008_not_TCAS = -1;
static gint hf_021_008_SA = -1;
static gint hf_021_010 = -1;
static gint hf_021_015 = -1;
static gint hf_021_015_SI = -1;
static gint hf_021_016 = -1;
static gint hf_021_016_RP = -1;
static gint hf_021_020 = -1;
static gint hf_021_020_ECAT = -1;
static gint hf_021_040 = -1;
static gint hf_021_040_ATP = -1;
static gint hf_021_040_ARC = -1;
static gint hf_021_040_RC = -1;
static gint hf_021_040_RAB = -1;
static gint hf_021_040_DCR = -1;
static gint hf_021_040_GBS = -1;
static gint hf_021_040_SIM = -1;
static gint hf_021_040_TST = -1;
static gint hf_021_040_SAA = -1;
static gint hf_021_040_CL = -1;
static gint hf_021_040_IPC = -1;
static gint hf_021_040_NOGO = -1;
static gint hf_021_040_CPR = -1;
static gint hf_021_040_LDPJ = -1;
static gint hf_021_040_RCF = -1;
static gint hf_021_070 = -1;
static gint hf_021_070_SQUAWK = -1;
static gint hf_021_071 = -1;
static gint hf_021_072 = -1;
static gint hf_021_073 = -1;
static gint hf_021_074 = -1;
static gint hf_021_074_FSI = -1;
static gint hf_021_074_TOMRP = -1;
static gint hf_021_075 = -1;
static gint hf_021_076 = -1;
static gint hf_021_077 = -1;
static gint hf_021_076_FSI = -1;
static gint hf_021_076_TOMRV = -1;
static gint hf_021_080 = -1;
static gint hf_021_090 = -1;
static gint hf_021_090_NUCR_NACV = -1;
static gint hf_021_090_NUCP_NIC = -1;
static gint hf_021_090_NIC_BARO = -1;
static gint hf_021_090_SIL = -1;
static gint hf_021_090_NACP = -1;
static gint hf_021_090_SIL_SUP = -1;
static gint hf_021_090_SDA = -1;
static gint hf_021_090_GVA = -1;
static gint hf_021_090_PIC = -1;
static gint hf_021_110 = -1;
static gint hf_021_110_01 = -1;
static gint hf_021_110_01_NAV = -1;
static gint hf_021_110_01_NVB = -1;
static gint hf_021_110_02 = -1;
static gint hf_021_110_02_TCA = -1;
static gint hf_021_110_02_NC = -1;
static gint hf_021_110_02_TCPNo = -1;
static gint hf_021_110_02_ALT = -1;
static gint hf_021_110_02_LAT = -1;
static gint hf_021_110_02_LON = -1;
static gint hf_021_110_02_PT = -1;
static gint hf_021_110_02_TD = -1;
static gint hf_021_110_02_TRA = -1;
static gint hf_021_110_02_TOA = -1;
static gint hf_021_110_02_TOV = -1;
static gint hf_021_110_02_TTR = -1;
static gint hf_021_130 = -1;
static gint hf_021_130_LAT = -1;
static gint hf_021_130_LON = -1;
static gint hf_021_131 = -1;
static gint hf_021_131_LAT = -1;
static gint hf_021_131_LON = -1;
static gint hf_021_132 = -1;
static gint hf_021_132_MAM = -1;
static gint hf_021_140 = -1;
static gint hf_021_140_GH = -1;
static gint hf_021_145 = -1;
static gint hf_021_145_FL = -1;
static gint hf_021_146 = -1;
static gint hf_021_146_SAS = -1;
static gint hf_021_146_Source = -1;
static gint hf_021_146_ALT = -1;
static gint hf_021_148 = -1;
static gint hf_021_148_MV = -1;
static gint hf_021_148_AH = -1;
static gint hf_021_148_AM = -1;
static gint hf_021_148_ALT = -1;
static gint hf_021_150 = -1;
static gint hf_021_150_IM = -1;
static gint hf_021_150_ASPD = -1;
static gint hf_021_151 = -1;
static gint hf_021_151_RE = -1;
static gint hf_021_151_TASPD = -1;
static gint hf_021_152 = -1;
static gint hf_021_152_MHDG = -1;
static gint hf_021_155 = -1;
static gint hf_021_155_RE = -1;
static gint hf_021_155_BVR = -1;
static gint hf_021_157 = -1;
static gint hf_021_157_RE = -1;
static gint hf_021_157_GVR = -1;
static gint hf_021_160 = -1;
static gint hf_021_160_RE = -1;
static gint hf_021_160_GSPD = -1;
static gint hf_021_160_TA = -1;
static gint hf_021_161 = -1;
static gint hf_021_161_TN = -1;
static gint hf_021_165 = -1;
static gint hf_021_165_TAR = -1;
static gint hf_021_170 = -1;
static gint hf_021_200 = -1;
static gint hf_021_200_ICF = -1;
static gint hf_021_200_LNAV = -1;
static gint hf_021_200_PS = -1;
static gint hf_021_200_SS = -1;
static gint hf_021_210 = -1;
static gint hf_021_210_VNS = -1;
static gint hf_021_210_VN = -1;
static gint hf_021_210_LTT = -1;
static gint hf_021_220 = -1;
static gint hf_021_220_01 = -1;
static gint hf_021_220_01_WSPD = -1;
static gint hf_021_220_02 = -1;
static gint hf_021_220_02_WDIR = -1;
static gint hf_021_220_03 = -1;
static gint hf_021_220_03_TEMP = -1;
static gint hf_021_220_04 = -1;
static gint hf_021_220_04_TURB = -1;
static gint hf_021_230 = -1;
static gint hf_021_230_RA = -1;
static gint hf_021_250 = -1;
static gint hf_021_260 = -1;
static gint hf_021_260_TYP = -1;
static gint hf_021_260_STYP = -1;
static gint hf_021_260_ARA = -1;
static gint hf_021_260_RAC = -1;
static gint hf_021_260_RAT = -1;
static gint hf_021_260_MTE = -1;
static gint hf_021_260_TTI = -1;
static gint hf_021_260_TID = -1;
static gint hf_021_271 = -1;
static gint hf_021_271_POA = -1;
static gint hf_021_271_CDTIS = -1;
static gint hf_021_271_B2low = -1;
static gint hf_021_271_RAS = -1;
static gint hf_021_271_IDENT = -1;
static gint hf_021_271_LW = -1;
static gint hf_021_295 = -1;
static gint hf_021_295_01 = -1;
static gint hf_021_295_01_AOS = -1;
static gint hf_021_295_02 = -1;
static gint hf_021_295_02_TRD = -1;
static gint hf_021_295_03 = -1;
static gint hf_021_295_03_M3A = -1;
static gint hf_021_295_04 = -1;
static gint hf_021_295_04_QI = -1;
static gint hf_021_295_05 = -1;
static gint hf_021_295_05_TI = -1;
static gint hf_021_295_06 = -1;
static gint hf_021_295_06_MAM = -1;
static gint hf_021_295_07 = -1;
static gint hf_021_295_07_GH = -1;
static gint hf_021_295_08 = -1;
static gint hf_021_295_08_FL = -1;
static gint hf_021_295_09 = -1;
static gint hf_021_295_09_ISA = -1;
static gint hf_021_295_10 = -1;
static gint hf_021_295_10_FSA = -1;
static gint hf_021_295_11 = -1;
static gint hf_021_295_11_AS = -1;
static gint hf_021_295_12 = -1;
static gint hf_021_295_12_TAS = -1;
static gint hf_021_295_13 = -1;
static gint hf_021_295_13_MH = -1;
static gint hf_021_295_14 = -1;
static gint hf_021_295_14_BVR = -1;
static gint hf_021_295_15 = -1;
static gint hf_021_295_15_GVR = -1;
static gint hf_021_295_16 = -1;
static gint hf_021_295_16_GV = -1;
static gint hf_021_295_17 = -1;
static gint hf_021_295_17_TAR = -1;
static gint hf_021_295_18 = -1;
static gint hf_021_295_18_TI = -1;
static gint hf_021_295_19 = -1;
static gint hf_021_295_19_TS = -1;
static gint hf_021_295_20 = -1;
static gint hf_021_295_20_MET = -1;
static gint hf_021_295_21 = -1;
static gint hf_021_295_21_ROA = -1;
static gint hf_021_295_22 = -1;
static gint hf_021_295_22_ARA = -1;
static gint hf_021_295_23 = -1;
static gint hf_021_295_23_SCC = -1;
static gint hf_021_400 = -1;
static gint hf_021_400_RID = -1;
static gint hf_021_RE = -1;
static gint hf_021_SP = -1;
/* Category 023 */
static gint hf_023_000 = -1;
static gint hf_023_000_RT = -1;
static gint hf_023_010 = -1;
static gint hf_023_015 = -1;
static gint hf_023_015_SID = -1;
static gint hf_023_015_STYPE = -1;
static gint hf_023_070 = -1;
static gint hf_023_100 = -1;
static gint hf_023_100_NOGO = -1;
static gint hf_023_100_ODP = -1;
static gint hf_023_100_OXT = -1;
static gint hf_023_100_MSC = -1;
static gint hf_023_100_TSV = -1;
static gint hf_023_100_SPO = -1;
static gint hf_023_100_RN = -1;
static gint hf_023_100_GSSP = -1;
static gint hf_023_101 = -1;
static gint hf_023_101_RP = -1;
static gint hf_023_101_SC = -1;
static gint hf_023_101_SSRP = -1;
static gint hf_023_110 = -1;
static gint hf_023_110_STAT = -1;
static gint hf_023_120 = -1;
static gint hf_023_120_TYPE = -1;
static gint hf_023_120_REF = -1;
static gint hf_023_120_COUNTER = -1;
static gint hf_023_200 = -1;
static gint hf_023_200_RANGE = -1;
static gint hf_023_RE = -1;
static gint hf_023_SP = -1;
/* Category 034 */
static gint hf_034_000 = -1;
static gint hf_034_000_MT = -1;
static gint hf_034_010 = -1;
static gint hf_034_020 = -1;
static gint hf_034_020_SN = -1;
static gint hf_034_030 = -1;
static gint hf_034_041 = -1;
static gint hf_034_041_ARS = -1;
static gint hf_034_050 = -1;
static gint hf_034_050_01 = -1;
static gint hf_034_050_01_NOGO = -1;
static gint hf_034_050_01_RDPC = -1;
static gint hf_034_050_01_RDPR = -1;
static gint hf_034_050_01_OVL_RDP = -1;
static gint hf_034_050_01_OVL_XMT = -1;
static gint hf_034_050_01_MSC = -1;
static gint hf_034_050_01_TSV = -1;
static gint hf_034_050_02 = -1;
static gint hf_034_050_02_ANT = -1;
static gint hf_034_050_02_CHAB = -1;
static gint hf_034_050_02_OVL = -1;
static gint hf_034_050_02_MSC = -1;
static gint hf_034_050_03 = -1;
static gint hf_034_050_03_ANT = -1;
static gint hf_034_050_03_CHAB = -1;
static gint hf_034_050_03_OVL = -1;
static gint hf_034_050_03_MSC = -1;
static gint hf_034_050_04 = -1;
static gint hf_034_050_04_ANT = -1;
static gint hf_034_050_04_CHAB = -1;
static gint hf_034_050_04_OVL_SUR = -1;
static gint hf_034_050_04_MSC = -1;
static gint hf_034_050_04_SCF = -1;
static gint hf_034_050_04_DLF = -1;
static gint hf_034_050_04_OVL_SCF = -1;
static gint hf_034_050_04_OVL_DLF = -1;
static gint hf_034_060 = -1;
static gint hf_034_060_01 = -1;
static gint hf_034_060_01_RED_RDP = -1;
static gint hf_034_060_01_RED_XMT = -1;
static gint hf_034_060_02 = -1;
static gint hf_034_060_02_POL = -1;
static gint hf_034_060_02_RED_RAD = -1;
static gint hf_034_060_02_STC = -1;
static gint hf_034_060_03 = -1;
static gint hf_034_060_03_RED_RAD = -1;
static gint hf_034_060_04 = -1;
static gint hf_034_060_04_RED_RAD = -1;
static gint hf_034_060_04_CLU = -1;
static gint hf_034_070 = -1;
static gint hf_034_070_TYP = -1;
static gint hf_034_070_COUNTER = -1;
static gint hf_034_090 = -1;
static gint hf_034_090_RE = -1;
static gint hf_034_090_AE = -1;
static gint hf_034_100 = -1;
static gint hf_035_100_RHOS = -1;
static gint hf_035_100_RHOE = -1;
static gint hf_035_100_THETAS = -1;
static gint hf_035_100_THETAE = -1;
static gint hf_034_110 = -1;
static gint hf_034_110_TYP = -1;
static gint hf_034_120 = -1;
static gint hf_034_120_H = -1;
static gint hf_034_120_LAT = -1;
static gint hf_034_120_LON = -1;
static gint hf_034_RE = -1;
static gint hf_034_SP = -1;
/* Category 048 */
static gint hf_048_010 = -1;
static gint hf_048_020 = -1;
static gint hf_048_020_TYP = -1;
static gint hf_048_020_SIM = -1;
static gint hf_048_020_RDP = -1;
static gint hf_048_020_SPI = -1;
static gint hf_048_020_RAB = -1;
static gint hf_048_020_TST = -1;
static gint hf_048_020_ME = -1;
static gint hf_048_020_MI = -1;
static gint hf_048_020_FOE = -1;
static gint hf_048_030 = -1;
static gint hf_048_030_WE = -1;
static gint hf_048_040 = -1;
static gint hf_048_040_RHO = -1;
static gint hf_048_040_THETA = -1;
static gint hf_048_042 = -1;
static gint hf_048_042_X = -1;
static gint hf_048_042_Y = -1;
static gint hf_048_050 = -1;
static gint hf_048_050_V = -1;
static gint hf_048_050_G = -1;
static gint hf_048_050_L = -1;
static gint hf_048_050_SQUAWK = -1;
static gint hf_048_055 = -1;
static gint hf_048_055_V = -1;
static gint hf_048_055_G = -1;
static gint hf_048_055_L = -1;
static gint hf_048_055_CODE = -1;
static gint hf_048_060 = -1;
static gint hf_048_060_QA4 = -1;
static gint hf_048_060_QA2 = -1;
static gint hf_048_060_QA1 = -1;
static gint hf_048_060_QB4 = -1;
static gint hf_048_060_QB2 = -1;
static gint hf_048_060_QB1 = -1;
static gint hf_048_060_QC4 = -1;
static gint hf_048_060_QC2 = -1;
static gint hf_048_060_QC1 = -1;
static gint hf_048_060_QD4 = -1;
static gint hf_048_060_QD2 = -1;
static gint hf_048_060_QD1 = -1;
static gint hf_048_065 = -1;
static gint hf_048_065_QA4 = -1;
static gint hf_048_065_QA2 = -1;
static gint hf_048_065_QA1 = -1;
static gint hf_048_065_QB2 = -1;
static gint hf_048_065_QB1 = -1;
static gint hf_048_070 = -1;
static gint hf_048_070_V = -1;
static gint hf_048_070_G = -1;
static gint hf_048_070_L = -1;
static gint hf_048_070_SQUAWK = -1;
static gint hf_048_080 = -1;
static gint hf_048_080_QA4 = -1;
static gint hf_048_080_QA2 = -1;
static gint hf_048_080_QA1 = -1;
static gint hf_048_080_QB4 = -1;
static gint hf_048_080_QB2 = -1;
static gint hf_048_080_QB1 = -1;
static gint hf_048_080_QC4 = -1;
static gint hf_048_080_QC2 = -1;
static gint hf_048_080_QC1 = -1;
static gint hf_048_080_QD4 = -1;
static gint hf_048_080_QD2 = -1;
static gint hf_048_080_QD1 = -1;
static gint hf_048_090 = -1;
static gint hf_048_090_V = -1;
static gint hf_048_090_G = -1;
static gint hf_048_090_FL = -1;
static gint hf_048_100 = -1;
static gint hf_048_100_V = -1;
static gint hf_048_100_G = -1;
static gint hf_048_100_A4 = -1;
static gint hf_048_100_A2 = -1;
static gint hf_048_100_A1 = -1;
static gint hf_048_100_B4 = -1;
static gint hf_048_100_B2 = -1;
static gint hf_048_100_B1 = -1;
static gint hf_048_100_C4 = -1;
static gint hf_048_100_C2 = -1;
static gint hf_048_100_C1 = -1;
static gint hf_048_100_D4 = -1;
static gint hf_048_100_D2 = -1;
static gint hf_048_100_D1 = -1;
static gint hf_048_100_QA4 = -1;
static gint hf_048_100_QA2 = -1;
static gint hf_048_100_QA1 = -1;
static gint hf_048_100_QB4 = -1;
static gint hf_048_100_QB2 = -1;
static gint hf_048_100_QB1 = -1;
static gint hf_048_100_QC4 = -1;
static gint hf_048_100_QC2 = -1;
static gint hf_048_100_QC1 = -1;
static gint hf_048_100_QD4 = -1;
static gint hf_048_100_QD2 = -1;
static gint hf_048_100_QD1 = -1;
static gint hf_048_110 = -1;
static gint hf_048_110_3DHEIGHT = -1;
static gint hf_048_120 = -1;
static gint hf_048_120_01 = -1;
static gint hf_048_120_01_D = -1;
static gint hf_048_120_01_CAL = -1;
static gint hf_048_120_02 = -1;
static gint hf_048_120_02_DOP = -1;
static gint hf_048_120_02_AMB = -1;
static gint hf_048_120_02_FRQ = -1;
static gint hf_048_130 = -1;
static gint hf_048_130_01 = -1;
static gint hf_048_130_01_SRL = -1;
static gint hf_048_130_02 = -1;
static gint hf_048_130_02_SRR = -1;
static gint hf_048_130_03 = -1;
static gint hf_048_130_03_SAM = -1;
static gint hf_048_130_04 = -1;
static gint hf_048_130_04_PRL = -1;
static gint hf_048_130_05 = -1;
static gint hf_048_130_05_PAM = -1;
static gint hf_048_130_06 = -1;
static gint hf_048_130_06_RPD = -1;
static gint hf_048_130_07 = -1;
static gint hf_048_130_07_APD = -1;
static gint hf_048_140 = -1;
static gint hf_048_161 = -1;
static gint hf_048_161_TN = -1;
static gint hf_048_170 = -1;
static gint hf_048_170_CNF = -1;
static gint hf_048_170_RAD = -1;
static gint hf_048_170_DOU = -1;
static gint hf_048_170_MAH = -1;
static gint hf_048_170_CDM = -1;
static gint hf_048_170_TRE = -1;
static gint hf_048_170_GHO = -1;
static gint hf_048_170_SUP = -1;
static gint hf_048_170_TCC = -1;
static gint hf_048_200 = -1;
static gint hf_048_200_GS = -1;
static gint hf_048_200_HDG = -1;
static gint hf_048_210 = -1;
static gint hf_048_210_X = -1;
static gint hf_048_210_Y = -1;
static gint hf_048_210_V = -1;
static gint hf_048_210_H = -1;
static gint hf_048_220 = -1;
static gint hf_048_230 = -1;
static gint hf_048_230_COM = -1;
static gint hf_048_230_STAT = -1;
static gint hf_048_230_SI = -1;
static gint hf_048_230_MSSC = -1;
static gint hf_048_230_ARC = -1;
static gint hf_048_230_AIC = -1;
static gint hf_048_230_B1A = -1;
static gint hf_048_230_B1B = -1;
static gint hf_048_240 = -1;
static gint hf_048_250 = -1;
static gint hf_048_260 = -1;
static gint hf_048_260_ACAS = -1;
static gint hf_048_RE = -1;
static gint hf_048_SP = -1;
/* Category 062*/
static gint hf_062_010 = -1;
static gint hf_062_015 = -1;
static gint hf_062_015_SI = -1;
static gint hf_062_040 = -1;
static gint hf_062_060 = -1;
static gint hf_062_060_CH = -1;
static gint hf_062_060_SQUAWK = -1;
static gint hf_062_070 = -1;
static gint hf_062_080 = -1;
static gint hf_062_080_MON = -1;
static gint hf_062_080_SPI = -1;
static gint hf_062_080_MRH = -1;
static gint hf_062_080_SRC = -1;
static gint hf_062_080_CNF = -1;
static gint hf_062_080_SIM = -1;
static gint hf_062_080_TSE = -1;
static gint hf_062_080_TSB = -1;
static gint hf_062_080_FPC = -1;
static gint hf_062_080_AFF = -1;
static gint hf_062_080_STP = -1;
static gint hf_062_080_KOS = -1;
static gint hf_062_080_AMA = -1;
static gint hf_062_080_MD4 = -1;
static gint hf_062_080_ME = -1;
static gint hf_062_080_MI = -1;
static gint hf_062_080_MD5 = -1;
static gint hf_062_080_CST = -1;
static gint hf_062_080_PSR = -1;
static gint hf_062_080_SSR = -1;
static gint hf_062_080_MDS = -1;
static gint hf_062_080_ADS = -1;
static gint hf_062_080_SUC = -1;
static gint hf_062_080_AAC = -1;
static gint hf_062_080_SDS = -1;
static gint hf_062_080_EMS = -1;
static gint hf_062_080_PFT = -1;
static gint hf_062_080_FPLT = -1;
static gint hf_062_080_DUPT = -1;
static gint hf_062_080_DUPF = -1;
static gint hf_062_080_DUPM = -1;
static gint hf_062_080_FRIFOE = -1;
static gint hf_062_080_COA = -1;
static gint hf_062_100 = -1;
static gint hf_062_100_X = -1;
static gint hf_062_100_Y = -1;
static gint hf_062_100_X_v0_17 = -1;
static gint hf_062_100_Y_v0_17 = -1;
static gint hf_062_105 = -1;
static gint hf_062_105_LAT = -1;
static gint hf_062_105_LON = -1;
static gint hf_062_110 = -1;
static gint hf_062_110_01 = -1;
static gint hf_062_110_01_M5 = -1;
static gint hf_062_110_01_ID = -1;
static gint hf_062_110_01_DA = -1;
static gint hf_062_110_01_M1 = -1;
static gint hf_062_110_01_M2 = -1;
static gint hf_062_110_01_M3 = -1;
static gint hf_062_110_01_MC = -1;
static gint hf_062_110_01_X = -1;
static gint hf_062_110_02 = -1;
static gint hf_062_110_02_PIN = -1;
static gint hf_062_110_02_NAT = -1;
static gint hf_062_110_02_MIS = -1;
static gint hf_062_110_03 = -1;
static gint hf_062_110_03_LAT = -1;
static gint hf_062_110_03_LON = -1;
static gint hf_062_110_04 = -1;
static gint hf_062_110_04_RES = -1;
static gint hf_062_110_04_GA = -1;
static gint hf_062_110_05 = -1;
static gint hf_062_110_05_SQUAWK = -1;
static gint hf_062_110_06 = -1;
static gint hf_062_110_06_TOS = -1;
static gint hf_062_110_07 = -1;
static gint hf_062_110_07_X5 = -1;
static gint hf_062_110_07_XC = -1;
static gint hf_062_110_07_X3 = -1;
static gint hf_062_110_07_X2 = -1;
static gint hf_062_110_07_X1 = -1;
/* v.0.17 */
static gint hf_062_110_v0_17 = -1;
static gint hf_062_110_A4 = -1;
static gint hf_062_110_A2 = -1;
static gint hf_062_110_A1 = -1;
static gint hf_062_110_B2 = -1;
static gint hf_062_110_B1 = -1;
static gint hf_062_120 = -1;
static gint hf_062_120_SQUAWK = -1;
static gint hf_062_130 = -1;
static gint hf_062_130_ALT = -1;
static gint hf_062_135 = -1;
static gint hf_062_135_QNH = -1;
static gint hf_062_135_ALT = -1;
static gint hf_062_136 = -1;
static gint hf_062_136_ALT = -1;
static gint hf_062_180 = -1;
static gint hf_062_180_SPEED = -1;
static gint hf_062_180_HEADING = -1;
static gint hf_062_185 = -1;
static gint hf_062_185_VX = -1;
static gint hf_062_185_VY = -1;
static gint hf_062_200 = -1;
static gint hf_062_200_TRANS = -1;
static gint hf_062_200_LONG = -1;
static gint hf_062_200_VERT = -1;
static gint hf_062_200_ADF = -1;
static gint hf_062_210 = -1;
static gint hf_062_210_AX = -1;
static gint hf_062_210_AY = -1;
static gint hf_062_210_CLA = -1;
static gint hf_062_210_v0_17 = -1;
static gint hf_062_220 = -1;
static gint hf_062_220_ROCD = -1;
static gint hf_062_240 = -1;
static gint hf_062_240_ROT = -1;
static gint hf_062_245 = -1;
static gint hf_062_270 = -1;
static gint hf_062_270_LENGTH = -1;
static gint hf_062_270_ORIENTATION = -1;
static gint hf_062_270_WIDTH = -1;
static gint hf_062_290 = -1;
static gint hf_062_290_01 = -1;
static gint hf_062_290_01_TRK = -1;
static gint hf_062_290_02 = -1;
static gint hf_062_290_02_PSR = -1;
static gint hf_062_290_03 = -1;
static gint hf_062_290_03_SSR = -1;
static gint hf_062_290_04 = -1;
static gint hf_062_290_04_MDS = -1;
static gint hf_062_290_05 = -1;
static gint hf_062_290_05_ADS = -1;
static gint hf_062_290_06 = -1;
static gint hf_062_290_06_ES = -1;
static gint hf_062_290_07 = -1;
static gint hf_062_290_07_VDL = -1;
static gint hf_062_290_08 = -1;
static gint hf_062_290_08_UAT = -1;
static gint hf_062_290_09 = -1;
static gint hf_062_290_09_LOP = -1;
static gint hf_062_290_10 = -1;
static gint hf_062_290_10_MLT = -1;
/* v.0.17 */
static gint hf_062_290_01_v0_17 = -1;
static gint hf_062_290_01_PSR = -1;
static gint hf_062_290_02_v0_17 = -1;
static gint hf_062_290_02_SSR = -1;
static gint hf_062_290_03_v0_17 = -1;
static gint hf_062_290_03_MDA = -1;
static gint hf_062_290_04_v0_17 = -1;
static gint hf_062_290_04_MFL = -1;
static gint hf_062_290_05_v0_17 = -1;
static gint hf_062_290_05_MDS = -1;
static gint hf_062_290_06_v0_17 = -1;
static gint hf_062_290_06_ADS = -1;
static gint hf_062_290_07_v0_17 = -1;
static gint hf_062_290_07_ADB = -1;
static gint hf_062_290_08_v0_17 = -1;
static gint hf_062_290_08_MD1 = -1;
static gint hf_062_290_09_v0_17 = -1;
static gint hf_062_290_09_MD2 = -1;
static gint hf_062_295 = -1;
static gint hf_062_295_01 = -1;
static gint hf_062_295_01_MFL = -1;
static gint hf_062_295_02 = -1;
static gint hf_062_295_02_MD1 = -1;
static gint hf_062_295_03 = -1;
static gint hf_062_295_03_MD2 = -1;
static gint hf_062_295_04 = -1;
static gint hf_062_295_04_MDA = -1;
static gint hf_062_295_05 = -1;
static gint hf_062_295_05_MD4 = -1;
static gint hf_062_295_06 = -1;
static gint hf_062_295_06_MD5 = -1;
static gint hf_062_295_07 = -1;
static gint hf_062_295_07_MHD = -1;
static gint hf_062_295_08 = -1;
static gint hf_062_295_08_IAS = -1;
static gint hf_062_295_09 = -1;
static gint hf_062_295_09_TAS = -1;
static gint hf_062_295_10 = -1;
static gint hf_062_295_10_SAL = -1;
static gint hf_062_295_11 = -1;
static gint hf_062_295_11_FSS = -1;
static gint hf_062_295_12 = -1;
static gint hf_062_295_12_TID = -1;
static gint hf_062_295_13 = -1;
static gint hf_062_295_13_COM = -1;
static gint hf_062_295_14 = -1;
static gint hf_062_295_14_SAB = -1;
static gint hf_062_295_15 = -1;
static gint hf_062_295_15_ACS = -1;
static gint hf_062_295_16 = -1;
static gint hf_062_295_16_BVR = -1;
static gint hf_062_295_17 = -1;
static gint hf_062_295_17_GVR = -1;
static gint hf_062_295_18 = -1;
static gint hf_062_295_18_RAN = -1;
static gint hf_062_295_19 = -1;
static gint hf_062_295_19_TAR = -1;
static gint hf_062_295_20 = -1;
static gint hf_062_295_20_TAN = -1;
static gint hf_062_295_21 = -1;
static gint hf_062_295_21_GSP = -1;
static gint hf_062_295_22 = -1;
static gint hf_062_295_22_VUN = -1;
static gint hf_062_295_23 = -1;
static gint hf_062_295_23_MET = -1;
static gint hf_062_295_24 = -1;
static gint hf_062_295_24_EMC = -1;
static gint hf_062_295_25 = -1;
static gint hf_062_295_25_POS = -1;
static gint hf_062_295_26 = -1;
static gint hf_062_295_26_GAL = -1;
static gint hf_062_295_27 = -1;
static gint hf_062_295_27_PUN = -1;
static gint hf_062_295_28 = -1;
static gint hf_062_295_28_MB = -1;
static gint hf_062_295_29 = -1;
static gint hf_062_295_29_IAR = -1;
static gint hf_062_295_30 = -1;
static gint hf_062_295_30_MAC = -1;
static gint hf_062_295_31 = -1;
static gint hf_062_295_31_BPS = -1;
static gint hf_062_300 = -1;
static gint hf_062_300_VFI = -1;
static gint hf_062_340 = -1;
static gint hf_062_340_01 = -1;
static gint hf_062_340_02 = -1;
static gint hf_062_340_02_RHO = -1;
static gint hf_062_340_02_THETA = -1;
static gint hf_062_340_03 = -1;
static gint hf_062_340_03_H = -1;
static gint hf_062_340_04 = -1;
static gint hf_062_340_04_V = -1;
static gint hf_062_340_04_G = -1;
static gint hf_062_340_04_FL = -1;
static gint hf_062_340_05 = -1;
static gint hf_062_340_05_V = -1;
static gint hf_062_340_05_G = -1;
static gint hf_062_340_05_L = -1;
static gint hf_062_340_05_SQUAWK = -1;
static gint hf_062_340_06 = -1;
static gint hf_062_340_06_TYP = -1;
static gint hf_062_340_06_SIM = -1;
static gint hf_062_340_06_RAB = -1;
static gint hf_062_340_06_TST = -1;
static gint hf_062_380 = -1;
static gint hf_062_380_01 = -1;
static gint hf_062_380_02 = -1;
static gint hf_062_380_03 = -1;
static gint hf_062_380_03_MH = -1;
static gint hf_062_380_04 = -1;
static gint hf_062_380_04_IM = -1;
static gint hf_062_380_04_IAS = -1;
static gint hf_062_380_05 = -1;
static gint hf_062_380_05_TAS = -1;
static gint hf_062_380_06 = -1;
static gint hf_062_380_06_SAS = -1;
static gint hf_062_380_06_SOURCE = -1;
static gint hf_062_380_06_ALT = -1;
static gint hf_062_380_07 = -1;
static gint hf_062_380_07_MV = -1;
static gint hf_062_380_07_AH = -1;
static gint hf_062_380_07_AM = -1;
static gint hf_062_380_07_ALT = -1;
static gint hf_062_380_08 = -1;
static gint hf_062_380_08_NAV = -1;
static gint hf_062_380_08_NVB = -1;
static gint hf_062_380_09 = -1;
static gint hf_062_380_09_TCA = -1;
static gint hf_062_380_09_NC = -1;
static gint hf_062_380_09_TCP = -1;
static gint hf_062_380_09_ALT = -1;
static gint hf_062_380_09_LAT = -1;
static gint hf_062_380_09_LON = -1;
static gint hf_062_380_09_PTYP = -1;
static gint hf_062_380_09_TD = -1;
static gint hf_062_380_09_TRA = -1;
static gint hf_062_380_09_TOA = -1;
static gint hf_062_380_09_TOV = -1;
static gint hf_062_380_09_TTR = -1;
static gint hf_062_380_10 = -1;
static gint hf_062_380_10_COM = -1;
static gint hf_062_380_10_STAT = -1;
static gint hf_062_380_10_SSC = -1;
static gint hf_062_380_10_ARC = -1;
static gint hf_062_380_10_AIC = -1;
static gint hf_062_380_10_B1A = -1;
static gint hf_062_380_10_B1B = -1;
static gint hf_062_380_11 = -1;
static gint hf_062_380_11_AC = -1;
static gint hf_062_380_11_MN = -1;
static gint hf_062_380_11_DC = -1;
static gint hf_062_380_11_GBS = -1;
static gint hf_062_380_11_STAT = -1;
static gint hf_062_380_12 = -1;
static gint hf_062_380_12_MB = -1;
static gint hf_062_380_13 = -1;
static gint hf_062_380_13_BVR = -1;
static gint hf_062_380_14 = -1;
static gint hf_062_380_14_GVR = -1;
static gint hf_062_380_15 = -1;
static gint hf_062_380_15_ROLL = -1;
static gint hf_062_380_16 = -1;
static gint hf_062_380_16_TI = -1;
static gint hf_062_380_16_RATE = -1;
static gint hf_062_380_17 = -1;
static gint hf_062_380_17_TA = -1;
static gint hf_062_380_18 = -1;
static gint hf_062_380_18_GS = -1;
static gint hf_062_380_19 = -1;
static gint hf_062_380_19_VUC = -1;
static gint hf_062_380_20 = -1;
static gint hf_062_380_20_WS = -1;
static gint hf_062_380_20_WD = -1;
static gint hf_062_380_20_TMP = -1;
static gint hf_062_380_20_TRB = -1;
static gint hf_062_380_20_WS_VAL = -1;
static gint hf_062_380_20_WD_VAL = -1;
static gint hf_062_380_20_TMP_VAL = -1;
static gint hf_062_380_20_TRB_VAL = -1;
static gint hf_062_380_21 = -1;
static gint hf_062_380_21_ECAT = -1;
static gint hf_062_380_22 = -1;
static gint hf_062_380_22_LAT = -1;
static gint hf_062_380_22_LON = -1;
static gint hf_062_380_23 = -1;
static gint hf_062_380_23_ALT = -1;
static gint hf_062_380_24 = -1;
static gint hf_062_380_24_PUN = -1;
static gint hf_062_380_25 = -1;
static gint hf_062_380_26 = -1;
static gint hf_062_380_26_IAS = -1;
static gint hf_062_380_27 = -1;
static gint hf_062_380_27_MACH = -1;
static gint hf_062_380_28 = -1;
static gint hf_062_380_28_BPS = -1;
/* v.0.17 */
static gint hf_062_380_v0_17 = -1;
static gint hf_062_380_01_v0_17 = -1;
static gint hf_062_380_02_v0_17 = -1;
static gint hf_062_380_03_v0_17 = -1;
static gint hf_062_380_04_v0_17 = -1;
static gint hf_062_380_04_COM = -1;
static gint hf_062_380_04_STAT = -1;
static gint hf_062_380_04_SSC = -1;
static gint hf_062_380_04_ARC = -1;
static gint hf_062_380_04_AIC = -1;
static gint hf_062_380_04_B1A = -1;
static gint hf_062_380_04_B1B = -1;
static gint hf_062_380_05_v0_17 = -1;
static gint hf_062_380_05_MB = -1;
static gint hf_062_390 = -1;
static gint hf_062_390_01 = -1;
static gint hf_062_390_02 = -1;
static gint hf_062_390_02_CS = -1;
static gint hf_062_390_03 = -1;
static gint hf_062_390_03_TYP = -1;
static gint hf_062_390_03_NBR = -1;
static gint hf_062_390_04 = -1;
static gint hf_062_390_04_GAT_OAT = -1;
static gint hf_062_390_04_FR12 = -1;
static gint hf_062_390_04_RVSM = -1;
static gint hf_062_390_04_HPR = -1;
static gint hf_062_390_05 = -1;
static gint hf_062_390_05_ACTYP = -1;
static gint hf_062_390_06 = -1;
static gint hf_062_390_06_WTC = -1;
static gint hf_062_390_07 = -1;
static gint hf_062_390_07_ADEP = -1;
static gint hf_062_390_08 = -1;
static gint hf_062_390_08_ADES = -1;
static gint hf_062_390_09 = -1;
static gint hf_062_390_09_NU1 = -1;
static gint hf_062_390_09_NU2 = -1;
static gint hf_062_390_09_LTR = -1;
static gint hf_062_390_10 = -1;
static gint hf_062_390_10_CFL = -1;
static gint hf_062_390_11 = -1;
static gint hf_062_390_11_CNTR = -1;
static gint hf_062_390_11_POS = -1;
static gint hf_062_390_12 = -1;
static gint hf_062_390_12_TYP = -1;
static gint hf_062_390_12_DAY = -1;
static gint hf_062_390_12_HOR = -1;
static gint hf_062_390_12_MIN = -1;
static gint hf_062_390_12_AVS = -1;
static gint hf_062_390_12_SEC = -1;
static gint hf_062_390_13 = -1;
static gint hf_062_390_13_STAND = -1;
static gint hf_062_390_14 = -1;
static gint hf_062_390_14_EMP = -1;
static gint hf_062_390_14_AVL = -1;
static gint hf_062_390_15 = -1;
static gint hf_062_390_15_SID = -1;
static gint hf_062_390_16 = -1;
static gint hf_062_390_16_STAR = -1;
static gint hf_062_390_17 = -1;
static gint hf_062_390_17_VA = -1;
static gint hf_062_390_17_SQUAWK = -1;
static gint hf_062_390_18 = -1;
static gint hf_062_390_18_CS = -1;
static gint hf_062_500 = -1;
static gint hf_062_500_01 = -1;
static gint hf_062_500_01_APCX = -1;
static gint hf_062_500_01_APCY = -1;
static gint hf_062_500_02 = -1;
static gint hf_062_500_02_COV = -1;
static gint hf_062_500_03 = -1;
static gint hf_062_500_03_APWLAT = -1;
static gint hf_062_500_03_APWLON = -1;
static gint hf_062_500_04 = -1;
static gint hf_062_500_04_AGA = -1;
static gint hf_062_500_05 = -1;
static gint hf_062_500_05_ABA = -1;
static gint hf_062_500_06 = -1;
static gint hf_062_500_06_ATVX = -1;
static gint hf_062_500_06_ATVY = -1;
static gint hf_062_500_07 = -1;
static gint hf_062_500_07_AAX = -1;
static gint hf_062_500_07_AAY = -1;
static gint hf_062_500_08 = -1;
static gint hf_062_500_08_ARC = -1;
/* v.0.17 */
static gint hf_062_500_01_APCX_8bit = -1;
static gint hf_062_500_01_APCY_8bit = -1;
static gint hf_062_500_02_v0_17 = -1;
static gint hf_062_500_02_APWLAT = -1;
static gint hf_062_500_02_APWLON = -1;
static gint hf_062_500_03_v0_17 = -1;
static gint hf_062_500_03_ATA = -1;
static gint hf_062_500_04_v0_17 = -1;
static gint hf_062_500_04_ATF = -1;
static gint hf_062_500_05_v0_17 = -1;
static gint hf_062_500_05_ATVS = -1;
static gint hf_062_500_05_ATVH = -1;
static gint hf_062_500_06_v0_17 = -1;
static gint hf_062_500_06_ART = -1;
static gint hf_062_500_07_v0_17 = -1;
static gint hf_062_500_07_ALA = -1;
static gint hf_062_510 = -1;
static gint hf_062_510_SID = -1;
static gint hf_062_510_STN = -1;
static gint hf_062_RE = -1;
static gint hf_062_RE_CST = -1;
static gint hf_062_RE_CST_SAC = -1;
static gint hf_062_RE_CST_SIC = -1;
static gint hf_062_RE_CST_TYP = -1;
static gint hf_062_RE_CST_TRK_NUM = -1;
static gint hf_062_RE_CSNT = -1;
static gint hf_062_RE_CSNT_SAC = -1;
static gint hf_062_RE_CSNT_SIC = -1;
static gint hf_062_RE_CSNT_TYP = -1;
static gint hf_062_RE_TVS = -1;
static gint hf_062_RE_TVS_VX = -1;
static gint hf_062_RE_TVS_VY = -1;
static gint hf_062_RE_STS = -1;
static gint hf_062_RE_STS_FDR = -1;
static gint hf_062_SP = -1;
/* Category 063 */
static gint hf_063_010 = -1;
static gint hf_063_015 = -1;
static gint hf_063_030 = -1;
static gint hf_063_050 = -1;
static gint hf_063_060 = -1;
static gint hf_063_070 = -1;
static gint hf_063_080 = -1;
static gint hf_063_081 = -1;
static gint hf_063_090 = -1;
static gint hf_063_091 = -1;
static gint hf_063_092 = -1;
static gint hf_063_RE = -1;
static gint hf_063_SP = -1;
/* Category 065 */
static gint hf_065_000 = -1;
static gint hf_065_010 = -1;
static gint hf_065_015 = -1;
static gint hf_065_020 = -1;
static gint hf_065_030 = -1;
static gint hf_065_040 = -1;
static gint hf_065_050 = -1;
static gint hf_065_RE = -1;
static gint hf_065_SP = -1;


static gint ett_asterix = -1;
static gint ett_asterix_category = -1;
static gint ett_asterix_length = -1;
static gint ett_asterix_message = -1;
static gint ett_asterix_subtree = -1;
static gint ett_spare = -1;
static gint ett_counter = -1;
static gint ett_XXX_SAC = -1;
static gint ett_XXX_SIC = -1;
static gint ett_XXX_FX = -1;
/*static gint ett_XXX_2FX = -1;*/
static gint ett_XXX_3FX = -1;
static gint ett_XXX_TOD = -1;
static gint ett_XXX_AA = -1;
static gint ett_XXX_AI = -1;
static gint ett_XXX_MB_DATA = -1;
static gint ett_XXX_BDS1 = -1;
static gint ett_XXX_BDS2 = -1;
static gint ett_XXX_TN_16 = -1;
/* Category 001 */
static gint ett_001_010 = -1;
static gint ett_001_020 = -1;
static gint ett_001_020_TYP = -1;
static gint ett_001_020_SIM = -1;
static gint ett_001_020_SSR_PSR = -1;
static gint ett_001_020_ANT = -1;
static gint ett_001_020_SPI = -1;
static gint ett_001_020_RAB = -1;
static gint ett_001_020_TST = -1;
static gint ett_001_020_DS12 = -1;
static gint ett_001_020_ME = -1;
static gint ett_001_020_MI = -1;
static gint ett_001_030 = -1;
static gint ett_001_030_WE = -1;
static gint ett_001_040 = -1;
static gint ett_001_040_RHO = -1;
static gint ett_001_040_THETA = -1;
static gint ett_001_042 = -1;
static gint ett_001_042_X = -1;
static gint ett_001_042_Y = -1;
static gint ett_001_050 = -1;
static gint ett_001_060 = -1;
static gint ett_001_070 = -1;
static gint ett_001_070_V = -1;
static gint ett_001_070_G = -1;
static gint ett_001_070_L = -1;
static gint ett_001_070_SQUAWK = -1;
static gint ett_001_080 = -1;
static gint ett_001_080_QA4 = -1;
static gint ett_001_080_QA2 = -1;
static gint ett_001_080_QA1 = -1;
static gint ett_001_080_QB4 = -1;
static gint ett_001_080_QB2 = -1;
static gint ett_001_080_QB1 = -1;
static gint ett_001_080_QC4 = -1;
static gint ett_001_080_QC2 = -1;
static gint ett_001_080_QC1 = -1;
static gint ett_001_080_QD4 = -1;
static gint ett_001_080_QD2 = -1;
static gint ett_001_080_QD1 = -1;
static gint ett_001_090 = -1;
static gint ett_001_090_V = -1;
static gint ett_001_090_G = -1;
static gint ett_001_090_FL = -1;
static gint ett_001_100 = -1;
static gint ett_001_120 = -1;
static gint ett_001_130 = -1;
static gint ett_001_131 = -1;
static gint ett_001_141 = -1;
static gint ett_001_141_TTOD = -1;
static gint ett_001_150 = -1;
static gint ett_001_161 = -1;
static gint ett_001_161_TPN = -1;
static gint ett_001_170 = -1;
static gint ett_001_170_CON = -1;
static gint ett_001_170_RAD = -1;
static gint ett_001_170_MAN = -1;
static gint ett_001_170_DOU = -1;
static gint ett_001_170_RDPC = -1;
static gint ett_001_170_GHO = -1;
static gint ett_001_170_TRE = -1;
static gint ett_001_200 = -1;
static gint ett_001_210 = -1;
static gint ett_001_RE = -1;
static gint ett_001_SP = -1;
/* Category 002 */
static gint ett_002_000 = -1;
static gint ett_002_000_MT = -1;
static gint ett_002_010 = -1;
static gint ett_002_020 = -1;
static gint ett_002_020_SN = -1;
static gint ett_002_030 = -1;
static gint ett_002_041 = -1;
static gint ett_002_041_ARS = -1;
static gint ett_002_050 = -1;
static gint ett_002_060 = -1;
static gint ett_002_070 = -1;
static gint ett_002_070_A = -1;
static gint ett_002_070_IDENT = -1;
static gint ett_002_070_COUNTER = -1;
static gint ett_002_080 = -1;
static gint ett_002_080_WE = -1;
static gint ett_002_090 = -1;
static gint ett_002_090_RE = -1;
static gint ett_002_090_AE = -1;
static gint ett_002_100 = -1;
static gint ett_002_100_RHOS = -1;
static gint ett_002_100_RHOE = -1;
static gint ett_002_100_THETAS = -1;
static gint ett_002_100_THETAE = -1;
static gint ett_002_RE = -1;
static gint ett_002_SP = -1;
/* Category 008 */
static gint ett_008_000 = -1;
static gint ett_008_000_MT = -1;
static gint ett_008_010 = -1;
static gint ett_008_020 = -1;
static gint ett_008_020_ORG = -1;
static gint ett_008_020_INT = -1;
static gint ett_008_020_DIR = -1;
static gint ett_008_020_TST = -1;
static gint ett_008_020_ER = -1;
static gint ett_008_034 = -1;
static gint ett_008_034_START_RANGE = -1;
static gint ett_008_034_END_RANGE = -1;
static gint ett_008_034_AZIMUTH = -1;
static gint ett_008_036 = -1;
static gint ett_008_036_X = -1;
static gint ett_008_036_Y = -1;
static gint ett_008_036_VL = -1;
static gint ett_008_038 = -1;
static gint ett_008_038_X1 = -1;
static gint ett_008_038_Y1 = -1;
static gint ett_008_038_X2 = -1;
static gint ett_008_038_Y2 = -1;
static gint ett_008_040 = -1;
static gint ett_008_040_ORG = -1;
static gint ett_008_040_INT = -1;
static gint ett_008_040_FST_LST = -1;
static gint ett_008_040_CSN = -1;
static gint ett_008_050 = -1;
static gint ett_008_050_X1 = -1;
static gint ett_008_050_Y1 = -1;
static gint ett_008_090 = -1;
static gint ett_008_100 = -1;
static gint ett_008_100_f = -1;
static gint ett_008_100_R = -1;
static gint ett_008_100_Q = -1;
static gint ett_008_110 = -1;
static gint ett_008_110_HW = -1;
static gint ett_008_120 = -1;
static gint ett_008_120_COUNT = -1;
static gint ett_008_SP = -1;
static gint ett_008_RFS = -1;
/* Category 009 */
static gint ett_009_000 = -1;
static gint ett_009_000_MT = -1;
static gint ett_009_010 = -1;
static gint ett_009_020 = -1;
static gint ett_009_020_ORG = -1;
static gint ett_009_020_INT = -1;
static gint ett_009_020_DIR = -1;
static gint ett_009_030 = -1;
static gint ett_009_030_X = -1;
static gint ett_009_030_Y = -1;
static gint ett_009_030_VL = -1;
static gint ett_009_060 = -1;
static gint ett_009_060_STEP = -1;
static gint ett_009_070 = -1;
static gint ett_009_080 = -1;
static gint ett_009_080_SCALE = -1;
static gint ett_009_080_R = -1;
static gint ett_009_080_Q = -1;
static gint ett_009_090 = -1;
static gint ett_009_090_CP = -1;
static gint ett_009_090_WO = -1;
static gint ett_009_090_RS = -1;
static gint ett_009_100 = -1;
static gint ett_009_100_VC = -1;
/* Category 021 */
static gint ett_021_008 = -1;
static gint ett_021_008_RA = -1;
static gint ett_021_008_TC = -1;
static gint ett_021_008_TS = -1;
static gint ett_021_008_ARV = -1;
static gint ett_021_008_CDTIA = -1;
static gint ett_021_008_not_TCAS = -1;
static gint ett_021_008_SA = -1;
static gint ett_021_010 = -1;
static gint ett_021_015 = -1;
static gint ett_021_015_SI = -1;
static gint ett_021_016 = -1;
static gint ett_021_016_RP = -1;
static gint ett_021_020 = -1;
static gint ett_021_020_ECAT = -1;
static gint ett_021_040 = -1;
static gint ett_021_040_ATP = -1;
static gint ett_021_040_ARC = -1;
static gint ett_021_040_RC = -1;
static gint ett_021_040_RAB = -1;
static gint ett_021_040_DCR = -1;
static gint ett_021_040_GBS = -1;
static gint ett_021_040_SIM = -1;
static gint ett_021_040_TST = -1;
static gint ett_021_040_SAA = -1;
static gint ett_021_040_CL = -1;
static gint ett_021_040_IPC = -1;
static gint ett_021_040_NOGO = -1;
static gint ett_021_040_CPR = -1;
static gint ett_021_040_LDPJ = -1;
static gint ett_021_040_RCF = -1;
static gint ett_021_070 = -1;
static gint ett_021_070_SQUAWK = -1;
static gint ett_021_071 = -1;
static gint ett_021_072 = -1;
static gint ett_021_073 = -1;
static gint ett_021_074 = -1;
static gint ett_021_074_FSI = -1;
static gint ett_021_074_TOMRP = -1;
static gint ett_021_075 = -1;
static gint ett_021_076 = -1;
static gint ett_021_077 = -1;
static gint ett_021_076_FSI = -1;
static gint ett_021_076_TOMRV = -1;
static gint ett_021_080 = -1;
static gint ett_021_090 = -1;
static gint ett_021_090_NUCR_NACV = -1;
static gint ett_021_090_NUCP_NIC = -1;
static gint ett_021_090_NIC_BARO = -1;
static gint ett_021_090_SIL = -1;
static gint ett_021_090_NACP = -1;
static gint ett_021_090_SIL_SUP = -1;
static gint ett_021_090_SDA = -1;
static gint ett_021_090_GVA = -1;
static gint ett_021_090_PIC = -1;
static gint ett_021_110 = -1;
static gint ett_021_110_01 = -1;
static gint ett_021_110_01_NAV = -1;
static gint ett_021_110_01_NVB = -1;
static gint ett_021_110_02 = -1;
static gint ett_021_110_02_TCA = -1;
static gint ett_021_110_02_NC = -1;
static gint ett_021_110_02_TCPNo = -1;
static gint ett_021_110_02_ALT = -1;
static gint ett_021_110_02_LAT = -1;
static gint ett_021_110_02_LON = -1;
static gint ett_021_110_02_PT = -1;
static gint ett_021_110_02_TD = -1;
static gint ett_021_110_02_TRA = -1;
static gint ett_021_110_02_TOA = -1;
static gint ett_021_110_02_TOV = -1;
static gint ett_021_110_02_TTR = -1;
static gint ett_021_130 = -1;
static gint ett_021_130_LAT = -1;
static gint ett_021_130_LON = -1;
static gint ett_021_131 = -1;
static gint ett_021_131_LAT = -1;
static gint ett_021_131_LON = -1;
static gint ett_021_132 = -1;
static gint ett_021_132_MAM = -1;
static gint ett_021_140 = -1;
static gint ett_021_140_GH = -1;
static gint ett_021_145 = -1;
static gint ett_021_145_FL = -1;
static gint ett_021_146 = -1;
static gint ett_021_146_SAS = -1;
static gint ett_021_146_Source = -1;
static gint ett_021_146_ALT = -1;
static gint ett_021_148 = -1;
static gint ett_021_148_MV = -1;
static gint ett_021_148_AH = -1;
static gint ett_021_148_AM = -1;
static gint ett_021_148_ALT = -1;
static gint ett_021_150 = -1;
static gint ett_021_150_IM = -1;
static gint ett_021_150_ASPD = -1;
static gint ett_021_151 = -1;
static gint ett_021_151_RE = -1;
static gint ett_021_151_TASPD = -1;
static gint ett_021_152 = -1;
static gint ett_021_152_MHDG = -1;
static gint ett_021_155 = -1;
static gint ett_021_155_RE = -1;
static gint ett_021_155_BVR = -1;
static gint ett_021_157 = -1;
static gint ett_021_157_RE = -1;
static gint ett_021_157_GVR = -1;
static gint ett_021_160 = -1;
static gint ett_021_160_RE = -1;
static gint ett_021_160_GSPD = -1;
static gint ett_021_160_TA = -1;
static gint ett_021_161 = -1;
static gint ett_021_161_TN = -1;
static gint ett_021_165 = -1;
static gint ett_021_165_TAR = -1;
static gint ett_021_170 = -1;
static gint ett_021_200 = -1;
static gint ett_021_200_ICF = -1;
static gint ett_021_200_LNAV = -1;
static gint ett_021_200_PS = -1;
static gint ett_021_200_SS = -1;
static gint ett_021_210 = -1;
static gint ett_021_210_VNS = -1;
static gint ett_021_210_VN = -1;
static gint ett_021_210_LTT = -1;
static gint ett_021_220 = -1;
static gint ett_021_220_01 = -1;
static gint ett_021_220_01_WSPD = -1;
static gint ett_021_220_02 = -1;
static gint ett_021_220_02_WDIR = -1;
static gint ett_021_220_03 = -1;
static gint ett_021_220_03_TEMP = -1;
static gint ett_021_220_04 = -1;
static gint ett_021_220_04_TURB = -1;
static gint ett_021_230 = -1;
static gint ett_021_230_RA = -1;
static gint ett_021_250 = -1;
static gint ett_021_260 = -1;
static gint ett_021_260_TYP = -1;
static gint ett_021_260_STYP = -1;
static gint ett_021_260_ARA = -1;
static gint ett_021_260_RAC = -1;
static gint ett_021_260_RAT = -1;
static gint ett_021_260_MTE = -1;
static gint ett_021_260_TTI = -1;
static gint ett_021_260_TID = -1;
static gint ett_021_271 = -1;
static gint ett_021_271_POA = -1;
static gint ett_021_271_CDTIS = -1;
static gint ett_021_271_B2low = -1;
static gint ett_021_271_RAS = -1;
static gint ett_021_271_IDENT = -1;
static gint ett_021_271_LW = -1;
static gint ett_021_295 = -1;
static gint ett_021_295_01 = -1;
static gint ett_021_295_01_AOS = -1;
static gint ett_021_295_02 = -1;
static gint ett_021_295_02_TRD = -1;
static gint ett_021_295_03 = -1;
static gint ett_021_295_03_M3A = -1;
static gint ett_021_295_04 = -1;
static gint ett_021_295_04_QI = -1;
static gint ett_021_295_05 = -1;
static gint ett_021_295_05_TI = -1;
static gint ett_021_295_06 = -1;
static gint ett_021_295_06_MAM = -1;
static gint ett_021_295_07 = -1;
static gint ett_021_295_07_GH = -1;
static gint ett_021_295_08 = -1;
static gint ett_021_295_08_FL = -1;
static gint ett_021_295_09 = -1;
static gint ett_021_295_09_ISA = -1;
static gint ett_021_295_10 = -1;
static gint ett_021_295_10_FSA = -1;
static gint ett_021_295_11 = -1;
static gint ett_021_295_11_AS = -1;
static gint ett_021_295_12 = -1;
static gint ett_021_295_12_TAS = -1;
static gint ett_021_295_13 = -1;
static gint ett_021_295_13_MH = -1;
static gint ett_021_295_14 = -1;
static gint ett_021_295_14_BVR = -1;
static gint ett_021_295_15 = -1;
static gint ett_021_295_15_GVR = -1;
static gint ett_021_295_16 = -1;
static gint ett_021_295_16_GV = -1;
static gint ett_021_295_17 = -1;
static gint ett_021_295_17_TAR = -1;
static gint ett_021_295_18 = -1;
static gint ett_021_295_18_TI = -1;
static gint ett_021_295_19 = -1;
static gint ett_021_295_19_TS = -1;
static gint ett_021_295_20 = -1;
static gint ett_021_295_20_MET = -1;
static gint ett_021_295_21 = -1;
static gint ett_021_295_21_ROA = -1;
static gint ett_021_295_22 = -1;
static gint ett_021_295_22_ARA = -1;
static gint ett_021_295_23 = -1;
static gint ett_021_295_23_SCC = -1;
static gint ett_021_400 = -1;
static gint ett_021_400_RID = -1;
static gint ett_021_RE = -1;
static gint ett_021_SP = -1;
/* Category 023 */
static gint ett_023_000 = -1;
static gint ett_023_000_RT = -1;
static gint ett_023_010 = -1;
static gint ett_023_015 = -1;
static gint ett_023_015_SID = -1;
static gint ett_023_015_STYPE = -1;
static gint ett_023_070 = -1;
static gint ett_023_100 = -1;
static gint ett_023_100_NOGO = -1;
static gint ett_023_100_ODP = -1;
static gint ett_023_100_OXT = -1;
static gint ett_023_100_MSC = -1;
static gint ett_023_100_TSV = -1;
static gint ett_023_100_SPO = -1;
static gint ett_023_100_RN = -1;
static gint ett_023_100_GSSP = -1;
static gint ett_023_101 = -1;
static gint ett_023_101_RP = -1;
static gint ett_023_101_SC = -1;
static gint ett_023_101_SSRP = -1;
static gint ett_023_110 = -1;
static gint ett_023_110_STAT = -1;
static gint ett_023_120 = -1;
static gint ett_023_120_TYPE = -1;
static gint ett_023_120_REF = -1;
static gint ett_023_120_COUNTER = -1;
static gint ett_023_200 = -1;
static gint ett_023_200_RANGE = -1;
static gint ett_023_RE = -1;
static gint ett_023_SP = -1;
/* Category 034 */
static gint ett_034_000 = -1;
static gint ett_034_000_MT = -1;
static gint ett_034_010 = -1;
static gint ett_034_020 = -1;
static gint ett_034_020_SN = -1;
static gint ett_034_030 = -1;
static gint ett_034_041 = -1;
static gint ett_034_041_ARS = -1;
static gint ett_034_050 = -1;
static gint ett_034_050_01 = -1;
static gint ett_034_050_01_NOGO = -1;
static gint ett_034_050_01_RDPC = -1;
static gint ett_034_050_01_RDPR = -1;
static gint ett_034_050_01_OVL_RDP = -1;
static gint ett_034_050_01_OVL_XMT = -1;
static gint ett_034_050_01_MSC = -1;
static gint ett_034_050_01_TSV = -1;
static gint ett_034_050_02 = -1;
static gint ett_034_050_02_ANT = -1;
static gint ett_034_050_02_CHAB = -1;
static gint ett_034_050_02_OVL = -1;
static gint ett_034_050_02_MSC = -1;
static gint ett_034_050_03 = -1;
static gint ett_034_050_03_ANT = -1;
static gint ett_034_050_03_CHAB = -1;
static gint ett_034_050_03_OVL = -1;
static gint ett_034_050_03_MSC = -1;
static gint ett_034_050_04 = -1;
static gint ett_034_050_04_ANT = -1;
static gint ett_034_050_04_CHAB = -1;
static gint ett_034_050_04_OVL_SUR = -1;
static gint ett_034_050_04_MSC = -1;
static gint ett_034_050_04_SCF = -1;
static gint ett_034_050_04_DLF = -1;
static gint ett_034_050_04_OVL_SCF = -1;
static gint ett_034_050_04_OVL_DLF = -1;
static gint ett_034_060 = -1;
static gint ett_034_060_01 = -1;
static gint ett_034_060_01_RED_RDP = -1;
static gint ett_034_060_01_RED_XMT = -1;
static gint ett_034_060_02 = -1;
static gint ett_034_060_02_POL = -1;
static gint ett_034_060_02_RED_RAD = -1;
static gint ett_034_060_02_STC = -1;
static gint ett_034_060_03 = -1;
static gint ett_034_060_03_RED_RAD = -1;
static gint ett_034_060_04 = -1;
static gint ett_034_060_04_RED_RAD = -1;
static gint ett_034_060_04_CLU = -1;
static gint ett_034_070 = -1;
static gint ett_034_070_TYP = -1;
static gint ett_034_070_COUNTER = -1;
static gint ett_034_090 = -1;
static gint ett_034_090_RE = -1;
static gint ett_034_090_AE = -1;
static gint ett_034_100 = -1;
static gint ett_035_100_RHOS = -1;
static gint ett_035_100_RHOE = -1;
static gint ett_035_100_THETAS = -1;
static gint ett_035_100_THETAE = -1;
static gint ett_034_110 = -1;
static gint ett_034_110_TYP = -1;
static gint ett_034_120 = -1;
static gint ett_034_120_H = -1;
static gint ett_034_120_LAT = -1;
static gint ett_034_120_LON = -1;
static gint ett_034_RE = -1;
static gint ett_034_SP = -1;
/* Category 048 */
static gint ett_048_010 = -1;
static gint ett_048_020 = -1;
static gint ett_048_020_TYP = -1;
static gint ett_048_020_SIM = -1;
static gint ett_048_020_RDP = -1;
static gint ett_048_020_SPI = -1;
static gint ett_048_020_RAB = -1;
static gint ett_048_020_TST = -1;
static gint ett_048_020_ME = -1;
static gint ett_048_020_MI = -1;
static gint ett_048_020_FOE = -1;
static gint ett_048_030 = -1;
static gint ett_048_030_WE = -1;
static gint ett_048_040 = -1;
static gint ett_048_040_RHO = -1;
static gint ett_048_040_THETA = -1;
static gint ett_048_042 = -1;
static gint ett_048_042_X = -1;
static gint ett_048_042_Y = -1;
static gint ett_048_050 = -1;
static gint ett_048_050_V = -1;
static gint ett_048_050_G = -1;
static gint ett_048_050_L = -1;
static gint ett_048_050_SQUAWK = -1;
static gint ett_048_055 = -1;
static gint ett_048_055_V = -1;
static gint ett_048_055_G = -1;
static gint ett_048_055_L = -1;
static gint ett_048_055_CODE = -1;
static gint ett_048_060 = -1;
static gint ett_048_060_QA4 = -1;
static gint ett_048_060_QA2 = -1;
static gint ett_048_060_QA1 = -1;
static gint ett_048_060_QB4 = -1;
static gint ett_048_060_QB2 = -1;
static gint ett_048_060_QB1 = -1;
static gint ett_048_060_QC4 = -1;
static gint ett_048_060_QC2 = -1;
static gint ett_048_060_QC1 = -1;
static gint ett_048_060_QD4 = -1;
static gint ett_048_060_QD2 = -1;
static gint ett_048_060_QD1 = -1;
static gint ett_048_065 = -1;
static gint ett_048_065_QA4 = -1;
static gint ett_048_065_QA2 = -1;
static gint ett_048_065_QA1 = -1;
static gint ett_048_065_QB2 = -1;
static gint ett_048_065_QB1 = -1;
static gint ett_048_070 = -1;
static gint ett_048_070_V = -1;
static gint ett_048_070_G = -1;
static gint ett_048_070_L = -1;
static gint ett_048_070_SQUAWK = -1;
static gint ett_048_080 = -1;
static gint ett_048_080_QA4 = -1;
static gint ett_048_080_QA2 = -1;
static gint ett_048_080_QA1 = -1;
static gint ett_048_080_QB4 = -1;
static gint ett_048_080_QB2 = -1;
static gint ett_048_080_QB1 = -1;
static gint ett_048_080_QC4 = -1;
static gint ett_048_080_QC2 = -1;
static gint ett_048_080_QC1 = -1;
static gint ett_048_080_QD4 = -1;
static gint ett_048_080_QD2 = -1;
static gint ett_048_080_QD1 = -1;
static gint ett_048_090 = -1;
static gint ett_048_090_V = -1;
static gint ett_048_090_G = -1;
static gint ett_048_090_FL = -1;
static gint ett_048_100 = -1;
static gint ett_048_100_V = -1;
static gint ett_048_100_G = -1;
static gint ett_048_100_A4 = -1;
static gint ett_048_100_A2 = -1;
static gint ett_048_100_A1 = -1;
static gint ett_048_100_B4 = -1;
static gint ett_048_100_B2 = -1;
static gint ett_048_100_B1 = -1;
static gint ett_048_100_C4 = -1;
static gint ett_048_100_C2 = -1;
static gint ett_048_100_C1 = -1;
static gint ett_048_100_D4 = -1;
static gint ett_048_100_D2 = -1;
static gint ett_048_100_D1 = -1;
static gint ett_048_100_QA4 = -1;
static gint ett_048_100_QA2 = -1;
static gint ett_048_100_QA1 = -1;
static gint ett_048_100_QB4 = -1;
static gint ett_048_100_QB2 = -1;
static gint ett_048_100_QB1 = -1;
static gint ett_048_100_QC4 = -1;
static gint ett_048_100_QC2 = -1;
static gint ett_048_100_QC1 = -1;
static gint ett_048_100_QD4 = -1;
static gint ett_048_100_QD2 = -1;
static gint ett_048_100_QD1 = -1;
static gint ett_048_110 = -1;
static gint ett_048_110_3DHEIGHT = -1;
static gint ett_048_120 = -1;
static gint ett_048_120_01 = -1;
static gint ett_048_120_01_D = -1;
static gint ett_048_120_01_CAL = -1;
static gint ett_048_120_02 = -1;
static gint ett_048_120_02_DOP = -1;
static gint ett_048_120_02_AMB = -1;
static gint ett_048_120_02_FRQ = -1;
static gint ett_048_130 = -1;
static gint ett_048_130_01 = -1;
static gint ett_048_130_01_SRL = -1;
static gint ett_048_130_02 = -1;
static gint ett_048_130_02_SRR = -1;
static gint ett_048_130_03 = -1;
static gint ett_048_130_03_SAM = -1;
static gint ett_048_130_04 = -1;
static gint ett_048_130_04_PRL = -1;
static gint ett_048_130_05 = -1;
static gint ett_048_130_05_PAM = -1;
static gint ett_048_130_06 = -1;
static gint ett_048_130_06_RPD = -1;
static gint ett_048_130_07 = -1;
static gint ett_048_130_07_APD = -1;
static gint ett_048_140 = -1;
static gint ett_048_161 = -1;
static gint ett_048_161_TN = -1;
static gint ett_048_170 = -1;
static gint ett_048_170_CNF = -1;
static gint ett_048_170_RAD = -1;
static gint ett_048_170_DOU = -1;
static gint ett_048_170_MAH = -1;
static gint ett_048_170_CDM = -1;
static gint ett_048_170_TRE = -1;
static gint ett_048_170_GHO = -1;
static gint ett_048_170_SUP = -1;
static gint ett_048_170_TCC = -1;
static gint ett_048_200 = -1;
static gint ett_048_200_GS = -1;
static gint ett_048_200_HDG = -1;
static gint ett_048_210 = -1;
static gint ett_048_210_X = -1;
static gint ett_048_210_Y = -1;
static gint ett_048_210_V = -1;
static gint ett_048_210_H = -1;
static gint ett_048_220 = -1;
static gint ett_048_230 = -1;
static gint ett_048_230_COM = -1;
static gint ett_048_230_STAT = -1;
static gint ett_048_230_SI = -1;
static gint ett_048_230_MSSC = -1;
static gint ett_048_230_ARC = -1;
static gint ett_048_230_AIC = -1;
static gint ett_048_230_B1A = -1;
static gint ett_048_230_B1B = -1;
static gint ett_048_240 = -1;
static gint ett_048_250 = -1;
static gint ett_048_260 = -1;
static gint ett_048_260_ACAS = -1;
static gint ett_048_RE = -1;
static gint ett_048_SP = -1;
/* Category 062*/
static gint ett_062_010 = -1;
static gint ett_062_015 = -1;
static gint ett_062_015_SI = -1;
static gint ett_062_040 = -1;
static gint ett_062_060 = -1;
static gint ett_062_060_CH = -1;
static gint ett_062_060_SQUAWK = -1;
static gint ett_062_070 = -1;
static gint ett_062_080 = -1;
static gint ett_062_080_MON = -1;
static gint ett_062_080_SPI = -1;
static gint ett_062_080_MRH = -1;
static gint ett_062_080_SRC = -1;
static gint ett_062_080_CNF = -1;
static gint ett_062_080_SIM = -1;
static gint ett_062_080_TSE = -1;
static gint ett_062_080_TSB = -1;
static gint ett_062_080_FPC = -1;
static gint ett_062_080_AFF = -1;
static gint ett_062_080_STP = -1;
static gint ett_062_080_KOS = -1;
static gint ett_062_080_AMA = -1;
static gint ett_062_080_MD4 = -1;
static gint ett_062_080_ME = -1;
static gint ett_062_080_MI = -1;
static gint ett_062_080_MD5 = -1;
static gint ett_062_080_CST = -1;
static gint ett_062_080_PSR = -1;
static gint ett_062_080_SSR = -1;
static gint ett_062_080_MDS = -1;
static gint ett_062_080_ADS = -1;
static gint ett_062_080_SUC = -1;
static gint ett_062_080_AAC = -1;
static gint ett_062_080_SDS = -1;
static gint ett_062_080_EMS = -1;
static gint ett_062_080_PFT = -1;
static gint ett_062_080_FPLT = -1;
static gint ett_062_080_DUPT = -1;
static gint ett_062_080_DUPF = -1;
static gint ett_062_080_DUPM = -1;
static gint ett_062_080_FRIFOE = -1;
static gint ett_062_080_COA = -1;
static gint ett_062_100 = -1;
static gint ett_062_100_X = -1;
static gint ett_062_100_Y = -1;
static gint ett_062_100_X_v0_17 = -1;
static gint ett_062_100_Y_v0_17 = -1;
static gint ett_062_105 = -1;
static gint ett_062_105_LAT = -1;
static gint ett_062_105_LON = -1;
static gint ett_062_110 = -1;
static gint ett_062_110_01 = -1;
static gint ett_062_110_01_M5 = -1;
static gint ett_062_110_01_ID = -1;
static gint ett_062_110_01_DA = -1;
static gint ett_062_110_01_M1 = -1;
static gint ett_062_110_01_M2 = -1;
static gint ett_062_110_01_M3 = -1;
static gint ett_062_110_01_MC = -1;
static gint ett_062_110_01_X = -1;
static gint ett_062_110_02 = -1;
static gint ett_062_110_02_PIN = -1;
static gint ett_062_110_02_NAT = -1;
static gint ett_062_110_02_MIS = -1;
static gint ett_062_110_03 = -1;
static gint ett_062_110_03_LAT = -1;
static gint ett_062_110_03_LON = -1;
static gint ett_062_110_04 = -1;
static gint ett_062_110_04_RES = -1;
static gint ett_062_110_04_GA = -1;
static gint ett_062_110_05 = -1;
static gint ett_062_110_05_SQUAWK = -1;
static gint ett_062_110_06 = -1;
static gint ett_062_110_06_TOS = -1;
static gint ett_062_110_07 = -1;
static gint ett_062_110_07_X5 = -1;
static gint ett_062_110_07_XC = -1;
static gint ett_062_110_07_X3 = -1;
static gint ett_062_110_07_X2 = -1;
static gint ett_062_110_07_X1 = -1;
/* v.0.17 */
static gint ett_062_110_v0_17 = -1;
static gint ett_062_110_A4 = -1;
static gint ett_062_110_A2 = -1;
static gint ett_062_110_A1 = -1;
static gint ett_062_110_B2 = -1;
static gint ett_062_110_B1 = -1;
static gint ett_062_120 = -1;
static gint ett_062_120_SQUAWK = -1;
static gint ett_062_130 = -1;
static gint ett_062_130_ALT = -1;
static gint ett_062_135 = -1;
static gint ett_062_135_QNH = -1;
static gint ett_062_135_ALT = -1;
static gint ett_062_136 = -1;
static gint ett_062_136_ALT = -1;
static gint ett_062_180 = -1;
static gint ett_062_180_SPEED = -1;
static gint ett_062_180_HEADING = -1;
static gint ett_062_185 = -1;
static gint ett_062_185_VX = -1;
static gint ett_062_185_VY = -1;
static gint ett_062_200 = -1;
static gint ett_062_200_TRANS = -1;
static gint ett_062_200_LONG = -1;
static gint ett_062_200_VERT = -1;
static gint ett_062_200_ADF = -1;
static gint ett_062_210 = -1;
static gint ett_062_210_AX = -1;
static gint ett_062_210_AY = -1;
static gint ett_062_210_CLA = -1;
static gint ett_062_210_v0_17 = -1;
static gint ett_062_220 = -1;
static gint ett_062_220_ROCD = -1;
static gint ett_062_240 = -1;
static gint ett_062_240_ROT = -1;
static gint ett_062_245 = -1;
static gint ett_062_270 = -1;
static gint ett_062_270_LENGTH = -1;
static gint ett_062_270_ORIENTATION = -1;
static gint ett_062_270_WIDTH = -1;
static gint ett_062_290 = -1;
static gint ett_062_290_01 = -1;
static gint ett_062_290_01_TRK = -1;
static gint ett_062_290_02 = -1;
static gint ett_062_290_02_PSR = -1;
static gint ett_062_290_03 = -1;
static gint ett_062_290_03_SSR = -1;
static gint ett_062_290_04 = -1;
static gint ett_062_290_04_MDS = -1;
static gint ett_062_290_05 = -1;
static gint ett_062_290_05_ADS = -1;
static gint ett_062_290_06 = -1;
static gint ett_062_290_06_ES = -1;
static gint ett_062_290_07 = -1;
static gint ett_062_290_07_VDL = -1;
static gint ett_062_290_08 = -1;
static gint ett_062_290_08_UAT = -1;
static gint ett_062_290_09 = -1;
static gint ett_062_290_09_LOP = -1;
static gint ett_062_290_10 = -1;
static gint ett_062_290_10_MLT = -1;
/* v.0.17 */
static gint ett_062_290_01_v0_17 = -1;
static gint ett_062_290_01_PSR = -1;
static gint ett_062_290_02_v0_17 = -1;
static gint ett_062_290_02_SSR = -1;
static gint ett_062_290_03_v0_17 = -1;
static gint ett_062_290_03_MDA = -1;
static gint ett_062_290_04_v0_17 = -1;
static gint ett_062_290_04_MFL = -1;
static gint ett_062_290_05_v0_17 = -1;
static gint ett_062_290_05_MDS = -1;
static gint ett_062_290_06_v0_17 = -1;
static gint ett_062_290_06_ADS = -1;
static gint ett_062_290_07_v0_17 = -1;
static gint ett_062_290_07_ADB = -1;
static gint ett_062_290_08_v0_17 = -1;
static gint ett_062_290_08_MD1 = -1;
static gint ett_062_290_09_v0_17 = -1;
static gint ett_062_290_09_MD2 = -1;
static gint ett_062_295 = -1;
static gint ett_062_295_01 = -1;
static gint ett_062_295_01_MFL = -1;
static gint ett_062_295_02 = -1;
static gint ett_062_295_02_MD1 = -1;
static gint ett_062_295_03 = -1;
static gint ett_062_295_03_MD2 = -1;
static gint ett_062_295_04 = -1;
static gint ett_062_295_04_MDA = -1;
static gint ett_062_295_05 = -1;
static gint ett_062_295_05_MD4 = -1;
static gint ett_062_295_06 = -1;
static gint ett_062_295_06_MD5 = -1;
static gint ett_062_295_07 = -1;
static gint ett_062_295_07_MHD = -1;
static gint ett_062_295_08 = -1;
static gint ett_062_295_08_IAS = -1;
static gint ett_062_295_09 = -1;
static gint ett_062_295_09_TAS = -1;
static gint ett_062_295_10 = -1;
static gint ett_062_295_10_SAL = -1;
static gint ett_062_295_11 = -1;
static gint ett_062_295_11_FSS = -1;
static gint ett_062_295_12 = -1;
static gint ett_062_295_12_TID = -1;
static gint ett_062_295_13 = -1;
static gint ett_062_295_13_COM = -1;
static gint ett_062_295_14 = -1;
static gint ett_062_295_14_SAB = -1;
static gint ett_062_295_15 = -1;
static gint ett_062_295_15_ACS = -1;
static gint ett_062_295_16 = -1;
static gint ett_062_295_16_BVR = -1;
static gint ett_062_295_17 = -1;
static gint ett_062_295_17_GVR = -1;
static gint ett_062_295_18 = -1;
static gint ett_062_295_18_RAN = -1;
static gint ett_062_295_19 = -1;
static gint ett_062_295_19_TAR = -1;
static gint ett_062_295_20 = -1;
static gint ett_062_295_20_TAN = -1;
static gint ett_062_295_21 = -1;
static gint ett_062_295_21_GSP = -1;
static gint ett_062_295_22 = -1;
static gint ett_062_295_22_VUN = -1;
static gint ett_062_295_23 = -1;
static gint ett_062_295_23_MET = -1;
static gint ett_062_295_24 = -1;
static gint ett_062_295_24_EMC = -1;
static gint ett_062_295_25 = -1;
static gint ett_062_295_25_POS = -1;
static gint ett_062_295_26 = -1;
static gint ett_062_295_26_GAL = -1;
static gint ett_062_295_27 = -1;
static gint ett_062_295_27_PUN = -1;
static gint ett_062_295_28 = -1;
static gint ett_062_295_28_MB = -1;
static gint ett_062_295_29 = -1;
static gint ett_062_295_29_IAR = -1;
static gint ett_062_295_30 = -1;
static gint ett_062_295_30_MAC = -1;
static gint ett_062_295_31 = -1;
static gint ett_062_295_31_BPS = -1;
static gint ett_062_300 = -1;
static gint ett_062_300_VFI = -1;
static gint ett_062_340 = -1;
static gint ett_062_340_01 = -1;
static gint ett_062_340_02 = -1;
static gint ett_062_340_02_RHO = -1;
static gint ett_062_340_02_THETA = -1;
static gint ett_062_340_03 = -1;
static gint ett_062_340_03_H = -1;
static gint ett_062_340_04 = -1;
static gint ett_062_340_04_V = -1;
static gint ett_062_340_04_G = -1;
static gint ett_062_340_04_FL = -1;
static gint ett_062_340_05 = -1;
static gint ett_062_340_05_V = -1;
static gint ett_062_340_05_G = -1;
static gint ett_062_340_05_L = -1;
static gint ett_062_340_05_SQUAWK = -1;
static gint ett_062_340_06 = -1;
static gint ett_062_340_06_TYP = -1;
static gint ett_062_340_06_SIM = -1;
static gint ett_062_340_06_RAB = -1;
static gint ett_062_340_06_TST = -1;
static gint ett_062_380 = -1;
static gint ett_062_380_01 = -1;
static gint ett_062_380_02 = -1;
static gint ett_062_380_03 = -1;
static gint ett_062_380_03_MH = -1;
static gint ett_062_380_04 = -1;
static gint ett_062_380_04_IM = -1;
static gint ett_062_380_04_IAS = -1;
static gint ett_062_380_05 = -1;
static gint ett_062_380_05_TAS = -1;
static gint ett_062_380_06 = -1;
static gint ett_062_380_06_SAS = -1;
static gint ett_062_380_06_SOURCE = -1;
static gint ett_062_380_06_ALT = -1;
static gint ett_062_380_07 = -1;
static gint ett_062_380_07_MV = -1;
static gint ett_062_380_07_AH = -1;
static gint ett_062_380_07_AM = -1;
static gint ett_062_380_07_ALT = -1;
static gint ett_062_380_08 = -1;
static gint ett_062_380_08_NAV = -1;
static gint ett_062_380_08_NVB = -1;
static gint ett_062_380_09 = -1;
static gint ett_062_380_09_TCA = -1;
static gint ett_062_380_09_NC = -1;
static gint ett_062_380_09_TCP = -1;
static gint ett_062_380_09_ALT = -1;
static gint ett_062_380_09_LAT = -1;
static gint ett_062_380_09_LON = -1;
static gint ett_062_380_09_PTYP = -1;
static gint ett_062_380_09_TD = -1;
static gint ett_062_380_09_TRA = -1;
static gint ett_062_380_09_TOA = -1;
static gint ett_062_380_09_TOV = -1;
static gint ett_062_380_09_TTR = -1;
static gint ett_062_380_10 = -1;
static gint ett_062_380_10_COM = -1;
static gint ett_062_380_10_STAT = -1;
static gint ett_062_380_10_SSC = -1;
static gint ett_062_380_10_ARC = -1;
static gint ett_062_380_10_AIC = -1;
static gint ett_062_380_10_B1A = -1;
static gint ett_062_380_10_B1B = -1;
static gint ett_062_380_11 = -1;
static gint ett_062_380_11_AC = -1;
static gint ett_062_380_11_MN = -1;
static gint ett_062_380_11_DC = -1;
static gint ett_062_380_11_GBS = -1;
static gint ett_062_380_11_STAT = -1;
static gint ett_062_380_12 = -1;
static gint ett_062_380_12_MB = -1;
static gint ett_062_380_13 = -1;
static gint ett_062_380_13_BVR = -1;
static gint ett_062_380_14 = -1;
static gint ett_062_380_14_GVR = -1;
static gint ett_062_380_15 = -1;
static gint ett_062_380_15_ROLL = -1;
static gint ett_062_380_16 = -1;
static gint ett_062_380_16_TI = -1;
static gint ett_062_380_16_RATE = -1;
static gint ett_062_380_17 = -1;
static gint ett_062_380_17_TA = -1;
static gint ett_062_380_18 = -1;
static gint ett_062_380_18_GS = -1;
static gint ett_062_380_19 = -1;
static gint ett_062_380_19_VUC = -1;
static gint ett_062_380_20 = -1;
static gint ett_062_380_20_WS = -1;
static gint ett_062_380_20_WD = -1;
static gint ett_062_380_20_TMP = -1;
static gint ett_062_380_20_TRB = -1;
static gint ett_062_380_20_WS_VAL = -1;
static gint ett_062_380_20_WD_VAL = -1;
static gint ett_062_380_20_TMP_VAL = -1;
static gint ett_062_380_20_TRB_VAL = -1;
static gint ett_062_380_21 = -1;
static gint ett_062_380_21_ECAT = -1;
static gint ett_062_380_22 = -1;
static gint ett_062_380_22_LAT = -1;
static gint ett_062_380_22_LON = -1;
static gint ett_062_380_23 = -1;
static gint ett_062_380_23_ALT = -1;
static gint ett_062_380_24 = -1;
static gint ett_062_380_24_PUN = -1;
static gint ett_062_380_25 = -1;
static gint ett_062_380_26 = -1;
static gint ett_062_380_26_IAS = -1;
static gint ett_062_380_27 = -1;
static gint ett_062_380_27_MACH = -1;
static gint ett_062_380_28 = -1;
static gint ett_062_380_28_BPS = -1;
/* v.0.17 */
static gint ett_062_380_v0_17 = -1;
static gint ett_062_380_01_v0_17 = -1;
static gint ett_062_380_02_v0_17 = -1;
static gint ett_062_380_03_v0_17 = -1;
static gint ett_062_380_04_v0_17 = -1;
static gint ett_062_380_04_COM = -1;
static gint ett_062_380_04_STAT = -1;
static gint ett_062_380_04_SSC = -1;
static gint ett_062_380_04_ARC = -1;
static gint ett_062_380_04_AIC = -1;
static gint ett_062_380_04_B1A = -1;
static gint ett_062_380_04_B1B = -1;
static gint ett_062_380_05_v0_17 = -1;
static gint ett_062_380_05_MB = -1;
static gint ett_062_390 = -1;
static gint ett_062_390_01 = -1;
static gint ett_062_390_02 = -1;
static gint ett_062_390_02_CS = -1;
static gint ett_062_390_03 = -1;
static gint ett_062_390_03_TYP = -1;
static gint ett_062_390_03_NBR = -1;
static gint ett_062_390_04 = -1;
static gint ett_062_390_04_GAT_OAT = -1;
static gint ett_062_390_04_FR12 = -1;
static gint ett_062_390_04_RVSM = -1;
static gint ett_062_390_04_HPR = -1;
static gint ett_062_390_05 = -1;
static gint ett_062_390_05_ACTYP = -1;
static gint ett_062_390_06 = -1;
static gint ett_062_390_06_WTC = -1;
static gint ett_062_390_07 = -1;
static gint ett_062_390_07_ADEP = -1;
static gint ett_062_390_08 = -1;
static gint ett_062_390_08_ADES = -1;
static gint ett_062_390_09 = -1;
static gint ett_062_390_09_NU1 = -1;
static gint ett_062_390_09_NU2 = -1;
static gint ett_062_390_09_LTR = -1;
static gint ett_062_390_10 = -1;
static gint ett_062_390_10_CFL = -1;
static gint ett_062_390_11 = -1;
static gint ett_062_390_11_CNTR = -1;
static gint ett_062_390_11_POS = -1;
static gint ett_062_390_12 = -1;
static gint ett_062_390_12_TYP = -1;
static gint ett_062_390_12_DAY = -1;
static gint ett_062_390_12_HOR = -1;
static gint ett_062_390_12_MIN = -1;
static gint ett_062_390_12_AVS = -1;
static gint ett_062_390_12_SEC = -1;
static gint ett_062_390_13 = -1;
static gint ett_062_390_13_STAND = -1;
static gint ett_062_390_14 = -1;
static gint ett_062_390_14_EMP = -1;
static gint ett_062_390_14_AVL = -1;
static gint ett_062_390_15 = -1;
static gint ett_062_390_15_SID = -1;
static gint ett_062_390_16 = -1;
static gint ett_062_390_16_STAR = -1;
static gint ett_062_390_17 = -1;
static gint ett_062_390_17_VA = -1;
static gint ett_062_390_17_SQUAWK = -1;
static gint ett_062_390_18 = -1;
static gint ett_062_390_18_CS = -1;
static gint ett_062_500 = -1;
static gint ett_062_500_01 = -1;
static gint ett_062_500_01_APCX = -1;
static gint ett_062_500_01_APCY = -1;
static gint ett_062_500_02 = -1;
static gint ett_062_500_02_COV = -1;
static gint ett_062_500_03 = -1;
static gint ett_062_500_03_APWLAT = -1;
static gint ett_062_500_03_APWLON = -1;
static gint ett_062_500_04 = -1;
static gint ett_062_500_04_AGA = -1;
static gint ett_062_500_05 = -1;
static gint ett_062_500_05_ABA = -1;
static gint ett_062_500_06 = -1;
static gint ett_062_500_06_ATVX = -1;
static gint ett_062_500_06_ATVY = -1;
static gint ett_062_500_07 = -1;
static gint ett_062_500_07_AAX = -1;
static gint ett_062_500_07_AAY = -1;
static gint ett_062_500_08 = -1;
static gint ett_062_500_08_ARC = -1;
/* v.0.17 */
static gint ett_062_500_01_APCX_8bit = -1;
static gint ett_062_500_01_APCY_8bit = -1;
static gint ett_062_500_02_v0_17 = -1;
static gint ett_062_500_02_APWLAT = -1;
static gint ett_062_500_02_APWLON = -1;
static gint ett_062_500_03_v0_17 = -1;
static gint ett_062_500_03_ATA = -1;
static gint ett_062_500_04_v0_17 = -1;
static gint ett_062_500_04_ATF = -1;
static gint ett_062_500_05_v0_17 = -1;
static gint ett_062_500_05_ATVS = -1;
static gint ett_062_500_05_ATVH = -1;
static gint ett_062_500_06_v0_17 = -1;
static gint ett_062_500_06_ART = -1;
static gint ett_062_500_07_v0_17 = -1;
static gint ett_062_500_07_ALA = -1;
static gint ett_062_510 = -1;
static gint ett_062_510_SID = -1;
static gint ett_062_510_STN = -1;
static gint ett_062_RE = -1;
static gint ett_062_RE_CST = -1;
static gint ett_062_RE_CST_SAC = -1;
static gint ett_062_RE_CST_SIC = -1;
static gint ett_062_RE_CST_TYP = -1;
static gint ett_062_RE_CST_TRK_NUM = -1;
static gint ett_062_RE_CSNT = -1;
static gint ett_062_RE_CSNT_SAC = -1;
static gint ett_062_RE_CSNT_SIC = -1;
static gint ett_062_RE_CSNT_TYP = -1;
static gint ett_062_RE_TVS = -1;
static gint ett_062_RE_TVS_VX = -1;
static gint ett_062_RE_TVS_VY = -1;
static gint ett_062_RE_STS = -1;
static gint ett_062_RE_STS_FDR = -1;
static gint ett_062_SP = -1;
/* Category 063 */
static gint ett_063_010 = -1;
static gint ett_063_015 = -1;
static gint ett_063_030 = -1;
static gint ett_063_050 = -1;
static gint ett_063_060 = -1;
static gint ett_063_070 = -1;
static gint ett_063_080 = -1;
static gint ett_063_081 = -1;
static gint ett_063_090 = -1;
static gint ett_063_091 = -1;
static gint ett_063_092 = -1;
static gint ett_063_RE = -1;
static gint ett_063_SP = -1;
/* Category 065 */
static gint ett_065_000 = -1;
static gint ett_065_010 = -1;
static gint ett_065_015 = -1;
static gint ett_065_020 = -1;
static gint ett_065_030 = -1;
static gint ett_065_040 = -1;
static gint ett_065_050 = -1;
static gint ett_065_RE  = -1;
static gint ett_065_SP  = -1;

static dissector_handle_t asterix_handle;

#define FIXED       0x01
#define REPETITIVE  0x02
#define FX          0x04
#define RE          0x08
#define COMPOUND    0x10
#define UAP         0x20
#define SP          0x40

#define FIELD_PART_INT        0
#define FIELD_PART_UINT       1
#define FIELD_PART_FLOAT      2
#define FIELD_PART_UFLOAT     3
#define FIELD_PART_SQUAWK     4
#define FIELD_PART_CALLSIGN   5
#define FIELD_PART_ASCII      6
#define FIELD_PART_FX         7
#define FIELD_PART_HEX        8

typedef struct FieldPart_s FieldPart;
struct FieldPart_s {
    guint8      bit_length;     /* length of field in bits */
    double      scaling_factor; /* scaling factor of the field (for instance: 1/128) */
    guint8      type;           /* Pre-defined type for proper presentation */
    gint       *hf;             /* Pointer to hf representing this kind of data */
    const char *format_string;  /* format string for showing float values */
};

typedef struct AsterixField_s AsterixField;
struct AsterixField_s {
    guint8               type;                    /* type of field */
    guint                length;                  /* fixed length */
    guint                repetition_counter_size; /* size of repetition counter, length of one item is in length */
    guint                header_length;           /* the size is in first header_length bytes of the field */
    gint                *hf;                      /* pointer to Wireshark hf_register_info */
    const FieldPart    **part;                    /* Look declaration and description of FieldPart above. */
    const AsterixField  *field[];                 /* subfields */
};

static void dissect_asterix (tvbuff_t *, packet_info *, proto_tree *);
static void dissect_asterix_packet (tvbuff_t *, proto_tree *);
static void dissect_asterix_data_block (tvbuff_t *tvb, guint, proto_tree *, guint8, gint);
static gint dissect_asterix_fields (tvbuff_t *, guint, proto_tree *, guint8, const AsterixField *[]);

static void asterix_build_subtree (tvbuff_t *, guint, proto_tree *, const AsterixField *);
static void twos_complement (gint64 *, guint8);
static guint8 byte_length (guint8);
static guint8 asterix_bit (guint8, guint8);
static guint8 asterix_fspec_len (tvbuff_t *, guint);
static guint8 asterix_field_exists (tvbuff_t *, guint, int);
static guint8 asterix_get_active_uap (tvbuff_t *, guint, guint8);
static int asterix_field_length (tvbuff_t *, guint, const AsterixField *);
static int asterix_field_offset (tvbuff_t *, guint, const AsterixField *[], int);
static int asterix_message_length (tvbuff_t *, guint, guint8, guint8);

static const char AISCode[] = { ' ', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
                                'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', ' ', ' ', ' ', ' ', ' ',
                                ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
                                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ' ', ' ', ' ', ' ', ' ', ' ' };

static const value_string valstr_XXX_FX[] = {
    { 0, "End of data item" },
    { 1, "Extension into next extent" },
    { 0, NULL }
};
static const FieldPart IXXX_FX = { 1, 1.0, FIELD_PART_FX, &hf_XXX_FX, NULL };
/*static const FieldPart IXXX_2FX = { 1, 1.0, FIELD_PART_FX, &hf_XXX_2FX, NULL };*/
static const FieldPart IXXX_3FX        = { 1, 1.0, FIELD_PART_FX, &hf_XXX_3FX, NULL };
static const FieldPart IXXX_1bit_spare = { 1, 1.0, FIELD_PART_UINT, NULL, NULL };
static const FieldPart IXXX_2bit_spare = { 2, 1.0, FIELD_PART_UINT, NULL, NULL };
static const FieldPart IXXX_3bit_spare = { 3, 1.0, FIELD_PART_UINT, NULL, NULL };
static const FieldPart IXXX_4bit_spare = { 4, 1.0, FIELD_PART_UINT, NULL, NULL };
static const FieldPart IXXX_5bit_spare = { 5, 1.0, FIELD_PART_UINT, NULL, NULL };
static const FieldPart IXXX_6bit_spare = { 6, 1.0, FIELD_PART_UINT, NULL, NULL };
static const FieldPart IXXX_7bit_spare = { 7, 1.0, FIELD_PART_UINT, NULL, NULL };

/* SAC SIC */
static const FieldPart IXXX_SAC = { 8, 1.0, FIELD_PART_UINT, &hf_XXX_SAC, NULL };
static const FieldPart IXXX_SIC = { 8, 1.0, FIELD_PART_UINT, &hf_XXX_SIC, NULL };
static const FieldPart *IXXX_SAC_SIC[] = { &IXXX_SAC, &IXXX_SIC, NULL };

/* Time of day */
static const FieldPart IXXX_TOD_VAL = { 24, 1.0/128.0, FIELD_PART_UFLOAT, &hf_XXX_TOD, "%.3f" };
static const FieldPart *IXXX_TOD[] = { &IXXX_TOD_VAL, NULL };

/* Track number */
static const FieldPart IXXX_TN_16 = { 16, 1.0, FIELD_PART_UINT, &hf_XXX_TN_16, NULL };
static const FieldPart *IXXX_TN_16_PARTS[] = { &IXXX_TN_16, NULL };

/* Aircraft Address */
static const FieldPart IXXX_AA = { 24, 1.0, FIELD_PART_HEX, &hf_XXX_AA, NULL };
static const FieldPart *IXXX_AA_PARTS[] = { &IXXX_AA, NULL };

/* Aircraft Identification */
static const FieldPart IXXX_AI = { 48, 1.0, FIELD_PART_CALLSIGN, &hf_XXX_AI, NULL };
static const FieldPart *IXXX_AI_PARTS[] = { &IXXX_AI, NULL };

/* Mode S MB Data */
static const FieldPart IXXX_MB_DATA = { 56, 1.0, FIELD_PART_HEX, &hf_XXX_MB_DATA, NULL };
static const FieldPart IXXX_BDS1 = { 4, 1.0, FIELD_PART_UINT, &hf_XXX_BDS1, NULL };
static const FieldPart IXXX_BDS2 = { 4, 1.0, FIELD_PART_UINT, &hf_XXX_BDS2, NULL };
static const FieldPart *IXXX_MB[] = { &IXXX_MB_DATA, &IXXX_BDS1, &IXXX_BDS2, NULL };

/* Spare Item */
static const AsterixField IX_SPARE = { FIXED, 0, 0, 0, &hf_spare, NULL, { NULL } };

/* *********************** */
/*      Category 001       */
/* *********************** */
/* Fields */

/* Target report descriptor */
static const value_string valstr_001_020_TYP[] = {
    { 0, "Plot" },
    { 1, "Track" },
    { 0, NULL }
};
static const value_string valstr_001_020_SIM[] = {
    { 0, "Actual plot or track" },
    { 1, "Simulated plot or track" },
    { 0, NULL }
};
static const value_string valstr_001_020_SSR_PSR[] = {
    { 0, "No detection" },
    { 1, "Sole primary detection" },
    { 2, "Sole secondary detection" },
    { 3, "Combined primary and secondary detection" },
    { 0, NULL }
};
static const value_string valstr_001_020_ANT[] = {
    { 0, "Target report from antenna 1" },
    { 1, "Target report from antenna 2" },
    { 0, NULL }
};
static const value_string valstr_001_020_SPI[] = {
    { 0, "Default" },
    { 1, "Special Position Identification" },
    { 0, NULL }
};
static const value_string valstr_001_020_RAB[] = {
    { 0, "Default" },
    { 1, "Plot or track from a fixed transponder" },
    { 0, NULL }
};
static const value_string valstr_001_020_TST[] = {
    { 0, "Default" },
    { 1, "Test target indicator" },
    { 0, NULL }
};
static const value_string valstr_001_020_DS12[] = {
    { 0, "Default" },
    { 1, "Unlawful interference (code 7500)" },
    { 2, "Radio-communication failure (code 7600)" },
    { 3, "Emergency (code 7700)" },
    { 0, NULL }
};
static const value_string valstr_001_020_ME[] = {
    { 0, "Default" },
    { 1, "Military emergency" },
    { 0, NULL }
};
static const value_string valstr_001_020_MI[] = {
    { 0, "Default" },
    { 1, "Military identification" },
    { 0, NULL }
};
static const FieldPart I001_020_TYP = { 1, 1.0, FIELD_PART_UINT, &hf_001_020_TYP, NULL };
static const FieldPart I001_020_SIM = { 1, 1.0, FIELD_PART_UINT, &hf_001_020_SIM, NULL };
static const FieldPart I001_020_SSR_PSR = { 2, 1.0, FIELD_PART_UINT, &hf_001_020_SSR_PSR, NULL };
static const FieldPart I001_020_ANT = { 1, 1.0, FIELD_PART_UINT, &hf_001_020_ANT, NULL };
static const FieldPart I001_020_SPI = { 1, 1.0, FIELD_PART_UINT, &hf_001_020_SPI, NULL };
static const FieldPart I001_020_RAB = { 1, 1.0, FIELD_PART_UINT, &hf_001_020_RAB, NULL };
static const FieldPart I001_020_TST = { 1, 1.0, FIELD_PART_UINT, &hf_001_020_TST, NULL };
static const FieldPart I001_020_DS12 = { 2, 1.0, FIELD_PART_UINT, &hf_001_020_DS12, NULL };
static const FieldPart I001_020_ME = { 1, 1.0, FIELD_PART_UINT, &hf_001_020_ME, NULL };
static const FieldPart I001_020_MI = { 1, 1.0, FIELD_PART_UINT, &hf_001_020_MI, NULL };
static const FieldPart *I001_020_PARTS[] = { &I001_020_TYP, &I001_020_SIM, &I001_020_SSR_PSR, &I001_020_ANT, &I001_020_SPI, &I001_020_RAB, &IXXX_FX,
                                             &I001_020_TST, &I001_020_DS12, &I001_020_ME, &I001_020_MI, &IXXX_2bit_spare, &IXXX_FX, NULL };

/* Warning/Error Conditions */
static const value_string valstr_001_030_WE[] = {
    {  0, "no warning nor error condition" },
    {  1, "garbled reply" },
    {  2, "reflection" },
    {  3, "sidelobe reply" },
    {  4, "split plot" },
    {  5, "second time around reply" },
    {  6, "angels" },
    {  7, "terrestrial vehicles" },
    { 64, "possible wrong code in Mode-3/A" },
    { 65, "possible wrong altitude information, transmitted when the Code C credibility check fails together with the Mode-C code in binary notation" },
    { 66, "possible phantom MSSR plot" },
    { 80, "fixed PSR plot" },
    { 81, "slow PSR plot" },
    { 82, "low quality PSR plot" },
    { 0, NULL }
};
static const FieldPart I001_030_WE = { 7, 1.0, FIELD_PART_UINT, &hf_001_030_WE, NULL };
static const FieldPart *I001_030_PARTS[] = { &I001_030_WE, &IXXX_FX, NULL };

/* Measured Position in Polar Coordinates */
static const FieldPart I001_040_RHO = { 16, 1.0/128.0, FIELD_PART_UFLOAT, &hf_001_040_RHO, NULL };
static const FieldPart I001_040_THETA = { 16, 360.0/65536.0, FIELD_PART_UFLOAT, &hf_001_040_THETA, NULL };
static const FieldPart *I001_040_PARTS[] = { &I001_040_RHO, &I001_040_THETA, NULL };

/* Cartesian position */
static const FieldPart I001_042_X = { 16, 1.0/64.0, FIELD_PART_FLOAT, &hf_001_042_X, NULL };
static const FieldPart I001_042_Y = { 16, 1.0/64.0, FIELD_PART_FLOAT, &hf_001_042_Y, NULL };
static const FieldPart *I001_042_PARTS[] = { &I001_042_X, &I001_042_Y, NULL };

/* Mode-3/A Code */
static const value_string valstr_001_070_V[] = {
    { 0, "Code validated" },
    { 1, "Code not validated" },
    { 0, NULL }
};
static const value_string valstr_001_070_G[] = {
    { 0, "Default" },
    { 1, "Garbled code" },
    { 0, NULL }
};
static const value_string valstr_001_070_L[] = {
    { 0, "Mode-3/A code as derived from the reply of the transponder" },
    { 1, "Smoothed Mode-3/A code as provided by a local tracker" },
    { 0, NULL }
};
static const FieldPart I001_070_V = { 1, 1.0, FIELD_PART_UINT, &hf_001_070_V, NULL };
static const FieldPart I001_070_G = { 1, 1.0, FIELD_PART_UINT, &hf_001_070_G, NULL };
static const FieldPart I001_070_L = { 1, 1.0, FIELD_PART_UINT, &hf_001_070_L, NULL };
static const FieldPart I001_070_SQUAWK = { 12, 1.0, FIELD_PART_SQUAWK, &hf_001_070_SQUAWK, NULL };
static const FieldPart *I001_070_PARTS[] = { &I001_070_V, &I001_070_G, &I001_070_L, &IXXX_1bit_spare, &I001_070_SQUAWK, NULL };

/* Mode-3/A Code Confidence Indicator */
static const value_string valstr_001_080_QA[] = {
    { 0, "High quality pulse" },
    { 1, "Low quality pulse" },
    { 0, NULL }
};
static const FieldPart I001_080_QA4 = { 1, 1.0, FIELD_PART_UINT, &hf_001_080_QA4, NULL };
static const FieldPart I001_080_QA2 = { 1, 1.0, FIELD_PART_UINT, &hf_001_080_QA2, NULL };
static const FieldPart I001_080_QA1 = { 1, 1.0, FIELD_PART_UINT, &hf_001_080_QA1, NULL };
static const FieldPart I001_080_QB4 = { 1, 1.0, FIELD_PART_UINT, &hf_001_080_QB4, NULL };
static const FieldPart I001_080_QB2 = { 1, 1.0, FIELD_PART_UINT, &hf_001_080_QB2, NULL };
static const FieldPart I001_080_QB1 = { 1, 1.0, FIELD_PART_UINT, &hf_001_080_QB1, NULL };
static const FieldPart I001_080_QC4 = { 1, 1.0, FIELD_PART_UINT, &hf_001_080_QC4, NULL };
static const FieldPart I001_080_QC2 = { 1, 1.0, FIELD_PART_UINT, &hf_001_080_QC2, NULL };
static const FieldPart I001_080_QC1 = { 1, 1.0, FIELD_PART_UINT, &hf_001_080_QC1, NULL };
static const FieldPart I001_080_QD4 = { 1, 1.0, FIELD_PART_UINT, &hf_001_080_QD4, NULL };
static const FieldPart I001_080_QD2 = { 1, 1.0, FIELD_PART_UINT, &hf_001_080_QD2, NULL };
static const FieldPart I001_080_QD1 = { 1, 1.0, FIELD_PART_UINT, &hf_001_080_QD1, NULL };
static const FieldPart *I001_080_PARTS[] = { &IXXX_4bit_spare,
                                              &I001_080_QA4, &I001_080_QA2, &I001_080_QA1,
                                              &I001_080_QB4, &I001_080_QB2, &I001_080_QB1,
                                              &I001_080_QC4, &I001_080_QC2, &I001_080_QC1,
                                              &I001_080_QD4, &I001_080_QD2, &I001_080_QD1, NULL };

/* Mode-C Code in Binary Representation - Flight Level */
static const value_string valstr_001_090_V[] = {
    { 0, "Code validated" },
    { 1, "Code not validated" },
    { 0, NULL }
};
static const value_string valstr_001_090_G[] = {
    { 0, "Default" },
    { 1, "Garbled code" },
    { 0, NULL }
};
static const FieldPart I001_090_V = { 1, 1.0, FIELD_PART_UINT, &hf_001_090_V, NULL };
static const FieldPart I001_090_G = { 1, 1.0, FIELD_PART_UINT, &hf_001_090_G, NULL };
static const FieldPart I001_090_FL = { 14, 1.0/4.0, FIELD_PART_FLOAT, &hf_001_090_FL, NULL };
static const FieldPart *I001_090_PARTS[] = { &I001_090_V, &I001_090_G, &I001_090_FL, NULL, NULL };

/* Truncated Time of Day */
static const FieldPart I001_141_TTOD = { 16, 1.0/128.0, FIELD_PART_UFLOAT, &hf_001_141_TTOD, NULL };
static const FieldPart *I001_141_PARTS[] = { &I001_141_TTOD, NULL };

/* Track Plot Number */
static const FieldPart I001_161_TPN = { 16, 1.0, FIELD_PART_UINT, &hf_001_161_TPN, NULL };
static const FieldPart *I001_161_PARTS[] = { &I001_161_TPN, NULL };

/* Track Status */
static const value_string valstr_001_170_CON[] = {
    { 0, "Confirmed track" },
    { 1, "Track in initialisation phase" },
    { 0, NULL }
};
static const value_string valstr_001_170_RAD[] = {
    { 0, "Primary track" },
    { 1, "SSR/Combined track" },
    { 0, NULL }
};
static const value_string valstr_001_170_MAN[] = {
    { 0, "Default" },
    { 1, "Aircraft manoeuvring" },
    { 0, NULL }
};
static const value_string valstr_001_170_DOU[] = {
    { 0, "Default" },
    { 1, "Doubtful plot to track association" },
    { 0, NULL }
};
static const value_string valstr_001_170_RDPC[] = {
    { 0, "RDP Chain 1" },
    { 1, "RDP Chain 2" },
    { 0, NULL }
};
static const value_string valstr_001_170_GHO[] = {
    { 0, "Default" },
    { 1, "Ghost track" },
    { 0, NULL }
};
static const value_string valstr_001_170_TRE[] = {
    { 0, "Default" },
    { 1, "Last report for a track" },
    { 0, NULL }
};
static const FieldPart I001_170_CON = { 1, 1.0, FIELD_PART_UINT, &hf_001_170_CON, NULL };
static const FieldPart I001_170_RAD = { 1, 1.0, FIELD_PART_UINT, &hf_001_170_RAD, NULL };
static const FieldPart I001_170_MAN = { 1, 1.0, FIELD_PART_UINT, &hf_001_170_MAN, NULL };
static const FieldPart I001_170_DOU = { 1, 1.0, FIELD_PART_UINT, &hf_001_170_DOU, NULL };
static const FieldPart I001_170_RDPC = { 1, 1.0, FIELD_PART_UINT, &hf_001_170_RDPC, NULL };
static const FieldPart I001_170_GHO = { 1, 1.0, FIELD_PART_UINT, &hf_001_170_GHO, NULL };
static const FieldPart I001_170_TRE = { 1, 1.0, FIELD_PART_UINT, &hf_001_170_TRE, NULL };
static const FieldPart *I001_170_PARTS[] = { &I001_170_CON, &I001_170_RAD, &I001_170_MAN, &I001_170_DOU, &I001_170_RDPC, &IXXX_1bit_spare, &I001_170_GHO, &IXXX_FX,
                                              &I001_170_TRE, &IXXX_6bit_spare, &IXXX_FX, NULL };

/* Items */
static const AsterixField I001_010 = { FIXED, 2, 0, 0, &hf_001_010, IXXX_SAC_SIC, { NULL } };
static const AsterixField I001_020 = { FX + UAP, 1, 0, 0, &hf_001_020, I001_020_PARTS, { NULL } };
static const AsterixField I001_030 = { FX, 1, 0, 0, &hf_001_030, I001_030_PARTS, { NULL } };
static const AsterixField I001_040 = { FIXED, 4, 0, 0, &hf_001_040, I001_040_PARTS, { NULL } };
static const AsterixField I001_042 = { FIXED, 4, 0, 0, &hf_001_042, I001_042_PARTS, { NULL } };
static const AsterixField I001_050 = { FIXED, 2, 0, 0, &hf_001_050, NULL, { NULL } };
static const AsterixField I001_060 = { FIXED, 2, 0, 0, &hf_001_060, NULL, { NULL } };
static const AsterixField I001_070 = { FIXED, 2, 0, 0, &hf_001_070, I001_070_PARTS, { NULL } };
static const AsterixField I001_080 = { FIXED, 2, 0, 0, &hf_001_080, I001_080_PARTS, { NULL } };
static const AsterixField I001_090 = { FIXED, 2, 0, 0, &hf_001_090, I001_090_PARTS, { NULL } };
static const AsterixField I001_100 = { FIXED, 4, 0, 0, &hf_001_100, NULL, { NULL } };
static const AsterixField I001_120 = { FIXED, 1, 0, 0, &hf_001_120, NULL, { NULL } };
static const AsterixField I001_130 = { FX, 1, 0, 0, &hf_001_130, NULL, { NULL } };
static const AsterixField I001_131 = { FIXED, 1, 0, 0, &hf_001_131, NULL, { NULL } };
static const AsterixField I001_141 = { FIXED, 2, 0, 0, &hf_001_141, I001_141_PARTS, { NULL } };
static const AsterixField I001_150 = { FIXED, 1, 0, 0, &hf_001_150, NULL, { NULL } };
static const AsterixField I001_161 = { FIXED, 2, 0, 0, &hf_001_161, I001_161_PARTS, { NULL } };
static const AsterixField I001_170 = { FX, 1, 0, 0, &hf_001_170, I001_170_PARTS, { NULL } };
static const AsterixField I001_200 = { FIXED, 4, 0, 0, &hf_001_200, NULL, { NULL } };
static const AsterixField I001_210 = { FIXED, 1, 0, 0, &hf_001_210, NULL, { NULL } };
static const AsterixField I001_RE = { RE, 0, 0, 1, &hf_001_RE, NULL, { NULL } };
static const AsterixField I001_SP = { SP, 0, 0, 1, &hf_001_SP, NULL, { NULL } };

static const AsterixField *I001_PLOT_v1_2_uap[] = { &I001_010, &I001_020, &I001_040, &I001_070, &I001_090, &I001_130, &I001_141,
                                                    &I001_050, &I001_120, &I001_131, &I001_080, &I001_100, &I001_060, &I001_030,
                                                    &I001_150, &IX_SPARE, &IX_SPARE, &IX_SPARE, &IX_SPARE, &I001_SP,  &I001_RE, NULL };

static const AsterixField *I001_TRACK_v1_2_uap[] = { &I001_010, &I001_020, &I001_161, &I001_040, &I001_042, &I001_200, &I001_070,
                                                     &I001_090, &I001_141, &I001_130, &I001_131, &I001_120, &I001_170, &I001_210,
                                                     &I001_050, &I001_080, &I001_100, &I001_060, &I001_030, &I001_SP,  &I001_RE,
                                                     &I001_150, NULL };
/* array of two (PLOT, TRACK) is for two different user application profiles (UAPs) */
static const AsterixField **I001_v1_2[] = { I001_PLOT_v1_2_uap, I001_TRACK_v1_2_uap, NULL };
static const AsterixField ***I001[] = { I001_v1_2 };

static const enum_val_t I001_versions[] = {
    { "I001_v1_2", "Version 1.2", 0 },
    { NULL, NULL, 0 }
};

/* *********************** */
/*      Category 002       */
/* *********************** */
/* Fields */

/* Message Type */
static const value_string valstr_002_000_MT[] = {
    { 1, "North Marker message" },
    { 2, "Sector crossing message" },
    { 3, "South marker message" },
    { 8, "Activation of blind zone filtering" },
    { 9, "Stop of blind zone filtering" },
    { 0, NULL }
};
static const FieldPart I002_000_MT = { 8, 1.0, FIELD_PART_UINT, &hf_002_000_MT, NULL };
static const FieldPart *I002_000_PARTS[] = { &I002_000_MT, NULL };

/* Sector Number */
static const FieldPart I002_020_SN = { 8, 360.0/256.0, FIELD_PART_UFLOAT, &hf_002_020_SN, NULL };
static const FieldPart *I002_020_PARTS[] = { &I002_020_SN, NULL };

/* Antenna Rotation Speed */
static const FieldPart I002_041_ARS = { 16, 1.0/128.0, FIELD_PART_UFLOAT, &hf_002_041_ARS, NULL };
static const FieldPart *I002_041_PARTS[] = { &I002_041_ARS, NULL };

/* Plot Count Values */
static const value_string valstr_002_070_A[] = {
    { 0, "Counter for antenna 1" },
    { 1, "Counter for antenna 2" },
    { 0, NULL }
};
static const value_string valstr_002_070_IDENT[] = {
    { 1, "Sole primary plots" },
    { 2, "Sole SSR plots" },
    { 3, "Combined plots" },
    { 0, NULL }
};
static const FieldPart I002_070_A = { 1, 1.0, FIELD_PART_UINT, &hf_002_070_A, NULL };
static const FieldPart I002_070_IDENT = { 5, 1.0, FIELD_PART_UINT, &hf_002_070_IDENT, NULL };
static const FieldPart I002_070_COUNTER = { 10, 1.0, FIELD_PART_UINT, &hf_002_070_COUNTER, NULL };
static const FieldPart *I002_070_PARTS[] = { &I002_070_A, &I002_070_IDENT, &I002_070_COUNTER, NULL };

/* Warning/Error Conditions */
static const FieldPart I002_080_WE = { 7, 1.0, FIELD_PART_UINT, &hf_002_080_WE, NULL };
static const FieldPart *I002_080_PARTS[] = { &I002_080_WE, &IXXX_FX, NULL };

/* Collimation Error */
static const FieldPart I002_090_RE = { 8, 1.0/128.0, FIELD_PART_FLOAT, &hf_002_090_RE, NULL };
static const FieldPart I002_090_AE = { 8, 360.0/16384.0, FIELD_PART_FLOAT, &hf_002_090_AE, NULL };
static const FieldPart *I002_090_PARTS[] = { &I002_090_RE, &I002_090_AE, NULL };

/* Dynamic Window - Type 1 */
static const FieldPart I002_100_RHOS = { 16, 1.0/128.0, FIELD_PART_UFLOAT, &hf_002_100_RHOS, NULL };
static const FieldPart I002_100_RHOE = { 16, 1.0/128.0, FIELD_PART_UFLOAT, &hf_002_100_RHOE, NULL };
static const FieldPart I002_100_THETAS = { 16, 360.0/65536.0, FIELD_PART_UFLOAT, &hf_002_100_THETAS, NULL };
static const FieldPart I002_100_THETAE = { 16, 360.0/65536.0, FIELD_PART_UFLOAT, &hf_002_100_THETAE, NULL };
static const FieldPart *I002_100_PARTS[] = { &I002_100_RHOS, &I002_100_RHOE, &I002_100_THETAS, &I002_100_THETAE, NULL };

/* Items */
static const AsterixField I002_000 = { FIXED, 1, 0, 0, &hf_002_000, I002_000_PARTS, { NULL } };
static const AsterixField I002_010 = { FIXED, 2, 0, 0, &hf_002_010, IXXX_SAC_SIC, { NULL } };
static const AsterixField I002_020 = { FIXED, 1, 0, 0, &hf_002_020, I002_020_PARTS, { NULL } };
static const AsterixField I002_030 = { FIXED, 3, 0, 0, &hf_002_030, IXXX_TOD, { NULL } };
static const AsterixField I002_041 = { FIXED, 2, 0, 0, &hf_002_041, I002_041_PARTS, { NULL } };
static const AsterixField I002_050 = { FX, 1, 0, 0, &hf_002_050, NULL, { NULL } };
static const AsterixField I002_060 = { FX, 1, 0, 0, &hf_002_060, NULL, { NULL } };
static const AsterixField I002_070 = { REPETITIVE, 2, 1, 0, &hf_002_070, I002_070_PARTS, { NULL } };
static const AsterixField I002_080 = { FIXED, 2, 0, 0, &hf_002_080, I002_080_PARTS, { NULL } };
static const AsterixField I002_090 = { FIXED, 2, 0, 0, &hf_002_090, I002_090_PARTS, { NULL } };
static const AsterixField I002_100 = { FIXED, 8, 0, 0, &hf_002_100, I002_100_PARTS, { NULL } };
static const AsterixField I002_RE = { RE, 0, 0, 1, &hf_002_RE, NULL, { NULL } };
static const AsterixField I002_SP = { SP, 0, 0, 1, &hf_002_SP, NULL, { NULL } };

static const AsterixField *I002_v1_0_uap[] = { &I002_010, &I002_000, &I002_020, &I002_030, &I002_041, &I002_050, &I002_060,
                                               &I002_070, &I002_100, &I002_090, &I002_080, &IX_SPARE, &I002_SP,  &I002_RE, NULL };
static const AsterixField **I002_v1_0[] = { I002_v1_0_uap, NULL };
static const AsterixField ***I002[] = { I002_v1_0 };

static const enum_val_t I002_versions[] = {
    { "I002_v1_0", "Version 1.0", 0 },
    { NULL, NULL, 0 }
};

/* *********************** */
/*      Category 008       */
/* *********************** */
/* Fields */

/* Message Type */
static const value_string valstr_008_000_MT[] = {
    { 001, "Polar vector" },
    { 002, "Cartesian vector of start point/ length" },
    { 003, "Contour record" },
    { 004, "Cartesian start point and end point vector" },
    { 254, "SOP message" },
    { 255, "EOP message" },
    { 0, NULL }
};
static const FieldPart I008_000_MT = { 8, 1.0, FIELD_PART_UINT, &hf_008_000_MT, NULL };
static const FieldPart *I008_000_PARTS[] = { &I008_000_MT, NULL };

/* Vector Qualifier */
static const value_string valstr_008_020_ORG[] = {
    { 0, "Local Coordinates" },
    { 1, "System Coordinates" },
    { 0, NULL }
};
static const value_string valstr_008_020_DIR[] = {
    { 0, "0" },
    { 1, "22.5" },
    { 2, "45" },
    { 3, "67.5" },
    { 4, "90" },
    { 5, "112,5" },
    { 6, "135" },
    { 7, "157.5" },
    { 0, NULL }
};
static const value_string valstr_008_020_TST[] = {
    { 0, "Default" },
    { 1, "Test vector" },
    { 0, NULL }
};
static const value_string valstr_008_020_ER[] = {
    { 0, "Default" },
    { 1, "Error condition encountered" },
    { 0, NULL }
};
static const FieldPart I008_020_ORG = { 1, 1.0, FIELD_PART_UINT, &hf_008_020_ORG, NULL };
static const FieldPart I008_020_INT = { 3, 1.0, FIELD_PART_UINT, &hf_008_020_INT, NULL };
static const FieldPart I008_020_DIR = { 3, 1.0, FIELD_PART_UINT, &hf_008_020_DIR, NULL };
static const FieldPart I008_020_TST = { 1, 1.0, FIELD_PART_UINT, &hf_008_020_TST, NULL };
static const FieldPart I008_020_ER  = { 1, 1.0, FIELD_PART_UINT, &hf_008_020_ER, NULL };
static const FieldPart *I008_020_PARTS[] = { &I008_020_ORG, &I008_020_INT, &I008_020_DIR, &IXXX_FX,
                                             &IXXX_5bit_spare, &I008_020_TST, &I008_020_ER, &IXXX_FX, NULL };

/* Sequence of Polar Vectors in SPF Notation */
static const FieldPart I008_034_START_RANGE = { 8, 1.0/128.0, FIELD_PART_UFLOAT, &hf_008_034_START_RANGE, NULL };
static const FieldPart I008_034_END_RANGE = { 8, 1.0/128.0, FIELD_PART_UFLOAT, &hf_008_034_END_RANGE, NULL };
static const FieldPart I008_034_AZIMUTH = { 16, 360.0/65536.0, FIELD_PART_UFLOAT, &hf_008_034_AZIMUTH, NULL };
static const FieldPart *I008_034_PARTS[] = { &I008_034_START_RANGE, &I008_034_END_RANGE, &I008_034_AZIMUTH, NULL };

/* Sequence of Cartesian Vectors in SPF Notation */
static const FieldPart I008_036_X = { 8, 1.0/64.0, FIELD_PART_FLOAT, &hf_008_036_X, NULL };
static const FieldPart I008_036_Y = { 8, 1.0/64.0, FIELD_PART_FLOAT, &hf_008_036_Y, NULL };
static const FieldPart I008_036_VL = { 8, 1.0/64.0, FIELD_PART_FLOAT, &hf_008_036_VL, NULL };
static const FieldPart *I008_036_PARTS[] = { &I008_036_X, &I008_036_Y, &I008_036_VL, NULL };

/* Sequence of Weather Vectors in SPF Notation */
static const FieldPart I008_038_X1 = { 8, 1.0/64.0, FIELD_PART_FLOAT, &hf_008_038_X1, NULL };
static const FieldPart I008_038_Y1 = { 8, 1.0/64.0, FIELD_PART_FLOAT, &hf_008_038_Y1, NULL };
static const FieldPart I008_038_X2 = { 8, 1.0/64.0, FIELD_PART_FLOAT, &hf_008_038_X2, NULL };
static const FieldPart I008_038_Y2 = { 8, 1.0/64.0, FIELD_PART_FLOAT, &hf_008_038_Y2, NULL };
static const FieldPart *I008_038_PARTS[] = { &I008_038_X1, &I008_038_Y1, &I008_038_X2, &I008_038_Y2, NULL };

/* Contour Identifier */
static const value_string valstr_008_040_ORG[] = {
    { 0, "Local Coordinates" },
    { 1, "System Coordinates" },
    { 0, NULL }
};
static const value_string valstr_008_040_FST_LST[] = {
    { 0, "Intermediate record of a contour" },
    { 1, "Last record of a contour of at least two records" },
    { 2, "First record of a contour of at least two records" },
    { 3, "First and only record, fully defining a contour" },
    { 0, NULL }
};

static const FieldPart I008_040_ORG = { 1, 1.0, FIELD_PART_UINT, &hf_008_040_ORG, NULL };
static const FieldPart I008_040_INT = { 3, 1.0, FIELD_PART_UINT, &hf_008_040_INT, NULL };
static const FieldPart I008_040_FST_LST = { 2, 1.0, FIELD_PART_UINT, &hf_008_040_FST_LST, NULL };
static const FieldPart I008_040_CSN  = { 8, 1.0, FIELD_PART_UINT, &hf_008_040_CSN, NULL };
static const FieldPart *I008_040_PARTS[] = { &I008_040_ORG, &I008_040_INT, &IXXX_2bit_spare, &I008_040_FST_LST,
                                             &I008_040_CSN, NULL };

/* Sequence of Contour Points in SPF Notation */
static const FieldPart I008_050_X1 = { 8, 1.0/64.0, FIELD_PART_FLOAT, &hf_008_050_X1, NULL };
static const FieldPart I008_050_Y1 = { 8, 1.0/64.0, FIELD_PART_FLOAT, &hf_008_050_Y1, NULL };
static const FieldPart *I008_050_PARTS[] = { &I008_050_X1, &I008_050_Y1, NULL };

/* Processing Status */
static const FieldPart I008_100_f = { 5, 1.0, FIELD_PART_FLOAT, &hf_008_100_f, NULL };
static const FieldPart I008_100_R = { 3, 1.0, FIELD_PART_UINT, &hf_008_100_R, NULL };
static const FieldPart I008_100_Q = { 15, 1.0, FIELD_PART_UINT, &hf_008_100_Q, NULL };
static const FieldPart *I008_100_PARTS[] = { &I008_100_f, &I008_100_R, &I008_100_Q, &IXXX_FX, NULL };

/* Station Configuration Status */
static const FieldPart I008_110_HW = { 7, 1.0, FIELD_PART_UINT, &hf_008_110_HW, NULL };
static const FieldPart *I008_110_PARTS[] = { &I008_110_HW, &IXXX_FX, NULL };

/* Total Number of Items Constituting One Weather */
static const FieldPart I008_120_COUNT = { 16, 1.0, FIELD_PART_UINT, &hf_008_120_COUNT, NULL };
static const FieldPart *I008_120_PARTS[] = { &I008_120_COUNT, NULL };

/* Items */
static const AsterixField I008_000 = { FIXED, 1, 0, 0, &hf_008_000, I008_000_PARTS, { NULL } };
static const AsterixField I008_010 = { FIXED, 2, 0, 0, &hf_008_010, IXXX_SAC_SIC, { NULL } };
static const AsterixField I008_020 = { FX, 1, 0, 0, &hf_008_020, I008_020_PARTS, { NULL } };
static const AsterixField I008_034 = { REPETITIVE, 4, 1, 0, &hf_008_034, I008_034_PARTS, { NULL } };
static const AsterixField I008_036 = { REPETITIVE, 3, 1, 0, &hf_008_036, I008_036_PARTS, { NULL } };
static const AsterixField I008_038 = { REPETITIVE, 4, 1, 0, &hf_008_038, I008_038_PARTS, { NULL } };
static const AsterixField I008_040 = { FIXED, 2, 0, 0, &hf_008_040, I008_040_PARTS, { NULL } };
static const AsterixField I008_050 = { REPETITIVE, 2, 1, 0, &hf_008_050, I008_050_PARTS, { NULL } };
static const AsterixField I008_090 = { FIXED, 3, 0, 0, &hf_008_090, IXXX_TOD, { NULL } };
static const AsterixField I008_100 = { FX, 3, 0, 0, &hf_008_100, I008_100_PARTS, { NULL } };
static const AsterixField I008_110 = { FX, 1, 0, 0, &hf_008_110, I008_110_PARTS, { NULL } };
static const AsterixField I008_120 = { FIXED, 2, 0, 0, &hf_008_120, I008_120_PARTS, { NULL } };
static const AsterixField I008_SP = { SP, 0, 0, 1, &hf_008_SP, NULL, { NULL } };
static const AsterixField I008_RFS = { RE, 0, 0, 1, &hf_008_RFS, NULL, { NULL } };

static const AsterixField *I008_v1_1_uap[] = { &I008_010, &I008_000, &I008_020, &I008_036, &I008_034, &I008_040, &I008_050,
                                               &I008_090, &I008_100, &I008_110, &I008_120, &I008_038, &I008_SP,  &I008_RFS, NULL };
static const AsterixField **I008_v1_1[] = { I008_v1_1_uap, NULL };
static const AsterixField ***I008[] = { I008_v1_1 };

static const enum_val_t I008_versions[] = {
    { "I008_v1_1", "Version 1.1", 0 },
    { NULL, NULL, 0 }
};

/* *********************** */
/*      Category 009       */
/* *********************** */
/* Fields */

/* Message Type */
static const value_string valstr_009_000_MT[] = {
    { 2, "Cartesian vector messages" },
    { 253, "intermediate-update-step message" },
    { 254, "start-of-picture message" },
    { 255, "end-of-picture message" },
    { 0, NULL }
};
static const FieldPart I009_000_MT = { 8, 1.0, FIELD_PART_UINT, &hf_009_000_MT, NULL };
static const FieldPart *I009_000_PARTS[] = { &I009_000_MT, NULL };

/* Vector Qualifier */
static const value_string valstr_009_020_INT[] = {
    { 0, "no data available" },
    { 1, "intensity 1" },
    { 2, "intensity 2" },
    { 3, "intensity 3" },
    { 4, "intensity 4" },
    { 5, "intensity 5" },
    { 6, "intensity 6" },
    { 7, "intensity 7" },
    { 0, NULL }
};
static const value_string valstr_009_020_DIR[] = {
    { 0, "0" },
    { 1, "22.5" },
    { 2, "45" },
    { 3, "67.5" },
    { 4, "90" },
    { 5, "112,5" },
    { 6, "135" },
    { 7, "157.5" },
    { 0, NULL }
};
static const FieldPart I009_020_ORG = { 1, 1.0, FIELD_PART_UINT, &hf_009_020_ORG, NULL };
static const FieldPart I009_020_INT = { 3, 1.0, FIELD_PART_UINT, &hf_009_020_INT, NULL };
static const FieldPart I009_020_DIR = { 3, 1.0, FIELD_PART_UINT, &hf_009_020_DIR, NULL };
static const FieldPart *I009_020_PARTS[] = { &I009_020_ORG, &I009_020_INT, &I009_020_DIR, &IXXX_FX, NULL };

/* Cartesian Vector */
static const FieldPart I009_030_X = { 16, 1.0/32.0, FIELD_PART_FLOAT, &hf_009_030_X, NULL };
static const FieldPart I009_030_Y = { 16, 1.0/32.0, FIELD_PART_FLOAT, &hf_009_030_Y, NULL };
static const FieldPart I009_030_VL = { 16, 1.0/32.0, FIELD_PART_FLOAT, &hf_009_030_VL, NULL };
static const FieldPart *I009_030_PARTS[] = { &I009_030_X, &I009_030_Y, &I009_030_VL, NULL };

/* Synchronisation/Control Signal */
static const FieldPart I009_060_STEP = { 6, 1.0, FIELD_PART_UINT, &hf_009_060_STEP, NULL };
static const FieldPart *I009_060_PARTS[] = { &I009_060_STEP, &IXXX_1bit_spare, &IXXX_FX, NULL };

/* Processing Status */
static const FieldPart I009_080_SCALE = { 5, 1.0, FIELD_PART_UINT, &hf_009_080_SCALE, NULL };
static const FieldPart I009_080_R = { 3, 1.0, FIELD_PART_UINT, &hf_009_080_R, NULL };
static const FieldPart I009_080_Q = { 15, 1.0, FIELD_PART_UINT, &hf_009_080_Q, NULL };
static const FieldPart *I009_080_PARTS[] = { &I009_080_SCALE, &I009_080_R, &I009_080_Q, &IXXX_3FX, NULL };

/* Radar Configuration and Status */
static const FieldPart I009_090_CP = { 1, 1.0, FIELD_PART_UINT, &hf_009_090_CP, NULL };
static const FieldPart I009_090_WO = { 1, 1.0, FIELD_PART_UINT, &hf_009_090_WO, NULL };
static const FieldPart I009_090_RS = { 3, 1.0, FIELD_PART_UINT, &hf_009_090_RS, NULL };
static const FieldPart *I009_090_PARTS[] = { &IXXX_SAC, &IXXX_SIC, &IXXX_3bit_spare, &I009_090_CP, &I009_090_WO, &I009_090_RS, NULL };

/* Vector Count */
static const FieldPart I009_100_VC = { 16, 1.0, FIELD_PART_UINT, &hf_009_100_VC, NULL };
static const FieldPart *I009_100_PARTS[] = { &I009_100_VC, NULL };

/* Items */
static const AsterixField I009_000 = { FIXED, 1, 0, 0, &hf_009_000, I009_000_PARTS, { NULL } };
static const AsterixField I009_010 = { FIXED, 2, 0, 0, &hf_009_010, IXXX_SAC_SIC, { NULL } };
static const AsterixField I009_020 = { FX, 1, 0, 0, &hf_009_020, I009_020_PARTS, { NULL } };
static const AsterixField I009_030 = { REPETITIVE, 6, 1, 0, &hf_009_030, I009_030_PARTS, { NULL } };
static const AsterixField I009_060 = { FX, 1, 0, 0, &hf_009_060, I009_060_PARTS, { NULL } };
static const AsterixField I009_070 = { FIXED, 3, 0, 0, &hf_009_070, IXXX_TOD, { NULL } };
static const AsterixField I009_080 = { FX, 3, 0, 0, &hf_009_080, I009_080_PARTS, { NULL } };
static const AsterixField I009_090 = { REPETITIVE, 3, 1, 0, &hf_009_090, I009_090_PARTS, { NULL } };
static const AsterixField I009_100 = { FIXED, 2, 0, 0, &hf_009_100, I009_100_PARTS, { NULL } };

static const AsterixField *I009_v2_0_uap[] = { &I009_010, &I009_000, &I009_020, &I009_030, &I009_060, &I009_070, &I009_080,
                                               &I009_090, &I009_100, NULL };
static const AsterixField **I009_v2_0[] = { I009_v2_0_uap, NULL };
static const AsterixField ***I009[] = { I009_v2_0 };

static const enum_val_t I009_versions[] = {
    { "I009_v2_0", "Version 2.0", 0 },
    { NULL, NULL, 0 }
};

/* *********************** */
/*      Category 021       */
/* *********************** */
/* Fields */

/* Aircraft Operational Status */
static const value_string valstr_021_008_RA[] = {
    { 0, "TCAS II or ACAS RA not active" },
    { 1, "TCAS RA active" },
    { 0, NULL }
};
static const value_string valstr_021_008_TC[] = {
    { 0, "no capability for Trajectory Change Reports" },
    { 1, "support for TC+0 reports only" },
    { 2, "support for multiple TC reports" },
    { 3, "reserved" },
    { 0, NULL }
};
static const value_string valstr_021_008_TS[] = {
    { 0, "no capability to support Target State Reports" },
    { 1, "capable of supporting target State Reports" },
    { 0, NULL }
};
static const value_string valstr_021_008_ARV[] = {
    { 0, "no capability to generate ARV-reports" },
    { 1, "capable of generate ARV-reports" },
    { 0, NULL }
};
static const value_string valstr_021_008_CDTIA[] = {
    { 0, "CDTI not operational" },
    { 1, "CDTI operational" },
    { 0, NULL }
};
static const value_string valstr_021_008_not_TCAS[] = {
    { 0, "TCAS operational" },
    { 1, "TCAS not operational" },
    { 0, NULL }
};
static const value_string valstr_021_008_SA[] = {
    { 0, "Antenna Diversity" },
    { 1, "Single Antenna only" },
    { 0, NULL }
};
static const FieldPart I021_008_RA = { 1, 1.0, FIELD_PART_UINT, &hf_021_008_RA, NULL };
static const FieldPart I021_008_TC = { 2, 1.0, FIELD_PART_UINT, &hf_021_008_TC, NULL };
static const FieldPart I021_008_TS = { 1, 1.0, FIELD_PART_UINT, &hf_021_008_TS, NULL };
static const FieldPart I021_008_ARV = { 1, 1.0, FIELD_PART_UINT, &hf_021_008_ARV, NULL };
static const FieldPart I021_008_CDTIA = { 1, 1.0, FIELD_PART_UINT, &hf_021_008_CDTIA, NULL };
static const FieldPart I021_008_not_TCAS = { 1, 1.0, FIELD_PART_UINT, &hf_021_008_not_TCAS, NULL };
static const FieldPart I021_008_SA = { 1, 1.0, FIELD_PART_UINT, &hf_021_008_SA, NULL };
static const FieldPart *I021_008_PARTS[] = { &I021_008_RA, &I021_008_TC, &I021_008_TS, &I021_008_ARV, &I021_008_CDTIA, &I021_008_not_TCAS, &I021_008_SA, NULL };

/* Service Identification */
static const FieldPart I021_015_SI = { 8, 1.0, FIELD_PART_UINT, &hf_021_015_SI, NULL };
static const FieldPart *I021_015_PARTS[] = { &I021_015_SI, NULL };

/* Service Management */
static const FieldPart I021_016_RP = { 8, 0.5, FIELD_PART_UFLOAT, &hf_021_016_RP, NULL };
static const FieldPart *I021_016_PARTS[] = { &I021_016_RP, NULL };

/* Emitter Category */
static const value_string valstr_021_020_ECAT[] = {
    { 0, "No ADS-B Emitter Category Information" },
    { 1, "light aircraft <= 15500 lbs" },
    { 2, "15500 lbs < small aircraft <75000 lbs" },
    { 3, "75000 lbs < medium a/c < 300000 lbs" },
    { 4, "High Vortex Large" },
    { 5, "300000 lbs <= heavy aircraft" },
    { 6, "highly manoeuvrable (5g acceleration capability) and high speed (>400 knots cruise)" },
    { 7, "reserved" },
    { 8, "reserved" },
    { 9, "reserved" },
    { 10, "rotocraft" },
    { 11, "glider / sailplane" },
    { 12, "lighter-than-air" },
    { 13, "unmanned aerial vehicle" },
    { 14, "space / transatmospheric vehicle" },
    { 15, "ultralight / handglider / paraglider" },
    { 16, "parachutist / skydiver" },
    { 17, "reserved" },
    { 18, "reserved" },
    { 19, "reserved" },
    { 20, "surface emergency vehicle" },
    { 21, "surface service vehicle" },
    { 22, "fixed ground or tethered obstruction" },
    { 23, "cluster obstacle" },
    { 24, "line obstacle" },
    { 0, NULL }
};
static const FieldPart I021_020_ECAT = { 8, 1.0, FIELD_PART_UINT, &hf_021_020_ECAT, NULL };
static const FieldPart *I021_020_PARTS[] = { &I021_020_ECAT, NULL };

/* Target Report Descriptor */
static const value_string valstr_021_040_ATP[] = {
    { 0, "24-Bit ICAO address" },
    { 1, "Duplicate address" },
    { 2, "Surface vehicle address" },
    { 3, "Anonymous address" },
    { 4, "Reserved for future use" },
    { 5, "Reserved for future use" },
    { 6, "Reserved for future use" },
    { 7, "Reserved for future use" },
    { 0, NULL }
};
static const value_string valstr_021_040_ARC[] = {
    { 0, "25 ft" },
    { 1, "100 ft" },
    { 2, "Unknown" },
    { 3, "Invalid" },
    { 0, NULL }
};
static const value_string valstr_021_040_RC[] = {
    { 0, "Default" },
    { 1, "Range Check passed, CPR Validation pending" },
    { 0, NULL }
};
static const value_string valstr_021_040_RAB[] = {
    { 0, "Report from target transponder" },
    { 1, "Report from field monitor (fixed transponder)" },
    { 0, NULL }
};
static const value_string valstr_021_040_DCR[] = {
    { 0, "No differential correction (ADS-B)" },
    { 1, "Differential correction (ADS-B)" },
    { 0, NULL }
};
static const value_string valstr_021_040_GBS[] = {
    { 0, "Ground Bit not set" },
    { 1, "Ground Bit set" },
    { 0, NULL }
};
static const value_string valstr_021_040_SIM[] = {
    { 0, "Actual target report" },
    { 1, "Simulated target report" },
    { 0, NULL }
};
static const value_string valstr_021_040_TST[] = {
    { 0, "Default" },
    { 1, "Test Target" },
    { 0, NULL }
};
static const value_string valstr_021_040_SAA[] = {
    { 0, "Equipment capable to provide Selected Altitude" },
    { 1, "Equipment not capable to provide Selected Altitude" },
    { 0, NULL }
};
static const value_string valstr_021_040_CL[] = {
    { 0, "Report valid" },
    { 1, "Report suspect" },
    { 2, "No information" },
    { 3, "Reserved for future use" },
    { 0, NULL }
};
static const value_string valstr_021_040_IPC[] = {
    { 0, "default" },
    { 1, "Independent Position Check failed" },
    { 0, NULL }
};
static const value_string valstr_021_040_NOGO[] = {
    { 0, "NOGO-bit not set" },
    { 1, "NOGO-bit set" },
    { 0, NULL }
};
static const value_string valstr_021_040_CPR[] = {
    { 0, "CPR Validation correct" },
    { 1, "CPR Validation failed" },
    { 0, NULL }
};
static const value_string valstr_021_040_LDPJ[] = {
    { 0, "LDPJ not detected" },
    { 1, "LDPJ detected" },
    { 0, NULL }
};
static const value_string valstr_021_040_RCF[] = {
    { 0, "default" },
    { 1, "Range Check failed" },
    { 0, NULL }
};
static const FieldPart I021_040_ATP = { 3, 1.0, FIELD_PART_UINT, &hf_021_040_ATP, NULL };
static const FieldPart I021_040_ARC = { 2, 1.0, FIELD_PART_UINT, &hf_021_040_ARC, NULL };
static const FieldPart I021_040_RC = { 1, 1.0, FIELD_PART_UINT, &hf_021_040_RC, NULL };
static const FieldPart I021_040_RAB = { 1, 1.0, FIELD_PART_UINT, &hf_021_040_RAB, NULL };
static const FieldPart I021_040_DCR = { 1, 1.0, FIELD_PART_UINT, &hf_021_040_DCR, NULL };
static const FieldPart I021_040_GBS = { 1, 1.0, FIELD_PART_UINT, &hf_021_040_GBS, NULL };
static const FieldPart I021_040_SIM = { 1, 1.0, FIELD_PART_UINT, &hf_021_040_SIM, NULL };
static const FieldPart I021_040_TST = { 1, 1.0, FIELD_PART_UINT, &hf_021_040_TST, NULL };
static const FieldPart I021_040_SAA = { 1, 1.0, FIELD_PART_UINT, &hf_021_040_SAA, NULL };
static const FieldPart I021_040_CL = { 2, 1.0, FIELD_PART_UINT, &hf_021_040_CL, NULL };
static const FieldPart I021_040_IPC = { 1, 1.0, FIELD_PART_UINT, &hf_021_040_IPC, NULL };
static const FieldPart I021_040_NOGO = { 1, 1.0, FIELD_PART_UINT, &hf_021_040_NOGO, NULL };
static const FieldPart I021_040_CPR = { 1, 1.0, FIELD_PART_UINT, &hf_021_040_CPR, NULL };
static const FieldPart I021_040_LDPJ = { 1, 1.0, FIELD_PART_UINT, &hf_021_040_LDPJ, NULL };
static const FieldPart I021_040_RCF = { 1, 1.0, FIELD_PART_UINT, &hf_021_040_RCF, NULL };
static const FieldPart *I021_040_PARTS[] = { &I021_040_ATP, &I021_040_ARC, &I021_040_RC, &I021_040_RAB, &IXXX_FX,
                                             &I021_040_DCR, &I021_040_GBS, &I021_040_SIM, &I021_040_TST, &I021_040_SAA, &I021_040_CL, &IXXX_FX,
                                             &I021_040_IPC, &I021_040_NOGO, &I021_040_CPR, &I021_040_LDPJ, &I021_040_RCF, &IXXX_FX, NULL };

/* Mode 3/A Code in Octal Representation */
static const FieldPart I021_070_SQUAWK = { 12, 1.0, FIELD_PART_SQUAWK, &hf_021_070_SQUAWK, NULL };
static const FieldPart *I021_070_PARTS[] = { &IXXX_4bit_spare, &I021_070_SQUAWK, NULL };

/* Time of Message Reception of Position-High Precision */
static const value_string valstr_021_074_FSI[] = {
    { 3, "Reserved" },
    { 2, "TOMRp whole seconds = (I021/073) Whole seconds - 1" },
    { 1, "TOMRp whole seconds = (I021/073) Whole seconds + 1" },
    { 0, "TOMRp whole seconds = (I021/073) Whole seconds" },
    { 0, NULL }
};
static const FieldPart I021_074_FSI = { 2, 1.0, FIELD_PART_UINT, &hf_021_074_FSI, NULL };
static const FieldPart I021_074_TOMRP = { 30, 1.0/1073741824.0, FIELD_PART_FLOAT, &hf_021_074_TOMRP, NULL };
static const FieldPart *I021_074_PARTS[] = { &I021_074_FSI, &I021_074_TOMRP, NULL };

/* Time of Message Reception of Position-High Precision */
static const value_string valstr_021_076_FSI[] = {
    { 3, "Reserved" },
    { 2, "TOMRv whole seconds = (I021/075) Whole seconds - 1" },
    { 1, "TOMRv whole seconds = (I021/075) Whole seconds + 1" },
    { 0, "TOMRv whole seconds = (I021/075) Whole seconds" },
    { 0, NULL }
};
static const FieldPart I021_076_FSI = { 2, 1.0, FIELD_PART_UINT, &hf_021_076_FSI, NULL };
static const FieldPart I021_076_TOMRV = { 30, 1.0/1073741824.0, FIELD_PART_FLOAT, &hf_021_076_TOMRV, NULL };
static const FieldPart *I021_076_PARTS[] = { &I021_076_FSI, &I021_076_TOMRV, NULL };

/* Quality Indicators */
static const value_string valstr_021_090_SIL_SUP[] = {
    { 0, "measured per flight-hour" },
    { 1, "measured per sample" },
    { 0, NULL }
};
static const FieldPart I021_090_NUCR_NACV = { 3, 1.0, FIELD_PART_UINT, &hf_021_090_NUCR_NACV, NULL };
static const FieldPart I021_090_NUCP_NIC = { 4, 1.0, FIELD_PART_UINT, &hf_021_090_NUCP_NIC, NULL };
static const FieldPart I021_090_NIC_BARO = { 1, 1.0, FIELD_PART_UINT, &hf_021_090_NIC_BARO, NULL };
static const FieldPart I021_090_SIL = { 2, 1.0, FIELD_PART_UINT, &hf_021_090_SIL, NULL };
static const FieldPart I021_090_NACP = { 4, 1.0, FIELD_PART_UINT, &hf_021_090_NACP, NULL };
static const FieldPart I021_090_SIL_SUP = { 1, 1.0, FIELD_PART_UINT, &hf_021_090_SIL_SUP, NULL };
static const FieldPart I021_090_SDA = { 2, 1.0, FIELD_PART_UINT, &hf_021_090_SDA, NULL };
static const FieldPart I021_090_GVA = { 2, 1.0, FIELD_PART_UINT, &hf_021_090_GVA, NULL };
static const FieldPart I021_090_PIC = { 4, 1.0, FIELD_PART_UINT, &hf_021_090_PIC, NULL };
static const FieldPart *I021_090_PARTS[] = { &I021_090_NUCR_NACV, &I021_090_NUCP_NIC, &IXXX_FX,
                                             &I021_090_NIC_BARO, &I021_090_SIL, &I021_090_NACP, &IXXX_FX,
                                             &I021_090_SIL_SUP, &I021_090_SDA, &I021_090_GVA, &IXXX_FX,
                                             &I021_090_PIC, &IXXX_3bit_spare, &IXXX_FX, NULL };

/* Trajectory Intent */
static const value_string valstr_021_110_01_NAV[] = {
    { 0, "Trajectory Intent Data is available for this aircraft" },
    { 1, "Trajectory Intent Data is not available for this aircraft" },
    { 0, NULL }
};
static const value_string valstr_021_110_01_NVB[] = {
    { 0, "Trajectory Intent Data is valid" },
    { 1, "Trajectory Intent Data is not valid" },
    { 0, NULL }
};
static const value_string valstr_021_110_02_TCA[] = {
    { 0, "TCP number available" },
    { 1, "TCP number not available" },
    { 0, NULL }
};
static const value_string valstr_021_110_02_NC[] = {
    { 0, "TCP compliance" },
    { 1, "TCP non-compliance" },
    { 0, NULL }
};
static const value_string valstr_021_110_02_PT[] = {
    { 0, "Unknown" },
    { 1, "Fly by waypoint (LT)" },
    { 2, "Fly over waypoint (LT)" },
    { 3, "Hold pattern (LT)" },
    { 4, "Procedure hold (LT)" },
    { 5, "Procedure turn (LT)" },
    { 6, "RF leg (LT)" },
    { 7, "Top of climb (VT)" },
    { 8, "Top of descent (VT)" },
    { 9, "Start of level (VT)" },
    { 10, "Cross-over altitude (VT)" },
    { 11, "Transition altitude (VT)" },
    { 0, NULL }
};
static const value_string valstr_021_110_02_TD[] = {
    { 0, "N/A" },
    { 1, "Turn right" },
    { 2, "Turn left" },
    { 3, "No turn" },
    { 0, NULL }
};
static const value_string valstr_021_110_02_TRA[] = {
    { 0, "TTR not available" },
    { 1, "TTR available" },
    { 0, NULL }
};
static const value_string valstr_021_110_02_TOA[] = {
    { 0, "TOV available" },
    { 1, "TOV not available" },
    { 0, NULL }
};
static const FieldPart I021_110_01_NAV = { 1, 1.0, FIELD_PART_UINT, &hf_021_110_01_NAV, NULL };
static const FieldPart I021_110_01_NVB = { 1, 1.0, FIELD_PART_UINT, &hf_021_110_01_NVB, NULL };
static const FieldPart *I021_110_01_PARTS[] = { &I021_110_01_NAV, &I021_110_01_NVB, &IXXX_5bit_spare, &IXXX_FX, NULL };
static const FieldPart I021_110_02_TCA = { 1, 1.0, FIELD_PART_UINT, &hf_021_110_02_TCA, NULL };
static const FieldPart I021_110_02_NC = { 1, 1.0, FIELD_PART_UINT, &hf_021_110_02_NC, NULL };
static const FieldPart I021_110_02_TCPNo = { 6, 1.0, FIELD_PART_UINT, &hf_021_110_02_TCPNo, NULL };
static const FieldPart I021_110_02_ALT = { 16, 10.0, FIELD_PART_FLOAT, &hf_021_110_02_ALT, NULL };
static const FieldPart I021_110_02_LAT = { 24, 180.0/8388608.0, FIELD_PART_FLOAT, &hf_021_110_02_LAT, NULL };
static const FieldPart I021_110_02_LON = { 24, 180.0/8388608.0, FIELD_PART_FLOAT, &hf_021_110_02_LON, NULL };
static const FieldPart I021_110_02_PT = { 4, 1.0, FIELD_PART_UINT, &hf_021_110_02_PT, NULL };
static const FieldPart I021_110_02_TD = { 2, 1.0, FIELD_PART_UINT, &hf_021_110_02_TD, NULL };
static const FieldPart I021_110_02_TRA = { 1, 1.0, FIELD_PART_UINT, &hf_021_110_02_TRA, NULL };
static const FieldPart I021_110_02_TOA = { 1, 1.0, FIELD_PART_UINT, &hf_021_110_02_TOA, NULL };
static const FieldPart I021_110_02_TOV = { 24, 1.0, FIELD_PART_UFLOAT, &hf_021_110_02_TOV, NULL };
static const FieldPart I021_110_02_TTR = { 16, 0.01, FIELD_PART_UFLOAT, &hf_021_110_02_TTR, NULL };
static const FieldPart *I021_110_02_PARTS[] = { &I021_110_02_TCA, &I021_110_02_NC, &I021_110_02_TCPNo,
                                                &I021_110_02_ALT, &I021_110_02_LAT, &I021_110_02_LON,
                                                &I021_110_02_PT, &I021_110_02_TD, &I021_110_02_TRA, &I021_110_02_TOA,
                                                &I021_110_02_TOV, &I021_110_02_TTR, NULL };

/* Position in WGS-84 Co-ordinates */
static const FieldPart I021_130_LAT = { 24, 180.0/8388608.0, FIELD_PART_FLOAT, &hf_021_130_LAT, NULL };
static const FieldPart I021_130_LON = { 24, 180.0/8388608.0, FIELD_PART_FLOAT, &hf_021_130_LON, NULL };
static const FieldPart *I021_130_PARTS[] = { &I021_130_LAT, &I021_130_LON, NULL };

/* High-Resolution Position in WGS-84 Co-ordinates */
static const FieldPart I021_131_LAT = { 32, 180.0/1073741824.0, FIELD_PART_FLOAT, &hf_021_131_LAT, NULL };
static const FieldPart I021_131_LON = { 32, 180.0/1073741824.0, FIELD_PART_FLOAT, &hf_021_131_LON, NULL };
static const FieldPart *I021_131_PARTS[] = { &I021_131_LAT, &I021_131_LON, NULL };

/* Message Amplitude */
static const FieldPart I021_132_MAM = { 8, 1.0, FIELD_PART_FLOAT, &hf_021_132_MAM, NULL };
static const FieldPart *I021_132_PARTS[] = { &I021_132_MAM, NULL };

/* Geometric Height */
static const FieldPart I021_140_GH = { 16, 6.25, FIELD_PART_FLOAT, &hf_021_140_GH, NULL };
static const FieldPart *I021_140_PARTS[] = { &I021_140_GH, NULL };

/* Flight Level */
static const FieldPart I021_145_FL = { 16, 0.25, FIELD_PART_FLOAT, &hf_021_145_FL, NULL };
static const FieldPart *I021_145_PARTS[] = { &I021_145_FL, NULL };

/* Selected Altitude */
static const value_string valstr_021_146_SAS[] = {
    { 0, "No source information provided" },
    { 1, "Source Information provided" },
    { 0, NULL }
};
static const value_string valstr_021_146_Source[] = {
    { 0, "Unknown" },
    { 1, "Aircraft Altitude (Holding Altitude)" },
    { 2, "MCP/FCU Selected Altitude" },
    { 3, "FMS Selected Altitude" },
    { 0, NULL }
};
static const FieldPart I021_146_SAS = { 1, 1.0, FIELD_PART_UINT, &hf_021_146_SAS, NULL };
static const FieldPart I021_146_Source = { 2, 1.0, FIELD_PART_UINT, &hf_021_146_Source, NULL };
static const FieldPart I021_146_ALT = { 13, 25.0, FIELD_PART_FLOAT, &hf_021_146_ALT, NULL };
static const FieldPart *I021_146_PARTS[] = { &I021_146_SAS, &I021_146_Source, &I021_146_ALT, NULL };

/* Final State Selected Altitude */
static const value_string valstr_021_148_MV[] = {
    { 0, "Not active or unknown" },
    { 1, "Active" },
    { 0, NULL }
};
static const value_string valstr_021_148_AH[] = {
    { 0, "Not active or unknown" },
    { 1, "Active" },
    { 0, NULL }
};
static const value_string valstr_021_148_AM[] = {
    { 0, "Not active or unknown" },
    { 1, "Active" },
    { 0, NULL }
};
static const FieldPart I021_148_MV = { 1, 1.0, FIELD_PART_UINT, &hf_021_148_MV, NULL };
static const FieldPart I021_148_AH = { 1, 1.0, FIELD_PART_UINT, &hf_021_148_AH, NULL };
static const FieldPart I021_148_AM = { 1, 1.0, FIELD_PART_UINT, &hf_021_148_AM, NULL };
static const FieldPart I021_148_ALT = { 13, 25.0, FIELD_PART_FLOAT, &hf_021_148_ALT, NULL };
static const FieldPart *I021_148_PARTS[] = { &I021_148_MV, &I021_148_AH, &I021_148_AM, &I021_148_ALT, NULL };

/* Air Speed */
static const value_string valstr_021_150_IM[] = {
    { 0, "Air Speed = IAS" },
    { 1, "Air Speed = Mach" },
    { 0, NULL }
};
static const FieldPart I021_150_IM = { 1, 1.0, FIELD_PART_UINT, &hf_021_150_IM, NULL };
static const FieldPart I021_150_ASPD = { 15, 1.0, FIELD_PART_UFLOAT, &hf_021_150_ASPD, NULL };
static const FieldPart *I021_150_PARTS[] = { &I021_150_IM, &I021_150_ASPD, NULL };

/* True Airspeed */
static const value_string valstr_021_151_RE[] = {
    { 0, "Value in defined range" },
    { 1, "Value exceeds defined range" },
    { 0, NULL }
};
static const FieldPart I021_151_RE = { 1, 1.0, FIELD_PART_UINT, &hf_021_151_RE, NULL };
static const FieldPart I021_151_TASPD = { 15, 1.0, FIELD_PART_UFLOAT, &hf_021_151_TASPD, NULL };
static const FieldPart *I021_151_PARTS[] = { &I021_151_RE, &I021_151_TASPD, NULL };

/* Magnetic Heading */
static const FieldPart I021_152_MHDG = { 16, 360.0/65536.0, FIELD_PART_UFLOAT, &hf_021_152_MHDG, NULL };
static const FieldPart *I021_152_PARTS[] = { &I021_152_MHDG, NULL };

/* Barometric Vertical Rate */
static const value_string valstr_021_155_RE[] = {
    { 0, "Value in defined range" },
    { 1, "Value exceeds defined range" },
    { 0, NULL }
};
static const FieldPart I021_155_RE = { 1, 1.0, FIELD_PART_UINT, &hf_021_155_RE, NULL };
static const FieldPart I021_155_BVR = { 15, 6.25, FIELD_PART_FLOAT, &hf_021_155_BVR, NULL };
static const FieldPart *I021_155_PARTS[] = { &I021_155_RE, &I021_155_BVR, NULL };

/* Geometric Vertical Rate */
static const value_string valstr_021_157_RE[] = {
    { 0, "Value in defined range" },
    { 1, "Value exceeds defined range" },
    { 0, NULL }
};
static const FieldPart I021_157_RE = { 1, 1.0, FIELD_PART_UINT, &hf_021_157_RE, NULL };
static const FieldPart I021_157_GVR = { 15, 6.25, FIELD_PART_FLOAT, &hf_021_157_GVR, NULL };
static const FieldPart *I021_157_PARTS[] = { &I021_157_RE, &I021_157_GVR, NULL };

/* Airborne Ground Vector */
static const value_string valstr_021_160_RE[] = {
    { 0, "Value in defined range" },
    { 1, "Value exceeds defined range" },
    { 0, NULL }
};
static const FieldPart I021_160_RE = { 1, 1.0, FIELD_PART_UINT, &hf_021_160_RE, NULL };
static const FieldPart I021_160_GSPD = { 15, 1.0/16384.0, FIELD_PART_FLOAT, &hf_021_160_GSPD, NULL };
static const FieldPart I021_160_TA = { 16, 360.0/65536.0, FIELD_PART_FLOAT, &hf_021_160_TA, NULL };
static const FieldPart *I021_160_PARTS[] = { &I021_160_RE, &I021_160_GSPD, &I021_160_TA, NULL };

/* Track Number */
static const FieldPart I021_161_TN = { 12, 1.0, FIELD_PART_UINT, &hf_021_161_TN, NULL };
static const FieldPart *I021_161_PARTS[] = { &IXXX_4bit_spare, &I021_161_TN, NULL };

/* Track Angle Rate */
static const FieldPart I021_165_TAR = { 19, 1.0/32.0, FIELD_PART_FLOAT, &hf_021_165_TAR, NULL };
static const FieldPart *I021_165_PARTS[] = { &IXXX_6bit_spare, &I021_165_TAR, NULL };

/* Target Status */
static const value_string valstr_021_200_ICF[] = {
    { 0, "No intent change active" },
    { 1, "Intent change flag raised" },
    { 0, NULL }
};
static const value_string valstr_021_200_LNAV[] = {
    { 0, "LNAV Mode engaged" },
    { 1, "LNAV Mode not engaged" },
    { 0, NULL }
};
static const value_string valstr_021_200_PS[] = {
    { 0, "No emergency / not reported" },
    { 1, "General emergency" },
    { 2, "Lifeguard / medical emergency" },
    { 3, "Minimum fuel" },
    { 4, "No communications" },
    { 5, "Unlawful interference" },
    { 6, "\"Downed\" Aircraft" },
    { 0, NULL }
};
static const value_string valstr_021_200_SS[] = {
    { 0, "No condition reported" },
    { 1, "Permanent Alert (Emergency condition)" },
    { 2, "Temporary Alert (change in Mode 3/A Code other than emergency)" },
    { 3, "SPI set" },
    { 0, NULL }
};
static const FieldPart I021_200_ICF = { 1, 1.0, FIELD_PART_UINT, &hf_021_200_ICF, NULL };
static const FieldPart I021_200_LNAV = { 1, 1.0, FIELD_PART_UINT, &hf_021_200_LNAV, NULL };
static const FieldPart I021_200_PS = { 3, 1.0, FIELD_PART_UINT, &hf_021_200_PS, NULL };
static const FieldPart I021_200_SS = { 2, 1.0, FIELD_PART_UINT, &hf_021_200_SS, NULL };
static const FieldPart *I021_200_PARTS[] = { &I021_200_ICF, &I021_200_LNAV, &I021_200_PS, &I021_200_SS, NULL };

/* MOPS Version */
static const value_string valstr_021_210_VNS[] = {
    { 0, "The MOPS Version is supported by the GS" },
    { 1, "The MOPS Version is not supported by the GS" },
    { 0, NULL }
};
static const value_string valstr_021_210_VN[] = {
    { 0, "ED102/DO-260" },
    { 1, "DO-260A" },
    { 2, "ED102A/DO-260B" },
    { 0, NULL }
};
static const value_string valstr_021_210_LTT[] = {
    { 0, "Other" },
    { 1, "UAT" },
    { 2, "1090 ES" },
    { 3, "VDL 4" },
    { 4, "Not assigned" },
    { 5, "Not assigned" },
    { 6, "Not assigned" },
    { 7, "Not assigned" },
    { 0, NULL }
};
static const FieldPart I021_210_VNS = { 1, 1.0, FIELD_PART_UINT, &hf_021_210_VNS, NULL };
static const FieldPart I021_210_VN = { 3, 1.0, FIELD_PART_UINT, &hf_021_210_VN, NULL };
static const FieldPart I021_210_LTT = { 2, 1.0, FIELD_PART_UINT, &hf_021_210_LTT, NULL };
static const FieldPart *I021_210_PARTS[] = { &I021_210_VNS, &I021_210_VN, &I021_210_LTT, NULL };

/* Met Information */
static const FieldPart I021_220_01_WSPD = { 16, 1.0, FIELD_PART_UFLOAT, &hf_021_220_01_WSPD, NULL };
static const FieldPart *I021_220_01_PARTS[] = { &I021_220_01_WSPD, NULL };
static const FieldPart I021_220_02_WDIR = { 16, 1.0, FIELD_PART_UFLOAT, &hf_021_220_02_WDIR, NULL };
static const FieldPart *I021_220_02_PARTS[] = { &I021_220_02_WDIR, NULL };
static const FieldPart I021_220_03_TEMP = { 16, 0.25, FIELD_PART_FLOAT, &hf_021_220_03_TEMP, NULL };
static const FieldPart *I021_220_03_PARTS[] = { &I021_220_03_TEMP, NULL };
static const FieldPart I021_220_04_TURB = { 8, 1.0, FIELD_PART_UINT, &hf_021_220_04_TURB, NULL };
static const FieldPart *I021_220_04_PARTS[] = { &I021_220_04_TURB, NULL };

/* Roll Angle */
static const FieldPart I021_230_RA = { 16, 0.01, FIELD_PART_FLOAT, &hf_021_230_RA, NULL };
static const FieldPart *I021_230_PARTS[] = { &I021_230_RA, NULL };

/* ACAS Resolution Advisory Report */
static const FieldPart I021_260_TYP = { 5, 1.0, FIELD_PART_UINT, &hf_021_260_TYP, NULL };
static const FieldPart I021_260_STYP = { 3, 1.0, FIELD_PART_UINT, &hf_021_260_STYP, NULL };
static const FieldPart I021_260_ARA = { 14, 1.0, FIELD_PART_UINT, &hf_021_260_ARA, NULL };
static const FieldPart I021_260_RAC = { 4, 1.0, FIELD_PART_UINT, &hf_021_260_RAC, NULL };
static const FieldPart I021_260_RAT = { 1, 1.0, FIELD_PART_UINT, &hf_021_260_RAT, NULL };
static const FieldPart I021_260_MTE = { 1, 1.0, FIELD_PART_UINT, &hf_021_260_MTE, NULL };
static const FieldPart I021_260_TTI = { 2, 1.0, FIELD_PART_UINT, &hf_021_260_TTI, NULL };
static const FieldPart I021_260_TID = { 26, 1.0, FIELD_PART_UINT, &hf_021_260_TID, NULL };
static const FieldPart *I021_260_PARTS[] = { &I021_260_TYP, &I021_260_STYP, &I021_260_ARA,
                                             &I021_260_RAC, &I021_260_RAT, &I021_260_MTE, &I021_260_TTI,
                                             &I021_260_TID, NULL };

/* Surface Capabilities and Characteristics */
static const value_string valstr_021_271_POA[] = {
    { 0, "Position transmitted is not ADS-B position reference point" },
    { 1, "Position transmitted is the ADS-B position reference point" },
    { 0, NULL }
};
static const value_string valstr_021_271_CDTIS[] = {
    { 0, "CDTI not operational" },
    { 1, "CDTI operational" },
    { 0, NULL }
};
static const value_string valstr_021_271_B2low[] = {
    { 0, ">= 70 Watts" },
    { 1, "< 70 Watts" },
    { 0, NULL }
};
static const value_string valstr_021_271_RAS[] = {
    { 0, "Aircraft not receiving ATC-services" },
    { 1, "Aircraft receiving ATC services" },
    { 0, NULL }
};
static const value_string valstr_021_271_IDENT[] = {
    { 0, "IDENT switch not active" },
    { 1, "IDENT switch active" },
    { 0, NULL }
};
static const FieldPart I021_271_POA = { 1, 1.0, FIELD_PART_UINT, &hf_021_271_POA, NULL };
static const FieldPart I021_271_CDTIS = { 1, 1.0, FIELD_PART_UINT, &hf_021_271_CDTIS, NULL };
static const FieldPart I021_271_B2low = { 1, 1.0, FIELD_PART_UINT, &hf_021_271_B2low, NULL };
static const FieldPart I021_271_RAS = { 1, 1.0, FIELD_PART_UINT, &hf_021_271_RAS, NULL };
static const FieldPart I021_271_IDENT = { 1, 1.0, FIELD_PART_UINT, &hf_021_271_IDENT, NULL };
static const FieldPart I021_271_LW = { 4, 1.0, FIELD_PART_UINT, &hf_021_271_LW, NULL };
static const FieldPart *I021_271_PARTS[] = { &I021_271_POA, &I021_271_CDTIS, &I021_271_B2low, &I021_271_RAS, &I021_271_IDENT, &IXXX_FX,
                                             &IXXX_4bit_spare, &I021_271_LW, NULL };

/* Data Ages */
static const FieldPart I021_295_01_AOS = { 8, 0.1, FIELD_PART_UFLOAT, &hf_021_295_01_AOS, NULL };
static const FieldPart *I021_295_01_PARTS[] = { &I021_295_01_AOS, NULL };
static const FieldPart I021_295_02_TRD = { 8, 0.1, FIELD_PART_UFLOAT, &hf_021_295_02_TRD, NULL };
static const FieldPart *I021_295_02_PARTS[] = { &I021_295_02_TRD, NULL };
static const FieldPart I021_295_03_M3A = { 8, 0.1, FIELD_PART_UFLOAT, &hf_021_295_03_M3A, NULL };
static const FieldPart *I021_295_03_PARTS[] = { &I021_295_03_M3A, NULL };
static const FieldPart I021_295_04_QI = { 8, 0.1, FIELD_PART_UFLOAT, &hf_021_295_04_QI, NULL };
static const FieldPart *I021_295_04_PARTS[] = { &I021_295_04_QI, NULL };
static const FieldPart I021_295_05_TI = { 8, 0.1, FIELD_PART_UFLOAT, &hf_021_295_05_TI, NULL };
static const FieldPart *I021_295_05_PARTS[] = { &I021_295_05_TI, NULL };
static const FieldPart I021_295_06_MAM = { 8, 0.1, FIELD_PART_UFLOAT, &hf_021_295_06_MAM, NULL };
static const FieldPart *I021_295_06_PARTS[] = { &I021_295_06_MAM, NULL };
static const FieldPart I021_295_07_GH = { 8, 0.1, FIELD_PART_UFLOAT, &hf_021_295_07_GH, NULL };
static const FieldPart *I021_295_07_PARTS[] = { &I021_295_07_GH, NULL };
static const FieldPart I021_295_08_FL = { 8, 0.1, FIELD_PART_UFLOAT, &hf_021_295_08_FL, NULL };
static const FieldPart *I021_295_08_PARTS[] = { &I021_295_08_FL, NULL };
static const FieldPart I021_295_09_ISA = { 8, 0.1, FIELD_PART_UFLOAT, &hf_021_295_09_ISA, NULL };
static const FieldPart *I021_295_09_PARTS[] = { &I021_295_09_ISA, NULL };
static const FieldPart I021_295_10_FSA = { 8, 0.1, FIELD_PART_UFLOAT, &hf_021_295_10_FSA, NULL };
static const FieldPart *I021_295_10_PARTS[] = { &I021_295_10_FSA, NULL };
static const FieldPart I021_295_11_AS = { 8, 0.1, FIELD_PART_UFLOAT, &hf_021_295_11_AS, NULL };
static const FieldPart *I021_295_11_PARTS[] = { &I021_295_11_AS, NULL };
static const FieldPart I021_295_12_TAS = { 8, 0.1, FIELD_PART_UFLOAT, &hf_021_295_12_TAS, NULL };
static const FieldPart *I021_295_12_PARTS[] = { &I021_295_12_TAS, NULL };
static const FieldPart I021_295_13_MH = { 8, 0.1, FIELD_PART_UFLOAT, &hf_021_295_13_MH, NULL };
static const FieldPart *I021_295_13_PARTS[] = { &I021_295_13_MH, NULL };
static const FieldPart I021_295_14_BVR = { 8, 0.1, FIELD_PART_UFLOAT, &hf_021_295_14_BVR, NULL };
static const FieldPart *I021_295_14_PARTS[] = { &I021_295_14_BVR, NULL };
static const FieldPart I021_295_15_GVR = { 8, 0.1, FIELD_PART_UFLOAT, &hf_021_295_15_GVR, NULL };
static const FieldPart *I021_295_15_PARTS[] = { &I021_295_15_GVR, NULL };
static const FieldPart I021_295_16_GV = { 8, 0.1, FIELD_PART_UFLOAT, &hf_021_295_16_GV, NULL };
static const FieldPart *I021_295_16_PARTS[] = { &I021_295_16_GV, NULL };
static const FieldPart I021_295_17_TAR = { 8, 0.1, FIELD_PART_UFLOAT, &hf_021_295_17_TAR, NULL };
static const FieldPart *I021_295_17_PARTS[] = { &I021_295_17_TAR, NULL };
static const FieldPart I021_295_18_TI = { 8, 0.1, FIELD_PART_UFLOAT, &hf_021_295_18_TI, NULL };
static const FieldPart *I021_295_18_PARTS[] = { &I021_295_18_TI, NULL };
static const FieldPart I021_295_19_TS = { 8, 0.1, FIELD_PART_UFLOAT, &hf_021_295_19_TS, NULL };
static const FieldPart *I021_295_19_PARTS[] = { &I021_295_19_TS, NULL };
static const FieldPart I021_295_20_MET = { 8, 0.1, FIELD_PART_UFLOAT, &hf_021_295_20_MET, NULL };
static const FieldPart *I021_295_20_PARTS[] = { &I021_295_20_MET, NULL };
static const FieldPart I021_295_21_ROA = { 8, 0.1, FIELD_PART_UFLOAT, &hf_021_295_21_ROA, NULL };
static const FieldPart *I021_295_21_PARTS[] = { &I021_295_21_ROA, NULL };
static const FieldPart I021_295_22_ARA = { 8, 0.1, FIELD_PART_UFLOAT, &hf_021_295_22_ARA, NULL };
static const FieldPart *I021_295_22_PARTS[] = { &I021_295_22_ARA, NULL };
static const FieldPart I021_295_23_SCC = { 8, 0.1, FIELD_PART_UFLOAT, &hf_021_295_23_SCC, NULL };
static const FieldPart *I021_295_23_PARTS[] = { &I021_295_23_SCC, NULL };

/* Receiver ID */
static const FieldPart I021_400_RID = { 8, 1.0, FIELD_PART_UINT, &hf_021_400_RID, NULL };
static const FieldPart *I021_400_PARTS[] = { &I021_400_RID, NULL };

/* Items */
static const AsterixField I021_008 = { FIXED, 1, 0, 0, &hf_021_008, I021_008_PARTS, { NULL } };
static const AsterixField I021_010 = { FIXED, 2, 0, 0, &hf_021_010, IXXX_SAC_SIC, { NULL } };
static const AsterixField I021_015 = { FIXED, 1, 0, 0, &hf_021_015, I021_015_PARTS, { NULL } };
static const AsterixField I021_016 = { FIXED, 1, 0, 0, &hf_021_016, I021_016_PARTS, { NULL } };
static const AsterixField I021_020 = { FIXED, 1, 0, 0, &hf_021_020, I021_020_PARTS, { NULL } };
static const AsterixField I021_040 = { FX, 1, 0, 0, &hf_021_040, I021_040_PARTS, { NULL } };
static const AsterixField I021_070 = { FIXED, 2, 0, 0, &hf_021_070, I021_070_PARTS, { NULL } };
static const AsterixField I021_071 = { FIXED, 3, 0, 0, &hf_021_071, IXXX_TOD, { NULL } };
static const AsterixField I021_072 = { FIXED, 3, 0, 0, &hf_021_072, IXXX_TOD, { NULL } };
static const AsterixField I021_073 = { FIXED, 3, 0, 0, &hf_021_073, IXXX_TOD, { NULL } };
static const AsterixField I021_074 = { FIXED, 4, 0, 0, &hf_021_074, I021_074_PARTS, { NULL } };
static const AsterixField I021_075 = { FIXED, 3, 0, 0, &hf_021_075, IXXX_TOD, { NULL } };
static const AsterixField I021_076 = { FIXED, 4, 0, 0, &hf_021_076, I021_076_PARTS, { NULL } };
static const AsterixField I021_077 = { FIXED, 3, 0, 0, &hf_021_077, IXXX_TOD, { NULL } };
static const AsterixField I021_080 = { FIXED, 3, 0, 0, &hf_021_080, IXXX_AA_PARTS, { NULL } };
static const AsterixField I021_090 = { FX, 1, 0, 0, &hf_021_090, I021_090_PARTS, { NULL } };
static const AsterixField I021_110_01 = { FIXED, 1, 0, 0, &hf_021_110_01, I021_110_01_PARTS, { NULL } };
static const AsterixField I021_110_02 = { REPETITIVE, 15, 1, 0, &hf_021_110_02, I021_110_02_PARTS, { NULL } };
static const AsterixField I021_110 = { COMPOUND, 0, 0, 0, &hf_021_110, NULL, { &I021_110_01,
                                                                               &I021_110_02,
                                                                               NULL} };
static const AsterixField I021_130 = { FIXED, 6, 0, 0, &hf_021_130, I021_130_PARTS, { NULL } };
static const AsterixField I021_131 = { FIXED, 8, 0, 0, &hf_021_131, I021_131_PARTS, { NULL } };
static const AsterixField I021_132 = { FIXED, 1, 0, 0, &hf_021_132, I021_132_PARTS, { NULL } };
static const AsterixField I021_140 = { FIXED, 2, 0, 0, &hf_021_140, I021_140_PARTS, { NULL } };
static const AsterixField I021_145 = { FIXED, 2, 0, 0, &hf_021_145, I021_145_PARTS, { NULL } };
static const AsterixField I021_146 = { FIXED, 2, 0, 0, &hf_021_146, I021_146_PARTS, { NULL } };
static const AsterixField I021_148 = { FIXED, 2, 0, 0, &hf_021_148, I021_148_PARTS, { NULL } };
static const AsterixField I021_150 = { FIXED, 2, 0, 0, &hf_021_150, I021_150_PARTS, { NULL } };
static const AsterixField I021_151 = { FIXED, 2, 0, 0, &hf_021_151, I021_151_PARTS, { NULL } };
static const AsterixField I021_152 = { FIXED, 2, 0, 0, &hf_021_152, I021_152_PARTS, { NULL } };
static const AsterixField I021_155 = { FIXED, 2, 0, 0, &hf_021_155, I021_155_PARTS, { NULL } };
static const AsterixField I021_157 = { FIXED, 2, 0, 0, &hf_021_157, I021_157_PARTS, { NULL } };
static const AsterixField I021_160 = { FIXED, 4, 0, 0, &hf_021_160, I021_160_PARTS, { NULL } };
static const AsterixField I021_161 = { FIXED, 2, 0, 0, &hf_021_161, I021_161_PARTS, { NULL } };
static const AsterixField I021_165 = { FIXED, 2, 0, 0, &hf_021_165, I021_165_PARTS, { NULL } };
static const AsterixField I021_170 = { FIXED, 6, 0, 0, &hf_021_170, IXXX_AI_PARTS, { NULL } };
static const AsterixField I021_200 = { FIXED, 1, 0, 0, &hf_021_200, I021_200_PARTS, { NULL } };
static const AsterixField I021_210 = { FIXED, 1, 0, 0, &hf_021_210, I021_210_PARTS, { NULL } };
static const AsterixField I021_220_01 = { FIXED, 2, 0, 0, &hf_021_220_01, I021_220_01_PARTS, { NULL } };
static const AsterixField I021_220_02 = { FIXED, 2, 0, 0, &hf_021_220_02, I021_220_02_PARTS, { NULL } };
static const AsterixField I021_220_03 = { FIXED, 2, 0, 0, &hf_021_220_03, I021_220_03_PARTS, { NULL } };
static const AsterixField I021_220_04 = { FIXED, 1, 0, 0, &hf_021_220_04, I021_220_04_PARTS, { NULL } };
static const AsterixField I021_220 = { COMPOUND, 0, 0, 0, &hf_021_220, NULL, { &I021_220_01,
                                                                               &I021_220_02,
                                                                               &I021_220_03,
                                                                               &I021_220_04,
                                                                               NULL} };
static const AsterixField I021_230 = { FIXED, 2, 0, 0, &hf_021_230, I021_230_PARTS, { NULL } };
static const AsterixField I021_250 = { REPETITIVE, 8, 1, 0, &hf_021_250, IXXX_MB, { NULL } };
static const AsterixField I021_260 = { FIXED, 7, 0, 0, &hf_021_260, I021_260_PARTS, { NULL } };
static const AsterixField I021_271 = { FX, 1, 0, 0, &hf_021_271, I021_271_PARTS, { NULL } };
static const AsterixField I021_295_01 = { FIXED, 1, 0, 0, &hf_021_295_01, I021_295_01_PARTS, { NULL } };
static const AsterixField I021_295_02 = { FIXED, 1, 0, 0, &hf_021_295_02, I021_295_02_PARTS, { NULL } };
static const AsterixField I021_295_03 = { FIXED, 1, 0, 0, &hf_021_295_03, I021_295_03_PARTS, { NULL } };
static const AsterixField I021_295_04 = { FIXED, 1, 0, 0, &hf_021_295_04, I021_295_04_PARTS, { NULL } };
static const AsterixField I021_295_05 = { FIXED, 1, 0, 0, &hf_021_295_05, I021_295_05_PARTS, { NULL } };
static const AsterixField I021_295_06 = { FIXED, 1, 0, 0, &hf_021_295_06, I021_295_06_PARTS, { NULL } };
static const AsterixField I021_295_07 = { FIXED, 1, 0, 0, &hf_021_295_07, I021_295_07_PARTS, { NULL } };
static const AsterixField I021_295_08 = { FIXED, 1, 0, 0, &hf_021_295_08, I021_295_08_PARTS, { NULL } };
static const AsterixField I021_295_09 = { FIXED, 1, 0, 0, &hf_021_295_09, I021_295_09_PARTS, { NULL } };
static const AsterixField I021_295_10 = { FIXED, 1, 0, 0, &hf_021_295_10, I021_295_10_PARTS, { NULL } };
static const AsterixField I021_295_11 = { FIXED, 1, 0, 0, &hf_021_295_11, I021_295_11_PARTS, { NULL } };
static const AsterixField I021_295_12 = { FIXED, 1, 0, 0, &hf_021_295_12, I021_295_12_PARTS, { NULL } };
static const AsterixField I021_295_13 = { FIXED, 1, 0, 0, &hf_021_295_13, I021_295_13_PARTS, { NULL } };
static const AsterixField I021_295_14 = { FIXED, 1, 0, 0, &hf_021_295_14, I021_295_14_PARTS, { NULL } };
static const AsterixField I021_295_15 = { FIXED, 1, 0, 0, &hf_021_295_15, I021_295_15_PARTS, { NULL } };
static const AsterixField I021_295_16 = { FIXED, 1, 0, 0, &hf_021_295_16, I021_295_16_PARTS, { NULL } };
static const AsterixField I021_295_17 = { FIXED, 1, 0, 0, &hf_021_295_17, I021_295_17_PARTS, { NULL } };
static const AsterixField I021_295_18 = { FIXED, 1, 0, 0, &hf_021_295_18, I021_295_18_PARTS, { NULL } };
static const AsterixField I021_295_19 = { FIXED, 1, 0, 0, &hf_021_295_19, I021_295_19_PARTS, { NULL } };
static const AsterixField I021_295_20 = { FIXED, 1, 0, 0, &hf_021_295_20, I021_295_20_PARTS, { NULL } };
static const AsterixField I021_295_21 = { FIXED, 1, 0, 0, &hf_021_295_21, I021_295_21_PARTS, { NULL } };
static const AsterixField I021_295_22 = { FIXED, 1, 0, 0, &hf_021_295_22, I021_295_22_PARTS, { NULL } };
static const AsterixField I021_295_23 = { FIXED, 1, 0, 0, &hf_021_295_23, I021_295_23_PARTS, { NULL } };
static const AsterixField I021_295 = { COMPOUND, 0, 0, 0, &hf_021_295, NULL, { &I021_295_01,
                                                                               &I021_295_02,
                                                                               &I021_295_03,
                                                                               &I021_295_04,
                                                                               &I021_295_05,
                                                                               &I021_295_06,
                                                                               &I021_295_07,
                                                                               &I021_295_08,
                                                                               &I021_295_09,
                                                                               &I021_295_10,
                                                                               &I021_295_11,
                                                                               &I021_295_12,
                                                                               &I021_295_13,
                                                                               &I021_295_14,
                                                                               &I021_295_15,
                                                                               &I021_295_16,
                                                                               &I021_295_17,
                                                                               &I021_295_18,
                                                                               &I021_295_19,
                                                                               &I021_295_20,
                                                                               &I021_295_21,
                                                                               &I021_295_22,
                                                                               &I021_295_23,
                                                                               NULL} };
static const AsterixField I021_400 = { FIXED, 1, 0, 0, &hf_021_400, I021_400_PARTS, { NULL } };
static const AsterixField I021_RE = { RE, 0, 0, 1, &hf_021_RE, NULL, { NULL } };
static const AsterixField I021_SP = { SP, 0, 0, 1, &hf_021_SP, NULL, { NULL } };

static const AsterixField *I021_v2_1_uap[] = { &I021_010, &I021_040, &I021_161, &I021_015, &I021_071, &I021_130, &I021_131,
                                               &I021_072, &I021_150, &I021_151, &I021_080, &I021_073, &I021_074, &I021_075,
                                               &I021_076, &I021_140, &I021_090, &I021_210, &I021_070, &I021_230, &I021_145,
                                               &I021_152, &I021_200, &I021_155, &I021_157, &I021_160, &I021_165, &I021_077,
                                               &I021_170, &I021_020, &I021_220, &I021_146, &I021_148, &I021_110, &I021_016,
                                               &I021_008, &I021_271, &I021_132, &I021_250, &I021_260, &I021_400, &I021_295,
                                               &IX_SPARE, &IX_SPARE, &IX_SPARE, &IX_SPARE, &IX_SPARE, &I021_RE,  &I021_SP, NULL };
static const AsterixField **I021_v2_1[] = { I021_v2_1_uap, NULL };
static const AsterixField ***I021[] = { I021_v2_1 };

static const enum_val_t I021_versions[] = {
    { "I021_v2_1", "Version 2.1", 0 },
    { NULL, NULL, 0 }
};

/* *********************** */
/*      Category 023       */
/* *********************** */
/* Fields */

/* Report Type */
static const value_string valstr_023_000_RT[] = {
    { 1, "Ground Station Status report" },
    { 2, "Service Status report" },
    { 3, "Service Statistics report" },
    { 0, NULL }
};
static const FieldPart I023_000_RT = { 8, 1.0, FIELD_PART_UINT, &hf_023_000_RT, NULL };
static const FieldPart *I023_000_PARTS[] = { &I023_000_RT, NULL };

/* Tpe of Service */
static const value_string valstr_023_015_STYP[] = {
    { 1, "ADS-B VDL4" },
    { 2, "ADS-B Ext Squitter" },
    { 3, "ADS-B UAT" },
    { 4, "TIS-B VDL4" },
    { 5, "TIS-B Ext Squitter" },
    { 6, "TIS-B UAT" },
    { 7, "FIS-B VDL4" },
    { 8, "GRAS VDL4" },
    { 9, "MLT" },
    { 0, NULL }
};
static const FieldPart I023_015_SID = { 4, 1.0, FIELD_PART_UINT, &hf_023_015_SID, NULL };
static const FieldPart I023_015_STYPE = { 4, 1.0, FIELD_PART_UINT, &hf_023_015_STYPE, NULL };
static const FieldPart *I023_015_PARTS[] = { &I023_015_SID, &I023_015_STYPE, NULL };

/* Ground Station Status */
static const value_string valstr_023_100_NOGO[] = {
    { 0, "Data is released for operational use" },
    { 1, "Data must not be used operationally" },
    { 0, NULL }
};
static const value_string valstr_023_100_ODP[] = {
    { 0, "Default, no overload" },
    { 1, "Overload in DP" },
    { 0, NULL }
};
static const value_string valstr_023_100_OXT[] = {
    { 0, "Default, no overload" },
    { 1, "Overload in transmission subsystem" },
    { 0, NULL }
};
static const value_string valstr_023_100_MSC[] = {
    { 0, "Monitoring system not connected or unknown" },
    { 1, "Monitoring system connected" },
    { 0, NULL }
};
static const value_string valstr_023_100_TSV[] = {
    { 0, "valid" },
    { 1, "invalid" },
    { 0, NULL }
};
static const value_string valstr_023_100_SPO[] = {
    { 0, "no spoofing detected" },
    { 1, "potential spoofing attack" },
    { 0, NULL }
};
static const value_string valstr_023_100_RN[] = {
    { 0, "default" },
    { 1, "track numbering has restarted" },
    { 0, NULL }
};
static const FieldPart I023_100_NOGO = { 1, 1.0, FIELD_PART_UINT, &hf_023_100_NOGO, NULL };
static const FieldPart I023_100_ODP = { 1, 1.0, FIELD_PART_UINT, &hf_023_100_ODP, NULL };
static const FieldPart I023_100_OXT = { 1, 1.0, FIELD_PART_UINT, &hf_023_100_OXT, NULL };
static const FieldPart I023_100_MSC = { 1, 1.0, FIELD_PART_UINT, &hf_023_100_MSC, NULL };
static const FieldPart I023_100_TSV = { 1, 1.0, FIELD_PART_UINT, &hf_023_100_TSV, NULL };
static const FieldPart I023_100_SPO = { 1, 1.0, FIELD_PART_UINT, &hf_023_100_SPO, NULL };
static const FieldPart I023_100_RN = { 1, 1.0, FIELD_PART_UINT, &hf_023_100_RN, NULL };
static const FieldPart I023_100_GSSP = { 7, 1.0, FIELD_PART_UFLOAT, &hf_023_100_GSSP, NULL };
static const FieldPart *I023_100_PARTS[] = { &I023_100_NOGO, &I023_100_ODP, &I023_100_OXT, &I023_100_MSC, &I023_100_TSV, &I023_100_SPO, &I023_100_RN, &IXXX_FX,
                                             &I023_100_GSSP, &IXXX_FX, NULL };

/* Service Configuration */
static const value_string valstr_023_101_SC[] = {
    { 0, "No information" },
    { 1, "NRA class" },
    { 2, "reserved for future use" },
    { 3, "reserved for future use" },
    { 4, "reserved for future use" },
    { 5, "reserved for future use" },
    { 6, "reserved for future use" },
    { 7, "reserved for future use" },
    { 0, NULL }
};
static const FieldPart I023_101_RP = { 8, 0.5, FIELD_PART_UFLOAT, &hf_023_101_RP, NULL };
static const FieldPart I023_101_SC = { 3, 1, FIELD_PART_UINT, &hf_023_101_SC, NULL };
static const FieldPart I023_101_SSRP = { 7, 1.0, FIELD_PART_UFLOAT, &hf_023_101_SSRP, NULL };
static const FieldPart *I023_101_PARTS[] = { &I023_101_RP, &I023_101_SC, &IXXX_4bit_spare, &IXXX_FX,
                                             &I023_101_SSRP, &IXXX_FX, NULL };

/* Service Status */
static const value_string valstr_023_110_STAT[] = {
    { 0, "Unknown" },
    { 1, "Failed" },
    { 2, "Disabled" },
    { 3, "Degraded" },
    { 4, "Normal" },
    { 5, "Initialisation" },
    { 0, NULL }
};
static const FieldPart I023_110_STAT = { 3, 1.0, FIELD_PART_UINT, &hf_023_110_STAT, NULL };
static const FieldPart *I023_110_PARTS[] = { &IXXX_4bit_spare, &I023_110_STAT, &IXXX_FX, NULL };

/* Service Statistics */
static const value_string valstr_023_120_TYPE[] = {
    { 0, "Number of unknown messages received" },
    { 1, "Number of \'too old\' messages received" },
    { 2, "Number of failed message conversions" },
    { 3, "Total Number of messages received" },
    { 4, "Total number of messages transmitted" },
    { 20, "Number of TIS-B management messages received" },
    { 21, "Number of \'Basic\' messages received" },
    { 22, "Number of \'High Dynamic\' messages received" },
    { 23, "Number of \'Full Position\' messages received" },
    { 24, "Number of \'Basic Ground\' messages received" },
    { 25, "Number of \'TCP\' messages received" },
    { 26, "Number of \'UTC time\' messages received" },
    { 27, "Number of \'Data\' messages received" },
    { 28, "Number of \'High Resolution\' messages received" },
    { 29, "Number of \'Aircraft Target Airborne\' messages received" },
    { 30, "Number of \'Aircraft Target Ground\' messages received" },
    { 31, "Number of \'Ground Vehicle Target\' messages received" },
    { 32, "Number of \'2 slots TCP messages received" },
    { 0, NULL }
};
static const value_string valstr_023_120_REF[] = {
    { 0, "From midnight" },
    { 1, "From the last report" },
    { 0, NULL }
};
static const FieldPart I023_120_TYPE = { 8, 1.0, FIELD_PART_UINT, &hf_023_120_TYPE, NULL };
static const FieldPart I023_120_REF = { 1, 1.0, FIELD_PART_UINT, &hf_023_120_REF, NULL };
static const FieldPart I023_120_COUNTER = { 32, 1.0, FIELD_PART_UINT, &hf_023_120_COUNTER, NULL };
static const FieldPart *I023_120_PARTS[] = { &I023_120_TYPE, &I023_120_REF, &IXXX_7bit_spare, &I023_120_COUNTER, NULL };

/* Operational Range */
static const FieldPart I023_200_RANGE = { 8, 1.0, FIELD_PART_UFLOAT, &hf_023_200_RANGE, NULL };
static const FieldPart *I023_200_PARTS[] = { &I023_200_RANGE, NULL };

/* Items */
static const AsterixField I023_000 = { FIXED, 1, 0, 0, &hf_023_000, I023_000_PARTS, { NULL } };
static const AsterixField I023_010 = { FIXED, 2, 0, 0, &hf_023_010, IXXX_SAC_SIC, { NULL } };
static const AsterixField I023_015 = { FIXED, 1, 0, 0, &hf_023_015, I023_015_PARTS, { NULL } };
static const AsterixField I023_070 = { FIXED, 3, 0, 0, &hf_023_070, IXXX_TOD, { NULL } };
static const AsterixField I023_100 = { FX, 1, 0, 0, &hf_023_100, I023_100_PARTS, { NULL } };
static const AsterixField I023_101 = { FX, 1, 0, 1, &hf_023_101, I023_101_PARTS, { NULL } };
static const AsterixField I023_110 = { FX, 1, 0, 0, &hf_023_110, I023_110_PARTS, { NULL } };
static const AsterixField I023_120 = { REPETITIVE, 6, 1, 0, &hf_023_120, I023_120_PARTS, { NULL } };
static const AsterixField I023_200 = { FIXED, 1, 0, 0, &hf_023_200, I023_200_PARTS, { NULL } };
static const AsterixField I023_RE = { RE, 0, 0, 1, &hf_023_RE, NULL, { NULL } };
static const AsterixField I023_SP = { SP, 0, 0, 1, &hf_023_SP, NULL, { NULL } };

static const AsterixField *I023_v1_2_uap[] = { &I023_010, &I023_000, &I023_015, &I023_070, &I023_100, &I023_101, &I023_200,
                                               &I023_110, &I023_120, &IX_SPARE, &IX_SPARE, &IX_SPARE, &I023_RE,  &I023_SP, NULL };
static const AsterixField **I023_v1_2[] = { I023_v1_2_uap, NULL };
static const AsterixField ***I023[] = { I023_v1_2 };

static const enum_val_t I023_versions[] = {
    { "I023_v1_2", "Version 1.2", 0 },
    { NULL, NULL, 0 }
};

/* *********************** */
/*      Category 034       */
/* *********************** */
/* Fields */

/* Message Type */
static const value_string valstr_034_000_MT[] = {
    { 1, "North Marker message" },
    { 2, "Sector crossing message" },
    { 3, "Geographical filtering message" },
    { 4, "Jamming Strobe message" },
    { 0, NULL }
};
static const FieldPart I034_000_MT = { 8, 1.0, FIELD_PART_UINT, &hf_034_000_MT, NULL };
static const FieldPart *I034_000_PARTS[] = { &I034_000_MT, NULL };

/* Sector Number */
static const FieldPart I034_020_SN = { 8, 360.0/256.0, FIELD_PART_UFLOAT, &hf_034_020_SN, NULL };
static const FieldPart *I034_020_PARTS[] = { &I034_020_SN, NULL };

/* Antenna Rotation Speed */
static const FieldPart I034_041_ARS = { 16, 1.0/128.0, FIELD_PART_UFLOAT, &hf_034_041_ARS, NULL };
static const FieldPart *I034_041_PARTS[] = { &I034_041_ARS, NULL };

/* System Configuration and Status */
static const value_string valstr_034_050_01_NOGO[] = {
    { 0, "System is released for operational use" },
    { 1, "Operational use of System is inhibited, i.e. the data shall be discarded by an operational SDPS" },
    { 0, NULL }
};
static const value_string valstr_034_050_01_RDPC[] = {
    { 0, "RDPC-1 selected" },
    { 1, "RDPC-2 selected" },
    { 0, NULL }
};
static const value_string valstr_034_050_01_RDPR[] = {
    { 0, "Default situation" },
    { 1, "Reset of RDPC" },
    { 0, NULL }
};
static const value_string valstr_034_050_01_OVL_RDP[] = {
    { 0, "Default, no overload" },
    { 1, "Overload in RDP" },
    { 0, NULL }
};
static const value_string valstr_034_050_01_OVL_XMT[] = {
    { 0, "Default, no overload" },
    { 1, "Overload in transmission subsystem" },
    { 0, NULL }
};
static const value_string valstr_034_050_01_MSC[] = {
    { 0, "Monitoring system connected" },
    { 1, "Monitoring system disconnected" },
    { 0, NULL }
};
static const value_string valstr_034_050_01_TSV[] = {
    { 0, "valid" },
    { 1, "invalid" },
    { 0, NULL }
};
static const value_string valstr_034_050_02_ANT[] = {
    { 0, "antenna 1" },
    { 1, "antenna 2" },
    { 0, NULL }
};
static const value_string valstr_034_050_02_CHAB[] = {
    { 0, "No channel selected" },
    { 1, "Channel A only selected" },
    { 2, "Channel B only selected" },
    { 3, "Diversity mode; Channel A and B selected" },
    { 0, NULL }
};
static const value_string valstr_034_050_02_OVL[] = {
    { 0, "No overload" },
    { 1, "Overload" },
    { 0, NULL }
};
static const value_string valstr_034_050_02_MSC[] = {
    { 0, "Monitoring system connected" },
    { 1, "Monitoring system disconnected" },
    { 0, NULL }
};
static const value_string valstr_034_050_03_ANT[] = {
    { 0, "antenna 1" },
    { 1, "antenna 2" },
    { 0, NULL }
};
static const value_string valstr_034_050_03_CHAB[] = {
    { 0, "No channel selected" },
    { 1, "Channel A only selected" },
    { 2, "Channel B only selected" },
    { 3, "Invalid combination" },
    { 0, NULL }
};
static const value_string valstr_034_050_03_OVL[] = {
    { 0, "No overload" },
    { 1, "Overload" },
    { 0, NULL }
};
static const value_string valstr_034_050_03_MSC[] = {
    { 0, "Monitoring system connected" },
    { 1, "Monitoring system disconnected" },
    { 0, NULL }
};
static const value_string valstr_034_050_04_ANT[] = {
    { 0, "antenna 1" },
    { 1, "antenna 2" },
    { 0, NULL }
};
static const value_string valstr_034_050_04_CHAB[] = {
    { 0, "No channel selected" },
    { 1, "Channel A only selected" },
    { 2, "Channel B only selected" },
    { 3, "Illegal combination" },
    { 0, NULL }
};
static const value_string valstr_034_050_04_OVL_SUR[] = {
    { 0, "No overload" },
    { 1, "Overload" },
    { 0, NULL }
};
static const value_string valstr_034_050_04_MSC[] = {
    { 0, "Monitoring system connected" },
    { 1, "Monitoring system disconnected" },
    { 0, NULL }
};
static const value_string valstr_034_050_04_SCF[] = {
    { 0, "Channel A in use" },
    { 1, "Channel B in use" },
    { 0, NULL }
};
static const value_string valstr_034_050_04_DLF[] = {
    { 0, "Channel A in use" },
    { 1, "Channel B in use" },
    { 0, NULL }
};
static const value_string valstr_034_050_04_OVL_SCF[] = {
    { 0, "No overload" },
    { 1, "Overload" },
    { 0, NULL }
};
static const value_string valstr_034_050_04_OVL_DLF[] = {
    { 0, "No overload" },
    { 1, "Overload" },
    { 0, NULL }
};
static const FieldPart I034_050_01_NOGO = { 1, 1.0, FIELD_PART_UINT, &hf_034_050_01_NOGO, NULL };
static const FieldPart I034_050_01_RDPC = { 1, 1.0, FIELD_PART_UINT, &hf_034_050_01_RDPC, NULL };
static const FieldPart I034_050_01_RDPR = { 1, 1.0, FIELD_PART_UINT, &hf_034_050_01_RDPR, NULL };
static const FieldPart I034_050_01_OVL_RDP = { 1, 1.0, FIELD_PART_UINT, &hf_034_050_01_OVL_RDP, NULL };
static const FieldPart I034_050_01_OVL_XMT = { 1, 1.0, FIELD_PART_UINT, &hf_034_050_01_OVL_XMT, NULL };
static const FieldPart I034_050_01_MSC = { 1, 1.0, FIELD_PART_UINT, &hf_034_050_01_MSC, NULL };
static const FieldPart I034_050_01_TSV = { 1, 1.0, FIELD_PART_UINT, &hf_034_050_01_TSV, NULL };
static const FieldPart *I034_050_01_PARTS[] = { &I034_050_01_NOGO, &I034_050_01_RDPC, &I034_050_01_RDPR, &I034_050_01_OVL_RDP, &I034_050_01_OVL_XMT, &I034_050_01_MSC, &I034_050_01_TSV, NULL };
static const FieldPart I034_050_02_ANT = { 1, 1.0, FIELD_PART_UINT, &hf_034_050_02_ANT, NULL };
static const FieldPart I034_050_02_CHAB = { 2, 1.0, FIELD_PART_UINT, &hf_034_050_02_CHAB, NULL };
static const FieldPart I034_050_02_OVL = { 1, 1.0, FIELD_PART_UINT, &hf_034_050_02_OVL, NULL };
static const FieldPart I034_050_02_MSC = { 1, 1.0, FIELD_PART_UINT, &hf_034_050_02_MSC, NULL };
static const FieldPart *I034_050_02_PARTS[] = { &I034_050_02_ANT, &I034_050_02_CHAB, &I034_050_02_OVL, &I034_050_02_MSC, NULL };
static const FieldPart I034_050_03_ANT = { 1, 1.0, FIELD_PART_UINT, &hf_034_050_03_ANT, NULL };
static const FieldPart I034_050_03_CHAB = { 2, 1.0, FIELD_PART_UINT, &hf_034_050_03_CHAB, NULL };
static const FieldPart I034_050_03_OVL = { 1, 1.0, FIELD_PART_UINT, &hf_034_050_03_OVL, NULL };
static const FieldPart I034_050_03_MSC = { 1, 1.0, FIELD_PART_UINT, &hf_034_050_03_MSC, NULL };
static const FieldPart *I034_050_03_PARTS[] = { &I034_050_03_ANT, &I034_050_03_CHAB, &I034_050_03_OVL, &I034_050_03_MSC, NULL };
static const FieldPart I034_050_04_ANT = { 1, 1.0, FIELD_PART_UINT, &hf_034_050_04_ANT, NULL };
static const FieldPart I034_050_04_CHAB = { 2, 1.0, FIELD_PART_UINT, &hf_034_050_04_CHAB, NULL };
static const FieldPart I034_050_04_OVL_SUR = { 1, 1.0, FIELD_PART_UINT, &hf_034_050_04_OVL_SUR, NULL };
static const FieldPart I034_050_04_MSC = { 1, 1.0, FIELD_PART_UINT, &hf_034_050_04_MSC, NULL };
static const FieldPart I034_050_04_SCF = { 1, 1.0, FIELD_PART_UINT, &hf_034_050_04_SCF, NULL };
static const FieldPart I034_050_04_DLF = { 1, 1.0, FIELD_PART_UINT, &hf_034_050_04_DLF, NULL };
static const FieldPart I034_050_04_OVL_SCF = { 1, 1.0, FIELD_PART_UINT, &hf_034_050_04_OVL_SCF, NULL };
static const FieldPart I034_050_04_OVL_DLF = { 1, 1.0, FIELD_PART_UINT, &hf_034_050_04_OVL_DLF, NULL };
static const FieldPart *I034_050_04_PARTS[] = { &I034_050_04_ANT, &I034_050_04_CHAB, &I034_050_04_OVL_SUR, &I034_050_04_MSC, &I034_050_04_SCF, &I034_050_04_DLF, &I034_050_04_OVL_SCF,
                                                &I034_050_04_OVL_DLF, NULL };

/* System Processing Mode */
static const value_string valstr_034_060_RED[] = {
    { 0, "No reduction active" },
    { 1, "Reduction step 1 active" },
    { 2, "Reduction step 2 active" },
    { 3, "Reduction step 3 active" },
    { 4, "Reduction step 4 active" },
    { 5, "Reduction step 5 active" },
    { 6, "Reduction step 6 active" },
    { 7, "Reduction step 7 active" },
    { 0, NULL }
};
static const value_string valstr_034_060_02_POL[] = {
    { 0, "Linear polarization" },
    { 1, "Circular polarization" },
    { 0, NULL }
};
static const value_string valstr_034_060_02_STC[] = {
    { 0, "STC Map-1" },
    { 1, "STC Map-2" },
    { 2, "STC Map-3" },
    { 3, "STC Map-4" },
    { 0, NULL }
};
static const value_string valstr_034_060_04_CLU[] = {
    { 0, "Autonomous" },
    { 1, "Not autonomous" },
    { 0, NULL }
};
static const FieldPart I034_060_01_RED_RDP = { 3, 1.0, FIELD_PART_UINT, &hf_034_060_01_RED_RDP, NULL };
static const FieldPart I034_060_01_RED_XMT = { 3, 1.0, FIELD_PART_UINT, &hf_034_060_01_RED_XMT, NULL };
static const FieldPart *I034_060_01_PARTS[] = { &IXXX_1bit_spare, &I034_060_01_RED_RDP, &I034_060_01_RED_XMT, NULL };
static const FieldPart I034_060_02_POL = { 1, 1.0, FIELD_PART_UINT, &hf_034_060_02_POL, NULL };
static const FieldPart I034_060_02_RED_RAD = { 3, 1.0, FIELD_PART_UINT, &hf_034_060_02_RED_RAD, NULL };
static const FieldPart I034_060_02_STC = { 2, 1.0, FIELD_PART_UINT, &hf_034_060_02_STC, NULL };
static const FieldPart *I034_060_02_PARTS[] = { &I034_060_02_POL, &I034_060_02_RED_RAD, &I034_060_02_STC, NULL };
static const FieldPart I034_060_03_RED_RAD = { 3, 1.0, FIELD_PART_UINT, &hf_034_060_03_RED_RAD, NULL };
static const FieldPart *I034_060_03_PARTS[] = { &I034_060_03_RED_RAD, NULL };
static const FieldPart I034_060_04_RED_RAD = { 3, 1.0, FIELD_PART_UINT, &hf_034_060_04_RED_RAD, NULL };
static const FieldPart I034_060_04_CLU = { 1, 1.0, FIELD_PART_UINT, &hf_034_060_04_CLU, NULL };
static const FieldPart *I034_060_04_PARTS[] = { &I034_060_04_RED_RAD, &I034_060_04_CLU, NULL };

/* Plot Count Values */
static const value_string valstr_034_070_TYP[] = {
    {  0, "No detection (number of misses)" },
    {  1, "Single PSR target reports" },
    {  2, "Single SSR target reports (Non-Mode S)" },
    {  3, "SSR+PSR target reports (Non-Mode S)" },
    {  4, "Single All-Call target reports (Mode S)" },
    {  5, "Single Roll-Call target reports (Mode S)" },
    {  6, "All-Call + PSR (Mode S) target reports" },
    {  7, "Roll-Call + PSR (Mode S) target reports" },
    {  8, "Filter for Weather data" },
    {  9, "Filter for Jamming Strobe" },
    { 10, "Filter for PSR data" },
    { 11, "Filter for SSR/Mode S data" },
    { 12, "Filter for SSR/Mode S+PSR data" },
    { 13, "Filter for Enhanced Surveillance data" },
    { 14, "Filter for PSR+Enhanced Surveillance" },
    { 15, "Filter for PSR+Enhanced Surveillance + SSR/Mode S data not in Area of Prime Interest" },
    { 16, "Filter for PSR+Enhanced Surveillance + all SSR/Mode S data" },
    { 0, NULL }
};
static const FieldPart I034_070_TYP = { 5, 1.0, FIELD_PART_UINT, &hf_034_070_TYP, NULL };
static const FieldPart I034_070_COUNTER = { 11, 1.0, FIELD_PART_UINT, &hf_034_070_COUNTER, NULL };
static const FieldPart *I034_070_PARTS[] = { &I034_070_TYP, &I034_070_COUNTER, NULL };

/* Collimation Error */
static const FieldPart I034_090_RE = { 8, 1.0/128.0, FIELD_PART_FLOAT, &hf_034_090_RE, NULL };
static const FieldPart I034_090_AE = { 8, 360.0/16384.0, FIELD_PART_FLOAT, &hf_034_090_AE, NULL };
static const FieldPart *I034_090_PARTS[] = { &I034_090_RE, &I034_090_AE, NULL };

/* Dynamic Window - Type 1 */
static const FieldPart I034_100_RHOS = { 16, 1.0/256.0, FIELD_PART_UFLOAT, &hf_035_100_RHOS, NULL };
static const FieldPart I034_100_RHOE = { 16, 1.0/256.0, FIELD_PART_UFLOAT, &hf_035_100_RHOE, NULL };
static const FieldPart I034_100_THETAS = { 16, 360.0/65536.0, FIELD_PART_UFLOAT, &hf_035_100_THETAS, NULL };
static const FieldPart I034_100_THETAE = { 16, 360.0/65536.0, FIELD_PART_UFLOAT, &hf_035_100_THETAE, NULL };
static const FieldPart *I034_100_PARTS[] = { &I034_100_RHOS, &I034_100_RHOE, &I034_100_THETAS, &I034_100_THETAE, NULL };

/* Data Filter */
static const value_string valstr_034_110_TYP[] = {
    { 0, "invalid value" },
    { 1, "Filter for Weather data" },
    { 2, "Filter for Jamming Strobe" },
    { 3, "Filter for PSR data" },
    { 4, "Filter for SSR/Mode S data" },
    { 5, "Filter for SSR/Mode S + PSR data" },
    { 6, "Enhanced Surveillance data" },
    { 7, "Filter for PSR+Enhanced Surveillance data" },
    { 8, "Filter for PSR+Enhanced Surveillance + SSR/Mode S data not in Area of Prime Interest" },
    { 9, "Filter for PSR+Enhanced Surveillance + all SSR/Mode S data" },
    { 0, NULL }
};
static const FieldPart I034_110_TYP = { 8, 1.0, FIELD_PART_UINT, &hf_034_110_TYP, NULL };
static const FieldPart *I034_110_PARTS[] = { &I034_110_TYP, NULL };

/* 3-D Position of Data Source */
static const FieldPart I034_120_H = { 16, 1.0, FIELD_PART_FLOAT, &hf_034_120_H, NULL };
static const FieldPart I034_120_LAT = { 24, 180.0/8388608.0, FIELD_PART_FLOAT, &hf_034_120_LAT, NULL };
static const FieldPart I034_120_LON = { 24, 180.0/8388608.0, FIELD_PART_FLOAT, &hf_034_120_LON, NULL };
static const FieldPart *I034_120_PARTS[] = { &I034_120_H, &I034_120_LAT, &I034_120_LON, NULL };

/* Items */
static const AsterixField I034_000 = { FIXED, 1, 0, 0, &hf_034_000, I034_000_PARTS, { NULL } };
static const AsterixField I034_010 = { FIXED, 2, 0, 0, &hf_034_010, IXXX_SAC_SIC, { NULL } };
static const AsterixField I034_020 = { FIXED, 1, 0, 0, &hf_034_020, I034_020_PARTS, { NULL } };
static const AsterixField I034_030 = { FIXED, 3, 0, 0, &hf_034_030, IXXX_TOD, { NULL } };
static const AsterixField I034_041 = { FIXED, 2, 0, 0, &hf_034_041, I034_041_PARTS, { NULL } };
static const AsterixField I034_050_01 = { FIXED, 1, 0, 0, &hf_034_050_01, I034_050_01_PARTS, { NULL } };
static const AsterixField I034_050_02 = { FIXED, 1, 0, 0, &hf_034_050_02, I034_050_02_PARTS, { NULL } };
static const AsterixField I034_050_03 = { FIXED, 1, 0, 0, &hf_034_050_03, I034_050_03_PARTS, { NULL } };
static const AsterixField I034_050_04 = { FIXED, 2, 0, 0, &hf_034_050_04, I034_050_04_PARTS, { NULL } };
static const AsterixField I034_050 = { COMPOUND, 0, 0, 0, &hf_034_050, NULL, { &I034_050_01,
                                                                               &IX_SPARE,
                                                                               &IX_SPARE,
                                                                               &I034_050_02,
                                                                               &I034_050_03,
                                                                               &I034_050_04,
                                                                               NULL} };
static const AsterixField I034_060_01 = { FIXED, 1, 0, 0, &hf_034_060_01, I034_060_01_PARTS, { NULL } };
static const AsterixField I034_060_02 = { FIXED, 1, 0, 0, &hf_034_060_02, I034_060_02_PARTS, { NULL } };
static const AsterixField I034_060_03 = { FIXED, 1, 0, 0, &hf_034_060_03, I034_060_03_PARTS, { NULL } };
static const AsterixField I034_060_04 = { FIXED, 1, 0, 0, &hf_034_060_04, I034_060_04_PARTS, { NULL } };
static const AsterixField I034_060 = { COMPOUND, 0, 0, 0, &hf_034_060, NULL, { &I034_060_01,
                                                                               &IX_SPARE,
                                                                               &IX_SPARE,
                                                                               &I034_060_02,
                                                                               &I034_060_03,
                                                                               &I034_060_04,
                                                                           NULL} };
static const AsterixField I034_070 = { REPETITIVE, 2, 1, 0, &hf_034_070, I034_070_PARTS, { NULL } };
static const AsterixField I034_090 = { FIXED, 2, 0, 0, &hf_034_090, I034_090_PARTS, { NULL } };
static const AsterixField I034_100 = { FIXED, 8, 0, 0, &hf_034_100, I034_100_PARTS, { NULL } };
static const AsterixField I034_110 = { FIXED, 1, 0, 0, &hf_034_110, I034_110_PARTS, { NULL } };
static const AsterixField I034_120 = { FIXED, 8, 0, 0, &hf_034_120, I034_120_PARTS, { NULL } };
static const AsterixField I034_RE = { RE, 0, 0, 1, &hf_034_RE, NULL, { NULL } };
static const AsterixField I034_SP = { SP, 0, 0, 1, &hf_034_SP, NULL, { NULL } };

static const AsterixField *I034_v1_27_uap[] = { &I034_010, &I034_000, &I034_030, &I034_020, &I034_041, &I034_050, &I034_060,
                                                &I034_070, &I034_100, &I034_110, &I034_120, &I034_090, &I034_RE,  &I034_SP, NULL };
static const AsterixField **I034_v1_27[] = { I034_v1_27_uap, NULL };
static const AsterixField ***I034[] = { I034_v1_27 };

static const enum_val_t I034_versions[] = {
    { "I034_v1_27", "Version 1.27", 0 },
    { NULL, NULL, 0 }
};

/* *********************** */
/*      Category 048       */
/* *********************** */
/* Fields */

/* Target report descriptor */
static const value_string valstr_048_020_TYP[] = {
    { 0, "No detection" },
    { 1, "Single PSR detection" },
    { 2, "Single SSR detection" },
    { 3, "SSR + PSR detection" },
    { 4, "Single ModeS All-Call" },
    { 5, "Single ModeS Roll-Call" },
    { 6, "ModeS All-Call + PSR" },
    { 7, "ModeS Roll-Call + PSR" },
    { 0, NULL }
};
static const value_string valstr_048_020_SIM[] = {
    { 0, "Actual target report" },
    { 1, "Simulated target report" },
    { 0, NULL }
};
static const value_string valstr_048_020_RDP[] = {
    { 0, "Report from RDP Chain 1" },
    { 1, "Report from RDP Chain 2" },
    { 0, NULL }
};
static const value_string valstr_048_020_SPI[] = {
    { 0, "Absence of SPI" },
    { 1, "Special Position Identification" },
    { 0, NULL }
};
static const value_string valstr_048_020_RAB[] = {
    { 0, "Report from aircraft transponder" },
    { 1, "Report from field monitor (fixed transponder)" },
    { 0, NULL }
};
static const value_string valstr_048_020_TST[] = {
    { 0, "Real target report" },
    { 1, "Test target report" },
    { 0, NULL }
};
static const value_string valstr_048_020_ME[] = {
    { 0, "No military emergency" },
    { 1, "Military emergency" },
    { 0, NULL }
};
static const value_string valstr_048_020_MI[] = {
    { 0, "No military identification" },
    { 1, "Military identification" },
    { 0, NULL }
};
static const value_string valstr_048_020_FOE[] = {
    { 0, "No Mode 4 interrogation" },
    { 1, "Friendly target" },
    { 2, "Unknown target" },
    { 3, "No reply" },
    { 0, NULL }
};
static const FieldPart I048_020_TYP = { 3, 1.0, FIELD_PART_UINT, &hf_048_020_TYP, NULL };
static const FieldPart I048_020_SIM = { 1, 1.0, FIELD_PART_UINT, &hf_048_020_SIM, NULL };
static const FieldPart I048_020_RDP = { 1, 1.0, FIELD_PART_UINT, &hf_048_020_RDP, NULL };
static const FieldPart I048_020_SPI = { 1, 1.0, FIELD_PART_UINT, &hf_048_020_SPI, NULL };
static const FieldPart I048_020_RAB = { 1, 1.0, FIELD_PART_UINT, &hf_048_020_RAB, NULL };
static const FieldPart I048_020_TST = { 1, 1.0, FIELD_PART_UINT, &hf_048_020_TST, NULL };
static const FieldPart I048_020_ME = { 1, 1.0, FIELD_PART_UINT, &hf_048_020_ME, NULL };
static const FieldPart I048_020_MI = { 1, 1.0, FIELD_PART_UINT, &hf_048_020_MI, NULL };
static const FieldPart I048_020_FOE = { 2, 1.0, FIELD_PART_UINT, &hf_048_020_FOE, NULL };
static const FieldPart *I048_020_PARTS[] = { &I048_020_TYP, &I048_020_SIM, &I048_020_RDP, &I048_020_SPI, &I048_020_RAB, &IXXX_FX,
                                              &I048_020_TST, &IXXX_2bit_spare, &I048_020_ME, &I048_020_MI, &I048_020_FOE, &IXXX_FX, NULL };

/* Warning/Error Conditions */
static const value_string valstr_048_030_WE[] = {
    {  0, "Not defined; never used." },
    {  1, "Multipath Reply (Reflection)" },
    {  2, "Reply due to sidelobe interrogation/reception" },
    {  3, "Split plot" },
    {  4, "Second time around reply" },
    {  5, "Angel" },
    {  6, "Slow moving target correlated with road infrastructure (terrestrial vehicle)" },
    {  7, "Fixed PSR plot" },
    {  8, "Slow PSR target" },
    {  9, "Low quality PSR plot" },
    { 10, "Phantom SSR plot" },
    { 11, "Non-Matching Mode-3/A Code" },
    { 12, "Mode C code / Mode S altitude code abnormal value compared to the track" },
    { 13, "Target in Clutter Area" },
    { 14, "Maximum Doppler Response in Zero Filter" },
    { 15, "Transponder anomaly detected" },
    { 16, "Duplicated or Illegal Mode S Aircraft Address" },
    { 17, "Mode S error correction applied" },
    { 18, "Undecodable Mode C code / Mode S altitude code" },
    { 19, "Birds" },
    { 20, "Flock of Birds" },
    { 0, NULL }
};
static const FieldPart I048_030_WE = { 7, 1.0, FIELD_PART_UINT, &hf_048_030_WE, NULL };
static const FieldPart *I048_030_PARTS[] = { &I048_030_WE, &IXXX_FX, NULL };

/* Measured Position in Polar Co-ordinates */
static const FieldPart I048_040_RHO = { 16, 1.0/256.0, FIELD_PART_UFLOAT, &hf_048_040_RHO, NULL };
static const FieldPart I048_040_THETA = { 16, 360.0/65536.0, FIELD_PART_UFLOAT, &hf_048_040_THETA, NULL };
static const FieldPart *I048_040_PARTS[] = { &I048_040_RHO, &I048_040_THETA, NULL };

/* Cartesian position */
static const FieldPart I048_042_X = { 16, 1.0/128.0, FIELD_PART_FLOAT, &hf_048_042_X, NULL };
static const FieldPart I048_042_Y = { 16, 1.0/128.0, FIELD_PART_FLOAT, &hf_048_042_Y, NULL };
static const FieldPart *I048_042_PARTS[] = { &I048_042_X, &I048_042_Y, NULL };

/* Mode-2 Code */
static const value_string valstr_048_050_V[] = {
    { 0, "Code validated" },
    { 1, "Code not validated" },
    { 0, NULL }
};
static const value_string valstr_048_050_G[] = {
    { 0, "Default" },
    { 1, "Garbled code" },
    { 0, NULL }
};
static const value_string valstr_048_050_L[] = {
    { 0, "Mode-2 code as derived from the reply of the transponder" },
    { 1, "Smoothed Mode-2 code as provided by a local tracker" },
    { 0, NULL }
};
static const FieldPart I048_050_V = { 1, 1.0, FIELD_PART_UINT, &hf_048_050_V, NULL };
static const FieldPart I048_050_G = { 1, 1.0, FIELD_PART_UINT, &hf_048_050_G, NULL };
static const FieldPart I048_050_L = { 1, 1.0, FIELD_PART_UINT, &hf_048_050_L, NULL };
static const FieldPart I048_050_SQUAWK = { 12, 1.0, FIELD_PART_SQUAWK, &hf_048_050_SQUAWK, NULL };
static const FieldPart *I048_050_PARTS[] = { &I048_050_V, &I048_050_G, &I048_050_L, &IXXX_1bit_spare, &I048_050_SQUAWK, NULL };

/* Mode-1 Code */
static const value_string valstr_048_055_V[] = {
    { 0, "Code validated" },
    { 1, "Code not validated" },
    { 0, NULL }
};
static const value_string valstr_048_055_G[] = {
    { 0, "Default" },
    { 1, "Garbled code" },
    { 0, NULL }
};
static const value_string valstr_048_055_L[] = {
    { 0, "Mode-1 code as derived from the reply of the transponder" },
    { 1, "Smoothed Mode-1 code as provided by a local tracker" },
    { 0, NULL }
};
static const FieldPart I048_055_V = { 1, 1.0, FIELD_PART_UINT, &hf_048_055_V, NULL };
static const FieldPart I048_055_G = { 1, 1.0, FIELD_PART_UINT, &hf_048_055_G, NULL };
static const FieldPart I048_055_L = { 1, 1.0, FIELD_PART_UINT, &hf_048_055_L, NULL };
static const FieldPart I048_055_CODE = { 5, 1.0, FIELD_PART_SQUAWK, &hf_048_055_CODE, NULL };
static const FieldPart *I048_055_PARTS[] = { &I048_055_V, &I048_055_G, &I048_055_L, &I048_055_CODE, NULL };

/* Mode-2 Code Confidence Indicator */
static const value_string valstr_048_060_QA[] = {
    { 0, "High quality pulse" },
    { 1, "Low quality pulse" },
    { 0, NULL }
};
static const FieldPart I048_060_QA4 = { 1, 1.0, FIELD_PART_UINT, &hf_048_060_QA4, NULL };
static const FieldPart I048_060_QA2 = { 1, 1.0, FIELD_PART_UINT, &hf_048_060_QA2, NULL };
static const FieldPart I048_060_QA1 = { 1, 1.0, FIELD_PART_UINT, &hf_048_060_QA1, NULL };
static const FieldPart I048_060_QB4 = { 1, 1.0, FIELD_PART_UINT, &hf_048_060_QB4, NULL };
static const FieldPart I048_060_QB2 = { 1, 1.0, FIELD_PART_UINT, &hf_048_060_QB2, NULL };
static const FieldPart I048_060_QB1 = { 1, 1.0, FIELD_PART_UINT, &hf_048_060_QB1, NULL };
static const FieldPart I048_060_QC4 = { 1, 1.0, FIELD_PART_UINT, &hf_048_060_QC4, NULL };
static const FieldPart I048_060_QC2 = { 1, 1.0, FIELD_PART_UINT, &hf_048_060_QC2, NULL };
static const FieldPart I048_060_QC1 = { 1, 1.0, FIELD_PART_UINT, &hf_048_060_QC1, NULL };
static const FieldPart I048_060_QD4 = { 1, 1.0, FIELD_PART_UINT, &hf_048_060_QD4, NULL };
static const FieldPart I048_060_QD2 = { 1, 1.0, FIELD_PART_UINT, &hf_048_060_QD2, NULL };
static const FieldPart I048_060_QD1 = { 1, 1.0, FIELD_PART_UINT, &hf_048_060_QD1, NULL };
static const FieldPart *I048_060_PARTS[] = { &IXXX_4bit_spare,
                                             &I048_060_QA4, &I048_060_QA2, &I048_060_QA1,
                                             &I048_060_QB4, &I048_060_QB2, &I048_060_QB1,
                                             &I048_060_QC4, &I048_060_QC2, &I048_060_QC1,
                                             &I048_060_QD4, &I048_060_QD2, &I048_060_QD1, NULL };

/* Mode-1 Code Confidence Indicator */
static const value_string valstr_048_065_QA[] = {
    { 0, "High quality pulse" },
    { 1, "Low quality pulse" },
    { 0, NULL }
};
static const FieldPart I048_065_QA4 = { 1, 1.0, FIELD_PART_UINT, &hf_048_065_QA4, NULL };
static const FieldPart I048_065_QA2 = { 1, 1.0, FIELD_PART_UINT, &hf_048_065_QA2, NULL };
static const FieldPart I048_065_QA1 = { 1, 1.0, FIELD_PART_UINT, &hf_048_065_QA1, NULL };
static const FieldPart I048_065_QB2 = { 1, 1.0, FIELD_PART_UINT, &hf_048_065_QB2, NULL };
static const FieldPart I048_065_QB1 = { 1, 1.0, FIELD_PART_UINT, &hf_048_065_QB1, NULL };
static const FieldPart *I048_065_PARTS[] = { &IXXX_3bit_spare,
                                             &I048_065_QA4, &I048_065_QA2, &I048_065_QA1,
                                             &I048_065_QB2, &I048_065_QB1, NULL };

/* Mode-3/A Code */
static const value_string valstr_048_070_V[] = {
    { 0, "Code validated" },
    { 1, "Code not validated" },
    { 0, NULL }
};
static const value_string valstr_048_070_G[] = {
    { 0, "Default" },
    { 1, "Garbled code" },
    { 0, NULL }
};
static const value_string valstr_048_070_L[] = {
    { 0, "Mode-3/A code derived from the reply of the transponder" },
    { 1, "Mode-3/A code not extracted during the last scan" },
    { 0, NULL }
};
static const FieldPart I048_070_V = { 1, 1.0, FIELD_PART_UINT, &hf_048_070_V, NULL };
static const FieldPart I048_070_G = { 1, 1.0, FIELD_PART_UINT, &hf_048_070_G, NULL };
static const FieldPart I048_070_L = { 1, 1.0, FIELD_PART_UINT, &hf_048_070_L, NULL };
static const FieldPart I048_070_SQUAWK = { 12, 1.0, FIELD_PART_SQUAWK, &hf_048_070_SQUAWK, NULL };
static const FieldPart *I048_070_PARTS[] = { &I048_070_V, &I048_070_G, &I048_070_L, &IXXX_1bit_spare, &I048_070_SQUAWK, NULL };

/* Mode 3/A Confidence Indicator */
static const value_string valstr_048_080_QA[] = {
    { 0, "High quality pulse" },
    { 1, "Low quality pulse" },
    { 0, NULL }
};
static const FieldPart I048_080_QA4 = { 1, 1.0, FIELD_PART_UINT, &hf_048_080_QA4, NULL };
static const FieldPart I048_080_QA2 = { 1, 1.0, FIELD_PART_UINT, &hf_048_080_QA2, NULL };
static const FieldPart I048_080_QA1 = { 1, 1.0, FIELD_PART_UINT, &hf_048_080_QA1, NULL };
static const FieldPart I048_080_QB4 = { 1, 1.0, FIELD_PART_UINT, &hf_048_080_QB4, NULL };
static const FieldPart I048_080_QB2 = { 1, 1.0, FIELD_PART_UINT, &hf_048_080_QB2, NULL };
static const FieldPart I048_080_QB1 = { 1, 1.0, FIELD_PART_UINT, &hf_048_080_QB1, NULL };
static const FieldPart I048_080_QC4 = { 1, 1.0, FIELD_PART_UINT, &hf_048_080_QC4, NULL };
static const FieldPart I048_080_QC2 = { 1, 1.0, FIELD_PART_UINT, &hf_048_080_QC2, NULL };
static const FieldPart I048_080_QC1 = { 1, 1.0, FIELD_PART_UINT, &hf_048_080_QC1, NULL };
static const FieldPart I048_080_QD4 = { 1, 1.0, FIELD_PART_UINT, &hf_048_080_QD4, NULL };
static const FieldPart I048_080_QD2 = { 1, 1.0, FIELD_PART_UINT, &hf_048_080_QD2, NULL };
static const FieldPart I048_080_QD1 = { 1, 1.0, FIELD_PART_UINT, &hf_048_080_QD1, NULL };
static const FieldPart *I048_080_PARTS[] = { &IXXX_4bit_spare,
                                             &I048_080_QA4, &I048_080_QA2, &I048_080_QA1,
                                             &I048_080_QB4, &I048_080_QB2, &I048_080_QB1,
                                             &I048_080_QC4, &I048_080_QC2, &I048_080_QC1,
                                             &I048_080_QD4, &I048_080_QD2, &I048_080_QD1, NULL };

/* Flight level */
static const value_string valstr_048_090_V[] = {
    { 0, "Code validated" },
    { 1, "Code not validated" },
    { 0, NULL }
};
static const value_string valstr_048_090_G[] = {
    { 0, "Default" },
    { 1, "Garbled code" },
    { 0, NULL }
};
static const FieldPart I048_090_V = { 1, 1.0, FIELD_PART_UINT, &hf_048_090_V, NULL };
static const FieldPart I048_090_G = { 1, 1.0, FIELD_PART_UINT, &hf_048_090_G, NULL };
static const FieldPart I048_090_FL = { 14, 1.0/4.0, FIELD_PART_FLOAT, &hf_048_090_FL, NULL };
static const FieldPart *I048_090_PARTS[] = { &I048_090_V, &I048_090_G, &I048_090_FL, NULL };

/* Mode-C Code and Code Confidence Indicator */
static const value_string valstr_048_100_V[] = {
    { 0, "Code validated" },
    { 1, "Code not validated" },
    { 0, NULL }
};
static const value_string valstr_048_100_G[] = {
    { 0, "Default" },
    { 1, "Garbled code" },
    { 0, NULL }
};
static const value_string valstr_048_100_QA[] = {
    { 0, "High quality pulse" },
    { 1, "Low quality pulse" },
    { 0, NULL }
};
static const FieldPart I048_100_V = { 1, 1.0, FIELD_PART_UINT, &hf_048_100_V, NULL };
static const FieldPart I048_100_G = { 1, 1.0, FIELD_PART_UINT, &hf_048_100_G, NULL };
static const FieldPart I048_100_A4 = { 1, 1.0, FIELD_PART_UINT, &hf_048_100_A4, NULL };
static const FieldPart I048_100_A2 = { 1, 1.0, FIELD_PART_UINT, &hf_048_100_A2, NULL };
static const FieldPart I048_100_A1 = { 1, 1.0, FIELD_PART_UINT, &hf_048_100_A1, NULL };
static const FieldPart I048_100_B4 = { 1, 1.0, FIELD_PART_UINT, &hf_048_100_B4, NULL };
static const FieldPart I048_100_B2 = { 1, 1.0, FIELD_PART_UINT, &hf_048_100_B2, NULL };
static const FieldPart I048_100_B1 = { 1, 1.0, FIELD_PART_UINT, &hf_048_100_B1, NULL };
static const FieldPart I048_100_C4 = { 1, 1.0, FIELD_PART_UINT, &hf_048_100_C4, NULL };
static const FieldPart I048_100_C2 = { 1, 1.0, FIELD_PART_UINT, &hf_048_100_C2, NULL };
static const FieldPart I048_100_C1 = { 1, 1.0, FIELD_PART_UINT, &hf_048_100_C1, NULL };
static const FieldPart I048_100_D4 = { 1, 1.0, FIELD_PART_UINT, &hf_048_100_D4, NULL };
static const FieldPart I048_100_D2 = { 1, 1.0, FIELD_PART_UINT, &hf_048_100_D2, NULL };
static const FieldPart I048_100_D1 = { 1, 1.0, FIELD_PART_UINT, &hf_048_100_D1, NULL };
static const FieldPart I048_100_QA4 = { 1, 1.0, FIELD_PART_UINT, &hf_048_100_QA4, NULL };
static const FieldPart I048_100_QA2 = { 1, 1.0, FIELD_PART_UINT, &hf_048_100_QA2, NULL };
static const FieldPart I048_100_QA1 = { 1, 1.0, FIELD_PART_UINT, &hf_048_100_QA1, NULL };
static const FieldPart I048_100_QB4 = { 1, 1.0, FIELD_PART_UINT, &hf_048_100_QB4, NULL };
static const FieldPart I048_100_QB2 = { 1, 1.0, FIELD_PART_UINT, &hf_048_100_QB2, NULL };
static const FieldPart I048_100_QB1 = { 1, 1.0, FIELD_PART_UINT, &hf_048_100_QB1, NULL };
static const FieldPart I048_100_QC4 = { 1, 1.0, FIELD_PART_UINT, &hf_048_100_QC4, NULL };
static const FieldPart I048_100_QC2 = { 1, 1.0, FIELD_PART_UINT, &hf_048_100_QC2, NULL };
static const FieldPart I048_100_QC1 = { 1, 1.0, FIELD_PART_UINT, &hf_048_100_QC1, NULL };
static const FieldPart I048_100_QD4 = { 1, 1.0, FIELD_PART_UINT, &hf_048_100_QD4, NULL };
static const FieldPart I048_100_QD2 = { 1, 1.0, FIELD_PART_UINT, &hf_048_100_QD2, NULL };
static const FieldPart I048_100_QD1 = { 1, 1.0, FIELD_PART_UINT, &hf_048_100_QD1, NULL };
static const FieldPart *I048_100_PARTS[] = { &I048_100_V, &I048_100_G, &IXXX_2bit_spare,
                                             &I048_100_C1, &I048_100_A1, &I048_100_C2, &I048_100_A2,
                                             &I048_100_C4, &I048_100_A4, &I048_100_B1, &I048_100_D1,
                                             &I048_100_B2, &I048_100_D2, &I048_100_B4, &I048_100_D4,
                                             &IXXX_4bit_spare,
                                             &I048_100_QC1, &I048_100_QA1, &I048_100_QC2, &I048_100_QA2,
                                             &I048_100_QC4, &I048_100_QA4, &I048_100_QB1, &I048_100_QD1,
                                             &I048_100_QB2, &I048_100_QD2, &I048_100_QB4, &I048_100_QD4, NULL };

/* Height Measured by a 3D Radar */
static const FieldPart I048_110_3DHEIGHT = { 14, 25.0, FIELD_PART_FLOAT, &hf_048_110_3DHEIGHT, NULL };
static const FieldPart *I048_110_PARTS[] = { &IXXX_2bit_spare, &I048_110_3DHEIGHT, NULL };

/* Radial Doppler Speed */
static const value_string valstr_048_120_01_D[] = {
    { 0, "Doppler speed is valid" },
    { 1, "Doppler speed is doubtful" },
    { 0, NULL }
};
static const FieldPart I048_120_01_D = { 1, 1.0, FIELD_PART_UINT, &hf_048_120_01_D, NULL };
static const FieldPart I048_120_01_CAL = { 10, 1.0, FIELD_PART_FLOAT, &hf_048_120_01_CAL, NULL };
static const FieldPart *I048_120_01_PARTS[] = { &I048_120_01_D, &IXXX_5bit_spare, &I048_120_01_CAL, NULL };

static const FieldPart I048_120_02_DOP = { 16, 1.0, FIELD_PART_UINT, &hf_048_120_02_DOP, NULL };
static const FieldPart I048_120_02_AMB = { 16, 1.0, FIELD_PART_UINT, &hf_048_120_02_AMB, NULL };
static const FieldPart I048_120_02_FRQ = { 16, 1.0, FIELD_PART_UINT, &hf_048_120_02_FRQ, NULL };
static const FieldPart *I048_120_02_PARTS[] = { &I048_120_02_DOP, &I048_120_02_AMB, &I048_120_02_FRQ, NULL };

/* Radar Plot Characteristics */
static const FieldPart I048_130_SRL_VAL = { 8, 360.0/8192.0, FIELD_PART_UFLOAT, &hf_048_130_01_SRL, NULL };
static const FieldPart *I048_130_SRL[] = { &I048_130_SRL_VAL, NULL };
static const FieldPart I048_130_SRR_VAL = { 8, 1.0, FIELD_PART_UINT, &hf_048_130_02_SRR, NULL };
static const FieldPart *I048_130_SRR[] = { &I048_130_SRR_VAL, NULL };
static const FieldPart I048_130_SAM_VAL = { 8, 1.0, FIELD_PART_INT, &hf_048_130_03_SAM, NULL };
static const FieldPart *I048_130_SAM[] = { &I048_130_SAM_VAL, NULL };
static const FieldPart I048_130_PRL_VAL = { 8, 360.0/8192.0, FIELD_PART_UFLOAT, &hf_048_130_04_PRL, NULL };
static const FieldPart *I048_130_PRL[] = { &I048_130_PRL_VAL, NULL };
static const FieldPart I048_130_PAM_VAL = { 8, 1.0, FIELD_PART_INT, &hf_048_130_05_PAM, NULL };
static const FieldPart *I048_130_PAM[] = { &I048_130_PAM_VAL, NULL };
static const FieldPart I048_130_RPD_VAL = { 8, 1.0/256.0, FIELD_PART_FLOAT, &hf_048_130_06_RPD, NULL };
static const FieldPart *I048_130_RPD[] = { &I048_130_RPD_VAL, NULL };
static const FieldPart I048_130_APD_VAL = { 8, 360.0/16384.0, FIELD_PART_FLOAT, &hf_048_130_07_APD, NULL };
static const FieldPart *I048_130_APD[] = { &I048_130_APD_VAL, NULL };

/* Track number */
static const FieldPart I048_161_TN = { 12, 1.0, FIELD_PART_UINT, &hf_048_161_TN, NULL };
static const FieldPart *I048_161_PARTS[] = { &IXXX_4bit_spare, &I048_161_TN, NULL };

/* Track Status */
static const value_string valstr_048_170_CNF[] = {
    { 0, "Confirmed Track" } ,
    { 1, "Tentative Track" } ,
    { 0, NULL }
};
static const value_string valstr_048_170_RAD[] = {
    { 0, "Combined Track" } ,
    { 1, "PSR Track" } ,
    { 2, "SSR/Mode S Track" } ,
    { 3, "Invalid" } ,
    { 0, NULL }
};
static const value_string valstr_048_170_DOU[] = {
    { 0, "Normal confidence" } ,
    { 1, "Low confidence in plot to track association." } ,
    { 0, NULL }
};
static const value_string valstr_048_170_MAH[] = {
    { 0, "No horizontal man.sensed" } ,
    { 1, "Horizontal man. sensed" } ,
    { 0, NULL }
};
static const value_string valstr_048_170_CDM[] = {
    { 0, "Maintaining" } ,
    { 1, "Climbing" } ,
    { 2, "Descending" } ,
    { 3, "Invalid" } ,
    { 0, NULL }
};
static const value_string valstr_048_170_TRE[] = {
    { 0, "Track still alive" } ,
    { 1, "End of track lifetime(last report for this track)" } ,
    { 0, NULL }
};
static const value_string valstr_048_170_GHO[] = {
    { 0, "True target track." } ,
    { 1, "Ghost target track." } ,
    { 0, NULL }
};
static const value_string valstr_048_170_SUP[] = {
    { 0, "no" } ,
    { 1, " yes" } ,
    { 0, NULL }
};
static const value_string valstr_048_170_TCC[] = {
    { 0, "Tracking performed in socalled 'Radar Plane', i.e. neither slant range correction nor stereographical projection was applied." } ,
    { 1, "Slant range correction and a suitable projection technique are used to track in a 2D.reference plane, tangential to the earth model at the Radar Site co-ordinates." } ,
    { 0, NULL }
};
static const FieldPart I048_170_CNF = { 1, 1.0, FIELD_PART_UINT, &hf_048_170_CNF, NULL };
static const FieldPart I048_170_RAD = { 2, 1.0, FIELD_PART_UINT, &hf_048_170_RAD, NULL };
static const FieldPart I048_170_DOU = { 1, 1.0, FIELD_PART_UINT, &hf_048_170_DOU, NULL };
static const FieldPart I048_170_MAH = { 1, 1.0, FIELD_PART_UINT, &hf_048_170_MAH, NULL };
static const FieldPart I048_170_CDM = { 2, 1.0, FIELD_PART_UINT, &hf_048_170_CDM, NULL };
static const FieldPart I048_170_TRE = { 1, 1.0, FIELD_PART_UINT, &hf_048_170_TRE, NULL };
static const FieldPart I048_170_GHO = { 1, 1.0, FIELD_PART_UINT, &hf_048_170_GHO, NULL };
static const FieldPart I048_170_SUP = { 1, 1.0, FIELD_PART_UINT, &hf_048_170_SUP, NULL };
static const FieldPart I048_170_TCC = { 1, 1.0, FIELD_PART_UINT, &hf_048_170_TCC, NULL };
static const FieldPart *I048_170_PARTS[] = { &I048_170_CNF, &I048_170_RAD, &I048_170_DOU, &I048_170_MAH, &I048_170_CDM, &IXXX_FX,
                                              &I048_170_TRE, &I048_170_GHO, &I048_170_SUP, &I048_170_TCC, &IXXX_3bit_spare, &IXXX_FX, NULL };

/* Calculated Track Velocity in Polar Co-ordinates */
static const FieldPart I048_200_GS = { 16, 1.0/16384.0, FIELD_PART_UFLOAT, &hf_048_200_GS, NULL };
static const FieldPart I048_200_HDG = { 16, 360.0/65536.0, FIELD_PART_UFLOAT, &hf_048_200_HDG, NULL };
static const FieldPart *I048_200_PARTS[] = { &I048_200_GS, &I048_200_HDG, NULL };

/* Track Quality */
static const FieldPart I048_210_X = { 8, 1.0/128.0, FIELD_PART_UFLOAT, &hf_048_210_X, NULL };
static const FieldPart I048_210_Y = { 8, 1.0/128.0, FIELD_PART_UFLOAT, &hf_048_210_Y, NULL };
static const FieldPart I048_210_V = { 8, 1.0/16384.0, FIELD_PART_UFLOAT, &hf_048_210_V, NULL };
static const FieldPart I048_210_H = { 8, 360.0/4096.0, FIELD_PART_UFLOAT, &hf_048_210_H, NULL };
static const FieldPart *I048_210_PARTS[] = { &I048_210_X, &I048_210_Y, &I048_210_V, &I048_210_H, NULL };

/* Communications/ACAS Capability and Flight Status */
static const value_string valstr_048_230_COM[] = {
    { 0, "No communications capability (surveillance only)" },
    { 1, "Comm. A and Comm. B capability" },
    { 2, "Comm. A, Comm. B and Uplink ELM" },
    { 3, "Comm. A, Comm. B, Uplink ELM and Downlink ELM" },
    { 4, "Level 5 Transponder capability" },
    { 0, NULL }
};
static const value_string valstr_048_230_STAT[] = {
    { 0, "No alert, no SPI, aircraft airborne" },
    { 1, "No alert, no SPI, aircraft on ground" },
    { 2, "Alert, no SPI, aircraft airborne" },
    { 3, "Alert, no SPI, aircraft on ground" },
    { 4, "Alert, SPI, aircraft airborne or on ground" },
    { 5, "No alert, SPI, aircraft airborne or on ground" },
    { 0, NULL }
};
static const value_string valstr_048_230_SI[] = {
    { 0, "SI-Code Capable" },
    { 1, "II-Code Capable" },
    { 0, NULL }
};
static const value_string valstr_048_230_MSSC[] = {
    { 0, "No" },
    { 1, "Yes" },
    { 0, NULL }
};
static const value_string valstr_048_230_ARC[] = {
    { 0, "100 ft resolution" },
    { 1, "25 ft resolution" },
    { 0, NULL }
};
static const value_string valstr_048_230_AIC[] = {
    { 0, "No" },
    { 1, "Yes" },
    { 0, NULL }
};
static const FieldPart I048_230_COM = { 3, 1.0, FIELD_PART_UINT, &hf_048_230_COM, NULL };
static const FieldPart I048_230_STAT = { 3, 1.0, FIELD_PART_UINT, &hf_048_230_STAT, NULL };
static const FieldPart I048_230_SI = { 1, 1.0, FIELD_PART_UINT, &hf_048_230_SI, NULL };
static const FieldPart I048_230_MSSC = { 1, 1.0, FIELD_PART_UINT, &hf_048_230_MSSC, NULL };
static const FieldPart I048_230_ARC = { 1, 1.0, FIELD_PART_UINT, &hf_048_230_ARC, NULL };
static const FieldPart I048_230_AIC = { 1, 1.0, FIELD_PART_UINT, &hf_048_230_AIC, NULL };
static const FieldPart I048_230_B1A = { 1, 1.0, FIELD_PART_UINT, &hf_048_230_B1A, NULL };
static const FieldPart I048_230_B1B = { 4, 1.0, FIELD_PART_UINT, &hf_048_230_B1B, NULL };
static const FieldPart *I048_230_PARTS[] = { &I048_230_COM, &I048_230_STAT, &I048_230_SI, &IXXX_1bit_spare,
                                              &I048_230_MSSC, &I048_230_ARC, &I048_230_AIC, &I048_230_B1A, &I048_230_B1B, NULL };

/* ACAS Resolution Advisory Report */
static const FieldPart I048_260_ACAS = { 56, 1.0, FIELD_PART_HEX, &hf_048_260_ACAS, NULL };
static const FieldPart *I048_260_PARTS[] = { &I048_260_ACAS, NULL };

/* Items */
static const AsterixField I048_010 = { FIXED, 2, 0, 0, &hf_048_010, IXXX_SAC_SIC, { NULL } };
static const AsterixField I048_020 = { FX, 1, 0, 0, &hf_048_020, I048_020_PARTS, { NULL } };
static const AsterixField I048_030 = { FX, 1, 0, 0, &hf_048_030, I048_030_PARTS, { NULL } };
static const AsterixField I048_040 = { FIXED, 4, 0, 0, &hf_048_040, I048_040_PARTS, { NULL } };
static const AsterixField I048_042 = { FIXED, 4, 0, 0, &hf_048_042, I048_042_PARTS, { NULL } };
static const AsterixField I048_050 = { FIXED, 2, 0, 0, &hf_048_050, I048_050_PARTS, { NULL } };
static const AsterixField I048_055 = { FIXED, 1, 0, 0, &hf_048_055, I048_055_PARTS, { NULL } };
static const AsterixField I048_060 = { FIXED, 2, 0, 0, &hf_048_060, I048_060_PARTS, { NULL } };
static const AsterixField I048_065 = { FIXED, 1, 0, 0, &hf_048_065, I048_065_PARTS, { NULL } };
static const AsterixField I048_070 = { FIXED, 2, 0, 0, &hf_048_070, I048_070_PARTS, { NULL } };
static const AsterixField I048_080 = { FIXED, 2, 0, 0, &hf_048_080, I048_080_PARTS, { NULL } };
static const AsterixField I048_090 = { FIXED, 2, 0, 0, &hf_048_090, I048_090_PARTS, { NULL } };
static const AsterixField I048_100 = { FIXED, 4, 0, 0, &hf_048_100, I048_100_PARTS, { NULL } };
static const AsterixField I048_110 = { FIXED, 2, 0, 0, &hf_048_110, I048_110_PARTS, { NULL } };
static const AsterixField I048_120_01 = { FIXED, 2, 0, 0, &hf_048_120_01, I048_120_01_PARTS, { NULL } };
static const AsterixField I048_120_02 = { REPETITIVE, 6, 1, 0, &hf_048_120_02, I048_120_02_PARTS, { NULL } };
static const AsterixField I048_120 = { COMPOUND, 0, 0, 0, &hf_048_120, NULL, { &I048_120_01,
                                                                               &I048_120_02,
                                                                               NULL } };
static const AsterixField I048_130_01 = { FIXED, 1, 0, 0, &hf_048_130_01, I048_130_SRL, { NULL } };
static const AsterixField I048_130_02 = { FIXED, 1, 0, 0, &hf_048_130_02, I048_130_SRR, { NULL } };
static const AsterixField I048_130_03 = { FIXED, 1, 0, 0, &hf_048_130_03, I048_130_SAM, { NULL } };
static const AsterixField I048_130_04 = { FIXED, 1, 0, 0, &hf_048_130_04, I048_130_PRL, { NULL } };
static const AsterixField I048_130_05 = { FIXED, 1, 0, 0, &hf_048_130_05, I048_130_PAM, { NULL } };
static const AsterixField I048_130_06 = { FIXED, 1, 0, 0, &hf_048_130_06, I048_130_RPD, { NULL } };
static const AsterixField I048_130_07 = { FIXED, 1, 0, 0, &hf_048_130_07, I048_130_APD, { NULL } };
static const AsterixField I048_130 = { COMPOUND, 0, 0, 0, &hf_048_130, NULL, { &I048_130_01,
                                                                               &I048_130_02,
                                                                               &I048_130_03,
                                                                               &I048_130_04,
                                                                               &I048_130_05,
                                                                               &I048_130_06,
                                                                               &I048_130_07,
                                                                               NULL } };
static const AsterixField I048_140 = { FIXED, 3, 0, 0, &hf_048_140, IXXX_TOD, { NULL } };
static const AsterixField I048_161 = { FIXED, 2, 0, 0, &hf_048_161, I048_161_PARTS, { NULL } };
static const AsterixField I048_170 = { FX, 1, 0, 0, &hf_048_170, I048_170_PARTS, { NULL } };
static const AsterixField I048_200 = { FIXED, 4, 0, 0, &hf_048_200, I048_200_PARTS, { NULL } };
static const AsterixField I048_210 = { FIXED, 4, 0, 0, &hf_048_210, I048_210_PARTS, { NULL } };
static const AsterixField I048_220 = { FIXED, 3, 0, 0, &hf_048_220, IXXX_AA_PARTS, { NULL } };
static const AsterixField I048_230 = { FIXED, 2, 0, 0, &hf_048_230, I048_230_PARTS, { NULL } };
static const AsterixField I048_240 = { FIXED, 6, 0, 0, &hf_048_240, IXXX_AI_PARTS, { NULL } };
static const AsterixField I048_250 = { REPETITIVE, 8, 1, 0, &hf_048_250, IXXX_MB, { NULL } };
static const AsterixField I048_260 = { FIXED, 7, 0, 0, &hf_048_260, I048_260_PARTS, { NULL } };
static const AsterixField I048_RE = { RE, 0, 0, 1, &hf_048_RE, NULL, { NULL } };
static const AsterixField I048_SP = { SP, 0, 0, 1, &hf_048_SP, NULL, { NULL } };

static const AsterixField *I048_v1_17_uap[] = { &I048_010, &I048_140, &I048_020, &I048_040, &I048_070, &I048_090, &I048_130,
                                                &I048_220, &I048_240, &I048_250, &I048_161, &I048_042, &I048_200, &I048_170,
                                                &I048_210, &I048_030, &I048_080, &I048_100, &I048_110, &I048_120, &I048_230,
                                                &I048_260, &I048_055, &I048_050, &I048_065, &I048_060, &I048_RE,  &I048_SP, NULL };
static const AsterixField **I048_v1_17[] = { I048_v1_17_uap, NULL };
static const AsterixField ***I048[] = { I048_v1_17 };

static const enum_val_t I048_versions[] = {
    { "I048_v1_17", "Version 1.17", 0 },
    { NULL, NULL, 0 }
};

/* *********************** */
/*      Category 062       */
/* *********************** */
/* Fields */

/* Service Identification */
static const FieldPart I062_015_SI = { 8, 1.0, FIELD_PART_UINT, &hf_062_015_SI, NULL };
static const FieldPart *I062_015_PARTS[] = { &I062_015_SI, NULL };

/* Track Mode 3/A Code */
static const value_string valstr_062_060_CH[] = {
    { 0, "No Change" },
    { 1, "Mode 3/A has changed" },
    { 0, NULL }
};
static const FieldPart I062_060_CH = { 1, 1.0, FIELD_PART_UINT, &hf_062_060_CH, NULL };
static const FieldPart I062_060_SQUAWK = { 12, 1.0, FIELD_PART_SQUAWK, &hf_062_060_SQUAWK, NULL };
static const FieldPart *I062_060_PARTS[] = { &IXXX_2bit_spare, &I062_060_CH, &IXXX_1bit_spare, &I062_060_SQUAWK, NULL };
static const FieldPart *I062_060_PARTS_v0_17[] = { &IXXX_4bit_spare, &I062_060_SQUAWK, NULL };

/* Track Status */
static const value_string valstr_062_080_MON[] = {
    { 0, "Multisensor" },
    { 1, "Monosensor track track" },
    { 0, NULL }
};
static const value_string valstr_062_080_SPI[] = {
    { 0, "default value" },
    { 1, "SPI present in the last report received from a sensor capable of decoding this data" },
    { 0, NULL }
};
static const value_string valstr_062_080_MRH[] = {
    { 0, "Barometric altitude (Mode C) more reliable" },
    { 1, "Geometric altitude more reliable" },
    { 0, NULL }
};
static const value_string valstr_062_080_SRC[] = {
    { 0, "no source" },
    { 1, "GNSS" },
    { 2, "3D radar" },
    { 3, "triangulation" },
    { 4, "height from coverage" },
    { 5, "speed look-up table" },
    { 6, "default height" },
    { 7, "multilateration" },
    { 0, NULL }
};
static const value_string valstr_062_080_CNF[] = {
    { 0, "Confirmed track" },
    { 1, "Tentative track" },
    { 0, NULL }
};
static const value_string valstr_062_080_SIM[] = {
    { 0, "Actual track" },
    { 1, "Simulated track" },
    { 0, NULL }
};
static const value_string valstr_062_080_TSE[] = {
    { 0, "default value" },
    { 1, "last message transmitted to the user for the track" },
    { 0, NULL }
};
static const value_string valstr_062_080_TSB[] = {
    { 0, "default value" },
    { 1, "first message transmitted to the user for the track" },
    { 0, NULL }
};
static const value_string valstr_062_080_FPC[] = {
    { 0, "Not flight-plan correlated" },
    { 1, "Flight plan correlated" },
    { 0, NULL }
};
static const value_string valstr_062_080_AFF[] = {
    { 0, "default value" },
    { 1, "ADS-B data inconsistent with other surveillance information" },
    { 0, NULL }
};
static const value_string valstr_062_080_STP[] = {
    { 0, "default value" },
    { 1, "Slave Track Promotion" },
    { 0, NULL }
};
static const value_string valstr_062_080_KOS[] = {
    { 0, "Complementary service used" },
    { 1, "Background service used" },
    { 0, NULL }
};
static const value_string valstr_062_080_AMA[] = {
    { 0, "track not resulting from amalgamation process" },
    { 1, "track resulting from amalgamation process" },
    { 0, NULL }
};
static const value_string valstr_062_080_MD4[] = {
    { 0, "No Mode 4 interrogation" },
    { 1, "Friendly target" },
    { 2, "Unknown target" },
    { 3, "No reply" },
    { 0, NULL }
};
static const value_string valstr_062_080_ME[] = {
    { 0, "default value" },
    { 1, "Military Emergency present in the last report received from a sensor capable of decoding this data" },
    { 0, NULL }
};
static const value_string valstr_062_080_MI[] = {
    { 0, "default value" },
    { 1, "Military Identification present in the last report received from a sensor capable of decoding this data" },
    { 0, NULL }
};
static const value_string valstr_062_080_MD5[] = {
    { 0, "No Mode 5 interrogation" },
    { 1, "Friendly target" },
    { 2, "Unknown target" },
    { 3, "No reply" },
    { 0, NULL }
};
static const value_string valstr_062_080_CST[] = {
    { 0, "Default value" },
    { 1, "Age of the last received track update is higher than system dependent threshold (coasting)" },
    { 0, NULL }
};
static const value_string valstr_062_080_PSR[] = {
    { 0, "Default value" },
    { 1, "Age of the last received PSR track update is higher than system dependent threshold" },
    { 0, NULL }
};
static const value_string valstr_062_080_SSR[] = {
    { 0, "Default value" },
    { 1, "Age of the last received SSR track update is higher than system dependent threshold" },
    { 0, NULL }
};
static const value_string valstr_062_080_MDS[] = {
    { 0, "Default value" },
    { 1, "Age of the last received Mode S track update is higher than system dependent threshold" },
    { 0, NULL }
};
static const value_string valstr_062_080_ADS[] = {
    { 0, "Default value" },
    { 1, "Age of the last received ADS-B track update is higher than system dependent threshold" },
    { 0, NULL }
};
static const value_string valstr_062_080_SUC[] = {
    { 0, "Default value" },
    { 1, "Special Used Code (Mode A codes to be defined in the system to mark a track with special interest)" },
    { 0, NULL }
};
static const value_string valstr_062_080_AAC[] = {
    { 0, "Default value" },
    { 1, "Assigned Mode A Code Conflict (same discrete Mode A Code assigned to another track)" },
    { 0, NULL }
};
static const value_string valstr_062_080_SDS[] = {
    { 0, "Combined" },
    { 1, "Co-operative only" },
    { 2, "Non-Cooperative only" },
    { 3, "Not defined" },
    { 0, NULL }
};
static const value_string valstr_062_080_EMS[] = {
    { 0, "No emergency" },
    { 1, "General emergency" },
    { 2, "Lifeguard / medical" },
    { 3, "Minimum fuel" },
    { 4, "No communications" },
    { 5, "Unlawful interference" },
    { 6, "\"Downed\" Aircraft" },
    { 7, "Undefined" },
    { 0, NULL }
};
static const value_string valstr_062_080_PFT[] = {
    { 0, "No indication" },
    { 1, "Potential False Track Indication" },
    { 0, NULL }
};
static const value_string valstr_062_080_FPLT[] = {
    { 0, "Default value" },
    { 1, "Track created / updated with FPL data" },
    { 0, NULL }
};
static const value_string valstr_062_080_DUPT[] = {
    { 0, "Default value" },
    { 1, "Duplicate Mode 3/A Code" },
    { 0, NULL }
};
static const value_string valstr_062_080_DUPF[] = {
    { 0, "Default value" },
    { 1, "Duplicate Flight Plan" },
    { 0, NULL }
};
static const value_string valstr_062_080_DUPM[] = {
    { 0, "Default value" },
    { 1, "Duplicate Flight Plan due to manual correlation" },
    { 0, NULL }
};
static const value_string valstr_062_080_FRIFOE[] = {
    { 0, "No Mode 4 interrogation" },
    { 1, "Friendly target" },
    { 2, "Unknown target" },
    { 3, "No reply" },
    { 0, NULL }
};
static const value_string valstr_062_080_COA[] = {
    { 0, "Default value" },
    { 1, "Age of the last received track update is higher than system dependent threshold (coasting)" },
    { 0, NULL }
};

static const FieldPart I062_080_MON = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_MON, NULL };
static const FieldPart I062_080_SPI = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_SPI, NULL };
static const FieldPart I062_080_MRH = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_MRH, NULL };
static const FieldPart I062_080_SRC = { 3, 1.0, FIELD_PART_UINT, &hf_062_080_SRC, NULL };
static const FieldPart I062_080_CNF = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_CNF, NULL };
static const FieldPart I062_080_SIM = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_SIM, NULL };
static const FieldPart I062_080_TSE = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_TSE, NULL };
static const FieldPart I062_080_TSB = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_TSB, NULL };
static const FieldPart I062_080_FPC = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_FPC, NULL };
static const FieldPart I062_080_AFF = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_AFF, NULL };
static const FieldPart I062_080_STP = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_STP, NULL };
static const FieldPart I062_080_KOS = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_KOS, NULL };
static const FieldPart I062_080_AMA = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_AMA, NULL };
static const FieldPart I062_080_MD4 = { 2, 1.0, FIELD_PART_UINT, &hf_062_080_MD4, NULL };
static const FieldPart I062_080_ME = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_ME, NULL };
static const FieldPart I062_080_MI = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_MI, NULL };
static const FieldPart I062_080_MD5 = { 2, 1.0, FIELD_PART_UINT, &hf_062_080_MD5, NULL };
static const FieldPart I062_080_CST = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_CST, NULL };
static const FieldPart I062_080_PSR = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_PSR, NULL };
static const FieldPart I062_080_SSR = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_SSR, NULL };
static const FieldPart I062_080_MDS = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_MDS, NULL };
static const FieldPart I062_080_ADS = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_ADS, NULL };
static const FieldPart I062_080_SUC = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_SUC, NULL };
static const FieldPart I062_080_AAC = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_AAC, NULL };
static const FieldPart I062_080_SDS = { 2, 1.0, FIELD_PART_UINT, &hf_062_080_SDS, NULL };
static const FieldPart I062_080_EMS = { 3, 1.0, FIELD_PART_UINT, &hf_062_080_EMS, NULL };
static const FieldPart I062_080_PFT = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_PFT, NULL };
static const FieldPart I062_080_FPLT = { 2, 1.0, FIELD_PART_UINT, &hf_062_080_FPLT, NULL };
static const FieldPart I062_080_DUPT = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_DUPT, NULL };
static const FieldPart I062_080_DUPF = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_DUPF, NULL };
static const FieldPart I062_080_DUPM = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_DUPM, NULL };
static const FieldPart I062_080_FRIFOE = { 2, 1.0, FIELD_PART_UINT, &hf_062_080_FRIFOE, NULL };
static const FieldPart I062_080_COA = { 2, 1.0, FIELD_PART_UINT, &hf_062_080_COA, NULL };
static const FieldPart *I062_080_PARTS[] = { &I062_080_MON, &I062_080_SPI, &I062_080_MRH, &I062_080_SRC, &I062_080_CNF, &IXXX_FX,
                                             &I062_080_SIM, &I062_080_TSE, &I062_080_TSB, &I062_080_FPC, &I062_080_AFF, &I062_080_STP, &I062_080_KOS, &IXXX_FX,
                                             &I062_080_AMA, &I062_080_MD4, &I062_080_ME, &I062_080_MI, &I062_080_MD5, &IXXX_FX,
                                             &I062_080_CST, &I062_080_PSR, &I062_080_SSR, &I062_080_MDS, &I062_080_ADS, &I062_080_SUC, &I062_080_AAC, &IXXX_FX,
                                             &I062_080_SDS, &I062_080_EMS, &I062_080_PFT, &I062_080_FPLT, &IXXX_FX,
                                             &I062_080_DUPT, &I062_080_DUPF, &I062_080_DUPM, &IXXX_4bit_spare, &IXXX_FX, NULL };
static const FieldPart *I062_080_PARTS_v0_17[] = { &I062_080_MON, &I062_080_SPI, &I062_080_MRH, &I062_080_SRC, &I062_080_CNF, &IXXX_FX,
                                                   &I062_080_SIM, &I062_080_TSE, &I062_080_TSB, &I062_080_FPC, &IXXX_3bit_spare, &IXXX_FX,
                                                   &I062_080_AMA, &I062_080_FRIFOE, &I062_080_ME, &I062_080_MI, &IXXX_2bit_spare, &IXXX_FX,
                                                   &I062_080_COA, &I062_080_PSR, &I062_080_SSR, &I062_080_MDS, &I062_080_ADS, &I062_080_SUC, &I062_080_AAC, &IXXX_FX, NULL };

/* Calculated Track Position. (Cartesian) */
static const FieldPart I062_100_X = { 24, 0.5, FIELD_PART_FLOAT, &hf_062_100_X, NULL };
static const FieldPart I062_100_Y = { 24, 0.5, FIELD_PART_FLOAT, &hf_062_100_Y, NULL };
static const FieldPart I062_100_X_v0_17 = { 16, 1.0/64.0, FIELD_PART_FLOAT, &hf_062_100_X_v0_17, NULL };
static const FieldPart I062_100_Y_v0_17 = { 16, 1.0/64.0, FIELD_PART_FLOAT, &hf_062_100_Y_v0_17, NULL };
static const FieldPart *I062_100_PARTS[] = { &I062_100_X, &I062_100_Y, NULL };
static const FieldPart *I062_100_PARTS_v0_17[] = { &I062_100_X_v0_17, &I062_100_Y_v0_17, NULL };

/* Calculated Position in WGS-84 Co-ordinates */
static const FieldPart I062_105_LAT = { 32, 180.0/33554432.0, FIELD_PART_FLOAT, &hf_062_105_LAT, NULL };
static const FieldPart I062_105_LON = { 32, 180.0/33554432.0, FIELD_PART_FLOAT, &hf_062_105_LON, NULL };
static const FieldPart I062_105_LAT_v0_17 = { 24, 180.0/8388608.0, FIELD_PART_FLOAT, &hf_062_105_LAT, NULL };
static const FieldPart I062_105_LON_v0_17 = { 24, 180.0/8388608.0, FIELD_PART_FLOAT, &hf_062_105_LON, NULL };
static const FieldPart *I062_105_PARTS[] = { &I062_105_LAT, &I062_105_LON, NULL };
static const FieldPart *I062_105_PARTS_v0_17[] = { &I062_105_LAT_v0_17, &I062_105_LON_v0_17, NULL };

/* Mode 5 Data reports & Extended Mode 1 Code */
static const value_string valstr_062_110_01_M5[] = {
    { 0, "No Mode 5 interrogation" },
    { 1, "Mode 5 interrogation" },
    { 0, NULL }
};
static const value_string valstr_062_110_01_ID[] = {
    { 0, "No authenticated Mode 5 ID reply" },
    { 1, "Authenticated Mode 5 ID reply" },
    { 0, NULL }
};
static const value_string valstr_062_110_01_DA[] = {
    { 0, "No authenticated Mode 5 Data reply or Report" },
    { 1, "Authenticated Mode 5 Data reply or Report (ie any valid Mode 5 reply type other than ID)" },
    { 0, NULL }
};
static const value_string valstr_062_110_01_M1[] = {
    { 0, "Mode 1 code not present or not from Mode 5 reply" },
    { 1, "Mode 1 code from Mode 5 reply" },
    { 0, NULL }
};
static const value_string valstr_062_110_01_M2[] = {
    { 0, "Mode 2 code not present or not from Mode 5 reply" },
    { 1, "Mode 2 code from Mode 5 reply" },
    { 0, NULL }
};
static const value_string valstr_062_110_01_M3[] = {
    { 0, "Mode 3 code not present or not from Mode 5 reply" },
    { 1, "Mode 3 code from Mode 5 reply" },
    { 0, NULL }
};
static const value_string valstr_062_110_01_MC[] = {
    { 0, "Mode C altitude not present or not from Mode 5 reply" },
    { 1, "Mode C altitude from Mode 5 reply" },
    { 0, NULL }
};
static const value_string valstr_062_110_01_X[] = {
    { 0, "X-pulse set to zero or no authenticated Data reply or Report received" },
    { 1, "X-pulse set to one" },
    { 0, NULL }
};
static const FieldPart I062_110_01_M5 = { 1, 1.0, FIELD_PART_UINT, &hf_062_110_01_M5, NULL };
static const FieldPart I062_110_01_ID = { 1, 1.0, FIELD_PART_UINT, &hf_062_110_01_ID, NULL };
static const FieldPart I062_110_01_DA = { 1, 1.0, FIELD_PART_UINT, &hf_062_110_01_DA, NULL };
static const FieldPart I062_110_01_M1 = { 1, 1.0, FIELD_PART_UINT, &hf_062_110_01_M1, NULL };
static const FieldPart I062_110_01_M2 = { 1, 1.0, FIELD_PART_UINT, &hf_062_110_01_M2, NULL };
static const FieldPart I062_110_01_M3 = { 1, 1.0, FIELD_PART_UINT, &hf_062_110_01_M3, NULL };
static const FieldPart I062_110_01_MC = { 1, 1.0, FIELD_PART_UINT, &hf_062_110_01_MC, NULL };
static const FieldPart I062_110_01_X = { 1, 1.0, FIELD_PART_UINT, &hf_062_110_01_X, NULL };
static const FieldPart *I062_110_01_PARTS[] = { &I062_110_01_M5, &I062_110_01_ID, &I062_110_01_DA, &I062_110_01_M1, &I062_110_01_M2, &I062_110_01_M3, &I062_110_01_MC, &I062_110_01_X, NULL };

static const FieldPart I062_110_02_PIN = { 14, 1.0, FIELD_PART_UINT, &hf_062_110_02_PIN, NULL };
static const FieldPart I062_110_02_NAT = { 5, 1.0, FIELD_PART_UINT, &hf_062_110_02_NAT, NULL };
static const FieldPart I062_110_02_MIS = { 6, 1.0, FIELD_PART_UINT, &hf_062_110_02_MIS, NULL };
static const FieldPart *I062_110_02_PARTS[] = { &IXXX_2bit_spare, &I062_110_02_PIN, &IXXX_3bit_spare, &I062_110_02_NAT, &IXXX_2bit_spare, &I062_110_02_MIS, NULL };

static const FieldPart I062_110_03_LAT = { 24, 180.0/8388608.0, FIELD_PART_FLOAT, &hf_062_110_03_LAT, NULL };
static const FieldPart I062_110_03_LON = { 24, 180.0/8388608.0, FIELD_PART_FLOAT, &hf_062_110_03_LON, NULL };
static const FieldPart *I062_110_03_PARTS[] = { &I062_110_03_LAT, &I062_110_03_LON, NULL };

static const value_string valstr_062_110_04_RES[] = {
    { 0, "GA reported in 100 ft increments" },
    { 1, "GA reported in 25 ft increments" },
    { 0, NULL }
};
static const FieldPart I062_110_04_RES = { 1, 1.0, FIELD_PART_UINT, &hf_062_110_04_RES, NULL };
static const FieldPart I062_110_04_GA = { 14, 25.0, FIELD_PART_FLOAT, &hf_062_110_04_GA, NULL };
static const FieldPart *I062_110_04_PARTS[] = { &I062_110_04_RES, &I062_110_04_GA, NULL };

static const FieldPart I062_110_05_SQUAWK = { 12, 1.0, FIELD_PART_SQUAWK, &hf_062_110_05_SQUAWK, NULL };
static const FieldPart *I062_110_05_PARTS[] = { &IXXX_4bit_spare, &I062_110_05_SQUAWK, NULL };

static const FieldPart I062_110_06_TOS = { 8, 1.0/128, FIELD_PART_FLOAT, &hf_062_110_06_TOS, NULL };
static const FieldPart *I062_110_06_PARTS[] = { &I062_110_06_TOS, NULL };

static const value_string valstr_062_110_07_X5[] = {
    { 0, "X-pulse set to zero or no authenticated Data reply or Report received" },
    { 1, "X-pulse set to one (present)" },
    { 0, NULL }
};
static const value_string valstr_062_110_07_XC[] = {
    { 0, "X-pulse set to zero or no Mode C reply" },
    { 1, "X-pulse set to one (present)" },
    { 0, NULL }
};
static const value_string valstr_062_110_07_X3[] = {
    { 0, "X-pulse set to zero or no Mode 3/A reply" },
    { 1, "X-pulse set to one (present)" },
    { 0, NULL }
};
static const value_string valstr_062_110_07_X2[] = {
    { 0, "X-pulse set to zero or no Mode 2 reply" },
    { 1, "X-pulse set to one (present)" },
    { 0, NULL }
};
static const value_string valstr_062_110_07_X1[] = {
    { 0, "X-pulse set to zero or no Mode 1 reply" },
    { 1, "X-pulse set to one (present)" },
    { 0, NULL }
};
static const FieldPart I062_110_07_X5 = { 1, 1.0, FIELD_PART_UINT, &hf_062_110_07_X5, NULL };
static const FieldPart I062_110_07_XC = { 1, 1.0, FIELD_PART_UINT, &hf_062_110_07_XC, NULL };
static const FieldPart I062_110_07_X3 = { 1, 1.0, FIELD_PART_UINT, &hf_062_110_07_X3, NULL };
static const FieldPart I062_110_07_X2 = { 1, 1.0, FIELD_PART_UINT, &hf_062_110_07_X2, NULL };
static const FieldPart I062_110_07_X1 = { 1, 1.0, FIELD_PART_UINT, &hf_062_110_07_X1, NULL };
static const FieldPart *I062_110_07_PARTS[] = { &IXXX_3bit_spare, &I062_110_07_X5, &I062_110_07_XC, &I062_110_07_X3, &I062_110_07_X2, &I062_110_07_X1, NULL };
/* v0.17 */
static const FieldPart I062_110_A4 = { 1, 1.0, FIELD_PART_UINT, &hf_062_110_A4, NULL };
static const FieldPart I062_110_A2 = { 1, 1.0, FIELD_PART_UINT, &hf_062_110_A2, NULL };
static const FieldPart I062_110_A1 = { 1, 1.0, FIELD_PART_UINT, &hf_062_110_A1, NULL };
static const FieldPart I062_110_B2 = { 1, 1.0, FIELD_PART_UINT, &hf_062_110_B2, NULL };
static const FieldPart I062_110_B1 = { 1, 1.0, FIELD_PART_UINT, &hf_062_110_B1, NULL };
static const FieldPart *I062_110_PARTS_v0_17[] = { &IXXX_3bit_spare, &I062_110_A4, &I062_110_A2, &I062_110_A1, &I062_110_B2, &I062_110_B1, NULL };

/* Track Mode 2 Code */
static const FieldPart I062_120_SQUAWK = { 12, 1.0, FIELD_PART_SQUAWK, &hf_062_120_SQUAWK, NULL };
static const FieldPart *I062_120_PARTS[] = { &IXXX_4bit_spare, &I062_120_SQUAWK, NULL };

/* Calculated Track Geometric Altitude */
static const FieldPart I062_130_ALT = { 16, 6.25, FIELD_PART_FLOAT, &hf_062_130_ALT, NULL };
static const FieldPart *I062_130_PARTS[] = { &I062_130_ALT, NULL };

/* Calculated Track Barometric Altitude */
static const value_string valstr_062_135_QNH[] = {
    { 0, "No QNH correction applied" },
    { 1, "QNH correction applied" },
    { 0, NULL }
};
static const FieldPart I062_135_QNH = { 1, 1.0, FIELD_PART_UINT, &hf_062_135_QNH, NULL };
static const FieldPart I062_135_ALT = { 15, 25.0, FIELD_PART_FLOAT, &hf_062_135_ALT, NULL };
static const FieldPart *I062_135_PARTS[] = { &I062_135_QNH, &I062_135_ALT, NULL };

/* Measured Flight Level */
static const FieldPart I062_136_ALT = { 16, 1.0/4.0, FIELD_PART_FLOAT, &hf_062_136_ALT, NULL };
static const FieldPart *I062_136_PARTS[] = { &I062_136_ALT, NULL };

/* Calculated Track Velocity (Polar) */
static const FieldPart I062_180_SPEED = { 16, 1.0/16384.0, FIELD_PART_FLOAT, &hf_062_180_SPEED, NULL };
static const FieldPart I062_180_HEADING = { 16, 360.0/65536.0, FIELD_PART_FLOAT, &hf_062_180_HEADING, NULL };
static const FieldPart *I062_180_PARTS[] = { &I062_180_SPEED, &I062_180_HEADING, NULL };

/* Calculated Track Velocity (Cartesian) */
static const FieldPart I062_185_VX = { 16, 1.0/4.0, FIELD_PART_FLOAT, &hf_062_185_VX, NULL };
static const FieldPart I062_185_VY = { 16, 1.0/4.0, FIELD_PART_FLOAT, &hf_062_185_VY, NULL };
static const FieldPart *I062_185_PARTS[] = { &I062_185_VX, &I062_185_VY, NULL };

/* Mode of Movement */
static const value_string valstr_062_200_TRANS[] = {
    { 0, "Constant Course" },
    { 1, "Right Turn" },
    { 2, "Left Turn" },
    { 3, "Undetermined" },
    { 0, NULL }
};
static const value_string valstr_062_200_LONG[] = {
    { 0, "Constant Groundspeed" },
    { 1, "Increasing Groundspeed" },
    { 2, "Decreasing Groundspeed" },
    { 3, "Undetermined" },
    { 0, NULL }
};
static const value_string valstr_062_200_VERT[] = {
    { 0, "Level" },
    { 1, "Climb" },
    { 2, "Descent" },
    { 3, "Undetermined" },
    { 0, NULL }
};
static const value_string valstr_062_200_ADF[] = {
    { 0, "No altitude discrepancy" },
    { 1, "Altitude discrepancy" },
    { 0, NULL }
};
static const FieldPart I062_200_TRANS = { 2, 1.0, FIELD_PART_UINT, &hf_062_200_TRANS, NULL };
static const FieldPart I062_200_LONG = { 2, 1.0, FIELD_PART_UINT, &hf_062_200_LONG, NULL };
static const FieldPart I062_200_VERT = { 2, 1.0, FIELD_PART_UINT, &hf_062_200_VERT, NULL };
static const FieldPart I062_200_ADF = { 1, 1.0, FIELD_PART_UINT, &hf_062_200_ADF, NULL };
static const FieldPart *I062_200_PARTS[] = { &I062_200_TRANS, &I062_200_LONG, &I062_200_VERT, &I062_200_ADF, NULL };
static const FieldPart *I062_200_PARTS_v0_17[] = { &I062_200_TRANS, &I062_200_LONG, &I062_200_VERT, NULL };

/* Calculated Acceleration (Cartesian) */
static const FieldPart I062_210_AX = { 8, 1.0/4.0, FIELD_PART_FLOAT, &hf_062_210_AX, NULL };
static const FieldPart I062_210_AY = { 8, 1.0/4.0, FIELD_PART_FLOAT, &hf_062_210_AY, NULL };
static const FieldPart I062_210_CLA = { 16, 1.0/4194304.0, FIELD_PART_FLOAT, &hf_062_210_CLA, NULL };
static const FieldPart *I062_210_PARTS[] = { &I062_210_AX, &I062_210_AY, NULL };
static const FieldPart *I062_210_PARTS_v0_17[] = { &I062_210_CLA, NULL };

/* Calculated Rate Of Climb/Descent */
static const FieldPart I062_220_ROCD = { 16, 6.25, FIELD_PART_FLOAT, &hf_062_220_ROCD, NULL };
static const FieldPart *I062_220_PARTS[] = { &I062_220_ROCD, NULL };

/* Calculated Rate of Turn */
static const FieldPart I062_240_ROT = { 8, 1.0/4.0, FIELD_PART_FLOAT, &hf_062_240_ROT, NULL };
static const FieldPart *I062_240_PARTS[] = { &I062_240_ROT, NULL };

/* Target Size & Orientation */
static const FieldPart I062_270_LENGTH = { 7, 1.0, FIELD_PART_UFLOAT, &hf_062_270_LENGTH, NULL };
static const FieldPart I062_270_ORIENTATION = { 7, 360.0/128.0, FIELD_PART_UFLOAT, &hf_062_270_ORIENTATION, NULL };
static const FieldPart I062_270_WIDTH = { 7, 1.0, FIELD_PART_UFLOAT, &hf_062_270_WIDTH, NULL };
static const FieldPart *I062_270_PARTS[] = { &I062_270_LENGTH, &IXXX_FX,
                                             &I062_270_ORIENTATION, &IXXX_FX,
                                             &I062_270_WIDTH, &IXXX_FX, NULL };

/* System Track Update Ages */
static const FieldPart I062_290_01_TRK = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_290_01_TRK, NULL };
static const FieldPart *I062_290_01_PARTS[] = { &I062_290_01_TRK, NULL };
static const FieldPart I062_290_02_PSR = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_290_02_PSR, NULL };
static const FieldPart *I062_290_02_PARTS[] = { &I062_290_02_PSR, NULL };
static const FieldPart I062_290_03_SSR = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_290_03_SSR, NULL };
static const FieldPart *I062_290_03_PARTS[] = { &I062_290_03_SSR, NULL };
static const FieldPart I062_290_04_MDS = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_290_04_MDS, NULL };
static const FieldPart *I062_290_04_PARTS[] = { &I062_290_04_MDS, NULL };
static const FieldPart I062_290_05_ADS = { 16, 0.25, FIELD_PART_UFLOAT, &hf_062_290_05_ADS, NULL };
static const FieldPart *I062_290_05_PARTS[] = { &I062_290_05_ADS, NULL };
static const FieldPart I062_290_06_ES = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_290_06_ES, NULL };
static const FieldPart *I062_290_06_PARTS[] = { &I062_290_06_ES, NULL };
static const FieldPart I062_290_07_VDL = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_290_07_VDL, NULL };
static const FieldPart *I062_290_07_PARTS[] = { &I062_290_07_VDL, NULL };
static const FieldPart I062_290_08_UAT = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_290_08_UAT, NULL };
static const FieldPart *I062_290_08_PARTS[] = { &I062_290_08_UAT, NULL };
static const FieldPart I062_290_09_LOP = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_290_09_LOP, NULL };
static const FieldPart *I062_290_09_PARTS[] = { &I062_290_09_LOP, NULL };
static const FieldPart I062_290_10_MLT = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_290_10_MLT, NULL };
static const FieldPart *I062_290_10_PARTS[] = { &I062_290_10_MLT, NULL };
/* V0.17 */
static const FieldPart I062_290_01_PSR = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_290_01_PSR, NULL };
static const FieldPart *I062_290_01_PARTS_v0_17[] = { &I062_290_01_PSR, NULL };
static const FieldPart I062_290_02_SSR = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_290_02_SSR, NULL };
static const FieldPart *I062_290_02_PARTS_v0_17[] = { &I062_290_02_SSR, NULL };
static const FieldPart I062_290_03_MDA = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_290_03_MDA, NULL };
static const FieldPart *I062_290_03_PARTS_v0_17[] = { &I062_290_03_MDA, NULL };
static const FieldPart I062_290_04_MFL = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_290_04_MFL, NULL };
static const FieldPart *I062_290_04_PARTS_v0_17[] = { &I062_290_04_MFL, NULL };
static const FieldPart I062_290_05_MDS = { 16, 0.25, FIELD_PART_UFLOAT, &hf_062_290_05_MDS, NULL };
static const FieldPart *I062_290_05_PARTS_v0_17[] = { &I062_290_05_MDS, NULL };
static const FieldPart I062_290_06_ADS = { 16, 0.25, FIELD_PART_UFLOAT, &hf_062_290_06_ADS, NULL };
static const FieldPart *I062_290_06_PARTS_v0_17[] = { &I062_290_06_ADS, NULL };
static const FieldPart I062_290_07_ADB = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_290_07_ADB, NULL };
static const FieldPart *I062_290_07_PARTS_v0_17[] = { &I062_290_07_ADB, NULL };
static const FieldPart I062_290_08_MD1 = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_290_08_MD1, NULL };
static const FieldPart *I062_290_08_PARTS_v0_17[] = { &I062_290_08_MD1, NULL };
static const FieldPart I062_290_09_MD2 = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_290_09_MD2, NULL };
static const FieldPart *I062_290_09_PARTS_v0_17[] = { &I062_290_09_MD2, NULL };

/* Track Data Ages */
static const FieldPart I062_295_01_MFL = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_01_MFL, NULL };
static const FieldPart *I062_295_01_PARTS[] = { &I062_295_01_MFL, NULL };
static const FieldPart I062_295_02_MD1 = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_02_MD1, NULL };
static const FieldPart *I062_295_02_PARTS[] = { &I062_295_02_MD1, NULL };
static const FieldPart I062_295_03_MD2 = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_03_MD2, NULL };
static const FieldPart *I062_295_03_PARTS[] = { &I062_295_03_MD2, NULL };
static const FieldPart I062_295_04_MDA = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_04_MDA, NULL };
static const FieldPart *I062_295_04_PARTS[] = { &I062_295_04_MDA, NULL };
static const FieldPart I062_295_05_MD4 = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_05_MD4, NULL };
static const FieldPart *I062_295_05_PARTS[] = { &I062_295_05_MD4, NULL };
static const FieldPart I062_295_06_MD5 = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_06_MD5, NULL };
static const FieldPart *I062_295_06_PARTS[] = { &I062_295_06_MD5, NULL };
static const FieldPart I062_295_07_MHD = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_07_MHD, NULL };
static const FieldPart *I062_295_07_PARTS[] = { &I062_295_07_MHD, NULL };
static const FieldPart I062_295_08_IAS = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_08_IAS, NULL };
static const FieldPart *I062_295_08_PARTS[] = { &I062_295_08_IAS, NULL };
static const FieldPart I062_295_09_TAS = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_09_TAS, NULL };
static const FieldPart *I062_295_09_PARTS[] = { &I062_295_09_TAS, NULL };
static const FieldPart I062_295_10_SAL = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_10_SAL, NULL };
static const FieldPart *I062_295_10_PARTS[] = { &I062_295_10_SAL, NULL };
static const FieldPart I062_295_11_FSS = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_11_FSS, NULL };
static const FieldPart *I062_295_11_PARTS[] = { &I062_295_11_FSS, NULL };
static const FieldPart I062_295_12_TID = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_12_TID, NULL };
static const FieldPart *I062_295_12_PARTS[] = { &I062_295_12_TID, NULL };
static const FieldPart I062_295_13_COM = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_13_COM, NULL };
static const FieldPart *I062_295_13_PARTS[] = { &I062_295_13_COM, NULL };
static const FieldPart I062_295_14_SAB = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_14_SAB, NULL };
static const FieldPart *I062_295_14_PARTS[] = { &I062_295_14_SAB, NULL };
static const FieldPart I062_295_15_ACS = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_15_ACS, NULL };
static const FieldPart *I062_295_15_PARTS[] = { &I062_295_15_ACS, NULL };
static const FieldPart I062_295_16_BVR = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_16_BVR, NULL };
static const FieldPart *I062_295_16_PARTS[] = { &I062_295_16_BVR, NULL };
static const FieldPart I062_295_17_GVR = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_17_GVR, NULL };
static const FieldPart *I062_295_17_PARTS[] = { &I062_295_17_GVR, NULL };
static const FieldPart I062_295_18_RAN = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_18_RAN, NULL };
static const FieldPart *I062_295_18_PARTS[] = { &I062_295_18_RAN, NULL };
static const FieldPart I062_295_19_TAR = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_19_TAR, NULL };
static const FieldPart *I062_295_19_PARTS[] = { &I062_295_19_TAR, NULL };
static const FieldPart I062_295_20_TAN = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_20_TAN, NULL };
static const FieldPart *I062_295_20_PARTS[] = { &I062_295_20_TAN, NULL };
static const FieldPart I062_295_21_GSP = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_21_GSP, NULL };
static const FieldPart *I062_295_21_PARTS[] = { &I062_295_21_GSP, NULL };
static const FieldPart I062_295_22_VUN = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_22_VUN, NULL };
static const FieldPart *I062_295_22_PARTS[] = { &I062_295_22_VUN, NULL };
static const FieldPart I062_295_23_MET = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_23_MET, NULL };
static const FieldPart *I062_295_23_PARTS[] = { &I062_295_23_MET, NULL };
static const FieldPart I062_295_24_EMC = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_24_EMC, NULL };
static const FieldPart *I062_295_24_PARTS[] = { &I062_295_24_EMC, NULL };
static const FieldPart I062_295_25_POS = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_25_POS, NULL };
static const FieldPart *I062_295_25_PARTS[] = { &I062_295_25_POS, NULL };
static const FieldPart I062_295_26_GAL = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_26_GAL, NULL };
static const FieldPart *I062_295_26_PARTS[] = { &I062_295_26_GAL, NULL };
static const FieldPart I062_295_27_PUN = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_27_PUN, NULL };
static const FieldPart *I062_295_27_PARTS[] = { &I062_295_27_PUN, NULL };
static const FieldPart I062_295_28_MB = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_28_MB, NULL };
static const FieldPart *I062_295_28_PARTS[] = { &I062_295_28_MB, NULL };
static const FieldPart I062_295_29_IAR = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_29_IAR, NULL };
static const FieldPart *I062_295_29_PARTS[] = { &I062_295_29_IAR, NULL };
static const FieldPart I062_295_30_MAC = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_30_MAC, NULL };
static const FieldPart *I062_295_30_PARTS[] = { &I062_295_30_MAC, NULL };
static const FieldPart I062_295_31_BPS = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_31_BPS, NULL };
static const FieldPart *I062_295_31_PARTS[] = { &I062_295_31_BPS, NULL };

/* Vehicle Fleet Identification */
static const value_string valstr_062_300_VFI[] = {
    {  0, "Unknown" },
    {  1, "ATC equipment maintenance" },
    {  2, "Airport maintenance" },
    {  3, "Fire" },
    {  4, "Bird scarer" },
    {  5, "Snow plough" },
    {  6, "Runway sweeper" },
    {  7, "Emergency" },
    {  8, "Police" },
    {  9, "Bus" },
    { 10, "Tug (push/tow)" },
    { 11, "Grass cutter" },
    { 12, "Fuel" },
    { 13, "Baggage" },
    { 14, "Catering" },
    { 15, "Aircraft maintenance" },
    { 16, "Flyco (follow me)" },
    { 0, NULL }
};
static const FieldPart I062_300_VFI = { 8, 1.0, FIELD_PART_UINT, &hf_062_300_VFI, NULL };
static const FieldPart *I062_300_PARTS[] = { &I062_300_VFI, NULL };

/* Measured Information */
/* Measured Position in Polar Co-ordinates */
static const FieldPart I062_340_02_RHO = { 16, 1.0/256.0, FIELD_PART_UFLOAT, &hf_062_340_02_RHO, NULL };
static const FieldPart I062_340_02_THETA = { 16, 360.0/65536.0, FIELD_PART_UFLOAT, &hf_062_340_02_THETA, NULL };
static const FieldPart *I062_340_02_PARTS[] = { &I062_340_02_RHO, &I062_340_02_THETA, NULL };

static const FieldPart I062_340_03_H = { 16, 25.0, FIELD_PART_FLOAT, &hf_062_340_03_H, NULL };
static const FieldPart *I062_340_03_PARTS[] = { &I062_340_03_H, NULL };

static const value_string valstr_062_340_04_V[] = {
    { 0, "Code validated" },
    { 1, "Code not validated" },
    { 0, NULL }
};
static const value_string valstr_062_340_04_G[] = {
    { 0, "Default" },
    { 1, "Garbled code" },
    { 0, NULL }
};
static const FieldPart I062_340_04_V = { 1, 1.0, FIELD_PART_UINT, &hf_062_340_04_V, NULL };
static const FieldPart I062_340_04_G = { 1, 1.0, FIELD_PART_UINT, &hf_062_340_04_G, NULL };
static const FieldPart I062_340_04_FL = { 14, 1.0/4.0, FIELD_PART_FLOAT, &hf_062_340_04_FL, NULL };
static const FieldPart *I062_340_04_PARTS[] = { &I062_340_04_V, &I062_340_04_G, &I062_340_04_FL, NULL, NULL };

static const value_string valstr_062_340_05_V[] = {
    { 0, "Code validated" },
    { 1, "Code not validated" },
    { 0, NULL }
};
static const value_string valstr_062_340_05_G[] = {
    { 0, "Default" },
    { 1, "Garbled code" },
    { 0, NULL }
};
static const value_string valstr_062_340_05_L[] = {
    { 0, "MODE 3/A code as derived from the reply of the transponder" },
    { 1, "Smoothed MODE 3/A code as provided by a sensor local tracker" },
    { 0, NULL }
};
static const FieldPart I062_340_05_V = { 1, 1.0, FIELD_PART_UINT, &hf_062_340_05_V, NULL };
static const FieldPart I062_340_05_G = { 1, 1.0, FIELD_PART_UINT, &hf_062_340_05_G, NULL };
static const FieldPart I062_340_05_L = { 1, 1.0, FIELD_PART_UINT, &hf_062_340_05_L, NULL };
static const FieldPart I062_340_05_SQUAWK = { 12, 1.0, FIELD_PART_SQUAWK, &hf_062_340_05_SQUAWK, NULL };
static const FieldPart *I062_340_05_PARTS[] = { &I062_340_05_V, &I062_340_05_G, &I062_340_05_L, &IXXX_1bit_spare, &I062_340_05_SQUAWK, NULL };

static const value_string valstr_062_340_06_TYP[] = {
    { 0, "No detection" },
    { 1, "Single PSR detection" },
    { 2, "Single SSR detection" },
    { 3, "SSR+PSR detection" },
    { 4, "Single All-Call" },
    { 5, "Single Roll-Call" },
    { 6, "ModeS All-Call + PSR" },
    { 7, "ModeS Roll-Call + PSR" },
    { 0, NULL }
};
static const value_string valstr_062_340_06_SIM[] = {
    { 0, "Actual target report" },
    { 1, "Simulated target report" },
    { 0, NULL }
};
static const value_string valstr_062_340_06_RAB[] = {
    { 0, "Report from target transponder" },
    { 1, "Report from field monitor (fixed transponder)" },
    { 0, NULL }
};
static const value_string valstr_062_340_06_TST[] = {
    { 0, "Real target report" },
    { 1, "Test target report" },
    { 0, NULL }
};
static const FieldPart I062_340_06_TYP = { 3, 1.0, FIELD_PART_UINT, &hf_062_340_06_TYP, NULL };
static const FieldPart I062_340_06_SIM = { 1, 1.0, FIELD_PART_UINT, &hf_062_340_06_SIM, NULL };
static const FieldPart I062_340_06_RAB = { 1, 1.0, FIELD_PART_UINT, &hf_062_340_06_RAB, NULL };
static const FieldPart I062_340_06_TST = { 1, 1.0, FIELD_PART_UINT, &hf_062_340_06_TST, NULL };
static const FieldPart *I062_340_06_PARTS[] = { &I062_340_06_TYP, &I062_340_06_SIM, &I062_340_06_RAB, &I062_340_06_TST, NULL };

/* Aircraft Derived Data */
/* Magnetic Heading */
static const FieldPart I062_380_03_MH = { 16, 360.0/65536.0, FIELD_PART_UFLOAT, &hf_062_380_03_MH, NULL };
static const FieldPart *I062_380_03_PARTS[] = { &I062_380_03_MH, NULL };

/* Indicated Airspeed/Mach Number */
/* The scaling factor of this field depends on IM field */
/* Various scaling factors not supported. */
/* Since field not used for compatibility purposes, it is OK. */
static const FieldPart I062_380_04_IM = { 1, 1.0, FIELD_PART_UINT, &hf_062_380_04_IM, NULL };
static const FieldPart I062_380_04_IAS = { 15, 1.0, FIELD_PART_UFLOAT, &hf_062_380_04_IAS, NULL };
static const FieldPart *I062_380_04_PARTS[] = { &I062_380_04_IM, &I062_380_04_IAS, NULL };

/* v.0.17 */
/* Communications / ACAS Capability and Flight Status */
static const value_string valstr_062_380_04_COM[] = {
    { 0, "No communications capability (surveillance only)" },
    { 1, "Comm. A and Comm. B capability" },
    { 2, "Comm. A, Comm. B and Uplink ELM" },
    { 3, "Comm. A, Comm. B, Uplink ELM and Downlink ELM" },
    { 4, "Level 5 Transponder capability" },
    { 0, NULL }
};
static const value_string valstr_062_380_04_STAT[] = {
    { 0, "No alert, no SPI, aircraft airborne" },
    { 1, "No alert, no SPI, aircraft on ground" },
    { 2, "Alert, no SPI, aircraft airborne" },
    { 3, "Alert, no SPI, aircraft on ground" },
    { 4, "Alert, SPI, aircraft airborne or on ground" },
    { 5, "No alert, SPI, aircraft airborne or on ground" },
    { 0, NULL }
};
static const value_string valstr_062_380_04_SSC[] = {
    { 0, "No" },
    { 1, "Yes" },
    { 0, NULL }
};
static const value_string valstr_062_380_04_ARC[] = {
    { 0, "100 ft resolution" },
    { 1, "25 ft resolution" },
    { 0, NULL }
};
static const value_string valstr_062_380_04_AIC[] = {
    { 0, "No" },
    { 1, "Yes" },
    { 0, NULL }
};
static const FieldPart I062_380_04_COM = { 3, 1.0, FIELD_PART_UINT, &hf_062_380_04_COM, NULL };
static const FieldPart I062_380_04_STAT = { 3, 1.0, FIELD_PART_UINT, &hf_062_380_04_STAT, NULL };
static const FieldPart I062_380_04_SSC = { 1, 1.0, FIELD_PART_UINT, &hf_062_380_04_SSC, NULL };
static const FieldPart I062_380_04_ARC = { 1, 1.0, FIELD_PART_UINT, &hf_062_380_04_ARC, NULL };
static const FieldPart I062_380_04_AIC = { 1, 1.0, FIELD_PART_UINT, &hf_062_380_04_AIC, NULL };
static const FieldPart I062_380_04_B1A = { 1, 1.0, FIELD_PART_UINT, &hf_062_380_04_B1A, NULL };
static const FieldPart I062_380_04_B1B = { 4, 1.0, FIELD_PART_UINT, &hf_062_380_04_B1B, NULL };
static const FieldPart *I062_380_04_PARTS_v0_17[] = { &I062_380_04_COM, &I062_380_04_STAT, &IXXX_2bit_spare, &I062_380_04_SSC, &I062_380_04_ARC, &I062_380_04_AIC, &I062_380_04_B1A, &I062_380_04_B1B, NULL };

/* True Airspeed */
static const FieldPart I062_380_05_TAS = { 16, 1.0, FIELD_PART_UFLOAT, &hf_062_380_05_TAS, NULL };
static const FieldPart *I062_380_05_PARTS[] = { &I062_380_05_TAS, NULL };

/* v.0.17 */
/* ACAS Resolution Advisory Report */
static const FieldPart I062_380_05_MB = { 56, 1.0, FIELD_PART_UINT, &hf_062_380_05_MB, NULL };
static const FieldPart *I062_380_05_PARTS_v0_17[] = { &I062_380_05_MB, NULL };

/* Selected Altitude */
static const value_string valstr_062_380_06_SAS[] = {
    { 0, "No source information provided" },
    { 1, "Source Information provided" },
    { 0, NULL }
};
static const value_string valstr_062_380_06_SOURCE[] = {
    { 0, "Unknown" },
    { 1, "Aircraft Altitude" },
    { 2, "FCU/MCP Selected Altitude" },
    { 3, "FMS Selected Altitude" },
    { 0, NULL }
};
static const FieldPart I062_380_06_SAS = { 1, 1.0, FIELD_PART_UINT, &hf_062_380_06_SAS, NULL };
static const FieldPart I062_380_06_SOURCE = { 2, 1.0, FIELD_PART_UINT, &hf_062_380_06_SOURCE, NULL };
static const FieldPart I062_380_06_ALT = { 13, 25.0, FIELD_PART_UFLOAT, &hf_062_380_06_ALT, NULL };
static const FieldPart *I062_380_06_PARTS[] = { &I062_380_06_SAS, &I062_380_06_SOURCE, &I062_380_06_ALT, NULL };

/* Final State Selected Altitude */
static const value_string valstr_062_380_07[] = {
    { 0, "Not active" },
    { 1, "Active" },
    { 0, NULL }
};
static const FieldPart I062_380_07_MV = { 1, 1.0, FIELD_PART_UINT, &hf_062_380_07_MV, NULL };
static const FieldPart I062_380_07_AH = { 1, 1.0, FIELD_PART_UINT, &hf_062_380_07_AH, NULL };
static const FieldPart I062_380_07_AM = { 1, 1.0, FIELD_PART_UINT, &hf_062_380_07_AM, NULL };
static const FieldPart I062_380_07_ALT = { 13, 25.0, FIELD_PART_UFLOAT, &hf_062_380_07_ALT, NULL };
static const FieldPart *I062_380_07_PARTS[] = { &I062_380_07_MV, &I062_380_07_AH, &I062_380_07_AM, &I062_380_07_ALT, NULL };

/* Trajectory Intent Status */
static const value_string valstr_062_380_08_NAV[] = {
    { 0, "Trajectory Intent Data is available for this aircraft" },
    { 1, "Trajectory Intent Data is not available for this aircraft" },
    { 0, NULL }
};
static const value_string valstr_062_380_08_NVB[] = {
    { 0, "Trajectory Intent Data is valid" },
    { 1, "Trajectory Intent Data is not valid" },
    { 0, NULL }
};
static const FieldPart I062_380_08_NAV = { 1, 1.0, FIELD_PART_UINT, &hf_062_380_08_NAV, NULL };
static const FieldPart I062_380_08_NVB = { 1, 1.0, FIELD_PART_UINT, &hf_062_380_08_NVB, NULL };
static const FieldPart *I062_380_08_PARTS[] = { &I062_380_08_NAV, &I062_380_08_NVB, &IXXX_5bit_spare, &IXXX_FX, NULL };

/* Trajectory Intent Data */
static const value_string valstr_062_380_09_TCA[] = {
    { 0, "TCP number available" },
    { 1, "TCP number not available" },
    { 0, NULL }
};
static const value_string valstr_062_380_09_NC[] = {
    { 0, "TCP compliance" },
    { 1, "TCP non-compliance" },
    { 0, NULL }
};
static const value_string valstr_062_380_09_PTYP[] = {
    {  0, "Unknown" },
    {  1, "Fly by waypoint " },
    {  2, "Fly over waypoint" },
    {  3, "Hold Pattern" },
    {  4, "Procedure hold" },
    {  5, "Procedure turn" },
    {  6, "RF leg" },
    {  7, "Top of climb" },
    {  8, "Top of descend"},
    {  9, "Start of level" },
    { 10, "Cross-over altitude" },
    { 11, "Transition altitude" },
    { 0, NULL }
};
static const value_string valstr_062_380_09_TD[] = {
    { 0, "N/A" },
    { 1, "Turn right" },
    { 2, "Turn left" },
    { 3, "No turn" },
    { 0, NULL }
};
static const value_string valstr_062_380_09_TRA[] = {
    { 0, "TTR not available" },
    { 1, "TTR available" },
    { 0, NULL }
};
static const value_string valstr_062_380_09_TOA[] = {
    { 0, "TOV available" },
    { 1, "TOV not available" },
    { 0, NULL }
};
static const FieldPart I062_380_09_TCA = { 1, 1.0, FIELD_PART_UINT, &hf_062_380_09_TCA, NULL };
static const FieldPart I062_380_09_NC = { 1, 1.0, FIELD_PART_UINT, &hf_062_380_09_NC, NULL };
static const FieldPart I062_380_09_TCP = { 6, 1.0, FIELD_PART_UINT, &hf_062_380_09_TCP, NULL };
static const FieldPart I062_380_09_ALT = { 16, 10.0, FIELD_PART_FLOAT, &hf_062_380_09_ALT, NULL };
static const FieldPart I062_380_09_LAT = { 24, 180.0/8388608.0, FIELD_PART_FLOAT, &hf_062_380_09_LAT, NULL };
static const FieldPart I062_380_09_LON = { 24, 180.0/8388608.0, FIELD_PART_FLOAT, &hf_062_380_09_LON, NULL };
static const FieldPart I062_380_09_PTYP = { 4, 1.0, FIELD_PART_UINT, &hf_062_380_09_PTYP, NULL };
static const FieldPart I062_380_09_TD = { 1, 1.0, FIELD_PART_UINT, &hf_062_380_09_TD, NULL };
static const FieldPart I062_380_09_TRA = { 1, 1.0, FIELD_PART_UINT, &hf_062_380_09_TRA, NULL };
static const FieldPart I062_380_09_TOA = { 1, 1.0, FIELD_PART_UINT, &hf_062_380_09_TOA, NULL };
static const FieldPart I062_380_09_TOV = { 24, 1.0, FIELD_PART_UFLOAT, &hf_062_380_09_TOV, NULL };
static const FieldPart I062_380_09_TTR = { 16, 0.01, FIELD_PART_UINT, &hf_062_380_09_TTR, NULL };
static const FieldPart *I062_380_09_PARTS[] = { &I062_380_09_TCA, &I062_380_09_NC, &I062_380_09_TCP, &I062_380_09_ALT, &I062_380_09_LAT, &I062_380_09_LON,
                                                 &I062_380_09_PTYP, &I062_380_09_TD, &I062_380_09_TRA, &I062_380_09_TOA, &I062_380_09_TOV, &I062_380_09_TTR, NULL };

/* Communications / ACAS Capability and Flight Status */
static const value_string valstr_062_380_10_COM[] = {
    { 0, "No communications capability (surveillance only)" },
    { 1, "Comm. A and Comm. B capability" },
    { 2, "Comm. A, Comm. B and Uplink ELM" },
    { 3, "Comm. A, Comm. B, Uplink ELM and Downlink ELM" },
    { 4, "Level 5 Transponder capability" },
    { 0, NULL }
};
static const value_string valstr_062_380_10_STAT[] = {
    { 0, "No alert, no SPI, aircraft airborne" },
    { 1, "No alert, no SPI, aircraft on ground" },
    { 2, "Alert, no SPI, aircraft airborne" },
    { 3, "Alert, no SPI, aircraft on ground" },
    { 4, "Alert, SPI, aircraft airborne or on ground" },
    { 5, "No alert, SPI, aircraft airborne or on ground" },
    { 0, NULL }
};
static const value_string valstr_062_380_10_SSC[] = {
    { 0, "No" },
    { 1, "Yes" },
    { 0, NULL }
};
static const value_string valstr_062_380_10_ARC[] = {
    { 0, "100 ft resolution" },
    { 1, "25 ft resolution" },
    { 0, NULL }
};
static const value_string valstr_062_380_10_AIC[] = {
    { 0, "No" },
    { 1, "Yes" },
    { 0, NULL }
};
static const FieldPart I062_380_10_COM = { 3, 1.0, FIELD_PART_UINT, &hf_062_380_10_COM, NULL };
static const FieldPart I062_380_10_STAT = { 3, 1.0, FIELD_PART_UINT, &hf_062_380_10_STAT, NULL };
static const FieldPart I062_380_10_SSC = { 1, 1.0, FIELD_PART_UINT, &hf_062_380_10_SSC, NULL };
static const FieldPart I062_380_10_ARC = { 1, 1.0, FIELD_PART_UINT, &hf_062_380_10_ARC, NULL };
static const FieldPart I062_380_10_AIC = { 1, 1.0, FIELD_PART_UINT, &hf_062_380_10_AIC, NULL };
static const FieldPart I062_380_10_B1A = { 1, 1.0, FIELD_PART_UINT, &hf_062_380_10_B1A, NULL };
static const FieldPart I062_380_10_B1B = { 4, 1.0, FIELD_PART_UINT, &hf_062_380_10_B1B, NULL };
static const FieldPart *I062_380_10_PARTS[] = { &I062_380_10_COM, &I062_380_10_STAT, &IXXX_2bit_spare, &I062_380_10_SSC, &I062_380_10_ARC, &I062_380_10_AIC, &I062_380_10_B1A, &I062_380_10_B1B, NULL };

/* Status reported by ADS-B */
static const value_string valstr_062_380_11_AC[] = {
    { 0, "unknown" },
    { 1, "ACAS not operational" },
    { 2, "ACAS operational" },
    { 3, "invalid" },
    { 0, NULL }
};
static const value_string valstr_062_380_11_MN[] = {
    { 0, "unknown" },
    { 1, "Multiple navigational aids not operating" },
    { 2, "Multiple navigational aids operating" },
    { 3, "invalid" },
    { 0, NULL }
};
static const value_string valstr_062_380_11_DC[] = {
    { 0, "unknown" },
    { 1, "Differential correction" },
    { 2, "No differential correction" },
    { 3, "invalid" },
    { 0, NULL }
};
static const value_string valstr_062_380_11_GBS[] = {
    { 0, "Transponder Ground Bit not set or unknown" },
    { 1, "Transponder Ground Bit set" },
    { 0, NULL }
};
static const value_string valstr_062_380_11_STAT[] = {
    { 0, "No emergency" },
    { 1, "General emergency" },
    { 2, "Lifeguard / medical" },
    { 3, "Minimum fuel" },
    { 4, "No communications" },
    { 5, "Unlawful interference" },
    { 6, "\"Downed\" Aircraft" },
    { 7, "Unknown" },
    { 0, NULL }
};
static const FieldPart I062_380_11_AC = { 2, 1.0, FIELD_PART_UINT, &hf_062_380_11_AC, NULL };
static const FieldPart I062_380_11_MN = { 2, 1.0, FIELD_PART_UINT, &hf_062_380_11_MN, NULL };
static const FieldPart I062_380_11_DC = { 2, 1.0, FIELD_PART_UINT, &hf_062_380_11_DC, NULL };
static const FieldPart I062_380_11_GBS = { 1, 1.0, FIELD_PART_UINT, &hf_062_380_11_GBS, NULL };
static const FieldPart I062_380_11_STAT = { 3, 1.0, FIELD_PART_UINT, &hf_062_380_11_STAT, NULL };
static const FieldPart *I062_380_11_PARTS[] = { &I062_380_11_AC, &I062_380_11_MN, &I062_380_11_DC, &I062_380_11_GBS, &IXXX_6bit_spare, &I062_380_11_STAT, NULL };

/* ACAS Resolution Advisory Report */
static const FieldPart I062_380_12_MB = { 56, 1.0, FIELD_PART_UINT, &hf_062_380_12_MB, NULL };
static const FieldPart *I062_380_12_PARTS[] = { &I062_380_12_MB, NULL };

/* Barometric Vertical Rate */
static const FieldPart I062_380_13_BVR = { 16, 6.25, FIELD_PART_FLOAT, &hf_062_380_13_BVR, NULL };
static const FieldPart *I062_380_13_PARTS[] = { &I062_380_13_BVR, NULL };

/* Geometric Vertical Rate */
static const FieldPart I062_380_14_GVR = { 16, 6.25, FIELD_PART_FLOAT, &hf_062_380_14_GVR, NULL };
static const FieldPart *I062_380_14_PARTS[] = { &I062_380_14_GVR, NULL };

/* Roll Angle */
static const FieldPart I062_380_15_ROLL = { 16, 0.01, FIELD_PART_FLOAT, &hf_062_380_15_ROLL, NULL };
static const FieldPart *I062_380_15_PARTS[] = { &I062_380_15_ROLL, NULL };

/* Track Angle Rate */
static const value_string valstr_062_380_16_TI[] = {
    { 0, "Not available" },
    { 1, "Left" },
    { 2, "Right" },
    { 3, "Straight" },
    { 0, NULL }
};
static const FieldPart I062_380_16_TI = { 2, 1.0, FIELD_PART_UINT, &hf_062_380_16_TI, NULL };
static const FieldPart I062_380_16_RATE = { 7, 1.0/4.0, FIELD_PART_FLOAT, &hf_062_380_16_RATE, NULL };
static const FieldPart *I062_380_16_PARTS[] = { &I062_380_16_TI, &IXXX_6bit_spare, &I062_380_16_RATE, NULL };

/* Track Angle */
static const FieldPart I062_380_17_TA = { 16, 360.0/65536.0, FIELD_PART_FLOAT, &hf_062_380_17_TA, NULL };
static const FieldPart *I062_380_17_PARTS[] = { &I062_380_17_TA, NULL };

/* Ground Speed */
static const FieldPart I062_380_18_GS = { 16, 1.0/16384.0, FIELD_PART_FLOAT, &hf_062_380_18_GS, NULL };
static const FieldPart *I062_380_18_PARTS[] = { &I062_380_18_GS, NULL };

/* Velocity Uncertainty */
static const FieldPart I062_380_19_VUC = { 16, 1.0, FIELD_PART_UINT, &hf_062_380_19_VUC, NULL };
static const FieldPart *I062_380_19_PARTS[] = { &I062_380_19_VUC, NULL };

/* Meteorological Data */
static const value_string valstr_062_380_20_WS[] = {
    { 0, "Not valid Wind Speed" },
    { 1, "Valid Wind Speed" },
    { 0, NULL }
};
static const value_string valstr_062_380_20_WD[] = {
    { 0, "Not valid Wind Direction" },
    { 1, "Valid Wind Direction" },
    { 0, NULL }
};
static const value_string valstr_062_380_20_TMP[] = {
    { 0, "Not valid Temperature" },
    { 1, "Valid Temperature" },
    { 0, NULL }
};
static const value_string valstr_062_380_20_TRB[] = {
    { 0, "Not valid Turbulence" },
    { 1, "Valid Turbulence" },
    { 0, NULL }
};
static const FieldPart I062_380_20_WS = { 1, 1.0, FIELD_PART_UINT, &hf_062_380_20_WS, NULL };
static const FieldPart I062_380_20_WD = { 1, 1.0, FIELD_PART_UINT, &hf_062_380_20_WD, NULL };
static const FieldPart I062_380_20_TMP = { 1, 1.0, FIELD_PART_UINT, &hf_062_380_20_TMP, NULL };
static const FieldPart I062_380_20_TRB = { 1, 1.0, FIELD_PART_UINT, &hf_062_380_20_TRB, NULL };
static const FieldPart I062_380_20_WS_VAL = { 16, 1.0, FIELD_PART_UFLOAT, &hf_062_380_20_WS_VAL, NULL };
static const FieldPart I062_380_20_WD_VAL = { 16, 1.0, FIELD_PART_UFLOAT, &hf_062_380_20_WD_VAL, NULL };
static const FieldPart I062_380_20_TMP_VAL = { 16, 1.0/4.0, FIELD_PART_FLOAT, &hf_062_380_20_TMP_VAL, NULL };
static const FieldPart I062_380_20_TRB_VAL = { 8, 1.0, FIELD_PART_UINT, &hf_062_380_20_TRB_VAL, NULL };
static const FieldPart *I062_380_20_PARTS[] = { &I062_380_20_WS, &I062_380_20_WD, &I062_380_20_TMP, &I062_380_20_TRB, &IXXX_4bit_spare,
                                                 &I062_380_20_WS_VAL, &I062_380_20_WD_VAL, &I062_380_20_TMP_VAL, &I062_380_20_TRB_VAL, NULL };

/* Emitter Category */
static const value_string valstr_062_380_21_ECAT[] = {
    {  1, "light aircraft <= 7000 kg" },
    {  2, "reserved" },
    {  3, "7000 kg < medium aircraft < 136000 kg" },
    {  4, "reserved" },
    {  5, "136000 kg <= heavy aircraft" },
    {  6, "highly manoeuvrable (5g acceleration capability) and high speed (>400 knots cruise)" },
    {  7, "reserved" },
    {  8, "reserved" },
    {  9, "reserved" },
    { 10, "rotocraft" },
    { 11, "glider / sailplane" },
    { 12, "lighter-than-air" },
    { 13, "unmanned aerial vehicle" },
    { 14, "space / transatmospheric vehicle" },
    { 15, "ultralight / handglider / paraglider" },
    { 16, "parachutist / skydiver" },
    { 17, "reserved" },
    { 18, "reserved" },
    { 19, "reserved" },
    { 20, "surface emergency vehicle" },
    { 21, "surface service vehicle" },
    { 22, "fixed ground or tethered obstruction" },
    { 23, "reserved" },
    { 24, "reserved" },
    { 0, NULL }
};
static const FieldPart I062_380_21_ECAT = { 8, 1.0, FIELD_PART_UINT, &hf_062_380_21_ECAT, NULL };
static const FieldPart *I062_380_21_PARTS[] = { &I062_380_21_ECAT, NULL };

/* Position Data */
static const FieldPart I062_380_22_LAT = { 24, 180.0/8388608.0, FIELD_PART_FLOAT, &hf_062_380_22_LAT, NULL };
static const FieldPart I062_380_22_LON = { 24, 180.0/8388608.0, FIELD_PART_FLOAT, &hf_062_380_22_LON, NULL };
static const FieldPart *I062_380_22_PARTS[] = { &I062_380_22_LAT, &I062_380_22_LON, NULL };

/* Geometric Altitude Data */
static const FieldPart I062_380_23_ALT = { 16, 6.25, FIELD_PART_FLOAT, &hf_062_380_23_ALT, NULL };
static const FieldPart *I062_380_23_PARTS[] = { &I062_380_23_ALT, NULL };

/* Position Uncertainty Data */
static const FieldPart I062_380_24_PUN = { 4, 1.0, FIELD_PART_UINT, &hf_062_380_24_PUN, NULL };
static const FieldPart *I062_380_24_PARTS[] = { &IXXX_4bit_spare, &I062_380_24_PUN, NULL };

/* Indicated Airspeed */
static const FieldPart I062_380_26_IAS = { 16, 1.0, FIELD_PART_UFLOAT, &hf_062_380_26_IAS, NULL };
static const FieldPart *I062_380_26_PARTS[] = { &I062_380_26_IAS, NULL };

/* Mach Number */
static const FieldPart I062_380_27_MACH = { 16, 0.008, FIELD_PART_UFLOAT, &hf_062_380_27_MACH, NULL };
static const FieldPart *I062_380_27_PARTS[] = { &I062_380_27_MACH, NULL };

/* Barometric Pressure Setting */
static const FieldPart I062_380_28_BPS = { 12, 0.1, FIELD_PART_UFLOAT, &hf_062_380_28_BPS, NULL };
static const FieldPart *I062_380_28_PARTS[] = { &IXXX_4bit_spare, &I062_380_28_BPS, NULL };

/* Flight Plan Related Data */
/* Callsign */
static const FieldPart I062_390_02_CS = { 56, 1.0, FIELD_PART_ASCII, &hf_062_390_02_CS, NULL };
static const FieldPart *I062_390_02_PARTS[] = { &I062_390_02_CS, NULL };

/* IFPS_FLIGHT_ID */
static const value_string valstr_062_390_03_TYP[] = {
    { 0, "Plan Number" },
    { 1, "Unit 1 internal flight number" },
    { 2, "Unit 2 internal flight number" },
    { 3, "Unit 3 internal flight number" },
    { 0, NULL }
};
static const FieldPart I062_390_03_TYP = { 2, 1.0, FIELD_PART_UINT, &hf_062_390_03_TYP, NULL };
static const FieldPart I062_390_03_NBR = { 27, 1.0, FIELD_PART_UINT, &hf_062_390_03_NBR, NULL };
static const FieldPart *I062_390_03_PARTS[] = { &I062_390_03_TYP, &IXXX_3bit_spare, &I062_390_03_NBR, NULL };

/* Flight Category */
static const value_string valstr_062_390_04_GAT_OAT[] = {
    { 0, "Unknown" },
    { 1, "General Air Traffic" },
    { 2, "Operational Air Traffic" },
    { 3, "Not applicable" },
    { 0, NULL }
};
static const value_string valstr_062_390_04_FR12[] = {
    { 0, "Instrument Flight Rules" },
    { 1, "Visual Flight rules" },
    { 2, "Not applicable" },
    { 3, "Controlled Visual Flight Rules" },
    { 0, NULL }
};
static const value_string valstr_062_390_04_RVSM[] = {
    { 0, "Unknown" },
    { 1, "Approved" },
    { 2, "Exempt" },
    { 3, "Not Approved" },
    { 0, NULL }
};
static const value_string valstr_062_390_04_HPR[] = {
    { 0, "Normal Priority Flight" },
    { 1, "High Priority Flight" },
    { 0, NULL }
};
static const FieldPart I062_390_04_GAT_OAT = { 2, 1.0, FIELD_PART_UINT, &hf_062_390_04_GAT_OAT, NULL };
static const FieldPart I062_390_04_FR12 = { 2, 1.0, FIELD_PART_UINT, &hf_062_390_04_FR12, NULL };
static const FieldPart I062_390_04_RVSM = { 2, 1.0, FIELD_PART_UINT, &hf_062_390_04_RVSM, NULL };
static const FieldPart I062_390_04_HPR = { 1, 1.0, FIELD_PART_UINT, &hf_062_390_04_HPR, NULL };
static const FieldPart *I062_390_04_PARTS[] = { &I062_390_04_GAT_OAT, &I062_390_04_FR12, &I062_390_04_RVSM, &I062_390_04_HPR, NULL };

/* Type of Aircraft */
static const FieldPart I062_390_05_ACTYP = { 32, 1.0, FIELD_PART_ASCII, &hf_062_390_05_ACTYP, NULL };
static const FieldPart *I062_390_05_PARTS[] = { &I062_390_05_ACTYP, NULL };

/* Wake Turbulence Category */
static const FieldPart I062_390_06_WTC = { 8, 1.0, FIELD_PART_ASCII, &hf_062_390_06_WTC, NULL };
static const FieldPart *I062_390_06_PARTS[] = { &I062_390_06_WTC, NULL };

/* Departure Airport */
static const FieldPart I062_390_07_ADEP = { 32, 1.0, FIELD_PART_ASCII, &hf_062_390_07_ADEP, NULL };
static const FieldPart *I062_390_07_PARTS[] = { &I062_390_07_ADEP, NULL };

/* Destination Airport */
static const FieldPart I062_390_08_ADES = { 32, 1.0, FIELD_PART_ASCII, &hf_062_390_08_ADES, NULL };
static const FieldPart *I062_390_08_PARTS[] = { &I062_390_08_ADES, NULL };

/* Runway Designation */
static const FieldPart I062_390_09_NU1 = { 8, 1.0, FIELD_PART_ASCII, &hf_062_390_09_NU1, NULL };
static const FieldPart I062_390_09_NU2 = { 8, 1.0, FIELD_PART_ASCII, &hf_062_390_09_NU2, NULL };
static const FieldPart I062_390_09_LTR = { 8, 1.0, FIELD_PART_ASCII, &hf_062_390_09_LTR, NULL };
static const FieldPart *I062_390_09_PARTS[] = { &I062_390_09_NU1, &I062_390_09_NU2, &I062_390_09_LTR, NULL };

/* Current Cleared Flight Level */
static const FieldPart I062_390_10_CFL = { 16, 1.0/4.0, FIELD_PART_UFLOAT, &hf_062_390_10_CFL, NULL };
static const FieldPart *I062_390_10_PARTS[] = { &I062_390_10_CFL, NULL };

/* Current Control Position */
static const FieldPart I062_390_11_CNTR = { 8, 1.0, FIELD_PART_UINT, &hf_062_390_11_CNTR, NULL };
static const FieldPart I062_390_11_POS = { 8, 1.0, FIELD_PART_UINT, &hf_062_390_11_POS, NULL };
static const FieldPart *I062_390_11_PARTS[] = { &I062_390_11_CNTR, &I062_390_11_POS, NULL };

/* Time of Departure / Arrival */
static const value_string valstr_062_390_12_TYP[] = {
    {  0, "Scheduled off-block time" },
    {  1, "Estimated off-block time" },
    {  2, "Estimated take-off time" },
    {  3, "Actual off-block time" },
    {  4, "Predicted time at runway hold" },
    {  5, "Actual time at runway hold" },
    {  6, "Actual line-up time" },
    {  7, "Actual take-off time" },
    {  8, "Estimated time of arrival" },
    {  9, "Predicted landing time" },
    { 10, "Actual landing time" },
    { 11, "Actual time off runway" },
    { 12, "Predicted time to gate" },
    { 13, "Actual on-block time" },
    { 0, NULL }
};
static const value_string valstr_062_390_12_DAY[] = {
    { 00, "Today" },
    { 01, "Yesterday" },
    { 10, "Tomorrow" },
    { 11, "Invalid" },
    { 0, NULL }
};
static const value_string valstr_062_390_12_AVS[] = {
    { 0, "Seconds available" },
    { 1, "Seconds not available" },
    { 0, NULL }
};
static const FieldPart I062_390_12_TYP = { 5, 1.0, FIELD_PART_UINT, &hf_062_390_12_TYP, NULL };
static const FieldPart I062_390_12_DAY = { 2, 1.0, FIELD_PART_UINT, &hf_062_390_12_DAY, NULL };
static const FieldPart I062_390_12_HOR = { 5, 1.0, FIELD_PART_UINT, &hf_062_390_12_HOR, NULL };
static const FieldPart I062_390_12_MIN = { 6, 1.0, FIELD_PART_UINT, &hf_062_390_12_MIN, NULL };
static const FieldPart I062_390_12_AVS = { 1, 1.0, FIELD_PART_UINT, &hf_062_390_12_AVS, NULL };
static const FieldPart I062_390_12_SEC = { 6, 1.0, FIELD_PART_UINT, &hf_062_390_12_SEC, NULL };
static const FieldPart *I062_390_12_PARTS[] = { &I062_390_12_TYP, &I062_390_12_DAY,
                                                &IXXX_4bit_spare, &I062_390_12_HOR,
                                                &IXXX_2bit_spare, &I062_390_12_MIN,
                                                &I062_390_12_AVS, &IXXX_1bit_spare, &I062_390_12_SEC, NULL };

/* Aircraft Stand */
static const FieldPart I062_390_13_STAND = { 48, 1.0, FIELD_PART_ASCII, &hf_062_390_13_STAND, NULL };
static const FieldPart *I062_390_13_PARTS[] = { &I062_390_13_STAND, NULL };

/* Stand Status */
static const value_string valstr_062_390_14_EMP[] = {
    { 0, "Empty" },
    { 1, "Occupied" },
    { 2, "Unknown" },
    { 3, "Invalid" },
    { 0, NULL }
};
static const value_string valstr_062_390_14_AVL[] = {
    { 0, "Available" },
    { 1, "Not available" },
    { 2, "Unknown" },
    { 3, "Invalid" },
    { 0, NULL }
};
static const FieldPart I062_390_14_EMP = { 1, 1.0, FIELD_PART_UINT, &hf_062_390_14_EMP, NULL };
static const FieldPart I062_390_14_AVL = { 6, 1.0, FIELD_PART_UINT, &hf_062_390_14_AVL, NULL };
static const FieldPart *I062_390_14_PARTS[] = { &I062_390_14_EMP, &I062_390_14_AVL, NULL };

/* Standard Instrument Departure */
static const FieldPart I062_390_15_SID = { 56, 1.0, FIELD_PART_ASCII, &hf_062_390_15_SID, NULL };
static const FieldPart *I062_390_15_PARTS[] = { &I062_390_15_SID, NULL };

/* Standard Instrument Arrival */
static const FieldPart I062_390_16_STAR = { 56, 1.0, FIELD_PART_ASCII, &hf_062_390_16_STAR, NULL };
static const FieldPart *I062_390_16_PARTS[] = { &I062_390_16_STAR, NULL };

/* Pre-Emergency Mode 3/A */
static const value_string valstr_062_390_17_VA[] = {
    { 0, "No valid Mode 3/A available" },
    { 1, "Valid Mode 3/A available" },
    { 0, NULL }
};
static const FieldPart I062_390_17_VA = { 1, 1.0, FIELD_PART_UINT, &hf_062_390_17_VA, NULL };
static const FieldPart I062_390_17_SQUAWK = { 12, 1.0, FIELD_PART_SQUAWK, &hf_062_390_17_SQUAWK, NULL };
static const FieldPart *I062_390_17_PARTS[] = { &IXXX_3bit_spare, &I062_390_17_VA, &I062_390_17_SQUAWK, NULL };

/* Pre-Emergency Callsign */
static const FieldPart I062_390_18_CS = { 56, 1.0, FIELD_PART_ASCII, &hf_062_390_18_CS, NULL };
static const FieldPart *I062_390_18_PARTS[] = { &I062_390_18_CS, NULL };

/* Estimated Accuracies */
/* Estimated Accuracy Of Track Position (Cartesian) */
static const FieldPart I062_500_01_APCX = { 16, 0.5, FIELD_PART_UFLOAT, &hf_062_500_01_APCX, NULL };
static const FieldPart I062_500_01_APCY = { 16, 0.5, FIELD_PART_UFLOAT, &hf_062_500_01_APCY, NULL };
static const FieldPart *I062_500_01_PARTS[] = { &I062_500_01_APCX, &I062_500_01_APCY, NULL };
/* v.0.17 */
static const FieldPart I062_500_01_APCX_8bit = { 8, 1.0/64.0, FIELD_PART_UFLOAT, &hf_062_500_01_APCX_8bit, NULL };
static const FieldPart I062_500_01_APCY_8bit = { 8, 1.0/64.0, FIELD_PART_UFLOAT, &hf_062_500_01_APCY_8bit, NULL };
static const FieldPart *I062_500_01_PARTS_v0_17[] = { &I062_500_01_APCX_8bit, &I062_500_01_APCY_8bit, NULL };

/* XY covariance component */
static const FieldPart I062_500_02_COV = { 16, 0.5, FIELD_PART_FLOAT, &hf_062_500_02_COV, NULL };
static const FieldPart *I062_500_02_PARTS[] = { &I062_500_02_COV, NULL };
/* v.0.17 */
/* Estimated Accuracy Of Track Position (WGS-84) */
static const FieldPart I062_500_02_APWLAT = { 16, 180.0/8388608.0, FIELD_PART_FLOAT, &hf_062_500_02_APWLAT, NULL };
static const FieldPart I062_500_02_APWLON = { 16, 180.0/8388608.0, FIELD_PART_FLOAT, &hf_062_500_02_APWLON, NULL };
static const FieldPart *I062_500_02_PARTS_v0_17[] = { &I062_500_02_APWLAT, &I062_500_02_APWLON, NULL };

/* Estimated Accuracy Of Track Position (WGS-84) */
static const FieldPart I062_500_03_APWLAT = { 16, 180.0/33554432.0, FIELD_PART_FLOAT, &hf_062_500_03_APWLAT, NULL };
static const FieldPart I062_500_03_APWLON = { 16, 180.0/33554432.0, FIELD_PART_FLOAT, &hf_062_500_03_APWLON, NULL };
static const FieldPart *I062_500_03_PARTS[] = { &I062_500_03_APWLAT, &I062_500_03_APWLON, NULL };
/* v.0.17 */
/* Estimated Accuracy Of Calculated Track Altitude */
static const FieldPart I062_500_03_ATA = { 16, 6.25, FIELD_PART_UFLOAT, &hf_062_500_03_ATA, NULL };
static const FieldPart *I062_500_03_PARTS_v0_17[] = { &I062_500_03_ATA, NULL };

/* Estimated Accuracy Of Calculated Track Geometric Altitude */
static const FieldPart I062_500_04_AGA = { 8, 6.25, FIELD_PART_UFLOAT, &hf_062_500_04_AGA, NULL };
static const FieldPart *I062_500_04_PARTS[] = { &I062_500_04_AGA, NULL };
/* v.0.17 */
/* Estimated Accuracy Of Calculated Track Geometric Altitude */
static const FieldPart I062_500_04_ATF = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_500_04_ATF, NULL };
static const FieldPart *I062_500_04_PARTS_v0_17[] = { &I062_500_04_ATF, NULL };

/* Estimated Accuracy Of Calculated Track Barometric Altitude */
static const FieldPart I062_500_05_ABA = { 8, 1.0/4.0, FIELD_PART_UFLOAT, &hf_062_500_05_ABA, NULL };
static const FieldPart *I062_500_05_PARTS[] = { &I062_500_05_ABA, NULL };
/* v.0.17 */
/* Estimated Accuracy Of Track Velocity (Polar) */
static const FieldPart I062_500_05_ATVS = { 8, 1.0/16384.0, FIELD_PART_UFLOAT, &hf_062_500_05_ATVS, NULL };
static const FieldPart I062_500_05_ATVH = { 16, 360.0/65536.0, FIELD_PART_UFLOAT, &hf_062_500_05_ATVH, NULL };
static const FieldPart *I062_500_05_PARTS_v0_17[] = { &I062_500_05_ATVS, &I062_500_05_ATVH, NULL };

/* Estimated Accuracy Of Track Velocity (Cartesian) */
static const FieldPart I062_500_06_ATVX = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_500_06_ATVX, NULL };
static const FieldPart I062_500_06_ATVY = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_500_06_ATVY, NULL };
static const FieldPart *I062_500_06_PARTS[] = { &I062_500_06_ATVX, &I062_500_06_ATVY, NULL };
/* v.0.17 */
/* Estimated Accuracy Of Rate Of Turn */
static const FieldPart I062_500_06_ART = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_500_06_ART, NULL };
static const FieldPart *I062_500_06_PARTS_v0_17[] = { &I062_500_06_ART, NULL };

/* Estimated Accuracy Of Acceleration (Cartesian) */
static const FieldPart I062_500_07_AAX = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_500_07_AAX, NULL };
static const FieldPart I062_500_07_AAY = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_500_07_AAY, NULL };
static const FieldPart *I062_500_07_PARTS[] = { &I062_500_07_AAX, &I062_500_07_AAY, NULL };
/* v.0.17 */
/* Estimated Accuracy Of Longitudinal Acceleration */
static const FieldPart I062_500_07_ALA = { 16, 1.0/4194304.0, FIELD_PART_UFLOAT, &hf_062_500_07_ALA, NULL };
static const FieldPart *I062_500_07_PARTS_v0_17[] = { &I062_500_07_ALA, NULL };

/* Estimated Accuracy Of Rate Of Climb/Descent */
static const FieldPart I062_500_08_ARC = { 8, 6.25, FIELD_PART_UFLOAT, &hf_062_500_08_ARC, NULL };
static const FieldPart *I062_500_08_PARTS[] = { &I062_500_08_ARC, NULL };

/* Composed Track Number */
static const FieldPart I062_510_SID = { 8, 1.0, FIELD_PART_UINT, &hf_062_510_SID, NULL };
static const FieldPart I062_510_STN = { 15, 1.0, FIELD_PART_UINT, &hf_062_510_STN, NULL };
static const FieldPart *I062_510_PARTS[] = { &I062_510_SID, &I062_510_STN, &IXXX_3FX, NULL };

/*Reserved Expansion*/
static const value_string valstr_062_RE_CST_TYPE[] = {
    { 0, "No Detection"},
    { 1, "Single PSR Detection"},
    { 2, "Single SSR Detection"},
    { 3, "SSR+PSR Detection"},
    { 4, "Single Mode S All-Call"},
    { 5, "Single Mode S Roll-Call"},
    { 6, "Mode S All-Call + PSR"},
    { 7, "Mode S Roll-Call + PSR"},
    { 8, "ADS-B"},
    { 9, "WAM"},
    { 0, NULL}
};

static const value_string valstr_062_RE_STS_FDR[] = {
    { 0, "Flight Plan Data From Active FDPS"},
    { 1, "Flight Plan Data Retained From No Longer Active FDPS"},
    { 0, NULL}
};

/*Contributing Sensors with Local Track Numbers*/
static const FieldPart I062_RE_CST_SAC = { 8, 1.0, FIELD_PART_UINT, &hf_062_RE_CST_SAC, NULL };
static const FieldPart I062_RE_CST_SIC = { 8, 1.0, FIELD_PART_UINT, &hf_062_RE_CST_SIC, NULL };
static const FieldPart I062_RE_CST_TYPE = { 8, 1.0, FIELD_PART_UINT, &hf_062_RE_CST_TYP, NULL };
static const FieldPart I062_RE_CST_TRK_NUM = { 16, 1.0, FIELD_PART_UINT, &hf_062_RE_CST_TRK_NUM, NULL };
static const FieldPart *I062_RE_CST_PARTS[] = { &I062_RE_CST_SAC, &I062_RE_CST_SIC, &I062_RE_CST_TYPE, &I062_RE_CST_TRK_NUM, NULL };

/*Contributing Sensors with No Local Track Numbers*/
static const FieldPart I062_RE_CSNT_SAC = { 8, 1.0, FIELD_PART_UINT, &hf_062_RE_CSNT_SAC, NULL };
static const FieldPart I062_RE_CSNT_SIC = { 8, 1.0, FIELD_PART_UINT, &hf_062_RE_CSNT_SIC, NULL };
static const FieldPart I062_RE_CSNT_TYPE = { 8, 1.0, FIELD_PART_UINT, &hf_062_RE_CSNT_TYP, NULL };
static const FieldPart *I062_RE_CSNT_PARTS[] = { &I062_RE_CSNT_SAC, &I062_RE_CSNT_SIC, &I062_RE_CSNT_TYPE, NULL };

/*Calculated Track Velocity Relative to System Reference Point*/
static const FieldPart I062_RE_TVS_VX = { 16, 0.25, FIELD_PART_FLOAT, &hf_062_RE_TVS_VX, NULL };
static const FieldPart I062_RE_TVS_VY = { 16, 0.25, FIELD_PART_FLOAT, &hf_062_RE_TVS_VY, NULL };
static const FieldPart *I062_RE_TVS_PARTS[] = { &I062_RE_TVS_VX, &I062_RE_TVS_VY, NULL };

/*Supplementary Track Status*/
static const FieldPart I062_RE_STS_FDR = { 1, 1.0, FIELD_PART_UINT, &hf_062_RE_STS_FDR, NULL };
static const FieldPart *I062_RE_STS_PARTS[] = { &I062_RE_STS_FDR, NULL };


/* Items */
static const AsterixField I062_010 = { FIXED, 2, 0, 0, &hf_062_010, IXXX_SAC_SIC, { NULL } };
static const AsterixField I062_015 = { FIXED, 1, 0, 0, &hf_062_015, I062_015_PARTS, { NULL } };
static const AsterixField I062_040 = { FIXED, 2, 0, 0, &hf_062_040, IXXX_TN_16_PARTS, { NULL } };
static const AsterixField I062_060 = { FIXED, 2, 0, 0, &hf_062_060, I062_060_PARTS, { NULL } };
static const AsterixField I062_060_v0_17 = { FIXED, 2, 0, 0, &hf_062_060, I062_060_PARTS_v0_17, { NULL } };
static const AsterixField I062_070 = { FIXED, 3, 0, 0, &hf_062_070, IXXX_TOD, { NULL } };
static const AsterixField I062_080 = { FX, 1, 0, 0, &hf_062_080, I062_080_PARTS, { NULL } };
static const AsterixField I062_080_v0_17 = { FX, 1, 0, 0, &hf_062_080, I062_080_PARTS_v0_17, { NULL } };
static const AsterixField I062_100 = { FIXED, 6, 0, 0, &hf_062_100, I062_100_PARTS, { NULL } };
static const AsterixField I062_100_v0_17 = { FIXED, 4, 0, 0, &hf_062_100, I062_100_PARTS_v0_17, { NULL } };
static const AsterixField I062_105 = { FIXED, 8, 0, 0, &hf_062_105, I062_105_PARTS, { NULL } };
static const AsterixField I062_105_v0_17 = { FIXED, 6, 0, 0, &hf_062_105, I062_105_PARTS_v0_17, { NULL } };
static const AsterixField I062_110_01 = { FIXED, 1, 0, 0, &hf_062_110_01, I062_110_01_PARTS, { NULL } };
static const AsterixField I062_110_02 = { FIXED, 4, 0, 0, &hf_062_110_02, I062_110_02_PARTS, { NULL } };
static const AsterixField I062_110_03 = { FIXED, 6, 0, 0, &hf_062_110_03, I062_110_03_PARTS, { NULL } };
static const AsterixField I062_110_04 = { FIXED, 2, 0, 0, &hf_062_110_04, I062_110_04_PARTS, { NULL } };
static const AsterixField I062_110_05 = { FIXED, 2, 0, 0, &hf_062_110_05, I062_110_05_PARTS, { NULL } };
static const AsterixField I062_110_06 = { FIXED, 1, 0, 0, &hf_062_110_06, I062_110_06_PARTS, { NULL } };
static const AsterixField I062_110_07 = { FIXED, 1, 0, 0, &hf_062_110_07, I062_110_07_PARTS, { NULL } };
static const AsterixField I062_110 = { COMPOUND, 0, 0, 0, &hf_062_110, NULL, { &I062_110_01,
                                                                               &I062_110_02,
                                                                               &I062_110_03,
                                                                               &I062_110_04,
                                                                               &I062_110_05,
                                                                               &I062_110_06,
                                                                               &I062_110_07,
                                                                               NULL } };
static const AsterixField I062_110_v0_17 = { FIXED, 1, 0, 0, &hf_062_110_v0_17, I062_110_PARTS_v0_17, { NULL } };
static const AsterixField I062_120 = { FIXED, 2, 0, 0, &hf_062_120, I062_120_PARTS, { NULL } };
static const AsterixField I062_130 = { FIXED, 2, 0, 0, &hf_062_130, I062_130_PARTS, { NULL } };
static const AsterixField I062_135 = { FIXED, 2, 0, 0, &hf_062_135, I062_135_PARTS, { NULL } };
static const AsterixField I062_136 = { FIXED, 2, 0, 0, &hf_062_136, I062_136_PARTS, { NULL } };
static const AsterixField I062_180 = { FIXED, 4, 0, 0, &hf_062_180, I062_180_PARTS, { NULL } };
static const AsterixField I062_185 = { FIXED, 4, 0, 0, &hf_062_185, I062_185_PARTS, { NULL } };
static const AsterixField I062_200 = { FIXED, 1, 0, 0, &hf_062_200, I062_200_PARTS, { NULL } };
static const AsterixField I062_200_v0_17 = { FIXED, 1, 0, 0, &hf_062_200, I062_200_PARTS_v0_17, { NULL } };
static const AsterixField I062_210 = { FIXED, 2, 0, 0, &hf_062_210, I062_210_PARTS, { NULL } };
static const AsterixField I062_210_v0_17 = { FIXED, 2, 0, 0, &hf_062_210_v0_17, I062_210_PARTS_v0_17, { NULL } };
static const AsterixField I062_220 = { FIXED, 2, 0, 0, &hf_062_220, I062_220_PARTS, { NULL } };
static const AsterixField I062_240 = { FIXED, 1, 0, 0, &hf_062_240, I062_240_PARTS, { NULL } };
static const AsterixField I062_245 = { FIXED, 7, 0, 0, &hf_062_245, NULL, { NULL } };
static const AsterixField I062_270 = { FX, 1, 0, 0, &hf_062_270, I062_270_PARTS, { NULL } };
static const AsterixField I062_290_01 = { FIXED, 1, 0, 0, &hf_062_290_01, I062_290_01_PARTS, { NULL } };
static const AsterixField I062_290_02 = { FIXED, 1, 0, 0, &hf_062_290_02, I062_290_02_PARTS, { NULL } };
static const AsterixField I062_290_03 = { FIXED, 1, 0, 0, &hf_062_290_03, I062_290_03_PARTS, { NULL } };
static const AsterixField I062_290_04 = { FIXED, 1, 0, 0, &hf_062_290_04, I062_290_04_PARTS, { NULL } };
static const AsterixField I062_290_05 = { FIXED, 2, 0, 0, &hf_062_290_05, I062_290_05_PARTS, { NULL } };
static const AsterixField I062_290_06 = { FIXED, 1, 0, 0, &hf_062_290_06, I062_290_06_PARTS, { NULL } };
static const AsterixField I062_290_07 = { FIXED, 1, 0, 0, &hf_062_290_07, I062_290_07_PARTS, { NULL } };
static const AsterixField I062_290_08 = { FIXED, 1, 0, 0, &hf_062_290_08, I062_290_08_PARTS, { NULL } };
static const AsterixField I062_290_09 = { FIXED, 1, 0, 0, &hf_062_290_09, I062_290_09_PARTS, { NULL } };
static const AsterixField I062_290_10 = { FIXED, 1, 0, 0, &hf_062_290_10, I062_290_10_PARTS, { NULL } };
static const AsterixField I062_290 = { COMPOUND, 0, 0, 0, &hf_062_290, NULL, { &I062_290_01,
                                                                               &I062_290_02,
                                                                               &I062_290_03,
                                                                               &I062_290_04,
                                                                               &I062_290_05,
                                                                               &I062_290_06,
                                                                               &I062_290_07,
                                                                               &I062_290_08,
                                                                               &I062_290_09,
                                                                               &I062_290_10,
                                                                               NULL } };
static const AsterixField I062_290_01_v0_17 = { FIXED, 1, 0, 0, &hf_062_290_01_v0_17, I062_290_01_PARTS_v0_17, { NULL } };
static const AsterixField I062_290_02_v0_17 = { FIXED, 1, 0, 0, &hf_062_290_02_v0_17, I062_290_02_PARTS_v0_17, { NULL } };
static const AsterixField I062_290_03_v0_17 = { FIXED, 1, 0, 0, &hf_062_290_03_v0_17, I062_290_03_PARTS_v0_17, { NULL } };
static const AsterixField I062_290_04_v0_17 = { FIXED, 1, 0, 0, &hf_062_290_04_v0_17, I062_290_04_PARTS_v0_17, { NULL } };
static const AsterixField I062_290_05_v0_17 = { FIXED, 2, 0, 0, &hf_062_290_05_v0_17, I062_290_05_PARTS_v0_17, { NULL } };
static const AsterixField I062_290_06_v0_17 = { FIXED, 1, 0, 0, &hf_062_290_06_v0_17, I062_290_06_PARTS_v0_17, { NULL } };
static const AsterixField I062_290_07_v0_17 = { FIXED, 1, 0, 0, &hf_062_290_07_v0_17, I062_290_07_PARTS_v0_17, { NULL } };
static const AsterixField I062_290_08_v0_17 = { FIXED, 1, 0, 0, &hf_062_290_08_v0_17, I062_290_08_PARTS_v0_17, { NULL } };
static const AsterixField I062_290_09_v0_17 = { FIXED, 1, 0, 0, &hf_062_290_09_v0_17, I062_290_09_PARTS_v0_17, { NULL } };
static const AsterixField I062_290_v0_17 = { COMPOUND, 0, 0, 0, &hf_062_290, NULL, { &I062_290_01_v0_17,
                                                                                     &I062_290_02_v0_17,
                                                                                     &I062_290_03_v0_17,
                                                                                     &I062_290_04_v0_17,
                                                                                     &I062_290_05_v0_17,
                                                                                     &I062_290_06_v0_17,
                                                                                     &I062_290_07_v0_17,
                                                                                     &I062_290_08_v0_17,
                                                                                     &I062_290_09_v0_17,
                                                                                     NULL } };
static const AsterixField I062_295_01 = { FIXED, 1, 0, 0, &hf_062_295_01, I062_295_01_PARTS, { NULL } };
static const AsterixField I062_295_02 = { FIXED, 1, 0, 0, &hf_062_295_02, I062_295_02_PARTS, { NULL } };
static const AsterixField I062_295_03 = { FIXED, 1, 0, 0, &hf_062_295_03, I062_295_03_PARTS, { NULL } };
static const AsterixField I062_295_04 = { FIXED, 1, 0, 0, &hf_062_295_04, I062_295_04_PARTS, { NULL } };
static const AsterixField I062_295_05 = { FIXED, 1, 0, 0, &hf_062_295_05, I062_295_05_PARTS, { NULL } };
static const AsterixField I062_295_06 = { FIXED, 1, 0, 0, &hf_062_295_06, I062_295_06_PARTS, { NULL } };
static const AsterixField I062_295_07 = { FIXED, 1, 0, 0, &hf_062_295_07, I062_295_07_PARTS, { NULL } };
static const AsterixField I062_295_08 = { FIXED, 1, 0, 0, &hf_062_295_08, I062_295_08_PARTS, { NULL } };
static const AsterixField I062_295_09 = { FIXED, 1, 0, 0, &hf_062_295_09, I062_295_09_PARTS, { NULL } };
static const AsterixField I062_295_10 = { FIXED, 1, 0, 0, &hf_062_295_10, I062_295_10_PARTS, { NULL } };
static const AsterixField I062_295_11 = { FIXED, 1, 0, 0, &hf_062_295_11, I062_295_11_PARTS, { NULL } };
static const AsterixField I062_295_12 = { FIXED, 1, 0, 0, &hf_062_295_12, I062_295_12_PARTS, { NULL } };
static const AsterixField I062_295_13 = { FIXED, 1, 0, 0, &hf_062_295_13, I062_295_13_PARTS, { NULL } };
static const AsterixField I062_295_14 = { FIXED, 1, 0, 0, &hf_062_295_14, I062_295_14_PARTS, { NULL } };
static const AsterixField I062_295_15 = { FIXED, 1, 0, 0, &hf_062_295_15, I062_295_15_PARTS, { NULL } };
static const AsterixField I062_295_16 = { FIXED, 1, 0, 0, &hf_062_295_16, I062_295_16_PARTS, { NULL } };
static const AsterixField I062_295_17 = { FIXED, 1, 0, 0, &hf_062_295_17, I062_295_17_PARTS, { NULL } };
static const AsterixField I062_295_18 = { FIXED, 1, 0, 0, &hf_062_295_18, I062_295_18_PARTS, { NULL } };
static const AsterixField I062_295_19 = { FIXED, 1, 0, 0, &hf_062_295_19, I062_295_19_PARTS, { NULL } };
static const AsterixField I062_295_20 = { FIXED, 1, 0, 0, &hf_062_295_20, I062_295_20_PARTS, { NULL } };
static const AsterixField I062_295_21 = { FIXED, 1, 0, 0, &hf_062_295_21, I062_295_21_PARTS, { NULL } };
static const AsterixField I062_295_22 = { FIXED, 1, 0, 0, &hf_062_295_22, I062_295_22_PARTS, { NULL } };
static const AsterixField I062_295_23 = { FIXED, 1, 0, 0, &hf_062_295_23, I062_295_23_PARTS, { NULL } };
static const AsterixField I062_295_24 = { FIXED, 1, 0, 0, &hf_062_295_24, I062_295_24_PARTS, { NULL } };
static const AsterixField I062_295_25 = { FIXED, 1, 0, 0, &hf_062_295_25, I062_295_25_PARTS, { NULL } };
static const AsterixField I062_295_26 = { FIXED, 1, 0, 0, &hf_062_295_26, I062_295_26_PARTS, { NULL } };
static const AsterixField I062_295_27 = { FIXED, 1, 0, 0, &hf_062_295_27, I062_295_27_PARTS, { NULL } };
static const AsterixField I062_295_28 = { FIXED, 1, 0, 0, &hf_062_295_28, I062_295_28_PARTS, { NULL } };
static const AsterixField I062_295_29 = { FIXED, 1, 0, 0, &hf_062_295_29, I062_295_29_PARTS, { NULL } };
static const AsterixField I062_295_30 = { FIXED, 1, 0, 0, &hf_062_295_30, I062_295_30_PARTS, { NULL } };
static const AsterixField I062_295_31 = { FIXED, 1, 0, 0, &hf_062_295_31, I062_295_31_PARTS, { NULL } };
static const AsterixField I062_295 = { COMPOUND, 0, 0, 0, &hf_062_295, NULL, { &I062_295_01,
                                                                               &I062_295_02,
                                                                               &I062_295_03,
                                                                               &I062_295_04,
                                                                               &I062_295_05,
                                                                               &I062_295_06,
                                                                               &I062_295_07,
                                                                               &I062_295_08,
                                                                               &I062_295_09,
                                                                               &I062_295_10,
                                                                               &I062_295_11,
                                                                               &I062_295_12,
                                                                               &I062_295_13,
                                                                               &I062_295_14,
                                                                               &I062_295_15,
                                                                               &I062_295_16,
                                                                               &I062_295_17,
                                                                               &I062_295_18,
                                                                               &I062_295_19,
                                                                               &I062_295_20,
                                                                               &I062_295_21,
                                                                               &I062_295_22,
                                                                               &I062_295_23,
                                                                               &I062_295_24,
                                                                               &I062_295_25,
                                                                               &I062_295_26,
                                                                               &I062_295_27,
                                                                               &I062_295_28,
                                                                               &I062_295_29,
                                                                               &I062_295_30,
                                                                               &I062_295_31,
                                                                               NULL } };
static const AsterixField I062_300 = { FIXED, 1, 0, 0, &hf_062_300, I062_300_PARTS, { NULL } };
static const AsterixField I062_340_01 = { FIXED, 2, 0, 0, &hf_062_340_01, IXXX_SAC_SIC, { NULL } };
static const AsterixField I062_340_02 = { FIXED, 4, 0, 0, &hf_062_340_02, I062_340_02_PARTS, { NULL } };
static const AsterixField I062_340_03 = { FIXED, 2, 0, 0, &hf_062_340_03, I062_340_03_PARTS, { NULL } };
static const AsterixField I062_340_04 = { FIXED, 2, 0, 0, &hf_062_340_04, I062_340_04_PARTS, { NULL } };
static const AsterixField I062_340_05 = { FIXED, 2, 0, 0, &hf_062_340_05, I062_340_05_PARTS, { NULL } };
static const AsterixField I062_340_06 = { FIXED, 1, 0, 0, &hf_062_340_06, I062_340_06_PARTS, { NULL } };
static const AsterixField I062_340 = { COMPOUND, 0, 0, 0, &hf_062_340, NULL, { &I062_340_01,
                                                                               &I062_340_02,
                                                                               &I062_340_03,
                                                                               &I062_340_04,
                                                                               &I062_340_05,
                                                                               &I062_340_06,
                                                                               NULL } };
static const AsterixField I062_380_01 = { FIXED, 3, 0, 0, &hf_062_380_01, IXXX_AA_PARTS, { NULL } };
static const AsterixField I062_380_02 = { FIXED, 6, 0, 0, &hf_062_380_02, IXXX_AI_PARTS, { NULL } };
static const AsterixField I062_380_03 = { FIXED, 2, 0, 0, &hf_062_380_03, I062_380_03_PARTS, { NULL } };
static const AsterixField I062_380_04 = { FIXED, 2, 0, 0, &hf_062_380_04, I062_380_04_PARTS, { NULL } };
static const AsterixField I062_380_05 = { FIXED, 2, 0, 0, &hf_062_380_05, I062_380_05_PARTS, { NULL } };
static const AsterixField I062_380_06 = { FIXED, 2, 0, 0, &hf_062_380_06, I062_380_06_PARTS, { NULL } };
static const AsterixField I062_380_07 = { FIXED, 2, 0, 0, &hf_062_380_07, I062_380_07_PARTS, { NULL } };
static const AsterixField I062_380_08 = { FX, 1, 0, 0, &hf_062_380_08, I062_380_08_PARTS, { NULL } };
static const AsterixField I062_380_09 = { REPETITIVE, 15, 1, 0, &hf_062_380_09, I062_380_09_PARTS, { NULL } };
static const AsterixField I062_380_10 = { FIXED, 2, 0, 0, &hf_062_380_10, I062_380_10_PARTS, { NULL } };
static const AsterixField I062_380_11 = { FIXED, 2, 0, 0, &hf_062_380_11, I062_380_11_PARTS, { NULL } };
static const AsterixField I062_380_12 = { FIXED, 7, 0, 0, &hf_062_380_12, I062_380_12_PARTS, { NULL } };
static const AsterixField I062_380_13 = { FIXED, 2, 0, 0, &hf_062_380_13, I062_380_13_PARTS, { NULL } };
static const AsterixField I062_380_14 = { FIXED, 2, 0, 0, &hf_062_380_14, I062_380_14_PARTS, { NULL } };
static const AsterixField I062_380_15 = { FIXED, 2, 0, 0, &hf_062_380_15, I062_380_15_PARTS, { NULL } };
static const AsterixField I062_380_16 = { FIXED, 2, 0, 0, &hf_062_380_16, I062_380_16_PARTS, { NULL } };
static const AsterixField I062_380_17 = { FIXED, 2, 0, 0, &hf_062_380_17, I062_380_17_PARTS, { NULL } };
static const AsterixField I062_380_18 = { FIXED, 2, 0, 0, &hf_062_380_18, I062_380_18_PARTS, { NULL } };
static const AsterixField I062_380_19 = { FIXED, 1, 0, 0, &hf_062_380_19, I062_380_19_PARTS, { NULL } };
static const AsterixField I062_380_20 = { FIXED, 8, 0, 0, &hf_062_380_20, I062_380_20_PARTS, { NULL } };
static const AsterixField I062_380_21 = { FIXED, 1, 0, 0, &hf_062_380_21, I062_380_21_PARTS, { NULL } };
static const AsterixField I062_380_22 = { FIXED, 6, 0, 0, &hf_062_380_22, I062_380_22_PARTS, { NULL } };
static const AsterixField I062_380_23 = { FIXED, 2, 0, 0, &hf_062_380_23, I062_380_23_PARTS, { NULL } };
static const AsterixField I062_380_24 = { FIXED, 1, 0, 0, &hf_062_380_24, I062_380_24_PARTS, { NULL } };
static const AsterixField I062_380_25 = { REPETITIVE, 8, 1, 0, &hf_062_380_25, IXXX_MB, { NULL } };
static const AsterixField I062_380_26 = { FIXED, 2, 0, 0, &hf_062_380_26, I062_380_26_PARTS, { NULL } };
static const AsterixField I062_380_27 = { FIXED, 2, 0, 0, &hf_062_380_27, I062_380_27_PARTS, { NULL } };
static const AsterixField I062_380_28 = { FIXED, 2, 0, 0, &hf_062_380_28, I062_380_28_PARTS, { NULL } };
static const AsterixField I062_380 = { COMPOUND, 0, 0, 0, &hf_062_380, NULL, { &I062_380_01,
                                                                               &I062_380_02,
                                                                               &I062_380_03,
                                                                               &I062_380_04,
                                                                               &I062_380_05,
                                                                               &I062_380_06,
                                                                               &I062_380_07,
                                                                               &I062_380_08,
                                                                               &I062_380_09,
                                                                               &I062_380_10,
                                                                               &I062_380_11,
                                                                               &I062_380_12,
                                                                               &I062_380_13,
                                                                               &I062_380_14,
                                                                               &I062_380_15,
                                                                               &I062_380_16,
                                                                               &I062_380_17,
                                                                               &I062_380_18,
                                                                               &I062_380_19,
                                                                               &I062_380_20,
                                                                               &I062_380_21,
                                                                               &I062_380_22,
                                                                               &I062_380_23,
                                                                               &I062_380_24,
                                                                               &I062_380_25,
                                                                               &I062_380_26,
                                                                               &I062_380_27,
                                                                               &I062_380_28,
                                                                               NULL } };
/* v.0.17 */
static const AsterixField I062_380_01_v0_17 = { REPETITIVE, 8, 1, 0, &hf_062_380_01_v0_17, IXXX_MB, { NULL } };
static const AsterixField I062_380_02_v0_17 = { FIXED, 3, 0, 0, &hf_062_380_02_v0_17, IXXX_AA_PARTS, { NULL } };
static const AsterixField I062_380_03_v0_17 = { FIXED, 6, 0, 0, &hf_062_380_03_v0_17, IXXX_AI_PARTS, { NULL } };
static const AsterixField I062_380_04_v0_17 = { FIXED, 2, 0, 0, &hf_062_380_04_v0_17, I062_380_04_PARTS_v0_17, { NULL } };
static const AsterixField I062_380_05_v0_17 = { FIXED, 7, 0, 0, &hf_062_380_05_v0_17, I062_380_05_PARTS_v0_17, { NULL } };
static const AsterixField I062_380_v0_17 = { COMPOUND, 0, 0, 0, &hf_062_380_v0_17, NULL, { &I062_380_01_v0_17,
                                                                                           &I062_380_02_v0_17,
                                                                                           &I062_380_03_v0_17,
                                                                                           &I062_380_04_v0_17,
                                                                                           &I062_380_05_v0_17,
                                                                                           NULL } };
static const AsterixField I062_390_01 = { FIXED, 2, 0, 0, &hf_062_390_01, IXXX_SAC_SIC, { NULL } };
static const AsterixField I062_390_02 = { FIXED, 7, 0, 0, &hf_062_390_02, I062_390_02_PARTS, { NULL } };
static const AsterixField I062_390_03 = { FIXED, 4, 0, 0, &hf_062_390_03, I062_390_03_PARTS, { NULL } };
static const AsterixField I062_390_04 = { FIXED, 1, 0, 0, &hf_062_390_04, I062_390_04_PARTS, { NULL } };
static const AsterixField I062_390_05 = { FIXED, 4, 0, 0, &hf_062_390_05, I062_390_05_PARTS, { NULL } };
static const AsterixField I062_390_06 = { FIXED, 1, 0, 0, &hf_062_390_06, I062_390_06_PARTS, { NULL } };
static const AsterixField I062_390_07 = { FIXED, 4, 0, 0, &hf_062_390_07, I062_390_07_PARTS, { NULL } };
static const AsterixField I062_390_08 = { FIXED, 4, 0, 0, &hf_062_390_08, I062_390_08_PARTS, { NULL } };
static const AsterixField I062_390_09 = { FIXED, 3, 0, 0, &hf_062_390_09, I062_390_09_PARTS, { NULL } };
static const AsterixField I062_390_10 = { FIXED, 2, 0, 0, &hf_062_390_10, I062_390_10_PARTS, { NULL } };
static const AsterixField I062_390_11 = { FIXED, 2, 0, 0, &hf_062_390_11, I062_390_11_PARTS, { NULL } };
static const AsterixField I062_390_12 = { REPETITIVE, 4, 1, 0, &hf_062_390_12, I062_390_12_PARTS, { NULL } };
static const AsterixField I062_390_13 = { FIXED, 6, 0, 0, &hf_062_390_13, I062_390_13_PARTS, { NULL } };
static const AsterixField I062_390_14 = { FIXED, 1, 0, 0, &hf_062_390_14, I062_390_14_PARTS, { NULL } };
static const AsterixField I062_390_15 = { FIXED, 7, 0, 0, &hf_062_390_15, I062_390_15_PARTS, { NULL } };
static const AsterixField I062_390_16 = { FIXED, 7, 0, 0, &hf_062_390_16, I062_390_16_PARTS, { NULL } };
static const AsterixField I062_390_17 = { FIXED, 2, 0, 0, &hf_062_390_17, I062_390_17_PARTS, { NULL } };
static const AsterixField I062_390_18 = { FIXED, 7, 0, 0, &hf_062_390_18, I062_390_18_PARTS, { NULL } };
static const AsterixField I062_390 = { COMPOUND, 0, 0, 0, &hf_062_390, NULL, { &I062_390_01,
                                                                               &I062_390_02,
                                                                               &I062_390_03,
                                                                               &I062_390_04,
                                                                               &I062_390_05,
                                                                               &I062_390_06,
                                                                               &I062_390_07,
                                                                               &I062_390_08,
                                                                               &I062_390_09,
                                                                               &I062_390_10,
                                                                               &I062_390_11,
                                                                               &I062_390_12,
                                                                               &I062_390_13,
                                                                               &I062_390_14,
                                                                               &I062_390_15,
                                                                               &I062_390_16,
                                                                               &I062_390_17,
                                                                               &I062_390_18,
                                                                               NULL } };
static const AsterixField I062_500_01 = { FIXED, 4, 0, 0, &hf_062_500_01, I062_500_01_PARTS, { NULL } };
static const AsterixField I062_500_02 = { FIXED, 2, 0, 0, &hf_062_500_02, I062_500_02_PARTS, { NULL } };
static const AsterixField I062_500_03 = { FIXED, 4, 0, 0, &hf_062_500_03, I062_500_03_PARTS, { NULL } };
static const AsterixField I062_500_04 = { FIXED, 1, 0, 0, &hf_062_500_04, I062_500_04_PARTS, { NULL } };
static const AsterixField I062_500_05 = { FIXED, 1, 0, 0, &hf_062_500_05, I062_500_05_PARTS, { NULL } };
static const AsterixField I062_500_06 = { FIXED, 2, 0, 0, &hf_062_500_06, I062_500_06_PARTS, { NULL } };
static const AsterixField I062_500_07 = { FIXED, 2, 0, 0, &hf_062_500_07, I062_500_07_PARTS, { NULL } };
static const AsterixField I062_500_08 = { FIXED, 1, 0, 0, &hf_062_500_08, I062_500_08_PARTS, { NULL } };
static const AsterixField I062_500 = { COMPOUND, 0, 0, 0, &hf_062_500, NULL, { &I062_500_01,
                                                                               &I062_500_02,
                                                                               &I062_500_03,
                                                                               &I062_500_04,
                                                                               &I062_500_05,
                                                                               &I062_500_06,
                                                                               &I062_500_07,
                                                                               &I062_500_08,
                                                                               NULL } };
static const AsterixField I062_500_01_v0_17 = { FIXED, 2, 0, 0, &hf_062_500_01, I062_500_01_PARTS_v0_17, { NULL } };
static const AsterixField I062_500_02_v0_17 = { FIXED, 4, 0, 0, &hf_062_500_02_v0_17, I062_500_02_PARTS_v0_17, { NULL } };
static const AsterixField I062_500_03_v0_17 = { FIXED, 2, 0, 0, &hf_062_500_03_v0_17, I062_500_03_PARTS_v0_17, { NULL } };
static const AsterixField I062_500_04_v0_17 = { FIXED, 1, 0, 0, &hf_062_500_04_v0_17, I062_500_04_PARTS_v0_17, { NULL } };
static const AsterixField I062_500_05_v0_17 = { FIXED, 3, 0, 0, &hf_062_500_05_v0_17, I062_500_05_PARTS_v0_17, { NULL } };
static const AsterixField I062_500_06_v0_17 = { FIXED, 1, 0, 0, &hf_062_500_06_v0_17, I062_500_06_PARTS_v0_17, { NULL } };
static const AsterixField I062_500_07_v0_17 = { FIXED, 2, 0, 0, &hf_062_500_07_v0_17, I062_500_07_PARTS_v0_17, { NULL } };
static const AsterixField I062_500_v0_17 = { COMPOUND, 0, 0, 0, &hf_062_500, NULL, { &I062_500_01_v0_17,
                                                                                     &I062_500_02_v0_17,
                                                                                     &I062_500_03_v0_17,
                                                                                     &I062_500_04_v0_17,
                                                                                     &I062_500_05_v0_17,
                                                                                     &I062_500_06_v0_17,
                                                                                     &I062_500_07_v0_17,
                                                                                     &I062_500_08,
                                                                                     NULL } };
static const AsterixField I062_510 = { FX, 3, 0, 0, &hf_062_510, I062_510_PARTS, { NULL } };
/*RE Field*/
static const AsterixField I062_RE_CST = { REPETITIVE, 5, 1, 0, &hf_062_RE_CST, I062_RE_CST_PARTS, { NULL } };
static const AsterixField I062_RE_CSNT = { REPETITIVE, 3, 1, 0, &hf_062_RE_CSNT, I062_RE_CSNT_PARTS, { NULL } };
static const AsterixField I062_RE_TVS = { FIXED, 4, 0, 0, &hf_062_RE_TVS, I062_RE_TVS_PARTS, { NULL } };
static const AsterixField I062_RE_STS = { FX, 1, 0, 0, &hf_062_RE_STS, I062_RE_STS_PARTS, { NULL } };
static const AsterixField I062_RE = { RE, 0, 0, 1, &hf_062_RE, NULL, { &I062_RE_CST, &I062_RE_CSNT, &I062_RE_TVS, &I062_RE_STS, NULL } };
static const AsterixField I062_SP = { SP, 0, 0, 1, &hf_062_SP, NULL, { NULL } };

static const AsterixField *I062_v1_16_uap[] = { &I062_010, &IX_SPARE, &I062_015, &I062_070, &I062_105, &I062_100, &I062_185,
                                                &I062_210, &I062_060, &I062_245, &I062_380, &I062_040, &I062_080, &I062_290,
                                                &I062_200, &I062_295, &I062_136, &I062_130, &I062_135, &I062_220, &I062_390,
                                                &I062_270, &I062_300, &I062_110, &I062_120, &I062_510, &I062_500, &I062_340,
                                                &IX_SPARE, &IX_SPARE, &IX_SPARE, &IX_SPARE, &IX_SPARE, &I062_RE,  &I062_SP, NULL };
static const AsterixField *I062_v0_17_uap[] = { &I062_010, &I062_015, &I062_070, &I062_040, &I062_105_v0_17, &I062_100_v0_17, &I062_060_v0_17,
                                                &I062_130, &I062_135, &I062_136, &I062_180, &I062_200_v0_17, &I062_220, &I062_240,
                                                &I062_210_v0_17, &I062_080_v0_17, &I062_290_v0_17, &I062_340, &I062_380_v0_17, &I062_500_v0_17, &I062_390,
                                                &I062_110_v0_17, &I062_120, &I062_510, &IX_SPARE, &IX_SPARE, &I062_RE,  &I062_SP, NULL };
static const AsterixField **I062_v1_16[] = { I062_v1_16_uap, NULL };
static const AsterixField **I062_v0_17[] = { I062_v0_17_uap, NULL };
static const AsterixField ***I062[] = { I062_v1_16, I062_v0_17 };

static const enum_val_t I062_versions[] = {
    { "I062_v1_16", "Version 1.16", 0 },
    { "I062_v0_17", "Version 0.17", 1 },
    { NULL, NULL, 0 }
};

/* *********************** */
/*      Category 063       */
/* *********************** */
/* Fields */


/* Items */
static const AsterixField I063_010 = { FIXED, 2, 0, 0, &hf_063_010, IXXX_SAC_SIC, { NULL } };
static const AsterixField I063_015 = { FIXED, 1, 0, 0, &hf_063_015, NULL, { NULL } };
static const AsterixField I063_030 = { FIXED, 3, 0, 0, &hf_063_030, IXXX_TOD, { NULL } };
static const AsterixField I063_050 = { FIXED, 2, 0, 0, &hf_063_050, IXXX_SAC_SIC, { NULL } };
static const AsterixField I063_060 = { FX, 1, 0, 0, &hf_063_060, NULL, { NULL } };
static const AsterixField I063_070 = { FIXED, 2, 0, 0, &hf_063_070, NULL, { NULL } };
static const AsterixField I063_080 = { FIXED, 4, 0, 0, &hf_063_080, NULL, { NULL } };
static const AsterixField I063_081 = { FIXED, 2, 0, 0, &hf_063_081, NULL, { NULL } };
static const AsterixField I063_090 = { FIXED, 4, 0, 0, &hf_063_090, NULL, { NULL } };
static const AsterixField I063_091 = { FIXED, 2, 0, 0, &hf_063_091, NULL, { NULL } };
static const AsterixField I063_092 = { FIXED, 2, 0, 0, &hf_063_092, NULL, { NULL } };
static const AsterixField I063_RE = { RE, 0, 0, 1, &hf_063_RE, NULL, { NULL } };
static const AsterixField I063_SP = { SP, 0, 0, 1, &hf_063_SP, NULL, { NULL } };

static const AsterixField *I063_v1_3_uap[] = { &I063_010, &I063_015, &I063_030, &I063_050, &I063_060, &I063_070, &I063_080,
                                               &I063_081, &I063_090, &I063_091, &I063_092, &IX_SPARE, &I063_RE,  &I063_SP, NULL };
static const AsterixField **I063_v1_3[] = { I063_v1_3_uap, NULL };
static const AsterixField ***I063[] = { I063_v1_3 };

static const enum_val_t I063_versions[] = {
    { "I063_v1_3", "Version 1.3", 0 },
    { NULL, NULL, 0 }
};

/* *********************** */
/*      Category 065       */
/* *********************** */
/* Fields */


/* Items */
static const AsterixField I065_000 = { FIXED, 1, 0, 0, &hf_065_000, NULL, { NULL } };
static const AsterixField I065_010 = { FIXED, 2, 0, 0, &hf_065_010, IXXX_SAC_SIC, { NULL } };
static const AsterixField I065_015 = { FIXED, 1, 0, 0, &hf_065_015, NULL, { NULL } };
static const AsterixField I065_020 = { FIXED, 1, 0, 0, &hf_065_020, NULL, { NULL } };
static const AsterixField I065_030 = { FIXED, 3, 0, 0, &hf_065_030, IXXX_TOD, { NULL } };
static const AsterixField I065_040 = { FIXED, 1, 0, 0, &hf_065_040, NULL, { NULL } };
static const AsterixField I065_050 = { FIXED, 1, 0, 0, &hf_065_050, NULL, { NULL } };
static const AsterixField I065_RE = { RE, 0, 0, 1, &hf_065_RE, NULL, { NULL } };
static const AsterixField I065_SP = { SP, 0, 0, 1, &hf_065_SP, NULL, { NULL } };

static const AsterixField *I065_v1_3_uap[] = { &I065_010, &I065_000, &I065_015, &I065_030, &I065_020, &I065_040, &I065_050,
                                               &IX_SPARE, &IX_SPARE, &IX_SPARE, &IX_SPARE, &IX_SPARE, &I065_RE,  &I065_SP, NULL };
static const AsterixField **I065_v1_3[] = { I065_v1_3_uap, NULL };
static const AsterixField ***I065[] = { I065_v1_3 };

static const enum_val_t I065_versions[] = {
    { "I065_v1_3", "Version 1.3", 0 },
    { NULL, NULL, 0 }
};

/* settings which category version to use for each ASTERIX category */
static gint global_categories_version[] = {
    0, /* 000 */
    0, /* 001 */
    0, /* 002 */
    0, /* 003 */
    0, /* 004 */
    0, /* 005 */
    0, /* 006 */
    0, /* 007 */
    0, /* 008 */
    0, /* 009 */
    0, /* 010 */
    0, /* 011 */
    0, /* 012 */
    0, /* 013 */
    0, /* 014 */
    0, /* 015 */
    0, /* 016 */
    0, /* 017 */
    0, /* 018 */
    0, /* 019 */
    0, /* 020 */
    0, /* 021 */
    0, /* 022 */
    0, /* 023 */
    0, /* 024 */
    0, /* 025 */
    0, /* 026 */
    0, /* 027 */
    0, /* 028 */
    0, /* 029 */
    0, /* 030 */
    0, /* 031 */
    0, /* 032 */
    0, /* 033 */
    0, /* 034 */
    0, /* 035 */
    0, /* 036 */
    0, /* 037 */
    0, /* 038 */
    0, /* 039 */
    0, /* 040 */
    0, /* 041 */
    0, /* 042 */
    0, /* 043 */
    0, /* 044 */
    0, /* 045 */
    0, /* 046 */
    0, /* 047 */
    0, /* 048 */
    0, /* 049 */
    0, /* 050 */
    0, /* 051 */
    0, /* 052 */
    0, /* 053 */
    0, /* 054 */
    0, /* 055 */
    0, /* 056 */
    0, /* 057 */
    0, /* 058 */
    0, /* 059 */
    0, /* 060 */
    0, /* 061 */
    0, /* 062 */
    0, /* 063 */
    0, /* 064 */
    0, /* 065 */
    0, /* 066 */
    0, /* 067 */
    0, /* 068 */
    0, /* 069 */
    0, /* 070 */
    0, /* 071 */
    0, /* 072 */
    0, /* 073 */
    0, /* 074 */
    0, /* 075 */
    0, /* 076 */
    0, /* 077 */
    0, /* 078 */
    0, /* 079 */
    0, /* 080 */
    0, /* 081 */
    0, /* 082 */
    0, /* 083 */
    0, /* 084 */
    0, /* 085 */
    0, /* 086 */
    0, /* 087 */
    0, /* 088 */
    0, /* 089 */
    0, /* 090 */
    0, /* 091 */
    0, /* 092 */
    0, /* 093 */
    0, /* 094 */
    0, /* 095 */
    0, /* 096 */
    0, /* 097 */
    0, /* 098 */
    0, /* 099 */
    0, /* 100 */
    0, /* 101 */
    0, /* 102 */
    0, /* 103 */
    0, /* 104 */
    0, /* 105 */
    0, /* 106 */
    0, /* 107 */
    0, /* 108 */
    0, /* 109 */
    0, /* 110 */
    0, /* 111 */
    0, /* 112 */
    0, /* 113 */
    0, /* 114 */
    0, /* 115 */
    0, /* 116 */
    0, /* 117 */
    0, /* 118 */
    0, /* 119 */
    0, /* 120 */
    0, /* 121 */
    0, /* 122 */
    0, /* 123 */
    0, /* 124 */
    0, /* 125 */
    0, /* 126 */
    0, /* 127 */
    0, /* 128 */
    0, /* 129 */
    0, /* 130 */
    0, /* 131 */
    0, /* 132 */
    0, /* 133 */
    0, /* 134 */
    0, /* 135 */
    0, /* 136 */
    0, /* 137 */
    0, /* 138 */
    0, /* 139 */
    0, /* 140 */
    0, /* 141 */
    0, /* 142 */
    0, /* 143 */
    0, /* 144 */
    0, /* 145 */
    0, /* 146 */
    0, /* 147 */
    0, /* 148 */
    0, /* 149 */
    0, /* 150 */
    0, /* 151 */
    0, /* 152 */
    0, /* 153 */
    0, /* 154 */
    0, /* 155 */
    0, /* 156 */
    0, /* 157 */
    0, /* 158 */
    0, /* 159 */
    0, /* 160 */
    0, /* 161 */
    0, /* 162 */
    0, /* 163 */
    0, /* 164 */
    0, /* 165 */
    0, /* 166 */
    0, /* 167 */
    0, /* 168 */
    0, /* 169 */
    0, /* 170 */
    0, /* 171 */
    0, /* 172 */
    0, /* 173 */
    0, /* 174 */
    0, /* 175 */
    0, /* 176 */
    0, /* 177 */
    0, /* 178 */
    0, /* 179 */
    0, /* 180 */
    0, /* 181 */
    0, /* 182 */
    0, /* 183 */
    0, /* 184 */
    0, /* 185 */
    0, /* 186 */
    0, /* 187 */
    0, /* 188 */
    0, /* 189 */
    0, /* 190 */
    0, /* 191 */
    0, /* 192 */
    0, /* 193 */
    0, /* 194 */
    0, /* 195 */
    0, /* 196 */
    0, /* 197 */
    0, /* 198 */
    0, /* 199 */
    0, /* 200 */
    0, /* 201 */
    0, /* 202 */
    0, /* 203 */
    0, /* 204 */
    0, /* 205 */
    0, /* 206 */
    0, /* 207 */
    0, /* 208 */
    0, /* 209 */
    0, /* 210 */
    0, /* 211 */
    0, /* 212 */
    0, /* 213 */
    0, /* 214 */
    0, /* 215 */
    0, /* 216 */
    0, /* 217 */
    0, /* 218 */
    0, /* 219 */
    0, /* 220 */
    0, /* 221 */
    0, /* 222 */
    0, /* 223 */
    0, /* 224 */
    0, /* 225 */
    0, /* 226 */
    0, /* 227 */
    0, /* 228 */
    0, /* 229 */
    0, /* 230 */
    0, /* 231 */
    0, /* 232 */
    0, /* 233 */
    0, /* 234 */
    0, /* 235 */
    0, /* 236 */
    0, /* 237 */
    0, /* 238 */
    0, /* 239 */
    0, /* 240 */
    0, /* 241 */
    0, /* 242 */
    0, /* 243 */
    0, /* 244 */
    0, /* 245 */
    0, /* 246 */
    0, /* 247 */
    0, /* 248 */
    0, /* 249 */
    0, /* 250 */
    0, /* 251 */
    0, /* 252 */
    0, /* 253 */
    0, /* 254 */
    0  /* 255 */
};

/* all possible categories: When category is added it shall be added to this array. */
static const AsterixField ****categories[] = {
    NULL, /* 000 */
    I001, /* 001 */
    I002, /* 002 */
    NULL, /* 003 */
    NULL, /* 004 */
    NULL, /* 005 */
    NULL, /* 006 */
    NULL, /* 007 */
    I008, /* 008 */
    I009, /* 009 */
    NULL, /* 010 */
    NULL, /* 011 */
    NULL, /* 012 */
    NULL, /* 013 */
    NULL, /* 014 */
    NULL, /* 015 */
    NULL, /* 016 */
    NULL, /* 017 */
    NULL, /* 018 */
    NULL, /* 019 */
    NULL, /* 020 */
    I021, /* 021 */
    NULL, /* 022 */
    I023, /* 023 */
    NULL, /* 024 */
    NULL, /* 025 */
    NULL, /* 026 */
    NULL, /* 027 */
    NULL, /* 028 */
    NULL, /* 029 */
    NULL, /* 030 */
    NULL, /* 031 */
    NULL, /* 032 */
    NULL, /* 033 */
    I034, /* 034 */
    NULL, /* 035 */
    NULL, /* 036 */
    NULL, /* 037 */
    NULL, /* 038 */
    NULL, /* 039 */
    NULL, /* 040 */
    NULL, /* 041 */
    NULL, /* 042 */
    NULL, /* 043 */
    NULL, /* 044 */
    NULL, /* 045 */
    NULL, /* 046 */
    NULL, /* 047 */
    I048, /* 048 */
    NULL, /* 049 */
    NULL, /* 050 */
    NULL, /* 051 */
    NULL, /* 052 */
    NULL, /* 053 */
    NULL, /* 054 */
    NULL, /* 055 */
    NULL, /* 056 */
    NULL, /* 057 */
    NULL, /* 058 */
    NULL, /* 059 */
    NULL, /* 060 */
    NULL, /* 061 */
    I062, /* 062 */
    I063, /* 063 */
    NULL, /* 064 */
    I065, /* 065 */
    NULL, /* 066 */
    NULL, /* 067 */
    NULL, /* 068 */
    NULL, /* 069 */
    NULL, /* 070 */
    NULL, /* 071 */
    NULL, /* 072 */
    NULL, /* 073 */
    NULL, /* 074 */
    NULL, /* 075 */
    NULL, /* 076 */
    NULL, /* 077 */
    NULL, /* 078 */
    NULL, /* 079 */
    NULL, /* 080 */
    NULL, /* 081 */
    NULL, /* 082 */
    NULL, /* 083 */
    NULL, /* 084 */
    NULL, /* 085 */
    NULL, /* 086 */
    NULL, /* 087 */
    NULL, /* 088 */
    NULL, /* 089 */
    NULL, /* 090 */
    NULL, /* 091 */
    NULL, /* 092 */
    NULL, /* 093 */
    NULL, /* 094 */
    NULL, /* 095 */
    NULL, /* 096 */
    NULL, /* 097 */
    NULL, /* 098 */
    NULL, /* 099 */
    NULL, /* 100 */
    NULL, /* 101 */
    NULL, /* 102 */
    NULL, /* 103 */
    NULL, /* 104 */
    NULL, /* 105 */
    NULL, /* 106 */
    NULL, /* 107 */
    NULL, /* 108 */
    NULL, /* 109 */
    NULL, /* 110 */
    NULL, /* 111 */
    NULL, /* 112 */
    NULL, /* 113 */
    NULL, /* 114 */
    NULL, /* 115 */
    NULL, /* 116 */
    NULL, /* 117 */
    NULL, /* 118 */
    NULL, /* 119 */
    NULL, /* 120 */
    NULL, /* 121 */
    NULL, /* 122 */
    NULL, /* 123 */
    NULL, /* 124 */
    NULL, /* 125 */
    NULL, /* 126 */
    NULL, /* 127 */
    NULL, /* 128 */
    NULL, /* 129 */
    NULL, /* 130 */
    NULL, /* 131 */
    NULL, /* 132 */
    NULL, /* 133 */
    NULL, /* 134 */
    NULL, /* 135 */
    NULL, /* 136 */
    NULL, /* 137 */
    NULL, /* 138 */
    NULL, /* 139 */
    NULL, /* 140 */
    NULL, /* 141 */
    NULL, /* 142 */
    NULL, /* 143 */
    NULL, /* 144 */
    NULL, /* 145 */
    NULL, /* 146 */
    NULL, /* 147 */
    NULL, /* 148 */
    NULL, /* 149 */
    NULL, /* 150 */
    NULL, /* 151 */
    NULL, /* 152 */
    NULL, /* 153 */
    NULL, /* 154 */
    NULL, /* 155 */
    NULL, /* 156 */
    NULL, /* 157 */
    NULL, /* 158 */
    NULL, /* 159 */
    NULL, /* 160 */
    NULL, /* 161 */
    NULL, /* 162 */
    NULL, /* 163 */
    NULL, /* 164 */
    NULL, /* 165 */
    NULL, /* 166 */
    NULL, /* 167 */
    NULL, /* 168 */
    NULL, /* 169 */
    NULL, /* 170 */
    NULL, /* 171 */
    NULL, /* 172 */
    NULL, /* 173 */
    NULL, /* 174 */
    NULL, /* 175 */
    NULL, /* 176 */
    NULL, /* 177 */
    NULL, /* 178 */
    NULL, /* 179 */
    NULL, /* 180 */
    NULL, /* 181 */
    NULL, /* 182 */
    NULL, /* 183 */
    NULL, /* 184 */
    NULL, /* 185 */
    NULL, /* 186 */
    NULL, /* 187 */
    NULL, /* 188 */
    NULL, /* 189 */
    NULL, /* 190 */
    NULL, /* 191 */
    NULL, /* 192 */
    NULL, /* 193 */
    NULL, /* 194 */
    NULL, /* 195 */
    NULL, /* 196 */
    NULL, /* 197 */
    NULL, /* 198 */
    NULL, /* 199 */
    NULL, /* 200 */
    NULL, /* 201 */
    NULL, /* 202 */
    NULL, /* 203 */
    NULL, /* 204 */
    NULL, /* 205 */
    NULL, /* 206 */
    NULL, /* 207 */
    NULL, /* 208 */
    NULL, /* 209 */
    NULL, /* 210 */
    NULL, /* 211 */
    NULL, /* 212 */
    NULL, /* 213 */
    NULL, /* 214 */
    NULL, /* 215 */
    NULL, /* 216 */
    NULL, /* 217 */
    NULL, /* 218 */
    NULL, /* 219 */
    NULL, /* 220 */
    NULL, /* 221 */
    NULL, /* 222 */
    NULL, /* 223 */
    NULL, /* 224 */
    NULL, /* 225 */
    NULL, /* 226 */
    NULL, /* 227 */
    NULL, /* 228 */
    NULL, /* 229 */
    NULL, /* 230 */
    NULL, /* 231 */
    NULL, /* 232 */
    NULL, /* 233 */
    NULL, /* 234 */
    NULL, /* 235 */
    NULL, /* 236 */
    NULL, /* 237 */
    NULL, /* 238 */
    NULL, /* 239 */
    NULL, /* 240 */
    NULL, /* 241 */
    NULL, /* 242 */
    NULL, /* 243 */
    NULL, /* 244 */
    NULL, /* 245 */
    NULL, /* 246 */
    NULL, /* 247 */
    NULL, /* 248 */
    NULL, /* 249 */
    NULL, /* 250 */
    NULL, /* 251 */
    NULL, /* 252 */
    NULL, /* 253 */
    NULL, /* 254 */
    NULL  /* 255 */
};


static void dissect_asterix (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    col_set_str (pinfo->cinfo, COL_PROTOCOL, "ASTERIX");
    col_clear (pinfo->cinfo, COL_INFO);

    if (tree) { /* we are being asked for details */
        dissect_asterix_packet (tvb, tree);
    }
}

static void dissect_asterix_packet (tvbuff_t *tvb, proto_tree *tree)
{
    guint i;
    guint8 category;
    guint16 length;
    proto_item *asterix_packet_item;
    proto_tree *asterix_packet_tree;

    for (i = 0; i < tvb_reported_length (tvb); i += length + 3) {
        category = tvb_get_guint8 (tvb, i);
        length = (tvb_get_guint8 (tvb, i + 1) << 8) + tvb_get_guint8 (tvb, i + 2) - 3; /* -3 for category and length */

        asterix_packet_item = proto_tree_add_item (tree, proto_asterix, tvb, i, length + 3, ENC_NA);
        proto_item_append_text (asterix_packet_item, ", Category %03d", category);
        asterix_packet_tree = proto_item_add_subtree (asterix_packet_item, ett_asterix);
        proto_tree_add_item (asterix_packet_tree, hf_asterix_category, tvb, i, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (asterix_packet_tree, hf_asterix_length, tvb, i + 1, 2, ENC_BIG_ENDIAN);

        dissect_asterix_data_block (tvb, i + 3, asterix_packet_tree, category, length);
    }
}

static void dissect_asterix_data_block (tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 category, gint length)
{
    guint8 active_uap;
    int fspec_len, inner_offset, size, counter;
    proto_item *asterix_message_item = NULL;
    proto_tree *asterix_message_tree = NULL;

    for (counter = 1, inner_offset = 0; inner_offset < length; counter++) {
        active_uap = asterix_get_active_uap (tvb, offset + inner_offset, category);
        size = asterix_message_length (tvb, offset + inner_offset, category, active_uap);
        if (size > 0) {
            asterix_message_item = proto_tree_add_item (tree, hf_asterix_message, tvb, offset + inner_offset, size, ENC_NA);
            proto_item_append_text (asterix_message_item, ", #%02d, length: %d", counter, size);
            asterix_message_tree = proto_item_add_subtree (asterix_message_item, ett_asterix_message);
            fspec_len = asterix_fspec_len (tvb, offset + inner_offset);
            /*show_fspec (tvb, asterix_message_tree, offset + inner_offset, fspec_len);*/
            proto_tree_add_item (asterix_message_tree, hf_asterix_fspec, tvb, offset + inner_offset, fspec_len, ENC_NA);

            size = dissect_asterix_fields (tvb, offset + inner_offset, asterix_message_tree, category, categories[category][global_categories_version[category]][active_uap]);

            inner_offset += size + fspec_len;
        }
        else {
            inner_offset = length;
        }
    }
}

static gint dissect_asterix_fields (tvbuff_t *tvb, guint offset, proto_tree *tree, guint8 category, const AsterixField *current_uap[])
{
    guint i, j, size, start, len, inner_offset, fspec_len;
    guint64 counter;
    proto_item *asterix_field_item = NULL;
    proto_tree *asterix_field_tree = NULL;
    proto_item *asterix_field_item2 = NULL;
    proto_tree *asterix_field_tree2 = NULL;

    if (current_uap == NULL)
        return 0;

    for (i = 0, size = 0; current_uap[i] != NULL; i++) {
        start = asterix_field_offset (tvb, offset, current_uap, i);
        if (start > 0) {
            len = asterix_field_length (tvb, offset + start, current_uap[i]);
            size += len;
            if (current_uap[i]->type & COMPOUND) {
                asterix_field_item = proto_tree_add_item (tree, *current_uap[i]->hf, tvb, offset + start, len, ENC_NA);
                asterix_field_tree = proto_item_add_subtree (asterix_field_item, ett_asterix_subtree);
                fspec_len = asterix_fspec_len (tvb, offset + start);
                proto_tree_add_item (asterix_field_tree, hf_asterix_fspec, tvb, offset + start, fspec_len, ENC_NA);
                dissect_asterix_fields (tvb, offset + start, asterix_field_tree, category, (const AsterixField **)current_uap[i]->field);
            }
            else if (current_uap[i]->type & REPETITIVE) {
                asterix_field_item = proto_tree_add_item (tree, *current_uap[i]->hf, tvb, offset + start, len, ENC_NA);
                asterix_field_tree = proto_item_add_subtree (asterix_field_item, ett_asterix_subtree);
                for (j = 0, counter = 0; j < current_uap[i]->repetition_counter_size; j++) {
                    counter = (counter << 8) + tvb_get_guint8 (tvb, offset + start + j);
                }
                proto_tree_add_item (asterix_field_tree, hf_counter, tvb, offset + start, current_uap[i]->repetition_counter_size, ENC_BIG_ENDIAN);
                for (j = 0, inner_offset = 0; j < counter; j++, inner_offset += current_uap[i]->length) {
                    asterix_field_item2 = proto_tree_add_item (asterix_field_tree, *current_uap[i]->hf, tvb, offset + start + current_uap[i]->repetition_counter_size + inner_offset, current_uap[i]->length, ENC_NA);
                    asterix_field_tree2 = proto_item_add_subtree (asterix_field_item2, ett_asterix_subtree);
                    asterix_build_subtree (tvb, offset + start + current_uap[i]->repetition_counter_size + inner_offset, asterix_field_tree2, current_uap[i]);
                }
            }
            else if (current_uap[i]->type & RE) {
                asterix_field_item = proto_tree_add_item (tree, *current_uap[i]->hf, tvb, offset + start, len, ENC_NA);
                asterix_field_tree = proto_item_add_subtree (asterix_field_item, ett_asterix_subtree);
                proto_tree_add_item (asterix_field_tree, hf_re_field_len, tvb, offset + start, 1, ENC_NA);
                start++;
                fspec_len = asterix_fspec_len (tvb, offset + start);
                proto_tree_add_item (asterix_field_tree, hf_asterix_fspec, tvb, offset + start, fspec_len, ENC_NA);
                dissect_asterix_fields (tvb, offset + start, asterix_field_tree, category, (const AsterixField **)current_uap[i]->field);
            }
            else {
                asterix_field_item = proto_tree_add_item (tree, *current_uap[i]->hf, tvb, offset + start, len, ENC_NA);
                asterix_field_tree = proto_item_add_subtree (asterix_field_item, ett_asterix_subtree);
                asterix_build_subtree (tvb, offset + start, asterix_field_tree, current_uap[i]);
            }
        }
    }
    return size;
}

static void asterix_build_subtree (tvbuff_t *tvb, guint offset, proto_tree *parent, const AsterixField *field)
{
    gint i, inner_offset;
    guint8 go_on;
    gint64 value;
    char *str_buffer = NULL;

    if (field->part != NULL) {
        for (i = 0, inner_offset = 0, go_on = 1; go_on && field->part[i] != NULL; i++) {
            value = tvb_get_bits64 (tvb, offset * 8 + inner_offset, field->part[i]->bit_length, ENC_BIG_ENDIAN);
            if (field->part[i]->hf != NULL) {
                switch (field->part[i]->type) {
                    case FIELD_PART_FX:
                        if (!value) go_on = 0;
                    case FIELD_PART_INT:
                    case FIELD_PART_UINT:
                    case FIELD_PART_HEX:
                    case FIELD_PART_ASCII:
                    case FIELD_PART_SQUAWK:
                        proto_tree_add_item (parent, *field->part[i]->hf, tvb, offset + inner_offset / 8, byte_length (field->part[i]->bit_length), ENC_BIG_ENDIAN);
                        break;
                    case FIELD_PART_FLOAT:
                        twos_complement (&value, field->part[i]->bit_length);
                    case FIELD_PART_UFLOAT:
                        if (field->part[i]->format_string != NULL)
                            proto_tree_add_double_format_value (parent, *field->part[i]->hf, tvb, offset + inner_offset / 8, byte_length (field->part[i]->bit_length), value * field->part[i]->scaling_factor, field->part[i]->format_string, value * field->part[i]->scaling_factor);
                        else
                            proto_tree_add_double (parent, *field->part[i]->hf, tvb, offset + inner_offset / 8, byte_length (field->part[i]->bit_length), value * field->part[i]->scaling_factor);
                        break;
                    case FIELD_PART_CALLSIGN:
                        str_buffer = (char *)wmem_alloc (wmem_packet_scope (), 9);
                        str_buffer[0] = '\0';
                        g_snprintf (str_buffer, 8, "%c%c%c%c%c%c%c%c, ", AISCode[(value >> 42) & 63],
                                                                         AISCode[(value >> 36) & 63],
                                                                         AISCode[(value >> 30) & 63],
                                                                         AISCode[(value >> 24) & 63],
                                                                         AISCode[(value >> 18) & 63],
                                                                         AISCode[(value >> 12) & 63],
                                                                         AISCode[(value >> 6) & 63],
                                                                         AISCode[value & 63]);
                        proto_tree_add_string (parent, *field->part[i]->hf, tvb, offset + inner_offset / 8, byte_length (field->part[i]->bit_length), str_buffer);
                        break;
                }
            }
            inner_offset += field->part[i]->bit_length;
        }
    } /* if not null */
}

static guint8 byte_length (guint8 bits)
{
    return (bits + 7) / 8;
}

static guint8 asterix_bit (guint8 b, guint8 bitNo)
{
    return bitNo < 8 && (b & (0x80 >> bitNo)) > 0;
}

/* Function makes gint64 two's complement.
 * Only the bit_len bit are set in gint64. All more significant
 * bits need to be set to have proper two's complement.
 * If the number is negative, all other bits must be set to 1.
 * If the number is positive, all other bits must remain 0. */
static void twos_complement (gint64 *v, guint8 bit_len)
{
    if (*v & (G_GUINT64_CONSTANT(1) << (bit_len - 1))) {
        *v |= (G_GUINT64_CONSTANT(0xffffffffffffffff) << bit_len);
    }
}

static guint8 asterix_fspec_len (tvbuff_t *tvb, guint offset)
{
    guint8 i;
    for (i = 0; (tvb_get_guint8 (tvb, offset + i) & 1) && i < tvb_reported_length (tvb) - offset; i++);
    return i + 1;
}

static guint8 asterix_field_exists (tvbuff_t *tvb, guint offset, int bitIndex)
{
    guint8 bitNo, i;
    bitNo = bitIndex + bitIndex / 7;
    for (i = 0; i < bitNo / 8; i++) {
        if (!(tvb_get_guint8 (tvb, offset + i) & 1)) return 0;
    }
    return asterix_bit (tvb_get_guint8 (tvb, offset + i), bitNo % 8);
}

static int asterix_field_length (tvbuff_t *tvb, guint offset, const AsterixField *field)
{
    guint size;
    guint64 count;
    guint8 i;

    size = 0;
    if (field->type & FIXED) {
        size = field->length;
    }
    else if (field->type & REPETITIVE) {
        for (i = 0, count = 0; i < field->repetition_counter_size && i < sizeof (count); i++)
            count = (count << 8) + tvb_get_guint8 (tvb, offset + i);
        size = (guint)(field->repetition_counter_size + count * field->length);
    }
    else if (field->type & FX) {
        for (size = field->length + field->header_length; tvb_get_guint8 (tvb, offset + size - 1) & 1; size += field->length);
    }
    else if (field->type & RE) {
        for (i = 0, size = 0; i < field->header_length; i++) {
            size = (size << 8) + tvb_get_guint8 (tvb, offset + i);
        }
    }
    else if (field->type & SP) {
        for (i = 0, size = 0; i < field->header_length; i++) {
            size = (size << 8) + tvb_get_guint8 (tvb, offset + i);
        }
    }
    else if (field->type & COMPOUND) {
        /* FSPEC */
        for (size = 0; tvb_get_guint8 (tvb, offset + size) & 1; size++);
        size++;

        for (i = 0; field->field[i] != NULL; i++) {
            if (asterix_field_exists (tvb, offset, i))
                size += asterix_field_length (tvb, offset + size, field->field[i]);
        }
    }
    return size;
}

/* This works for category 001. For other it may require changes. */
static guint8 asterix_get_active_uap (tvbuff_t *tvb, guint offset, guint8 category)
{
    int i, inner_offset;
    AsterixField **current_uap;

    if (categories[category] != NULL) { /* if category is supported */
        if (categories[category][global_categories_version[category]][1] != NULL) { /* if exists another uap */
            current_uap = (AsterixField **)categories[category][global_categories_version[category]][0];
            if (current_uap != NULL) {
                inner_offset = asterix_fspec_len (tvb, offset);
                for (i = 0; current_uap[i] != NULL; i++) {
                    if (asterix_field_exists (tvb, offset, i)) {
                        if (current_uap[i]->type & UAP) {
                            return tvb_get_guint8 (tvb, offset + inner_offset) >> 7;
                        }
                        inner_offset += asterix_field_length (tvb, offset + inner_offset, current_uap[i]);
                    }
                }
            }
        }
    }
    return 0;
}

static int asterix_field_offset (tvbuff_t *tvb, guint offset, const AsterixField *current_uap[], int field_index)
{
    int i, inner_offset;
    inner_offset = 0;
    if (asterix_field_exists (tvb, offset, field_index)) {
        inner_offset = asterix_fspec_len (tvb, offset);
        for (i = 0; i < field_index; i++) {
            if (asterix_field_exists (tvb, offset, i))
                inner_offset += asterix_field_length (tvb, offset + inner_offset, current_uap[i]);
        }
    }
    return inner_offset;
}

static int asterix_message_length (tvbuff_t *tvb, guint offset, guint8 category, guint8 active_uap)
{
    int i, size;
    AsterixField **current_uap;

    if (categories[category] != NULL) { /* if category is supported */
        current_uap = (AsterixField **)categories[category][global_categories_version[category]][active_uap];
        if (current_uap != NULL) {
            size = asterix_fspec_len (tvb, offset);
            for (i = 0; current_uap[i] != NULL; i++) {
                if (asterix_field_exists (tvb, offset, i)) {
                    size += asterix_field_length (tvb, offset + size, current_uap[i]);
                }
            }
            return size;
        }
    }
    return 0;
}

void proto_register_asterix (void)
{
    static hf_register_info hf[] = {
        { &hf_asterix_category, { "Category", "asterix.category", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_asterix_length, { "Length", "asterix.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_asterix_message, { "Asterix message", "asterix.message", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_asterix_fspec, { "FSPEC", "asterix.fspec", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_re_field_len, { "RE LEN", "asterix.re_field_len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_spare, { "Spare", "asterix.spare", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_counter, { "Counter", "asterix.counter", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_XXX_SAC, { "SAC", "asterix.SAC", FT_UINT8, BASE_DEC, NULL, 0x0, "SAC code of the source", HFILL } },
        { &hf_XXX_SIC, { "SIC", "asterix.SIC", FT_UINT8, BASE_DEC, NULL, 0x0, "SIC code of the source", HFILL } },
        { &hf_XXX_FX, { "FX", "asterix.FX", FT_UINT8, BASE_DEC, VALS (valstr_XXX_FX), 0x01, "Extension into next extent", HFILL } },
        /*{ &hf_XXX_2FX, { "FX", "asterix.FX", FT_UINT16, BASE_DEC, VALS (valstr_XXX_FX), 0x0001, "Extension into next extent", HFILL } },*/
        { &hf_XXX_3FX, { "FX", "asterix.FX", FT_UINT24, BASE_DEC, VALS (valstr_XXX_FX), 0x000001, "Extension into next extent", HFILL } },
        { &hf_XXX_TOD, { "[s]", "asterix.TOD", FT_DOUBLE, BASE_NONE, NULL, 0x0, "Time of day", HFILL } },
        { &hf_XXX_AA, { "Aircraft Address", "asterix.AA", FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_XXX_AI, { "Aircraft Identification", "asterix.AI", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_XXX_MB_DATA, { "MB DATA", "asterix.MB_DATA", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_XXX_BDS1, { "BDS1", "asterix.BDS1", FT_UINT8, BASE_DEC, NULL, 0xf0, NULL, HFILL } },
        { &hf_XXX_BDS2, { "BDS2", "asterix.BDS2", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL } },
        { &hf_XXX_TN_16, { "TN", "asterix.TN", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        /* Category 001 */
        { &hf_001_010, { "010, Data Source Identifier", "asterix.001_010", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_020, { "020, Target Report Descriptor", "asterix.001_020", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_020_TYP, { "TYP", "asterix.001_020_TYP", FT_UINT8, BASE_DEC, VALS (valstr_001_020_TYP), 0x80, NULL, HFILL } },
        { &hf_001_020_SIM, { "SIM", "asterix.001_020_SIM", FT_UINT8, BASE_DEC, VALS (valstr_001_020_SIM), 0x40, NULL, HFILL } },
        { &hf_001_020_SSR_PSR, { "SSR/PSR", "asterix.001_020_SSP_PSR", FT_UINT8, BASE_DEC, VALS (valstr_001_020_SSR_PSR), 0x30, NULL, HFILL } },
        { &hf_001_020_ANT, { "ANT", "asterix.001_020_ANT", FT_UINT8, BASE_DEC, VALS (valstr_001_020_ANT), 0x08, NULL, HFILL } },
        { &hf_001_020_SPI, { "SPI", "asterix.001_020_SPI", FT_UINT8, BASE_DEC, VALS (valstr_001_020_SPI), 0x04, NULL, HFILL } },
        { &hf_001_020_RAB, { "RAB", "asterix.001_020_RAB", FT_UINT8, BASE_DEC, VALS (valstr_001_020_RAB), 0x02, NULL, HFILL } },
        { &hf_001_020_TST, { "TST", "asterix.001_020_TST", FT_UINT8, BASE_DEC, VALS (valstr_001_020_TST), 0x80, NULL, HFILL } },
        { &hf_001_020_DS12, { "DS1/DS2", "asterix.001_020_DS12", FT_UINT8, BASE_DEC, VALS (valstr_001_020_DS12), 0x60, NULL, HFILL } },
        { &hf_001_020_ME, { "ME", "asterix.001_020_ME", FT_UINT8, BASE_DEC, VALS (valstr_001_020_ME), 0x10, NULL, HFILL } },
        { &hf_001_020_MI, { "MI", "asterix.001_020_MI", FT_UINT8, BASE_DEC, VALS (valstr_001_020_MI), 0x08, NULL, HFILL } },
        { &hf_001_030, { "030, Warning/Error Conditions", "asterix.001_030", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_030_WE, { "Warning/Error Condition", "asterix.001_030_WE", FT_UINT8, BASE_DEC, VALS (valstr_001_030_WE), 0xfe, NULL, HFILL } },
        { &hf_001_040, { "040, Measured Position in Polar Coordinates", "asterix.001_040", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_040_RHO, { "Rho[NM]", "asterix.001_040_RHO", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_040_THETA, { "Theta[deg]", "asterix.001_040_THETA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_042, { "042, Calculated Position in Cartesian Coordinates", "asterix.001_042", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_042_X, { "X[NM]", "asterix.001_042_X", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_042_Y, { "Y[NM]", "asterix.001_042_Y", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_050, { "050, Mode-2 Code in Octal Representation", "asterix.001_050", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_060, { "060, Mode-2 Code Confidence Indicator", "asterix.001_060", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_070, { "070, Mode-3/A Code in Octal Representation", "asterix.001_070", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_070_V, { "V", "asterix.001_070_V", FT_UINT8, BASE_DEC, VALS (valstr_001_070_V), 0x80, NULL, HFILL } },
        { &hf_001_070_G, { "G", "asterix.001_070_G", FT_UINT8, BASE_DEC, VALS (valstr_001_070_G), 0x40, NULL, HFILL } },
        { &hf_001_070_L, { "L", "asterix.001_070_L", FT_UINT8, BASE_DEC, VALS (valstr_001_070_L), 0x20, NULL, HFILL } },
        { &hf_001_070_SQUAWK, { "SQUAWK", "asterix.001_070_SQUAWK", FT_UINT16, BASE_OCT, NULL, 0x0fff, NULL, HFILL } },
        { &hf_001_080, { "080, Mode-3/A Code Confidence Indicator", "asterix.001_080", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_080_QA4, { "QA4", "asterix.001_080_QA4", FT_UINT8, BASE_DEC, VALS (valstr_001_080_QA), 0x08, NULL, HFILL } },
        { &hf_001_080_QA2, { "QA2", "asterix.001_080_QA2", FT_UINT8, BASE_DEC, VALS (valstr_001_080_QA), 0x04, NULL, HFILL } },
        { &hf_001_080_QA1, { "QA1", "asterix.001_080_QA1", FT_UINT8, BASE_DEC, VALS (valstr_001_080_QA), 0x02, NULL, HFILL } },
        { &hf_001_080_QB4, { "QB4", "asterix.001_080_QB4", FT_UINT8, BASE_DEC, VALS (valstr_001_080_QA), 0x01, NULL, HFILL } },
        { &hf_001_080_QB2, { "QB2", "asterix.001_080_QB2", FT_UINT8, BASE_DEC, VALS (valstr_001_080_QA), 0x80, NULL, HFILL } },
        { &hf_001_080_QB1, { "QB1", "asterix.001_080_QB1", FT_UINT8, BASE_DEC, VALS (valstr_001_080_QA), 0x40, NULL, HFILL } },
        { &hf_001_080_QC4, { "QC4", "asterix.001_080_QC4", FT_UINT8, BASE_DEC, VALS (valstr_001_080_QA), 0x20, NULL, HFILL } },
        { &hf_001_080_QC2, { "QC2", "asterix.001_080_QC2", FT_UINT8, BASE_DEC, VALS (valstr_001_080_QA), 0x10, NULL, HFILL } },
        { &hf_001_080_QC1, { "QC1", "asterix.001_080_QC1", FT_UINT8, BASE_DEC, VALS (valstr_001_080_QA), 0x08, NULL, HFILL } },
        { &hf_001_080_QD4, { "QD4", "asterix.001_080_QD4", FT_UINT8, BASE_DEC, VALS (valstr_001_080_QA), 0x04, NULL, HFILL } },
        { &hf_001_080_QD2, { "QD2", "asterix.001_080_QD2", FT_UINT8, BASE_DEC, VALS (valstr_001_080_QA), 0x02, NULL, HFILL } },
        { &hf_001_080_QD1, { "QD1", "asterix.001_080_QD1", FT_UINT8, BASE_DEC, VALS (valstr_001_080_QA), 0x01, NULL, HFILL } },
        { &hf_001_090, { "090, Mode-C Code in Binary Representation", "asterix.001_090", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_090_V, { "V", "asterix.001_090_V", FT_UINT8, BASE_DEC, VALS (valstr_001_090_V), 0x80, NULL, HFILL } },
        { &hf_001_090_G, { "G", "asterix.001_090_G", FT_UINT8, BASE_DEC, VALS (valstr_001_090_G), 0x40, NULL, HFILL } },
        { &hf_001_090_FL, { "FL", "asterix.001_090_FL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_100, { "100, Mode-C Code and Code Confidence Indicator", "asterix.001_100", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_120, { "120, Measured Radial Doppler Speed", "asterix.001_120", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_130, { "130, Radar Plot Characteristics", "asterix.001_130", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_131, { "131, Received Power", "asterix.001_131", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_141, { "141, Truncated Time of Day", "asterix.001_141", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_141_TTOD, { "TTOD", "asterix.001_141_TTOD", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_150, { "150, Presence of X-Pulse", "asterix.001_150", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_161, { "161, Track Plot Number", "asterix.001_161", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_161_TPN, { "TPN", "asterix.001_161_TPN", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_001_170, { "170, Track Status", "asterix.001_170", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_170_CON, { "CON", "asterix.001_170_CON", FT_UINT8, BASE_DEC, VALS (valstr_001_170_CON), 0x80, NULL, HFILL } },
        { &hf_001_170_RAD, { "RAD", "asterix.001_170_RAD", FT_UINT8, BASE_DEC, VALS (valstr_001_170_RAD), 0x40, NULL, HFILL } },
        { &hf_001_170_MAN, { "MAN", "asterix.001_170_MAN", FT_UINT8, BASE_DEC, VALS (valstr_001_170_MAN), 0x20, NULL, HFILL } },
        { &hf_001_170_DOU, { "DOU", "asterix.001_170_DOU", FT_UINT8, BASE_DEC, VALS (valstr_001_170_DOU), 0x10, NULL, HFILL } },
        { &hf_001_170_RDPC, { "RDPC", "asterix.001_170_RDPC", FT_UINT8, BASE_DEC, VALS (valstr_001_170_RDPC), 0x08, NULL, HFILL } },
        { &hf_001_170_GHO, { "GHO", "asterix.001_170_GHO", FT_UINT8, BASE_DEC, VALS (valstr_001_170_GHO), 0x02, NULL, HFILL } },
        { &hf_001_170_TRE, { "TRE", "asterix.001_170_TRE", FT_UINT8, BASE_DEC, VALS (valstr_001_170_TRE), 0x80, NULL, HFILL } },
        { &hf_001_200, { "200, Calculated Track Velocity in Polar Coordinates", "asterix.001_200", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_210, { "210, Track Quality", "asterix.001_210", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_RE, { "Reserved Field", "asterix.001_RE", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_SP, { "Special Field", "asterix.001_SP", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        /* Category 002 */
        { &hf_002_000, { "000, Message Type", "asterix.002_000", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_002_000_MT, { "MT", "asterix.002_000_MT", FT_UINT8, BASE_DEC, VALS (valstr_002_000_MT), 0x0, NULL, HFILL } },
        { &hf_002_010, { "010, Data Source Identifier", "asterix.002_010", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_002_020, { "020, Sector Number", "asterix.002_020", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_002_020_SN, { "Sector number", "asterix.002_020_SN", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_002_030, { "030, Time of Day", "asterix.002_030", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_002_041, { "041, Antenna Rotation Speed", "asterix.002_041", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_002_041_ARS, { "Antenna Rotation Speed", "asterix.002_041_ARN", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_002_050, { "050, Station Configuration Status", "asterix.002_050", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_002_060, { "060, Station Processing Mode", "asterix.002_060", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_002_070, { "070, Message Count Values", "asterix.002_070", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_002_070_A, { "A", "asterix.002_070_A", FT_UINT8, BASE_DEC, VALS (valstr_002_070_A), 0x80, NULL, HFILL } },
        { &hf_002_070_IDENT, { "IDENT", "asterix.002_070_V", FT_UINT8, BASE_DEC, VALS (valstr_002_070_IDENT), 0xeb, NULL, HFILL } },
        { &hf_002_070_COUNTER, { "COUNTER", "asterix.002_070_COUNTER", FT_UINT16, BASE_DEC, NULL, 0x03ff, NULL, HFILL } },
        { &hf_002_080, { "080, Warning/Error Conditions", "asterix.002_080", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_002_080_WE, { "W/E value", "asterix.002_080_WE", FT_UINT8, BASE_DEC, NULL, 0xfe, NULL, HFILL } },
        { &hf_002_090, { "090, Collimation Error", "asterix.002_090", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_002_090_RE, { "Range error[NM]", "asterix.002_090_RE", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_002_090_AE, { "Azimuth error[deg]", "asterix.002_090_AE", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_002_100, { "100, Dynamic Window - Type 1", "asterix.002_100", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_002_100_RHOS, { "Rho start[NM]", "asterix.002_100_RHOS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_002_100_RHOE, { "Rho end[NM]", "asterix.002_100_RHOE", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_002_100_THETAS, { "Theta start[deg]", "asterix.002_100_THETAS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_002_100_THETAE, { "Theta end[deg]", "asterix.002_100_THETAE", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_002_RE, { "Reserved Field", "asterix.002_RE", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_002_SP, { "Special Field", "asterix.002_SP", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        /* Category 008 */
        { &hf_008_000, { "000, Message Type", "asterix.008_000", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_008_000_MT, { "MT", "asterix.008_000_MT", FT_UINT8, BASE_DEC, VALS (valstr_008_000_MT), 0x0, NULL, HFILL } },
        { &hf_008_010, { "010, Data Source Identifier", "asterix.008_010", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_008_020, { "020, Vector Qualifier", "asterix.008_020", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_008_020_ORG, { "ORG", "asterix.008_020_ORG", FT_UINT8, BASE_DEC, VALS (valstr_008_020_ORG), 0x80, NULL, HFILL } },
        { &hf_008_020_INT, { "INT", "asterix.008_020_INT", FT_UINT8, BASE_DEC, NULL, 0x70, NULL, HFILL } },
        { &hf_008_020_DIR, { "DIR", "asterix.008_020_DIR", FT_UINT8, BASE_DEC, VALS (valstr_008_020_DIR), 0x0e, NULL, HFILL } },
        { &hf_008_020_TST, { "TST", "asterix.008_020_DIR", FT_UINT8, BASE_DEC, VALS (valstr_008_020_TST), 0x04, NULL, HFILL } },
        { &hf_008_020_ER, { "ER", "asterix.008_020_DIR", FT_UINT8, BASE_DEC, VALS (valstr_008_020_ER), 0x02, NULL, HFILL } },
        { &hf_008_034, { "034, Sequence of Polar Vectors in SPF Notation", "asterix.008_034", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_008_034_START_RANGE, { "START RANGE", "asterix.008_034_START_RANGE", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_008_034_END_RANGE, { "END RANGE", "asterix.008_034_END_RANGE", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_008_034_AZIMUTH, { "AZIMUTH", "asterix.008_034_AZIMUTH", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_008_036, { "036, Sequence of Cartesian Vectors in SPF Notation", "asterix.008_036", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_008_036_X, { "X", "asterix.008_036_X", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_008_036_Y, { "Y", "asterix.008_036_Y", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_008_036_VL, { "VL", "asterix.008_036_VL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_008_038, { "038, Sequence of Weather Vectors in SPF Notation", "asterix.008_038", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_008_038_X1, { "X1", "asterix.008_038_X1", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_008_038_Y1, { "Y1", "asterix.008_038_Y1", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_008_038_X2, { "X2", "asterix.008_038_X2", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_008_038_Y2, { "Y1", "asterix.008_038_Y1", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_008_040, { "040, Contour Identifier", "asterix.008_040", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_008_040_ORG, { "ORG", "asterix.008_040_ORG", FT_UINT8, BASE_DEC, VALS (valstr_008_040_ORG), 0x80, NULL, HFILL } },
        { &hf_008_040_INT, { "INT", "asterix.008_040_INT", FT_UINT8, BASE_DEC, NULL, 0x70, NULL, HFILL } },
        { &hf_008_040_FST_LST, { "FST/LST", "asterix.008_040_FST_LST", FT_UINT8, BASE_DEC, VALS (valstr_008_040_FST_LST), 0x03, NULL, HFILL } },
        { &hf_008_040_CSN, { "CSN", "asterix.008_040_CSN", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        { &hf_008_050, { "050, Sequence of Contour Points in SPF Notation", "asterix.008_050", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_008_050_X1, { "X1", "asterix.008_050_X1", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_008_050_Y1, { "Y1", "asterix.008_050_Y1", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_008_090, { "090, Time of Day", "asterix.008_090", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_008_100, { "100, Processing Status", "asterix.008_100", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_008_100_f, { "f", "asterix.008_100_f", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_008_100_R, { "R", "asterix.008_100_R", FT_UINT8, BASE_DEC, NULL, 0x03, NULL, HFILL } },
        { &hf_008_100_Q, { "Q", "asterix.008_100_Q", FT_UINT16, BASE_DEC, NULL, 0xfffe, NULL, HFILL } },
        { &hf_008_110, { "110, Station Configuration Status", "asterix.008_110", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_008_110_HW, { "HW", "asterix.008_110_HW", FT_UINT8, BASE_DEC, NULL, 0xfe, NULL, HFILL } },
        { &hf_008_120, { "120, Total Number of Items Constituting One Weather", "asterix.008_120", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_008_120_COUNT, { "COUNT", "asterix.008_120_COUNT", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_008_SP, { "SP, Sequence of Contour Points in SPF Notation", "asterix.008_SP", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_008_RFS, { "RFS, Sequence of Contour Points in SPF Notation", "asterix.008_RFS", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        /* Category 009 */
        { &hf_009_000, { "000, Message Type", "asterix.009_000", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_009_000_MT, { "MT", "asterix.009_000_MT", FT_UINT8, BASE_DEC, VALS (valstr_009_000_MT), 0x0, NULL, HFILL } },
        { &hf_009_010, { "010, Data Source Identifier", "asterix.009_010", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_009_020, { "020, Vector Qualifier", "asterix.009_020", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_009_020_ORG, { "ORG", "asterix.009_020_ORG", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL } },
        { &hf_009_020_INT, { "INT", "asterix.009_020_INT", FT_UINT8, BASE_DEC, VALS (valstr_009_020_INT), 0x70, NULL, HFILL } },
        { &hf_009_020_DIR, { "DIR", "asterix.009_020_DIR", FT_UINT8, BASE_DEC, VALS (valstr_009_020_DIR), 0x0e, NULL, HFILL } },
        { &hf_009_030, { "030, Sequence of Cartesian Vectors", "asterix.009_030", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_009_030_X, { "X", "asterix.009_030_X", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_009_030_Y, { "Y", "asterix.009_030_Y", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_009_030_VL, { "VL", "asterix.009_030_VL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_009_060, { "060, Synchronisation/Control Signal", "asterix.009_060", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_009_060_STEP, { "Step number", "asterix.009_060_STEP", FT_UINT8, BASE_DEC, NULL, 0xfc, NULL, HFILL } },
        { &hf_009_070, { "070, Time of Day", "asterix.009_070", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_009_080, { "080, Processing Status", "asterix.009_080", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_009_080_SCALE, { "Scaling factor", "asterix.009_080_SCALE", FT_UINT24, BASE_DEC, NULL, 0xf80000, NULL, HFILL } },
        { &hf_009_080_R, { "R", "asterix.009_080_R", FT_UINT24, BASE_DEC, NULL, 0x070000, NULL, HFILL } },
        { &hf_009_080_Q, { "Q", "asterix.009_080_Q", FT_UINT24, BASE_DEC, NULL, 0x00fffe, NULL, HFILL } },
        { &hf_009_090, { "090, Radar Configuration and Status", "asterix.009_090", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_009_090_CP, { "CP", "asterix.009_090_CP", FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL } },
        { &hf_009_090_WO, { "WO", "asterix.009_090_WO", FT_UINT8, BASE_DEC, NULL, 0x08, NULL, HFILL } },
        { &hf_009_090_RS, { "RS", "asterix.009_090_RS", FT_UINT8, BASE_DEC, NULL, 0x07, NULL, HFILL } },
        { &hf_009_100, { "100, Vector Count", "asterix.009_100", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_009_100_VC, { "VC", "asterix.009_030_VC", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        /* Category 021 */
        { &hf_021_008, { "008, Aircraft Operational Status", "asterix.021_008", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_008_RA, { "RA", "asterix.021_008_RA", FT_UINT8, BASE_DEC, VALS (valstr_021_008_RA), 0x80, NULL, HFILL } },
        { &hf_021_008_TC, { "TC", "asterix.021_008_TC", FT_UINT8, BASE_DEC, VALS (valstr_021_008_TC), 0x40, NULL, HFILL } },
        { &hf_021_008_TS, { "TS", "asterix.021_008_TS", FT_UINT8, BASE_DEC, VALS (valstr_021_008_TS), 0x10, NULL, HFILL } },
        { &hf_021_008_ARV, { "ARV", "asterix.021_008_ARV", FT_UINT8, BASE_DEC, VALS (valstr_021_008_ARV), 0x08, NULL, HFILL } },
        { &hf_021_008_CDTIA, { "CDTI/A", "asterix.021_008_CDTIA", FT_UINT8, BASE_DEC, VALS (valstr_021_008_CDTIA), 0x04, NULL, HFILL } },
        { &hf_021_008_not_TCAS, { "Not TCAS", "asterix.021_008_not_TCAS", FT_UINT8, BASE_DEC, VALS (valstr_021_008_not_TCAS), 0x02, NULL, HFILL } },
        { &hf_021_008_SA, { "SA", "asterix.021_008_SA", FT_UINT8, BASE_DEC, VALS (valstr_021_008_SA), 0x01, NULL, HFILL } },
        { &hf_021_010, { "010, Data Source Identification", "asterix.021_010", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_015, { "015, Service Identification", "asterix.021_015", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_015_SI, { "SI", "asterix.021_015_SI", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_021_016, { "016, Service Management", "asterix.021_016", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_016_RP, { "RP[s]", "asterix.021_016_RP", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_020, { "020, Emitter Category", "asterix.021_020", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_020_ECAT, { "ECAT", "asterix.021_020_ECAT", FT_UINT8, BASE_DEC, VALS (valstr_021_020_ECAT), 0x0, NULL, HFILL } },
        { &hf_021_040, { "040, Target Report Descriptor", "asterix.021_040", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_040_ATP, { "ATP", "asterix.021_040_ATP", FT_UINT8, BASE_DEC, VALS (valstr_021_040_ATP), 0xe0, NULL, HFILL } },
        { &hf_021_040_ARC, { "ARC", "asterix.021_040_ARC", FT_UINT8, BASE_DEC, VALS (valstr_021_040_ARC), 0x18, NULL, HFILL } },
        { &hf_021_040_RC, { "RC", "asterix.021_040_RC", FT_UINT8, BASE_DEC, VALS (valstr_021_040_RC), 0x04, NULL, HFILL } },
        { &hf_021_040_RAB, { "RAB", "asterix.021_040_RAB", FT_UINT8, BASE_DEC, VALS (valstr_021_040_RAB), 0x02, NULL, HFILL } },
        { &hf_021_040_DCR, { "DCR", "asterix.021_040_DCR", FT_UINT8, BASE_DEC, VALS (valstr_021_040_DCR), 0x80, NULL, HFILL } },
        { &hf_021_040_GBS, { "GBS", "asterix.021_040_GBS", FT_UINT8, BASE_DEC, VALS (valstr_021_040_GBS), 0x40, NULL, HFILL } },
        { &hf_021_040_SIM, { "SIM", "asterix.021_040_SIM", FT_UINT8, BASE_DEC, VALS (valstr_021_040_SIM), 0x20, NULL, HFILL } },
        { &hf_021_040_TST, { "TST", "asterix.021_040_TST", FT_UINT8, BASE_DEC, VALS (valstr_021_040_TST), 0x10, NULL, HFILL } },
        { &hf_021_040_SAA, { "SAA", "asterix.021_040_SAA", FT_UINT8, BASE_DEC, VALS (valstr_021_040_SAA), 0x08, NULL, HFILL } },
        { &hf_021_040_CL, { "CL", "asterix.021_040_CL", FT_UINT8, BASE_DEC, VALS (valstr_021_040_CL), 0x06, NULL, HFILL } },
        { &hf_021_040_IPC, { "IPC", "asterix.021_040_IPC", FT_UINT8, BASE_DEC, VALS (valstr_021_040_IPC), 0x20, NULL, HFILL } },
        { &hf_021_040_NOGO, { "NOGO", "asterix.021_040_NOGO", FT_UINT8, BASE_DEC, VALS (valstr_021_040_NOGO), 0x10, NULL, HFILL } },
        { &hf_021_040_CPR, { "CPR", "asterix.021_040_CPR", FT_UINT8, BASE_DEC, VALS (valstr_021_040_CPR), 0x08, NULL, HFILL } },
        { &hf_021_040_LDPJ, { "LDPJ", "asterix.021_040_LDPJ", FT_UINT8, BASE_DEC, VALS (valstr_021_040_LDPJ), 0x04, NULL, HFILL } },
        { &hf_021_040_RCF, { "RCF", "asterix.021_040_RCF", FT_UINT8, BASE_DEC, VALS (valstr_021_040_RCF), 0x02, NULL, HFILL } },
        { &hf_021_070, { "070, Mode 3/A Code in Octal Representation", "asterix.021_070", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_070_SQUAWK, { "SQUAWK", "asterix.021_070_SQUAWK", FT_UINT16, BASE_OCT, NULL, 0x0fff, NULL, HFILL } },
        { &hf_021_071, { "071, Time of Applicability for Position", "asterix.021_071", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_072, { "072, Time of Applicability for Velocity", "asterix.021_072", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_073, { "073, Time of Message Reception for Position", "asterix.021_073", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_074, { "074, Time of Message Reception of Position-High Precision", "asterix.021_074", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_074_FSI, { "FSI", "asterix.021_074_FSI", FT_UINT8, BASE_DEC, VALS (valstr_021_074_FSI), 0xc0, NULL, HFILL } },
        { &hf_021_074_TOMRP, { "TOMRp[s]", "asterix.021_074_TOMRP", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_075, { "075, Time of Message Reception for Velocity", "asterix.021_075", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_076, { "076, Time of Message Reception of Velocity-High Precision", "asterix.021_076", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_076_FSI, { "FSI", "asterix.021_076_FSI", FT_UINT8, BASE_DEC, VALS (valstr_021_076_FSI), 0xc0, NULL, HFILL } },
        { &hf_021_076_TOMRV, { "TOMRv[s]", "asterix.021_076_TOMRV", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_077, { "077, Time of ASTERIX Report Transmission", "asterix.021_077", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_080, { "080, Target Address", "asterix.021_080", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_090, { "090, Quality Indicators", "asterix.021_090", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_090_NUCR_NACV, { "NUCr or NACv", "asterix.021_090_NUCR_NACV", FT_UINT8, BASE_DEC, NULL, 0xe0, NULL, HFILL } },
        { &hf_021_090_NUCP_NIC, { "NUCp or NIC", "asterix.021_090_NUCP_NIC", FT_UINT8, BASE_DEC, NULL, 0x1e, NULL, HFILL } },
        { &hf_021_090_NIC_BARO, { "NIC BARO", "asterix.021_090_NIC_BARO", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL } },
        { &hf_021_090_SIL, { "SIL", "asterix.021_090_SIL", FT_UINT8, BASE_DEC, NULL, 0x60, NULL, HFILL } },
        { &hf_021_090_NACP, { "NACP", "asterix.021_090_NACP", FT_UINT8, BASE_DEC, NULL, 0x1e, NULL, HFILL } },
        { &hf_021_090_SIL_SUP, { "SIL-supplement", "asterix.021_090_SIL_SUP", FT_UINT8, BASE_DEC, VALS (valstr_021_090_SIL_SUP), 0x20, NULL, HFILL } },
        { &hf_021_090_SDA, { "SDA", "asterix.021_090_SDA", FT_UINT8, BASE_DEC, NULL, 0x18, NULL, HFILL } },
        { &hf_021_090_GVA, { "GVA", "asterix.021_090_GVA", FT_UINT8, BASE_DEC, NULL, 0x06, NULL, HFILL } },
        { &hf_021_090_PIC, { "PIC", "asterix.021_090_PIC", FT_UINT8, BASE_DEC, NULL, 0xf0, NULL, HFILL } },
        { &hf_021_110, { "110, Trajectory Intent", "asterix.021_110", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_110_01, { "#01: Trajectory Intent Status", "asterix.021_110_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_110_01_NAV, { "NAV", "asterix.021_110_01_NAV", FT_UINT8, BASE_DEC, VALS (valstr_021_110_01_NAV), 0x80, NULL, HFILL } },
        { &hf_021_110_01_NVB, { "NVB", "asterix.021_110_01_NVB", FT_UINT8, BASE_DEC, VALS (valstr_021_110_01_NVB), 0x40, NULL, HFILL } },
        { &hf_021_110_02, { "#02: Trajectory Intent Data", "asterix.021_110_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_110_02_TCA, { "TCA", "asterix.021_110_02_TCA", FT_UINT8, BASE_DEC, VALS (valstr_021_110_02_TCA), 0x80, NULL, HFILL } },
        { &hf_021_110_02_NC, { "NC", "asterix.021_110_02_NC", FT_UINT8, BASE_DEC, VALS (valstr_021_110_02_NC), 0x40, NULL, HFILL } },
        { &hf_021_110_02_TCPNo, { "TCP number", "asterix.021_110_TCPNo", FT_UINT8, BASE_DEC, NULL, 0x3f, NULL, HFILL } },
        { &hf_021_110_02_ALT, { "Altitude [ft]", "asterix.021_110_02_ALT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_110_02_LAT, { "Latitude [deg]", "asterix.021_110_02_LAT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_110_02_LON, { "Longitude [deg]", "asterix.021_110_02_LON", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_110_02_PT, { "PT", "asterix.021_110_02_PT", FT_UINT8, BASE_DEC, VALS (valstr_021_110_02_PT), 0xf0, NULL, HFILL } },
        { &hf_021_110_02_TD, { "TD", "asterix.021_110_02_TD", FT_UINT8, BASE_DEC, VALS (valstr_021_110_02_TD), 0x0e, NULL, HFILL } },
        { &hf_021_110_02_TRA, { "TRA", "asterix.021_110_02_TRA", FT_UINT8, BASE_DEC, VALS (valstr_021_110_02_TRA), 0x02, NULL, HFILL } },
        { &hf_021_110_02_TOA, { "TOA", "asterix.021_110_02_TOA", FT_UINT8, BASE_DEC, VALS (valstr_021_110_02_TOA), 0x01, NULL, HFILL } },
        { &hf_021_110_02_TOV, { "Time Over Point [s]", "asterix.021_110_02_TOV", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_110_02_TTR, { "TCP Turn radius [Nm]", "asterix.021_110_02_TTR", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_130, { "130, Position in WGS-84 Co-ordinates", "asterix.021_130", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_130_LAT, { "Latitude [deg]", "asterix.021_130_LAT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_130_LON, { "Longitude [deg]", "asterix.021_130_LON", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_131, { "131, High-Resolution Position in WGS-84 Co-ordinates", "asterix.021_131", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_131_LAT, { "Latitude [deg]", "asterix.021_131_LAT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_131_LON, { "Longitude [deg]", "asterix.021_131_LON", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_132, { "132, Message Amplitude", "asterix.021_132", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_132_MAM, { "MAM [dBm]", "asterix.021_132_MAM", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_140, { "140, Geometric Height", "asterix.021_140", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_140_GH, { "GH [ft]", "asterix.021_140_GH", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_145, { "145, Flight Level", "asterix.021_145", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_145_FL, { "FL", "asterix.021_145_FL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_146, { "146, Selected Altitude", "asterix.021_146", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_146_SAS, { "SAS", "asterix.021_146_SAS", FT_UINT8, BASE_DEC, VALS (valstr_021_146_SAS), 0x80, NULL, HFILL } },
        { &hf_021_146_Source, { "Source", "asterix.021_146_Source", FT_UINT8, BASE_DEC, VALS (valstr_021_146_Source), 0x40, NULL, HFILL } },
        { &hf_021_146_ALT, { "Altitude [ft]", "asterix.021_146_ALT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_148, { "148, Final State Selected Altitude", "asterix.021_148", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_148_MV, { "MV", "asterix.021_148_MV", FT_UINT8, BASE_DEC, VALS (valstr_021_148_MV), 0x80, NULL, HFILL } },
        { &hf_021_148_AH, { "AH", "asterix.021_148_AH", FT_UINT8, BASE_DEC, VALS (valstr_021_148_AH), 0x40, NULL, HFILL } },
        { &hf_021_148_AM, { "AM", "asterix.021_148_AM", FT_UINT8, BASE_DEC, VALS (valstr_021_148_AM), 0x20, NULL, HFILL } },
        { &hf_021_148_ALT, { "Altitude [ft]", "asterix.021_148_ALT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_150, { "150, Air Speed", "asterix.021_150", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_150_IM, { "IM", "asterix.021_150_IM", FT_UINT8, BASE_DEC, VALS (valstr_021_150_IM), 0x80, NULL, HFILL } },
        { &hf_021_150_ASPD, { "ASPD [2^-14NM/s or 0.001Mach]", "asterix.021_150_ASPD", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_151, { "151 True Airspeed", "asterix.021_151", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_151_RE, { "RE", "asterix.021_151_RE", FT_UINT8, BASE_DEC, VALS (valstr_021_151_RE), 0x80, NULL, HFILL } },
        { &hf_021_151_TASPD, { "TASPD [knot]", "asterix.021_151_TASPD", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_152, { "152, Magnetic Heading", "asterix.021_152", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_152_MHDG, { "MHDG [deg]", "asterix.021_152_MHDG", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_155, { "155, Barometric Vertical Rate", "asterix.021_155", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_155_RE, { "RE", "asterix.021_155_RE", FT_UINT8, BASE_DEC, VALS (valstr_021_155_RE), 0x80, NULL, HFILL } },
        { &hf_021_155_BVR, { "BVR [ft/min]", "asterix.021_155_BVR", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_157, { "157, Geometric Vertical Rate", "asterix.021_157", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_157_RE, { "RE", "asterix.021_157_RE", FT_UINT8, BASE_DEC, VALS (valstr_021_157_RE), 0x80, NULL, HFILL } },
        { &hf_021_157_GVR, { "GVR [ft/min]", "asterix.021_157_GVR", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_160, { "160, Airborne Ground Vector", "asterix.021_160", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_160_RE, { "RE", "asterix.021_160_RE", FT_UINT8, BASE_DEC, VALS (valstr_021_160_RE), 0x80, NULL, HFILL } },
        { &hf_021_160_GSPD, { "Ground speed [NM/s]", "asterix.021_160_GSPD", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_160_TA, { "Track angle [deg]", "asterix.021_160_TA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_161, { "161, Track Number", "asterix.021_161", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_161_TN, { "TN", "asterix.021_161", FT_UINT8, BASE_DEC, NULL, 0x0fff, NULL, HFILL } },
        { &hf_021_165, { "165, Track Angle Rate", "asterix.021_165", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_165_TAR, { "TAR [deg/s]", "asterix.021_165_TAR", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_170, { "170, Target Identification", "asterix.021_170", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_200, { "200, Target Status", "asterix.021_200", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_200_ICF, { "ICF", "asterix.021_200_ICF", FT_UINT8, BASE_DEC, VALS (valstr_021_200_ICF), 0x80, NULL, HFILL } },
        { &hf_021_200_LNAV, { "LNAV", "asterix.021_200_LNAV", FT_UINT8, BASE_DEC, VALS (valstr_021_200_LNAV), 0x40, NULL, HFILL } },
        { &hf_021_200_PS, { "PS", "asterix.021_200_PS", FT_UINT8, BASE_DEC, VALS (valstr_021_200_PS), 0x1c, NULL, HFILL } },
        { &hf_021_200_SS, { "SS", "asterix.021_200_SS", FT_UINT8, BASE_DEC, VALS (valstr_021_200_SS), 0x03, NULL, HFILL } },
        { &hf_021_210, { "210, MOPS Version", "asterix.021_210", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_210_VNS, { "VNS", "asterix.021_210_VNS", FT_UINT8, BASE_DEC, VALS (valstr_021_210_VNS), 0x40, NULL, HFILL } },
        { &hf_021_210_VN, { "VN", "asterix.021_210_VN", FT_UINT8, BASE_DEC, VALS (valstr_021_210_VN), 0x38, NULL, HFILL } },
        { &hf_021_210_LTT, { "LTT", "asterix.021_210_LTT", FT_UINT8, BASE_DEC, VALS (valstr_021_210_LTT), 0x07, NULL, HFILL } },
        { &hf_021_220, { "220, Met Information", "asterix.021_220", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_220_01, { "#01: Wind Speed", "asterix.021_220_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_220_01_WSPD, { "WSPD [knot]", "asterix.021_220_01_WSPD", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_220_02, { "#02: Wind Direction", "asterix.021_220_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_220_02_WDIR, { "WDIR [deg]", "asterix.021_220_02_WDIR", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_220_03, { "#03: Temperature", "asterix.021_220_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_220_03_TEMP, { "TEMP [deg C]", "asterix.021_220_03_TEMP", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_220_04, { "#04: Turbulence", "asterix.021_220_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_220_04_TURB, { "TURB", "asterix.021_220_04_TURB", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_021_230, { "230, Roll Angle", "asterix.021_230", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_230_RA, { "RA [deg]", "asterix.021_230_RA", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_250, { "250, Mode S MB Data", "asterix.021_250", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_260, { "260, ACAS Resolution Advisory Report", "asterix.021_260", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_260_TYP, { "TYP", "asterix.021_260_TYP", FT_UINT8, BASE_DEC, NULL, 0xf8, NULL, HFILL } },
        { &hf_021_260_STYP, { "STYP", "asterix.021_260_STYP", FT_UINT8, BASE_DEC, NULL, 0x07, NULL, HFILL } },
        { &hf_021_260_ARA, { "ARA", "asterix.021_260_ARA", FT_UINT16, BASE_DEC, NULL, 0xfffc, NULL, HFILL } },
        { &hf_021_260_RAC, { "RAC", "asterix.021_260_RAC", FT_UINT16, BASE_DEC, NULL, 0x03c0, NULL, HFILL } },
        { &hf_021_260_RAT, { "RAT", "asterix.021_260_RAT", FT_UINT8, BASE_DEC, NULL, 0x20, NULL, HFILL } },
        { &hf_021_260_MTE, { "MTE", "asterix.021_260_MTE", FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL } },
        { &hf_021_260_TTI, { "TTI", "asterix.021_260_TTI", FT_UINT8, BASE_DEC, NULL, 0x0c, NULL, HFILL } },
        { &hf_021_260_TID, { "TID", "asterix.021_260_TID", FT_UINT32, BASE_DEC, NULL, 0x03ffffff, NULL, HFILL } },
        { &hf_021_271, { "271, Surface Capabilities and Characteristics", "asterix.021_271", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_271_POA, { "POA", "asterix.021_271_POA", FT_UINT8, BASE_DEC, VALS (valstr_021_271_POA), 0x20, NULL, HFILL } },
        { &hf_021_271_CDTIS, { "CDTI/S", "asterix.021_271_CDTIS", FT_UINT8, BASE_DEC, VALS (valstr_021_271_CDTIS), 0x10, NULL, HFILL } },
        { &hf_021_271_B2low, { "B2low", "asterix.021_271_B2low", FT_UINT8, BASE_DEC, VALS (valstr_021_271_B2low), 0x08, NULL, HFILL } },
        { &hf_021_271_RAS, { "RAS", "asterix.021_271_RAS", FT_UINT8, BASE_DEC, VALS (valstr_021_271_RAS), 0x04, NULL, HFILL } },
        { &hf_021_271_IDENT, { "IDENT", "asterix.021_271_IDENT", FT_UINT8, BASE_DEC, VALS (valstr_021_271_IDENT), 0x02, NULL, HFILL } },
        { &hf_021_271_LW, { "L+W", "asterix.021_271_LW", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL } },
        { &hf_021_295, { "295, Data Ages", "asterix.021_295", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_01, { "#01: Aircraft Operational Status age", "asterix.021_295_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_01_AOS, { "AOS [s]", "asterix.021_295_01_AOS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_02, { "#02: Target Report Descriptor age", "asterix.021_295_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_02_TRD, { "TRD [s]", "asterix.021_295_02_TRD", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_03, { "#03: Mode 3/A Code age", "asterix.021_295_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_03_M3A, { "M3A [s]", "asterix.021_295_03_M3A", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_04, { "#04: Quality Indicators age", "asterix.021_295_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_04_QI, { "QI [s]", "asterix.021_295_04_QI", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_05, { "#05: Trajectory Intent age", "asterix.021_295_05", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_05_TI, { "TI [s]", "asterix.021_295_05_TI", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_06, { "#06: Message Amplitude age", "asterix.021_295_06", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_06_MAM, { "MAM [s]", "asterix.021_295_06_MAM", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_07, { "#07: Geometric Height age", "asterix.021_295_07", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_07_GH, { "GH [s]", "asterix.021_295_07_GH", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_08, { "#08: Flight Level age", "asterix.021_295_08", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_08_FL, { "FL [s]", "asterix.021_295_08_FL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_09, { "#09: Intermediate State Selected Altitude age", "asterix.021_295_09", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_09_ISA, { "ISA [s]", "asterix.021_295_09_ISA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_10, { "#10: Final State Selected Altitude age", "asterix.021_295_10", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_10_FSA, { "FSA [s]", "asterix.021_295_10_FSA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_11, { "#11: Air Speed age", "asterix.021_295_11", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_11_AS, { "AS [s]", "asterix.021_295_11_AS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_12, { "#12: True Air Speed age", "asterix.021_295_12", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_12_TAS, { "TAS [s]", "asterix.021_295_12_TAS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_13, { "#13: Magnetic Heading age", "asterix.021_295_13", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_13_MH, { "MH [s]", "asterix.021_295_13_MH", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_14, { "#14: Barometric Vertical Rate age", "asterix.021_295_14", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_14_BVR, { "BVR [s]", "asterix.021_295_14_BVR", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_15, { "#15: Geometric Vertical Rate age", "asterix.021_295_15", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_15_GVR, { "GVR [s]", "asterix.021_295_15_GVR", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_16, { "#16: Ground Vector age", "asterix.021_295_16", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_16_GV, { "GV [s]", "asterix.021_295_16_GV", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_17, { "#17: Track Angle Rate age", "asterix.021_295_17", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_17_TAR, { "TAR [s]", "asterix.021_295_17_TAR", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_18, { "#18: Target Identification age", "asterix.021_295_18", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_18_TI, { "TI [s]", "asterix.021_295_18_TI", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_19, { "#19: Target Status age", "asterix.021_295_19", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_19_TS, { "TS [s]", "asterix.021_295_19_TS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_20, { "#20: Met Information age", "asterix.021_295_20", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_20_MET, { "MET [s]", "asterix.021_295_20_MET", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_21, { "#21: Roll Angle age", "asterix.021_295_21", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_21_ROA, { "ROA [s]", "asterix.021_295_21_ROA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_22, { "#22: ACAS Resolution Advisory age", "asterix.021_295_22", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_22_ARA, { "ARA [s]", "asterix.021_295_22_ARA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_23, { "#23: Surface Capabilities and Characteristics age", "asterix.021_295_23", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_295_23_SCC, { "SCC [s]", "asterix.021_295_23_SCC", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_400, { "400, Receiver ID", "asterix.021_400", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_400_RID, { "RID", "asterix.021_400_RID", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_021_RE, { "Reserved Field", "asterix.021_RE", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_SP, { "Special Field", "asterix.021_SP", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        /* Category 023 */
        { &hf_023_000, { "000, Report Type", "asterix.023_000", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_023_000_RT, { "RT", "asterix.023_000_RT", FT_UINT8, BASE_DEC, VALS (valstr_023_000_RT), 0x0, NULL, HFILL } },
        { &hf_023_010, { "010, Data Source Identifier", "asterix.023_010", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_023_015, { "015, Service Type and Identification", "asterix.023_015", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_023_015_SID, { "SID", "asterix.023_015_SID", FT_UINT8, BASE_DEC, NULL, 0xf0, NULL, HFILL } },
        { &hf_023_015_STYPE, { "STYPE", "asterix.023_015_STYPE", FT_UINT8, BASE_DEC, VALS (valstr_023_015_STYP), 0x0f, NULL, HFILL } },
        { &hf_023_070, { "070, Time of Day", "asterix.023_070", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_023_100, { "100, Ground Station Status", "asterix.023_100", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_023_100_NOGO, { "NOGO", "asterix.023_100_NOGO", FT_UINT8, BASE_DEC, VALS (valstr_023_100_NOGO), 0x80, NULL, HFILL } },
        { &hf_023_100_ODP, { "ODP", "asterix.023_100_ODP", FT_UINT8, BASE_DEC, VALS (valstr_023_100_ODP), 0x40, NULL, HFILL } },
        { &hf_023_100_OXT, { "OXT", "asterix.023_100_OXT", FT_UINT8, BASE_DEC, VALS (valstr_023_100_OXT), 0x20, NULL, HFILL } },
        { &hf_023_100_MSC, { "MSC", "asterix.023_100_MSC", FT_UINT8, BASE_DEC, VALS (valstr_023_100_MSC), 0x10, NULL, HFILL } },
        { &hf_023_100_TSV, { "TSV", "asterix.023_100_TSV", FT_UINT8, BASE_DEC, VALS (valstr_023_100_TSV), 0x08, NULL, HFILL } },
        { &hf_023_100_SPO, { "SPO", "asterix.023_100_SPO", FT_UINT8, BASE_DEC, VALS (valstr_023_100_SPO), 0x04, NULL, HFILL } },
        { &hf_023_100_RN, { "RN", "asterix.023_100_RN", FT_UINT8, BASE_DEC, VALS (valstr_023_100_RN), 0x02, NULL, HFILL } },
        { &hf_023_100_GSSP, { "GSSP [s]", "asterix.023_100_GSSP", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_023_101, { "101, Service Configuration", "asterix.023_101", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_023_101_RP, { "RP [s]", "asterix.023_101_RP", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_023_101_SC, { "SC", "asterix.023_101_SC", FT_UINT8, BASE_DEC, VALS (valstr_023_101_SC), 0xe0, NULL, HFILL } },
        { &hf_023_101_SSRP, { "SSRP [s]", "asterix.023_101_SSRP", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_023_110, { "110, Service Status", "asterix.023_110", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_023_110_STAT, { "STAT", "asterix.023_110_STAT", FT_UINT8, BASE_DEC, VALS (valstr_023_110_STAT), 0x0e, NULL, HFILL } },
        { &hf_023_120, { "120, Service Statistics", "asterix.023_120", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_023_120_TYPE, { "TYPE", "asterix.023_120_TYPE", FT_UINT8, BASE_DEC, VALS (valstr_023_120_TYPE), 0x0, NULL, HFILL } },
        { &hf_023_120_REF, { "REF", "asterix.023_120_REF", FT_UINT8, BASE_DEC, VALS (valstr_023_120_REF), 0x80, NULL, HFILL } },
        { &hf_023_120_COUNTER, { "COUNTER", "asterix.023_120_COUNTER", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_023_200, { "200, Operational Range", "asterix.023_200", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_023_200_RANGE, { "RANGE [NM]", "asterix.023_200_RANGE", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_023_RE, { "Reserved Field", "asterix.023_RE", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_023_SP, { "Special Field", "asterix.023_SP", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        /* Category 034 */
        { &hf_034_000, { "000, Message Type", "asterix.034_000", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_000_MT, { "MT", "asterix.034_000_MT", FT_UINT8, BASE_DEC, VALS (valstr_034_000_MT), 0x0, NULL, HFILL } },
        { &hf_034_010, { "010, Data Source Identifier", "asterix.034_010", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_020, { "020, Sector Number", "asterix.034_020", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_020_SN, { "Sector number", "asterix.034_020_SN", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_030, { "030, Time of Day", "asterix.034_030", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_041, { "041, Antenna Rotation Speed", "asterix.034_041", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_041_ARS, { "Antenna Rotation Speed", "asterix.034_041_ARN", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_050, { "050, System Configuration and Status", "asterix.034_050", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_050_01, { "COM", "asterix.034_050_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_050_01_NOGO, { "Operational Release Status of the System", "asterix.034_050_01_NOGO", FT_UINT8, BASE_DEC, VALS (valstr_034_050_01_NOGO), 0x80, NULL, HFILL } },
        { &hf_034_050_01_RDPC, { "Radar Data Processor Chain Selection Status", "asterix.034_050_01_RDPC", FT_UINT8, BASE_DEC, VALS (valstr_034_050_01_RDPC), 0x40, NULL, HFILL } },
        { &hf_034_050_01_RDPR, { "Event to signal a reset/restart of the selected Radar Data Processor Chain, i.e. expect a new assignment of track numbers", "asterix.034_050_01_RDPR", FT_UINT8, BASE_DEC, VALS (valstr_034_050_01_RDPR), 0x20, NULL, HFILL } },
        { &hf_034_050_01_OVL_RDP, { "Radar Data Processor Overload Indicator", "asterix.034_050_01_OVL_RDP", FT_UINT8, BASE_DEC, VALS (valstr_034_050_01_OVL_RDP), 0x10, NULL, HFILL } },
        { &hf_034_050_01_OVL_XMT, { "Transmission Subsystem Overload Status", "asterix.034_050_01_OVL_XMT", FT_UINT8, BASE_DEC, VALS (valstr_034_050_01_OVL_XMT), 0x08, NULL, HFILL } },
        { &hf_034_050_01_MSC, { "Monitoring System Connected Status", "asterix.034_050_01_MSC", FT_UINT8, BASE_DEC, VALS (valstr_034_050_01_MSC), 0x04, NULL, HFILL } },
        { &hf_034_050_01_TSV, { "Time Source Validity", "asterix.034_050_01_TSV", FT_UINT8, BASE_DEC, VALS (valstr_034_050_01_TSV), 0x02, NULL, HFILL } },
        { &hf_034_050_02, { "Specific Status information for a PSR sensor", "asterix.034_050_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_050_02_ANT, { "Selected antenna", "asterix.034_050_02_ANT", FT_UINT8, BASE_DEC, VALS (valstr_034_050_02_ANT), 0x80, NULL, HFILL } },
        { &hf_034_050_02_CHAB, { "Channel A/B selection status", "asterix.034_050_02_CHAB", FT_UINT8, BASE_DEC, VALS (valstr_034_050_02_CHAB), 0x60, NULL, HFILL } },
        { &hf_034_050_02_OVL, { "Overload condition", "asterix.034_050_02_OVL", FT_UINT8, BASE_DEC, VALS (valstr_034_050_02_OVL), 0x10, NULL, HFILL } },
        { &hf_034_050_02_MSC, { "Monitoring System Connected Status", "asterix.034_050_02_MSC", FT_UINT8, BASE_DEC, VALS (valstr_034_050_02_MSC), 0x08, NULL, HFILL } },
        { &hf_034_050_03, { "Specific Status information for a SSR sensor", "asterix.034_050_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_050_03_ANT, { "Selected antenna", "asterix.034_050_03_ANT", FT_UINT8, BASE_DEC, VALS (valstr_034_050_03_ANT), 0x80, NULL, HFILL } },
        { &hf_034_050_03_CHAB, { "Channel A/B selection status", "asterix.034_050_03_CHAB", FT_UINT8, BASE_DEC, VALS (valstr_034_050_03_CHAB), 0x60, NULL, HFILL } },
        { &hf_034_050_03_OVL, { "Overload condition", "asterix.034_050_03_OVL", FT_UINT8, BASE_DEC, VALS (valstr_034_050_03_OVL), 0x10, NULL, HFILL } },
        { &hf_034_050_03_MSC, { "Monitoring System Connected Status", "asterix.034_050_03_MSC", FT_UINT8, BASE_DEC, VALS (valstr_034_050_03_MSC), 0x08, NULL, HFILL } },
        { &hf_034_050_04, { "Specific Status information for a Mode S sensor", "asterix.034_050_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_050_04_ANT, { "Selected antenna", "asterix.034_050_04_ANT", FT_UINT8, BASE_DEC, VALS (valstr_034_050_04_ANT), 0x80, NULL, HFILL } },
        { &hf_034_050_04_CHAB, { "Channel A/B selection status for surveillance", "asterix.034_050_04_CHAB", FT_UINT8, BASE_DEC, VALS (valstr_034_050_04_CHAB), 0x60, NULL, HFILL } },
        { &hf_034_050_04_OVL_SUR, { "Overload condition", "asterix.034_050_04_OVL_SUR", FT_UINT8, BASE_DEC, VALS (valstr_034_050_04_OVL_SUR), 0x10, NULL, HFILL } },
        { &hf_034_050_04_MSC, { "Monitoring System Connected Status", "asterix.034_050_04_MSC", FT_UINT8, BASE_DEC, VALS (valstr_034_050_04_MSC), 0x08, NULL, HFILL } },
        { &hf_034_050_04_SCF, { "Channel A/B selection status for Surveillance Co-ordination Function", "asterix.034_050_04_SCF", FT_UINT8, BASE_DEC, VALS (valstr_034_050_04_SCF), 0x04, NULL, HFILL } },
        { &hf_034_050_04_DLF, { "Channel A/B selection status for Data Link Function", "asterix.034_050_04_DLF", FT_UINT8, BASE_DEC, VALS (valstr_034_050_04_DLF), 0x02, NULL, HFILL } },
        { &hf_034_050_04_OVL_SCF, { "Overload in Surveillance", "asterix.034_050_04_OVL_SCF", FT_UINT8, BASE_DEC, VALS (valstr_034_050_04_OVL_SCF), 0x01, NULL, HFILL } },
        { &hf_034_050_04_OVL_DLF, { "Overload in Data Link Function", "asterix.034_050_04_OVL_DLF", FT_UINT8, BASE_DEC, VALS (valstr_034_050_04_OVL_DLF), 0x80, NULL, HFILL } },
        { &hf_034_060, { "060, System Processing Mode", "asterix.034_060", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_060_01, { "COM", "asterix.034_060_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_060_01_RED_RDP, { "Reduction Steps in use for an overload of the RDP", "asterix.034_060_01_RED_RDP", FT_UINT8, BASE_DEC, VALS (valstr_034_060_RED), 0x70, NULL, HFILL } },
        { &hf_034_060_01_RED_XMT, { "Reduction Steps in use for an overload of the Transmission subsystem", "asterix.034_060_01_RED_XMT", FT_UINT8, BASE_DEC, VALS (valstr_034_060_RED), 0x0e, NULL, HFILL } },
        { &hf_034_060_02, { "Specific Processing Mode information for a PSR sensor", "asterix.034_060_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_060_02_POL, { "Polarization in use by PSR", "asterix.034_060_02_POL", FT_UINT8, BASE_DEC, VALS (valstr_034_060_02_POL), 0x80, NULL, HFILL } },
        { &hf_034_060_02_RED_RAD, { "Reduction Steps in use as result of an overload within the PSR subsystem", "asterix.034_060_02_RED_RDP", FT_UINT8, BASE_DEC, VALS (valstr_034_060_RED), 0x70, NULL, HFILL } },
        { &hf_034_060_02_STC, { "Sensitivity Time Control Map in use", "asterix.034_060_02_STC", FT_UINT8, BASE_DEC, VALS (valstr_034_060_02_STC), 0x70, NULL, HFILL } },
        { &hf_034_060_03, { "Specific Processing Mode information for a SSR sensor", "asterix.034_060_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_060_03_RED_RAD, { "Reduction Steps in use as result of an overload within the SSR subsystem", "asterix.034_060_03_RED_RDP", FT_UINT8, BASE_DEC, VALS (valstr_034_060_RED), 0xe0, NULL, HFILL } },
        { &hf_034_060_04, { "Specific Processing Mode information for a Mode S Sensor", "asterix.034_060_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_060_04_RED_RAD, { "Reduction Steps in use as result of an overload within the Mode S subsystem", "asterix.034_060_04_RED_RDP", FT_UINT8, BASE_DEC, VALS (valstr_034_060_RED), 0xe0, NULL, HFILL } },
        { &hf_034_060_04_CLU, { "Cluster State", "asterix.034_060_04_CLU", FT_UINT8, BASE_DEC, VALS (valstr_034_060_04_CLU), 0x10, NULL, HFILL } },
        { &hf_034_070, { "070, Message Count Values", "asterix.034_070", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_070_TYP, { "Type of message counter", "asterix.034_070_TYP", FT_UINT8, BASE_DEC, VALS (valstr_034_070_TYP), 0xf8, NULL, HFILL } },
        { &hf_034_070_COUNTER, { "COUNTER", "asterix.034_070_COUNTER", FT_UINT16, BASE_DEC, NULL, 0x07ff, NULL, HFILL } },
        { &hf_034_090, { "090, Collimation Error", "asterix.034_090", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_090_RE, { "Range error[NM]", "asterix.034_090_RE", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_090_AE, { "Azimuth error[deg]", "asterix.034_090_AE", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_100, { "100, Generic Polar Window", "asterix.034_100", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_035_100_RHOS, { "Rho start[NM]", "asterix.034_100_RHOS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_035_100_RHOE, { "Rho end[NM]", "asterix.034_100_RHOE", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_035_100_THETAS, { "Theta start[deg]", "asterix.034_100_THETAS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_035_100_THETAE, { "Theta end[deg]", "asterix.034_100_THETAE", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_110, { "110, Data Filter", "asterix.034_110", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_110_TYP, { "TYP", "asterix.034_100_TYP", FT_UINT8, BASE_DEC, VALS (valstr_034_110_TYP), 0x0, NULL, HFILL } },
        { &hf_034_120, { "120, 3D-Position Of Data Source", "asterix.034_120", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_120_H, { "Height in WGS 84[m]", "asterix.034_120_H", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_120_LAT, { "Latitude in WGS 84[deg]", "asterix.034_120_LAT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_120_LON, { "Longitude in WGS 84[deg]", "asterix.034_120_LON", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_RE, { "Reserved Field", "asterix.034_RE", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_SP, { "Special Field", "asterix.034_SP", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        /* Category 048 */
        { &hf_048_010, { "010, Data Source Identifier", "asterix.048_010", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_020, { "020, Target Report Descriptor", "asterix.048_020", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_020_TYP, { "TYP", "asterix.048_020_TYP", FT_UINT8, BASE_DEC, VALS (valstr_048_020_TYP), 0xe0, "Type of detection", HFILL } },
        { &hf_048_020_SIM, { "SIM", "asterix.048_020_SIM", FT_UINT8, BASE_DEC, VALS (valstr_048_020_SIM), 0x10, "Simulated od Actual target", HFILL } },
        { &hf_048_020_RDP, { "RDP", "asterix.048_020_RDP", FT_UINT8, BASE_DEC, VALS (valstr_048_020_RDP), 0x08, "RDP CHain", HFILL } },
        { &hf_048_020_SPI, { "SPI", "asterix.048_020_SPI", FT_UINT8, BASE_DEC, VALS (valstr_048_020_SPI), 0x04, "Special Position Identification", HFILL } },
        { &hf_048_020_RAB, { "RAB", "asterix.048_020_RAB", FT_UINT8, BASE_DEC, VALS (valstr_048_020_RAB), 0x02, "Report from aircraft or field monitor", HFILL } },
        { &hf_048_020_TST, { "TST", "asterix.048_020_TST", FT_UINT8, BASE_DEC, VALS (valstr_048_020_TST), 0x80, "Real or test target", HFILL } },
        { &hf_048_020_ME, { "ME", "asterix.048_020_ME", FT_UINT8, BASE_DEC, VALS (valstr_048_020_ME), 0x10, "Military emergency", HFILL } },
        { &hf_048_020_MI, { "MI", "asterix.048_020_MI", FT_UINT8, BASE_DEC, VALS (valstr_048_020_MI), 0x08, "Military identification", HFILL } },
        { &hf_048_020_FOE, { "FOE/FRI", "asterix.048_020_FOE", FT_UINT8, BASE_DEC, VALS (valstr_048_020_FOE), 0x06, "Foe of friend", HFILL } },
        { &hf_048_030, { "030, Warning/Error Conditions", "asterix.048_030", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_030_WE, { "W/E value", "asterix.048_030_WE", FT_UINT8, BASE_DEC, VALS (valstr_048_030_WE), 0xfe, NULL, HFILL } },
        { &hf_048_040, { "040, Measured Position in Polar Co-ordinates", "asterix.048_040", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_040_RHO, { "RHO[NM]", "asterix.048_040_RHO", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_040_THETA, { "THETA[deg]", "asterix.048_040_THETA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_042, { "042, Calculated Position in Cartesian Co-ordinates", "asterix.048_042", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_042_X, { "X[NM]", "asterix.048_042_X", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_042_Y, { "Y[deg]", "asterix.048_042_Y", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_050, { "050, Mode-2 Code in Octal Representation", "asterix.048_050", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_050_V, { "V", "asterix.048_050_V", FT_UINT8, BASE_DEC, VALS (valstr_048_050_V), 0x80, NULL, HFILL } },
        { &hf_048_050_G, { "G", "asterix.048_050_G", FT_UINT8, BASE_DEC, VALS (valstr_048_050_G), 0x40, NULL, HFILL } },
        { &hf_048_050_L, { "L", "asterix.048_050_L", FT_UINT8, BASE_DEC, VALS (valstr_048_050_L), 0x20, NULL, HFILL } },
        { &hf_048_050_SQUAWK, { "SQUAWK", "asterix.048_050_SQUAWK", FT_UINT16, BASE_OCT, NULL, 0x0fff, NULL, HFILL } },
        { &hf_048_055, { "055, Mode-1 Code in Octal Representation", "asterix.048_055", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_055_V, { "V", "asterix.048_055_V", FT_UINT8, BASE_DEC, VALS (valstr_048_055_V), 0x80, NULL, HFILL } },
        { &hf_048_055_G, { "G", "asterix.048_055_G", FT_UINT8, BASE_DEC, VALS (valstr_048_055_G), 0x40, NULL, HFILL } },
        { &hf_048_055_L, { "L", "asterix.048_055_L", FT_UINT8, BASE_DEC, VALS (valstr_048_055_L), 0x20, NULL, HFILL } },
        { &hf_048_055_CODE, { "CODE", "asterix.048_055_CODE", FT_UINT8, BASE_OCT, NULL, 0x1f, NULL, HFILL } },
        { &hf_048_060, { "060, Mode-2 Code Confidence Indicator", "asterix.048_060", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_060_QA4, { "QA4", "asterix.048_060_QA4", FT_UINT8, BASE_DEC, VALS (valstr_048_060_QA), 0x08, NULL, HFILL } },
        { &hf_048_060_QA2, { "QA2", "asterix.048_060_QA2", FT_UINT8, BASE_DEC, VALS (valstr_048_060_QA), 0x04, NULL, HFILL } },
        { &hf_048_060_QA1, { "QA1", "asterix.048_060_QA1", FT_UINT8, BASE_DEC, VALS (valstr_048_060_QA), 0x02, NULL, HFILL } },
        { &hf_048_060_QB4, { "QB4", "asterix.048_060_QB4", FT_UINT8, BASE_DEC, VALS (valstr_048_060_QA), 0x01, NULL, HFILL } },
        { &hf_048_060_QB2, { "QB2", "asterix.048_060_QB2", FT_UINT8, BASE_DEC, VALS (valstr_048_060_QA), 0x80, NULL, HFILL } },
        { &hf_048_060_QB1, { "QB1", "asterix.048_060_QB1", FT_UINT8, BASE_DEC, VALS (valstr_048_060_QA), 0x40, NULL, HFILL } },
        { &hf_048_060_QC4, { "QC4", "asterix.048_060_QC4", FT_UINT8, BASE_DEC, VALS (valstr_048_060_QA), 0x20, NULL, HFILL } },
        { &hf_048_060_QC2, { "QC2", "asterix.048_060_QC2", FT_UINT8, BASE_DEC, VALS (valstr_048_060_QA), 0x10, NULL, HFILL } },
        { &hf_048_060_QC1, { "QC1", "asterix.048_060_QC1", FT_UINT8, BASE_DEC, VALS (valstr_048_060_QA), 0x08, NULL, HFILL } },
        { &hf_048_060_QD4, { "QD4", "asterix.048_060_QD4", FT_UINT8, BASE_DEC, VALS (valstr_048_060_QA), 0x04, NULL, HFILL } },
        { &hf_048_060_QD2, { "QD2", "asterix.048_060_QD2", FT_UINT8, BASE_DEC, VALS (valstr_048_060_QA), 0x02, NULL, HFILL } },
        { &hf_048_060_QD1, { "QD1", "asterix.048_060_QD1", FT_UINT8, BASE_DEC, VALS (valstr_048_060_QA), 0x01, NULL, HFILL } },
        { &hf_048_065, { "065, Mode-1 Code Confidence Indicator", "asterix.048_065", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_065_QA4, { "QA4", "asterix.048_065_QA4", FT_UINT8, BASE_DEC, VALS (valstr_048_065_QA), 0x10, NULL, HFILL } },
        { &hf_048_065_QA2, { "QA2", "asterix.048_065_QA2", FT_UINT8, BASE_DEC, VALS (valstr_048_065_QA), 0x08, NULL, HFILL } },
        { &hf_048_065_QA1, { "QA1", "asterix.048_065_QA1", FT_UINT8, BASE_DEC, VALS (valstr_048_065_QA), 0x04, NULL, HFILL } },
        { &hf_048_065_QB2, { "QB2", "asterix.048_065_QB2", FT_UINT8, BASE_DEC, VALS (valstr_048_065_QA), 0x02, NULL, HFILL } },
        { &hf_048_065_QB1, { "QB1", "asterix.048_065_QB1", FT_UINT8, BASE_DEC, VALS (valstr_048_065_QA), 0x01, NULL, HFILL } },
        { &hf_048_070, { "070, Mode-3/A Code in Octal Representation", "asterix.048_070", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_070_V, { "V", "asterix.048_070_V", FT_UINT8, BASE_DEC, VALS (valstr_048_070_V), 0x80, NULL, HFILL } },
        { &hf_048_070_G, { "G", "asterix.048_070_G", FT_UINT8, BASE_DEC, VALS (valstr_048_070_G), 0x40, NULL, HFILL } },
        { &hf_048_070_L, { "L", "asterix.048_070_L", FT_UINT8, BASE_DEC, VALS (valstr_048_070_L), 0x20, NULL, HFILL } },
        { &hf_048_070_SQUAWK, { "SQUAWK", "asterix.048_070_SQUAWK", FT_UINT16, BASE_OCT, NULL, 0x0fff, NULL, HFILL } },
        { &hf_048_080, { "080, Mode-3/A Code Confidence Indicator", "asterix.048_080", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_080_QA4, { "QA4", "asterix.048_080_QA4", FT_UINT8, BASE_DEC, VALS (valstr_048_080_QA), 0x08, NULL, HFILL } },
        { &hf_048_080_QA2, { "QA2", "asterix.048_080_QA2", FT_UINT8, BASE_DEC, VALS (valstr_048_080_QA), 0x04, NULL, HFILL } },
        { &hf_048_080_QA1, { "QA1", "asterix.048_080_QA1", FT_UINT8, BASE_DEC, VALS (valstr_048_080_QA), 0x02, NULL, HFILL } },
        { &hf_048_080_QB4, { "QB4", "asterix.048_080_QB4", FT_UINT8, BASE_DEC, VALS (valstr_048_080_QA), 0x01, NULL, HFILL } },
        { &hf_048_080_QB2, { "QB2", "asterix.048_080_QB2", FT_UINT8, BASE_DEC, VALS (valstr_048_080_QA), 0x80, NULL, HFILL } },
        { &hf_048_080_QB1, { "QB1", "asterix.048_080_QB1", FT_UINT8, BASE_DEC, VALS (valstr_048_080_QA), 0x40, NULL, HFILL } },
        { &hf_048_080_QC4, { "QC4", "asterix.048_080_QC4", FT_UINT8, BASE_DEC, VALS (valstr_048_080_QA), 0x20, NULL, HFILL } },
        { &hf_048_080_QC2, { "QC2", "asterix.048_080_QC2", FT_UINT8, BASE_DEC, VALS (valstr_048_080_QA), 0x10, NULL, HFILL } },
        { &hf_048_080_QC1, { "QC1", "asterix.048_080_QC1", FT_UINT8, BASE_DEC, VALS (valstr_048_080_QA), 0x08, NULL, HFILL } },
        { &hf_048_080_QD4, { "QD4", "asterix.048_080_QD4", FT_UINT8, BASE_DEC, VALS (valstr_048_080_QA), 0x04, NULL, HFILL } },
        { &hf_048_080_QD2, { "QD2", "asterix.048_080_QD2", FT_UINT8, BASE_DEC, VALS (valstr_048_080_QA), 0x02, NULL, HFILL } },
        { &hf_048_080_QD1, { "QD1", "asterix.048_080_QD1", FT_UINT8, BASE_DEC, VALS (valstr_048_080_QA), 0x01, NULL, HFILL } },
        { &hf_048_090, { "090, Flight Level in Binary Representation", "asterix.048_090", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_090_V, { "V", "asterix.048_090_V", FT_UINT8, BASE_DEC, VALS (valstr_048_090_V), 0x80, NULL, HFILL } },
        { &hf_048_090_G, { "G", "asterix.048_090_G", FT_UINT8, BASE_DEC, VALS (valstr_048_090_G), 0x40, NULL, HFILL } },
        { &hf_048_090_FL, { "FL", "asterix.048_090_FL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_100, { "100, Mode-C Code and Code Confidence Indicator", "asterix.048_100", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_100_V, { "V", "asterix.048_100_V", FT_UINT8, BASE_DEC, VALS (valstr_048_100_V), 0x80, NULL, HFILL } },
        { &hf_048_100_G, { "G", "asterix.048_100_G", FT_UINT8, BASE_DEC, VALS (valstr_048_100_G), 0x40, NULL, HFILL } },
        { &hf_048_100_A4, { "A4", "asterix.048_100_A4", FT_UINT8, BASE_DEC, NULL, 0x08, NULL, HFILL } },
        { &hf_048_100_A2, { "A2", "asterix.048_100_A2", FT_UINT8, BASE_DEC, NULL, 0x04, NULL, HFILL } },
        { &hf_048_100_A1, { "A1", "asterix.048_100_A1", FT_UINT8, BASE_DEC, NULL, 0x02, NULL, HFILL } },
        { &hf_048_100_B4, { "B4", "asterix.048_100_B4", FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL } },
        { &hf_048_100_B2, { "B2", "asterix.048_100_B2", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL } },
        { &hf_048_100_B1, { "B1", "asterix.048_100_B1", FT_UINT8, BASE_DEC, NULL, 0x40, NULL, HFILL } },
        { &hf_048_100_C4, { "C4", "asterix.048_100_C4", FT_UINT8, BASE_DEC, NULL, 0x20, NULL, HFILL } },
        { &hf_048_100_C2, { "C2", "asterix.048_100_C2", FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL } },
        { &hf_048_100_C1, { "C1", "asterix.048_100_C1", FT_UINT8, BASE_DEC, NULL, 0x08, NULL, HFILL } },
        { &hf_048_100_D4, { "D4", "asterix.048_100_D4", FT_UINT8, BASE_DEC, NULL, 0x04, NULL, HFILL } },
        { &hf_048_100_D2, { "D2", "asterix.048_100_D2", FT_UINT8, BASE_DEC, NULL, 0x02, NULL, HFILL } },
        { &hf_048_100_D1, { "D1", "asterix.048_100_D1", FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL } },
        { &hf_048_100_QA4, { "QA4", "asterix.048_100_QA4", FT_UINT8, BASE_DEC, VALS (valstr_048_100_QA), 0x08, NULL, HFILL } },
        { &hf_048_100_QA2, { "QA2", "asterix.048_100_QA2", FT_UINT8, BASE_DEC, VALS (valstr_048_100_QA), 0x04, NULL, HFILL } },
        { &hf_048_100_QA1, { "QA1", "asterix.048_100_QA1", FT_UINT8, BASE_DEC, VALS (valstr_048_100_QA), 0x02, NULL, HFILL } },
        { &hf_048_100_QB4, { "QB4", "asterix.048_100_QB4", FT_UINT8, BASE_DEC, VALS (valstr_048_100_QA), 0x01, NULL, HFILL } },
        { &hf_048_100_QB2, { "QB2", "asterix.048_100_QB2", FT_UINT8, BASE_DEC, VALS (valstr_048_100_QA), 0x80, NULL, HFILL } },
        { &hf_048_100_QB1, { "QB1", "asterix.048_100_QB1", FT_UINT8, BASE_DEC, VALS (valstr_048_100_QA), 0x40, NULL, HFILL } },
        { &hf_048_100_QC4, { "QC4", "asterix.048_100_QC4", FT_UINT8, BASE_DEC, VALS (valstr_048_100_QA), 0x20, NULL, HFILL } },
        { &hf_048_100_QC2, { "QC2", "asterix.048_100_QC2", FT_UINT8, BASE_DEC, VALS (valstr_048_100_QA), 0x10, NULL, HFILL } },
        { &hf_048_100_QC1, { "QC1", "asterix.048_100_QC1", FT_UINT8, BASE_DEC, VALS (valstr_048_100_QA), 0x08, NULL, HFILL } },
        { &hf_048_100_QD4, { "QD4", "asterix.048_100_QD4", FT_UINT8, BASE_DEC, VALS (valstr_048_100_QA), 0x04, NULL, HFILL } },
        { &hf_048_100_QD2, { "QD2", "asterix.048_100_QD2", FT_UINT8, BASE_DEC, VALS (valstr_048_100_QA), 0x02, NULL, HFILL } },
        { &hf_048_100_QD1, { "QD1", "asterix.048_100_QD1", FT_UINT8, BASE_DEC, VALS (valstr_048_100_QA), 0x01, NULL, HFILL } },
        { &hf_048_110, { "110, Height Measured by a 3D Radar", "asterix.048_110", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_110_3DHEIGHT, { "3D-Height [feet]", "asterix.048_110_3DHEIGHT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_120, { "120, Radial Doppler Speed", "asterix.048_120", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_120_01, { "Subfield #1: Calculated Doppler Speed", "asterix.048_120_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_120_01_D, { "D", "asterix.048_120_01_D", FT_UINT8, BASE_DEC, VALS (valstr_048_120_01_D), 0x80, NULL, HFILL } },
        { &hf_048_120_01_CAL, { "CAL[m/s]", "asterix.048_120_01_CAL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_120_02, { "Subfield # 2: Raw Doppler Speed", "asterix.048_120_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_120_02_DOP, { "DOP[m/s]", "asterix.048_120_02_DOP", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_120_02_AMB, { "AMB[m/s]", "asterix.048_120_02_AMB", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_120_02_FRQ, { "FRQ[MHz]", "asterix.048_120_02_FRQ", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_130, { "130, Radar Plot Characteristics", "asterix.048_130", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_130_01, { "#1: SSR Plot Runlength", "asterix.048_130_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_130_01_SRL, { "SRL[deg]", "asterix.048_130_01_SRL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_130_02, { "#2: Number of Received Replies for (M)SSR", "asterix.048_130_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_130_02_SRR, { "SRR", "asterix.048_130_02_SRR", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_048_130_03, { "#3: Amplitude of (M)SSR Reply", "asterix.048_130_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_130_03_SAM, { "SAM[dBm]", "asterix.048_130_03_SAM", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_048_130_04, { "#4: Primary Plot Runlength", "asterix.048_130_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_130_04_PRL, { "PRL[deg]", "asterix.048_130_04_PRL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_130_05, { "#5: Amplitude of Primary Plot", "asterix.048_130_05", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_130_05_PAM, { "PAM[dBm]", "asterix.048_130_05_PAM", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_048_130_06, { "#6: Difference in Range between PSR and SSR plot", "asterix.048_130_06", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_130_06_RPD, { "RPD[NM]", "asterix.048_130_06_RPD", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_130_07, { "#7: Difference in Azimuth between PSR and SSR plot", "asterix.048_130_07", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_130_07_APD, { "APD[deg]", "asterix.048_130_07_APD", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_140, { "140, Time of Day", "asterix.048_140", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_161, { "161, Track Number", "asterix.048_161", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_161_TN, { "TN", "asterix.048_161_TN", FT_UINT16, BASE_DEC, NULL, 0x0fff, NULL, HFILL } },
        { &hf_048_170, { "170, Track Status", "asterix.048_170", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_170_CNF, { "CNF", "asterix.048_170_CNF", FT_UINT8, BASE_DEC, VALS (valstr_048_170_CNF), 0x80, "Confirmed vs. Tentative Track", HFILL } },
        { &hf_048_170_RAD, { "RAD", "asterix.048_170_RAD", FT_UINT8, BASE_DEC, VALS (valstr_048_170_RAD), 0x60, "Type of Sensor(s) maintaining Track", HFILL } },
        { &hf_048_170_DOU, { "DOU", "asterix.048_170_DOU", FT_UINT8, BASE_DEC, VALS (valstr_048_170_DOU), 0x10, "Signals level of confidence in plot to track association process", HFILL } },
        { &hf_048_170_MAH, { "MAH", "asterix.048_170_MAH", FT_UINT8, BASE_DEC, VALS (valstr_048_170_MAH), 0x08, "Manoeuvre detection in Horizontal Sense", HFILL } },
        { &hf_048_170_CDM, { "CDM", "asterix.048_170_CDM", FT_UINT8, BASE_DEC, VALS (valstr_048_170_CDM), 0x06, "Climbing / Descending Mode", HFILL } },
        { &hf_048_170_TRE, { "TRE", "asterix.048_170_TRE", FT_UINT8, BASE_DEC, VALS (valstr_048_170_TRE), 0x80, "Signal for End_of_Track", HFILL } },
        { &hf_048_170_GHO, { "GHO", "asterix.048_170_GHO", FT_UINT8, BASE_DEC, VALS (valstr_048_170_GHO), 0x40, "Ghost vs. true target", HFILL } },
        { &hf_048_170_SUP, { "SUP", "asterix.048_170_SUP", FT_UINT8, BASE_DEC, VALS (valstr_048_170_SUP), 0x20, "Track maintained with track information from neighbouring Node B on the cluster, or network", HFILL } },
        { &hf_048_170_TCC, { "TCC", "asterix.048_170_TCC", FT_UINT8, BASE_DEC, VALS (valstr_048_170_TCC), 0x10, "Type of plot coordinate transformation mechanism", HFILL } },
        { &hf_048_200, { "200, Calculated Track Velocity in Polar Co-ordinates", "asterix.048_200", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_200_GS, { "Calculated groundspeed[NM/s]", "asterix.048_200_GS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_200_HDG, { "Calculated heading[deg]", "asterix.048_200_HDG", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_210, { "210, Track Quality", "asterix.048_210", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_210_X, { "Sigma (X)[NM]", "asterix.048_210_X", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_210_Y, { "Sigma (Y)[NM]", "asterix.048_210_Y", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_210_V, { "Sigma (V)[NM/s]", "asterix.048_210_V", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_210_H, { "Sigma (H)[deg]", "asterix.048_210_H", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_220, { "220, Aircraft Address", "asterix.048_220", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_230, { "230, Communications/ACAS Capability and Flight Status", "asterix.048_230", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_230_COM, { "COM", "asterix.048_230_COM", FT_UINT8, BASE_DEC, VALS (valstr_048_230_COM), 0xe0, "Communications capabiltiy of the transponder", HFILL } },
        { &hf_048_230_STAT, { "STAT", "asterix.048_230_STAT", FT_UINT8, BASE_DEC, VALS (valstr_048_230_STAT), 0x1c, "Flight status", HFILL } },
        { &hf_048_230_SI, { "SI", "asterix.048_230_SI", FT_UINT8, BASE_DEC, VALS (valstr_048_230_SI), 0x02, "SI/II Transponder Capability", HFILL } },
        { &hf_048_230_MSSC, { "MSSC", "asterix.048_230_MSSC", FT_UINT8, BASE_DEC, VALS (valstr_048_230_MSSC), 0x80, "Mode-S Specific Service Capability", HFILL } },
        { &hf_048_230_ARC, { "ARC", "asterix.048_230_ARC", FT_UINT8, BASE_DEC, VALS (valstr_048_230_ARC), 0x40, "Altitude reporting capability", HFILL } },
        { &hf_048_230_AIC, { "AIC", "asterix.048_230_AIC", FT_UINT8, BASE_DEC, VALS (valstr_048_230_AIC), 0x20, "Aircraft identification capability", HFILL } },
        { &hf_048_230_B1A, { "B1A", "asterix.048_230_B1A", FT_UINT8, BASE_DEC, NULL, 0x10, "BDS 1,0 bit 16", HFILL } },
        { &hf_048_230_B1B, { "B1B", "asterix.048_230_B1B", FT_UINT8, BASE_DEC, NULL, 0x0f, "BDS 1,0 bits 37/40", HFILL } },
        { &hf_048_240, { "240, Aircraft Identification", "asterix.048_240", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_250, { "250, Mode S MB Data", "asterix.048_250", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_260, { "260, ACAS Resolution Advisory Report", "asterix.048_260", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_260_ACAS, { "ACAS", "asterix.048_260_ACAS", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE, { "Reserved Expansion Field", "asterix.048_RE", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_SP, { "Special Purpose Field", "asterix.048_SP", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        /* Category 062*/
        { &hf_062_010, { "010, Data Source Identifier", "asterix.062_010", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_015, { "015, Service Identification", "asterix.062_015", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_015_SI, { "SI", "asterix.062_015_SI", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_062_040, { "040, Track Number", "asterix.062_040", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_060, { "060, Track Mode 3/A Code", "asterix.062_060", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_060_CH, { "CH", "asterix.062_060_CH", FT_UINT8, BASE_DEC, VALS (valstr_062_060_CH), 0x20, "Change in Mode 3/A", HFILL } },
        { &hf_062_060_SQUAWK, { "SQUAWK", "asterix.062_060_SQUAWK", FT_UINT16, BASE_OCT, NULL, 0x0fff, NULL, HFILL } },
        { &hf_062_070, { "070, Time Of Track Information", "asterix.062_070", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_080, { "080, Track Status", "asterix.062_080", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_080_MON, { "MON", "asterix.062_080_MON", FT_UINT8, BASE_DEC, VALS (valstr_062_080_MON), 0x80, NULL, HFILL } },
        { &hf_062_080_SPI, { "SPI", "asterix.062_080_SPI", FT_UINT8, BASE_DEC, VALS (valstr_062_080_SPI), 0x40, NULL, HFILL } },
        { &hf_062_080_MRH, { "MRH", "asterix.062_080_MRH", FT_UINT8, BASE_DEC, VALS (valstr_062_080_MRH), 0x20, NULL, HFILL } },
        { &hf_062_080_SRC, { "SRC", "asterix.062_080_SRC", FT_UINT8, BASE_DEC, VALS (valstr_062_080_SRC), 0x1c, NULL, HFILL } },
        { &hf_062_080_CNF, { "CNF", "asterix.062_080_CNF", FT_UINT8, BASE_DEC, VALS (valstr_062_080_CNF), 0x02, NULL, HFILL } },
        { &hf_062_080_SIM, { "SIM", "asterix.062_080_SIM", FT_UINT8, BASE_DEC, VALS (valstr_062_080_SIM), 0x80, NULL, HFILL } },
        { &hf_062_080_TSE, { "TSE", "asterix.062_080_TSE", FT_UINT8, BASE_DEC, VALS (valstr_062_080_TSE), 0x40, NULL, HFILL } },
        { &hf_062_080_TSB, { "TSB", "asterix.062_080_TSB", FT_UINT8, BASE_DEC, VALS (valstr_062_080_TSB), 0x20, NULL, HFILL } },
        { &hf_062_080_FPC, { "FPC", "asterix.062_080_FPC", FT_UINT8, BASE_DEC, VALS (valstr_062_080_FPC), 0x10, NULL, HFILL } },
        { &hf_062_080_AFF, { "AFF", "asterix.062_080_AFF", FT_UINT8, BASE_DEC, VALS (valstr_062_080_AFF), 0x08, NULL, HFILL } },
        { &hf_062_080_STP, { "STP", "asterix.062_080_STP", FT_UINT8, BASE_DEC, VALS (valstr_062_080_STP), 0x04, NULL, HFILL } },
        { &hf_062_080_KOS, { "KOS", "asterix.062_080_KOS", FT_UINT8, BASE_DEC, VALS (valstr_062_080_KOS), 0x02, NULL, HFILL } },
        { &hf_062_080_AMA, { "AMA", "asterix.062_080_AMA", FT_UINT8, BASE_DEC, VALS (valstr_062_080_AMA), 0x80, NULL, HFILL } },
        { &hf_062_080_MD4, { "MD4", "asterix.062_080_MD4", FT_UINT8, BASE_DEC, VALS (valstr_062_080_MD4), 0x60, NULL, HFILL } },
        { &hf_062_080_ME, { "ME", "asterix.062_080_ME", FT_UINT8, BASE_DEC, VALS (valstr_062_080_ME), 0x10, NULL, HFILL } },
        { &hf_062_080_MI, { "MI", "asterix.062_080_MI", FT_UINT8, BASE_DEC, VALS (valstr_062_080_MI), 0x08, NULL, HFILL } },
        { &hf_062_080_MD5, { "MD5", "asterix.062_080_MD5", FT_UINT8, BASE_DEC, VALS (valstr_062_080_MD5), 0x06, NULL, HFILL } },
        { &hf_062_080_CST, { "CST", "asterix.062_080_CST", FT_UINT8, BASE_DEC, VALS (valstr_062_080_CST), 0x80, NULL, HFILL } },
        { &hf_062_080_PSR, { "PSR", "asterix.062_080_PSR", FT_UINT8, BASE_DEC, VALS (valstr_062_080_PSR), 0x40, NULL, HFILL } },
        { &hf_062_080_SSR, { "SSR", "asterix.062_080_SSR", FT_UINT8, BASE_DEC, VALS (valstr_062_080_SSR), 0x20, NULL, HFILL } },
        { &hf_062_080_MDS, { "MDS", "asterix.062_080_MDS", FT_UINT8, BASE_DEC, VALS (valstr_062_080_MDS), 0x10, NULL, HFILL } },
        { &hf_062_080_ADS, { "ADS", "asterix.062_080_ADS", FT_UINT8, BASE_DEC, VALS (valstr_062_080_ADS), 0x08, NULL, HFILL } },
        { &hf_062_080_SUC, { "SUC", "asterix.062_080_SUC", FT_UINT8, BASE_DEC, VALS (valstr_062_080_SUC), 0x04, NULL, HFILL } },
        { &hf_062_080_AAC, { "AAC", "asterix.062_080_AAC", FT_UINT8, BASE_DEC, VALS (valstr_062_080_AAC), 0x02, NULL, HFILL } },
        { &hf_062_080_SDS, { "SDS", "asterix.062_080_SDS", FT_UINT8, BASE_DEC, VALS (valstr_062_080_SDS), 0xe0, NULL, HFILL } },
        { &hf_062_080_EMS, { "EMS", "asterix.062_080_EMS", FT_UINT8, BASE_DEC, VALS (valstr_062_080_EMS), 0x38, NULL, HFILL } },
        { &hf_062_080_PFT, { "PFT", "asterix.062_080_PFT", FT_UINT8, BASE_DEC, VALS (valstr_062_080_PFT), 0x04, NULL, HFILL } },
        { &hf_062_080_FPLT, { "FPLT", "asterix.062_080_FPLT", FT_UINT8, BASE_DEC, VALS (valstr_062_080_FPLT), 0x02, NULL, HFILL } },
        { &hf_062_080_DUPT, { "DUPT", "asterix.062_080_DUPT", FT_UINT8, BASE_DEC, VALS (valstr_062_080_DUPT), 0x80, NULL, HFILL } },
        { &hf_062_080_DUPF, { "DUPT", "asterix.062_080_DUPF", FT_UINT8, BASE_DEC, VALS (valstr_062_080_DUPF), 0x40, NULL, HFILL } },
        { &hf_062_080_DUPM, { "DUPM", "asterix.062_080_DUPM", FT_UINT8, BASE_DEC, VALS (valstr_062_080_DUPM), 0x20, NULL, HFILL } },
        { &hf_062_080_FRIFOE, { "FRI/FOE", "asterix.062_080_FRIFOE", FT_UINT8, BASE_DEC, VALS (valstr_062_080_FRIFOE), 0x60, NULL, HFILL } },
        { &hf_062_080_COA, { "COA", "asterix.062_080_COA", FT_UINT8, BASE_DEC, VALS (valstr_062_080_COA), 0x80, NULL, HFILL } },
        { &hf_062_100, { "100, Calculated Track Position (Cartesian)", "asterix.062_100", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_100_X, { "X[m]", "asterix.062_100_X", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_100_Y, { "Y[m]", "asterix.062_100_Y", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_100_X_v0_17, { "X[NM]", "asterix.062_100_X_v0_17", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_100_Y_v0_17, { "Y[NM]", "asterix.062_100_Y_v0_17", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_105, { "105, Calculated Position In WGS-84 Co-ordinates", "asterix.062_105", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_105_LAT, { "LAT[deg]", "asterix.062_105_LAT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_105_LON, { "LON[deg]", "asterix.062_105_LON", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_110, { "110, Mode 5 Data reports & Extended Mode 1 Code", "asterix.062_110", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_110_01, { "#1: Mode 5 Summary", "asterix.062_110_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_110_01_M5, { "MD5", "asterix.062_110_01_MD5", FT_UINT8, BASE_DEC, VALS (valstr_062_110_01_M5), 0x80, NULL, HFILL } },
        { &hf_062_110_01_ID, { "ID", "asterix.062_110_01_ID", FT_UINT8, BASE_DEC, VALS (valstr_062_110_01_ID), 0x40, NULL, HFILL } },
        { &hf_062_110_01_DA, { "DA", "asterix.062_110_01_DA", FT_UINT8, BASE_DEC, VALS (valstr_062_110_01_DA), 0x20, NULL, HFILL } },
        { &hf_062_110_01_M1, { "M1", "asterix.062_110_01_M1", FT_UINT8, BASE_DEC, VALS (valstr_062_110_01_M1), 0x10, NULL, HFILL } },
        { &hf_062_110_01_M2, { "M2", "asterix.062_110_01_M2", FT_UINT8, BASE_DEC, VALS (valstr_062_110_01_M2), 0x08, NULL, HFILL } },
        { &hf_062_110_01_M3, { "M3", "asterix.062_110_01_M3", FT_UINT8, BASE_DEC, VALS (valstr_062_110_01_M3), 0x04, NULL, HFILL } },
        { &hf_062_110_01_MC, { "MC", "asterix.062_110_01_MC", FT_UINT8, BASE_DEC, VALS (valstr_062_110_01_MC), 0x02, NULL, HFILL } },
        { &hf_062_110_01_X, { "X", "asterix.062_110_01_X", FT_UINT8, BASE_DEC, VALS (valstr_062_110_01_X), 0x01, NULL, HFILL } },
        { &hf_062_110_02, { "#2: Mode 5 PIN /National Origin/ Mission Code", "asterix.062_110_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_110_02_PIN, { "PIN", "asterix.062_110_02_PIN", FT_UINT16, BASE_DEC, NULL, 0x3fff, NULL, HFILL } },
        { &hf_062_110_02_NAT, { "NAT", "asterix.062_110_02_NAT", FT_UINT8, BASE_DEC, NULL, 0x1f, NULL, HFILL } },
        { &hf_062_110_02_MIS, { "MIS", "asterix.062_110_02_MIS", FT_UINT8, BASE_DEC, NULL, 0x3f, NULL, HFILL } },
        { &hf_062_110_03, { "#3: Mode 5 Reported Position", "asterix.062_", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_110_03_LAT, { "LAT[deg]", "asterix.062_110_03_LAT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_110_03_LON, { "LON[deg]", "asterix.062_110_03_LON", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_110_04, { "#4: Mode 5 GNSS-derived Altitude", "asterix.062_11_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_110_04_RES, { "RES", "asterix.062_110_04_RES", FT_UINT8, BASE_DEC, VALS (valstr_062_110_04_RES), 0x60, NULL, HFILL } },
        { &hf_062_110_04_GA, { "GA[feet]", "asterix.062_110_04_GA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_110_05, { "#5: Extended Mode 1 Code in Octal Representation", "asterix.062_110_05", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_110_05_SQUAWK, { "SQUAWK", "asterix.062_110_05_SQUAWK", FT_UINT16, BASE_OCT, NULL, 0x0fff, NULL, HFILL } },
        { &hf_062_110_06, { "#6: Time Offset for POS and GA", "asterix.062_11_06", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_110_06_TOS, { "TOS[s]", "asterix.062_110_06_TOS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_110_07, { "#7: X Pulse Presence", "asterix.062_110_07", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_110_07_X5, { "X5", "asterix.062_110_07_X5", FT_UINT8, BASE_DEC, VALS (valstr_062_110_07_X5), 0x10, NULL, HFILL } },
        { &hf_062_110_07_XC, { "XC", "asterix.062_110_07_XC", FT_UINT8, BASE_DEC, VALS (valstr_062_110_07_XC), 0x08, NULL, HFILL } },
        { &hf_062_110_07_X3, { "X3", "asterix.062_110_07_X3", FT_UINT8, BASE_DEC, VALS (valstr_062_110_07_X3), 0x04, NULL, HFILL } },
        { &hf_062_110_07_X2, { "X2", "asterix.062_110_07_X2", FT_UINT8, BASE_DEC, VALS (valstr_062_110_07_X2), 0x02, NULL, HFILL } },
        { &hf_062_110_07_X1, { "X1", "asterix.062_110_07_X1", FT_UINT8, BASE_DEC, VALS (valstr_062_110_07_X1), 0x01, NULL, HFILL } },
        /* v.0.17 */
        { &hf_062_110_v0_17, { "110, Track Mode 1 Code", "asterix.062_110_v0_17", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_110_A4, { "A4", "asterix.062_110_A4", FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL } },
        { &hf_062_110_A2, { "A2", "asterix.062_110_A2", FT_UINT8, BASE_DEC, NULL, 0x08, NULL, HFILL } },
        { &hf_062_110_A1, { "A1", "asterix.062_110_A1", FT_UINT8, BASE_DEC, NULL, 0x04, NULL, HFILL } },
        { &hf_062_110_B2, { "B2", "asterix.062_110_B2", FT_UINT8, BASE_DEC, NULL, 0x02, NULL, HFILL } },
        { &hf_062_110_B1, { "B1", "asterix.062_110_B1", FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL } },
        { &hf_062_120, { "120, Track Mode 2 Code", "asterix.062_120", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_120_SQUAWK, { "SQUAWK", "asterix.062_120_SQUAWK", FT_UINT16, BASE_OCT, NULL, 0x0fff, NULL, HFILL } },
        { &hf_062_130, { "130, Calculated Track Geometric Altitude", "asterix.062_130", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_130_ALT, { "Altitude[feet]", "asterix.062_130_ALT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_135, { "135, Calculated Track Barometric Altitude", "asterix.062_135", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_135_QNH, { "QNH", "asterix.062_135_QNH", FT_UINT8, BASE_DEC, VALS (valstr_062_135_QNH), 0x80, NULL, HFILL } },
        { &hf_062_135_ALT, { "Altitude[FL]", "asterix.062_135_ALT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_136, { "136, Measured Flight Level", "asterix.062_136", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_136_ALT, { "Measured Flight Level[FL]", "asterix.062_136_ALT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_180, { "180, Calculated Track Velocity (Polar)", "asterix.062_180", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_180_SPEED, { "Speed[NM/s]", "asterix.062_180_SPEED", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_180_HEADING, { "Heading[deg]", "asterix.062_180_HEADING", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_185, { "185, Calculated Track Velocity (Cartesian)", "asterix.062_185", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_185_VX, { "Vx[m/s]", "asterix.062_185_VX", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_185_VY, { "Vy[m/s]", "asterix.062_185_VY", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_200, { "200, Mode of Movement", "asterix.062_200", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_200_TRANS, { "TRANS", "asterix.062_200_TRANS", FT_UINT8, BASE_DEC, VALS (valstr_062_200_TRANS), 0xc0, NULL, HFILL } },
        { &hf_062_200_LONG, { "LONG", "asterix.062_200_LONG", FT_UINT8, BASE_DEC, VALS (valstr_062_200_LONG), 0x30, NULL, HFILL } },
        { &hf_062_200_VERT, { "VERT", "asterix.062_200_VERT", FT_UINT8, BASE_DEC, VALS (valstr_062_200_VERT), 0x0c, NULL, HFILL } },
        { &hf_062_200_ADF, { "ADF", "asterix.062_200_ADF", FT_UINT8, BASE_DEC, VALS (valstr_062_200_ADF), 0x02, NULL, HFILL } },
        { &hf_062_210, { "210, Calculated Acceleration (Cartesian)", "asterix.062_210", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_210_AX, { "Ax[m/s^2]", "asterix.062_210_AX", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_210_AY, { "Ay[m/s^2]", "asterix.062_210_AY", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        /* v.0.17 */
        { &hf_062_210_v0_17, { "210, Calculated Longitudinal Acceleration", "asterix.062_210_v0_17", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_210_CLA, { "CLA[NM/s^2]", "asterix.062_210_CLA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_220, { "220, Calculated Rate Of Climb/Descent", "asterix.062_220", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_220_ROCD, { "ROCD[feet/minute]", "asterix.062_220_ROCD", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_240, { "240, Calculated Rate Of Turn", "asterix.062_240", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_240_ROT, { "TOR[deg/s]", "asterix.062_240_ROT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_245, { "245, Target Identification", "asterix.062_245", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_270, { "270, Target Size & Orientation", "asterix.062_270", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_270_LENGTH, { "Length[m]", "asterix.062_270_LENGTH", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_270_ORIENTATION, { "Orientation[m]", "asterix.062_270_ORIENTATION", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_270_WIDTH, { "Width[m]", "asterix.062_270_WIDTH", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290, { "290, System Track Update Ages", "asterix.062_", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_01, { "#1: Track Age", "asterix.062_290_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_01_TRK, { "TRK[s]", "asterix.062_290_01_TRK", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_02, { "#2: PSR Age", "asterix.062_290_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_02_PSR, { "PSR[s]", "asterix.062_290_02_PSR", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_03, { "#3: SSR Age", "asterix.062_290_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_03_SSR, { "SSR[s]", "asterix.062_290_03_SSR", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_04, { "#4: Mode S Age", "asterix.062_290_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_04_MDS, { "MDS[s]", "asterix.062_290_04_MDS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_05, { "#5: ADS-C Age", "asterix.062_290_05", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_05_ADS, { "ADS[s]", "asterix.062_290_05_ADS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_06, { "#6: ES Age", "asterix.062_290_06", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_06_ES, { "ES[s]", "asterix.062_290_06_ES", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_07, { "#7: VDL Age", "asterix.062_290_07", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_07_VDL, { "VDL[s]", "asterix.062_290_07_VDL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_08, { "#8: UAT Age", "asterix.062_290_08", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_08_UAT, { "UAT[s]", "asterix.062_290_08_UAT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_09, { "#9: Loop Age", "asterix.062_290_09", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_09_LOP, { "LOP[s]", "asterix.062_290_09_LOP", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_10, { "#10: Multilateration Age", "asterix.062_290_10", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_10_MLT, { "MLT[s]", "asterix.062_290_10_MLT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        /* v.0.17 */
        { &hf_062_290_01_v0_17, { "#1: PSR Age", "asterix.062_290_01_v0_17", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_01_PSR, { "PSR[s]", "asterix.062_290_01_PSR", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_02_v0_17, { "#2: PSR Age", "asterix.062_290_02_v0_17", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_02_SSR, { "SSR[s]", "asterix.062_290_02_SSR", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_03_v0_17, { "#3: Mode 3/A Age", "asterix.062_290_03_v0_17", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_03_MDA, { "MDA[s]", "asterix.062_290_03_MDA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_04_v0_17, { "#4: Meausered Flight Level Age", "asterix.062_290_04_v0_17", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_04_MFL, { "MFL[s]", "asterix.062_290_04_MFL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_05_v0_17, { "#5: Mode S Age", "asterix.062_290_05_v0_17", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_05_MDS, { "MDS[s]", "asterix.062_290_05_MDS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_06_v0_17, { "#6: ADS Age", "asterix.062_290_06_v0_17", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_06_ADS, { "ADS[s]", "asterix.062_290_06_ADS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_07_v0_17, { "#7: ADS-B Age", "asterix.062_290_07_v0_17", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_07_ADB, { "ADB[s]", "asterix.062_290_07_ADB", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_08_v0_17, { "#8: Mode 1 Age", "asterix.062_290_08_v0_17", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_08_MD1, { "MD1[s]", "asterix.062_290_08_MD1", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_09_v0_17, { "#9: Mode 2 Age", "asterix.062_290_09_v0_17", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290_09_MD2, { "MD2[s]", "asterix.062_290_09_MD2", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295, { "295, Track Data Ages", "asterix.062_295", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_01, { "#1: Measured Flight Level Age", "asterix.062_295_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_01_MFL, { "MFL[s]", "asterix.062_295_01_MFL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_02, { "#2: Mode 1 Age", "asterix.062_295_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_02_MD1, { "MD1[s]", "asterix.062_295_02_MD1", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_03, { "#3: Mode 2 Age", "asterix.062_295_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_03_MD2, { "MD2[s]", "asterix.062_295_03_MD2", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_04, { "#4: Mode 3/A Age", "asterix.062_295_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_04_MDA, { "MDA[s]", "asterix.062_295_04_MDA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_05, { "#5: Mode 4 Age", "asterix.062_295_05", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_05_MD4, { "MD4[s]", "asterix.062_295_05_MD4", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_06, { "#6: Mode 5 Age", "asterix.062_295_06", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_06_MD5, { "MD5[s]", "asterix.062_295_06_MD5", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_07, { "#7: Magnetic Heading Age", "asterix.062_295_07", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_07_MHD, { "MHD[s]", "asterix.062_295_07_MHD", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_08, { "#8: Indicated Airspeed / Mach Nb age", "asterix.062_295_08", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_08_IAS, { "IAS[s]", "asterix.062_295_08_IAS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_09, { "#9: True Airspeed Age", "asterix.062_295_09", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_09_TAS, { "TAS[s]", "asterix.062_295_09_TAS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_10, { "#10: Selected Altitude Age", "asterix.062_295_10", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_10_SAL, { "SAL[s]", "asterix.062_295_10_SAL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_11, { "#11: Final State Selected Altitude Age", "asterix.062_295_11", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_11_FSS, { "FSS[s]", "asterix.062_295_11_FSS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_12, { "#12: Trajectory Intent Age", "asterix.062_295_12", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_12_TID, { "TID[s]", "asterix.062_295_12_TID", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_13, { "#13: Communication/ACAS Capability and Flight Status Age", "asterix.062_295_13", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_13_COM, { "COM[s]", "asterix.062_295_13_COM", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_14, { "#14: Status Reported by ADS-B Age", "asterix.062_295_14", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_14_SAB, { "SAB[s]", "asterix.062_295_14_SAB", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_15, { "#15: ACAS Resolution Advisory Report Age", "asterix.062_295_15", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_15_ACS, { "ACS[s]", "asterix.062_295_15_ACS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_16, { "#16: Barometric Vertical Rate Age", "asterix.062_295_16", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_16_BVR, { "BVR[s]", "asterix.062_295_16_BVR", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_17, { "#17: Geometrical Vertical Rate Age", "asterix.062_295_17", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_17_GVR, { "GVR[s]", "asterix.062_295_17_GVR", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_18, { "#18: Roll Angle Age", "asterix.062_295_18", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_18_RAN, { "RAN[s]", "asterix.062_295_18_RAN", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_19, { "#19: Track Angle Rate Age", "asterix.062_295_19", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_19_TAR, { "TAR[s]", "asterix.062_295_19_TAR", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_20, { "#20: Track Angle Age", "asterix.062_295_20", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_20_TAN, { "TAN[s]", "asterix.062_295_20_TAN", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_21, { "#21: Ground Speed Age", "asterix.062_295_21", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_21_GSP, { "GSP[s]", "asterix.062_295_21_GSP", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_22, { "#22: Velocity Uncertainty Age", "asterix.062_295_22", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_22_VUN, { "VUN[s]", "asterix.062_295_22_VUN", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_23, { "#23: Meteorological Data Age", "asterix.062_295_23", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_23_MET, { "MET[s]", "asterix.062_295_23_MET", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_24, { "#24: Emitter Category Age", "asterix.062_295_24", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_24_EMC, { "EMC[s]", "asterix.062_295_24_EMC", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_25, { "#25: Position Age", "asterix.062_295_25", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_25_POS, { "POS[s]", "asterix.062_295_25_POS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_26, { "#26: Geometric Altitude Age", "asterix.062_295_26", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_26_GAL, { "GAL[s]", "asterix.062_295_26_GAL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_27, { "#27: Position Uncertainty Age", "asterix.062_295_27", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_27_PUN, { "PUN[s]", "asterix.062_295_27_PUN", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_28, { "#28: Mode S MB Data Age", "asterix.062_295_28", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_28_MB, { "MB[s]", "asterix.062_295_28_MB", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_29, { "#29: Indicated Airspeed Data Age", "asterix.062_295_29", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_29_IAR, { "IAR[s]", "asterix.062_295_29_IAR", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_30, { "#30: Mach Number Data Age", "asterix.062_295_30", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_30_MAC, { "MAC[s]", "asterix.062_295_30_MAC", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_31, { "#31: Barometric Pressure Setting Data Age", "asterix.062_295_31", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_295_31_BPS, { "31[s]", "asterix.062_295_31_BPS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_300, { "300, Vehicle Fleet Identification", "asterix.062_300", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_300_VFI, { "VFI", "asterix.062_300_VFI", FT_UINT8, BASE_DEC, VALS (valstr_062_300_VFI), 0x0, NULL, HFILL } },
        { &hf_062_340, { "340, Measured Information", "asterix.062_340", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_340_01, { "#1: Sensor Identification", "asterix.062_340_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_340_02, { "#2: Measured Position", "asterix.062_340_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_340_02_RHO, { "RHO[NM]", "asterix.062_340_02_RHO", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_340_02_THETA, { "THETA[deg]", "asterix.062_340_02_THETA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_340_03, { "#3: Measured 3-D Height", "asterix.062_340_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_340_03_H, { "HEIGHT[feet]", "asterix.062_340_03_H", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_340_04, { "#4: Last Measured Mode C Code", "asterix.062_340_", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_340_04_V, { "V", "asterix.062_340_04_V", FT_UINT8, BASE_DEC, VALS (valstr_062_340_04_V), 0x80, NULL, HFILL } },
        { &hf_062_340_04_G, { "G", "asterix.062_340_04_G", FT_UINT8, BASE_DEC, VALS (valstr_062_340_04_G), 0x40, NULL, HFILL } },
        { &hf_062_340_04_FL, { "HEIGHT[FL]", "asterix.062_340_04_FL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_340_05, { "#5: Last Measured Mode 3/A Code", "asterix.062_340_", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_340_05_V, { "V", "asterix.062_340_05_V", FT_UINT8, BASE_DEC, VALS (valstr_062_340_05_V), 0x80, NULL, HFILL } },
        { &hf_062_340_05_G, { "G", "asterix.062_340_05_G", FT_UINT8, BASE_DEC, VALS (valstr_062_340_05_G), 0x40, NULL, HFILL } },
        { &hf_062_340_05_L, { "L", "asterix.062_340_05_L", FT_UINT8, BASE_DEC, VALS (valstr_062_340_05_L), 0x20, NULL, HFILL } },
        { &hf_062_340_05_SQUAWK, { "SQUAWK", "asterix.062_340_05_SQUAWK", FT_UINT16, BASE_OCT, NULL, 0x0fff, NULL, HFILL } },
        { &hf_062_340_06, { "#6: Report Type", "asterix.062_340_06", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_340_06_TYP, { "TYP", "asterix.062_340_06_TYP", FT_UINT8, BASE_DEC, VALS (valstr_062_340_06_TYP), 0xe0, NULL, HFILL } },
        { &hf_062_340_06_SIM, { "SIM", "asterix.062_340_06_SIM", FT_UINT8, BASE_DEC, VALS (valstr_062_340_06_SIM), 0x10, NULL, HFILL } },
        { &hf_062_340_06_RAB, { "RAB", "asterix.062_340_06_RAB", FT_UINT8, BASE_DEC, VALS (valstr_062_340_06_RAB), 0x08, NULL, HFILL } },
        { &hf_062_340_06_TST, { "TST", "asterix.062_340_06_TST", FT_UINT8, BASE_DEC, VALS (valstr_062_340_06_TST), 0x04, NULL, HFILL } },
        { &hf_062_380, { "380, Aircraft Derived Data", "asterix.062_380", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_01, { "#1: Target Address", "asterix.062_380_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_02, { "#2: Target Identification", "asterix.062_380_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_03, { "#3: Magnetic Heading", "asterix.062_380_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_03_MH, { "MH[deg]", "asterix.062_380_03_MH", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_04, { "#4: Indicated Airspeed / Mach No", "asterix.062_380_4", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_04_IM, { "IM", "asterix.062_380_04_IM", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL } },
        { &hf_062_380_04_IAS, { "IAS[NM/s or Mach]", "asterix.062_380_04_IAS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_05, { "#5: True Airspeed", "asterix.062_380_05", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_05_TAS, { "TAS[knot]", "asterix.062_380_05_TAS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_06, { "#6: Selected Altitude", "asterix.062_380_06", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_06_SAS, { "SAS", "asterix.062_380_06_SAS", FT_UINT8, BASE_DEC, VALS (valstr_062_380_06_SAS), 0x80, NULL, HFILL } },
        { &hf_062_380_06_SOURCE, { "SOURCE", "asterix.062_380_06_SOURCE", FT_UINT8, BASE_DEC, VALS (valstr_062_380_06_SOURCE), 0x60, NULL, HFILL } },
        { &hf_062_380_06_ALT, { "ALT[feet]", "asterix.062_380_06_ALT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_07, { "#7: Final State Selected Altitude", "asterix.062_380_07", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_07_MV, { "MV", "asterix.062_380_07_MV", FT_UINT8, BASE_DEC, VALS (valstr_062_380_07), 0x80, NULL, HFILL } },
        { &hf_062_380_07_AH, { "AH", "asterix.062_380_07_AH", FT_UINT8, BASE_DEC, VALS (valstr_062_380_07), 0x40, NULL, HFILL } },
        { &hf_062_380_07_AM, { "AM", "asterix.062_380_07_AM", FT_UINT8, BASE_DEC, VALS (valstr_062_380_07), 0x20, NULL, HFILL } },
        { &hf_062_380_07_ALT, { "ALT[feet]", "asterix.062_380_07_ALT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_08, { "#8: Trajectory Intent Status", "asterix.062_380_08", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_08_NAV, { "NAV", "asterix.062_380_08_NAV", FT_UINT8, BASE_DEC, VALS (valstr_062_380_08_NAV), 0x80, NULL, HFILL } },
        { &hf_062_380_08_NVB, { "NVB", "asterix.062_380_08_NVB", FT_UINT8, BASE_DEC, VALS (valstr_062_380_08_NVB), 0x40, NULL, HFILL } },
        { &hf_062_380_09, { "#9: ", "asterix.062_380_09", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_09_TCA, { "TCA", "asterix.062_380_09_TCA", FT_UINT8, BASE_DEC, VALS (valstr_062_380_09_TCA), 0x80, NULL, HFILL } },
        { &hf_062_380_09_NC, { "NC", "asterix.062_380_09_NC", FT_UINT8, BASE_DEC, VALS (valstr_062_380_09_NC), 0x80, NULL, HFILL } },
        { &hf_062_380_09_TCP, { "TCP", "asterix.062_380_09_TCP", FT_UINT8, BASE_DEC, NULL, 0x3f, NULL, HFILL } },
        { &hf_062_380_09_ALT, { "ALT[feet]", "asterix.062_380_09_ALT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_09_LAT, { "LAT[deg]", "asterix.062_380_09_LAT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_09_LON, { "LON[deg]", "asterix.062_380_09_LON", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_09_PTYP, { "PTYP", "asterix.062_380_09_PTYP", FT_UINT8, BASE_DEC, VALS (valstr_062_380_09_PTYP), 0xf0, NULL, HFILL } },
        { &hf_062_380_09_TD, { "TD", "asterix.062_380_09_TD", FT_UINT8, BASE_DEC, VALS (valstr_062_380_09_TD), 0x0c, NULL, HFILL } },
        { &hf_062_380_09_TRA, { "TRA", "asterix.062_380_09_TRA", FT_UINT8, BASE_DEC, VALS (valstr_062_380_09_TRA), 0x02, NULL, HFILL } },
        { &hf_062_380_09_TOA, { "TOA", "asterix.062_380_09_TOA", FT_UINT8, BASE_DEC, VALS (valstr_062_380_09_TOA), 0x01, NULL, HFILL } },
        { &hf_062_380_09_TOV, { "TOV[s]", "asterix.062_380_09_TOV", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_09_TTR, { "TTR[NM]", "asterix.062_380_09_TTR", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_10, { "#10: Communications/ACAS Capability and Flight Status reported by Mode-S", "asterix.062_380_10", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_10_COM, { "COM", "asterix.062_380_10_COM", FT_UINT8, BASE_DEC, VALS (valstr_062_380_10_COM), 0xe0, NULL, HFILL } },
        { &hf_062_380_10_STAT, { "STAT", "asterix.062_380_10_STAT", FT_UINT8, BASE_DEC, VALS (valstr_062_380_10_STAT), 0x1c, NULL, HFILL } },
        { &hf_062_380_10_SSC, { "SSC", "asterix.062_380_10_SSC", FT_UINT8, BASE_DEC, VALS (valstr_062_380_10_SSC), 0x80, NULL, HFILL } },
        { &hf_062_380_10_ARC, { "ARC", "asterix.062_380_10_ARC", FT_UINT8, BASE_DEC, VALS (valstr_062_380_10_ARC), 0x40, NULL, HFILL } },
        { &hf_062_380_10_AIC, { "AIC", "asterix.062_380_10_AIC", FT_UINT8, BASE_DEC, VALS (valstr_062_380_10_AIC), 0x20, NULL, HFILL } },
        { &hf_062_380_10_B1A, { "B1A", "asterix.062_380_10_B1A", FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL } },
        { &hf_062_380_10_B1B, { "B1B", "asterix.062_380_10_B1B", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL } },
        { &hf_062_380_11, { "#11: Status reported by ADS-B", "asterix.062_380_11", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_11_AC, { "AC", "asterix.062_380_11_AC", FT_UINT8, BASE_DEC, VALS (valstr_062_380_11_AC), 0xc0, NULL, HFILL } },
        { &hf_062_380_11_MN, { "MN", "asterix.062_380_11_MN", FT_UINT8, BASE_DEC, VALS (valstr_062_380_11_MN), 0x30, NULL, HFILL } },
        { &hf_062_380_11_DC, { "DC", "asterix.062_380_11_DC", FT_UINT8, BASE_DEC, VALS (valstr_062_380_11_DC), 0x0c, NULL, HFILL } },
        { &hf_062_380_11_GBS, { "GBS", "asterix.062_380_11_GBS", FT_UINT8, BASE_DEC, VALS (valstr_062_380_11_GBS), 0x02, NULL, HFILL } },
        { &hf_062_380_11_STAT, { "STAT", "asterix.062_380_11_STAT", FT_UINT8, BASE_DEC, VALS (valstr_062_380_11_STAT), 0x07, NULL, HFILL } },
        { &hf_062_380_12, { "#12: ACAS Resolution Advisory Report", "asterix.062_380_12", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_12_MB, { "MB DATA", "asterix.062_380_12_MB", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_13, { "#13: Barometric Vertical Rate", "asterix.062_380_13", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_13_BVR, { "BVR[feet/min]", "asterix.062_380_13_BVR", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_14, { "#14: Geometric Vertical Rate", "asterix.062_380_14", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_14_GVR, { "GVR[feet/min]", "asterix.062_380_14_GVR", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_15, { "#15: Roll Angle", "asterix.062_380_15", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_15_ROLL, { "ROLL[deg]", "asterix.062_380_15_ROLL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_16, { "#16: Track Angle Rate", "asterix.062_380_16", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_16_TI, { "TI", "asterix.062_380_16_TI", FT_UINT8, BASE_DEC, VALS (valstr_062_380_16_TI), 0xc0, NULL, HFILL } },
        { &hf_062_380_16_RATE, { "RATE[deg/s]", "asterix.062_380_16_RATE", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_17, { "#17: Track Angle", "asterix.062_380_17", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_17_TA, { "TA[deg]", "asterix.062_380_17_TA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_18, { "#18: Ground Speed", "asterix.062_380_18", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_18_GS, { "GS[NM/s]", "asterix.062_380_18_GS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_19, { "#19: Velocity Uncertainty", "asterix.062_380_19", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_19_VUC, { "VUC", "asterix.062_380_19_VUC", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_20, { "#20: Met Data", "asterix.062_380_20", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_20_WS, { "WS", "asterix.062_380_20_WS", FT_UINT8, BASE_DEC, VALS (valstr_062_380_20_WS), 0x80, NULL, HFILL } },
        { &hf_062_380_20_WD, { "WD", "asterix.062_380_20_WD", FT_UINT8, BASE_DEC, VALS (valstr_062_380_20_WD), 0x40, NULL, HFILL } },
        { &hf_062_380_20_TMP, { "TMP", "asterix.062_380_20_TMP", FT_UINT8, BASE_DEC, VALS (valstr_062_380_20_TMP), 0x20, NULL, HFILL } },
        { &hf_062_380_20_TRB, { "TRB", "asterix.062_380_20_TRB", FT_UINT8, BASE_DEC, VALS (valstr_062_380_20_TRB), 0x10, NULL, HFILL } },
        { &hf_062_380_20_WS_VAL, { "WS[knot]", "asterix.062_380_20_WS_VAL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_20_WD_VAL, { "WD[deg]", "asterix.062_380_20_WD_VAL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_20_TMP_VAL, { "TMP[deg Celcius]", "asterix.062_380_20_TMP_VAL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_20_TRB_VAL, { "TRB", "asterix.062_380_20_TRB_VAL", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_21, { "#21: Emitter Category", "asterix.062_380_21", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_21_ECAT, { "ECAT", "asterix.062_380_21_ECAT", FT_UINT8, BASE_DEC, VALS (valstr_062_380_21_ECAT), 0x0, NULL, HFILL } },
        { &hf_062_380_22, { "#22: Position", "asterix.062_380_22", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_22_LAT, { "LAT[deg]", "asterix.062_380_22_LAT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_22_LON, { "LON[deg]", "asterix.062_380_22_LON", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_23, { "#23: Geometric Altitude", "asterix.062_380_23", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_23_ALT, { "ALT[feet]", "asterix.062_380_23_ALT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_24, { "#24: Position Uncertainty", "asterix.062_380_24", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_24_PUN, { "PUN", "asterix.062_380_24_PUN", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL } },
        { &hf_062_380_25, { "#25: MODE S MB DATA", "asterix.062_380_25", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_26, { "#26: Indicated Airspeed", "asterix.062_380_26", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_26_IAS, { "IAS[knot]", "asterix.062_380_26_IAS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_27, { "#27: Mach Number", "asterix.062_380_27", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_27_MACH, { "MACH[mach]", "asterix.062_380_27_MACH", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_28, { "#28: Barometric Pressure Setting (derived from Mode S BDS 4,0)", "asterix.062_380_28", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_28_BPS, { "BPS[mb]", "asterix.062_380_28_BPS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        /* v.0.17 */
        { &hf_062_380_v0_17, { "380, Mode S Related Data", "asterix.062_380", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_01_v0_17, { "#1: Mode S MB Data", "asterix.062_380_01_v0_17", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_02_v0_17, { "#2: Aircraft Address", "asterix.062_380_02_v0_17", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_03_v0_17, { "#3: Communications / ACAS", "asterix.062_380_03_v0_17", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_04_v0_17, { "#4: Communications/ACAS Capability and Flight Status", "asterix.062_380_04_v0_17", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_04_COM, { "COM", "asterix.062_380_04_COM", FT_UINT8, BASE_DEC, VALS (valstr_062_380_04_COM), 0xe0, NULL, HFILL } },
        { &hf_062_380_04_STAT, { "STAT", "asterix.062_380_04_STAT", FT_UINT8, BASE_DEC, VALS (valstr_062_380_04_STAT), 0x1c, NULL, HFILL } },
        { &hf_062_380_04_SSC, { "SSC", "asterix.062_380_04_SSC", FT_UINT8, BASE_DEC, VALS (valstr_062_380_04_SSC), 0x80, NULL, HFILL } },
        { &hf_062_380_04_ARC, { "ARC", "asterix.062_380_04_ARC", FT_UINT8, BASE_DEC, VALS (valstr_062_380_04_ARC), 0x40, NULL, HFILL } },
        { &hf_062_380_04_AIC, { "AIC", "asterix.062_380_04_AIC", FT_UINT8, BASE_DEC, VALS (valstr_062_380_04_AIC), 0x20, NULL, HFILL } },
        { &hf_062_380_04_B1A, { "B1A", "asterix.062_380_04_B1A", FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL } },
        { &hf_062_380_04_B1B, { "B1B", "asterix.062_380_04_B1B", FT_UINT8, BASE_HEX, NULL, 0x0f, NULL, HFILL } },
        { &hf_062_380_05_v0_17, { "#5: ACAS Resolution Advisory Report", "asterix.062_380_05_v0_17", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_05_MB, { "#4: ACAS Resolution Advisory Report", "asterix.062_380_05_MB", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390, { "390, Flight Plan Related Data", "asterix.062_390", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_01, { "#1: FPPS Identification Tag", "asterix.062_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_02, { "#2: Callsign", "asterix.062_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_02_CS, { "CS", "asterix.062_390_02_CS", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_03, { "#3: IFPS_FLIGHT_ID", "asterix.062_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_03_TYP, { "TYP", "asterix.062_390_03_TYP", FT_UINT32, BASE_DEC, VALS (valstr_062_390_03_TYP), 0xc0000000, NULL, HFILL } },
        { &hf_062_390_03_NBR, { "NBR", "asterix.062_390_03_NBR", FT_UINT32, BASE_DEC, NULL, 0x07ffffff, NULL, HFILL } },
        { &hf_062_390_04, { "#4: Flight Category", "asterix.062_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_04_GAT_OAT, { "GAT/OAT", "asterix.062_390_04_GAT_OAT", FT_UINT8, BASE_DEC, VALS (valstr_062_390_04_GAT_OAT), 0xc0, NULL, HFILL } },
        { &hf_062_390_04_FR12, { "FR1/FR2", "asterix.062_390_04_FR12", FT_UINT8, BASE_DEC, VALS (valstr_062_390_04_FR12), 0x30, NULL, HFILL } },
        { &hf_062_390_04_RVSM, { "RVSM", "asterix.062_390_04_RVSM", FT_UINT8, BASE_DEC, VALS (valstr_062_390_04_RVSM), 0x0c, NULL, HFILL } },
        { &hf_062_390_04_HPR, { "HPR", "asterix.062_390_04_HPR", FT_UINT8, BASE_DEC, VALS (valstr_062_390_04_HPR), 0x02, NULL, HFILL } },
        { &hf_062_390_05, { "#5: Type of Aircraft", "asterix.062_05", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_05_ACTYP, { "ACTYP", "asterix.062_390_05_ACTYP", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_06, { "#6: Wake Turbulence Category", "asterix.062_06", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_06_WTC, { "WTC", "asterix.062_390_06_WTC", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_07, { "#7: Departure Airport", "asterix.062_07", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_07_ADEP, { "ADEP", "asterix.062_390_07_ADEP", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_08, { "#8: Destination Airport", "asterix.062_08", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_08_ADES, { "ADES", "asterix.062_390_08_ADES", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_09, { "#9: Runway Designation", "asterix.062_09", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_09_NU1, { "NU1", "asterix.062_390_09_NU1", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_09_NU2, { "NU2", "asterix.062_390_09_NU2", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_09_LTR, { "LTR", "asterix.062_390_09_LTR", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_10, { "#10: Current Cleared Flight Level", "asterix.062_10", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_10_CFL, { "CFL[FL]", "asterix.062_390_10_CFL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_11, { "#11: Current Control Position", "asterix.062_11", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_11_CNTR, { "CNTR", "asterix.062_390_11_CNTR", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_11_POS, { "POS", "asterix.062_390_11_POS", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_12, { "#12: Time of Departure / Arrival", "asterix.062_12", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_12_TYP, { "TYP", "asterix.062_390_12_TYP", FT_UINT8, BASE_DEC, VALS (valstr_062_390_12_TYP), 0xf8, NULL, HFILL } },
        { &hf_062_390_12_DAY, { "DAY", "asterix.062_390_12_DAY", FT_UINT8, BASE_DEC, VALS (valstr_062_390_12_DAY), 0x06, NULL, HFILL } },
        { &hf_062_390_12_HOR, { "HOUR", "asterix.062_390_12_HOR", FT_UINT8, BASE_DEC, NULL, 0x1f, NULL, HFILL } },
        { &hf_062_390_12_MIN, { "MIN", "asterix.062_390_12_MIN", FT_UINT8, BASE_DEC, NULL, 0x3f, NULL, HFILL } },
        { &hf_062_390_12_AVS, { "AVS", "asterix.062_390_12_AVS", FT_UINT8, BASE_DEC, VALS (valstr_062_390_12_AVS), 0x80, NULL, HFILL } },
        { &hf_062_390_12_SEC, { "SEC", "asterix.062_390_12_SEC", FT_UINT8, BASE_DEC, NULL, 0x3f, NULL, HFILL } },
        { &hf_062_390_13, { "#13: Aircraft Stand", "asterix.062_13", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_13_STAND, { "STAND", "asterix.062_390_13_STAND", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_14, { "#14: Stand Status", "asterix.062_14", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_14_EMP, { "EMP", "asterix.062_390_14_EMP", FT_UINT8, BASE_DEC, VALS (valstr_062_390_14_EMP), 0xc0, NULL, HFILL } },
        { &hf_062_390_14_AVL, { "AVL", "asterix.062_390_14_AVL", FT_UINT8, BASE_DEC, VALS (valstr_062_390_14_AVL), 0x30, NULL, HFILL } },
        { &hf_062_390_15, { "#15: Standard Instrument Departure", "asterix.062_15", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_15_SID, { "SID", "asterix.062_390_15_SID", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_16, { "#16: Standard Instrument Arrival", "asterix.062_16", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_16_STAR, { "STAR", "asterix.062_390_16_STAR", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_17, { "#17: Pre-Emergency Mode 3/A", "asterix.062_17", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_17_VA, { "VA", "asterix.062_390_17_VA", FT_UINT8, BASE_DEC, VALS (valstr_062_390_17_VA), 0x10, NULL, HFILL } },
        { &hf_062_390_17_SQUAWK, { "SQUAWK", "asterix.062_390_17_SQUAWK", FT_UINT16, BASE_OCT, NULL, 0x0fff, NULL, HFILL } },
        { &hf_062_390_18, { "#18: Pre-Emergency Callsign", "asterix.062_18", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_18_CS, { "CS", "asterix.062_390_18_CS", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500, { "500, Estimated Accuracies", "asterix.062_500", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_01, { "#1: Estimated Accuracy Of Track Position (Cartesian)", "asterix.062_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_01_APCX, { "APC X[m]", "asterix.062_500_01_APCX", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_01_APCY, { "APC Y[m]", "asterix.062_500_01_APCY", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_02, { "#2: XY covariance component", "asterix.062_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_02_COV, { "COV[m]", "asterix.062_500_02_COV", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_03, { "#3: Estimated Accuracy Of Track Position (WGS-84)", "asterix.062_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_03_APWLAT, { "APW LAT[deg]", "asterix.062_500_03_APWLAT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_03_APWLON, { "APW LON[deg]", "asterix.062_500_03_APWLON", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_04, { "#4: Estimated Accuracy Of Calculated Track Geometric Altitude", "asterix.062_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_04_AGA, { "AGA[feet]", "asterix.062_500_04_AGA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_05, { "#5: Estimated Accuracy Of Calculated Track Barometric Altitude", "asterix.062_05", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_05_ABA, { "ABA[FL]", "asterix.062_500_05_ABA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_06, { "#6: ", "asterix.062_06", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_06_ATVX, { "ATV X[m/s]", "asterix.062_500_06_ATVX", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_06_ATVY, { "ATV Y[m/s]", "asterix.062_500_06_ATVY", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_07, { "#7: Estimated Accuracy Of Acceleration (Cartesian)", "asterix.062_07", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_07_AAX, { "AA X[m/s^2]", "asterix.062_500_07_AAX", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_07_AAY, { "AA X[m/s^2]", "asterix.062_500_07_AAY", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_08, { "#8: Estimated Accuracy Of Rate Of Climb/Descent", "asterix.062_08", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_08_ARC, { "ARC[feet/min]", "asterix.062_500_08_ARC", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        /* v.0.17 */
        { &hf_062_500_01_APCX_8bit, { "APC X[NM]", "asterix.062_500_01_APCX_8bit", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_01_APCY_8bit, { "APC Y[NM]", "asterix.062_500_01_APCY_8bit", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_02_v0_17, { "#2: Estimated Accuracy Of Track Position (WGS-84)", "asterix.062_500_02_v0_17", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_02_APWLAT, { "APW LAT[deg]", "asterix.062_500_02_APWLAT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_02_APWLON, { "APW LON[deg]", "asterix.062_500_02_APWLON", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_03_v0_17, { "#3: Estimated Accuracy Of Track Altitude", "asterix.062_500_03_v0_17", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_03_ATA, { "ATA [feet]", "asterix.062_500_03_ATA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_04_v0_17, { "#4: Estimated Accuracy Of Calculated Track Flight Level", "asterix.062_500_04_v0_17", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_04_ATF, { "ATF [FL]", "asterix.062_500_04_ATF", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_05_v0_17, { "#5: Estimated Accuracy Of Track Velocity (Polar)", "asterix.062_500_05_v0_17", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_05_ATVS, { "ATV X[kt]", "asterix.062_500_05_ATVS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_05_ATVH, { "ATV Y[deg]", "asterix.062_500_05_ATVH", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_06_v0_17, { "#6: Estimated Accuracy Of Rate Of Turn", "asterix.062_500_06_v0_17", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_06_ART, { "ART[deg/s]", "asterix.062_500_06_ART", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_07_v0_17, { "#7: Estimated Accuracy Of Longitudinal Acceleration", "asterix.062_500_07_v0_17", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_07_ALA, { "ALA[NM/s^2]", "asterix.062_500_07_ALA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_510, { "510, Composed Track Number", "asterix.062_510", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_510_SID, { "SID", "asterix.062_510_SID", FT_UINT24, BASE_DEC, NULL, 0xfffffe, NULL, HFILL } },
        { &hf_062_510_STN, { "STN", "asterix.062_510_STN", FT_UINT24, BASE_DEC, NULL, 0xfffffe, NULL, HFILL } },
        { &hf_062_RE, { "Reserved Expansion Field", "asterix.062_RE", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_RE_CST, {"CST", "asterix.062_RE_CST", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_RE_CST_SAC, {"Sensor SAC", "asterix.062_RE_SAC", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_062_RE_CST_SIC, {"Sensor SIC", "asterix.062_RE_SIC", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_062_RE_CST_TYP, {"TYP", "asterix.062_RE_CST_TYP", FT_UINT8, BASE_DEC, VALS(valstr_062_RE_CST_TYPE), 0x0F, NULL, HFILL } },
        { &hf_062_RE_CST_TRK_NUM, {"TRK NUM", "asterix.062_RE_CST_TRK_NUM", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_062_RE_CSNT, {"CSNT", "asterix.062_RE_CSNT", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_RE_CSNT_SAC, {"Sensor SAC", "asterix.062_RE_CSNT_SAC", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_062_RE_CSNT_SIC, {"Sensor SIC", "asterix.062_RE_CSNT_SIC", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_062_RE_CSNT_TYP, {"TYP", "asterix.062_RE_CSNT_TYP", FT_UINT8, BASE_DEC, VALS(valstr_062_RE_CST_TYPE), 0x0F, NULL, HFILL } },
        { &hf_062_RE_TVS, {"TVS", "asterix.062_RE_TVS", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_RE_TVS_VX, {"VX[m/s]", "asterix.062_RE_TVS_VX", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_RE_TVS_VY, {"VY[m/s]", "asterix.062_RE_TVS_VY", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_RE_STS, {"STS", "asterix.062_RE_STS", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_RE_STS_FDR, {"FDR", "asterix.062_RE_STS_FDR", FT_UINT8, BASE_DEC, VALS(valstr_062_RE_STS_FDR), 0x80, NULL, HFILL } },
        { &hf_062_SP, { "Special Purpose Field", "asterix.062_SP", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        /* Category 063 */
        { &hf_063_010, { "010, Data Source Identifier", "asterix.063_010", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_015, { "015, Service Identification", "asterix.063_015", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_030, { "030, Time of Message", "asterix.063_030", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_050, { "050, Sensor Identifier", "asterix.063_050", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_060, { "060, Sensor Configuration and Status", "asterix.063_060", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_070, { "070, Time Stamping Bias", "asterix.063_070", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_080, { "080, SSR / Mode S Range Gain and Bias", "asterix.063_080", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_081, { "081, SSR / Mode S Azimuth Bias", "asterix.063_081", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_090, { "090, PSR Range Gain and Bias", "asterix.063_090", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_091, { "091, PSR Azimuth Bias", "asterix.063_091", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_092, { "092, PSR Elevation Bias", "asterix.063_092", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_RE, { "Reserved Expansion Field", "asterix.063_RE", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_SP, { "Special Purpose Field", "asterix.063_SP", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        /* Category 065 */
        { &hf_065_000, { "000, Message Type", "asterix.063_000", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_065_010, { "010, Data Source Identifier", "asterix.063_010", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_065_015, { "015, Service Identification", "asterix.063_015", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_065_020, { "020, Batch Number", "asterix.063_020", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_065_030, { "030, Time of Message", "asterix.063_030", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_065_040, { "040, SDPS Configuration and Status", "asterix.063_040", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_065_050, { "050, Service Status Report", "asterix.063_050", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_065_RE, { "Reserved Expansion Field", "asterix.063_RE", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_065_SP, { "Special Purpose Field", "asterix.063_SP", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_asterix,
        &ett_asterix_category,
        &ett_asterix_length,
        &ett_asterix_message,
        &ett_asterix_subtree,
        &ett_spare,
        &ett_counter,
        &ett_XXX_SAC,
        &ett_XXX_SIC,
        &ett_XXX_FX,
        /*&ett_XXX_2FX,*/
        &ett_XXX_3FX,
        &ett_XXX_TOD,
        &ett_XXX_AA,
        &ett_XXX_AI,
        &ett_XXX_MB_DATA,
        &ett_XXX_BDS1,
        &ett_XXX_BDS2,
        &ett_XXX_TN_16,
        /* Category 001 */
        &ett_001_010,
        &ett_001_020,
        &ett_001_020_TYP,
        &ett_001_020_SIM,
        &ett_001_020_SSR_PSR,
        &ett_001_020_ANT,
        &ett_001_020_SPI,
        &ett_001_020_RAB,
        &ett_001_020_TST,
        &ett_001_020_DS12,
        &ett_001_020_ME,
        &ett_001_020_MI,
        &ett_001_030,
        &ett_001_030_WE,
        &ett_001_040,
        &ett_001_040_RHO,
        &ett_001_040_THETA,
        &ett_001_042,
        &ett_001_042_X,
        &ett_001_042_Y,
        &ett_001_050,
        &ett_001_060,
        &ett_001_070,
        &ett_001_070_V,
        &ett_001_070_G,
        &ett_001_070_L,
        &ett_001_070_SQUAWK,
        &ett_001_080,
        &ett_001_080_QA4,
        &ett_001_080_QA2,
        &ett_001_080_QA1,
        &ett_001_080_QB4,
        &ett_001_080_QB2,
        &ett_001_080_QB1,
        &ett_001_080_QC4,
        &ett_001_080_QC2,
        &ett_001_080_QC1,
        &ett_001_080_QD4,
        &ett_001_080_QD2,
        &ett_001_080_QD1,
        &ett_001_090,
        &ett_001_090_V,
        &ett_001_090_G,
        &ett_001_090_FL,
        &ett_001_100,
        &ett_001_120,
        &ett_001_130,
        &ett_001_131,
        &ett_001_141,
        &ett_001_141_TTOD,
        &ett_001_150,
        &ett_001_161,
        &ett_001_161_TPN,
        &ett_001_170,
        &ett_001_170_CON,
        &ett_001_170_RAD,
        &ett_001_170_MAN,
        &ett_001_170_DOU,
        &ett_001_170_RDPC,
        &ett_001_170_GHO,
        &ett_001_170_TRE,
        &ett_001_200,
        &ett_001_210,
        &ett_001_RE,
        &ett_001_SP,
        /* Category 002 */
        &ett_002_000,
        &ett_002_000_MT,
        &ett_002_010,
        &ett_002_020,
        &ett_002_020_SN,
        &ett_002_030,
        &ett_002_041,
        &ett_002_041_ARS,
        &ett_002_050,
        &ett_002_060,
        &ett_002_070,
        &ett_002_070_A,
        &ett_002_070_IDENT,
        &ett_002_070_COUNTER,
        &ett_002_080,
        &ett_002_080_WE,
        &ett_002_090,
        &ett_002_090_RE,
        &ett_002_090_AE,
        &ett_002_100,
        &ett_002_100_RHOS,
        &ett_002_100_RHOE,
        &ett_002_100_THETAS,
        &ett_002_100_THETAE,
        &ett_002_RE,
        &ett_002_SP,
        /* Category 008 */
        &ett_008_000,
        &ett_008_000_MT,
        &ett_008_010,
        &ett_008_020,
        &ett_008_020_ORG,
        &ett_008_020_INT,
        &ett_008_020_DIR,
        &ett_008_020_TST,
        &ett_008_020_ER,
        &ett_008_034,
        &ett_008_034_START_RANGE,
        &ett_008_034_END_RANGE,
        &ett_008_034_AZIMUTH,
        &ett_008_036,
        &ett_008_036_X,
        &ett_008_036_Y,
        &ett_008_036_VL,
        &ett_008_038,
        &ett_008_038_X1,
        &ett_008_038_Y1,
        &ett_008_038_X2,
        &ett_008_038_Y2,
        &ett_008_040,
        &ett_008_040_ORG,
        &ett_008_040_INT,
        &ett_008_040_FST_LST,
        &ett_008_040_CSN,
        &ett_008_050,
        &ett_008_050_X1,
        &ett_008_050_Y1,
        &ett_008_090,
        &ett_008_100,
        &ett_008_100_f,
        &ett_008_100_R,
        &ett_008_100_Q,
        &ett_008_110,
        &ett_008_110_HW,
        &ett_008_120,
        &ett_008_120_COUNT,
        &ett_008_SP,
        &ett_008_RFS,
        /* Category 009 */
        &ett_009_000,
        &ett_009_000_MT,
        &ett_009_010,
        &ett_009_020,
        &ett_009_020_ORG,
        &ett_009_020_INT,
        &ett_009_020_DIR,
        &ett_009_030,
        &ett_009_030_X,
        &ett_009_030_Y,
        &ett_009_030_VL,
        &ett_009_060,
        &ett_009_060_STEP,
        &ett_009_070,
        &ett_009_080,
        &ett_009_080_SCALE,
        &ett_009_080_R,
        &ett_009_080_Q,
        &ett_009_090,
        &ett_009_090_CP,
        &ett_009_090_WO,
        &ett_009_090_RS,
        &ett_009_100,
        &ett_009_100_VC,
        /* Category 021 */
        &ett_021_008,
        &ett_021_008_RA,
        &ett_021_008_TC,
        &ett_021_008_TS,
        &ett_021_008_ARV,
        &ett_021_008_CDTIA,
        &ett_021_008_not_TCAS,
        &ett_021_008_SA,
        &ett_021_010,
        &ett_021_015,
        &ett_021_015_SI,
        &ett_021_016,
        &ett_021_016_RP,
        &ett_021_020,
        &ett_021_020_ECAT,
        &ett_021_040,
        &ett_021_040_ATP,
        &ett_021_040_ARC,
        &ett_021_040_RC,
        &ett_021_040_RAB,
        &ett_021_040_DCR,
        &ett_021_040_GBS,
        &ett_021_040_SIM,
        &ett_021_040_TST,
        &ett_021_040_SAA,
        &ett_021_040_CL,
        &ett_021_040_IPC,
        &ett_021_040_NOGO,
        &ett_021_040_CPR,
        &ett_021_040_LDPJ,
        &ett_021_040_RCF,
        &ett_021_070,
        &ett_021_070_SQUAWK,
        &ett_021_071,
        &ett_021_072,
        &ett_021_073,
        &ett_021_074,
        &ett_021_074_FSI,
        &ett_021_074_TOMRP,
        &ett_021_075,
        &ett_021_076,
        &ett_021_077,
        &ett_021_076_FSI,
        &ett_021_076_TOMRV,
        &ett_021_080,
        &ett_021_090,
        &ett_021_090_NUCR_NACV,
        &ett_021_090_NUCP_NIC,
        &ett_021_090_NIC_BARO,
        &ett_021_090_SIL,
        &ett_021_090_NACP,
        &ett_021_090_SIL_SUP,
        &ett_021_090_SDA,
        &ett_021_090_GVA,
        &ett_021_090_PIC,
        &ett_021_110,
        &ett_021_110_01,
        &ett_021_110_01_NAV,
        &ett_021_110_01_NVB,
        &ett_021_110_02,
        &ett_021_110_02_TCA,
        &ett_021_110_02_NC,
        &ett_021_110_02_TCPNo,
        &ett_021_110_02_ALT,
        &ett_021_110_02_LAT,
        &ett_021_110_02_LON,
        &ett_021_110_02_PT,
        &ett_021_110_02_TD,
        &ett_021_110_02_TRA,
        &ett_021_110_02_TOA,
        &ett_021_110_02_TOV,
        &ett_021_110_02_TTR,
        &ett_021_130,
        &ett_021_130_LAT,
        &ett_021_130_LON,
        &ett_021_131,
        &ett_021_131_LAT,
        &ett_021_131_LON,
        &ett_021_132,
        &ett_021_132_MAM,
        &ett_021_140,
        &ett_021_140_GH,
        &ett_021_145,
        &ett_021_145_FL,
        &ett_021_146,
        &ett_021_146_SAS,
        &ett_021_146_Source,
        &ett_021_146_ALT,
        &ett_021_148,
        &ett_021_148_MV,
        &ett_021_148_AH,
        &ett_021_148_AM,
        &ett_021_148_ALT,
        &ett_021_150,
        &ett_021_150_IM,
        &ett_021_150_ASPD,
        &ett_021_151,
        &ett_021_151_RE,
        &ett_021_151_TASPD,
        &ett_021_152,
        &ett_021_152_MHDG,
        &ett_021_155,
        &ett_021_155_RE,
        &ett_021_155_BVR,
        &ett_021_157,
        &ett_021_157_RE,
        &ett_021_157_GVR,
        &ett_021_160,
        &ett_021_160_RE,
        &ett_021_160_GSPD,
        &ett_021_160_TA,
        &ett_021_161,
        &ett_021_161_TN,
        &ett_021_165,
        &ett_021_165_TAR,
        &ett_021_170,
        &ett_021_200,
        &ett_021_200_ICF,
        &ett_021_200_LNAV,
        &ett_021_200_PS,
        &ett_021_200_SS,
        &ett_021_210,
        &ett_021_210_VNS,
        &ett_021_210_VN,
        &ett_021_210_LTT,
        &ett_021_220,
        &ett_021_220_01,
        &ett_021_220_01_WSPD,
        &ett_021_220_02,
        &ett_021_220_02_WDIR,
        &ett_021_220_03,
        &ett_021_220_03_TEMP,
        &ett_021_220_04,
        &ett_021_220_04_TURB,
        &ett_021_230,
        &ett_021_230_RA,
        &ett_021_250,
        &ett_021_260,
        &ett_021_260_TYP,
        &ett_021_260_STYP,
        &ett_021_260_ARA,
        &ett_021_260_RAC,
        &ett_021_260_RAT,
        &ett_021_260_MTE,
        &ett_021_260_TTI,
        &ett_021_260_TID,
        &ett_021_271,
        &ett_021_271_POA,
        &ett_021_271_CDTIS,
        &ett_021_271_B2low,
        &ett_021_271_RAS,
        &ett_021_271_IDENT,
        &ett_021_271_LW,
        &ett_021_295,
        &ett_021_295_01,
        &ett_021_295_01_AOS,
        &ett_021_295_02,
        &ett_021_295_02_TRD,
        &ett_021_295_03,
        &ett_021_295_03_M3A,
        &ett_021_295_04,
        &ett_021_295_04_QI,
        &ett_021_295_05,
        &ett_021_295_05_TI,
        &ett_021_295_06,
        &ett_021_295_06_MAM,
        &ett_021_295_07,
        &ett_021_295_07_GH,
        &ett_021_295_08,
        &ett_021_295_08_FL,
        &ett_021_295_09,
        &ett_021_295_09_ISA,
        &ett_021_295_10,
        &ett_021_295_10_FSA,
        &ett_021_295_11,
        &ett_021_295_11_AS,
        &ett_021_295_12,
        &ett_021_295_12_TAS,
        &ett_021_295_13,
        &ett_021_295_13_MH,
        &ett_021_295_14,
        &ett_021_295_14_BVR,
        &ett_021_295_15,
        &ett_021_295_15_GVR,
        &ett_021_295_16,
        &ett_021_295_16_GV,
        &ett_021_295_17,
        &ett_021_295_17_TAR,
        &ett_021_295_18,
        &ett_021_295_18_TI,
        &ett_021_295_19,
        &ett_021_295_19_TS,
        &ett_021_295_20,
        &ett_021_295_20_MET,
        &ett_021_295_21,
        &ett_021_295_21_ROA,
        &ett_021_295_22,
        &ett_021_295_22_ARA,
        &ett_021_295_23,
        &ett_021_295_23_SCC,
        &ett_021_400,
        &ett_021_400_RID,
        &ett_021_RE,
        &ett_021_SP,
        /* Category 023 */
        &ett_023_000,
        &ett_023_000_RT,
        &ett_023_010,
        &ett_023_015,
        &ett_023_015_SID,
        &ett_023_015_STYPE,
        &ett_023_070,
        &ett_023_100,
        &ett_023_100_NOGO,
        &ett_023_100_ODP,
        &ett_023_100_OXT,
        &ett_023_100_MSC,
        &ett_023_100_TSV,
        &ett_023_100_SPO,
        &ett_023_100_RN,
        &ett_023_100_GSSP,
        &ett_023_101,
        &ett_023_101_RP,
        &ett_023_101_SC,
        &ett_023_101_SSRP,
        &ett_023_110,
        &ett_023_110_STAT,
        &ett_023_120,
        &ett_023_120_TYPE,
        &ett_023_120_REF,
        &ett_023_120_COUNTER,
        &ett_023_200,
        &ett_023_200_RANGE,
        &ett_023_RE,
        &ett_023_SP,
        /* Category 034 */
        &ett_034_000,
        &ett_034_000_MT,
        &ett_034_010,
        &ett_034_020,
        &ett_034_020_SN,
        &ett_034_030,
        &ett_034_041,
        &ett_034_041_ARS,
        &ett_034_050,
        &ett_034_050_01,
        &ett_034_050_01_NOGO,
        &ett_034_050_01_RDPC,
        &ett_034_050_01_RDPR,
        &ett_034_050_01_OVL_RDP,
        &ett_034_050_01_OVL_XMT,
        &ett_034_050_01_MSC,
        &ett_034_050_01_TSV,
        &ett_034_050_02,
        &ett_034_050_02_ANT,
        &ett_034_050_02_CHAB,
        &ett_034_050_02_OVL,
        &ett_034_050_02_MSC,
        &ett_034_050_03,
        &ett_034_050_03_ANT,
        &ett_034_050_03_CHAB,
        &ett_034_050_03_OVL,
        &ett_034_050_03_MSC,
        &ett_034_050_04,
        &ett_034_050_04_ANT,
        &ett_034_050_04_CHAB,
        &ett_034_050_04_OVL_SUR,
        &ett_034_050_04_MSC,
        &ett_034_050_04_SCF,
        &ett_034_050_04_DLF,
        &ett_034_050_04_OVL_SCF,
        &ett_034_050_04_OVL_DLF,
        &ett_034_060,
        &ett_034_060_01,
        &ett_034_060_01_RED_RDP,
        &ett_034_060_01_RED_XMT,
        &ett_034_060_02,
        &ett_034_060_02_POL,
        &ett_034_060_02_RED_RAD,
        &ett_034_060_02_STC,
        &ett_034_060_03,
        &ett_034_060_03_RED_RAD,
        &ett_034_060_04,
        &ett_034_060_04_RED_RAD,
        &ett_034_060_04_CLU,
        &ett_034_070,
        &ett_034_070_TYP,
        &ett_034_070_COUNTER,
        &ett_034_090,
        &ett_034_090_RE,
        &ett_034_090_AE,
        &ett_034_100,
        &ett_035_100_RHOS,
        &ett_035_100_RHOE,
        &ett_035_100_THETAS,
        &ett_035_100_THETAE,
        &ett_034_110,
        &ett_034_110_TYP,
        &ett_034_120,
        &ett_034_120_H,
        &ett_034_120_LAT,
        &ett_034_120_LON,
        &ett_034_RE,
        &ett_034_SP,
        /* Category 048 */
        &ett_048_010,
        &ett_048_020,
        &ett_048_020_TYP,
        &ett_048_020_SIM,
        &ett_048_020_RDP,
        &ett_048_020_SPI,
        &ett_048_020_RAB,
        &ett_048_020_TST,
        &ett_048_020_ME,
        &ett_048_020_MI,
        &ett_048_020_FOE,
        &ett_048_030,
        &ett_048_030_WE,
        &ett_048_040,
        &ett_048_040_RHO,
        &ett_048_040_THETA,
        &ett_048_042,
        &ett_048_042_X,
        &ett_048_042_Y,
        &ett_048_050,
        &ett_048_050_V,
        &ett_048_050_G,
        &ett_048_050_L,
        &ett_048_050_SQUAWK,
        &ett_048_055,
        &ett_048_055_V,
        &ett_048_055_G,
        &ett_048_055_L,
        &ett_048_055_CODE,
        &ett_048_060,
        &ett_048_060_QA4,
        &ett_048_060_QA2,
        &ett_048_060_QA1,
        &ett_048_060_QB4,
        &ett_048_060_QB2,
        &ett_048_060_QB1,
        &ett_048_060_QC4,
        &ett_048_060_QC2,
        &ett_048_060_QC1,
        &ett_048_060_QD4,
        &ett_048_060_QD2,
        &ett_048_060_QD1,
        &ett_048_065,
        &ett_048_065_QA4,
        &ett_048_065_QA2,
        &ett_048_065_QA1,
        &ett_048_065_QB2,
        &ett_048_065_QB1,
        &ett_048_070,
        &ett_048_070_V,
        &ett_048_070_G,
        &ett_048_070_L,
        &ett_048_070_SQUAWK,
        &ett_048_080,
        &ett_048_080_QA4,
        &ett_048_080_QA2,
        &ett_048_080_QA1,
        &ett_048_080_QB4,
        &ett_048_080_QB2,
        &ett_048_080_QB1,
        &ett_048_080_QC4,
        &ett_048_080_QC2,
        &ett_048_080_QC1,
        &ett_048_080_QD4,
        &ett_048_080_QD2,
        &ett_048_080_QD1,
        &ett_048_090,
        &ett_048_090_V,
        &ett_048_090_G,
        &ett_048_090_FL,
        &ett_048_100,
        &ett_048_100_V,
        &ett_048_100_G,
        &ett_048_100_A4,
        &ett_048_100_A2,
        &ett_048_100_A1,
        &ett_048_100_B4,
        &ett_048_100_B2,
        &ett_048_100_B1,
        &ett_048_100_C4,
        &ett_048_100_C2,
        &ett_048_100_C1,
        &ett_048_100_D4,
        &ett_048_100_D2,
        &ett_048_100_D1,
        &ett_048_100_QA4,
        &ett_048_100_QA2,
        &ett_048_100_QA1,
        &ett_048_100_QB4,
        &ett_048_100_QB2,
        &ett_048_100_QB1,
        &ett_048_100_QC4,
        &ett_048_100_QC2,
        &ett_048_100_QC1,
        &ett_048_100_QD4,
        &ett_048_100_QD2,
        &ett_048_100_QD1,
        &ett_048_110,
        &ett_048_110_3DHEIGHT,
        &ett_048_120,
        &ett_048_120_01,
        &ett_048_120_01_D,
        &ett_048_120_01_CAL,
        &ett_048_120_02,
        &ett_048_120_02_DOP,
        &ett_048_120_02_AMB,
        &ett_048_120_02_FRQ,
        &ett_048_130,
        &ett_048_130_01,
        &ett_048_130_01_SRL,
        &ett_048_130_02,
        &ett_048_130_02_SRR,
        &ett_048_130_03,
        &ett_048_130_03_SAM,
        &ett_048_130_04,
        &ett_048_130_04_PRL,
        &ett_048_130_05,
        &ett_048_130_05_PAM,
        &ett_048_130_06,
        &ett_048_130_06_RPD,
        &ett_048_130_07,
        &ett_048_130_07_APD,
        &ett_048_140,
        &ett_048_161,
        &ett_048_161_TN,
        &ett_048_170,
        &ett_048_170_CNF,
        &ett_048_170_RAD,
        &ett_048_170_DOU,
        &ett_048_170_MAH,
        &ett_048_170_CDM,
        &ett_048_170_TRE,
        &ett_048_170_GHO,
        &ett_048_170_SUP,
        &ett_048_170_TCC,
        &ett_048_200,
        &ett_048_200_GS,
        &ett_048_200_HDG,
        &ett_048_210,
        &ett_048_210_X,
        &ett_048_210_Y,
        &ett_048_210_V,
        &ett_048_210_H,
        &ett_048_220,
        &ett_048_230,
        &ett_048_230_COM,
        &ett_048_230_STAT,
        &ett_048_230_SI,
        &ett_048_230_MSSC,
        &ett_048_230_ARC,
        &ett_048_230_AIC,
        &ett_048_230_B1A,
        &ett_048_230_B1B,
        &ett_048_240,
        &ett_048_250,
        &ett_048_260,
        &ett_048_260_ACAS,
        &ett_048_RE,
        &ett_048_SP,
        /* Category 062*/
        &ett_062_010,
        &ett_062_015,
        &ett_062_015_SI,
        &ett_062_040,
        &ett_062_060,
        &ett_062_060_CH,
        &ett_062_060_SQUAWK,
        &ett_062_070,
        &ett_062_080,
        &ett_062_080_MON,
        &ett_062_080_SPI,
        &ett_062_080_MRH,
        &ett_062_080_SRC,
        &ett_062_080_CNF,
        &ett_062_080_SIM,
        &ett_062_080_TSE,
        &ett_062_080_TSB,
        &ett_062_080_FPC,
        &ett_062_080_AFF,
        &ett_062_080_STP,
        &ett_062_080_KOS,
        &ett_062_080_AMA,
        &ett_062_080_MD4,
        &ett_062_080_ME,
        &ett_062_080_MI,
        &ett_062_080_MD5,
        &ett_062_080_CST,
        &ett_062_080_PSR,
        &ett_062_080_SSR,
        &ett_062_080_MDS,
        &ett_062_080_ADS,
        &ett_062_080_SUC,
        &ett_062_080_AAC,
        &ett_062_080_SDS,
        &ett_062_080_EMS,
        &ett_062_080_PFT,
        &ett_062_080_FPLT,
        &ett_062_080_DUPT,
        &ett_062_080_DUPF,
        &ett_062_080_DUPM,
        &ett_062_080_FRIFOE,
        &ett_062_080_COA,
        &ett_062_100,
        &ett_062_100_X,
        &ett_062_100_Y,
        &ett_062_100_X_v0_17,
        &ett_062_100_Y_v0_17,
        &ett_062_105,
        &ett_062_105_LAT,
        &ett_062_105_LON,
        &ett_062_110,
        &ett_062_110_01,
        &ett_062_110_01_M5,
        &ett_062_110_01_ID,
        &ett_062_110_01_DA,
        &ett_062_110_01_M1,
        &ett_062_110_01_M2,
        &ett_062_110_01_M3,
        &ett_062_110_01_MC,
        &ett_062_110_01_X,
        &ett_062_110_02,
        &ett_062_110_02_PIN,
        &ett_062_110_02_NAT,
        &ett_062_110_02_MIS,
        &ett_062_110_03,
        &ett_062_110_03_LAT,
        &ett_062_110_03_LON,
        &ett_062_110_04,
        &ett_062_110_04_RES,
        &ett_062_110_04_GA,
        &ett_062_110_05,
        &ett_062_110_05_SQUAWK,
        &ett_062_110_06,
        &ett_062_110_06_TOS,
        &ett_062_110_07,
        &ett_062_110_07_X5,
        &ett_062_110_07_XC,
        &ett_062_110_07_X3,
        &ett_062_110_07_X2,
        &ett_062_110_07_X1,
        /* v.0.17 */
        &ett_062_110_v0_17,
        &ett_062_110_A4,
        &ett_062_110_A2,
        &ett_062_110_A1,
        &ett_062_110_B2,
        &ett_062_110_B1,
        &ett_062_120,
        &ett_062_120_SQUAWK,
        &ett_062_130,
        &ett_062_130_ALT,
        &ett_062_135,
        &ett_062_135_QNH,
        &ett_062_135_ALT,
        &ett_062_136,
        &ett_062_136_ALT,
        &ett_062_180,
        &ett_062_180_SPEED,
        &ett_062_180_HEADING,
        &ett_062_185,
        &ett_062_185_VX,
        &ett_062_185_VY,
        &ett_062_200,
        &ett_062_200_TRANS,
        &ett_062_200_LONG,
        &ett_062_200_VERT,
        &ett_062_200_ADF,
        &ett_062_210,
        &ett_062_210_AX,
        &ett_062_210_AY,
        &ett_062_210_CLA,
        &ett_062_210_v0_17,
        &ett_062_220,
        &ett_062_220_ROCD,
        &ett_062_240,
        &ett_062_240_ROT,
        &ett_062_245,
        &ett_062_270,
        &ett_062_270_LENGTH,
        &ett_062_270_ORIENTATION,
        &ett_062_270_WIDTH,
        &ett_062_290,
        &ett_062_290_01,
        &ett_062_290_01_TRK,
        &ett_062_290_02,
        &ett_062_290_02_PSR,
        &ett_062_290_03,
        &ett_062_290_03_SSR,
        &ett_062_290_04,
        &ett_062_290_04_MDS,
        &ett_062_290_05,
        &ett_062_290_05_ADS,
        &ett_062_290_06,
        &ett_062_290_06_ES,
        &ett_062_290_07,
        &ett_062_290_07_VDL,
        &ett_062_290_08,
        &ett_062_290_08_UAT,
        &ett_062_290_09,
        &ett_062_290_09_LOP,
        &ett_062_290_10,
        &ett_062_290_10_MLT,
        /* v.0.17 */
        &ett_062_290_01_v0_17,
        &ett_062_290_01_PSR,
        &ett_062_290_02_v0_17,
        &ett_062_290_02_SSR,
        &ett_062_290_03_v0_17,
        &ett_062_290_03_MDA,
        &ett_062_290_04_v0_17,
        &ett_062_290_04_MFL,
        &ett_062_290_05_v0_17,
        &ett_062_290_05_MDS,
        &ett_062_290_06_v0_17,
        &ett_062_290_06_ADS,
        &ett_062_290_07_v0_17,
        &ett_062_290_07_ADB,
        &ett_062_290_08_v0_17,
        &ett_062_290_08_MD1,
        &ett_062_290_09_v0_17,
        &ett_062_290_09_MD2,
        &ett_062_295,
        &ett_062_295_01,
        &ett_062_295_01_MFL,
        &ett_062_295_02,
        &ett_062_295_02_MD1,
        &ett_062_295_03,
        &ett_062_295_03_MD2,
        &ett_062_295_04,
        &ett_062_295_04_MDA,
        &ett_062_295_05,
        &ett_062_295_05_MD4,
        &ett_062_295_06,
        &ett_062_295_06_MD5,
        &ett_062_295_07,
        &ett_062_295_07_MHD,
        &ett_062_295_08,
        &ett_062_295_08_IAS,
        &ett_062_295_09,
        &ett_062_295_09_TAS,
        &ett_062_295_10,
        &ett_062_295_10_SAL,
        &ett_062_295_11,
        &ett_062_295_11_FSS,
        &ett_062_295_12,
        &ett_062_295_12_TID,
        &ett_062_295_13,
        &ett_062_295_13_COM,
        &ett_062_295_14,
        &ett_062_295_14_SAB,
        &ett_062_295_15,
        &ett_062_295_15_ACS,
        &ett_062_295_16,
        &ett_062_295_16_BVR,
        &ett_062_295_17,
        &ett_062_295_17_GVR,
        &ett_062_295_18,
        &ett_062_295_18_RAN,
        &ett_062_295_19,
        &ett_062_295_19_TAR,
        &ett_062_295_20,
        &ett_062_295_20_TAN,
        &ett_062_295_21,
        &ett_062_295_21_GSP,
        &ett_062_295_22,
        &ett_062_295_22_VUN,
        &ett_062_295_23,
        &ett_062_295_23_MET,
        &ett_062_295_24,
        &ett_062_295_24_EMC,
        &ett_062_295_25,
        &ett_062_295_25_POS,
        &ett_062_295_26,
        &ett_062_295_26_GAL,
        &ett_062_295_27,
        &ett_062_295_27_PUN,
        &ett_062_295_28,
        &ett_062_295_28_MB,
        &ett_062_295_29,
        &ett_062_295_29_IAR,
        &ett_062_295_30,
        &ett_062_295_30_MAC,
        &ett_062_295_31,
        &ett_062_295_31_BPS,
        &ett_062_300,
        &ett_062_300_VFI,
        &ett_062_340,
        &ett_062_340_01,
        &ett_062_340_02,
        &ett_062_340_02_RHO,
        &ett_062_340_02_THETA,
        &ett_062_340_03,
        &ett_062_340_03_H,
        &ett_062_340_04,
        &ett_062_340_04_V,
        &ett_062_340_04_G,
        &ett_062_340_04_FL,
        &ett_062_340_05,
        &ett_062_340_05_V,
        &ett_062_340_05_G,
        &ett_062_340_05_L,
        &ett_062_340_05_SQUAWK,
        &ett_062_340_06,
        &ett_062_340_06_TYP,
        &ett_062_340_06_SIM,
        &ett_062_340_06_RAB,
        &ett_062_340_06_TST,
        &ett_062_380,
        &ett_062_380_01,
        &ett_062_380_02,
        &ett_062_380_03,
        &ett_062_380_03_MH,
        &ett_062_380_04,
        &ett_062_380_04_IM,
        &ett_062_380_04_IAS,
        &ett_062_380_05,
        &ett_062_380_05_TAS,
        &ett_062_380_06,
        &ett_062_380_06_SAS,
        &ett_062_380_06_SOURCE,
        &ett_062_380_06_ALT,
        &ett_062_380_07,
        &ett_062_380_07_MV,
        &ett_062_380_07_AH,
        &ett_062_380_07_AM,
        &ett_062_380_07_ALT,
        &ett_062_380_08,
        &ett_062_380_08_NAV,
        &ett_062_380_08_NVB,
        &ett_062_380_09,
        &ett_062_380_09_TCA,
        &ett_062_380_09_NC,
        &ett_062_380_09_TCP,
        &ett_062_380_09_ALT,
        &ett_062_380_09_LAT,
        &ett_062_380_09_LON,
        &ett_062_380_09_PTYP,
        &ett_062_380_09_TD,
        &ett_062_380_09_TRA,
        &ett_062_380_09_TOA,
        &ett_062_380_09_TOV,
        &ett_062_380_09_TTR,
        &ett_062_380_10,
        &ett_062_380_10_COM,
        &ett_062_380_10_STAT,
        &ett_062_380_10_SSC,
        &ett_062_380_10_ARC,
        &ett_062_380_10_AIC,
        &ett_062_380_10_B1A,
        &ett_062_380_10_B1B,
        &ett_062_380_11,
        &ett_062_380_11_AC,
        &ett_062_380_11_MN,
        &ett_062_380_11_DC,
        &ett_062_380_11_GBS,
        &ett_062_380_11_STAT,
        &ett_062_380_12,
        &ett_062_380_12_MB,
        &ett_062_380_13,
        &ett_062_380_13_BVR,
        &ett_062_380_14,
        &ett_062_380_14_GVR,
        &ett_062_380_15,
        &ett_062_380_15_ROLL,
        &ett_062_380_16,
        &ett_062_380_16_TI,
        &ett_062_380_16_RATE,
        &ett_062_380_17,
        &ett_062_380_17_TA,
        &ett_062_380_18,
        &ett_062_380_18_GS,
        &ett_062_380_19,
        &ett_062_380_19_VUC,
        &ett_062_380_20,
        &ett_062_380_20_WS,
        &ett_062_380_20_WD,
        &ett_062_380_20_TMP,
        &ett_062_380_20_TRB,
        &ett_062_380_20_WS_VAL,
        &ett_062_380_20_WD_VAL,
        &ett_062_380_20_TMP_VAL,
        &ett_062_380_20_TRB_VAL,
        &ett_062_380_21,
        &ett_062_380_21_ECAT,
        &ett_062_380_22,
        &ett_062_380_22_LAT,
        &ett_062_380_22_LON,
        &ett_062_380_23,
        &ett_062_380_23_ALT,
        &ett_062_380_24,
        &ett_062_380_24_PUN,
        &ett_062_380_25,
        &ett_062_380_26,
        &ett_062_380_26_IAS,
        &ett_062_380_27,
        &ett_062_380_27_MACH,
        &ett_062_380_28,
        &ett_062_380_28_BPS,
        /* v.0.17 */
        &ett_062_380_v0_17,
        &ett_062_380_01_v0_17,
        &ett_062_380_02_v0_17,
        &ett_062_380_03_v0_17,
        &ett_062_380_04_v0_17,
        &ett_062_380_04_COM,
        &ett_062_380_04_STAT,
        &ett_062_380_04_SSC,
        &ett_062_380_04_ARC,
        &ett_062_380_04_AIC,
        &ett_062_380_04_B1A,
        &ett_062_380_04_B1B,
        &ett_062_380_05_v0_17,
        &ett_062_380_05_MB,
        &ett_062_390,
        &ett_062_390_01,
        &ett_062_390_02,
        &ett_062_390_02_CS,
        &ett_062_390_03,
        &ett_062_390_03_TYP,
        &ett_062_390_03_NBR,
        &ett_062_390_04,
        &ett_062_390_04_GAT_OAT,
        &ett_062_390_04_FR12,
        &ett_062_390_04_RVSM,
        &ett_062_390_04_HPR,
        &ett_062_390_05,
        &ett_062_390_05_ACTYP,
        &ett_062_390_06,
        &ett_062_390_06_WTC,
        &ett_062_390_07,
        &ett_062_390_07_ADEP,
        &ett_062_390_08,
        &ett_062_390_08_ADES,
        &ett_062_390_09,
        &ett_062_390_09_NU1,
        &ett_062_390_09_NU2,
        &ett_062_390_09_LTR,
        &ett_062_390_10,
        &ett_062_390_10_CFL,
        &ett_062_390_11,
        &ett_062_390_11_CNTR,
        &ett_062_390_11_POS,
        &ett_062_390_12,
        &ett_062_390_12_TYP,
        &ett_062_390_12_DAY,
        &ett_062_390_12_HOR,
        &ett_062_390_12_MIN,
        &ett_062_390_12_AVS,
        &ett_062_390_12_SEC,
        &ett_062_390_13,
        &ett_062_390_13_STAND,
        &ett_062_390_14,
        &ett_062_390_14_EMP,
        &ett_062_390_14_AVL,
        &ett_062_390_15,
        &ett_062_390_15_SID,
        &ett_062_390_16,
        &ett_062_390_16_STAR,
        &ett_062_390_17,
        &ett_062_390_17_VA,
        &ett_062_390_17_SQUAWK,
        &ett_062_390_18,
        &ett_062_390_18_CS,
        &ett_062_500,
        &ett_062_500_01,
        &ett_062_500_01_APCX,
        &ett_062_500_01_APCY,
        &ett_062_500_02,
        &ett_062_500_02_COV,
        &ett_062_500_03,
        &ett_062_500_03_APWLAT,
        &ett_062_500_03_APWLON,
        &ett_062_500_04,
        &ett_062_500_04_AGA,
        &ett_062_500_05,
        &ett_062_500_05_ABA,
        &ett_062_500_06,
        &ett_062_500_06_ATVX,
        &ett_062_500_06_ATVY,
        &ett_062_500_07,
        &ett_062_500_07_AAX,
        &ett_062_500_07_AAY,
        &ett_062_500_08,
        &ett_062_500_08_ARC,
        /* v.0.17 */
        &ett_062_500_01_APCX_8bit,
        &ett_062_500_01_APCY_8bit,
        &ett_062_500_02_v0_17,
        &ett_062_500_02_APWLAT,
        &ett_062_500_02_APWLON,
        &ett_062_500_03_v0_17,
        &ett_062_500_03_ATA,
        &ett_062_500_04_v0_17,
        &ett_062_500_04_ATF,
        &ett_062_500_05_v0_17,
        &ett_062_500_05_ATVS,
        &ett_062_500_05_ATVH,
        &ett_062_500_06_v0_17,
        &ett_062_500_06_ART,
        &ett_062_500_07_v0_17,
        &ett_062_500_07_ALA,
        &ett_062_510,
        &ett_062_510_SID,
        &ett_062_510_STN,
        &ett_062_RE,
        &ett_062_RE_CST,
        &ett_062_RE_CST_SAC,
        &ett_062_RE_CST_SIC,
        &ett_062_RE_CST_TYP,
        &ett_062_RE_CST_TRK_NUM,
        &ett_062_RE_CSNT,
        &ett_062_RE_CSNT_SAC,
        &ett_062_RE_CSNT_SIC,
        &ett_062_RE_CSNT_TYP,
        &ett_062_RE_TVS,
        &ett_062_RE_TVS_VX,
        &ett_062_RE_TVS_VY,
        &ett_062_RE_STS,
        &ett_062_RE_STS_FDR,
        &ett_062_SP,
        /* Category 063 */
        &ett_063_010,
        &ett_063_015,
        &ett_063_030,
        &ett_063_050,
        &ett_063_060,
        &ett_063_070,
        &ett_063_080,
        &ett_063_081,
        &ett_063_090,
        &ett_063_091,
        &ett_063_092,
        &ett_063_RE,
        &ett_063_SP,
        /* Category 065 */
        &ett_065_000,
        &ett_065_010,
        &ett_065_015,
        &ett_065_020,
        &ett_065_030,
        &ett_065_040,
        &ett_065_050,
        &ett_065_RE,
        &ett_065_SP
    };

    module_t *asterix_prefs_module;

    proto_asterix = proto_register_protocol (
        "ASTERIX packet", /* name       */
        "ASTERIX",        /* short name */
        "asterix"         /* abbrev     */
    );

    proto_register_field_array (proto_asterix, hf, array_length (hf));
    proto_register_subtree_array (ett, array_length (ett));

    asterix_handle = register_dissector ("asterix", dissect_asterix, proto_asterix);

    asterix_prefs_module = prefs_register_protocol (proto_asterix, proto_reg_handoff_asterix);

    prefs_register_enum_preference (asterix_prefs_module, "i001_version", "I001 version", "Select the CAT001 version", &global_categories_version[1],  I001_versions, FALSE);
    prefs_register_enum_preference (asterix_prefs_module, "i002_version", "I002 version", "Select the CAT001 version", &global_categories_version[2],  I002_versions, FALSE);
    prefs_register_enum_preference (asterix_prefs_module, "i008_version", "I008 version", "Select the CAT008 version", &global_categories_version[8],  I008_versions, FALSE);
    prefs_register_enum_preference (asterix_prefs_module, "i009_version", "I009 version", "Select the CAT009 version", &global_categories_version[9],  I009_versions, FALSE);
    prefs_register_enum_preference (asterix_prefs_module, "i021_version", "I021 version", "Select the CAT021 version", &global_categories_version[21], I021_versions, FALSE);
    prefs_register_enum_preference (asterix_prefs_module, "i023_version", "I023 version", "Select the CAT023 version", &global_categories_version[23], I023_versions, FALSE);
    prefs_register_enum_preference (asterix_prefs_module, "i034_version", "I034 version", "Select the CAT034 version", &global_categories_version[34], I034_versions, FALSE);
    prefs_register_enum_preference (asterix_prefs_module, "i048_version", "I048 version", "Select the CAT048 version", &global_categories_version[48], I048_versions, FALSE);
    prefs_register_enum_preference (asterix_prefs_module, "i062_version", "I062 version", "Select the CAT062 version", &global_categories_version[62], I062_versions, FALSE);
    prefs_register_enum_preference (asterix_prefs_module, "i063_version", "I063 version", "Select the CAT063 version", &global_categories_version[63], I063_versions, FALSE);
    prefs_register_enum_preference (asterix_prefs_module, "i065_version", "I065 version", "Select the CAT065 version", &global_categories_version[65], I065_versions, FALSE);
}

void proto_reg_handoff_asterix (void)
{
    dissector_add_uint ("udp.port", ASTERIX_PORT, asterix_handle);
}

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
