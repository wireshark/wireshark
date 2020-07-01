/* packet-asterix.c
 * Routines for ASTERIX decoding
 * By Marko Hrastovec <marko.hrastovec@sloveniacontrol.si>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * ASTERIX (All-purpose structured EUROCONTROL surveillances
 * information exchange) is a protocol related to air traffic control.
 *
 * The specifications can be downloaded from
 * http://www.eurocontrol.int/services/asterix
 */

#include <config.h>

#include <wsutil/bits_ctz.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>

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
static gint hf_001_050_V = -1;
static gint hf_001_050_G = -1;
static gint hf_001_050_L = -1;
static gint hf_001_050_SQUAWK = -1;
static gint hf_001_060 = -1;
static gint hf_001_060_QA4 = -1;
static gint hf_001_060_QA2 = -1;
static gint hf_001_060_QA1 = -1;
static gint hf_001_060_QB4 = -1;
static gint hf_001_060_QB2 = -1;
static gint hf_001_060_QB1 = -1;
static gint hf_001_060_QC4 = -1;
static gint hf_001_060_QC2 = -1;
static gint hf_001_060_QC1 = -1;
static gint hf_001_060_QD4 = -1;
static gint hf_001_060_QD2 = -1;
static gint hf_001_060_QD1 = -1;
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
static gint hf_001_100_V = -1;
static gint hf_001_100_G = -1;
static gint hf_001_100_C1 = -1;
static gint hf_001_100_A1 = -1;
static gint hf_001_100_C2 = -1;
static gint hf_001_100_A2 = -1;
static gint hf_001_100_C4 = -1;
static gint hf_001_100_A4 = -1;
static gint hf_001_100_B1 = -1;
static gint hf_001_100_D1 = -1;
static gint hf_001_100_B2 = -1;
static gint hf_001_100_D2 = -1;
static gint hf_001_100_B4 = -1;
static gint hf_001_100_D4 = -1;
static gint hf_001_100_QC1 = -1;
static gint hf_001_100_QA1 = -1;
static gint hf_001_100_QC2 = -1;
static gint hf_001_100_QA2 = -1;
static gint hf_001_100_QC4 = -1;
static gint hf_001_100_QA4 = -1;
static gint hf_001_100_QB1 = -1;
static gint hf_001_100_QD1 = -1;
static gint hf_001_100_QB2 = -1;
static gint hf_001_100_QD2 = -1;
static gint hf_001_100_QB4 = -1;
static gint hf_001_100_QD4 = -1;
static gint hf_001_120 = -1;
static gint hf_001_120_MRDS = -1;
static gint hf_001_130 = -1;
static gint hf_001_130_RPC = -1;
static gint hf_001_131 = -1;
static gint hf_001_131_RP = -1;
static gint hf_001_141 = -1;
static gint hf_001_141_TTOD = -1;
static gint hf_001_150 = -1;
static gint hf_001_150_XA = -1;
static gint hf_001_150_XC = -1;
static gint hf_001_150_X2 = -1;
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
static gint hf_001_200_CGS = -1;
static gint hf_001_200_CH = -1;
static gint hf_001_210 = -1;
static gint hf_001_210_TQ = -1;
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
/* Category 004 */
static gint hf_004_000 = -1;
static gint hf_004_000_MT = -1;
static gint hf_004_010 = -1;
static gint hf_004_015 = -1;
static gint hf_004_020 = -1;
static gint hf_004_030 = -1;
static gint hf_004_030_TN1 = -1;
static gint hf_004_035 = -1;
static gint hf_004_035_TN2 = -1;
static gint hf_004_040 = -1;
static gint hf_004_040_AI = -1;
static gint hf_004_045 = -1;
static gint hf_004_045_AS = -1;
static gint hf_004_060 = -1;
static gint hf_004_060_MRVA = -1;
static gint hf_004_060_RAMLD = -1;
static gint hf_004_060_RAMHD = -1;
static gint hf_004_060_MSAW = -1;
static gint hf_004_060_APW = -1;
static gint hf_004_060_CLAM = -1;
static gint hf_004_060_STCA = -1;
static gint hf_004_060_AFDA = -1;
static gint hf_004_060_RIMCA = -1;
static gint hf_004_060_ACASRA = -1;
static gint hf_004_060_NTCA = -1;
static gint hf_004_060_DG = -1;
static gint hf_004_060_OF = -1;
static gint hf_004_060_OL = -1;
static gint hf_004_070 = -1;
static gint hf_004_070_01 = -1;
static gint hf_004_070_01_TC = -1;
static gint hf_004_070_02 = -1;
static gint hf_004_070_02_TCA = -1;
static gint hf_004_070_03 = -1;
static gint hf_004_070_03_CHS = -1;
static gint hf_004_070_04 = -1;
static gint hf_004_070_04_MHS = -1;
static gint hf_004_070_05 = -1;
static gint hf_004_070_05_CVS = -1;
static gint hf_004_070_06 = -1;
static gint hf_004_070_06_MVS = -1;
static gint hf_004_074 = -1;
static gint hf_004_074_LD = -1;
static gint hf_004_075 = -1;
static gint hf_004_075_TDD = -1;
static gint hf_004_076 = -1;
static gint hf_004_076_VD = -1;
static gint hf_004_100 = -1;
static gint hf_004_100_01 = -1;
static gint hf_004_100_01_AN = -1;
static gint hf_004_100_02 = -1;
static gint hf_004_100_02_CAN = -1;
static gint hf_004_100_03 = -1;
static gint hf_004_100_03_RT1 = -1;
static gint hf_004_100_04 = -1;
static gint hf_004_100_04_RT2 = -1;
static gint hf_004_100_05 = -1;
static gint hf_004_100_05_SB = -1;
static gint hf_004_100_06 = -1;
static gint hf_004_100_06_G = -1;
static gint hf_004_110 = -1;
static gint hf_004_110_Centre = -1;
static gint hf_004_110_Position = -1;
static gint hf_004_120 = -1;
static gint hf_004_120_01 = -1;
static gint hf_004_120_01_MAS = -1;
static gint hf_004_120_01_CAS = -1;
static gint hf_004_120_01_FLD = -1;
static gint hf_004_120_01_FVD = -1;
static gint hf_004_120_01_Type = -1;
static gint hf_004_120_01_Cross = -1;
static gint hf_004_120_01_Div = -1;
static gint hf_004_120_01_RRC = -1;
static gint hf_004_120_01_RTC = -1;
static gint hf_004_120_01_MRVA = -1;
static gint hf_004_120_02 = -1;
static gint hf_004_120_02_TID = -1;
static gint hf_004_120_02_SC = -1;
static gint hf_004_120_02_CS = -1;
static gint hf_004_120_03 = -1;
static gint hf_004_120_03_Probability = -1;
static gint hf_004_120_04 = -1;
static gint hf_004_120_04_Duration = -1;
static gint hf_004_170 = -1;
static gint hf_004_170_01 = -1;
static gint hf_004_170_01_AI1 = -1;
static gint hf_004_170_02 = -1;
static gint hf_004_170_02_M31 = -1;
static gint hf_004_170_03 = -1;
static gint hf_004_170_03_LAT = -1;
static gint hf_004_170_03_LON = -1;
static gint hf_004_170_03_ALT = -1;
static gint hf_004_170_04 = -1;
static gint hf_004_170_04_X = -1;
static gint hf_004_170_04_Y = -1;
static gint hf_004_170_04_Z = -1;
static gint hf_004_170_05 = -1;
static gint hf_004_170_05_TT1 = -1;
static gint hf_004_170_06 = -1;
static gint hf_004_170_06_DT1 = -1;
static gint hf_004_170_07 = -1;
static gint hf_004_170_07_GATOAT = -1;
static gint hf_004_170_07_FR1FR2 = -1;
static gint hf_004_170_07_RVSM = -1;
static gint hf_004_170_07_HPR = -1;
static gint hf_004_170_07_CDM = -1;
static gint hf_004_170_07_PRI = -1;
static gint hf_004_170_07_GV = -1;
static gint hf_004_170_08 = -1;
static gint hf_004_170_08_MS1 = -1;
static gint hf_004_170_09 = -1;
static gint hf_004_170_09_FP1 = -1;
static gint hf_004_170_10 = -1;
static gint hf_004_170_10_CF1 = -1;
static gint hf_004_171 = -1;
static gint hf_004_171_01 = -1;
static gint hf_004_171_01_AI2 = -1;
static gint hf_004_171_02 = -1;
static gint hf_004_171_02_M32 = -1;
static gint hf_004_171_03 = -1;
static gint hf_004_171_03_LAT = -1;
static gint hf_004_171_03_LON = -1;
static gint hf_004_171_03_ALT = -1;
static gint hf_004_171_04 = -1;
static gint hf_004_171_04_X = -1;
static gint hf_004_171_04_Y = -1;
static gint hf_004_171_04_Z = -1;
static gint hf_004_171_05 = -1;
static gint hf_004_171_05_TT2 = -1;
static gint hf_004_171_06 = -1;
static gint hf_004_171_06_DT2 = -1;
static gint hf_004_171_07 = -1;
static gint hf_004_171_07_GATOAT = -1;
static gint hf_004_171_07_FR1FR2 = -1;
static gint hf_004_171_07_RVSM = -1;
static gint hf_004_171_07_HPR = -1;
static gint hf_004_171_07_CDM = -1;
static gint hf_004_171_07_PRI = -1;
static gint hf_004_171_07_GV = -1;
static gint hf_004_171_08 = -1;
static gint hf_004_171_08_MS2 = -1;
static gint hf_004_171_09 = -1;
static gint hf_004_171_09_FP2 = -1;
static gint hf_004_171_10 = -1;
static gint hf_004_171_10_CF2 = -1;
static gint hf_004_SP = -1;
static gint hf_004_RE = -1;
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
/* Category 010 */
static gint hf_010_000 = -1;
static gint hf_010_000_MT = -1;
static gint hf_010_010 = -1;
static gint hf_010_020 = -1;
static gint hf_010_020_TYP = -1;
static gint hf_010_020_DCR = -1;
static gint hf_010_020_CHN = -1;
static gint hf_010_020_GBS = -1;
static gint hf_010_020_CRT = -1;
static gint hf_010_020_SIM = -1;
static gint hf_010_020_TST = -1;
static gint hf_010_020_RAB = -1;
static gint hf_010_020_LOP = -1;
static gint hf_010_020_TOT = -1;
static gint hf_010_020_SPI = -1;
static gint hf_010_040 = -1;
static gint hf_010_040_RHO = -1;
static gint hf_010_040_THETA = -1;
static gint hf_010_041 = -1;
static gint hf_010_041_LAT = -1;
static gint hf_010_041_LON = -1;
static gint hf_010_042 = -1;
static gint hf_010_042_X = -1;
static gint hf_010_042_Y = -1;
static gint hf_010_060 = -1;
static gint hf_010_060_V = -1;
static gint hf_010_060_G = -1;
static gint hf_010_060_L = -1;
static gint hf_010_060_SQUAWK = -1;
static gint hf_010_090 = -1;
static gint hf_010_090_V = -1;
static gint hf_010_090_G = -1;
static gint hf_010_090_FL = -1;
static gint hf_010_091 = -1;
static gint hf_010_091_MH = -1;
static gint hf_010_131 = -1;
static gint hf_010_131_PAM = -1;
static gint hf_010_140 = -1;
static gint hf_010_161 = -1;
static gint hf_010_161_TN = -1;
static gint hf_010_170 = -1;
static gint hf_010_170_CNF = -1;
static gint hf_010_170_TRE = -1;
static gint hf_010_170_CST = -1;
static gint hf_010_170_MAH = -1;
static gint hf_010_170_TCC = -1;
static gint hf_010_170_STH = -1;
static gint hf_010_170_TOM = -1;
static gint hf_010_170_DOU = -1;
static gint hf_010_170_MRS = -1;
static gint hf_010_170_GHO = -1;
static gint hf_010_200 = -1;
static gint hf_010_200_GS = -1;
static gint hf_010_200_TA = -1;
static gint hf_010_202 = -1;
static gint hf_010_202_VX = -1;
static gint hf_010_202_VY = -1;
static gint hf_010_210 = -1;
static gint hf_010_210_AX = -1;
static gint hf_010_210_AY = -1;
static gint hf_010_220 = -1;
static gint hf_010_245 = -1;
static gint hf_010_245_STI = -1;
static gint hf_010_250 = -1;
static gint hf_010_270 = -1;
static gint hf_010_270_LENGTH = -1;
static gint hf_010_270_ORIENTATION = -1;
static gint hf_010_270_WIDTH = -1;
static gint hf_010_280 = -1;
static gint hf_010_280_DRHO = -1;
static gint hf_010_280_DTHETA = -1;
static gint hf_010_300 = -1;
static gint hf_010_300_VFI = -1;
static gint hf_010_310 = -1;
static gint hf_010_310_TRB = -1;
static gint hf_010_310_MSG = -1;
static gint hf_010_500 = -1;
static gint hf_010_500_SDPx = -1;
static gint hf_010_500_SDPy = -1;
static gint hf_010_500_SDPxy = -1;
static gint hf_010_550 = -1;
static gint hf_010_550_NOGO = -1;
static gint hf_010_550_OVL = -1;
static gint hf_010_550_TSV = -1;
static gint hf_010_550_DIV = -1;
static gint hf_010_550_TTF = -1;
static gint hf_010_SP = -1;
static gint hf_010_RE = -1;
/* Category 011 */
static gint hf_011_000 = -1;
static gint hf_011_000_MT = -1;
static gint hf_011_010 = -1;
static gint hf_011_015 = -1;
static gint hf_011_015_SI = -1;
static gint hf_011_041 = -1;
static gint hf_011_041_LAT = -1;
static gint hf_011_041_LON = -1;
static gint hf_011_042 = -1;
static gint hf_011_042_X = -1;
static gint hf_011_042_Y = -1;
static gint hf_011_060 = -1;
static gint hf_011_060_SQUAWK = -1;
static gint hf_011_090 = -1;
static gint hf_011_090_MFL = -1;
static gint hf_011_092 = -1;
static gint hf_011_092_ALT = -1;
static gint hf_011_093 = -1;
static gint hf_011_093_QNH = -1;
static gint hf_011_093_ALT = -1;
static gint hf_011_140 = -1;
static gint hf_011_161 = -1;
static gint hf_011_161_TN = -1;
static gint hf_011_170 = -1;
static gint hf_011_170_MON = -1;
static gint hf_011_170_GBS = -1;
static gint hf_011_170_MRH = -1;
static gint hf_011_170_SRC = -1;
static gint hf_011_170_CNF = -1;
static gint hf_011_170_SIM = -1;
static gint hf_011_170_TSE = -1;
static gint hf_011_170_TSB = -1;
static gint hf_011_170_FRIFOE = -1;
static gint hf_011_170_ME = -1;
static gint hf_011_170_MI = -1;
static gint hf_011_170_AMA = -1;
static gint hf_011_170_SPI = -1;
static gint hf_011_170_CST = -1;
static gint hf_011_170_FPC = -1;
static gint hf_011_170_AFF = -1;
static gint hf_011_170_PSR = -1;
static gint hf_011_170_SSR = -1;
static gint hf_011_170_MDS = -1;
static gint hf_011_170_ADS = -1;
static gint hf_011_170_SUC = -1;
static gint hf_011_170_AAC = -1;
static gint hf_011_202 = -1;
static gint hf_011_202_VX = -1;
static gint hf_011_202_VY = -1;
static gint hf_011_210 = -1;
static gint hf_011_210_AX = -1;
static gint hf_011_210_AY = -1;
static gint hf_011_215 = -1;
static gint hf_011_215_ROCD = -1;
static gint hf_011_245 = -1;
static gint hf_011_245_STI = -1;
static gint hf_011_270 = -1;
static gint hf_011_270_LENGTH = -1;
static gint hf_011_270_ORIENTATION = -1;
static gint hf_011_270_WIDTH = -1;
static gint hf_011_290 = -1;
static gint hf_011_290_01 = -1;
static gint hf_011_290_01_PSR = -1;
static gint hf_011_290_02 = -1;
static gint hf_011_290_02_SSR = -1;
static gint hf_011_290_03 = -1;
static gint hf_011_290_03_MDA = -1;
static gint hf_011_290_04 = -1;
static gint hf_011_290_04_MFL = -1;
static gint hf_011_290_05 = -1;
static gint hf_011_290_05_MDS = -1;
static gint hf_011_290_06 = -1;
static gint hf_011_290_06_ADS = -1;
static gint hf_011_290_07 = -1;
static gint hf_011_290_07_ADB = -1;
static gint hf_011_290_08 = -1;
static gint hf_011_290_08_MD1 = -1;
static gint hf_011_290_09 = -1;
static gint hf_011_290_09_MD2 = -1;
static gint hf_011_290_10 = -1;
static gint hf_011_290_10_LOP = -1;
static gint hf_011_290_11 = -1;
static gint hf_011_290_11_TRK = -1;
static gint hf_011_290_12 = -1;
static gint hf_011_290_12_MUL = -1;
static gint hf_011_300 = -1;
static gint hf_011_300_VFI = -1;
static gint hf_011_310 = -1;
static gint hf_011_310_TRB = -1;
static gint hf_011_310_MSG = -1;
static gint hf_011_380 = -1;
static gint hf_011_380_01 = -1;
static gint hf_011_380_02 = -1;
/* #3 Never Sent */
static gint hf_011_380_04 = -1;
static gint hf_011_380_04_COM = -1;
static gint hf_011_380_04_STAT = -1;
static gint hf_011_380_04_SSC = -1;
static gint hf_011_380_04_ARC = -1;
static gint hf_011_380_04_AIC = -1;
static gint hf_011_380_04_B1A = -1;
static gint hf_011_380_04_B1B = -1;
static gint hf_011_380_04_AC = -1;
static gint hf_011_380_04_MN = -1;
static gint hf_011_380_04_DC = -1;
/* #5 to #7 Never Sent */
static gint hf_011_380_08 = -1;
static gint hf_011_380_08_ADAT = -1;
static gint hf_011_380_09 = -1;
static gint hf_011_380_09_ECAT = -1;
/* #10 Never Sent */
static gint hf_011_380_11 = -1;
static gint hf_011_380_11_VDL = -1;
static gint hf_011_380_11_MDS = -1;
static gint hf_011_380_11_UAT = -1;
static gint hf_011_390 = -1;
static gint hf_011_390_01 = -1;
static gint hf_011_390_02 = -1;
static gint hf_011_390_02_CSN = -1;
static gint hf_011_390_03 = -1;
static gint hf_011_390_03_TYP = -1;
static gint hf_011_390_03_NBR = -1;
static gint hf_011_390_04 = -1;
static gint hf_011_390_04_GAT_OAT = -1;
static gint hf_011_390_04_FR12 = -1;
static gint hf_011_390_04_RVSM = -1;
static gint hf_011_390_04_HPR = -1;
static gint hf_011_390_05 = -1;
static gint hf_011_390_05_ACTYP = -1;
static gint hf_011_390_06 = -1;
static gint hf_011_390_06_WTC = -1;
static gint hf_011_390_07 = -1;
static gint hf_011_390_07_ADEP = -1;
static gint hf_011_390_08 = -1;
static gint hf_011_390_08_ADES = -1;
static gint hf_011_390_09 = -1;
static gint hf_011_390_09_RWY = -1;
static gint hf_011_390_10 = -1;
static gint hf_011_390_10_CFL = -1;
static gint hf_011_390_11 = -1;
static gint hf_011_390_11_CNTR = -1;
static gint hf_011_390_11_POS = -1;
static gint hf_011_390_12 = -1;
static gint hf_011_390_12_TYP = -1;
static gint hf_011_390_12_DAY = -1;
static gint hf_011_390_12_HOR = -1;
static gint hf_011_390_12_MIN = -1;
static gint hf_011_390_12_AVS = -1;
static gint hf_011_390_12_SEC = -1;
static gint hf_011_390_13 = -1;
static gint hf_011_390_13_STAND = -1;
static gint hf_011_390_14 = -1;
static gint hf_011_390_14_EMP = -1;
static gint hf_011_390_14_AVL = -1;
static gint hf_011_430 = -1;
static gint hf_011_430_FLS = -1;
static gint hf_011_500 = -1;
static gint hf_011_500_01 = -1;
static gint hf_011_500_01_APCX = -1;
static gint hf_011_500_01_APCY = -1;
static gint hf_011_500_02 = -1;
static gint hf_011_500_02_APWLAT = -1;
static gint hf_011_500_02_APWLON = -1;
static gint hf_011_500_03 = -1;
static gint hf_011_500_03_ATA = -1;
static gint hf_011_500_04 = -1;
static gint hf_011_500_04_AVCX = -1;
static gint hf_011_500_04_AVCY = -1;
static gint hf_011_500_05 = -1;
static gint hf_011_500_05_ARC = -1;
static gint hf_011_500_06 = -1;
static gint hf_011_500_06_AACX = -1;
static gint hf_011_500_06_AACY = -1;
static gint hf_011_600 = -1;
static gint hf_011_600_ACK = -1;
static gint hf_011_600_SVR = -1;
static gint hf_011_600_ALT = -1;
static gint hf_011_600_ALN = -1;
static gint hf_011_605 = -1;
static gint hf_011_605_FTN = -1;
static gint hf_011_610 = -1;
static gint hf_011_610_BKN = -1;
static gint hf_011_610_I01 = -1;
static gint hf_011_610_I02 = -1;
static gint hf_011_610_I03 = -1;
static gint hf_011_610_I04 = -1;
static gint hf_011_610_I05 = -1;
static gint hf_011_610_I06 = -1;
static gint hf_011_610_I07 = -1;
static gint hf_011_610_I08 = -1;
static gint hf_011_610_I09 = -1;
static gint hf_011_610_I10 = -1;
static gint hf_011_610_I11 = -1;
static gint hf_011_610_I12 = -1;
static gint hf_011_SP = -1;
static gint hf_011_RE = -1;
/* Category 019 */
static gint hf_019_000 = -1;
static gint hf_019_000_MT = -1;
static gint hf_019_010 = -1;
static gint hf_019_140 = -1;
static gint hf_019_550 = -1;
static gint hf_019_550_NOGO = -1;
static gint hf_019_550_OVL = -1;
static gint hf_019_550_TSV = -1;
static gint hf_019_550_TTF = -1;
static gint hf_019_551 = -1;
static gint hf_019_551_TP1_EXEC = -1;
static gint hf_019_551_TP1_GOOD = -1;
static gint hf_019_551_TP2_EXEC = -1;
static gint hf_019_551_TP2_GOOD = -1;
static gint hf_019_551_TP3_EXEC = -1;
static gint hf_019_551_TP3_GOOD = -1;
static gint hf_019_551_TP4_EXEC = -1;
static gint hf_019_551_TP4_GOOD = -1;
static gint hf_019_552 = -1;
static gint hf_019_552_RS_Identification = -1;
static gint hf_019_552_Receiver_1090_MHz = -1;
static gint hf_019_552_Transmitter_1030_MHz = -1;
static gint hf_019_552_Transmitter_1090_MHz = -1;
static gint hf_019_552_RS_Status = -1;
static gint hf_019_552_RS_Operational = -1;
static gint hf_019_553 = -1;
static gint hf_019_553_Ref_Trans_1_Status = -1;
static gint hf_019_553_Ref_Trans_2_Status = -1;
static gint hf_019_553_Ref_Trans_3_Status = -1;
static gint hf_019_553_Ref_Trans_4_Status = -1;
static gint hf_019_553_Ref_Trans_5_Status = -1;
static gint hf_019_553_Ref_Trans_6_Status = -1;
static gint hf_019_553_Ref_Trans_7_Status = -1;
static gint hf_019_553_Ref_Trans_8_Status = -1;
static gint hf_019_553_Ref_Trans_9_Status = -1;
static gint hf_019_553_Ref_Trans_10_Status = -1;
static gint hf_019_553_Ref_Trans_11_Status = -1;
static gint hf_019_553_Ref_Trans_12_Status = -1;
static gint hf_019_553_Ref_Trans_13_Status = -1;
static gint hf_019_553_Ref_Trans_14_Status = -1;
static gint hf_019_553_Ref_Trans_15_Status = -1;
static gint hf_019_553_Ref_Trans_16_Status = -1;
static gint hf_019_553_Ref_Trans_17_Status = -1;
static gint hf_019_553_Ref_Trans_18_Status = -1;
static gint hf_019_553_Ref_Trans_19_Status = -1;
static gint hf_019_553_Ref_Trans_20_Status = -1;
static gint hf_019_600 = -1;
static gint hf_019_600_Latitude = -1;
static gint hf_019_600_Longitude = -1;
static gint hf_019_610 = -1;
static gint hf_019_610_Height = -1;
static gint hf_019_620 = -1;
static gint hf_019_620_Undulation = -1;
static gint hf_019_RE = -1;
static gint hf_019_SP = -1;
/* Category 020 */
static gint hf_020_010 = -1;
static gint hf_020_020 = -1;
static gint hf_020_020_SSR = -1;
static gint hf_020_020_MS = -1;
static gint hf_020_020_HF = -1;
static gint hf_020_020_VDL4 = -1;
static gint hf_020_020_UAT = -1;
static gint hf_020_020_DME = -1;
static gint hf_020_020_OT = -1;
static gint hf_020_020_RAB = -1;
static gint hf_020_020_SPI = -1;
static gint hf_020_020_CHN = -1;
static gint hf_020_020_GBS = -1;
static gint hf_020_020_CRT = -1;
static gint hf_020_020_SIM = -1;
static gint hf_020_020_TST = -1;
static gint hf_020_030 = -1;
static gint hf_020_030_WE = -1;
static gint hf_020_041 = -1;
static gint hf_020_041_LAT = -1;
static gint hf_020_041_LON = -1;
static gint hf_020_042 = -1;
static gint hf_020_042_X = -1;
static gint hf_020_042_Y = -1;
static gint hf_020_050 = -1;
static gint hf_020_050_V = -1;
static gint hf_020_050_G = -1;
static gint hf_020_050_L = -1;
static gint hf_020_050_SQUAWK = -1;
static gint hf_020_055 = -1;
static gint hf_020_055_V = -1;
static gint hf_020_055_G = -1;
static gint hf_020_055_L = -1;
static gint hf_020_055_A = -1;
static gint hf_020_055_B = -1;
static gint hf_020_070 = -1;
static gint hf_020_070_V = -1;
static gint hf_020_070_G = -1;
static gint hf_020_070_L = -1;
static gint hf_020_070_SQUAWK = -1;
static gint hf_020_090 = -1;
static gint hf_020_090_V = -1;
static gint hf_020_090_G = -1;
static gint hf_020_090_FL = -1;
static gint hf_020_100 = -1;
static gint hf_020_100_V = -1;
static gint hf_020_100_G = -1;
static gint hf_020_100_C1 = -1;
static gint hf_020_100_A1 = -1;
static gint hf_020_100_C2 = -1;
static gint hf_020_100_A2 = -1;
static gint hf_020_100_C4 = -1;
static gint hf_020_100_A4 = -1;
static gint hf_020_100_B1 = -1;
static gint hf_020_100_D1 = -1;
static gint hf_020_100_B2 = -1;
static gint hf_020_100_D2 = -1;
static gint hf_020_100_B4 = -1;
static gint hf_020_100_D4 = -1;
static gint hf_020_100_QC1 = -1;
static gint hf_020_100_QA1 = -1;
static gint hf_020_100_QC2 = -1;
static gint hf_020_100_QA2 = -1;
static gint hf_020_100_QC4 = -1;
static gint hf_020_100_QA4 = -1;
static gint hf_020_100_QB1 = -1;
static gint hf_020_100_QD1 = -1;
static gint hf_020_100_QB2 = -1;
static gint hf_020_100_QD2 = -1;
static gint hf_020_100_QB4 = -1;
static gint hf_020_100_QD4 = -1;
static gint hf_020_105 = -1;
static gint hf_020_105_GH = -1;
static gint hf_020_110 = -1;
static gint hf_020_110_MH = -1;
static gint hf_020_140 = -1;
static gint hf_020_161 = -1;
static gint hf_020_161_TN = -1;
static gint hf_020_170 = -1;
static gint hf_020_170_CNF = -1;
static gint hf_020_170_TRE = -1;
static gint hf_020_170_CST = -1;
static gint hf_020_170_CDM = -1;
static gint hf_020_170_MAH = -1;
static gint hf_020_170_STH = -1;
static gint hf_020_170_GHO = -1;
static gint hf_020_202 = -1;
static gint hf_020_202_VX = -1;
static gint hf_020_202_VY = -1;
static gint hf_020_210 = -1;
static gint hf_020_210_AX = -1;
static gint hf_020_210_AY = -1;
static gint hf_020_220 = -1;
static gint hf_020_230 = -1;
static gint hf_020_230_COM = -1;
static gint hf_020_230_STAT = -1;
static gint hf_020_230_MSSC = -1;
static gint hf_020_230_ARC = -1;
static gint hf_020_230_AIC = -1;
static gint hf_020_230_B1A = -1;
static gint hf_020_230_B1B = -1;
static gint hf_020_245 = -1;
static gint hf_020_245_STI = -1;
static gint hf_020_250 = -1;
static gint hf_020_260 = -1;
static gint hf_020_300 = -1;
static gint hf_020_300_VFI = -1;
static gint hf_020_310 = -1;
static gint hf_020_310_TRB = -1;
static gint hf_020_310_MSG = -1;
static gint hf_020_400 = -1;
static gint hf_020_400_TU8RU8 = -1;
static gint hf_020_400_TU7RU7 = -1;
static gint hf_020_400_TU6RU6 = -1;
static gint hf_020_400_TU5RU5 = -1;
static gint hf_020_400_TU4RU4 = -1;
static gint hf_020_400_TU3RU3 = -1;
static gint hf_020_400_TU2RU2 = -1;
static gint hf_020_400_TU1RU1 = -1;
static gint hf_020_500 = -1;
static gint hf_020_500_01 = -1;
static gint hf_020_500_01_DOPx = -1;
static gint hf_020_500_01_DOPy = -1;
static gint hf_020_500_01_DOPxy = -1;
static gint hf_020_500_02 = -1;
static gint hf_020_500_02_SDPx = -1;
static gint hf_020_500_02_SDPy = -1;
static gint hf_020_500_02_SDPxy = -1;
static gint hf_020_500_03 = -1;
static gint hf_020_500_03_SDH = -1;
static gint hf_020_RE = -1;
static gint hf_020_RE_PA = -1;
static gint hf_020_RE_PA_01 = -1;
static gint hf_020_RE_PA_01_DOPx = -1;
static gint hf_020_RE_PA_01_DOPy = -1;
static gint hf_020_RE_PA_01_DOPxy = -1;
static gint hf_020_RE_PA_02 = -1;
static gint hf_020_RE_PA_02_SDCx = -1;
static gint hf_020_RE_PA_02_SDCy = -1;
static gint hf_020_RE_PA_02_SDCxy = -1;
static gint hf_020_RE_PA_03 = -1;
static gint hf_020_RE_PA_03_SDH = -1;
static gint hf_020_RE_PA_04 = -1;
static gint hf_020_RE_PA_04_LAT = -1;
static gint hf_020_RE_PA_04_LON = -1;
static gint hf_020_RE_PA_04_COV = -1;
static gint hf_020_RE_GVV = -1;
static gint hf_020_RE_GVV_RE = -1;
static gint hf_020_RE_GVV_GS = -1;
static gint hf_020_RE_GVV_TA = -1;
static gint hf_020_RE_GVA = -1;
static gint hf_020_RE_GVA_GSSD = -1;
static gint hf_020_RE_GVA_TASD = -1;
static gint hf_020_RE_TRT = -1;
static gint hf_020_RE_DA = -1;
static gint hf_020_RE_DA_01 = -1;
static gint hf_020_RE_DA_01_SPI = -1;
static gint hf_020_RE_DA_02 = -1;
static gint hf_020_RE_DA_02_TI = -1;
static gint hf_020_RE_DA_03 = -1;
static gint hf_020_RE_DA_03_BDS1 = -1;
static gint hf_020_RE_DA_03_BDS2 = -1;
static gint hf_020_RE_DA_03_MBA = -1;
static gint hf_020_RE_DA_04 = -1;
static gint hf_020_RE_DA_04_M3A = -1;
static gint hf_020_RE_DA_05 = -1;
static gint hf_020_RE_DA_05_FL = -1;
static gint hf_020_RE_DA_06 = -1;
static gint hf_020_RE_DA_06_STAT = -1;
static gint hf_020_RE_DA_07 = -1;
static gint hf_020_RE_DA_07_GH = -1;
static gint hf_020_RE_DA_08 = -1;
static gint hf_020_RE_DA_08_TA = -1;
static gint hf_020_RE_DA_09 = -1;
static gint hf_020_RE_DA_09_MC = -1;
static gint hf_020_RE_DA_10 = -1;
static gint hf_020_RE_DA_10_MSSC = -1;
static gint hf_020_RE_DA_11 = -1;
static gint hf_020_RE_DA_11_ARC = -1;
static gint hf_020_RE_DA_12 = -1;
static gint hf_020_RE_DA_12_AIC = -1;
static gint hf_020_RE_DA_13 = -1;
static gint hf_020_RE_DA_13_M2 = -1;
static gint hf_020_RE_DA_14 = -1;
static gint hf_020_RE_DA_14_M1 = -1;
static gint hf_020_RE_DA_15 = -1;
static gint hf_020_RE_DA_15_ARA = -1;
static gint hf_020_RE_DA_16 = -1;
static gint hf_020_RE_DA_16_VI = -1;
static gint hf_020_RE_DA_17 = -1;
static gint hf_020_RE_DA_17_MSG = -1;
static gint hf_020_SP = -1;
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
static gint hf_021_020_v0_2_ECAT = -1;
static gint hf_021_030 = -1;
static gint hf_021_032 = -1;
static gint hf_021_032_TODA = -1;
static gint hf_021_040 = -1;
static gint hf_021_040_ATP = -1;
static gint hf_021_040_v0_2_ATP = -1;
static gint hf_021_040_ARC = -1;
static gint hf_021_040_v0_2_ARC = -1;
static gint hf_021_040_RC = -1;
static gint hf_021_040_RAB = -1;
static gint hf_021_040_v0_2_RAB = -1;
static gint hf_021_040_DCR = -1;
static gint hf_021_040_GBS = -1;
static gint hf_021_040_SIM = -1;
static gint hf_021_040_TST = -1;
static gint hf_021_040_SAA = -1;
static gint hf_021_040_v0_2_SAA = -1;
static gint hf_021_040_SPI = -1;
static gint hf_021_040_CL = -1;
static gint hf_021_040_LLC = -1;
static gint hf_021_040_IPC = -1;
static gint hf_021_040_NOGO = -1;
static gint hf_021_040_CPR = -1;
static gint hf_021_040_LDPJ = -1;
static gint hf_021_040_RCF = -1;
static gint hf_021_070 = -1;
static gint hf_021_070_SQUAWK = -1;
static gint hf_021_070_V = -1;
static gint hf_021_070_G = -1;
static gint hf_021_070_L = -1;
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
static gint hf_021_090_v0_2 = -1;
static gint hf_021_090_NUCR_NACV = -1;
static gint hf_021_090_NUCP_NIC = -1;
static gint hf_021_090_NIC_BARO = -1;
static gint hf_021_090_SIL = -1;
static gint hf_021_090_NACP = -1;
static gint hf_021_090_SILS = -1;
static gint hf_021_090_SDA = -1;
static gint hf_021_090_GVA = -1;
static gint hf_021_090_PIC = -1;
static gint hf_021_090_AC = -1;
static gint hf_021_090_MN = -1;
static gint hf_021_090_DC = -1;
static gint hf_021_090_PA = -1;
static gint hf_021_095 = -1;
static gint hf_021_095_VUC = -1;
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
static gint hf_021_131_v0_2 = -1;
static gint hf_021_131_LAT = -1;
static gint hf_021_131_LON = -1;
static gint hf_021_131_SAM = -1;
static gint hf_021_132 = -1;
static gint hf_021_132_MAM = -1;
static gint hf_021_140 = -1;
static gint hf_021_140_v0_2 = -1;
static gint hf_021_140_GH = -1;
static gint hf_021_140_ALT = -1;
static gint hf_021_145 = -1;
static gint hf_021_145_FL = -1;
static gint hf_021_146 = -1;
static gint hf_021_146_v0_2 = -1;
static gint hf_021_146_SAS = -1;
static gint hf_021_146_Source = -1;
static gint hf_021_146_v0_2_Source = -1;
static gint hf_021_146_ALT = -1;
static gint hf_021_148 = -1;
static gint hf_021_148_MV = -1;
static gint hf_021_148_v0_2_MV = -1;
static gint hf_021_148_AH = -1;
static gint hf_021_148_v0_2_AH = -1;
static gint hf_021_148_AM = -1;
static gint hf_021_148_v0_2_AM = -1;
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
static gint hf_021_160_v0_2 = -1;
static gint hf_021_160_RE = -1;
static gint hf_021_160_GSPD = -1;
static gint hf_021_160_TA = -1;
static gint hf_021_161 = -1;
static gint hf_021_161_TN = -1;
static gint hf_021_165 = -1;
static gint hf_021_165_v0_2 = -1;
static gint hf_021_165_TAR = -1;
static gint hf_021_165_TI = -1;
static gint hf_021_165_ROT = -1;
static gint hf_021_170 = -1;
static gint hf_021_200 = -1;
static gint hf_021_200_ICF = -1;
static gint hf_021_200_LNAV = -1;
static gint hf_021_200_ME = -1;
static gint hf_021_200_PS = -1;
static gint hf_021_200_SS = -1;
static gint hf_021_200_TS = -1;
static gint hf_021_210 = -1;
static gint hf_021_210_v0_2 = -1;
static gint hf_021_210_VNS = -1;
static gint hf_021_210_VN = -1;
static gint hf_021_210_LTT = -1;
static gint hf_021_210_DTI = -1;
static gint hf_021_210_MDS = -1;
static gint hf_021_210_UAT = -1;
static gint hf_021_210_VDL = -1;
static gint hf_021_210_OTR = -1;
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
static gint hf_021_271_LW_v2_1 = -1;
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
static gint hf_021_RE_BPS = -1;
static gint hf_021_RE_BPS_BPS = -1;
static gint hf_021_RE_SelH = -1;
static gint hf_021_RE_SelH_HRD = -1;
static gint hf_021_RE_SelH_Stat = -1;
static gint hf_021_RE_SelH_SelH = -1;
static gint hf_021_RE_NAV = -1;
static gint hf_021_RE_NAV_AP = -1;
static gint hf_021_RE_NAV_VN = -1;
static gint hf_021_RE_NAV_AH = -1;
static gint hf_021_RE_NAV_AM = -1;
static gint hf_021_RE_GAO = -1;
static gint hf_021_RE_GAO_GAO = -1;
static gint hf_021_RE_SGV = -1;
static gint hf_021_RE_SGV_STP = -1;
static gint hf_021_RE_SGV_HTS = -1;
static gint hf_021_RE_SGV_HTT = -1;
static gint hf_021_RE_SGV_HRD = -1;
static gint hf_021_RE_SGV_GSS = -1;
static gint hf_021_RE_SGV_HGT = -1;
static gint hf_021_RE_STA = -1;
static gint hf_021_RE_STA_ES = -1;
static gint hf_021_RE_STA_UAT = -1;
static gint hf_021_RE_TNH = -1;
static gint hf_021_RE_TNH_TNH = -1;
static gint hf_021_RE_MES = -1;
static gint hf_021_RE_MES_01 = -1;
static gint hf_021_RE_MES_01_M5 = -1;
static gint hf_021_RE_MES_01_ID = -1;
static gint hf_021_RE_MES_01_DA = -1;
static gint hf_021_RE_MES_01_M1 = -1;
static gint hf_021_RE_MES_01_M2 = -1;
static gint hf_021_RE_MES_01_M3 = -1;
static gint hf_021_RE_MES_01_MC = -1;
static gint hf_021_RE_MES_01_PO = -1;
static gint hf_021_RE_MES_02 = -1;
static gint hf_021_RE_MES_02_PIN = -1;
static gint hf_021_RE_MES_02_NO = -1;
static gint hf_021_RE_MES_03 = -1;
static gint hf_021_RE_MES_03_V = -1;
static gint hf_021_RE_MES_03_L = -1;
static gint hf_021_RE_MES_03_SQUAWK = -1;
static gint hf_021_RE_MES_04 = -1;
static gint hf_021_RE_MES_04_XP = -1;
static gint hf_021_RE_MES_04_X5 = -1;
static gint hf_021_RE_MES_04_XC = -1;
static gint hf_021_RE_MES_04_X3 = -1;
static gint hf_021_RE_MES_04_X2 = -1;
static gint hf_021_RE_MES_04_X1 = -1;
static gint hf_021_RE_MES_05 = -1;
static gint hf_021_RE_MES_05_FOM = -1;
static gint hf_021_RE_MES_06 = -1;
static gint hf_021_RE_MES_06_V = -1;
static gint hf_021_RE_MES_06_L = -1;
static gint hf_021_RE_MES_06_SQUAWK = -1;
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
/* Category 025 */
static gint hf_025_000 = -1;
static gint hf_025_000_RT = -1;
static gint hf_025_000_RG = -1;
static gint hf_025_010 = -1;
static gint hf_025_015 = -1;
static gint hf_025_015_SID = -1;
static gint hf_025_020 = -1;
static gint hf_025_020_SD = -1;
static gint hf_025_070 = -1;
static gint hf_025_100 = -1;
static gint hf_025_100_NOGO = -1;
static gint hf_025_100_OPS = -1;
static gint hf_025_100_SSTAT = -1;
static gint hf_025_105 = -1;
static gint hf_025_105_ERR = -1;
static gint hf_025_120 = -1;
static gint hf_025_120_CID = -1;
static gint hf_025_120_EC = -1;
static gint hf_025_120_CS = -1;
static gint hf_025_140 = -1;
static gint hf_025_140_TYPE = -1;
static gint hf_025_140_REF = -1;
static gint hf_025_140_COUNTER = -1;
static gint hf_025_200 = -1;
static gint hf_025_200_MID = -1;
static gint hf_025_SP = -1;
/* Category 032 */
static gint hf_032_010 = -1;
static gint hf_032_015 = -1;
static gint hf_032_015_UN = -1;
static gint hf_032_018 = -1;
static gint hf_032_020 = -1;
static gint hf_032_035 = -1;
static gint hf_032_035_FAM = -1;
static gint hf_032_035_NAT = -1;
static gint hf_032_040 = -1;
static gint hf_032_040_TRK = -1;
static gint hf_032_050 = -1;
static gint hf_032_050_SUI = -1;
static gint hf_032_050_STN = -1;
static gint hf_032_060 = -1;
static gint hf_032_060_M3 = -1;
static gint hf_032_400 = -1;
static gint hf_032_400_CALL = -1;
static gint hf_032_410 = -1;
static gint hf_032_410_PLN = -1;
static gint hf_032_420 = -1;
static gint hf_032_420_GAT = -1;
static gint hf_032_420_FR = -1;
static gint hf_032_420_SP = -1;
static gint hf_032_430 = -1;
static gint hf_032_430_TYP = -1;
static gint hf_032_435 = -1;
static gint hf_032_435_TUR = -1;
static gint hf_032_440 = -1;
static gint hf_032_440_DEP = -1;
static gint hf_032_450 = -1;
static gint hf_032_450_DEST = -1;
static gint hf_032_460 = -1;
static gint hf_032_460_SSR = -1;
static gint hf_032_480 = -1;
static gint hf_032_480_CFL = -1;
static gint hf_032_490 = -1;
static gint hf_032_490_CEN = -1;
static gint hf_032_490_POS = -1;
static gint hf_032_500 = -1;
static gint hf_032_500_01 = -1;
static gint hf_032_500_IFI_TYP = -1;
static gint hf_032_500_IFI_NBR = -1;
static gint hf_032_500_02 = -1;
static gint hf_032_500_RVSM_RVSM = -1;
static gint hf_032_500_RVSM_HPR = -1;
static gint hf_032_500_03 = -1;
static gint hf_032_500_RUNWAY_NU1 = -1;
static gint hf_032_500_RUNWAY_NU2 = -1;
static gint hf_032_500_RUNWAY_LTR = -1;
static gint hf_032_500_04 = -1;
static gint hf_032_500_TIME_TYP = -1;
static gint hf_032_500_TIME_DAY = -1;
static gint hf_032_500_TIME_HOR = -1;
static gint hf_032_500_TIME_MIN = -1;
static gint hf_032_500_TIME_AVS = -1;
static gint hf_032_500_TIME_SEC = -1;
static gint hf_032_500_05 = -1;
static gint hf_032_500_AIR_STD = -1;
static gint hf_032_500_06 = -1;
static gint hf_032_500_STS_EMP = -1;
static gint hf_032_500_STS_AVL = -1;
static gint hf_032_500_07 = -1;
static gint hf_032_500_SID = -1;
static gint hf_032_500_08 = -1;
static gint hf_032_500_SIA = -1;
static gint hf_032_RE = -1;
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
static gint hf_034_100_RHOS = -1;
static gint hf_034_100_RHOE = -1;
static gint hf_034_100_THETAS = -1;
static gint hf_034_100_THETAE = -1;
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
static gint hf_048_020_ERR = -1;
static gint hf_048_020_XPP = -1;
static gint hf_048_020_ME = -1;
static gint hf_048_020_MI = -1;
static gint hf_048_020_FOE = -1;
static gint hf_048_030 = -1;
static gint hf_048_030_WE = -1;
static gint hf_048_030_1_WE = -1;
static gint hf_048_030_2_WE = -1;
static gint hf_048_030_3_WE = -1;
static gint hf_048_030_4_WE = -1;
static gint hf_048_030_5_WE = -1;
static gint hf_048_030_6_WE = -1;
static gint hf_048_030_7_WE = -1;
static gint hf_048_030_8_WE = -1;
static gint hf_048_030_9_WE = -1;
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
static gint hf_048_170_CDM_v1_21 = -1;
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
static gint hf_048_RE_MD5 = -1;
static gint hf_048_RE_MD5_01 = -1;
static gint hf_048_RE_MD5_01_M5 = -1;
static gint hf_048_RE_MD5_01_ID = -1;
static gint hf_048_RE_MD5_01_DA = -1;
static gint hf_048_RE_MD5_01_M1 = -1;
static gint hf_048_RE_MD5_01_M2 = -1;
static gint hf_048_RE_MD5_01_M3 = -1;
static gint hf_048_RE_MD5_01_MC = -1;
static gint hf_048_RE_MD5_02 = -1;
static gint hf_048_RE_MD5_02_PIN = -1;
static gint hf_048_RE_MD5_02_NAV = -1;
static gint hf_048_RE_MD5_02_NAT = -1;
static gint hf_048_RE_MD5_02_MIS = -1;
static gint hf_048_RE_MD5_03 = -1;
static gint hf_048_RE_MD5_03_LAT = -1;
static gint hf_048_RE_MD5_03_LON = -1;
static gint hf_048_RE_MD5_04 = -1;
static gint hf_048_RE_MD5_04_RES = -1;
static gint hf_048_RE_MD5_04_GA = -1;
static gint hf_048_RE_MD5_05 = -1;
static gint hf_048_RE_MD5_05_V = -1;
static gint hf_048_RE_MD5_05_G = -1;
static gint hf_048_RE_MD5_05_L = -1;
static gint hf_048_RE_MD5_05_SQUAWK = -1;
static gint hf_048_RE_MD5_06 = -1;
static gint hf_048_RE_MD5_06_TOS = -1;
static gint hf_048_RE_MD5_07 = -1;
static gint hf_048_RE_MD5_07_XP = -1;
static gint hf_048_RE_MD5_07_X5 = -1;
static gint hf_048_RE_MD5_07_XC = -1;
static gint hf_048_RE_MD5_07_X3 = -1;
static gint hf_048_RE_MD5_07_X2 = -1;
static gint hf_048_RE_MD5_07_X1 = -1;
static gint hf_048_RE_M5N = -1;
static gint hf_048_RE_M5N_01 = -1;
static gint hf_048_RE_M5N_01_M5 = -1;
static gint hf_048_RE_M5N_01_ID = -1;
static gint hf_048_RE_M5N_01_DA = -1;
static gint hf_048_RE_M5N_01_M1 = -1;
static gint hf_048_RE_M5N_01_M2 = -1;
static gint hf_048_RE_M5N_01_M3 = -1;
static gint hf_048_RE_M5N_01_MC = -1;
static gint hf_048_RE_M5N_02 = -1;
static gint hf_048_RE_M5N_02_PIN = -1;
static gint hf_048_RE_M5N_02_NOV = -1;
static gint hf_048_RE_M5N_02_NO = -1;
static gint hf_048_RE_M5N_03 = -1;
static gint hf_048_RE_M5N_03_LAT = -1;
static gint hf_048_RE_M5N_03_LON = -1;
static gint hf_048_RE_M5N_04 = -1;
static gint hf_048_RE_M5N_04_RES = -1;
static gint hf_048_RE_M5N_04_GA = -1;
static gint hf_048_RE_M5N_05 = -1;
static gint hf_048_RE_M5N_05_V = -1;
static gint hf_048_RE_M5N_05_G = -1;
static gint hf_048_RE_M5N_05_L = -1;
static gint hf_048_RE_M5N_05_SQUAWK = -1;
static gint hf_048_RE_M5N_06 = -1;
static gint hf_048_RE_M5N_06_TOS = -1;
static gint hf_048_RE_M5N_07 = -1;
static gint hf_048_RE_M5N_07_XP = -1;
static gint hf_048_RE_M5N_07_X5 = -1;
static gint hf_048_RE_M5N_07_XC = -1;
static gint hf_048_RE_M5N_07_X3 = -1;
static gint hf_048_RE_M5N_07_X2 = -1;
static gint hf_048_RE_M5N_07_X1 = -1;
static gint hf_048_RE_M5N_08 = -1;
static gint hf_048_RE_M5N_08_FOM = -1;
static gint hf_048_RE_M4E = -1;
static gint hf_048_RE_M4E_FOE_FRI = -1;
static gint hf_048_RE_RPC = -1;
static gint hf_048_RE_RPC_01 = -1;
static gint hf_048_RE_RPC_01_SCO = -1;
static gint hf_048_RE_RPC_02 = -1;
static gint hf_048_RE_RPC_02_SCR = -1;
static gint hf_048_RE_RPC_03 = -1;
static gint hf_048_RE_RPC_03_RW = -1;
static gint hf_048_RE_RPC_04 = -1;
static gint hf_048_RE_RPC_04_AR = -1;
static gint hf_048_RE_ERR = -1;
static gint hf_048_RE_ERR_RHO = -1;
static gint hf_048_SP = -1;
/* Category 062*/
static gint hf_062_010 = -1;
static gint hf_062_015 = -1;
static gint hf_062_015_SI = -1;
static gint hf_062_040 = -1;
static gint hf_062_060 = -1;
static gint hf_062_060_V = -1;
static gint hf_062_060_G = -1;
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
static gint hf_062_080_SFC = -1;
static gint hf_062_080_IDD = -1;
static gint hf_062_080_IEC = -1;
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
static gint hf_062_136_MFL = -1;
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
static gint hf_062_210_v0_17 = -1;
static gint hf_062_210_CLA = -1;
static gint hf_062_220 = -1;
static gint hf_062_220_ROCD = -1;
static gint hf_062_240 = -1;
static gint hf_062_240_ROT = -1;
static gint hf_062_245 = -1;
static gint hf_062_245_STI = -1;
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
static gint hf_062_295_07_MHG = -1;
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
static gint hf_062_390_09_RWY = -1;
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
static gint hf_062_510_SUD = -1;
static gint hf_062_510_STN = -1;
static gint hf_062_510_SLV_01_SUD = -1;
static gint hf_062_510_SLV_01_STN = -1;
static gint hf_062_510_SLV_02_SUD = -1;
static gint hf_062_510_SLV_02_STN = -1;
static gint hf_062_510_SLV_03_SUD = -1;
static gint hf_062_510_SLV_03_STN = -1;
static gint hf_062_510_SLV_04_SUD = -1;
static gint hf_062_510_SLV_04_STN = -1;
static gint hf_062_RE = -1;
static gint hf_062_RE_CST = -1;
static gint hf_062_RE_CST_TYP = -1;
static gint hf_062_RE_CST_TRK_NUM = -1;
static gint hf_062_RE_CSNT = -1;
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
static gint hf_063_015_SI = -1;
static gint hf_063_030 = -1;
static gint hf_063_050 = -1;
static gint hf_063_060 = -1;
static gint hf_063_060_CON = -1;
static gint hf_063_060_PSR = -1;
static gint hf_063_060_SSR = -1;
static gint hf_063_060_MDS = -1;
static gint hf_063_060_ADS = -1;
static gint hf_063_060_MLT = -1;
static gint hf_063_060_OPS = -1;
static gint hf_063_060_ODP = -1;
static gint hf_063_060_OXT = -1;
static gint hf_063_060_MSC = -1;
static gint hf_063_060_TSV = -1;
static gint hf_063_060_NPW = -1;
static gint hf_063_070 = -1;
static gint hf_063_070_TSB = -1;
static gint hf_063_080 = -1;
static gint hf_063_080_SRG = -1;
static gint hf_063_080_SRB = -1;
static gint hf_063_081 = -1;
static gint hf_063_081_SAB = -1;
static gint hf_063_090 = -1;
static gint hf_063_090_PRG = -1;
static gint hf_063_090_PRB = -1;
static gint hf_063_091 = -1;
static gint hf_063_091_PAB = -1;
static gint hf_063_092 = -1;
static gint hf_063_092_PEB = -1;
static gint hf_063_RE = -1;
static gint hf_063_SP = -1;
/* Category 065 */
static gint hf_065_000 = -1;
static gint hf_065_000_MT = -1;
static gint hf_065_010 = -1;
static gint hf_065_015 = -1;
static gint hf_065_015_SI = -1;
static gint hf_065_020 = -1;
static gint hf_065_020_BTN = -1;
static gint hf_065_030 = -1;
static gint hf_065_040 = -1;
static gint hf_065_040_NOGO = -1;
static gint hf_065_040_OVL = -1;
static gint hf_065_040_TSV = -1;
static gint hf_065_040_PSS = -1;
static gint hf_065_040_STTN = -1;
static gint hf_065_050 = -1;
static gint hf_065_050_REP = -1;
static gint hf_065_RE = -1;
static gint hf_065_RE_SRP = -1;
static gint hf_065_RE_SRP_Latitude = -1;
static gint hf_065_RE_SRP_Longitude = -1;
static gint hf_065_RE_ARL = -1;
static gint hf_065_RE_ARL_ARL = -1;
static gint hf_065_SP = -1;


static gint ett_asterix = -1;
static gint ett_asterix_category = -1;
static gint ett_asterix_length = -1;
static gint ett_asterix_message = -1;
static gint ett_asterix_subtree = -1;

static dissector_handle_t asterix_handle;

/* The following defines tell us how to decode the length of
 * fields and how to construct their display structure */
#define FIXED          1
#define REPETITIVE     2
#define FX             3
#define FX_1           4
#define RE             5
#define COMPOUND       6
#define SP             7
#define FX_UAP         8    /* The FX_UAP field type is a hack. Currently it *
                             * is only used in:                              *
                             *   - I001_020                                  *
                             *   - asterix_get_active_uap()                  */

/* The following defines tell us how to
 * decode and display individual fields. */
#define FIELD_PART_INT        0
#define FIELD_PART_UINT       1
#define FIELD_PART_FLOAT      2
#define FIELD_PART_UFLOAT     3
#define FIELD_PART_SQUAWK     4
#define FIELD_PART_CALLSIGN   5
#define FIELD_PART_ASCII      6
#define FIELD_PART_FX         7
#define FIELD_PART_HEX        8
#define FIELD_PART_IAS_IM     9
#define FIELD_PART_IAS_ASPD   10

typedef struct FieldPart_s FieldPart;
struct FieldPart_s {
    guint8      bit_length;     /* length of field in bits */
    double      scaling_factor; /* scaling factor of the field (for instance: 1/128) */
    guint8      type;           /* Pre-defined type for proper presentation */
    gint       *hf;             /* Pointer to hf representing this kind of data */
    const char *format_string;  /* format string for showing float values */
};

DIAG_OFF_PEDANTIC
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
DIAG_ON_PEDANTIC

static void dissect_asterix_packet (tvbuff_t *, packet_info *pinfo, proto_tree *);
static void dissect_asterix_data_block (tvbuff_t *tvb, packet_info *pinfo, guint, proto_tree *, guint8, gint);
static gint dissect_asterix_fields (tvbuff_t *, packet_info *pinfo, guint, proto_tree *, guint8, const AsterixField *[]);

static void asterix_build_subtree (tvbuff_t *, packet_info *pinfo, guint, proto_tree *, const AsterixField *);
static void twos_complement (gint64 *, guint8);
static guint8 asterix_bit (guint8, guint8);
static guint asterix_fspec_len (tvbuff_t *, guint);
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
DIAG_OFF_PEDANTIC
static const AsterixField IX_SPARE = { FIXED, 0, 0, 0, &hf_spare, NULL, { NULL } };
DIAG_ON_PEDANTIC

/* *********************** */
/*      Category 001       */
/* *********************** */
/* Fields */

/* I001/020, Target Report Descriptor */
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

/* I001/030, Warning/Error Conditions */
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

/* I001/040, Measured Position in Polar Coordinates */
static const FieldPart I001_040_RHO = { 16, 1.0/128.0, FIELD_PART_UFLOAT, &hf_001_040_RHO, NULL };
static const FieldPart I001_040_THETA = { 16, 360.0/65536.0, FIELD_PART_UFLOAT, &hf_001_040_THETA, NULL };
static const FieldPart *I001_040_PARTS[] = { &I001_040_RHO, &I001_040_THETA, NULL };

/* I001/042, Calculated Position in Cartesian Coordinates */
static const FieldPart I001_042_X = { 16, 1.0/64.0, FIELD_PART_FLOAT, &hf_001_042_X, NULL };
static const FieldPart I001_042_Y = { 16, 1.0/64.0, FIELD_PART_FLOAT, &hf_001_042_Y, NULL };
static const FieldPart *I001_042_PARTS[] = { &I001_042_X, &I001_042_Y, NULL };

/* I001/050, Mode-2 Code in Octal Representation */
static const value_string valstr_001_050_V[] = {
    { 0, "Code validated" },
    { 1, "Code not validated" },
    { 0, NULL }
};
static const value_string valstr_001_050_G[] = {
    { 0, "Default" },
    { 1, "Garbled code" },
    { 0, NULL }
};
static const value_string valstr_001_050_L[] = {
    { 0, "Mode-2 code as derived from the reply of the transponder" },
    { 1, "Smoothed Mode-2 code as provided by a local tracker" },
    { 0, NULL }
};
static const FieldPart I001_050_V = { 1, 1.0, FIELD_PART_UINT, &hf_001_050_V, NULL };
static const FieldPart I001_050_G = { 1, 1.0, FIELD_PART_UINT, &hf_001_050_G, NULL };
static const FieldPart I001_050_L = { 1, 1.0, FIELD_PART_UINT, &hf_001_050_L, NULL };
static const FieldPart I001_050_SQUAWK = { 12, 1.0, FIELD_PART_SQUAWK, &hf_001_050_SQUAWK, NULL };
static const FieldPart *I001_050_PARTS[] = { &I001_050_V, &I001_050_G, &I001_050_L, &IXXX_1bit_spare, &I001_050_SQUAWK, NULL };

/* I001/060, Mode-2 Code Confidence Indicator */
static const value_string valstr_001_060_Q[] = {
    { 0, "High quality pulse" },
    { 1, "Low quality pulse" },
    { 0, NULL }
};
static const FieldPart I001_060_QA4 = { 1, 1.0, FIELD_PART_UINT, &hf_001_060_QA4, NULL };
static const FieldPart I001_060_QA2 = { 1, 1.0, FIELD_PART_UINT, &hf_001_060_QA2, NULL };
static const FieldPart I001_060_QA1 = { 1, 1.0, FIELD_PART_UINT, &hf_001_060_QA1, NULL };
static const FieldPart I001_060_QB4 = { 1, 1.0, FIELD_PART_UINT, &hf_001_060_QB4, NULL };
static const FieldPart I001_060_QB2 = { 1, 1.0, FIELD_PART_UINT, &hf_001_060_QB2, NULL };
static const FieldPart I001_060_QB1 = { 1, 1.0, FIELD_PART_UINT, &hf_001_060_QB1, NULL };
static const FieldPart I001_060_QC4 = { 1, 1.0, FIELD_PART_UINT, &hf_001_060_QC4, NULL };
static const FieldPart I001_060_QC2 = { 1, 1.0, FIELD_PART_UINT, &hf_001_060_QC2, NULL };
static const FieldPart I001_060_QC1 = { 1, 1.0, FIELD_PART_UINT, &hf_001_060_QC1, NULL };
static const FieldPart I001_060_QD4 = { 1, 1.0, FIELD_PART_UINT, &hf_001_060_QD4, NULL };
static const FieldPart I001_060_QD2 = { 1, 1.0, FIELD_PART_UINT, &hf_001_060_QD2, NULL };
static const FieldPart I001_060_QD1 = { 1, 1.0, FIELD_PART_UINT, &hf_001_060_QD1, NULL };
static const FieldPart *I001_060_PARTS[] = { &IXXX_4bit_spare,
                                              &I001_060_QA4, &I001_060_QA2, &I001_060_QA1,
                                              &I001_060_QB4, &I001_060_QB2, &I001_060_QB1,
                                              &I001_060_QC4, &I001_060_QC2, &I001_060_QC1,
                                              &I001_060_QD4, &I001_060_QD2, &I001_060_QD1, NULL };

/* I001/070, Mode-3/A Code in Octal Representation */
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

/* I001/080, Mode-3/A Code Confidence Indicator */
static const value_string valstr_001_080_Q[] = {
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

/* I001/090, Mode-C Code in Binary Representation */
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
static const FieldPart *I001_090_PARTS[] = { &I001_090_V, &I001_090_G, &I001_090_FL, NULL };

/* I001/100, Mode-C Code and Code Confidence Indicator */
static const value_string valstr_001_100_V[] = {
    { 0, "Code validated" },
    { 1, "Code not validated" },
    { 0, NULL }
};
static const value_string valstr_001_100_G[] = {
    { 0, "Default" },
    { 1, "Garbled code" },
    { 0, NULL }
};
static const value_string valstr_001_100_Q[] = {
    { 0, "High quality pulse" },
    { 1, "Low quality pulse" },
    { 0, NULL }
};
static const FieldPart I001_100_V = { 1, 1.0, FIELD_PART_UINT, &hf_001_100_V, NULL };
static const FieldPart I001_100_G = { 1, 1.0, FIELD_PART_UINT, &hf_001_100_G, NULL };
static const FieldPart I001_100_C1 = { 1, 1.0, FIELD_PART_UINT, &hf_001_100_C1, NULL };
static const FieldPart I001_100_A1 = { 1, 1.0, FIELD_PART_UINT, &hf_001_100_A1, NULL };
static const FieldPart I001_100_C2 = { 1, 1.0, FIELD_PART_UINT, &hf_001_100_C2, NULL };
static const FieldPart I001_100_A2 = { 1, 1.0, FIELD_PART_UINT, &hf_001_100_A2, NULL };
static const FieldPart I001_100_C4 = { 1, 1.0, FIELD_PART_UINT, &hf_001_100_C4, NULL };
static const FieldPart I001_100_A4 = { 1, 1.0, FIELD_PART_UINT, &hf_001_100_A4, NULL };
static const FieldPart I001_100_B1 = { 1, 1.0, FIELD_PART_UINT, &hf_001_100_B1, NULL };
static const FieldPart I001_100_D1 = { 1, 1.0, FIELD_PART_UINT, &hf_001_100_D1, NULL };
static const FieldPart I001_100_B2 = { 1, 1.0, FIELD_PART_UINT, &hf_001_100_B2, NULL };
static const FieldPart I001_100_D2 = { 1, 1.0, FIELD_PART_UINT, &hf_001_100_D2, NULL };
static const FieldPart I001_100_B4 = { 1, 1.0, FIELD_PART_UINT, &hf_001_100_B4, NULL };
static const FieldPart I001_100_D4 = { 1, 1.0, FIELD_PART_UINT, &hf_001_100_D4, NULL };
static const FieldPart I001_100_QC1 = { 1, 1.0, FIELD_PART_UINT, &hf_001_100_QC1, NULL };
static const FieldPart I001_100_QA1 = { 1, 1.0, FIELD_PART_UINT, &hf_001_100_QA1, NULL };
static const FieldPart I001_100_QC2 = { 1, 1.0, FIELD_PART_UINT, &hf_001_100_QC2, NULL };
static const FieldPart I001_100_QA2 = { 1, 1.0, FIELD_PART_UINT, &hf_001_100_QA2, NULL };
static const FieldPart I001_100_QC4 = { 1, 1.0, FIELD_PART_UINT, &hf_001_100_QC4, NULL };
static const FieldPart I001_100_QA4 = { 1, 1.0, FIELD_PART_UINT, &hf_001_100_QA4, NULL };
static const FieldPart I001_100_QB1 = { 1, 1.0, FIELD_PART_UINT, &hf_001_100_QB1, NULL };
static const FieldPart I001_100_QD1 = { 1, 1.0, FIELD_PART_UINT, &hf_001_100_QD1, NULL };
static const FieldPart I001_100_QB2 = { 1, 1.0, FIELD_PART_UINT, &hf_001_100_QB2, NULL };
static const FieldPart I001_100_QD2 = { 1, 1.0, FIELD_PART_UINT, &hf_001_100_QD2, NULL };
static const FieldPart I001_100_QB4 = { 1, 1.0, FIELD_PART_UINT, &hf_001_100_QB4, NULL };
static const FieldPart I001_100_QD4 = { 1, 1.0, FIELD_PART_UINT, &hf_001_100_QD4, NULL };
static const FieldPart *I001_100_PARTS[] = { &I001_100_V, &I001_100_G, &IXXX_2bit_spare,
                                             &I001_100_C1, &I001_100_A1, &I001_100_C2, &I001_100_A2, &I001_100_C4, &I001_100_A4,
                                             &I001_100_B1, &I001_100_D1, &I001_100_B2, &I001_100_D2, &I001_100_B4, &I001_100_D4,
                                             &IXXX_4bit_spare,
                                             &I001_100_QC1, &I001_100_QA1, &I001_100_QC2, &I001_100_QA2, &I001_100_QC4, &I001_100_QA4,
                                             &I001_100_QB1, &I001_100_QD1, &I001_100_QB2, &I001_100_QD2, &I001_100_QB4, &I001_100_QD4, NULL };

/* I001/120, Measured Radial Doppler Speed */
static const FieldPart I001_120_MRDS = { 8, 1.0/256.0, FIELD_PART_FLOAT, &hf_001_120_MRDS, NULL };
static const FieldPart *I001_120_PARTS[] = { &I001_120_MRDS, NULL };

/* I001/130, Radar Plot Characteristics */
static const FieldPart I001_130_RPC = { 7, 1.0, FIELD_PART_HEX, &hf_001_130_RPC, NULL };
static const FieldPart *I001_130_PARTS[] = { &I001_130_RPC, &IXXX_FX, NULL };

/* I001/131, Received Power */
static const FieldPart I001_131_RP = { 8, 1.0, FIELD_PART_INT, &hf_001_131_RP, NULL };
static const FieldPart *I001_131_PARTS[] = { &I001_131_RP, NULL };

/* I001/141, Truncated Time of Day */
static const FieldPart I001_141_TTOD = { 16, 1.0/128.0, FIELD_PART_UFLOAT, &hf_001_141_TTOD, NULL };
static const FieldPart *I001_141_PARTS[] = { &I001_141_TTOD, NULL };

/* I001/150, Presence of X-Pulse */
static const value_string valstr_001_150_XA[] = {
    { 0, "Default" },
    { 1, "X-pulse received in Mode-3/A reply" },
    { 0, NULL }
};
static const value_string valstr_001_150_XC[] = {
    { 0, "Default" },
    { 1, "X-pulse received in Mode-C reply" },
    { 0, NULL }
};
static const value_string valstr_001_150_X2[] = {
    { 0, "Default" },
    { 1, "X-pulse received in Mode-2 reply" },
    { 0, NULL }
};
static const FieldPart I001_150_XA = { 1, 1.0, FIELD_PART_UINT, &hf_001_150_XA, NULL };
static const FieldPart I001_150_XC = { 1, 1.0, FIELD_PART_UINT, &hf_001_150_XC, NULL };
static const FieldPart I001_150_X2 = { 1, 1.0, FIELD_PART_UINT, &hf_001_150_X2, NULL };
static const FieldPart *I001_150_PARTS[] = { &I001_150_XA, &IXXX_1bit_spare, &I001_150_XC, &IXXX_2bit_spare, &I001_150_X2, &IXXX_2bit_spare, NULL };

/* I001/161, Track Plot Number */
static const FieldPart I001_161_TPN = { 16, 1.0, FIELD_PART_UINT, &hf_001_161_TPN, NULL };
static const FieldPart *I001_161_PARTS[] = { &I001_161_TPN, NULL };

/*I001/170, Track Status  */
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

/* I001/200, Calculated Track Velocity in Polar Coordinates */
static const FieldPart I001_200_CGS = { 16, 1.0/16384.0, FIELD_PART_FLOAT, &hf_001_200_CGS, NULL };
static const FieldPart I001_200_CH = { 16, 360.0/65536.0, FIELD_PART_FLOAT, &hf_001_200_CH, NULL };
static const FieldPart *I001_200_PARTS[] = { &I001_200_CGS, &I001_200_CH, NULL };

/* I001/210, Track Quality */
static const FieldPart I001_210_TQ = { 7, 1.0, FIELD_PART_HEX, &hf_001_210_TQ, NULL };
static const FieldPart *I001_210_PARTS[] = { &I001_210_TQ, &IXXX_FX, NULL };

/* Items */
DIAG_OFF_PEDANTIC
static const AsterixField I001_010 = { FIXED, 2, 0, 0, &hf_001_010, IXXX_SAC_SIC, { NULL } };
static const AsterixField I001_020 = { FX_UAP, 1, 0, 0, &hf_001_020, I001_020_PARTS, { NULL } };
static const AsterixField I001_030 = { FX, 1, 0, 0, &hf_001_030, I001_030_PARTS, { NULL } };
static const AsterixField I001_040 = { FIXED, 4, 0, 0, &hf_001_040, I001_040_PARTS, { NULL } };
static const AsterixField I001_042 = { FIXED, 4, 0, 0, &hf_001_042, I001_042_PARTS, { NULL } };
static const AsterixField I001_050 = { FIXED, 2, 0, 0, &hf_001_050, I001_050_PARTS, { NULL } };
static const AsterixField I001_060 = { FIXED, 2, 0, 0, &hf_001_060, I001_060_PARTS, { NULL } };
static const AsterixField I001_070 = { FIXED, 2, 0, 0, &hf_001_070, I001_070_PARTS, { NULL } };
static const AsterixField I001_080 = { FIXED, 2, 0, 0, &hf_001_080, I001_080_PARTS, { NULL } };
static const AsterixField I001_090 = { FIXED, 2, 0, 0, &hf_001_090, I001_090_PARTS, { NULL } };
static const AsterixField I001_100 = { FIXED, 4, 0, 0, &hf_001_100, I001_100_PARTS, { NULL } };
static const AsterixField I001_120 = { FIXED, 1, 0, 0, &hf_001_120, I001_120_PARTS, { NULL } };
static const AsterixField I001_130 = { FX, 1, 0, 0, &hf_001_130, I001_130_PARTS, { NULL } };
static const AsterixField I001_131 = { FIXED, 1, 0, 0, &hf_001_131, I001_131_PARTS, { NULL } };
static const AsterixField I001_141 = { FIXED, 2, 0, 0, &hf_001_141, I001_141_PARTS, { NULL } };
static const AsterixField I001_150 = { FIXED, 1, 0, 0, &hf_001_150, I001_150_PARTS, { NULL } };
static const AsterixField I001_161 = { FIXED, 2, 0, 0, &hf_001_161, I001_161_PARTS, { NULL } };
static const AsterixField I001_170 = { FX, 1, 0, 0, &hf_001_170, I001_170_PARTS, { NULL } };
static const AsterixField I001_200 = { FIXED, 4, 0, 0, &hf_001_200, I001_200_PARTS, { NULL } };
static const AsterixField I001_210 = { FX, 1, 0, 0, &hf_001_210, I001_210_PARTS, { NULL } };
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
DIAG_ON_PEDANTIC

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
DIAG_OFF_PEDANTIC
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
DIAG_ON_PEDANTIC

static const enum_val_t I002_versions[] = {
    { "I002_v1_0", "Version 1.0", 0 },
    { NULL, NULL, 0 }
};

/* *********************** */
/*      Category 004       */
/* *********************** */
/* Fields */

/* Message Type */
static const value_string valstr_004_000_MT[] = {
    { 1, "Alive Message" },
    { 2, "Route Adherence Monitor Longitudinal Deviation" },
    { 3, "Route Adherence Monitor Heading Deviation" },
    { 4, "Minimum Safe Altitude Warning" },
    { 5, "Area Proximity Warning" },
    { 6, "Clearance Level Adherence Monitor" },
    { 7, "Short Term Conflict Alert" },
    { 8, "Approach Funnel Deviation Alert" },
    { 9, "RIMCAS Arrival / Landing Monitor (ALM)" },
    { 10, "RIMCAS Arrival / Departure Wrong Runway Alert (WRA)" },
    { 11, "RIMCAS Arrival / Departure Opposite Traffic Alert (OTA)" },
    { 12, "RIMCAS Departure Monitor (RDM)" },
    { 13, "RIMCAS Runway / Taxiway Crossing Monitor (RCM)" },
    { 14, "RIMCAS Taxiway Separation Monitor (TSM)" },
    { 15, "RIMCAS Unauthorized Taxiway Movement Monitor(UTMM)" },
    { 16, "RIMCAS Stop Bar Overrun Alert (SBOA)" },
    { 17, "End Of Conflict (EOC)" },
    { 18, "ACAS Resolution Advisory (ACASRA)" },
    { 19, "Near Term Conflict Alert (NTCA)" },
    { 0, NULL }
};
static const FieldPart I004_000_MT = { 8, 1.0, FIELD_PART_UINT, &hf_004_000_MT, NULL };
static const FieldPart *I004_000_PARTS[] = { &I004_000_MT, NULL };

/* Track number 1 */
static const FieldPart I004_030_TN1 = { 16, 1.0, FIELD_PART_UINT, &hf_004_030_TN1, NULL };
static const FieldPart *I004_030_PARTS[] = { &I004_030_TN1, NULL };

/* Track number 2 */
static const FieldPart I004_035_TN2 = { 16, 1.0, FIELD_PART_UINT, &hf_004_035_TN2, NULL };
static const FieldPart *I004_035_PARTS[] = { &I004_035_TN2, NULL };

/* Alert Identifier */
static const FieldPart I004_040_AI = { 16, 1.0, FIELD_PART_UINT, &hf_004_040_AI, NULL };
static const FieldPart *I004_040_PARTS[] = { &I004_040_AI, NULL };

/* Alert Status */
static const FieldPart I004_045_AS = { 3, 1.0, FIELD_PART_UINT, &hf_004_045_AS, NULL };
static const FieldPart *I004_045_PARTS[] = { &IXXX_4bit_spare, &I004_045_AS, &IXXX_1bit_spare, NULL };

/* Safety Net Function & System Status */
/* MRVA */
static const value_string valstr_004_060_MRVA[] = {
    { 0, "Default" },
    { 1, "MRVA function" },
    { 0, NULL }
};

/* RAMLD */
static const value_string valstr_004_060_RAMLD[] = {
    { 0, "Default" },
    { 1, "RAMLD function" },
    { 0, NULL }
};

/* RAMHD */
static const value_string valstr_004_060_RAMHD[] = {
    { 0, "Default" },
    { 1, "RAMHD function" },
    { 0, NULL }
};

/* MSAW */
static const value_string valstr_004_060_MSAW[] = {
    { 0, "Default" },
    { 1, "MSAW function" },
    { 0, NULL }
};

/* APW */
static const value_string valstr_004_060_APW[] = {
    { 0, "Default" },
    { 1, "APW function" },
    { 0, NULL }
};

/* CLAM */
static const value_string valstr_004_060_CLAM[] = {
    { 0, "Default" },
    { 1, "CLAM function" },
    { 0, NULL }
};

/* STCA */
static const value_string valstr_004_060_STCA[] = {
    { 0, "Default" },
    { 1, "STCA function" },
    { 0, NULL }
};

/* AFDA */
static const value_string valstr_004_060_AFDA[] = {
    { 0, "Default" },
    { 1, "AFDA function" },
    { 0, NULL }
};

/* RIMCA */
static const value_string valstr_004_060_RIMCA[] = {
    { 0, "Default" },
    { 1, "RIMCA function" },
    { 0, NULL }
};

/* ACASRA */
static const value_string valstr_004_060_ACASRA[] = {
    { 0, "Default" },
    { 1, "ACAS RA function" },
    { 0, NULL }
};

/* NTCA */
static const value_string valstr_004_060_NTCA[] = {
    { 0, "Default" },
    { 1, "NTCA function" },
    { 0, NULL }
};

/* DG */
static const value_string valstr_004_060_DG[] = {
    { 0, "Default" },
    { 1, "System degraded" },
    { 0, NULL }
};

/* OF */
static const value_string valstr_004_060_OF[] = {
    { 0, "Default" },
    { 1, "Overflow error" },
    { 0, NULL }
};

/* OL */
static const value_string valstr_004_060_OL[] = {
    { 0, "Default" },
    { 1, "Overload error" },
    { 0, NULL }
};

static const FieldPart I004_060_MRVA = { 1, 1.0, FIELD_PART_UINT, &hf_004_060_MRVA, NULL };
static const FieldPart I004_060_RAMLD = { 1, 1.0, FIELD_PART_UINT, &hf_004_060_RAMLD, NULL };
static const FieldPart I004_060_RAMHD = { 1, 1.0, FIELD_PART_UINT, &hf_004_060_RAMHD, NULL };
static const FieldPart I004_060_MSAW = { 1, 1.0, FIELD_PART_UINT, &hf_004_060_MSAW, NULL };
static const FieldPart I004_060_APW = { 1, 1.0, FIELD_PART_UINT, &hf_004_060_APW, NULL };
static const FieldPart I004_060_CLAM = { 1, 1.0, FIELD_PART_UINT, &hf_004_060_CLAM, NULL };
static const FieldPart I004_060_STCA = { 1, 1.0, FIELD_PART_UINT, &hf_004_060_STCA, NULL };
static const FieldPart I004_060_AFDA = { 1, 1.0, FIELD_PART_UINT, &hf_004_060_AFDA, NULL };
static const FieldPart I004_060_RIMCA = { 1, 1.0, FIELD_PART_UINT, &hf_004_060_RIMCA, NULL };
static const FieldPart I004_060_ACASRA = { 1, 1.0, FIELD_PART_UINT, &hf_004_060_ACASRA, NULL };
static const FieldPart I004_060_NTCA = { 1, 1.0, FIELD_PART_UINT, &hf_004_060_NTCA, NULL };
static const FieldPart I004_060_DG = { 1, 1.0, FIELD_PART_UINT, &hf_004_060_DG, NULL };
static const FieldPart I004_060_OF = { 1, 1.0, FIELD_PART_UINT, &hf_004_060_OF, NULL };
static const FieldPart I004_060_OL = { 1, 1.0, FIELD_PART_UINT, &hf_004_060_OL, NULL };
static const FieldPart *I004_060_PARTS[] = { &I004_060_MRVA, &I004_060_RAMLD, &I004_060_RAMHD, &I004_060_MSAW, &I004_060_APW, &I004_060_CLAM, &I004_060_STCA, &IXXX_FX,
                                             &I004_060_AFDA, &I004_060_RIMCA, &I004_060_ACASRA, &I004_060_NTCA, &I004_060_DG, &I004_060_OF, &I004_060_OL, &IXXX_FX, NULL };

/* Conflict Timing and Separation */
/* Time to Conflict */
static const FieldPart I004_070_01_TC = { 24, 1.0/128.0, FIELD_PART_UFLOAT, &hf_004_070_01_TC, "%.3f" };
static const FieldPart *I004_070_01_PARTS[] = { &I004_070_01_TC, NULL };

/* Time to Closest Approach */
static const FieldPart I004_070_02_TCA = { 24, 1.0/128.0, FIELD_PART_UFLOAT, &hf_004_070_02_TCA, "%.3f" };
static const FieldPart *I004_070_02_PARTS[] = { &I004_070_02_TCA, NULL };

/* Current Horizontal Separation */
static const FieldPart I004_070_03_CHS = { 24, 0.5, FIELD_PART_UFLOAT, &hf_004_070_03_CHS, NULL };
static const FieldPart *I004_070_03_PARTS[] = { &I004_070_03_CHS, NULL };

/* Estimated Minimum Horizontal Separation */
static const FieldPart I004_070_04_MHS = { 16, 0.5, FIELD_PART_UFLOAT, &hf_004_070_04_MHS, NULL };
static const FieldPart *I004_070_04_PARTS[] = { &I004_070_04_MHS, NULL };

/* Current Vertical Separation */
static const FieldPart I004_070_05_CVS = { 16, 25.0, FIELD_PART_UFLOAT, &hf_004_070_05_CVS, NULL };
static const FieldPart *I004_070_05_PARTS[] = { &I004_070_05_CVS, NULL };

/* Estimated Minimum Vertical Separation */
static const FieldPart I004_070_06_MVS = { 16, 25.0, FIELD_PART_UFLOAT, &hf_004_070_06_MVS, NULL };
static const FieldPart *I004_070_06_PARTS[] = { &I004_070_06_MVS, NULL };

/* Longitudinal Deviation */
static const FieldPart I004_074_LD = { 16, 32.0, FIELD_PART_FLOAT, &hf_004_074_LD, NULL };
static const FieldPart *I004_074_PARTS[] = { &I004_074_LD, NULL };

/* Transversal Distance Deviation */
static const FieldPart I004_075_TDD = { 24, 0.5, FIELD_PART_FLOAT, &hf_004_075_TDD, NULL };
static const FieldPart *I004_075_PARTS[] = { &I004_075_TDD, NULL };

/* Vertical Deviation */
static const FieldPart I004_076_VD = { 16, 25.0, FIELD_PART_FLOAT, &hf_004_076_VD, NULL };
static const FieldPart *I004_076_PARTS[] = { &I004_076_VD, NULL };

/* Area Definition*/
/* Area Name */
static const FieldPart I004_100_01_AN = { 48, 1.0, FIELD_PART_CALLSIGN, &hf_004_100_01_AN, NULL };
static const FieldPart *I004_100_01_PARTS[] = { &I004_100_01_AN, NULL };

/* Crossing Area Name */
static const FieldPart I004_100_02_CAN = { 56, 1.0, FIELD_PART_ASCII, &hf_004_100_02_CAN, NULL };
static const FieldPart *I004_100_02_PARTS[] = { &I004_100_02_CAN, NULL };

/* Runway/Taxiway Designator 1 */
static const FieldPart I004_100_03_RT1 = { 56, 1.0, FIELD_PART_ASCII, &hf_004_100_03_RT1, NULL };
static const FieldPart *I004_100_03_PARTS[] = { &I004_100_03_RT1, NULL };

/* Runway/Taxiway Designator 2 */
static const FieldPart I004_100_04_RT2 = { 56, 1.0, FIELD_PART_ASCII, &hf_004_100_04_RT2, NULL };
static const FieldPart *I004_100_04_PARTS[] = { &I004_100_04_RT2, NULL };

/* Stop Bar Designator */
static const FieldPart I004_100_05_SB = { 56, 1.0, FIELD_PART_ASCII, &hf_004_100_05_SB, NULL };
static const FieldPart *I004_100_05_PARTS[] = { &I004_100_05_SB, NULL };

/* Gate Designator */
static const FieldPart I004_100_06_G = { 56, 1.0, FIELD_PART_ASCII, &hf_004_100_06_G, NULL };
static const FieldPart *I004_100_06_PARTS[] = { &I004_100_06_G, NULL };

/* FDPS Sector Control Identification */
static const FieldPart I004_110_Centre = { 8, 1.0, FIELD_PART_UINT, &hf_004_110_Centre, NULL };
static const FieldPart I004_110_Position = { 8, 1.0, FIELD_PART_UINT, &hf_004_110_Position, NULL };
static const FieldPart *I004_110_PARTS[] = { &I004_110_Centre, &I004_110_Position, NULL };

/* Conflict Characteristics */
/* Conflict Nature */
static const value_string valstr_004_120_01_MAS[] = {
    { 0, "conflict not predicted to occur in military airspace" },
    { 1, "conflict predicted to occur in military airspace" },
    { 0, NULL }
};

static const value_string valstr_004_120_01_CAS[] = {
    { 0, "conflict not predicted to occur in civil airspace" },
    { 1, "conflict predicted to occur in civil airspace" },
    { 0, NULL }
};

static const value_string valstr_004_120_01_FLD[] = {
    { 0, "Aircraft are not fast diverging laterally at current time" },
    { 1, "Aircraft are fast diverging laterally at current time" },
    { 0, NULL }
};

static const value_string valstr_004_120_01_FVD[] = {
    { 0, "Aircraft are not fast diverging vertically at current time" },
    { 1, "Aircraft are fast diverging vertically at current time" },
    { 0, NULL }
};

static const value_string valstr_004_120_01_Type[] = {
    { 0, "Minor separation infringement" },
    { 1, "Major separation infringement" },
    { 0, NULL }
};

static const value_string valstr_004_120_01_Cross[] = {
    { 0, "Aircraft have not crossed at starting time of conflict" },
    { 1, "Aircraft have crossed at starting time of conflict" },
    { 0, NULL }
};

static const value_string valstr_004_120_01_Div[] = {
    { 0, "Aircraft are not diverging at starting time of conflict" },
    { 1, "Aircraft are diverging at starting time of conflict" },
    { 0, NULL }
};

static const value_string valstr_004_120_01_RRC[] = {
    { 0, "Default" },
    { 1, "Runway/Runway Crossing" },
    { 0, NULL }
};

static const value_string valstr_004_120_01_RTC[] = {
    { 0, "Default" },
    { 1, "Runway/Taxiway Crossing" },
    { 0, NULL }
};

static const value_string valstr_004_120_01_MRVA[] = {
    { 0, "Default" },
    { 1, "Msg Type 4 (MSAW) indicates MRVA" },
    { 0, NULL }
};

static const FieldPart I004_120_01_MAS = { 1, 1.0, FIELD_PART_UINT, &hf_004_120_01_MAS, NULL };
static const FieldPart I004_120_01_CAS = { 1, 1.0, FIELD_PART_UINT, &hf_004_120_01_CAS, NULL };
static const FieldPart I004_120_01_FLD = { 1, 1.0, FIELD_PART_UINT, &hf_004_120_01_FLD, NULL };
static const FieldPart I004_120_01_FVD = { 1, 1.0, FIELD_PART_UINT, &hf_004_120_01_FVD, NULL };
static const FieldPart I004_120_01_Type = { 1, 1.0, FIELD_PART_UINT, &hf_004_120_01_Type, NULL };
static const FieldPart I004_120_01_Cross = { 1, 1.0, FIELD_PART_UINT, &hf_004_120_01_Cross, NULL };
static const FieldPart I004_120_01_Div = { 1, 1.0, FIELD_PART_UINT, &hf_004_120_01_Div, NULL };
static const FieldPart I004_120_01_RRC = { 1, 1.0, FIELD_PART_UINT, &hf_004_120_01_RRC, NULL };
static const FieldPart I004_120_01_RTC = { 1, 1.0, FIELD_PART_UINT, &hf_004_120_01_RTC, NULL };
static const FieldPart I004_120_01_MRVA = { 1, 1.0, FIELD_PART_UINT, &hf_004_120_01_MRVA, NULL };
static const FieldPart *I004_120_01_PARTS[] = { &I004_120_01_MAS, &I004_120_01_CAS, &I004_120_01_FLD, &I004_120_01_FVD, &I004_120_01_Type, &I004_120_01_Cross, &I004_120_01_Div,
                                                &I004_120_01_RRC, &I004_120_01_RTC, &I004_120_01_MRVA, &IXXX_4bit_spare, NULL };

/* Conflict Classification */
static const value_string valstr_004_120_02_CS[] = {
    { 0, "LOW" },
    { 1, "HIGH" },
    { 0, NULL }
};

static const FieldPart I004_120_02_TID = { 4, 1.0, FIELD_PART_UINT, &hf_004_120_02_TID, NULL };
static const FieldPart I004_120_02_SC = { 3, 1.0, FIELD_PART_UINT, &hf_004_120_02_SC, NULL };
static const FieldPart I004_120_02_CS = { 1, 1.0, FIELD_PART_UINT, &hf_004_120_02_CS, NULL };
static const FieldPart *I004_120_02_PARTS[] = { &I004_120_02_TID, &I004_120_02_SC, &I004_120_02_CS, NULL };

/* Conflict Probabilty */
static const FieldPart I004_120_03_Probability = { 8, 0.5, FIELD_PART_UFLOAT, &hf_004_120_03_Probability, NULL };
static const FieldPart *I004_120_03_PARTS[] = { &I004_120_03_Probability, NULL };

/* Conflict Duration */
static const FieldPart I004_120_04_Duration = { 24, 1.0/128.0, FIELD_PART_UFLOAT, &hf_004_120_04_Duration, "%.3f" };
static const FieldPart *I004_120_04_PARTS[] = { &I004_120_04_Duration, NULL };

/* Aircraft Identification & Characteristics 1 */
/* Aircraft Identifier 1 */
static const FieldPart I004_170_01_AI1 = { 56, 1.0, FIELD_PART_ASCII, &hf_004_170_01_AI1, NULL };
static const FieldPart *I004_170_01_PARTS[] = { &I004_170_01_AI1, NULL };

/* Mode 3/A Code Aircraft 1 */
static const FieldPart I004_170_02_M31 = { 12, 1.0, FIELD_PART_SQUAWK, &hf_004_170_02_M31, NULL };
static const FieldPart *I004_170_02_PARTS[] = { &IXXX_4bit_spare, &I004_170_02_M31, NULL };

/* Predicted Conflict Position Aircraft 1 (WGS-84) */
static const FieldPart I004_170_03_LAT = { 32, 180.0/33554432.0, FIELD_PART_FLOAT, &hf_004_170_03_LAT, NULL };
static const FieldPart I004_170_03_LON = { 32, 180.0/33554432.0, FIELD_PART_FLOAT, &hf_004_170_03_LON, NULL };
static const FieldPart I004_170_03_ALT = { 16, 25.0, FIELD_PART_FLOAT, &hf_004_170_03_ALT, NULL };
static const FieldPart *I004_170_03_PARTS[] = { &I004_170_03_LAT, &I004_170_03_LON, &I004_170_03_ALT, NULL };

/* Predicted Conflict Position Aircraft 1 in Cartesian Coordinates */
static const FieldPart I004_170_04_X = { 24, 0.5, FIELD_PART_FLOAT, &hf_004_170_04_X, NULL };
static const FieldPart I004_170_04_Y = { 24, 0.5, FIELD_PART_FLOAT, &hf_004_170_04_Y, NULL };
static const FieldPart I004_170_04_Z = { 16, 25.0, FIELD_PART_FLOAT, &hf_004_170_04_Z, NULL };
static const FieldPart *I004_170_04_PARTS[] = { &I004_170_04_X, &I004_170_04_Y, &I004_170_04_Z, NULL };

/* Time to Threshold Aircraft 1 */
static const FieldPart I004_170_05_TT1 = { 24, 1.0/128.0, FIELD_PART_UFLOAT, &hf_004_170_05_TT1, "%.3f" };
static const FieldPart *I004_170_05_PARTS[] = { &I004_170_05_TT1, NULL };

/* Distance to Threshold Aircraft 1 */
static const FieldPart I004_170_06_DT1 = { 16, 0.5, FIELD_PART_UFLOAT, &hf_004_170_06_DT1, NULL };
static const FieldPart *I004_170_06_PARTS[] = { &I004_170_06_DT1, NULL };

/* Aircraft Characteristics Aircraft 1 */
static const value_string valstr_004_170_07_GATOAT[] = {
    { 0, "Unknown" },
    { 1, "General Air Traffic" },
    { 2, "Operational Air Traffic" },
    { 3, "Not applicable" },
    { 0, NULL }
};
static const value_string valstr_004_170_07_FR1FR2[] = {
    { 0, "Instrument Flight Rules" },
    { 1, "Visual Flight rules" },
    { 2, "Not applicable" },
    { 3, "Controlled Visual Flight Rules" },
    { 0, NULL }
};
static const value_string valstr_004_170_07_RVSM[] = {
    { 0, "Unknown" },
    { 1, "Approved" },
    { 2, "Exempt" },
    { 3, "Not Approved" },
    { 0, NULL }
};
static const value_string valstr_004_170_07_HPR[] = {
    { 0, "Normal Priority Flight" },
    { 1, "High Priority Flight" },
    { 0, NULL }
};
static const value_string valstr_004_170_07_CDM[] = {
    { 0, "Maintaining" },
    { 1, "Climbing" },
    { 2, "Descending" },
    { 3, "Invalid" },
    { 0, NULL }
};
static const value_string valstr_004_170_07_PRI[] = {
    { 0, "Non primary target" },
    { 1, "Primary target" },
    { 0, NULL }
};
static const value_string valstr_004_170_07_GV[] = {
    { 0, "Default" },
    { 1, "Ground Vehicle" },
    { 0, NULL }
};

static const FieldPart I004_170_07_GATOAT = { 2, 1.0, FIELD_PART_UINT, &hf_004_170_07_GATOAT, NULL };
static const FieldPart I004_170_07_FR1FR2 = { 2, 1.0, FIELD_PART_UINT, &hf_004_170_07_FR1FR2, NULL };
static const FieldPart I004_170_07_RVSM = { 2, 1.0, FIELD_PART_UINT, &hf_004_170_07_RVSM, NULL };
static const FieldPart I004_170_07_HPR = { 1, 1.0, FIELD_PART_UINT, &hf_004_170_07_HPR, NULL };
static const FieldPart I004_170_07_CDM = { 2, 1.0, FIELD_PART_UINT, &hf_004_170_07_CDM, NULL };
static const FieldPart I004_170_07_PRI = { 1, 1.0, FIELD_PART_UINT, &hf_004_170_07_PRI, NULL };
static const FieldPart I004_170_07_GV = { 1, 1.0, FIELD_PART_UINT, &hf_004_170_07_GV, NULL };
static const FieldPart *I004_170_07_PARTS[] = { &I004_170_07_GATOAT, &I004_170_07_FR1FR2, &I004_170_07_RVSM, &I004_170_07_HPR, &IXXX_FX,
                                                &I004_170_07_CDM, &I004_170_07_PRI, &I004_170_07_GV, &IXXX_3bit_spare, &IXXX_FX, NULL };

/* Mode-S Identifier Aircraft 1 */
static const FieldPart I004_170_08_MS1 = { 48, 1.0, FIELD_PART_CALLSIGN, &hf_004_170_08_MS1, NULL };
static const FieldPart *I004_170_08_PARTS[] = { &I004_170_08_MS1, NULL };

/* Flight Plan Number Aircraft 1 */
static const FieldPart I004_170_09_FP1 = { 27, 1.0, FIELD_PART_UINT, &hf_004_170_09_FP1, NULL };
static const FieldPart *I004_170_09_PARTS[] = { &IXXX_5bit_spare, &I004_170_09_FP1, NULL };

/* Cleared Flight Level Aircraft 1 */
static const FieldPart I004_170_10_CF1 = { 16, 0.25, FIELD_PART_FLOAT, &hf_004_170_10_CF1, NULL };
static const FieldPart *I004_170_10_PARTS[] = { &I004_170_10_CF1, NULL };

/* Aircraft Identification & Characteristics 2 */
/* Aircraft Identifier 2 */
static const FieldPart I004_171_01_AI2 = { 56, 1.0, FIELD_PART_ASCII, &hf_004_171_01_AI2, NULL };
static const FieldPart *I004_171_01_PARTS[] = { &I004_171_01_AI2, NULL };

/* Mode 3/A Code Aircraft 2 */
static const FieldPart I004_171_02_M32 = { 12, 1.0, FIELD_PART_SQUAWK, &hf_004_171_02_M32, NULL };
static const FieldPart *I004_171_02_PARTS[] = { &IXXX_4bit_spare, &I004_171_02_M32, NULL };

/* Predicted Conflict Position Aircraft 2 (WGS-84) */
static const FieldPart I004_171_03_LAT = { 32, 180.0/33554432.0, FIELD_PART_FLOAT, &hf_004_171_03_LAT, NULL };
static const FieldPart I004_171_03_LON = { 32, 180.0/33554432.0, FIELD_PART_FLOAT, &hf_004_171_03_LON, NULL };
static const FieldPart I004_171_03_ALT = { 16, 25.0, FIELD_PART_FLOAT, &hf_004_171_03_ALT, NULL };
static const FieldPart *I004_171_03_PARTS[] = { &I004_171_03_LAT, &I004_171_03_LON, &I004_171_03_ALT, NULL };

/* Predicted Conflict Position Aircraft 2 in Cartesian Coordinates */
static const FieldPart I004_171_04_X = { 24, 0.5, FIELD_PART_FLOAT, &hf_004_171_04_X, NULL };
static const FieldPart I004_171_04_Y = { 24, 0.5, FIELD_PART_FLOAT, &hf_004_171_04_Y, NULL };
static const FieldPart I004_171_04_Z = { 16, 25.0, FIELD_PART_FLOAT, &hf_004_171_04_Z, NULL };
static const FieldPart *I004_171_04_PARTS[] = { &I004_171_04_X, &I004_171_04_Y, &I004_171_04_Z, NULL };

/* Time to Threshold Aircraft 2 */
static const FieldPart I004_171_05_TT2 = { 24, 1.0/128.0, FIELD_PART_UFLOAT, &hf_004_171_05_TT2, "%.3f" };
static const FieldPart *I004_171_05_PARTS[] = { &I004_171_05_TT2, NULL };

/* Distance to Threshold Aircraft 2 */
static const FieldPart I004_171_06_DT2 = { 16, 0.5, FIELD_PART_UFLOAT, &hf_004_171_06_DT2, NULL };
static const FieldPart *I004_171_06_PARTS[] = { &I004_171_06_DT2, NULL };

/* Aircraft Characteristics Aircraft 2 */
static const value_string valstr_004_171_07_GATOAT[] = {
    { 0, "Unknown" },
    { 1, "General Air Traffic" },
    { 2, "Operational Air Traffic" },
    { 3, "Not applicable" },
    { 0, NULL }
};
static const value_string valstr_004_171_07_FR1FR2[] = {
    { 0, "Instrument Flight Rules" },
    { 1, "Visual Flight rules" },
    { 2, "Not applicable" },
    { 3, "Controlled Visual Flight Rules" },
    { 0, NULL }
};
static const value_string valstr_004_171_07_RVSM[] = {
    { 0, "Unknown" },
    { 1, "Approved" },
    { 2, "Exempt" },
    { 3, "Not Approved" },
    { 0, NULL }
};
static const value_string valstr_004_171_07_HPR[] = {
    { 0, "Normal Priority Flight" },
    { 1, "High Priority Flight" },
    { 0, NULL }
};
static const value_string valstr_004_171_07_CDM[] = {
    { 0, "Maintaining" },
    { 1, "Climbing" },
    { 2, "Descending" },
    { 3, "Invalid" },
    { 0, NULL }
};
static const value_string valstr_004_171_07_PRI[] = {
    { 0, "Non primary target" },
    { 1, "Primary target" },
    { 0, NULL }
};
static const value_string valstr_004_171_07_GV[] = {
    { 0, "Default" },
    { 1, "Ground Vehicle" },
    { 0, NULL }
};

static const FieldPart I004_171_07_GATOAT = { 2, 1.0, FIELD_PART_UINT, &hf_004_171_07_GATOAT, NULL };
static const FieldPart I004_171_07_FR1FR2 = { 2, 1.0, FIELD_PART_UINT, &hf_004_171_07_FR1FR2, NULL };
static const FieldPart I004_171_07_RVSM = { 2, 1.0, FIELD_PART_UINT, &hf_004_171_07_RVSM, NULL };
static const FieldPart I004_171_07_HPR = { 1, 1.0, FIELD_PART_UINT, &hf_004_171_07_HPR, NULL };
static const FieldPart I004_171_07_CDM = { 2, 1.0, FIELD_PART_UINT, &hf_004_171_07_CDM, NULL };
static const FieldPart I004_171_07_PRI = { 1, 1.0, FIELD_PART_UINT, &hf_004_171_07_PRI, NULL };
static const FieldPart I004_171_07_GV = { 1, 1.0, FIELD_PART_UINT, &hf_004_171_07_GV, NULL };
static const FieldPart *I004_171_07_PARTS[] = { &I004_171_07_GATOAT, &I004_171_07_FR1FR2, &I004_171_07_RVSM, &I004_171_07_HPR, &IXXX_FX,
                                                &I004_171_07_CDM, &I004_171_07_PRI, &I004_171_07_GV, &IXXX_3bit_spare, &IXXX_FX, NULL };

/* Mode-S Identifier Aircraft 2 */
static const FieldPart I004_171_08_MS2 = { 48, 1.0, FIELD_PART_CALLSIGN, &hf_004_171_08_MS2, NULL };
static const FieldPart *I004_171_08_PARTS[] = { &I004_171_08_MS2, NULL };

/* Flight Plan Number Aircraft 2 */
static const FieldPart I004_171_09_FP2 = { 27, 1.0, FIELD_PART_UINT, &hf_004_171_09_FP2, NULL };
static const FieldPart *I004_171_09_PARTS[] = { &IXXX_5bit_spare, &I004_171_09_FP2, NULL };

/* Cleared Flight Level Aircraft 2 */
static const FieldPart I004_171_10_CF2 = { 16, 0.25, FIELD_PART_FLOAT, &hf_004_171_10_CF2, NULL };
static const FieldPart *I004_171_10_PARTS[] = { &I004_171_10_CF2, NULL };

/* Items */
DIAG_OFF_PEDANTIC
static const AsterixField I004_000 = { FIXED, 1, 0, 0, &hf_004_000, I004_000_PARTS, { NULL } };
static const AsterixField I004_010 = { FIXED, 2, 0, 0, &hf_004_010, IXXX_SAC_SIC, { NULL } };
static const AsterixField I004_015 = { REPETITIVE, 2, 1, 0, &hf_004_015, IXXX_SAC_SIC, { NULL } };
static const AsterixField I004_020 = { FIXED, 3, 0, 0, &hf_004_020, IXXX_TOD, { NULL } };
static const AsterixField I004_030 = { FIXED, 2, 0, 0, &hf_004_030, I004_030_PARTS, { NULL } };
static const AsterixField I004_035 = { FIXED, 2, 0, 0, &hf_004_035, I004_035_PARTS, { NULL } };
static const AsterixField I004_040 = { FIXED, 2, 0, 0, &hf_004_040, I004_040_PARTS, { NULL } };
static const AsterixField I004_045 = { FIXED, 1, 0, 0, &hf_004_045, I004_045_PARTS, { NULL } };
static const AsterixField I004_060 = { FX, 1, 0, 0, &hf_004_060, I004_060_PARTS, { NULL } };
static const AsterixField I004_070_01 = { FIXED, 3, 0, 0, &hf_004_070_01, I004_070_01_PARTS, { NULL } };
static const AsterixField I004_070_02 = { FIXED, 3, 0, 0, &hf_004_070_02, I004_070_02_PARTS, { NULL } };
static const AsterixField I004_070_03 = { FIXED, 3, 0, 0, &hf_004_070_03, I004_070_03_PARTS, { NULL } };
static const AsterixField I004_070_04 = { FIXED, 2, 0, 0, &hf_004_070_04, I004_070_04_PARTS, { NULL } };
static const AsterixField I004_070_05 = { FIXED, 2, 0, 0, &hf_004_070_05, I004_070_05_PARTS, { NULL } };
static const AsterixField I004_070_06 = { FIXED, 2, 0, 0, &hf_004_070_06, I004_070_06_PARTS, { NULL } };
static const AsterixField I004_070 = { COMPOUND, 0, 0, 0, &hf_004_070, NULL, { &I004_070_01,
                                                                               &I004_070_02,
                                                                               &I004_070_03,
                                                                               &I004_070_04,
                                                                               &I004_070_05,
                                                                               &I004_070_06,
                                                                               NULL } };
static const AsterixField I004_074 = { FIXED, 2, 0, 0, &hf_004_074, I004_074_PARTS, { NULL } };
static const AsterixField I004_075 = { FIXED, 3, 0, 0, &hf_004_075, I004_075_PARTS, { NULL } };
static const AsterixField I004_076 = { FIXED, 2, 0, 0, &hf_004_076, I004_076_PARTS, { NULL } };
static const AsterixField I004_100_01 = { FIXED, 6, 0, 0, &hf_004_100_01, I004_100_01_PARTS, { NULL } };
static const AsterixField I004_100_02 = { FIXED, 7, 0, 0, &hf_004_100_02, I004_100_02_PARTS, { NULL } };
static const AsterixField I004_100_03 = { FIXED, 7, 0, 0, &hf_004_100_03, I004_100_03_PARTS, { NULL } };
static const AsterixField I004_100_04 = { FIXED, 7, 0, 0, &hf_004_100_04, I004_100_04_PARTS, { NULL } };
static const AsterixField I004_100_05 = { FIXED, 7, 0, 0, &hf_004_100_05, I004_100_05_PARTS, { NULL } };
static const AsterixField I004_100_06 = { FIXED, 7, 0, 0, &hf_004_100_06, I004_100_06_PARTS, { NULL } };
static const AsterixField I004_100 = { COMPOUND, 0, 0, 0, &hf_004_100, NULL, { &I004_100_01,
                                                                               &I004_100_02,
                                                                               &I004_100_03,
                                                                               &I004_100_04,
                                                                               &I004_100_05,
                                                                               &I004_100_06,
                                                                               NULL } };
static const AsterixField I004_110 = { REPETITIVE, 1, 2, 0, &hf_004_110, I004_110_PARTS, { NULL } };
static const AsterixField I004_120_01 = { FX, 1, 0, 0, &hf_004_120_01, I004_120_01_PARTS, { NULL } };
static const AsterixField I004_120_02 = { FIXED, 1, 0, 0, &hf_004_120_02, I004_120_02_PARTS, { NULL } };
static const AsterixField I004_120_03 = { FIXED, 1, 0, 0, &hf_004_120_03, I004_120_03_PARTS, { NULL } };
static const AsterixField I004_120_04 = { FIXED, 3, 0, 0, &hf_004_120_04, I004_120_04_PARTS, { NULL } };
static const AsterixField I004_120 = { COMPOUND, 0, 0, 0, &hf_004_120, NULL, { &I004_120_01,
                                                                               &I004_120_02,
                                                                               &I004_120_03,
                                                                               &I004_120_04,
                                                                               NULL } };
static const AsterixField I004_170_01 = { FIXED, 7, 0, 0, &hf_004_170_01, I004_170_01_PARTS, { NULL } };
static const AsterixField I004_170_02 = { FIXED, 2, 0, 0, &hf_004_170_02, I004_170_02_PARTS, { NULL } };
static const AsterixField I004_170_03 = { FIXED, 10, 0, 0, &hf_004_170_03, I004_170_03_PARTS, { NULL } };
static const AsterixField I004_170_04 = { FIXED, 8, 0, 0, &hf_004_170_04, I004_170_04_PARTS, { NULL } };
static const AsterixField I004_170_05 = { FIXED, 3, 0, 0, &hf_004_170_05, I004_170_05_PARTS, { NULL } };
static const AsterixField I004_170_06 = { FIXED, 2, 0, 0, &hf_004_170_06, I004_170_06_PARTS, { NULL } };
static const AsterixField I004_170_07 = { FX, 1, 0, 0, &hf_004_170_07, I004_170_07_PARTS, { NULL } };
static const AsterixField I004_170_08 = { FIXED, 6, 0, 0, &hf_004_170_08, I004_170_08_PARTS, { NULL } };
static const AsterixField I004_170_09 = { FIXED, 4, 0, 0, &hf_004_170_09, I004_170_09_PARTS, { NULL } };
static const AsterixField I004_170_10 = { FIXED, 2, 0, 0, &hf_004_170_10, I004_170_10_PARTS, { NULL } };
static const AsterixField I004_170 = { COMPOUND, 0, 0, 0, &hf_004_170, NULL, { &I004_170_01,
                                                                               &I004_170_02,
                                                                               &I004_170_03,
                                                                               &I004_170_04,
                                                                               &I004_170_05,
                                                                               &I004_170_06,
                                                                               &I004_170_07,
                                                                               &I004_170_08,
                                                                               &I004_170_09,
                                                                               &I004_170_10,
                                                                               NULL } };
static const AsterixField I004_171_01 = { FIXED, 7, 0, 0, &hf_004_171_01, I004_171_01_PARTS, { NULL } };
static const AsterixField I004_171_02 = { FIXED, 2, 0, 0, &hf_004_171_02, I004_171_02_PARTS, { NULL } };
static const AsterixField I004_171_03 = { FIXED, 10, 0, 0, &hf_004_171_03, I004_171_03_PARTS, { NULL } };
static const AsterixField I004_171_04 = { FIXED, 8, 0, 0, &hf_004_171_04, I004_171_04_PARTS, { NULL } };
static const AsterixField I004_171_05 = { FIXED, 3, 0, 0, &hf_004_171_05, I004_171_05_PARTS, { NULL } };
static const AsterixField I004_171_06 = { FIXED, 2, 0, 0, &hf_004_171_06, I004_171_06_PARTS, { NULL } };
static const AsterixField I004_171_07 = { FX, 1, 0, 0, &hf_004_171_07, I004_171_07_PARTS, { NULL } };
static const AsterixField I004_171_08 = { FIXED, 6, 0, 0, &hf_004_171_08, I004_171_08_PARTS, { NULL } };
static const AsterixField I004_171_09 = { FIXED, 4, 0, 0, &hf_004_171_09, I004_171_09_PARTS, { NULL } };
static const AsterixField I004_171_10 = { FIXED, 2, 0, 0, &hf_004_171_10, I004_171_10_PARTS, { NULL } };
static const AsterixField I004_171 = { COMPOUND, 0, 0, 0, &hf_004_171, NULL, { &I004_171_01,
                                                                               &I004_171_02,
                                                                               &I004_171_03,
                                                                               &I004_171_04,
                                                                               &I004_171_05,
                                                                               &I004_171_06,
                                                                               &I004_171_07,
                                                                               &I004_171_08,
                                                                               &I004_171_09,
                                                                               &I004_171_10,
                                                                               NULL } };
static const AsterixField I004_SP = { SP, 0, 0, 1, &hf_004_SP, NULL, { NULL } };
static const AsterixField I004_RE = { RE, 0, 0, 1, &hf_004_RE, NULL, { NULL } };

static const AsterixField *I004_v1_7_uap[] = { &I004_010, &I004_000, &I004_015, &I004_020, &I004_040, &I004_045, &I004_060,
                                               &I004_030, &I004_170, &I004_120, &I004_070, &I004_076, &I004_074, &I004_075,
                                               &I004_100, &I004_035, &I004_171, &I004_110, &IX_SPARE, &I004_RE,  &I004_SP, NULL };
static const AsterixField **I004_v1_7[] = { I004_v1_7_uap, NULL };
static const AsterixField ***I004[] = { I004_v1_7 };
DIAG_ON_PEDANTIC

static const enum_val_t I004_versions[] = {
    { "I004_v1_7", "Version 1.7", 0 },
    { NULL, NULL, 0 }
};

/* *********************** */
/*      Category 008       */
/* *********************** */
/* Fields */

/* Message Type */
static const value_string valstr_008_000_MT[] = {
    { 1, "Polar vector" },
    { 2, "Cartesian vector of start point/ length" },
    { 3, "Contour record" },
    { 4, "Cartesian start point and end point vector" },
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
DIAG_OFF_PEDANTIC
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
DIAG_ON_PEDANTIC

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
DIAG_OFF_PEDANTIC
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
DIAG_ON_PEDANTIC

static const enum_val_t I009_versions[] = {
    { "I009_v2_0", "Version 2.0", 0 },
    { NULL, NULL, 0 }
};

/* *********************** */
/*      Category 010       */
/* *********************** */

/*
 * Online specification:
 * https://www.eurocontrol.int/publication/cat010-eurocontrol-specification-surveillance-data-exchange-part-7-category-010
 */

/* Fields */

/* Message Type */
static const value_string valstr_010_000_MT[] = {
    { 1, "Target Report" },
    { 2, "Start of Update Cycle" },
    { 3, "Periodic Status Message" },
    { 4, "Event-triggered Status Message" },
    { 0, NULL }
};
static const FieldPart I010_000_MT = { 8, 1.0, FIELD_PART_UINT, &hf_010_000_MT, NULL };
static const FieldPart *I010_000_PARTS[] = { &I010_000_MT, NULL };

/* Target Descriptor */
static const value_string valstr_010_020_TYP[] = {
    { 0, "SSR multilateration" },
    { 1, "Mode-S multilateration" },
    { 2, "ADS-B" },
    { 3, "PSR" },
    { 4, "Magnetic Loop System" },
    { 5, "HF multilateration" },
    { 6, "Not defined" },
    { 7, "Other types" },
    { 0, NULL }
};
static const value_string valstr_010_020_DCR[] = {
    { 0, "No differential correction (ADS-B)" },
    { 1, "Differential correction (ADS-B)" },
    { 0, NULL }
};
static const value_string valstr_010_020_CHN[] = {
    { 0, "Chain 1" },
    { 1, "Chain 2" },
    { 0, NULL }
};
static const value_string valstr_010_020_GBS[] = {
    { 0, "Transponder Ground bit not set" },
    { 1, "Transponder Ground bit set" },
    { 0, NULL }
};
static const value_string valstr_010_020_CRT[] = {
    { 0, "No Corrupted reply in multilateration" },
    { 1, "Corrupted reply in multilateration" },
    { 0, NULL }
};
static const value_string valstr_010_020_SIM[] = {
    { 0, "Actual target report" },
    { 1, "Simulated target report" },
    { 0, NULL }
};
static const value_string valstr_010_020_TST[] = {
    { 0, "Default" },
    { 1, "Test Target" },
    { 0, NULL }
};
static const value_string valstr_010_020_RAB[] = {
    { 0, "Report from target transponder" },
    { 1, "Report from field monitor (fixed transponder)" },
    { 0, NULL }
};
static const value_string valstr_010_020_LOP[] = {
    { 0, "Undetermined" },
    { 1, "Loop start" },
    { 2, "Loop finish" },
    { 0, NULL }
};
static const value_string valstr_010_020_TOT[] = {
    { 0, "Undetermined" },
    { 1, "Aircraft" },
    { 2, "Ground vehicle" },
    { 3, "Helicopter" },
    { 0, NULL }
};
static const value_string valstr_010_020_SPI[] = {
    { 0, "Absence of SPI" },
    { 1, "Special Position Identification" },
    { 0, NULL }
};
static const FieldPart I010_020_TYP = { 3, 1.0, FIELD_PART_UINT, &hf_010_020_TYP, NULL };
static const FieldPart I010_020_DCR = { 1, 1.0, FIELD_PART_UINT, &hf_010_020_DCR, NULL };
static const FieldPart I010_020_CHN = { 1, 1.0, FIELD_PART_UINT, &hf_010_020_CHN, NULL };
static const FieldPart I010_020_GBS = { 1, 1.0, FIELD_PART_UINT, &hf_010_020_GBS, NULL };
static const FieldPart I010_020_CRT = { 1, 1.0, FIELD_PART_UINT, &hf_010_020_CRT, NULL };
static const FieldPart I010_020_SIM = { 1, 1.0, FIELD_PART_UINT, &hf_010_020_SIM, NULL };
static const FieldPart I010_020_TST = { 1, 1.0, FIELD_PART_UINT, &hf_010_020_TST, NULL };
static const FieldPart I010_020_RAB = { 1, 1.0, FIELD_PART_UINT, &hf_010_020_RAB, NULL };
static const FieldPart I010_020_LOP = { 2, 1.0, FIELD_PART_UINT, &hf_010_020_LOP, NULL };
static const FieldPart I010_020_TOT = { 2, 1.0, FIELD_PART_UINT, &hf_010_020_TOT, NULL };
static const FieldPart I010_020_SPI = { 1, 1.0, FIELD_PART_UINT, &hf_010_020_SPI, NULL };
static const FieldPart *I010_020_PARTS[] = { &I010_020_TYP, &I010_020_DCR, &I010_020_CHN, &I010_020_GBS, &I010_020_CRT, &IXXX_FX,
                                             &I010_020_SIM, &I010_020_TST, &I010_020_RAB, &I010_020_LOP, &I010_020_TOT, &IXXX_FX,
                                             &I010_020_SPI, &IXXX_6bit_spare, &IXXX_FX, NULL };

/* Measured Position in Polar Coordinates */
static const FieldPart I010_040_RHO = { 16, 1.0, FIELD_PART_UFLOAT, &hf_010_040_RHO, NULL };
static const FieldPart I010_040_THETA = { 16, 360.0/65536.0, FIELD_PART_UFLOAT, &hf_010_040_THETA, NULL };
static const FieldPart *I010_040_PARTS[] = { &I010_040_RHO, &I010_040_THETA, NULL };

/* Position in WGS-84 Coordinates */
static const FieldPart I010_041_LAT = { 32, 180.0/33554432.0, FIELD_PART_FLOAT, &hf_010_041_LAT, NULL };
static const FieldPart I010_041_LON = { 32, 180.0/33554432.0, FIELD_PART_FLOAT, &hf_010_041_LON, NULL };
static const FieldPart *I010_041_PARTS[] = { &I010_041_LAT, &I010_041_LON, NULL };

/* Position in Cartesian Coordinates */
static const FieldPart I010_042_X = { 24, 1.0, FIELD_PART_FLOAT, &hf_010_042_X, NULL };
static const FieldPart I010_042_Y = { 24, 1.0, FIELD_PART_FLOAT, &hf_010_042_Y, NULL };
static const FieldPart *I010_042_PARTS[] = { &I010_042_X, &I010_042_Y, NULL };

/* Mode-3/A Code in Octal Representation */
static const value_string valstr_010_060_V[] = {
    { 0, "Code validated" },
    { 1, "Code not validated" },
    { 0, NULL }
};
static const value_string valstr_010_060_G[] = {
    { 0, "Default" },
    { 1, "Garbled code" },
    { 0, NULL }
};
static const value_string valstr_010_060_L[] = {
    { 0, "Mode-3/A code derived from the reply of the transponder" },
    { 1, "Mode-3/A code not extracted during the last scan" },
    { 0, NULL }
};
static const FieldPart I010_060_V = { 1, 1.0, FIELD_PART_UINT, &hf_010_060_V, NULL };
static const FieldPart I010_060_G = { 1, 1.0, FIELD_PART_UINT, &hf_010_060_G, NULL };
static const FieldPart I010_060_L = { 1, 1.0, FIELD_PART_UINT, &hf_010_060_L, NULL };
static const FieldPart I010_060_SQUAWK = { 12, 1.0, FIELD_PART_SQUAWK, &hf_010_060_SQUAWK, NULL };
static const FieldPart *I010_060_PARTS[] = { &I010_060_V, &I010_060_G, &I010_060_L, &IXXX_1bit_spare, &I010_060_SQUAWK, NULL };

/* Flight Level in Binary Representation */
static const value_string valstr_010_090_V[] = {
    { 0, "Code validated" },
    { 1, "Code not validated" },
    { 0, NULL }
};
static const value_string valstr_010_090_G[] = {
    { 0, "Default" },
    { 1, "Garbled code" },
    { 0, NULL }
};
static const FieldPart I010_090_V = { 1, 1.0, FIELD_PART_UINT, &hf_010_090_V, NULL };
static const FieldPart I010_090_G = { 1, 1.0, FIELD_PART_UINT, &hf_010_090_G, NULL };
static const FieldPart I010_090_FL = { 14, 0.25, FIELD_PART_FLOAT, &hf_010_090_FL, NULL };
static const FieldPart *I010_090_PARTS[] = { &I010_090_V, &I010_090_G, &I010_090_FL, NULL };

/* Measured Height */
static const FieldPart I010_091_MH = { 16, 6.25, FIELD_PART_FLOAT, &hf_010_091_MH, NULL };
static const FieldPart *I010_091_PARTS[] = { &I010_091_MH, NULL };

/* Amplitude of Primary Plot */
static const FieldPart I010_131_PAM = { 8, 1.0, FIELD_PART_INT, &hf_010_131_PAM, NULL };
static const FieldPart *I010_131_PARTS[] = { &I010_131_PAM, NULL };

/* Time of Day 140*/
/* IXXX_TOD */

/* Track Number */
static const FieldPart I010_161_TN = { 12, 1.0, FIELD_PART_UINT, &hf_010_161_TN, NULL };
static const FieldPart *I010_161_PARTS[] = { &IXXX_4bit_spare, &I010_161_TN, NULL };

/* Track Status */
static const value_string valstr_010_170_CNF[] = {
    { 0, "Confirmed track" },
    { 1, "Track in initiation phase" },
    { 0, NULL }
};
static const value_string valstr_010_170_TRE[] = {
    { 0, "Default" },
    { 1, "Last report for a track" },
    { 0, NULL }
};
static const value_string valstr_010_170_CST[] = {
    { 0, "No extrapolation" },
    { 1, "Predictable extrapolation due to sensor refresh period" },
    { 2, "Predictable extrapolation in masked area" },
    { 3, "Extrapolation due to unpredictable absence of detection" },
    { 0, NULL }
};
static const value_string valstr_010_170_MAH[] = {
    { 0, "Default" },
    { 1, "Horizontal manoeuvre" },
    { 0, NULL }
};
static const value_string valstr_010_170_TCC[] = {
    { 0, "Tracking performed in 'Sensor Plane', i.e. neither slant range correction nor projection was applied." },
    { 1, "Slant range correction and a suitable projection technique are used to track in a 2D.reference plane, tangential to the earth model at the Sensor Site co-ordinates." },
    { 0, NULL }
};
static const value_string valstr_010_170_STH[] = {
    { 0, "Measured position" },
    { 1, "Smoothed position" },
    { 0, NULL }
};
static const value_string valstr_010_170_TOM[] = {
    { 0, "Unknown type of movement" },
    { 1, "Taking-off" },
    { 2, "Landing" },
    { 3, "Other types of movement" },
    { 0, NULL }
};
static const value_string valstr_010_170_DOU[] = {
    { 0, "No doubt" },
    { 1, "Doubtful correlation (undetermined reason)" },
    { 2, "Doubtful correlation in clutter" },
    { 3, "Loss of accuracy" },
    { 4, "Loss of accuracy in clutter" },
    { 5, "Unstable track" },
    { 6, "Previously coasted" },
    { 0, NULL }
};
static const value_string valstr_010_170_MRS[] = {
    { 0, "Merge or split indication undetermined" },
    { 1, "Track merged by association to plot" },
    { 2, "Track merged by non-association to plot" },
    { 3, "Split track" },
    { 0, NULL }
};
static const value_string valstr_010_170_GHO[] = {
    { 0, "Default" },
    { 1, "Ghost track" },
    { 0, NULL }
};

static const FieldPart I010_170_CNF = { 1, 1.0, FIELD_PART_UINT, &hf_010_170_CNF, NULL };
static const FieldPart I010_170_TRE = { 1, 1.0, FIELD_PART_UINT, &hf_010_170_TRE, NULL };
static const FieldPart I010_170_CST = { 2, 1.0, FIELD_PART_UINT, &hf_010_170_CST, NULL };
static const FieldPart I010_170_MAH = { 1, 1.0, FIELD_PART_UINT, &hf_010_170_MAH, NULL };
static const FieldPart I010_170_TCC = { 1, 1.0, FIELD_PART_UINT, &hf_010_170_TCC, NULL };
static const FieldPart I010_170_STH = { 1, 1.0, FIELD_PART_UINT, &hf_010_170_STH, NULL };
static const FieldPart I010_170_TOM = { 2, 1.0, FIELD_PART_UINT, &hf_010_170_TOM, NULL };
static const FieldPart I010_170_DOU = { 3, 1.0, FIELD_PART_UINT, &hf_010_170_DOU, NULL };
static const FieldPart I010_170_MRS = { 2, 1.0, FIELD_PART_UINT, &hf_010_170_MRS, NULL };
static const FieldPart I010_170_GHO = { 1, 1.0, FIELD_PART_UINT, &hf_010_170_GHO, NULL };

static const FieldPart *I010_170_PARTS[] = { &I010_170_CNF, &I010_170_TRE, &I010_170_CST, &I010_170_MAH, &I010_170_TCC, &I010_170_STH, &IXXX_FX,
                                             &I010_170_TOM, &I010_170_DOU, &I010_170_MRS, &IXXX_FX,
                                             &I010_170_GHO, &IXXX_6bit_spare, &IXXX_FX, NULL };

/* Calculated Track Velocity in Polar Co-ordinates */
static const FieldPart I010_200_GS = { 16, 1.0/16384.0, FIELD_PART_UFLOAT, &hf_010_200_GS, NULL };
static const FieldPart I010_200_TA = { 16, 360.0/65536.0, FIELD_PART_UFLOAT, &hf_010_200_TA, NULL };
static const FieldPart *I010_200_PARTS[] = { &I010_200_GS, &I010_200_TA, NULL };

/* Calculated Track Velocity in Cartesian Co-ordinates */
static const FieldPart I010_202_VX = { 16, 0.25, FIELD_PART_FLOAT, &hf_010_202_VX, NULL };
static const FieldPart I010_202_VY = { 16, 0.25, FIELD_PART_FLOAT, &hf_010_202_VY, NULL };
static const FieldPart *I010_202_PARTS[] = { &I010_202_VX, &I010_202_VY, NULL };

/* Calculated Acceleration */
static const FieldPart I010_210_AX = { 8, 0.25, FIELD_PART_FLOAT, &hf_010_210_AX, NULL };
static const FieldPart I010_210_AY = { 8, 0.25, FIELD_PART_FLOAT, &hf_010_210_AY, NULL };
static const FieldPart *I010_210_PARTS[] = { &I010_210_AX, &I010_210_AY, NULL };

/* Target Address */
/* IXXX_AA */

/* Target Identification */
static const value_string valstr_010_245_STI[] = {
    { 0, "Callsign or registration not downlinked from transponder" },
    { 1, "Registration downlinked from transponder" },
    { 2, "Callsign downlinked from transponder" },
    { 3, "Not defined" },
    { 0, NULL }
};
static const FieldPart I010_245_STI = { 2, 1.0, FIELD_PART_UINT, &hf_010_245_STI, NULL };
static const FieldPart *I010_245_PARTS[] = { &I010_245_STI, &IXXX_6bit_spare, &IXXX_AI, NULL };

/* Mode S MB Data */
/* IXXX_MB */

/* Target Size & Orientation */
static const FieldPart I010_270_LENGTH = { 7, 1.0, FIELD_PART_UFLOAT, &hf_010_270_LENGTH, NULL };
static const FieldPart I010_270_ORIENTATION = { 7, 360.0/128.0, FIELD_PART_UFLOAT, &hf_010_270_ORIENTATION, NULL };
static const FieldPart I010_270_WIDTH = { 7, 1.0, FIELD_PART_UFLOAT, &hf_010_270_WIDTH, NULL };
static const FieldPart *I010_270_PARTS[] = { &I010_270_LENGTH, &IXXX_FX,
                                             &I010_270_ORIENTATION, &IXXX_FX,
                                             &I010_270_WIDTH, &IXXX_FX, NULL };

/* Presence */
static const FieldPart I010_280_DHRO = { 8, 1.0, FIELD_PART_UFLOAT, &hf_010_280_DRHO, NULL };
static const FieldPart I010_280_DTHETA = { 8, 1.0, FIELD_PART_UFLOAT, &hf_010_280_DTHETA, NULL };
static const FieldPart *I010_280_PARTS[] = { &I010_280_DHRO, &I010_280_DTHETA, NULL };

/* Vehicle Fleet Identification */
static const value_string valstr_010_300_VFI[] = {
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
    {  0, NULL }
};
static const FieldPart I010_300_VFI = { 8, 1.0, FIELD_PART_UINT, &hf_010_300_VFI, NULL };
static const FieldPart *I010_300_PARTS[] = { &I010_300_VFI, NULL };

/* Pre-programmed Message */
static const value_string valstr_010_310_TRB[] = {
    { 0, "Default" },
    { 1, "In Trouble" },
    { 0, NULL }
};
static const value_string valstr_010_310_MSG[] = {
    { 1, "Towing aircraft" },
    { 2, "\"Follow me\" operation" },
    { 3, "Runway check" },
    { 4, "Emergency operation (fire, medical...)" },
    { 5, "Work in progress (maintenance, birds scarer, sweepers...)" },
    { 0, NULL }
};
static const FieldPart I010_310_TRB = { 1, 1.0, FIELD_PART_UINT, &hf_010_310_TRB, NULL };
static const FieldPart I010_310_MSG = { 7, 1.0, FIELD_PART_UINT, &hf_010_310_MSG, NULL };
static const FieldPart *I010_310_PARTS[] = { &I010_310_TRB, &I010_310_MSG, NULL };

/* Standard Deviation of Position */
static const FieldPart I010_500_SDPx = { 8, 0.25, FIELD_PART_UFLOAT, &hf_010_500_SDPx, NULL };
static const FieldPart I010_500_SDPy = { 8, 0.25, FIELD_PART_UFLOAT, &hf_010_500_SDPy, NULL };
static const FieldPart I010_500_SDPxy = { 16, 0.25, FIELD_PART_FLOAT, &hf_010_500_SDPxy, NULL };
static const FieldPart *I010_500_PARTS[] = { &I010_500_SDPx, &I010_500_SDPy, &I010_500_SDPxy, NULL };

/* System Status */
static const value_string valstr_010_550_NOGO[] = {
    { 0, "Operational" },
    { 1, "Degraded" },
    { 2, "NOGO" },
    { 0, NULL }
};

static const value_string valstr_010_550_OVL[] = {
    { 0, "No overload" },
    { 1, "Overload" },
    { 0, NULL }
};

static const value_string valstr_010_550_TSV[] = {
    { 0, "Valid" },
    { 1, "Invalid" },
    { 0, NULL }
};

static const value_string valstr_010_550_DIV[] = {
    { 0, "Normal Operation" },
    { 1, "Diversity degraded" },
    { 0, NULL }
};

static const value_string valstr_010_550_TTF[] = {
    { 0, "Test Target Operative" },
    { 1, "Test Target Failure" },
    { 0, NULL }
};

static const FieldPart I010_550_NOGO = { 2, 1.0, FIELD_PART_UINT, &hf_010_550_NOGO, NULL };
static const FieldPart I010_550_OVL = { 1, 1.0, FIELD_PART_UINT, &hf_010_550_OVL, NULL };
static const FieldPart I010_550_TSV = { 1, 1.0, FIELD_PART_UINT, &hf_010_550_TSV, NULL };
static const FieldPart I010_550_DIV = { 1, 1.0, FIELD_PART_UINT, &hf_010_550_DIV, NULL };
static const FieldPart I010_550_TTF = { 1, 1.0, FIELD_PART_UINT, &hf_010_550_TTF, NULL };
static const FieldPart *I010_550_PARTS[] = { &I010_550_NOGO, &I010_550_OVL, &I010_550_TSV, &I010_550_DIV, &I010_550_TTF, &IXXX_2bit_spare, NULL };

/* Items */
DIAG_OFF(pedantic)
static const AsterixField I010_000 = { FIXED, 1, 0, 0, &hf_010_000, I010_000_PARTS, { NULL } };
static const AsterixField I010_010 = { FIXED, 2, 0, 0, &hf_010_010, IXXX_SAC_SIC, { NULL } };
static const AsterixField I010_020 = { FX_UAP, 1, 0, 0, &hf_010_020, I010_020_PARTS, { NULL } };
static const AsterixField I010_040 = { FIXED, 4, 0, 0, &hf_010_040, I010_040_PARTS, { NULL } };
static const AsterixField I010_041 = { FIXED, 8, 0, 0, &hf_010_041, I010_041_PARTS, { NULL } };
static const AsterixField I010_042 = { FIXED, 6, 0, 0, &hf_010_042, I010_042_PARTS, { NULL } };
static const AsterixField I010_060 = { FIXED, 2, 0, 0, &hf_010_060, I010_060_PARTS, { NULL } };
static const AsterixField I010_090 = { FIXED, 2, 0, 0, &hf_010_090, I010_090_PARTS, { NULL } };
static const AsterixField I010_091 = { FIXED, 2, 0, 0, &hf_010_091, I010_091_PARTS, { NULL } };
static const AsterixField I010_131 = { FIXED, 1, 0, 0, &hf_010_131, I010_131_PARTS, { NULL } };
static const AsterixField I010_140 = { FIXED, 3, 0, 0, &hf_010_140, IXXX_TOD, { NULL } };
static const AsterixField I010_161 = { FIXED, 2, 0, 0, &hf_010_161, I010_161_PARTS, { NULL } };
static const AsterixField I010_170 = { FX, 1, 0, 0, &hf_010_170, I010_170_PARTS, { NULL } };
static const AsterixField I010_200 = { FIXED, 4, 0, 0, &hf_010_200, I010_200_PARTS, { NULL } };
static const AsterixField I010_202 = { FIXED, 4, 0, 0, &hf_010_202, I010_202_PARTS, { NULL } };
static const AsterixField I010_210 = { FIXED, 2, 0, 0, &hf_010_210, I010_210_PARTS, { NULL } };
static const AsterixField I010_220 = { FIXED, 3, 0, 0, &hf_010_220, IXXX_AA_PARTS, { NULL } };
static const AsterixField I010_245 = { FIXED, 7, 0, 0, &hf_010_245, I010_245_PARTS, { NULL } };
static const AsterixField I010_250 = { REPETITIVE, 8, 1, 0, &hf_010_250, IXXX_MB, { NULL } };
static const AsterixField I010_270 = { FX, 1, 0, 0, &hf_010_270, I010_270_PARTS, { NULL } };
static const AsterixField I010_280 = { REPETITIVE, 2, 1, 0, &hf_010_280, I010_280_PARTS, { NULL } };
static const AsterixField I010_300 = { FIXED, 1, 0, 0, &hf_010_300, I010_300_PARTS, { NULL } };
static const AsterixField I010_310 = { FIXED, 1, 0, 0, &hf_010_310, I010_310_PARTS, { NULL } };
static const AsterixField I010_500 = { FIXED, 4, 0, 0, &hf_010_500, I010_500_PARTS, { NULL } };
static const AsterixField I010_550 = { FIXED, 1, 0, 0, &hf_010_550, I010_550_PARTS, { NULL } };
static const AsterixField I010_SP = { SP, 0, 0, 1, &hf_010_SP, NULL, { NULL } };
static const AsterixField I010_RE = { RE, 0, 0, 1, &hf_010_RE, NULL, { NULL } };

static const AsterixField *I010_v1_1_uap[] = { &I010_010, &I010_000, &I010_020, &I010_140, &I010_041, &I010_040, &I010_042,
                                               &I010_200, &I010_202, &I010_161, &I010_170, &I010_060, &I010_220, &I010_245,
                                               &I010_250, &I010_300, &I010_090, &I010_091, &I010_270, &I010_550, &I010_310,
                                               &I010_500, &I010_280, &I010_131, &I010_210, &IX_SPARE, &I010_SP,  &I010_RE,
                                               NULL };
static const AsterixField **I010_v1_1[] = { I010_v1_1_uap, NULL };
static const AsterixField ***I010[] = { I010_v1_1 };
DIAG_ON(pedantic)

static const enum_val_t I010_versions[] = {
    { "I010_v1_1", "Version 1.10", 0 },
    { NULL, NULL, 0 }
};

/* *********************** */
/*      Category 011       */
/* *********************** */

/*
 * Online specification:
 * https://www.eurocontrol.int/publication/cat011-eurocontrol-specification-surveillance-data-exchange-part-8-category-011
 */

/* Fields */

/* Message Type */
static const value_string valstr_011_000_MT[] = {
    { 1, "Target reports, flight plan data and basic alerts" },
    { 2, "Manual attachment of flight plan to track" },
    { 3, "Manual detachment of flight plan to track" },
    { 4, "Insertion of flight plan data" },
    { 5, "Suppression of flight plan data" },
    { 6, "Modification of flight plan data" },
    { 7, "Holdbar status" },
    { 0, NULL }
};
static const FieldPart I011_000_MT = { 8, 1.0, FIELD_PART_UINT, &hf_011_000_MT, NULL };
static const FieldPart *I011_000_PARTS[] = { &I011_000_MT, NULL };

/* Data Source Identifier */
/* IXXX_SAC_SIC */

/* Service Identification */
static const FieldPart I011_015_SI = { 8, 1.0, FIELD_PART_UINT, &hf_011_015_SI, NULL };
static const FieldPart *I011_015_PARTS[] = { &I011_015_SI, NULL };

/* Position in WGS-84 Co-ordinates */
static const FieldPart I011_041_LAT = { 32, 180.0/2147483648.0, FIELD_PART_FLOAT, &hf_011_041_LAT, NULL };
static const FieldPart I011_041_LON = { 32, 180.0/2147483648.0, FIELD_PART_FLOAT, &hf_011_041_LON, NULL };
static const FieldPart *I011_041_PARTS[] = { &I011_041_LAT, &I011_041_LON, NULL };

/* Calculated Position in Cartesian Co-ordinates */
static const FieldPart I011_042_X = { 16, 1.0, FIELD_PART_FLOAT, &hf_011_042_X, NULL };
static const FieldPart I011_042_Y = { 16, 1.0, FIELD_PART_FLOAT, &hf_011_042_Y, NULL };
static const FieldPart *I011_042_PARTS[] = { &I011_042_X, &I011_042_Y, NULL };

/* Mode-3/A Code in Octal Representation */
static const FieldPart I011_060_SQUAWK = { 12, 1.0, FIELD_PART_SQUAWK, &hf_011_060_SQUAWK, NULL };
static const FieldPart *I011_060_PARTS[] = { &IXXX_4bit_spare, &I011_060_SQUAWK, NULL };

/* Measured Flight Level */
static const FieldPart I011_090_MFL = { 16, 1.0/4.0, FIELD_PART_FLOAT, &hf_011_090_MFL, NULL };
static const FieldPart *I011_090_PARTS[] = { &I011_090_MFL, NULL };

/* Calculated Track Geometric Altitude */
static const FieldPart I011_092_ALT = { 16, 6.25, FIELD_PART_FLOAT, &hf_011_092_ALT, NULL };
static const FieldPart *I011_092_PARTS[] = { &I011_092_ALT, NULL };

/* Calculated Track Barometric Altitude */
static const value_string valstr_011_093_QNH[] = {
    { 0, "No QNH correction applied" },
    { 1, "QNH correction applied" },
    { 0, NULL }
};
static const FieldPart I011_093_QNH = { 1, 1.0, FIELD_PART_UINT, &hf_011_093_QNH, NULL };
static const FieldPart I011_093_ALT = { 15, 1.0/4.0, FIELD_PART_FLOAT, &hf_011_093_ALT, NULL };
static const FieldPart *I011_093_PARTS[] = { &I011_093_QNH, &I011_093_ALT, NULL };

/* Time of Track Information */
/* IXXX_TOD */

/* Track number */
static const FieldPart I011_161_TN = { 15, 1.0, FIELD_PART_UINT, &hf_011_161_TN, NULL };
static const FieldPart *I011_161_PARTS[] = { &IXXX_1bit_spare, &I011_161_TN, NULL };

/* Track Status */
static const value_string valstr_011_170_MON[] = {
    { 0, "Multisensor" },
    { 1, "Monosensor track track" },
    { 0, NULL }
};
static const value_string valstr_011_170_GBS[] = {
    { 0, "Transponder Ground bit not set or unknown" },
    { 1, "Transponder Ground bit set" },
    { 0, NULL }
};
static const value_string valstr_011_170_MRH[] = {
    { 0, "Barometric altitude (Mode C) more reliable" },
    { 1, "Geometric altitude more reliable" },
    { 0, NULL }
};
static const value_string valstr_011_170_SRC[] = {
    { 0, "No source" },
    { 1, "GPS" },
    { 2, "3D radar" },
    { 3, "Triangulation" },
    { 4, "Height from coverage" },
    { 5, "Speed look-up table" },
    { 6, "Default height" },
    { 7, "Multilateration" },
    { 0, NULL }
};
static const value_string valstr_011_170_CNF[] = {
    { 0, "Confirmed track" },
    { 1, "Tentative track" },
    { 0, NULL }
};
static const value_string valstr_011_170_SIM[] = {
    { 0, "Actual track" },
    { 1, "Simulated track" },
    { 0, NULL }
};
static const value_string valstr_011_170_TSE[] = {
    { 0, "Default value" },
    { 1, "Track service end (i.e. Last message transmitted to the user for the track)" },
    { 0, NULL }
};
static const value_string valstr_011_170_TSB[] = {
    { 0, "Default value" },
    { 1, "Track service begin (i.e. First message transmitted to the user for the track)" },
    { 0, NULL }
};
static const value_string valstr_011_170_FRIFOE[] = {
    { 0, "No Mode 4 interrogation" },
    { 1, "Friendly target" },
    { 2, "Unknown target" },
    { 3, "No reply" },
    { 0, NULL }
};
static const value_string valstr_011_170_ME[] = {
    { 0, "Default value" },
    { 1, "Military Emergency present in the last report received from a sensor capable of decoding this data" },
    { 0, NULL }
};
static const value_string valstr_011_170_MI[] = {
    { 0, "Default value" },
    { 1, "Military Identification present in the last report received from a sensor capable of decoding this data" },
    { 0, NULL }
};

static const value_string valstr_011_170_AMA[] = {
    { 0, "Track not resulting from amalgamation process" },
    { 1, "Track resulting from amalgamation process" },
    { 0, NULL }
};
static const value_string valstr_011_170_SPI[] = {
    { 0, "Default value" },
    { 1, "SPI present in the last report received from a sensor capable of decoding this data" },
    { 0, NULL }
};
static const value_string valstr_011_170_CST[] = {
    { 0, "Default value" },
    { 1, "Age of the last received track update is higher than system dependent threshold (coasting)" },
    { 0, NULL }
};
static const value_string valstr_011_170_FPC[] = {
    { 0, "Not flight-plan correlated" },
    { 1, "Flight plan correlated" },
    { 0, NULL }
};
static const value_string valstr_011_170_AFF[] = {
    { 0, "Default value" },
    { 1, "ADS-B data inconsistent with other surveillance information" },
    { 0, NULL }
};
static const value_string valstr_011_170_PSR[] = {
    { 0, "Default value" },
    { 1, "Age of the last received PSR track update is higher than system dependent threshold" },
    { 0, NULL }
};
static const value_string valstr_011_170_SSR[] = {
    { 0, "Default value" },
    { 1, "Age of the last received SSR track update is higher than system dependent threshold" },
    { 0, NULL }
};
static const value_string valstr_011_170_MDS[] = {
    { 0, "Default value" },
    { 1, "Age of the last received Mode S track update is higher than system dependent threshold" },
    { 0, NULL }
};
static const value_string valstr_011_170_ADS[] = {
    { 0, "Default value" },
    { 1, "Age of the last received ADS-B track update is higher than system dependent threshold" },
    { 0, NULL }
};
static const value_string valstr_011_170_SUC[] = {
    { 0, "Default value" },
    { 1, "Special Used Code (Mode A codes to be defined in the system to mark a track with special interest)" },
    { 0, NULL }
};
static const value_string valstr_011_170_AAC[] = {
    { 0, "Default value" },
    { 1, "Assigned Mode A Code Conflict (same individual Mode A Code assigned to another track)" },
    { 0, NULL }
};
static const FieldPart I011_170_MON = { 1, 1.0, FIELD_PART_UINT, &hf_011_170_MON, NULL };
static const FieldPart I011_170_GBS = { 1, 1.0, FIELD_PART_UINT, &hf_011_170_GBS, NULL };
static const FieldPart I011_170_MRH = { 1, 1.0, FIELD_PART_UINT, &hf_011_170_MRH, NULL };
static const FieldPart I011_170_SRC = { 3, 1.0, FIELD_PART_UINT, &hf_011_170_SRC, NULL };
static const FieldPart I011_170_CNF = { 1, 1.0, FIELD_PART_UINT, &hf_011_170_CNF, NULL };
static const FieldPart I011_170_SIM = { 1, 1.0, FIELD_PART_UINT, &hf_011_170_SIM, NULL };
static const FieldPart I011_170_TSE = { 1, 1.0, FIELD_PART_UINT, &hf_011_170_TSE, NULL };
static const FieldPart I011_170_TSB = { 1, 1.0, FIELD_PART_UINT, &hf_011_170_TSB, NULL };
static const FieldPart I011_170_FRIFOE = { 2, 1.0, FIELD_PART_UINT, &hf_011_170_FRIFOE, NULL };
static const FieldPart I011_170_ME = { 1, 1.0, FIELD_PART_UINT, &hf_011_170_ME, NULL };
static const FieldPart I011_170_MI = { 1, 1.0, FIELD_PART_UINT, &hf_011_170_MI, NULL };
static const FieldPart I011_170_AMA = { 1, 1.0, FIELD_PART_UINT, &hf_011_170_AMA, NULL };
static const FieldPart I011_170_SPI = { 1, 1.0, FIELD_PART_UINT, &hf_011_170_SPI, NULL };
static const FieldPart I011_170_CST = { 1, 1.0, FIELD_PART_UINT, &hf_011_170_CST, NULL };
static const FieldPart I011_170_FPC = { 1, 1.0, FIELD_PART_UINT, &hf_011_170_FPC, NULL };
static const FieldPart I011_170_AFF = { 1, 1.0, FIELD_PART_UINT, &hf_011_170_AFF, NULL };
static const FieldPart I011_170_PSR = { 1, 1.0, FIELD_PART_UINT, &hf_011_170_PSR, NULL };
static const FieldPart I011_170_SSR = { 1, 1.0, FIELD_PART_UINT, &hf_011_170_SSR, NULL };
static const FieldPart I011_170_MDS = { 1, 1.0, FIELD_PART_UINT, &hf_011_170_MDS, NULL };
static const FieldPart I011_170_ADS = { 1, 1.0, FIELD_PART_UINT, &hf_011_170_ADS, NULL };
static const FieldPart I011_170_SUC = { 1, 1.0, FIELD_PART_UINT, &hf_011_170_SUC, NULL };
static const FieldPart I011_170_AAC = { 1, 1.0, FIELD_PART_UINT, &hf_011_170_AAC, NULL };

static const FieldPart *I011_170_PARTS[] = { &I011_170_MON, &I011_170_GBS, &I011_170_MRH, &I011_170_SRC, &I011_170_CNF, &IXXX_FX,
                                             &I011_170_SIM, &I011_170_TSE, &I011_170_TSB, &I011_170_FRIFOE, &I011_170_ME, &I011_170_MI, &IXXX_FX,
                                             &I011_170_AMA, &I011_170_SPI, &I011_170_CST, &I011_170_FPC, &I011_170_AFF, &IXXX_2bit_spare, &IXXX_FX,
                                             &IXXX_1bit_spare, &I011_170_PSR, &I011_170_SSR, &I011_170_MDS, &I011_170_ADS, &I011_170_SUC, &I011_170_AAC, &IXXX_FX,
                                             NULL };

/* Calculated Track Velocity in Cartesian Co-ordinates */
static const FieldPart I011_202_VX = { 16, 0.25, FIELD_PART_FLOAT, &hf_011_202_VX, NULL };
static const FieldPart I011_202_VY = { 16, 0.25, FIELD_PART_FLOAT, &hf_011_202_VY, NULL };
static const FieldPart *I011_202_PARTS[] = { &I011_202_VX, &I011_202_VY, NULL };

/* Calculated Acceleration */
static const FieldPart I011_210_AX = { 8, 0.25, FIELD_PART_FLOAT, &hf_011_210_AX, NULL };
static const FieldPart I011_210_AY = { 8, 0.25, FIELD_PART_FLOAT, &hf_011_210_AY, NULL };
static const FieldPart *I011_210_PARTS[] = { &I011_210_AX, &I011_210_AY, NULL };

/* Calculated Rate Of Climb/Descent */
static const FieldPart I011_215_ROCD = { 16, 6.25, FIELD_PART_FLOAT, &hf_011_215_ROCD, NULL };
static const FieldPart *I011_215_PARTS[] = { &I011_215_ROCD, NULL };

/* Target Identification */
static const value_string valstr_011_245_STI[] = {
    { 0, "Callsign or registration not downlinked from transponder" },
    { 1, "Callsign downlinked from transponder" },
    { 2, "Registration downlinked from transponder" },
    { 0, NULL }
};
static const FieldPart I011_245_STI = { 2, 1.0, FIELD_PART_UINT, &hf_011_245_STI, NULL };
static const FieldPart *I011_245_PARTS[] = { &I011_245_STI, &IXXX_6bit_spare, &IXXX_AI, NULL };

/* Target Size & Orientation */
static const FieldPart I011_270_LENGTH = { 7, 1.0, FIELD_PART_UFLOAT, &hf_011_270_LENGTH, NULL };
static const FieldPart I011_270_ORIENTATION = { 7, 360.0/128.0, FIELD_PART_UFLOAT, &hf_011_270_ORIENTATION, NULL };
static const FieldPart I011_270_WIDTH = { 7, 1.0, FIELD_PART_UFLOAT, &hf_011_270_WIDTH, NULL };
static const FieldPart *I011_270_PARTS[] = { &I011_270_LENGTH, &IXXX_FX,
                                             &I011_270_ORIENTATION, &IXXX_FX,
                                             &I011_270_WIDTH, &IXXX_FX,
                                             NULL };

/* System Track Update Ages */
static const FieldPart I011_290_01_PSR = { 8, 1.0/4.0, FIELD_PART_UFLOAT, &hf_011_290_01_PSR, NULL };
static const FieldPart *I011_290_01_PARTS[] = { &I011_290_01_PSR, NULL };
static const FieldPart I011_290_02_SSR = { 8, 1.0/4.0, FIELD_PART_UFLOAT, &hf_011_290_02_SSR, NULL };
static const FieldPart *I011_290_02_PARTS[] = { &I011_290_02_SSR, NULL };
static const FieldPart I011_290_03_MDA = { 8, 1.0/4.0, FIELD_PART_UFLOAT, &hf_011_290_03_MDA, NULL };
static const FieldPart *I011_290_03_PARTS[] = { &I011_290_03_MDA, NULL };
static const FieldPart I011_290_04_MFL = { 8, 1.0/4.0, FIELD_PART_UFLOAT, &hf_011_290_04_MFL, NULL };
static const FieldPart *I011_290_04_PARTS[] = { &I011_290_04_MFL, NULL };
static const FieldPart I011_290_05_MDS = { 8, 1.0/4.0, FIELD_PART_UFLOAT, &hf_011_290_05_MDS, NULL };
static const FieldPart *I011_290_05_PARTS[] = { &I011_290_05_MDS, NULL };
static const FieldPart I011_290_06_ADS = { 16, 1.0/4.0, FIELD_PART_UFLOAT, &hf_011_290_06_ADS, NULL };
static const FieldPart *I011_290_06_PARTS[] = { &I011_290_06_ADS, NULL };
static const FieldPart I011_290_07_ADB = { 8, 1.0/4.0, FIELD_PART_UFLOAT, &hf_011_290_07_ADB, NULL };
static const FieldPart *I011_290_07_PARTS[] = { &I011_290_07_ADB, NULL };
static const FieldPart I011_290_08_MD1 = { 8, 1.0/4.0, FIELD_PART_UFLOAT, &hf_011_290_08_MD1, NULL };
static const FieldPart *I011_290_08_PARTS[] = { &I011_290_08_MD1, NULL };
static const FieldPart I011_290_09_MD2 = { 8, 1.0/4.0, FIELD_PART_UFLOAT, &hf_011_290_09_MD2, NULL };
static const FieldPart *I011_290_09_PARTS[] = { &I011_290_09_MD2, NULL };
static const FieldPart I011_290_10_LOP = { 8, 1.0/4.0, FIELD_PART_UFLOAT, &hf_011_290_10_LOP, NULL };
static const FieldPart *I011_290_10_PARTS[] = { &I011_290_10_LOP, NULL };
static const FieldPart I011_290_11_TRK = { 8, 1.0/4.0, FIELD_PART_UFLOAT, &hf_011_290_11_TRK, NULL };
static const FieldPart *I011_290_11_PARTS[] = { &I011_290_11_TRK, NULL };
static const FieldPart I011_290_12_MUL = { 8, 1.0/4.0, FIELD_PART_UFLOAT, &hf_011_290_12_MUL, NULL };
static const FieldPart *I011_290_12_PARTS[] = { &I011_290_12_MUL, NULL };

/* Vehicle Fleet Identification */
static const value_string valstr_011_300_VFI[] = {
    {  0, "Flyco (follow me)" },
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
    { 16, "Unknown" },
    {  0, NULL }
};
static const FieldPart I011_300_VFI = { 8, 1.0, FIELD_PART_UINT, &hf_011_300_VFI, NULL };
static const FieldPart *I011_300_PARTS[] = { &I011_300_VFI, NULL };

/* Pre-programmed Message */
static const value_string valstr_011_310_TRB[] = {
    { 0, "Default" },
    { 1, "In Trouble" },
    { 0, NULL }
};
static const value_string valstr_011_310_MSG[] = {
    { 1, "Towing aircraft" },
    { 2, "\"Follow me\" operation" },
    { 3, "Runway check" },
    { 4, "Emergency operation (fire, medical...)" },
    { 5, "Work in progress (maintenance, birds scarer, sweepers...)" },
    { 0, NULL }
};
static const FieldPart I011_310_TRB = { 1, 1.0, FIELD_PART_UINT, &hf_011_310_TRB, NULL };
static const FieldPart I011_310_MSG = { 7, 1.0, FIELD_PART_UINT, &hf_011_310_MSG, NULL };
static const FieldPart *I011_310_PARTS[] = { &I011_310_TRB, &I011_310_MSG, NULL };

/* Mode-S / ADS-B Related Data */
/* MODE S MB DATA */
/* IXXX_MB */

/* Aircraft Address */
/* IXXX_AA */

/* Communications/ACAS Capability and Flight Status */
static const value_string valstr_011_380_04_COM[] = {
    { 0, "No communications capability (surveillance only)" },
    { 1, "Comm. A and Comm. B capability" },
    { 2, "Comm. A, Comm. B and Uplink ELM" },
    { 3, "Comm. A, Comm. B, Uplink ELM and Downlink ELM" },
    { 4, "Level 5 Transponder capability" },
    { 0, NULL }
};
static const value_string valstr_011_380_04_STAT[] = {
    { 0, "No alert, no SPI, aircraft airborne" },
    { 1, "No alert, no SPI, aircraft on ground" },
    { 2, "Alert, no SPI, aircraft airborne" },
    { 3, "Alert, no SPI, aircraft on ground" },
    { 4, "Alert, SPI, aircraft airborne or on ground" },
    { 5, "No alert, SPI, aircraft airborne or on ground" },
    { 6, "General Emergency" },
    { 7, "Lifeguard / medical" },
    { 8, "Minimum fuel" },
    { 9, "No communications" },
    { 10, "Unlawful interference" },
    { 0, NULL }
};
static const value_string valstr_011_380_04_SSC[] = {
    { 0, "No" },
    { 1, "Yes" },
    { 0, NULL }
};
static const value_string valstr_011_380_04_ARC[] = {
    { 0, "100 ft resolution" },
    { 1, "25 ft resolution" },
    { 0, NULL }
};
static const value_string valstr_011_380_04_AIC[] = {
    { 0, "No" },
    { 1, "Yes" },
    { 0, NULL }
};
static const value_string valstr_011_380_04_AC[] = {
    { 0, "No" },
    { 1, "Yes" },
    { 0, NULL }
};
static const value_string valstr_011_380_04_MN[] = {
    { 0, "No" },
    { 1, "Yes" },
    { 0, NULL }
};
static const value_string valstr_011_380_04_DC[] = {
    { 0, "Yes" },
    { 1, "No" },
    { 0, NULL }
};

static const FieldPart I011_380_04_COM = { 3, 1.0, FIELD_PART_UINT, &hf_011_380_04_COM, NULL };
static const FieldPart I011_380_04_STAT = { 4, 1.0, FIELD_PART_UINT, &hf_011_380_04_STAT, NULL };
static const FieldPart I011_380_04_SSC = { 1, 1.0, FIELD_PART_UINT, &hf_011_380_04_SSC, NULL };
static const FieldPart I011_380_04_ARC = { 1, 1.0, FIELD_PART_UINT, &hf_011_380_04_ARC, NULL };
static const FieldPart I011_380_04_AIC = { 1, 1.0, FIELD_PART_UINT, &hf_011_380_04_AIC, NULL };
static const FieldPart I011_380_04_B1A = { 1, 1.0, FIELD_PART_UINT, &hf_011_380_04_B1A, NULL };
static const FieldPart I011_380_04_B1B = { 4, 1.0, FIELD_PART_UINT, &hf_011_380_04_B1B, NULL };
static const FieldPart I011_380_04_AC = { 1, 1.0, FIELD_PART_UINT, &hf_011_380_04_AC, NULL };
static const FieldPart I011_380_04_MN = { 1, 1.0, FIELD_PART_UINT, &hf_011_380_04_MN, NULL };
static const FieldPart I011_380_04_DC = { 1, 1.0, FIELD_PART_UINT, &hf_011_380_04_DC, NULL };
static const FieldPart *I011_380_04_PARTS[] = { &I011_380_04_COM,
                                                &I011_380_04_STAT,
                                                &I011_380_04_SSC,
                                                &IXXX_1bit_spare,
                                                &I011_380_04_ARC,
                                                &I011_380_04_AIC,
                                                &I011_380_04_B1A,
                                                &I011_380_04_B1B,
                                                &I011_380_04_AC,
                                                &I011_380_04_MN,
                                                &I011_380_04_DC,
                                                &IXXX_5bit_spare,
                                                NULL };

/* Aircraft Derived Aircraft Type */
static const FieldPart I011_380_08_ADAT = { 32, 1.0, FIELD_PART_ASCII, &hf_011_380_08_ADAT, NULL };
static const FieldPart *I011_380_08_PARTS[] = { &I011_380_08_ADAT, NULL };

/* Emitter Category */
static const value_string valstr_011_380_09_ECAT[] = {
    { 1, "Light aircraft <= 7000 kg" },
    { 2, "Reserved" },
    { 3, "7000 kg < medium aircraft  < 136000 kg" },
    { 4, "Reserved" },
    { 5, "136000 kg <= heavy aircraft" },
    { 6, "Highly manoeuvrable (5g acceleration capability) and high speed (>400 knots cruise)" },
    { 7, "Reserved" },
    { 8, "Reserved" },
    { 9, "Reserved" },
    { 10, "Rotocraft" },
    { 11, "Glider / sailplane" },
    { 12, "Lighter-than-air" },
    { 13, "Unmanned aerial vehicle" },
    { 14, "Space / transatmospheric vehicle" },
    { 15, "Ultralight / handglider / paraglider" },
    { 16, "Parachutist / skydiver" },
    { 17, "Reserved" },
    { 18, "Reserved" },
    { 19, "Reserved" },
    { 20, "Surface emergency vehicle" },
    { 21, "Surface service vehicle" },
    { 22, "Fixed ground or tethered obstruction" },
    { 23, "Reserved" },
    { 24, "Reserved" },
    { 0, NULL }
};
static const FieldPart I011_380_09_ECAT = { 8, 1.0, FIELD_PART_UINT, &hf_011_380_09_ECAT, NULL };
static const FieldPart *I011_380_09_PARTS[] = { &I011_380_09_ECAT, NULL };

/* Available Technologies */
static const value_string valstr_011_380_11_VDL[] = {
    { 0, "VDL Mode 4 available" },
    { 1, "VDL Mode 4 not available" },
    { 0, NULL }
};
static const value_string valstr_011_380_11_MDS[] = {
    { 0, "Mode S available" },
    { 1, "Mode S not available" },
    { 0, NULL }
};
static const value_string valstr_011_380_11_UAT[] = {
    { 0, "UAT available" },
    { 1, "UAT not available" },
    { 0, NULL }
};
static const FieldPart I011_380_11_VDL = { 1, 1.0, FIELD_PART_UINT, &hf_011_380_11_VDL, NULL };
static const FieldPart I011_380_11_MDS = { 1, 1.0, FIELD_PART_UINT, &hf_011_380_11_MDS, NULL };
static const FieldPart I011_380_11_UAT = { 1, 1.0, FIELD_PART_UINT, &hf_011_380_11_UAT, NULL };
static const FieldPart *I011_380_11_PARTS[] = { &I011_380_11_VDL, &I011_380_11_MDS, &I011_380_11_UAT, NULL };

/* Flight Plan Related Data */
/* FFPS Identification Tag */
/* IXXX_SAC_SIC */

/* Callsign */
static const FieldPart I011_390_02_CSN = { 56, 1.0, FIELD_PART_ASCII, &hf_011_390_02_CSN, NULL };
static const FieldPart *I011_390_02_PARTS[] = { &I011_390_02_CSN, NULL };

/* IFPS_FLIGHT_ID */
static const value_string valstr_011_390_03_TYP[] = {
    { 0, "Plan Number" },
    { 1, "Unit 1 internal flight number" },
    { 2, "Unit 2 internal flight number" },
    { 3, "Unit 3 internal flight number" },
    { 0, NULL }
};
static const FieldPart I011_390_03_TYP = { 2, 1.0, FIELD_PART_UINT, &hf_011_390_03_TYP, NULL };
static const FieldPart I011_390_03_NBR = { 27, 1.0, FIELD_PART_UINT, &hf_011_390_03_NBR, NULL };
static const FieldPart *I011_390_03_PARTS[] = { &I011_390_03_TYP, &IXXX_3bit_spare, &I011_390_03_NBR, NULL };

/* Flight Category */
static const value_string valstr_011_390_04_GAT_OAT[] = {
    { 0, "Unknown" },
    { 1, "General Air Traffic" },
    { 2, "Operational Air Traffic" },
    { 3, "Not applicable" },
    { 0, NULL }
};
static const value_string valstr_011_390_04_FR12[] = {
    { 0, "Instrument Flight Rules" },
    { 1, "Visual Flight Rules" },
    { 2, "Not applicable" },
    { 3, "Controlled Visual Flight Rules" },
    { 0, NULL }
};
static const value_string valstr_011_390_04_RVSM[] = {
    { 0, "Unknown" },
    { 1, "Approved" },
    { 2, "Exempt" },
    { 3, "Not Approved" },
    { 0, NULL }
};
static const value_string valstr_011_390_04_HPR[] = {
    { 0, "Normal Priority Flight" },
    { 1, "High Priority Flight" },
    { 0, NULL }
};
static const FieldPart I011_390_04_GAT_OAT = { 2, 1.0, FIELD_PART_UINT, &hf_011_390_04_GAT_OAT, NULL };
static const FieldPart I011_390_04_FR12 = { 2, 1.0, FIELD_PART_UINT, &hf_011_390_04_FR12, NULL };
static const FieldPart I011_390_04_RVSM = { 2, 1.0, FIELD_PART_UINT, &hf_011_390_04_RVSM, NULL };
static const FieldPart I011_390_04_HPR = { 1, 1.0, FIELD_PART_UINT, &hf_011_390_04_HPR, NULL };
static const FieldPart *I011_390_04_PARTS[] = { &I011_390_04_GAT_OAT, &I011_390_04_FR12, &I011_390_04_RVSM, &I011_390_04_HPR, &IXXX_1bit_spare, NULL };

/* Type of Aircraft */
static const FieldPart I011_390_05_ACTYP = { 32, 1.0, FIELD_PART_ASCII, &hf_011_390_05_ACTYP, NULL };
static const FieldPart *I011_390_05_PARTS[] = { &I011_390_05_ACTYP, NULL };

/* Wake Turbulence Category */
static const FieldPart I011_390_06_WTC = { 8, 1.0, FIELD_PART_ASCII, &hf_011_390_06_WTC, NULL };
static const FieldPart *I011_390_06_PARTS[] = { &I011_390_06_WTC, NULL };

/* Departure Airport */
static const FieldPart I011_390_07_ADEP = { 32, 1.0, FIELD_PART_ASCII, &hf_011_390_07_ADEP, NULL };
static const FieldPart *I011_390_07_PARTS[] = { &I011_390_07_ADEP, NULL };

/* Destination Airport */
static const FieldPart I011_390_08_ADES = { 32, 1.0, FIELD_PART_ASCII, &hf_011_390_08_ADES, NULL };
static const FieldPart *I011_390_08_PARTS[] = { &I011_390_08_ADES, NULL };

/* Runway Designation */
static const FieldPart I011_390_09_RWY = { 24, 1.0, FIELD_PART_ASCII, &hf_011_390_09_RWY, NULL };
static const FieldPart *I011_390_09_PARTS[] = { &I011_390_09_RWY, NULL };

/* Current Cleared Flight Level */
static const FieldPart I011_390_10_CFL = { 16, 1.0/4.0, FIELD_PART_UFLOAT, &hf_011_390_10_CFL, NULL };
static const FieldPart *I011_390_10_PARTS[] = { &I011_390_10_CFL, NULL };

/* Current Control Position */
static const FieldPart I011_390_11_CNTR = { 8, 1.0, FIELD_PART_UINT, &hf_011_390_11_CNTR, NULL };
static const FieldPart I011_390_11_POS = { 8, 1.0, FIELD_PART_UINT, &hf_011_390_11_POS, NULL };
static const FieldPart *I011_390_11_PARTS[] = { &I011_390_11_CNTR, &I011_390_11_POS, NULL };

/* Time of Departure */
static const value_string valstr_011_390_12_TYP[] = {
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
static const value_string valstr_011_390_12_DAY[] = {
    { 00, "Today" },
    { 01, "Yesterday" },
    { 10, "Tomorrow" },
    { 0, NULL }
};
static const value_string valstr_011_390_12_AVS[] = {
    { 0, "Seconds available" },
    { 1, "Seconds not available" },
    { 0, NULL }
};
static const FieldPart I011_390_12_TYP = { 5, 1.0, FIELD_PART_UINT, &hf_011_390_12_TYP, NULL };
static const FieldPart I011_390_12_DAY = { 2, 1.0, FIELD_PART_UINT, &hf_011_390_12_DAY, NULL };
static const FieldPart I011_390_12_HOR = { 5, 1.0, FIELD_PART_UINT, &hf_011_390_12_HOR, NULL };
static const FieldPart I011_390_12_MIN = { 6, 1.0, FIELD_PART_UINT, &hf_011_390_12_MIN, NULL };
static const FieldPart I011_390_12_AVS = { 1, 1.0, FIELD_PART_UINT, &hf_011_390_12_AVS, NULL };
static const FieldPart I011_390_12_SEC = { 6, 1.0, FIELD_PART_UINT, &hf_011_390_12_SEC, NULL };
static const FieldPart *I011_390_12_PARTS[] = { &I011_390_12_TYP, &I011_390_12_DAY, &IXXX_1bit_spare,
                                                &IXXX_3bit_spare, &I011_390_12_HOR,
                                                &IXXX_2bit_spare, &I011_390_12_MIN,
                                                &I011_390_12_AVS, &IXXX_1bit_spare, &I011_390_12_SEC, NULL };

/* Aircraft Stand */
static const FieldPart I011_390_13_STAND = { 48, 1.0, FIELD_PART_ASCII, &hf_011_390_13_STAND, NULL };
static const FieldPart *I011_390_13_PARTS[] = { &I011_390_13_STAND, NULL };

/* Stand Status */
static const value_string valstr_011_390_14_EMP[] = {
    { 0, "Empty" },
    { 1, "Occupied" },
    { 2, "Unknown" },
    { 0, NULL }
};
static const value_string valstr_011_390_14_AVL[] = {
    { 0, "Available" },
    { 1, "Not available" },
    { 2, "Unknown" },
    { 0, NULL }
};
static const FieldPart I011_390_14_EMP = { 2, 1.0, FIELD_PART_UINT, &hf_011_390_14_EMP, NULL };
static const FieldPart I011_390_14_AVL = { 2, 1.0, FIELD_PART_UINT, &hf_011_390_14_AVL, NULL };
static const FieldPart *I011_390_14_PARTS[] = { &I011_390_14_EMP, &I011_390_14_AVL, &IXXX_4bit_spare, NULL };

/* Phase of Flight */
static const value_string valstr_011_430_FLS[] = {
    { 0, "Unknown" },
    { 1, "On Stand" },
    { 2, "Taxiing for Departure" },
    { 3, "Taxiing for Arrival" },
    { 4, "Ruwnay for Departure" },
    { 5, "Runway for Arrival" },
    { 6, "Hold for Departure" },
    { 7, "Hold for arrival" },
    { 8, "Push Back" },
    { 9, "On Finals" },
    { 0, NULL }
};
static const FieldPart I011_430_FLS = { 8, 1.0, FIELD_PART_UINT, &hf_011_430_FLS, NULL };
static const FieldPart *I011_430_PARTS[] = { &I011_430_FLS, NULL };

/* Estimated Accuracies */
/* Estimated Accuracy Of Track Position (Cartesian) */
static const FieldPart I011_500_01_APCX = { 8, 0.25, FIELD_PART_UFLOAT, &hf_011_500_01_APCX, NULL };
static const FieldPart I011_500_01_APCY = { 8, 0.25, FIELD_PART_UFLOAT, &hf_011_500_01_APCY, NULL };
static const FieldPart *I011_500_01_PARTS[] = { &I011_500_01_APCX, &I011_500_01_APCY, NULL };

/* Estimated Accuracy Of Track Position (WGS-84) */
static const FieldPart I011_500_02_APWLAT = { 16, 180.0/2147483648.0, FIELD_PART_FLOAT, &hf_011_500_02_APWLAT, NULL };
static const FieldPart I011_500_02_APWLON = { 16, 180.0/2147483648.0, FIELD_PART_FLOAT, &hf_011_500_02_APWLON, NULL };
static const FieldPart *I011_500_02_PARTS[] = { &I011_500_02_APWLAT, &I011_500_02_APWLON, NULL };

/* Estimated Accuracy Of Height */
static const FieldPart I011_500_03_ATA = { 16, 0.5, FIELD_PART_UFLOAT, &hf_011_500_03_ATA, NULL };
static const FieldPart *I011_500_03_PARTS[] = { &I011_500_03_ATA, NULL };

/* Estimated Accuracy Of Track Velocity (Cartesian) */
static const FieldPart I011_500_04_AVCX = { 8, 0.1, FIELD_PART_UFLOAT, &hf_011_500_04_AVCX, NULL };
static const FieldPart I011_500_04_AVCY = { 8, 0.1, FIELD_PART_UFLOAT, &hf_011_500_04_AVCY, NULL };
static const FieldPart *I011_500_04_PARTS[] = { &I011_500_04_AVCX, &I011_500_04_AVCY, NULL };

/* Estimated Accuracy Of Rate Of Climb/Descent */
static const FieldPart I011_500_05_ARC = { 8, 0.1, FIELD_PART_UFLOAT, &hf_011_500_05_ARC, NULL };
static const FieldPart *I011_500_05_PARTS[] = { &I011_500_05_ARC, NULL };

/* Estimated Accuracy Of Acceleration (Cartesian) */
static const FieldPart I011_500_06_AAX = { 8, 0.01, FIELD_PART_UFLOAT, &hf_011_500_06_AACX, NULL };
static const FieldPart I011_500_06_AAY = { 8, 0.01, FIELD_PART_UFLOAT, &hf_011_500_06_AACY, NULL };
static const FieldPart *I011_500_06_PARTS[] = { &I011_500_06_AAX, &I011_500_06_AAY, NULL };

/* Alert Messages */
static const value_string valstr_011_600_ACK[] = {
    { 0, "Alert acknowledged" },
    { 1, "Alert not acknowledged" },
    { 0, NULL }
};
static const value_string valstr_011_600_SVR[] = {
    { 0, "End of alert" },
    { 1, "Pre-alarm" },
    { 2, "Severe alert" },
    { 0, NULL }
};
static const FieldPart I011_600_ACK = { 1, 1.0, FIELD_PART_UINT, &hf_011_600_ACK, NULL };
static const FieldPart I011_600_SVR = { 2, 1.0, FIELD_PART_UINT, &hf_011_600_SVR, NULL };
static const FieldPart I011_600_ALT = { 8, 1.0, FIELD_PART_UINT, &hf_011_600_ALT, NULL };
static const FieldPart I011_600_ALN = { 8, 1.0, FIELD_PART_UINT, &hf_011_600_ALN, NULL };
static const FieldPart *I011_600_PARTS[] = { &I011_600_ACK, &I011_600_SVR, &IXXX_5bit_spare, &I011_600_ALT, &I011_600_ALN, NULL };

/* Tracks in Alert */
static const FieldPart I011_605_FTN = { 12, 1.0, FIELD_PART_UINT, &hf_011_605_FTN, NULL };
static const FieldPart *I011_605_PARTS[] = { &IXXX_4bit_spare, &I011_605_FTN, NULL };

/* Holdbar Status */
static const value_string valstr_011_610_I01[] = {
    { 0, "Indicator 1 off" },
    { 1, "Indicator 1 on" },
    { 0, NULL }
};
static const value_string valstr_011_610_I02[] = {
    { 0, "Indicator 2 off" },
    { 1, "Indicator 2 on" },
    { 0, NULL }
};
static const value_string valstr_011_610_I03[] = {
    { 0, "Indicator 3 off" },
    { 1, "Indicator 3 on" },
    { 0, NULL }
};
static const value_string valstr_011_610_I04[] = {
    { 0, "Indicator 4 off" },
    { 1, "Indicator 4 on" },
    { 0, NULL }
};
static const value_string valstr_011_610_I05[] = {
    { 0, "Indicator 5 off" },
    { 1, "Indicator 5 on" },
    { 0, NULL }
};
static const value_string valstr_011_610_I06[] = {
    { 0, "Indicator 6 off" },
    { 1, "Indicator 6 on" },
    { 0, NULL }
};
static const value_string valstr_011_610_I07[] = {
    { 0, "Indicator 7 off" },
    { 1, "Indicator 7 on" },
    { 0, NULL }
};
static const value_string valstr_011_610_I08[] = {
    { 0, "Indicator 8 off" },
    { 1, "Indicator 8 on" },
    { 0, NULL }
};
static const value_string valstr_011_610_I09[] = {
    { 0, "Indicator 9 off" },
    { 1, "Indicator 9 on" },
    { 0, NULL }
};
static const value_string valstr_011_610_I10[] = {
    { 0, "Indicator 10 off" },
    { 1, "Indicator 10 on" },
    { 0, NULL }
};
static const value_string valstr_011_610_I11[] = {
    { 0, "Indicator 11 off" },
    { 1, "Indicator 11 on" },
    { 0, NULL }
};
static const value_string valstr_011_610_I12[] = {
    { 0, "Indicator 12 off" },
    { 1, "Indicator 12 on" },
    { 0, NULL }
};
static const FieldPart I011_610_BKN = { 4, 1.0, FIELD_PART_UINT, &hf_011_610_BKN, NULL };
static const FieldPart I011_610_I01 = { 1, 1.0, FIELD_PART_UINT, &hf_011_610_I01, NULL };
static const FieldPart I011_610_I02 = { 1, 1.0, FIELD_PART_UINT, &hf_011_610_I02, NULL };
static const FieldPart I011_610_I03 = { 1, 1.0, FIELD_PART_UINT, &hf_011_610_I03, NULL };
static const FieldPart I011_610_I04 = { 1, 1.0, FIELD_PART_UINT, &hf_011_610_I04, NULL };
static const FieldPart I011_610_I05 = { 1, 1.0, FIELD_PART_UINT, &hf_011_610_I05, NULL };
static const FieldPart I011_610_I06 = { 1, 1.0, FIELD_PART_UINT, &hf_011_610_I06, NULL };
static const FieldPart I011_610_I07 = { 1, 1.0, FIELD_PART_UINT, &hf_011_610_I07, NULL };
static const FieldPart I011_610_I08 = { 1, 1.0, FIELD_PART_UINT, &hf_011_610_I08, NULL };
static const FieldPart I011_610_I09 = { 1, 1.0, FIELD_PART_UINT, &hf_011_610_I09, NULL };
static const FieldPart I011_610_I10 = { 1, 1.0, FIELD_PART_UINT, &hf_011_610_I10, NULL };
static const FieldPart I011_610_I11 = { 1, 1.0, FIELD_PART_UINT, &hf_011_610_I11, NULL };
static const FieldPart I011_610_I12 = { 1, 1.0, FIELD_PART_UINT, &hf_011_610_I12, NULL };
static const FieldPart *I011_610_PARTS[] = { &I011_610_BKN, &I011_610_I01, &I011_610_I02, &I011_610_I03, &I011_610_I04, &I011_610_I05,
                                             &I011_610_I06, &I011_610_I07, &I011_610_I08, &I011_610_I09, &I011_610_I10, &I011_610_I11, &I011_610_I12,
                                             NULL };

/* Items */
DIAG_OFF(pedantic)
static const AsterixField I011_000 = { FIXED, 1, 0, 0, &hf_011_000, I011_000_PARTS, { NULL } };
static const AsterixField I011_010 = { FIXED, 2, 0, 0, &hf_011_010, IXXX_SAC_SIC, { NULL } };
static const AsterixField I011_015 = { FIXED, 1, 0, 0, &hf_011_015, I011_015_PARTS, { NULL } };
static const AsterixField I011_041 = { FIXED, 8, 0, 0, &hf_011_041, I011_041_PARTS, { NULL } };
static const AsterixField I011_042 = { FIXED, 4, 0, 0, &hf_011_042, I011_042_PARTS, { NULL } };
static const AsterixField I011_060 = { FIXED, 2, 0, 0, &hf_011_060, I011_060_PARTS, { NULL } };
static const AsterixField I011_090 = { FIXED, 2, 0, 0, &hf_011_090, I011_090_PARTS, { NULL } };
static const AsterixField I011_092 = { FIXED, 2, 0, 0, &hf_011_092, I011_092_PARTS, { NULL } };
static const AsterixField I011_093 = { FIXED, 2, 0, 0, &hf_011_093, I011_093_PARTS, { NULL } };
static const AsterixField I011_140 = { FIXED, 3, 0, 0, &hf_011_140, IXXX_TOD, { NULL } };
static const AsterixField I011_161 = { FIXED, 2, 0, 0, &hf_011_161, I011_161_PARTS, { NULL } };
static const AsterixField I011_170 = { FX, 1, 0, 0, &hf_011_170, I011_170_PARTS, { NULL } };
static const AsterixField I011_202 = { FIXED, 4, 0, 0, &hf_011_202, I011_202_PARTS, { NULL } };
static const AsterixField I011_210 = { FIXED, 2, 0, 0, &hf_011_210, I011_210_PARTS, { NULL } };
static const AsterixField I011_215 = { FIXED, 2, 0, 0, &hf_011_215, I011_215_PARTS, { NULL } };
static const AsterixField I011_245 = { FIXED, 7, 0, 0, &hf_011_245, I011_245_PARTS, { NULL } };
static const AsterixField I011_270 = { FX, 1, 0, 0, &hf_011_270, I011_270_PARTS, { NULL } };
static const AsterixField I011_290_01 = { FIXED, 1, 0, 0, &hf_011_290_01, I011_290_01_PARTS, { NULL } };
static const AsterixField I011_290_02 = { FIXED, 1, 0, 0, &hf_011_290_02, I011_290_02_PARTS, { NULL } };
static const AsterixField I011_290_03 = { FIXED, 1, 0, 0, &hf_011_290_03, I011_290_03_PARTS, { NULL } };
static const AsterixField I011_290_04 = { FIXED, 1, 0, 0, &hf_011_290_04, I011_290_04_PARTS, { NULL } };
static const AsterixField I011_290_05 = { FIXED, 1, 0, 0, &hf_011_290_05, I011_290_05_PARTS, { NULL } };
static const AsterixField I011_290_06 = { FIXED, 2, 0, 0, &hf_011_290_06, I011_290_06_PARTS, { NULL } };
static const AsterixField I011_290_07 = { FIXED, 1, 0, 0, &hf_011_290_07, I011_290_07_PARTS, { NULL } };
static const AsterixField I011_290_08 = { FIXED, 1, 0, 0, &hf_011_290_08, I011_290_08_PARTS, { NULL } };
static const AsterixField I011_290_09 = { FIXED, 1, 0, 0, &hf_011_290_09, I011_290_09_PARTS, { NULL } };
static const AsterixField I011_290_10 = { FIXED, 1, 0, 0, &hf_011_290_10, I011_290_10_PARTS, { NULL } };
static const AsterixField I011_290_11 = { FIXED, 1, 0, 0, &hf_011_290_11, I011_290_11_PARTS, { NULL } };
static const AsterixField I011_290_12 = { FIXED, 1, 0, 0, &hf_011_290_12, I011_290_12_PARTS, { NULL } };
static const AsterixField I011_290 = { COMPOUND, 0, 0, 0, &hf_011_290, NULL, { &I011_290_01,
                                                                               &I011_290_02,
                                                                               &I011_290_03,
                                                                               &I011_290_04,
                                                                               &I011_290_05,
                                                                               &I011_290_06,
                                                                               &I011_290_07,
                                                                               &I011_290_08,
                                                                               &I011_290_09,
                                                                               &I011_290_10,
                                                                               &I011_290_11,
                                                                               &I011_290_12,
                                                                               &IX_SPARE,
                                                                               &IX_SPARE,
                                                                               NULL } };
static const AsterixField I011_300 = { FIXED, 1, 0, 0, &hf_011_300, I011_300_PARTS, { NULL } };
static const AsterixField I011_310 = { FIXED, 1, 0, 0, &hf_011_310, I011_310_PARTS, { NULL } };
static const AsterixField I011_380_01 = { REPETITIVE, 8, 1, 0, &hf_011_380_01, IXXX_MB, { NULL } };
static const AsterixField I011_380_02 = { FIXED, 3, 0, 0, &hf_011_380_02, IXXX_AA_PARTS, { NULL } };
/* #3 Never Sent */
static const AsterixField I011_380_04 = { FIXED, 3, 0, 0, &hf_011_380_04, I011_380_04_PARTS, { NULL } };
/* #5 to #7 Never Sent */
static const AsterixField I011_380_08 = { FIXED, 4, 0, 0, &hf_011_380_08, I011_380_08_PARTS, { NULL } };
static const AsterixField I011_380_09 = { FIXED, 1, 0, 0, &hf_011_380_09, I011_380_09_PARTS, { NULL } };
/* #10 Never Sent */
static const AsterixField I011_380_11 = { FIXED, 1, 0, 0, &hf_011_380_11, I011_380_11_PARTS, { NULL } };
static const AsterixField I011_380 = { COMPOUND, 0, 0, 0, &hf_011_380, NULL, { &I011_380_01,
                                                                               &I011_380_02,
                                                                               &IX_SPARE,
                                                                               &I011_380_04,
                                                                               &IX_SPARE,
                                                                               &IX_SPARE,
                                                                               &IX_SPARE,
                                                                               &I011_380_08,
                                                                               &I011_380_09,
                                                                               &IX_SPARE,
                                                                               &I011_380_11,
                                                                               NULL } };
static const AsterixField I011_390_01 = { FIXED, 2, 0, 0, &hf_011_390_01, IXXX_SAC_SIC, { NULL } };
static const AsterixField I011_390_02 = { FIXED, 7, 0, 0, &hf_011_390_02, I011_390_02_PARTS, { NULL } };
static const AsterixField I011_390_03 = { FIXED, 4, 0, 0, &hf_011_390_03, I011_390_03_PARTS, { NULL } };
static const AsterixField I011_390_04 = { FIXED, 1, 0, 0, &hf_011_390_04, I011_390_04_PARTS, { NULL } };
static const AsterixField I011_390_05 = { FIXED, 4, 0, 0, &hf_011_390_05, I011_390_05_PARTS, { NULL } };
static const AsterixField I011_390_06 = { FIXED, 1, 0, 0, &hf_011_390_06, I011_390_06_PARTS, { NULL } };
static const AsterixField I011_390_07 = { FIXED, 4, 0, 0, &hf_011_390_07, I011_390_07_PARTS, { NULL } };
static const AsterixField I011_390_08 = { FIXED, 4, 0, 0, &hf_011_390_08, I011_390_08_PARTS, { NULL } };
static const AsterixField I011_390_09 = { FIXED, 3, 0, 0, &hf_011_390_09, I011_390_09_PARTS, { NULL } };
static const AsterixField I011_390_10 = { FIXED, 2, 0, 0, &hf_011_390_10, I011_390_10_PARTS, { NULL } };
static const AsterixField I011_390_11 = { FIXED, 2, 0, 0, &hf_011_390_11, I011_390_11_PARTS, { NULL } };
static const AsterixField I011_390_12 = { REPETITIVE, 4, 1, 0, &hf_011_390_12, I011_390_12_PARTS, { NULL } };
static const AsterixField I011_390_13 = { FIXED, 6, 0, 0, &hf_011_390_13, I011_390_13_PARTS, { NULL } };
static const AsterixField I011_390_14 = { FIXED, 1, 0, 0, &hf_011_390_14, I011_390_14_PARTS, { NULL } };
static const AsterixField I011_390 = { COMPOUND, 0, 0, 0, &hf_011_390, NULL, { &I011_390_01,
                                                                               &I011_390_02,
                                                                               &I011_390_03,
                                                                               &I011_390_04,
                                                                               &I011_390_05,
                                                                               &I011_390_06,
                                                                               &I011_390_07,
                                                                               &I011_390_08,
                                                                               &I011_390_09,
                                                                               &I011_390_10,
                                                                               &I011_390_11,
                                                                               &I011_390_12,
                                                                               &I011_390_13,
                                                                               &I011_390_14,
                                                                               NULL } };
static const AsterixField I011_430 = { FIXED, 1, 0, 0, &hf_011_430, I011_430_PARTS, { NULL } };
static const AsterixField I011_500_01 = { FIXED, 2, 0, 0, &hf_011_500_01, I011_500_01_PARTS, { NULL } };
static const AsterixField I011_500_02 = { FIXED, 4, 0, 0, &hf_011_500_02, I011_500_02_PARTS, { NULL } };
static const AsterixField I011_500_03 = { FIXED, 2, 0, 0, &hf_011_500_03, I011_500_03_PARTS, { NULL } };
static const AsterixField I011_500_04 = { FIXED, 2, 0, 0, &hf_011_500_04, I011_500_04_PARTS, { NULL } };
static const AsterixField I011_500_05 = { FIXED, 1, 0, 0, &hf_011_500_05, I011_500_05_PARTS, { NULL } };
static const AsterixField I011_500_06 = { FIXED, 2, 0, 0, &hf_011_500_06, I011_500_06_PARTS, { NULL } };
static const AsterixField I011_500 = { COMPOUND, 0, 0, 0, &hf_011_500, NULL, { &I011_500_01,
                                                                               &I011_500_02,
                                                                               &I011_500_03,
                                                                               &I011_500_04,
                                                                               &I011_500_05,
                                                                               &I011_500_06,
                                                                               NULL } };
static const AsterixField I011_600 = { FIXED, 3, 0, 0, &hf_011_600, I011_600_PARTS, { NULL } };
static const AsterixField I011_605 = { REPETITIVE, 2, 1, 0, &hf_011_605, I011_605_PARTS, { NULL } };
static const AsterixField I011_610 = { REPETITIVE, 2, 1, 0, &hf_011_610, I011_610_PARTS, { NULL } };
static const AsterixField I011_SP = { SP, 0, 0, 1, &hf_011_SP, NULL, { NULL } };
static const AsterixField I011_RE = { RE, 0, 0, 1, &hf_011_RE, NULL, { NULL } };

static const AsterixField *I011_v1_2_uap[] = { &I011_010, &I011_000, &I011_015, &I011_140, &I011_041, &I011_042, &I011_202,
                                               &I011_210, &I011_060, &I011_245, &I011_380, &I011_161, &I011_170, &I011_290,
                                               &I011_430, &I011_090, &I011_093, &I011_092, &I011_215, &I011_270, &I011_390,
                                               &I011_300, &I011_310, &I011_500, &I011_600, &I011_605, &I011_610, &I011_SP,
                                               &I011_RE, &IX_SPARE, &IX_SPARE, &IX_SPARE, &IX_SPARE, &IX_SPARE, &IX_SPARE,
                                               NULL };

static const AsterixField **I011_v1_2[] = { I011_v1_2_uap, NULL };
static const AsterixField ***I011[] = { I011_v1_2 };
DIAG_ON(pedantic)

static const enum_val_t I011_versions[] = {
    { "I011_v1_2", "Version 1.20", 0 },
    { NULL, NULL, 0 }
};

/* *********************** */
/*      Category 019       */
/* *********************** */

/*
 * Online specification:
 * https://www.eurocontrol.int/publications/cat019-multilateration-system-status-messages-part-18
 */

/* Fields */

/* Message Type */
static const value_string valstr_019_000_MT[] = {
    { 1, "Start of Update Cycle" },
    { 2, "Periodic Status Message" },
    { 3, "Event Status Message" },
    { 0, NULL }
};

/* System Status */
static const value_string valstr_019_550_NOGO[] = {
    { 0, "Operational" },
    { 1, "Degraded" },
    { 2, "NOGO" },
    { 3, "Undefined" },
    { 0, NULL }
};

static const value_string valstr_019_550_OVL[] = {
    { 0, "No overload" },
    { 1, "Overload" },
    { 0, NULL }
};

static const value_string valstr_019_550_TSV[] = {
    { 0, "Valid" },
    { 1, "Invalid" },
    { 0, NULL }
};

static const value_string valstr_019_550_TTF[] = {
    { 0, "Test Target Operative" },
    { 1, "Test Target Failure" },
    { 0, NULL }
};

/* Tracking Processor Detailed Status */
static const value_string valstr_019_551_TPX_EXEC[] = {
    { 0, "Standby" },
    { 1, "Exec" },
    { 0, NULL }
};

static const value_string valstr_019_551_TPX_GOOD[] = {
    { 0, "Faulted" },
    { 1, "Good" },
    { 0, NULL }
};

/* Remote Sensor Detailed Status */
static const value_string valstr_019_552_present[] = {
    { 0, "Absent" },
    { 1, "Present" },
    { 0, NULL }
};

static const value_string valstr_019_552_RS_Status[] = {
    { 0, "Faulted" },
    { 1, "Good" },
    { 0, NULL }
};

static const value_string valstr_019_552_RS_Operational[] = {
    { 0, "Offline" },
    { 1, "Online" },
    { 0, NULL }
};

/* Reference Transponder Detailed Status */
static const value_string valstr_019_553_Ref_Trans_Status[] = {
    { 0, "Not present" },
    { 1, "Warning" },
    { 2, "Faulted" },
    { 3, "Good" },
    { 0, NULL },
};

static const FieldPart I019_000_MT = { 8, 1.0, FIELD_PART_UINT, &hf_019_000_MT, NULL };
static const FieldPart *I019_000_PARTS[] = { &I019_000_MT, NULL };

static const FieldPart I019_550_NOGO = { 2, 1.0, FIELD_PART_UINT, &hf_019_550_NOGO, NULL };
static const FieldPart I019_550_OVL = { 1, 1.0, FIELD_PART_UINT, &hf_019_550_OVL, NULL };
static const FieldPart I019_550_TSV = { 1, 1.0, FIELD_PART_UINT, &hf_019_550_TSV, NULL };
static const FieldPart I019_550_TTF = { 1, 1.0, FIELD_PART_UINT, &hf_019_550_TTF, NULL };
static const FieldPart *I019_550_PARTS[] = { &I019_550_NOGO, &I019_550_OVL, &I019_550_TSV, &I019_550_TTF, &IXXX_3bit_spare, NULL };

static const FieldPart I019_551_TP1_EXEC = { 1, 1.0, FIELD_PART_UINT, &hf_019_551_TP1_EXEC, NULL };
static const FieldPart I019_551_TP1_GOOD = { 1, 1.0, FIELD_PART_UINT, &hf_019_551_TP1_GOOD, NULL };
static const FieldPart I019_551_TP2_EXEC = { 1, 1.0, FIELD_PART_UINT, &hf_019_551_TP2_EXEC, NULL };
static const FieldPart I019_551_TP2_GOOD = { 1, 1.0, FIELD_PART_UINT, &hf_019_551_TP2_GOOD, NULL };
static const FieldPart I019_551_TP3_EXEC = { 1, 1.0, FIELD_PART_UINT, &hf_019_551_TP3_EXEC, NULL };
static const FieldPart I019_551_TP3_GOOD = { 1, 1.0, FIELD_PART_UINT, &hf_019_551_TP3_GOOD, NULL };
static const FieldPart I019_551_TP4_EXEC = { 1, 1.0, FIELD_PART_UINT, &hf_019_551_TP4_EXEC, NULL };
static const FieldPart I019_551_TP4_GOOD = { 1, 1.0, FIELD_PART_UINT, &hf_019_551_TP4_GOOD, NULL };

static const FieldPart *I019_551_PARTS[] = { &I019_551_TP1_EXEC, &I019_551_TP1_GOOD,
                                             &I019_551_TP2_EXEC, &I019_551_TP2_GOOD,
                                             &I019_551_TP3_EXEC, &I019_551_TP3_GOOD,
                                             &I019_551_TP4_EXEC, &I019_551_TP4_GOOD,
                                             NULL };

static const FieldPart I019_552_RS_Identification = { 8, 1.0, FIELD_PART_UINT, &hf_019_552_RS_Identification, NULL };
static const FieldPart I019_552_Receiver_1090_MHz = { 1, 1.0, FIELD_PART_UINT, &hf_019_552_Receiver_1090_MHz, NULL };
static const FieldPart I019_552_Transmitter_1030_MHz = { 1, 1.0, FIELD_PART_UINT, &hf_019_552_Transmitter_1030_MHz, NULL };
static const FieldPart I019_552_Transmitter_1090_MHz = { 1, 1.0, FIELD_PART_UINT, &hf_019_552_Transmitter_1090_MHz, NULL };
static const FieldPart I019_552_RS_Status = { 1, 1.0, FIELD_PART_UINT, &hf_019_552_RS_Status, NULL };
static const FieldPart I019_552_RS_Operational = { 1, 1.0, FIELD_PART_UINT, &hf_019_552_RS_Operational, NULL };
static const FieldPart *I019_552_PARTS[] = { &I019_552_RS_Identification,
                                             &IXXX_1bit_spare,
                                             &I019_552_Receiver_1090_MHz,
                                             &I019_552_Transmitter_1030_MHz,
                                             &I019_552_Transmitter_1090_MHz,
                                             &I019_552_RS_Status,
                                             &I019_552_RS_Operational,
                                             &IXXX_2bit_spare,
                                             NULL };

/* Note: I019/553 is an FX field that has no limit on the number of extensions.
 * There is currently no function available for us to deal dynamically with that so we
 * will just hardcode support for a maximum of 10 extensions.
 **/

static const FieldPart I019_553_Ref_Trans_1_Status = { 2, 1.0, FIELD_PART_UINT, &hf_019_553_Ref_Trans_1_Status, NULL };
static const FieldPart I019_553_Ref_Trans_2_Status = { 2, 1.0, FIELD_PART_UINT, &hf_019_553_Ref_Trans_2_Status, NULL };
static const FieldPart I019_553_Ref_Trans_3_Status = { 2, 1.0, FIELD_PART_UINT, &hf_019_553_Ref_Trans_3_Status, NULL };
static const FieldPart I019_553_Ref_Trans_4_Status = { 2, 1.0, FIELD_PART_UINT, &hf_019_553_Ref_Trans_4_Status, NULL };
static const FieldPart I019_553_Ref_Trans_5_Status = { 2, 1.0, FIELD_PART_UINT, &hf_019_553_Ref_Trans_5_Status, NULL };
static const FieldPart I019_553_Ref_Trans_6_Status = { 2, 1.0, FIELD_PART_UINT, &hf_019_553_Ref_Trans_6_Status, NULL };
static const FieldPart I019_553_Ref_Trans_7_Status = { 2, 1.0, FIELD_PART_UINT, &hf_019_553_Ref_Trans_7_Status, NULL };
static const FieldPart I019_553_Ref_Trans_8_Status = { 2, 1.0, FIELD_PART_UINT, &hf_019_553_Ref_Trans_8_Status, NULL };
static const FieldPart I019_553_Ref_Trans_9_Status = { 2, 1.0, FIELD_PART_UINT, &hf_019_553_Ref_Trans_9_Status, NULL };
static const FieldPart I019_553_Ref_Trans_10_Status = { 2, 1.0, FIELD_PART_UINT, &hf_019_553_Ref_Trans_10_Status, NULL };
static const FieldPart I019_553_Ref_Trans_11_Status = { 2, 1.0, FIELD_PART_UINT, &hf_019_553_Ref_Trans_11_Status, NULL };
static const FieldPart I019_553_Ref_Trans_12_Status = { 2, 1.0, FIELD_PART_UINT, &hf_019_553_Ref_Trans_12_Status, NULL };
static const FieldPart I019_553_Ref_Trans_13_Status = { 2, 1.0, FIELD_PART_UINT, &hf_019_553_Ref_Trans_13_Status, NULL };
static const FieldPart I019_553_Ref_Trans_14_Status = { 2, 1.0, FIELD_PART_UINT, &hf_019_553_Ref_Trans_14_Status, NULL };
static const FieldPart I019_553_Ref_Trans_15_Status = { 2, 1.0, FIELD_PART_UINT, &hf_019_553_Ref_Trans_15_Status, NULL };
static const FieldPart I019_553_Ref_Trans_16_Status = { 2, 1.0, FIELD_PART_UINT, &hf_019_553_Ref_Trans_16_Status, NULL };
static const FieldPart I019_553_Ref_Trans_17_Status = { 2, 1.0, FIELD_PART_UINT, &hf_019_553_Ref_Trans_17_Status, NULL };
static const FieldPart I019_553_Ref_Trans_18_Status = { 2, 1.0, FIELD_PART_UINT, &hf_019_553_Ref_Trans_18_Status, NULL };
static const FieldPart I019_553_Ref_Trans_19_Status = { 2, 1.0, FIELD_PART_UINT, &hf_019_553_Ref_Trans_19_Status, NULL };
static const FieldPart I019_553_Ref_Trans_20_Status = { 2, 1.0, FIELD_PART_UINT, &hf_019_553_Ref_Trans_20_Status, NULL };

static const FieldPart *I019_553_PARTS[] = { &I019_553_Ref_Trans_1_Status,
                                             &IXXX_2bit_spare,
                                             &I019_553_Ref_Trans_2_Status,
                                             &IXXX_1bit_spare,
                                             &IXXX_FX,
                                             &I019_553_Ref_Trans_3_Status,
                                             &IXXX_2bit_spare,
                                             &I019_553_Ref_Trans_4_Status,
                                             &IXXX_1bit_spare,
                                             &IXXX_FX,
                                             &I019_553_Ref_Trans_5_Status,
                                             &IXXX_2bit_spare,
                                             &I019_553_Ref_Trans_6_Status,
                                             &IXXX_1bit_spare,
                                             &IXXX_FX,
                                             &I019_553_Ref_Trans_7_Status,
                                             &IXXX_2bit_spare,
                                             &I019_553_Ref_Trans_8_Status,
                                             &IXXX_1bit_spare,
                                             &IXXX_FX,
                                             &I019_553_Ref_Trans_9_Status,
                                             &IXXX_2bit_spare,
                                             &I019_553_Ref_Trans_10_Status,
                                             &IXXX_1bit_spare,
                                             &IXXX_FX,
                                             &I019_553_Ref_Trans_11_Status,
                                             &IXXX_2bit_spare,
                                             &I019_553_Ref_Trans_12_Status,
                                             &IXXX_1bit_spare,
                                             &IXXX_FX,
                                             &I019_553_Ref_Trans_13_Status,
                                             &IXXX_2bit_spare,
                                             &I019_553_Ref_Trans_14_Status,
                                             &IXXX_1bit_spare,
                                             &IXXX_FX,
                                             &I019_553_Ref_Trans_15_Status,
                                             &IXXX_2bit_spare,
                                             &I019_553_Ref_Trans_16_Status,
                                             &IXXX_1bit_spare,
                                             &IXXX_FX,
                                             &I019_553_Ref_Trans_17_Status,
                                             &IXXX_2bit_spare,
                                             &I019_553_Ref_Trans_18_Status,
                                             &IXXX_1bit_spare,
                                             &IXXX_FX,
                                             &I019_553_Ref_Trans_19_Status,
                                             &IXXX_2bit_spare,
                                             &I019_553_Ref_Trans_20_Status,
                                             &IXXX_1bit_spare,
                                             &IXXX_FX,
                                             NULL };

static const FieldPart I019_600_Latitude = { 32, 180.0/1073741824.0, FIELD_PART_FLOAT, &hf_019_600_Latitude, NULL };
static const FieldPart I019_600_Longitude = { 32, 180.0/1073741824.0, FIELD_PART_FLOAT, &hf_019_600_Longitude, NULL };

static const FieldPart *I019_600_PARTS[] = { &I019_600_Latitude, &I019_600_Longitude, NULL };


static const FieldPart I019_610_Height = { 16, 16384.0/65536.0, FIELD_PART_FLOAT, &hf_019_610_Height, NULL };

static const FieldPart *I019_610_PARTS[] = { &I019_610_Height, NULL };

static const FieldPart I019_620_Undulation = { 8, 1.0, FIELD_PART_INT, &hf_019_620_Undulation, NULL };

static const FieldPart *I019_620_PARTS[] = { &I019_620_Undulation, NULL };

/* Items */
DIAG_OFF(pedantic)
static const AsterixField I019_000 = { FIXED, 1, 0, 0, &hf_019_000, I019_000_PARTS, { NULL } };
static const AsterixField I019_010 = { FIXED, 2, 0, 0, &hf_019_010, IXXX_SAC_SIC, { NULL } };
static const AsterixField I019_140 = { FIXED, 3, 0, 0, &hf_019_140, IXXX_TOD, { NULL } };
static const AsterixField I019_550 = { FIXED, 1, 0, 0, &hf_019_550, I019_550_PARTS, { NULL } };
static const AsterixField I019_551 = { FIXED, 1, 0, 0, &hf_019_551, I019_551_PARTS, { NULL } };
static const AsterixField I019_552 = { REPETITIVE, 2, 1, 0, &hf_019_552, I019_552_PARTS, { NULL } };
static const AsterixField I019_553 = { FX, 1, 0, 0, &hf_019_553, I019_553_PARTS, { NULL } };
static const AsterixField I019_600 = { FIXED, 8, 0, 0, &hf_019_600, I019_600_PARTS, { NULL } };
static const AsterixField I019_610 = { FIXED, 2, 0, 0, &hf_019_610, I019_610_PARTS, { NULL } };
static const AsterixField I019_620 = { FIXED, 1, 0, 0, &hf_019_620, I019_620_PARTS, { NULL } };
static const AsterixField I019_RE = { RE, 0, 0, 1, &hf_019_RE, NULL, { NULL } };
static const AsterixField I019_SP = { SP, 0, 0, 1, &hf_019_SP, NULL, { NULL } };

static const AsterixField *I019_v1_3_uap[] = { &I019_010, &I019_000, &I019_140, &I019_550, &I019_551, &I019_552, &I019_553,
                                               &I019_600, &I019_610, &I019_620, &IX_SPARE, &IX_SPARE, &I019_RE, &I019_SP, NULL };
static const AsterixField **I019_v1_3[] = { I019_v1_3_uap, NULL };
static const AsterixField ***I019[] = { I019_v1_3 };
DIAG_ON(pedantic)

static const enum_val_t I019_versions[] = {
    { "I019_v1_3", "Version 1.3", 0 },
    { NULL, NULL, 0 }
};

/* *********************** */
/*      Category 020       */
/* *********************** */
/*
 * Online specification:
 * https://www.eurocontrol.int/publications/cat020-multilateration-mlt-messages-part-14
 * https://www.eurocontrol.int/publications/cat020-coding-rule-reserved-expansion-field-part14-appendix
 */

/* Fields */
/* Target Report Descriptor */
static const value_string valstr_020_020_SSR[] = {
    { 0, "no Non-Mode S 1090MHz multilat" },
    { 1, "Non-Mode S 1090MHz multilateration" },
    { 0, NULL }
};
static const value_string valstr_020_020_MS[] = {
    { 0, "no Mode-S 1090 MHz multilateration" },
    { 1, "Mode-S 1090 MHz multilateration" },
    { 0, NULL }
};
static const value_string valstr_020_020_HF[] = {
    { 0, "no HF multilateration" },
    { 1, "HF multilateration" },
    { 0, NULL }
};
static const value_string valstr_020_020_VDL4[] = {
    { 0, "no VDL Mode 4 multilateration" },
    { 1, "VDL Mode 4 multilateration" },
    { 0, NULL }
};
static const value_string valstr_020_020_UAT[] = {
    { 0, "no UAT multilateration" },
    { 1, "UAT multilateration" },
    { 0, NULL }
};
static const value_string valstr_020_020_DME[] = {
    { 0, "no DME/TACAN multilateration" },
    { 1, "DME/TACAN multilateration" },
    { 0, NULL }
};
static const value_string valstr_020_020_OT[] = {
    { 0, "No Other Technology Multilateration" },
    { 1, "Other Technology Multilateration" },
    { 0, NULL }
};
static const value_string valstr_020_020_RAB[] = {
    { 0, "Report from target transponder" },
    { 1, "Report from field monitor (fixed transponder)" },
    { 0, NULL }
};
static const value_string valstr_020_020_SPI[] = {
    { 0, "Absence of SPI" },
    { 1, "Special Position Identification" },
    { 0, NULL }
};
static const value_string valstr_020_020_CHN[] = {
    { 0, "Chain 1" },
    { 1, "Chain 2" },
    { 0, NULL }
};
static const value_string valstr_020_020_GBS[] = {
    { 0, "Transponder Ground bit not set" },
    { 1, "Transponder Ground bit set" },
    { 0, NULL }
};
static const value_string valstr_020_020_CRT[] = {
    { 0, "No Corrupted reply in multilateration" },
    { 1, "Corrupted replies in multilateration" },
    { 0, NULL }
};
static const value_string valstr_020_020_SIM[] = {
    { 0, "Actual target report" },
    { 1, "Simulated target report" },
    { 0, NULL }
};
static const value_string valstr_020_020_TST[] = {
    { 0, "Default" },
    { 1, "Test Target" },
    { 0, NULL }
};
static const FieldPart I020_020_SSR = { 1, 1.0, FIELD_PART_UINT, &hf_020_020_SSR, NULL };
static const FieldPart I020_020_MS = { 1, 1.0, FIELD_PART_UINT, &hf_020_020_MS, NULL };
static const FieldPart I020_020_HF = { 1, 1.0, FIELD_PART_UINT, &hf_020_020_HF, NULL };
static const FieldPart I020_020_VDL4 = { 1, 1.0, FIELD_PART_UINT, &hf_020_020_VDL4, NULL };
static const FieldPart I020_020_UAT = { 1, 1.0, FIELD_PART_UINT, &hf_020_020_UAT, NULL };
static const FieldPart I020_020_DME = { 1, 1.0, FIELD_PART_UINT, &hf_020_020_DME, NULL };
static const FieldPart I020_020_OT = { 1, 1.0, FIELD_PART_UINT, &hf_020_020_OT, NULL };
static const FieldPart I020_020_RAB = { 1, 1.0, FIELD_PART_UINT, &hf_020_020_RAB, NULL };
static const FieldPart I020_020_SPI = { 1, 1.0, FIELD_PART_UINT, &hf_020_020_SPI, NULL };
static const FieldPart I020_020_CHN = { 1, 1.0, FIELD_PART_UINT, &hf_020_020_CHN, NULL };
static const FieldPart I020_020_GBS = { 1, 1.0, FIELD_PART_UINT, &hf_020_020_GBS, NULL };
static const FieldPart I020_020_CRT = { 1, 1.0, FIELD_PART_UINT, &hf_020_020_CRT, NULL };
static const FieldPart I020_020_SIM = { 1, 1.0, FIELD_PART_UINT, &hf_020_020_SIM, NULL };
static const FieldPart I020_020_TST = { 1, 1.0, FIELD_PART_UINT, &hf_020_020_TST, NULL };
static const FieldPart *I020_020_PARTS[] = { &I020_020_SSR, &I020_020_MS, &I020_020_HF, &I020_020_VDL4, &I020_020_UAT, &I020_020_DME, &I020_020_OT, &IXXX_FX,
                                             &I020_020_RAB, &I020_020_SPI, &I020_020_CHN, &I020_020_GBS, &I020_020_CRT, &I020_020_SIM, &I020_020_TST, &IXXX_FX, NULL };

/* Warning/Error Conditions */
static const value_string valstr_020_030_WE[] = {
    {  0, "Not defined; never used" },
    {  1, "Multipath Reply (Reflection)" },
    {  3, "Split plot" },
    { 10, "Phantom SSR plot" },
    { 11, "Non-Matching Mode-3/A Code" },
    { 12, "Mode C code / Mode S altitude code abnormal value compared to the track" },
    { 15, "Transponder anomaly detected" },
    { 16, "Duplicated or Illegal Mode S Aircraft Address" },
    { 17, "Mode S error correction applied" },
    { 18, "Undecodable Mode C code / Mode S altitude code" },
    {  0, NULL }
};
static const FieldPart I020_030_WE = { 7, 1.0, FIELD_PART_UINT, &hf_020_030_WE, NULL };
/* It is not specified how many W/E conditions may be present. Since FX fields are not made that way, MAX 10 for now.
 * For such field, repetitive field should be used, but it is not. */
static const FieldPart *I020_030_PARTS[] = { &I020_030_WE, &IXXX_FX,
                                             &I020_030_WE, &IXXX_FX,
                                             &I020_030_WE, &IXXX_FX,
                                             &I020_030_WE, &IXXX_FX,
                                             &I020_030_WE, &IXXX_FX,
                                             &I020_030_WE, &IXXX_FX,
                                             &I020_030_WE, &IXXX_FX,
                                             &I020_030_WE, &IXXX_FX,
                                             &I020_030_WE, &IXXX_FX,
                                             &I020_030_WE, &IXXX_FX, NULL };

/* Position in WGS-84 Coordinates */
static const FieldPart I020_041_LAT = { 32, 180.0/33554432.0, FIELD_PART_FLOAT, &hf_020_041_LAT, NULL };
static const FieldPart I020_041_LON = { 32, 180.0/33554432.0, FIELD_PART_FLOAT, &hf_020_041_LON, NULL };
static const FieldPart *I020_041_PARTS[] = { &I020_041_LAT, &I020_041_LON, NULL };

/* Position in Cartesian Coordinates */
static const FieldPart I020_042_X = { 24, 0.5, FIELD_PART_FLOAT, &hf_020_042_X, NULL };
static const FieldPart I020_042_Y = { 24, 0.5, FIELD_PART_FLOAT, &hf_020_042_Y, NULL };
static const FieldPart *I020_042_PARTS[] = { &I020_042_X, &I020_042_Y, NULL };

/* Mode-2 Code in Octal Representation */
static const value_string valstr_020_050_V[] = {
    { 0, "Code validated" },
    { 1, "Code not validated" },
    { 0, NULL }
};
static const value_string valstr_020_050_G[] = {
    { 0, "Default" },
    { 1, "Garbled code" },
    { 0, NULL }
};
static const value_string valstr_020_050_L[] = {
    { 0, "Mode-2 code derived from the reply of the transponder" },
    { 1, "Smoothed Mode-2 code as provided by a local tracker n" },
    { 0, NULL }
};
static const FieldPart I020_050_V = { 1, 1.0, FIELD_PART_UINT, &hf_020_050_V, NULL };
static const FieldPart I020_050_G = { 1, 1.0, FIELD_PART_UINT, &hf_020_050_G, NULL };
static const FieldPart I020_050_L = { 1, 1.0, FIELD_PART_UINT, &hf_020_050_L, NULL };
static const FieldPart I020_050_CODE = { 12, 1.0, FIELD_PART_SQUAWK, &hf_020_050_SQUAWK, NULL };
static const FieldPart *I020_050_PARTS[] = { &I020_050_V, &I020_050_G, &I020_050_L, &IXXX_1bit_spare, &I020_050_CODE, NULL };

/* Mode-1 Code in Octal Representation */
static const value_string valstr_020_055_V[] = {
    { 0, "Code validated" },
    { 1, "Code not validated" },
    { 0, NULL }
};
static const value_string valstr_020_055_G[] = {
    { 0, "Default" },
    { 1, "Garbled code" },
    { 0, NULL }
};
static const value_string valstr_020_055_L[] = {
    { 0, "Mode-1 code derived from the reply of the transponder" },
    { 1, "Smoothed Mode-1 code as provided by a local tracker" },
    { 0, NULL }
};
static const FieldPart I020_055_V = { 1, 1.0, FIELD_PART_UINT, &hf_020_055_V, NULL };
static const FieldPart I020_055_G = { 1, 1.0, FIELD_PART_UINT, &hf_020_055_G, NULL };
static const FieldPart I020_055_L = { 1, 1.0, FIELD_PART_UINT, &hf_020_055_L, NULL };
static const FieldPart I020_055_A = { 3, 1.0, FIELD_PART_UINT, &hf_020_055_A, NULL };
static const FieldPart I020_055_B = { 2, 1.0, FIELD_PART_UINT, &hf_020_055_B, NULL };
static const FieldPart *I020_055_PARTS[] = { &I020_055_V, &I020_055_G, &I020_055_L, &I020_055_A, &I020_055_B, NULL };

/* Mode-3/A Code in Octal Representation */
static const value_string valstr_020_070_V[] = {
    { 0, "Code validated" },
    { 1, "Code not validated" },
    { 0, NULL }
};
static const value_string valstr_020_070_G[] = {
    { 0, "Default" },
    { 1, "Garbled code" },
    { 0, NULL }
};
static const value_string valstr_020_070_L[] = {
    { 0, "Mode-3/A code derived from the reply of the transponder" },
    { 1, "Mode-3/A code not extracted during the last update period" },
    { 0, NULL }
};
static const FieldPart I020_070_V = { 1, 1.0, FIELD_PART_UINT, &hf_020_070_V, NULL };
static const FieldPart I020_070_G = { 1, 1.0, FIELD_PART_UINT, &hf_020_070_G, NULL };
static const FieldPart I020_070_L = { 1, 1.0, FIELD_PART_UINT, &hf_020_070_L, NULL };
static const FieldPart I020_070_SQUAWK = { 12, 1.0, FIELD_PART_SQUAWK, &hf_020_070_SQUAWK, NULL };
static const FieldPart *I020_070_PARTS[] = { &I020_070_V, &I020_070_G, &I020_070_L, &IXXX_1bit_spare, &I020_070_SQUAWK, NULL };

/* Flight Level in Binary Representation */
static const value_string valstr_020_090_V[] = {
    { 0, "Code validated" },
    { 1, "Code not validated" },
    { 0, NULL }
};
static const value_string valstr_020_090_G[] = {
    { 0, "Default" },
    { 1, "Garbled code" },
    { 0, NULL }
};
static const FieldPart I020_090_V = { 1, 1.0, FIELD_PART_UINT, &hf_020_090_V, NULL };
static const FieldPart I020_090_G = { 1, 1.0, FIELD_PART_UINT, &hf_020_090_G, NULL };
static const FieldPart I020_090_FL = { 14, 0.25, FIELD_PART_FLOAT, &hf_020_090_FL, NULL };
static const FieldPart *I020_090_PARTS[] = { &I020_090_V, &I020_090_G, &I020_090_FL, NULL };

/* Mode-C Code */
static const value_string valstr_020_100_V[] = {
    { 0, "Code validated" },
    { 1, "Code not validated" },
    { 0, NULL }
};
static const value_string valstr_020_100_G[] = {
    { 0, "Default" },
    { 1, "Garbled code" },
    { 0, NULL }
};
static const value_string valstr_020_100_QA[] = {
    { 0, "High quality pulse" },
    { 1, "Low quality pulse" },
    { 0, NULL }
};
static const FieldPart I020_100_V = { 1, 1.0, FIELD_PART_UINT, &hf_020_100_V, NULL };
static const FieldPart I020_100_G = { 1, 1.0, FIELD_PART_UINT, &hf_020_100_G, NULL };
static const FieldPart I020_100_C1 = { 1, 1.0, FIELD_PART_UINT, &hf_020_100_C1, NULL };
static const FieldPart I020_100_A1 = { 1, 1.0, FIELD_PART_UINT, &hf_020_100_A1, NULL };
static const FieldPart I020_100_C2 = { 1, 1.0, FIELD_PART_UINT, &hf_020_100_C2, NULL };
static const FieldPart I020_100_A2 = { 1, 1.0, FIELD_PART_UINT, &hf_020_100_A2, NULL };
static const FieldPart I020_100_C4 = { 1, 1.0, FIELD_PART_UINT, &hf_020_100_C4, NULL };
static const FieldPart I020_100_A4 = { 1, 1.0, FIELD_PART_UINT, &hf_020_100_A4, NULL };
static const FieldPart I020_100_B1 = { 1, 1.0, FIELD_PART_UINT, &hf_020_100_B1, NULL };
static const FieldPart I020_100_D1 = { 1, 1.0, FIELD_PART_UINT, &hf_020_100_D1, NULL };
static const FieldPart I020_100_B2 = { 1, 1.0, FIELD_PART_UINT, &hf_020_100_B2, NULL };
static const FieldPart I020_100_D2 = { 1, 1.0, FIELD_PART_UINT, &hf_020_100_D2, NULL };
static const FieldPart I020_100_B4 = { 1, 1.0, FIELD_PART_UINT, &hf_020_100_B4, NULL };
static const FieldPart I020_100_D4 = { 1, 1.0, FIELD_PART_UINT, &hf_020_100_D4, NULL };
static const FieldPart I020_100_QC1 = { 1, 1.0, FIELD_PART_UINT, &hf_020_100_QC1, NULL };
static const FieldPart I020_100_QA1 = { 1, 1.0, FIELD_PART_UINT, &hf_020_100_QA1, NULL };
static const FieldPart I020_100_QC2 = { 1, 1.0, FIELD_PART_UINT, &hf_020_100_QC2, NULL };
static const FieldPart I020_100_QA2 = { 1, 1.0, FIELD_PART_UINT, &hf_020_100_QA2, NULL };
static const FieldPart I020_100_QC4 = { 1, 1.0, FIELD_PART_UINT, &hf_020_100_QC4, NULL };
static const FieldPart I020_100_QA4 = { 1, 1.0, FIELD_PART_UINT, &hf_020_100_QA4, NULL };
static const FieldPart I020_100_QB1 = { 1, 1.0, FIELD_PART_UINT, &hf_020_100_QB1, NULL };
static const FieldPart I020_100_QD1 = { 1, 1.0, FIELD_PART_UINT, &hf_020_100_QD1, NULL };
static const FieldPart I020_100_QB2 = { 1, 1.0, FIELD_PART_UINT, &hf_020_100_QB2, NULL };
static const FieldPart I020_100_QD2 = { 1, 1.0, FIELD_PART_UINT, &hf_020_100_QD2, NULL };
static const FieldPart I020_100_QB4 = { 1, 1.0, FIELD_PART_UINT, &hf_020_100_QB4, NULL };
static const FieldPart I020_100_QD4 = { 1, 1.0, FIELD_PART_UINT, &hf_020_100_QD4, NULL };
static const FieldPart *I020_100_PARTS[] = { &I020_100_V, &I020_100_G, &IXXX_2bit_spare,
                                             &I020_100_C1, &I020_100_A1, &I020_100_C2, &I020_100_A2,
                                             &I020_100_C4, &I020_100_A4, &I020_100_B1, &I020_100_D1,
                                             &I020_100_B2, &I020_100_D2, &I020_100_B4, &I020_100_D4,
                                             &IXXX_4bit_spare,
                                             &I020_100_QC1, &I020_100_QA1, &I020_100_QC2, &I020_100_QA2,
                                             &I020_100_QC4, &I020_100_QA4, &I020_100_QB1, &I020_100_QD1,
                                             &I020_100_QB2, &I020_100_QD2, &I020_100_QB4, &I020_100_QD4, NULL };

/* Geometric Height (WGS-84) */
static const FieldPart I020_105_GH = { 16, 6.25, FIELD_PART_FLOAT, &hf_020_105_GH, NULL };
static const FieldPart *I020_105_PARTS[] = { &I020_105_GH, NULL };

/* Measured Height (Local Cartesian Coordinates) */
static const FieldPart I020_110_MH = { 16, 6.25, FIELD_PART_FLOAT, &hf_020_110_MH, NULL };
static const FieldPart *I020_110_PARTS[] = { &I020_110_MH, NULL };

/* Time of Day */
/* IXXX_TOD */

/* Track Number */
static const FieldPart I020_161_TN = { 12, 1.0, FIELD_PART_UINT, &hf_020_161_TN, NULL };
static const FieldPart *I020_161_PARTS[] = { &IXXX_4bit_spare, &I020_161_TN, NULL };

/* Track Status */
static const value_string valstr_020_170_CNF[] = {
    { 0, "Confirmed track" },
    { 1, "Track in initiation phase" },
    { 0, NULL }
};
static const value_string valstr_020_170_TRE[] = {
    { 0, "Default" },
    { 1, "Last report for a track" },
    { 0, NULL }
};
static const value_string valstr_020_170_CST[] = {
    { 0, "Not extrapolated" },
    { 1, "Extrapolated" },
    { 0, NULL }
};
static const value_string valstr_020_170_CDM[] = {
    { 0, "Maintaining" },
    { 1, "Climbing" },
    { 2, "Descending" },
    { 3, "Invalid" },
    { 0, NULL }
};
static const value_string valstr_020_170_MAH[] = {
    { 0, "Default" },
    { 1, "Horizontal manoeuvre" },
    { 0, NULL }
};
static const value_string valstr_020_170_STH[] = {
    { 0, "Measured position" },
    { 1, "Smoothed position" },
    { 0, NULL }
};
static const value_string valstr_020_170_GHO[] = {
    { 0, "Default" },
    { 1, "Ghost track" },
    { 0, NULL }
};
static const FieldPart I020_170_CNF = { 1, 1.0, FIELD_PART_UINT, &hf_020_170_CNF, NULL };
static const FieldPart I020_170_TRE = { 1, 1.0, FIELD_PART_UINT, &hf_020_170_TRE, NULL };
static const FieldPart I020_170_CST = { 1, 1.0, FIELD_PART_UINT, &hf_020_170_CST, NULL };
static const FieldPart I020_170_CDM = { 2, 1.0, FIELD_PART_UINT, &hf_020_170_CDM, NULL };
static const FieldPart I020_170_MAH = { 1, 1.0, FIELD_PART_UINT, &hf_020_170_MAH, NULL };
static const FieldPart I020_170_STH = { 1, 1.0, FIELD_PART_UINT, &hf_020_170_STH, NULL };
static const FieldPart I020_170_GHO = { 1, 1.0, FIELD_PART_UINT, &hf_020_170_GHO, NULL };
static const FieldPart *I020_170_PARTS[] = { &I020_170_CNF, &I020_170_TRE, &I020_170_CST, &I020_170_CDM, &I020_170_MAH, &I020_170_STH, &IXXX_FX,
                                             &I020_170_GHO, &IXXX_6bit_spare, &IXXX_FX, NULL };

/* Calculated Track Velocity in Cartesian Coordinates */
static const FieldPart I020_202_VX = { 16, 0.25, FIELD_PART_FLOAT, &hf_020_202_VX, NULL };
static const FieldPart I020_202_VY = { 16, 0.25, FIELD_PART_FLOAT, &hf_020_202_VY, NULL };
static const FieldPart *I020_202_PARTS[] = { &I020_202_VX, &I020_202_VY, NULL };

/* Calculated Acceleration */
static const FieldPart I020_210_AX = { 8, 0.25, FIELD_PART_FLOAT, &hf_020_210_AX, NULL };
static const FieldPart I020_210_AY = { 8, 0.25, FIELD_PART_FLOAT, &hf_020_210_AY, NULL };
static const FieldPart *I020_210_PARTS[] = { &I020_210_AX, &I020_210_AY, NULL };

/* Target Address */
/* IXXX_AA */

/* Communications/ACAS Capability and Flight Status */
static const value_string valstr_020_230_COM[] = {
    { 0, "No communications capability (surveillance only)" },
    { 1, "Comm. A and Comm. B capability" },
    { 2, "Comm. A, Comm. B and Uplink ELM" },
    { 3, "Comm. A, Comm. B, Uplink ELM and Downlink ELM" },
    { 4, "Level 5 Transponder capability" },
    { 5, "Not assigned" },
    { 6, "Not assigned" },
    { 7, "Not assigned" },
    { 0, NULL }
};
static const value_string valstr_020_230_STAT[] = {
    { 0, "No alert, no SPI, aircraft airborne" },
    { 1, "No alert, no SPI, aircraft on ground" },
    { 2, "Alert, no SPI, aircraft airborne" },
    { 3, "Alert, no SPI, aircraft on ground" },
    { 4, "Alert, SPI, aircraft airborne or on ground" },
    { 5, "No alert, SPI, aircraft airborne or on ground" },
    { 6, "Not assigned" },
    { 7, "Information not yet extracted" },
    { 0, NULL }
};
static const value_string valstr_020_230_MSSC[] = {
    { 0, "No" },
    { 1, "Yes" },
    { 0, NULL }
};
static const value_string valstr_020_230_ARC[] = {
    { 0, "100 ft resolution" },
    { 1, "25 ft resolution" },
    { 0, NULL }
};
static const value_string valstr_020_230_AIC[] = {
    { 0, "No" },
    { 1, "Yes" },
    { 0, NULL }
};
static const FieldPart I020_230_COM = { 3, 1.0, FIELD_PART_UINT, &hf_020_230_COM, NULL };
static const FieldPart I020_230_STAT = { 3, 1.0, FIELD_PART_UINT, &hf_020_230_STAT, NULL };
static const FieldPart I020_230_MSSC = { 1, 1.0, FIELD_PART_UINT, &hf_020_230_MSSC, NULL };
static const FieldPart I020_230_ARC = { 1, 1.0, FIELD_PART_UINT, &hf_020_230_ARC, NULL };
static const FieldPart I020_230_AIC = { 1, 1.0, FIELD_PART_UINT, &hf_020_230_AIC, NULL };
static const FieldPart I020_230_B1A = { 1, 1.0, FIELD_PART_UINT, &hf_020_230_B1A, NULL };
static const FieldPart I020_230_B1B = { 4, 1.0, FIELD_PART_HEX, &hf_020_230_B1B, NULL };
static const FieldPart *I020_230_PARTS[] = { &I020_230_COM, &I020_230_STAT, &IXXX_2bit_spare,
                                             &I020_230_MSSC, &I020_230_ARC, &I020_230_AIC, &I020_230_B1A, &I020_230_B1B, NULL };

/* Target Identification */
static const value_string valstr_020_245_STI[] = {
    { 0, "Callsign or registration not downlinked from transponder" },
    { 1, "Registration downlinked from transponder" },
    { 2, "Callsign downlinked from transponder" },
    { 3, "Not defined" },
    { 0, NULL }
};
static const FieldPart I020_245_STI = { 2, 1.0, FIELD_PART_UINT, &hf_020_245_STI, NULL };
static const FieldPart *I020_245_PARTS[] = { &I020_245_STI, &IXXX_6bit_spare, &IXXX_AI, NULL };

/* Mode S MB Data */
/* IXXX_MB */

/* ACAS Resolution Advisory Report */
static const FieldPart *I020_260_PARTS[] = { &IXXX_MB_DATA, NULL };

/* Vehicle Fleet Identification */
static const value_string valstr_020_300_VFI[] = {
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
    {  0, NULL }
};
static const FieldPart I020_300_VFI = { 8, 1.0, FIELD_PART_UINT, &hf_020_300_VFI, NULL };
static const FieldPart *I020_300_PARTS[] = { &I020_300_VFI, NULL };

/* Pre-programmed Message */
static const value_string valstr_020_310_TRB[] = {
    { 0, "Default" },
    { 1, "In Trouble" },
    { 0, NULL }
};
static const value_string valstr_020_310_MSG[] = {
    { 1, "Towing aircraft" },
    { 2, "\"Follow me\" operation" },
    { 3, "Runway check" },
    { 4, "Emergency operation (fire, medical...)" },
    { 5, "Work in progress (maintenance, birds scarer, sweepers...)" },
    { 0, NULL }
};
static const FieldPart I020_310_TRB = { 1, 1.0, FIELD_PART_UINT, &hf_020_310_TRB, NULL };
static const FieldPart I020_310_MSG = { 7, 1.0, FIELD_PART_UINT, &hf_020_310_MSG, NULL };
static const FieldPart *I020_310_PARTS[] = { &I020_310_TRB, &I020_310_MSG, NULL };

/* Contributing Devices */
static const value_string valstr_020_400_TUxRUx[] = {
    { 0, "TUx/RUx has NOT contributed to the target detection" },
    { 1, "TUx/RUx has contributed to the target detection" },
    { 0, NULL }
};
static const FieldPart I020_400_TU8RU8 = { 1, 1.0, FIELD_PART_UINT, &hf_020_400_TU8RU8, NULL };
static const FieldPart I020_400_TU7RU7 = { 1, 1.0, FIELD_PART_UINT, &hf_020_400_TU7RU7, NULL };
static const FieldPart I020_400_TU6RU6 = { 1, 1.0, FIELD_PART_UINT, &hf_020_400_TU6RU6, NULL };
static const FieldPart I020_400_TU5RU5 = { 1, 1.0, FIELD_PART_UINT, &hf_020_400_TU5RU5, NULL };
static const FieldPart I020_400_TU4RU4 = { 1, 1.0, FIELD_PART_UINT, &hf_020_400_TU4RU4, NULL };
static const FieldPart I020_400_TU3RU3 = { 1, 1.0, FIELD_PART_UINT, &hf_020_400_TU3RU3, NULL };
static const FieldPart I020_400_TU2RU2 = { 1, 1.0, FIELD_PART_UINT, &hf_020_400_TU2RU2, NULL };
static const FieldPart I020_400_TU1RU1 = { 1, 1.0, FIELD_PART_UINT, &hf_020_400_TU1RU1, NULL };
static const FieldPart *I020_400_PARTS[] = { &I020_400_TU8RU8, &I020_400_TU7RU7, &I020_400_TU6RU6, &I020_400_TU5RU5, &I020_400_TU4RU4, &I020_400_TU3RU3, &I020_400_TU2RU2, &I020_400_TU1RU1, NULL };

/* Position Accuracy */
static const FieldPart I020_500_01_DOPx = { 16, 0.25, FIELD_PART_UFLOAT, &hf_020_500_01_DOPx, NULL };
static const FieldPart I020_500_01_DOPy = { 16, 0.25, FIELD_PART_UFLOAT, &hf_020_500_01_DOPy, NULL };
static const FieldPart I020_500_01_DOPxy = { 16, 0.25, FIELD_PART_FLOAT, &hf_020_500_01_DOPxy, NULL };
static const FieldPart *I020_500_01_PARTS[] = { &I020_500_01_DOPx, &I020_500_01_DOPy, &I020_500_01_DOPxy, NULL };
static const FieldPart I020_500_02_SDPx = { 16, 0.25, FIELD_PART_UFLOAT, &hf_020_500_02_SDPx, NULL };
static const FieldPart I020_500_02_SDPy = { 16, 0.25, FIELD_PART_UFLOAT, &hf_020_500_02_SDPy, NULL };
static const FieldPart I020_500_02_SDPxy = { 16, 0.25, FIELD_PART_FLOAT, &hf_020_500_02_SDPxy, NULL };
static const FieldPart *I020_500_02_PARTS[] = { &I020_500_02_SDPx, &I020_500_02_SDPy, &I020_500_02_SDPxy, NULL };
static const FieldPart I020_500_03_SDH = { 16, 0.5, FIELD_PART_UFLOAT, &hf_020_500_03_SDH, NULL };
static const FieldPart *I020_500_03_PARTS[] = { &I020_500_03_SDH, NULL };

/* Reserved expansion field */
/* Range exceeded indicator */
static const value_string valstr_020_RE_GVV_RE[] = {
    { 0, "Value in defined range" },
    { 1, "Value exceeds defined range" },
    { 0, NULL }
};

static const FieldPart I020_RE_PA_01_DOPx = { 16, 0.25, FIELD_PART_UFLOAT, &hf_020_RE_PA_01_DOPx, NULL };
static const FieldPart I020_RE_PA_01_DOPy = { 16, 0.25, FIELD_PART_UFLOAT, &hf_020_RE_PA_01_DOPy, NULL };
static const FieldPart I020_RE_PA_01_DOPxy = { 16, 0.25, FIELD_PART_FLOAT, &hf_020_RE_PA_01_DOPxy, NULL };
static const FieldPart *I020_RE_PA_01_DOP_PARTS[] = { &I020_RE_PA_01_DOPx, &I020_RE_PA_01_DOPy, &I020_RE_PA_01_DOPxy, NULL };
static const FieldPart I020_RE_PA_02_SDCx = { 16, 0.25, FIELD_PART_UFLOAT, &hf_020_RE_PA_02_SDCx, NULL };
static const FieldPart I020_RE_PA_02_SDCy = { 16, 0.25, FIELD_PART_UFLOAT, &hf_020_RE_PA_02_SDCy, NULL };
static const FieldPart I020_RE_PA_02_SDCxy = { 16, 0.25, FIELD_PART_FLOAT, &hf_020_RE_PA_02_SDCxy, NULL };
static const FieldPart *I020_RE_PA_02_SDC_PARTS[] = { &I020_RE_PA_02_SDCx, &I020_RE_PA_02_SDCy, &I020_RE_PA_02_SDCxy, NULL };
static const FieldPart I020_RE_PA_03_SDH_SDH = { 16, 1, FIELD_PART_UFLOAT, &hf_020_RE_PA_03_SDH, NULL };
static const FieldPart *I020_RE_PA_03_SDH_PARTS[] = { &I020_RE_PA_03_SDH_SDH, NULL };
static const FieldPart I020_RE_PA_04_LAT = { 16, 180.0/33554432.0, FIELD_PART_UFLOAT, &hf_020_RE_PA_04_LAT, NULL };
static const FieldPart I020_RE_PA_04_LON = { 16, 180.0/33554432.0, FIELD_PART_UFLOAT, &hf_020_RE_PA_04_LON, NULL };
static const FieldPart I020_RE_PA_04_COV = { 16, 180.0/33554432.0, FIELD_PART_FLOAT, &hf_020_RE_PA_04_COV, NULL };
static const FieldPart *I020_RE_PA_04_SDW_PARTS[] = { &I020_RE_PA_04_LAT, &I020_RE_PA_04_LON, &I020_RE_PA_04_COV, NULL };
static const FieldPart I020_RE_GVV_RE = { 1, 1.0, FIELD_PART_UINT, &hf_020_RE_GVV_RE, NULL };
static const FieldPart I020_RE_GVV_GS = { 15, 1.0/16384.0, FIELD_PART_UFLOAT, &hf_020_RE_GVV_GS, NULL };
static const FieldPart I020_RE_GVV_TA = { 16, 360.0/65536.0, FIELD_PART_UFLOAT, &hf_020_RE_GVV_TA, NULL };
static const FieldPart *I020_RE_GVV_PARTS[] = { &I020_RE_GVV_RE, &I020_RE_GVV_GS, &I020_RE_GVV_TA, NULL };
static const FieldPart I020_RE_GVA_GSSD = { 8, 1.0/16384.0, FIELD_PART_UFLOAT, &hf_020_RE_GVA_GSSD, NULL };
static const FieldPart I020_RE_GVA_TASD = { 8, 360.0/4096.0, FIELD_PART_UFLOAT, &hf_020_RE_GVA_TASD, NULL };
static const FieldPart *I020_RE_GVA_PARTS[] = { &I020_RE_GVA_GSSD, &I020_RE_GVA_TASD, NULL };
/* 04 - Time of day */
static const FieldPart I020_RE_DA_01_SPI = { 8, 0.1, FIELD_PART_UFLOAT, &hf_020_RE_DA_01_SPI, NULL };
static const FieldPart *I020_RE_DA_01_PARTS[] = { &I020_RE_DA_01_SPI, NULL };
static const FieldPart I020_RE_DA_02_TI = { 8, 0.1, FIELD_PART_UFLOAT, &hf_020_RE_DA_02_TI, NULL };
static const FieldPart *I020_RE_DA_02_PARTS[] = { &I020_RE_DA_02_TI, NULL };
static const FieldPart I020_RE_DA_03_BDS1 = { 4, 1.0, FIELD_PART_UINT, &hf_020_RE_DA_03_BDS1, NULL };
static const FieldPart I020_RE_DA_03_BDS2 = { 4, 1.0, FIELD_PART_UINT, &hf_020_RE_DA_03_BDS2, NULL };
static const FieldPart I020_RE_DA_03_MBA = { 8, 0.1, FIELD_PART_UFLOAT, &hf_020_RE_DA_03_MBA, NULL };
static const FieldPart *I020_RE_DA_03_PARTS[] = { &I020_RE_DA_03_BDS1, &I020_RE_DA_03_BDS2, &I020_RE_DA_03_MBA, NULL };
static const FieldPart I020_RE_DA_04_M3A = { 8, 0.1, FIELD_PART_UFLOAT, &hf_020_RE_DA_04_M3A, NULL };
static const FieldPart *I020_RE_DA_04_PARTS[] = { &I020_RE_DA_04_M3A, NULL };
static const FieldPart I020_RE_DA_05_FL = { 8, 0.1, FIELD_PART_UFLOAT, &hf_020_RE_DA_05_FL, NULL };
static const FieldPart *I020_RE_DA_05_PARTS[] = { &I020_RE_DA_05_FL, NULL };
static const FieldPart I020_RE_DA_06_STAT = { 8, 0.1, FIELD_PART_UFLOAT, &hf_020_RE_DA_06_STAT, NULL };
static const FieldPart *I020_RE_DA_06_PARTS[] = { &I020_RE_DA_06_STAT, NULL };
static const FieldPart I020_RE_DA_07_GH = { 8, 0.1, FIELD_PART_UFLOAT, &hf_020_RE_DA_07_GH, NULL };
static const FieldPart *I020_RE_DA_07_PARTS[] = { &I020_RE_DA_07_GH, NULL };
static const FieldPart I020_RE_DA_08_TA = { 8, 0.1, FIELD_PART_UFLOAT, &hf_020_RE_DA_08_TA, NULL };
static const FieldPart *I020_RE_DA_08_PARTS[] = { &I020_RE_DA_08_TA, NULL };
static const FieldPart I020_RE_DA_09_MC = { 8, 0.1, FIELD_PART_UFLOAT, &hf_020_RE_DA_09_MC, NULL };
static const FieldPart *I020_RE_DA_09_PARTS[] = { &I020_RE_DA_09_MC, NULL };
static const FieldPart I020_RE_DA_10_MSSC = { 8, 0.1, FIELD_PART_UFLOAT, &hf_020_RE_DA_10_MSSC, NULL };
static const FieldPart *I020_RE_DA_10_PARTS[] = { &I020_RE_DA_10_MSSC, NULL };
static const FieldPart I020_RE_DA_11_ARC = { 8, 0.1, FIELD_PART_UFLOAT, &hf_020_RE_DA_11_ARC, NULL };
static const FieldPart *I020_RE_DA_11_PARTS[] = { &I020_RE_DA_11_ARC, NULL };
static const FieldPart I020_RE_DA_12_AIC = { 8, 0.1, FIELD_PART_UFLOAT, &hf_020_RE_DA_12_AIC, NULL };
static const FieldPart *I020_RE_DA_12_PARTS[] = { &I020_RE_DA_12_AIC, NULL };
static const FieldPart I020_RE_DA_13_M2 = { 8, 0.1, FIELD_PART_UFLOAT, &hf_020_RE_DA_13_M2, NULL };
static const FieldPart *I020_RE_DA_13_PARTS[] = { &I020_RE_DA_13_M2, NULL };
static const FieldPart I020_RE_DA_14_M1 = { 8, 0.1, FIELD_PART_UFLOAT, &hf_020_RE_DA_14_M1, NULL };
static const FieldPart *I020_RE_DA_14_PARTS[] = { &I020_RE_DA_14_M1, NULL };
static const FieldPart I020_RE_DA_15_ARA = { 8, 0.1, FIELD_PART_UFLOAT, &hf_020_RE_DA_15_ARA, NULL };
static const FieldPart *I020_RE_DA_15_PARTS[] = { &I020_RE_DA_15_ARA, NULL };
static const FieldPart I020_RE_DA_16_VI = { 8, 0.1, FIELD_PART_UFLOAT, &hf_020_RE_DA_16_VI, NULL };
static const FieldPart *I020_RE_DA_16_PARTS[] = { &I020_RE_DA_16_VI, NULL };
static const FieldPart I020_RE_DA_17_MSG = { 8, 0.1, FIELD_PART_UFLOAT, &hf_020_RE_DA_17_MSG, NULL };
static const FieldPart *I020_RE_DA_17_PARTS[] = { &I020_RE_DA_17_MSG, NULL };

/* Items */
DIAG_OFF(pedantic)
static const AsterixField I020_010 = { FIXED, 2, 0, 0, &hf_020_010, IXXX_SAC_SIC, { NULL } };
static const AsterixField I020_020 = { FX, 1, 0, 0, &hf_020_020, I020_020_PARTS, { NULL } };
static const AsterixField I020_030 = { FX, 1, 0, 0, &hf_020_030, I020_030_PARTS, { NULL } };
static const AsterixField I020_041 = { FIXED, 8, 0, 0, &hf_020_041, I020_041_PARTS, { NULL } };
static const AsterixField I020_042 = { FIXED, 6, 0, 0, &hf_020_042, I020_042_PARTS, { NULL } };
static const AsterixField I020_050 = { FIXED, 2, 0, 0, &hf_020_050, I020_050_PARTS, { NULL } };
static const AsterixField I020_055 = { FIXED, 1, 0, 0, &hf_020_055, I020_055_PARTS, { NULL } };
static const AsterixField I020_070 = { FIXED, 2, 0, 0, &hf_020_070, I020_070_PARTS, { NULL } };
static const AsterixField I020_090 = { FIXED, 2, 0, 0, &hf_020_090, I020_090_PARTS, { NULL } };
static const AsterixField I020_100 = { FIXED, 4, 0, 0, &hf_020_100, I020_100_PARTS, { NULL } };
static const AsterixField I020_105 = { FIXED, 2, 0, 0, &hf_020_105, I020_105_PARTS, { NULL } };
static const AsterixField I020_110 = { FIXED, 2, 0, 0, &hf_020_110, I020_110_PARTS, { NULL } };
static const AsterixField I020_140 = { FIXED, 3, 0, 0, &hf_020_140, IXXX_TOD, { NULL } };
static const AsterixField I020_161 = { FIXED, 2, 0, 0, &hf_020_161, I020_161_PARTS, { NULL } };
static const AsterixField I020_170 = { FX, 1, 0, 0, &hf_020_170, I020_170_PARTS, { NULL } };
static const AsterixField I020_202 = { FIXED, 4, 0, 0, &hf_020_202, I020_202_PARTS, { NULL } };
static const AsterixField I020_210 = { FIXED, 2, 0, 0, &hf_020_210, I020_210_PARTS, { NULL } };
static const AsterixField I020_220 = { FIXED, 3, 0, 0, &hf_020_220, IXXX_AA_PARTS, { NULL } };
static const AsterixField I020_230 = { FIXED, 2, 0, 0, &hf_020_230, I020_230_PARTS, { NULL } };
static const AsterixField I020_245 = { FIXED, 7, 0, 0, &hf_020_245, I020_245_PARTS, { NULL } };
static const AsterixField I020_250 = { REPETITIVE, 8, 1, 0, &hf_020_250, IXXX_MB, { NULL } };
static const AsterixField I020_260 = { FIXED, 7, 0, 0, &hf_020_260, I020_260_PARTS, { NULL } };
static const AsterixField I020_300 = { FIXED, 1, 0, 0, &hf_020_300, I020_300_PARTS, { NULL } };
static const AsterixField I020_310 = { FIXED, 1, 0, 0, &hf_020_310, I020_310_PARTS, { NULL } };
static const AsterixField I020_400 = { REPETITIVE, 1, 1, 0, &hf_020_400, I020_400_PARTS, { NULL } };
static const AsterixField I020_500_01 = { FIXED, 6, 0, 0, &hf_020_500_01, I020_500_01_PARTS, { NULL } };
static const AsterixField I020_500_02 = { FIXED, 6, 0, 0, &hf_020_500_02, I020_500_02_PARTS, { NULL } };
static const AsterixField I020_500_03 = { FIXED, 2, 0, 0, &hf_020_500_03, I020_500_03_PARTS, { NULL } };
static const AsterixField I020_500 = { COMPOUND, 0, 0, 0, &hf_020_500, NULL, { &I020_500_01,
                                                                               &I020_500_02,
                                                                               &I020_500_03,
                                                                               NULL } };
static const AsterixField I020_RE_PA_01_DOP = { FIXED, 6, 0, 0, &hf_020_RE_PA_01, I020_RE_PA_01_DOP_PARTS, { NULL } };
static const AsterixField I020_RE_PA_02_SDC = { FIXED, 6, 0, 0, &hf_020_RE_PA_02, I020_RE_PA_02_SDC_PARTS, { NULL } };
static const AsterixField I020_RE_PA_03_SDH = { FIXED, 2, 0, 0, &hf_020_RE_PA_03, I020_RE_PA_03_SDH_PARTS, { NULL } };
static const AsterixField I020_RE_PA_04_SDW = { FIXED, 6, 0, 0, &hf_020_RE_PA_04, I020_RE_PA_04_SDW_PARTS, { NULL } };
static const AsterixField I020_RE_PA = { COMPOUND, 0, 0, 0, &hf_020_RE_PA, NULL, { &I020_RE_PA_01_DOP,
                                                                                   &I020_RE_PA_02_SDC,
                                                                                   &I020_RE_PA_03_SDH,
                                                                                   &I020_RE_PA_04_SDW,
                                                                                   NULL } };
static const AsterixField I020_RE_GVV = { FIXED, 4, 0, 0, &hf_020_RE_GVV, I020_RE_GVV_PARTS, { NULL } };
static const AsterixField I020_RE_GVA = { FIXED, 2, 0, 0, &hf_020_RE_GVA, I020_RE_GVA_PARTS, { NULL } };
static const AsterixField I020_RE_TRT = { FIXED, 3, 0, 0, &hf_020_RE_TRT, IXXX_TOD, { NULL } };
static const AsterixField I020_RE_DA_01 = { FIXED, 1, 0, 0, &hf_020_RE_DA_01, I020_RE_DA_01_PARTS, { NULL } };
static const AsterixField I020_RE_DA_02 = { FIXED, 1, 0, 0, &hf_020_RE_DA_02, I020_RE_DA_02_PARTS, { NULL } };
static const AsterixField I020_RE_DA_03 = { REPETITIVE, 2, 1, 0, &hf_020_RE_DA_03, I020_RE_DA_03_PARTS, { NULL } };
static const AsterixField I020_RE_DA_04 = { FIXED, 1, 0, 0, &hf_020_RE_DA_04, I020_RE_DA_04_PARTS, { NULL } };
static const AsterixField I020_RE_DA_05 = { FIXED, 1, 0, 0, &hf_020_RE_DA_05, I020_RE_DA_05_PARTS, { NULL } };
static const AsterixField I020_RE_DA_06 = { FIXED, 1, 0, 0, &hf_020_RE_DA_06, I020_RE_DA_06_PARTS, { NULL } };
static const AsterixField I020_RE_DA_07 = { FIXED, 1, 0, 0, &hf_020_RE_DA_07, I020_RE_DA_07_PARTS, { NULL } };
static const AsterixField I020_RE_DA_08 = { FIXED, 1, 0, 0, &hf_020_RE_DA_08, I020_RE_DA_08_PARTS, { NULL } };
static const AsterixField I020_RE_DA_09 = { FIXED, 1, 0, 0, &hf_020_RE_DA_09, I020_RE_DA_09_PARTS, { NULL } };
static const AsterixField I020_RE_DA_10 = { FIXED, 1, 0, 0, &hf_020_RE_DA_10, I020_RE_DA_10_PARTS, { NULL } };
static const AsterixField I020_RE_DA_11 = { FIXED, 1, 0, 0, &hf_020_RE_DA_11, I020_RE_DA_11_PARTS, { NULL } };
static const AsterixField I020_RE_DA_12 = { FIXED, 1, 0, 0, &hf_020_RE_DA_12, I020_RE_DA_12_PARTS, { NULL } };
static const AsterixField I020_RE_DA_13 = { FIXED, 1, 0, 0, &hf_020_RE_DA_13, I020_RE_DA_13_PARTS, { NULL } };
static const AsterixField I020_RE_DA_14 = { FIXED, 1, 0, 0, &hf_020_RE_DA_14, I020_RE_DA_14_PARTS, { NULL } };
static const AsterixField I020_RE_DA_15 = { FIXED, 1, 0, 0, &hf_020_RE_DA_15, I020_RE_DA_15_PARTS, { NULL } };
static const AsterixField I020_RE_DA_16 = { FIXED, 1, 0, 0, &hf_020_RE_DA_16, I020_RE_DA_16_PARTS, { NULL } };
static const AsterixField I020_RE_DA_17 = { FIXED, 1, 0, 0, &hf_020_RE_DA_17, I020_RE_DA_17_PARTS, { NULL } };
static const AsterixField I020_RE_DA = { COMPOUND, 0, 0, 0, &hf_020_RE_DA, NULL, { &I020_RE_DA_01,
                                                                                   &I020_RE_DA_02,
                                                                                   &I020_RE_DA_03,
                                                                                   &I020_RE_DA_04,
                                                                                   &I020_RE_DA_05,
                                                                                   &I020_RE_DA_06,
                                                                                   &I020_RE_DA_07,
                                                                                   &I020_RE_DA_08,
                                                                                   &I020_RE_DA_09,
                                                                                   &I020_RE_DA_10,
                                                                                   &I020_RE_DA_11,
                                                                                   &I020_RE_DA_12,
                                                                                   &I020_RE_DA_13,
                                                                                   &I020_RE_DA_14,
                                                                                   &I020_RE_DA_15,
                                                                                   &I020_RE_DA_16,
                                                                                   &I020_RE_DA_17,
                                                                                   NULL } };
static const AsterixField I020_RE = { RE, 0, 0, 1, &hf_020_RE, NULL, { &I020_RE_PA,
                                                                       &I020_RE_GVV,
                                                                       &I020_RE_GVA,
                                                                       &I020_RE_TRT,
                                                                       &I020_RE_DA,
                                                                       NULL } };
static const AsterixField I020_SP = { SP, 0, 0, 1, &hf_020_SP, NULL, { NULL } };

static const AsterixField *I020_v1_9_uap[] = { &I020_010, &I020_020, &I020_140, &I020_041, &I020_042, &I020_161, &I020_170,
                                               &I020_070, &I020_202, &I020_090, &I020_100, &I020_220, &I020_245, &I020_110,
                                               &I020_105, &I020_210, &I020_300, &I020_310, &I020_500, &I020_400, &I020_250,
                                               &I020_230, &I020_260, &I020_030, &I020_055, &I020_050, &I020_RE,  &I020_SP,  NULL };
static const AsterixField **I020_v1_9[] = { I020_v1_9_uap, NULL };
static const AsterixField ***I020[] = { I020_v1_9 };
DIAG_ON(pedantic)

static const enum_val_t I020_versions[] = {
    { "I020_v1_9", "Version 1.9", 0 },
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
    { 0, "No capability for Trajectory Change Reports" },
    { 1, "Support for TC+0 reports only" },
    { 2, "Support for multiple TC reports" },
    { 3, "Reserved" },
    { 0, NULL }
};
static const value_string valstr_021_008_TS[] = {
    { 0, "No capability to support Target State Reports" },
    { 1, "Capable of supporting target State Reports" },
    { 0, NULL }
};
static const value_string valstr_021_008_ARV[] = {
    { 0, "No capability to generate ARV-reports" },
    { 1, "Capable of generate ARV-reports" },
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
    { 1, "Light aircraft <= 15500 lbs" },
    { 2, "15500 lbs < small aircraft <75000 lbs" },
    { 3, "75000 lbs < medium a/c < 300000 lbs" },
    { 4, "High Vortex Large" },
    { 5, "300000 lbs <= heavy aircraft" },
    { 6, "Highly manoeuvrable (5g acceleration capability) and high speed (>400 knots cruise)" },
    { 7, "Reserved" },
    { 8, "Reserved" },
    { 9, "Reserved" },
    { 10, "Rotocraft" },
    { 11, "Glider / sailplane" },
    { 12, "Lighter-than-air" },
    { 13, "Unmanned aerial vehicle" },
    { 14, "Space / transatmospheric vehicle" },
    { 15, "Ultralight / handglider / paraglider" },
    { 16, "Parachutist / skydiver" },
    { 17, "Reserved" },
    { 18, "Reserved" },
    { 19, "Reserved" },
    { 20, "Surface emergency vehicle" },
    { 21, "Surface service vehicle" },
    { 22, "Fixed ground or tethered obstruction" },
    { 23, "Cluster obstacle" },
    { 24, "Line obstacle" },
    { 0, NULL }
};
static const value_string valstr_021_020_v0_2_ECAT[] = {
    { 1, "Light aircraft <= 7000 kg" },
    { 2, "Reserved" },
    { 3, "7000 kg < medium aircraft  < 136000 kg" },
    { 4, "Reserved" },
    { 5, "136000 kg <= heavy aircraft" },
    { 6, "highly manoeuvrable (5g acceleration capability) and high speed (>400 knots cruise)" },
    { 7, "Reserved" },
    { 8, "Reserved" },
    { 9, "Reserved" },
    { 10, "Rotocraft" },
    { 11, "Glider / sailplane" },
    { 12, "Lighter-than-air" },
    { 13, "Unmanned aerial vehicle" },
    { 14, "Space / transatmospheric vehicle" },
    { 15, "Ultralight / handglider / paraglider" },
    { 16, "Parachutist / skydiver" },
    { 17, "Reserved" },
    { 18, "Reserved" },
    { 19, "Reserved" },
    { 20, "Surface emergency vehicle" },
    { 21, "Surface service vehicle" },
    { 22, "Fixed ground or tethered obstruction" },
    { 23, "Reserved" },
    { 24, "Reserved" },
    { 0, NULL }
};
static const FieldPart I021_020_ECAT = { 8, 1.0, FIELD_PART_UINT, &hf_021_020_ECAT, NULL };
static const FieldPart I021_020_v0_2_ECAT = { 8, 1.0, FIELD_PART_UINT, &hf_021_020_v0_2_ECAT, NULL };
static const FieldPart *I021_020_PARTS[] = { &I021_020_ECAT, NULL };
static const FieldPart *I021_020_PARTS_v0_2[] = { &I021_020_v0_2_ECAT, NULL };

/* Time of Day Accuracy */
static const FieldPart I021_032_TODA = { 8, 1.0/256.0, FIELD_PART_UFLOAT, &hf_021_032_TODA, NULL };
static const FieldPart *I021_032_PARTS[] = { &I021_032_TODA, NULL };


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
static const value_string valstr_021_040_v0_2_ATP[] = {
    { 0, "Non unique address" },
    { 1, "24-Bit ICAO address" },
    { 2, "Surface vehicle address" },
    { 3, "Anonymous address" },
    { 4, "Reserved for future use" },
    { 5, "Reserved for future use" },
    { 6, "Reserved for future use" },
    { 7, "Reserved for future use" },
    { 0, NULL}
};
static const value_string valstr_021_040_ARC[] = {
    { 0, "25 ft" },
    { 1, "100 ft" },
    { 2, "Unknown" },
    { 3, "Invalid" },
    { 0, NULL }
};
static const value_string valstr_021_040_v0_2_ARC[] = {
  { 0, "Unknown" },
  { 1, "25 ft" },
  { 2, "100 ft" },
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
static const value_string valstr_021_040_SPI[] = {
    { 0, "Absence of SPI" },
    { 1, "Special Position Identification" },
    { 0, NULL }
};
static const value_string valstr_021_040_CL[] = {
    { 0, "Report valid" },
    { 1, "Report suspect" },
    { 2, "No information" },
    { 3, "Reserved for future use" },
    { 0, NULL }
};
static const value_string valstr_021_040_LLC[] = {
    { 0, "Default" },
    { 1, "List Lookup failed" },
    { 0, NULL }
};
static const value_string valstr_021_040_IPC[] = {
    { 0, "Default" },
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
    { 0, "Default" },
    { 1, "Range Check failed" },
    { 0, NULL }
};
static const FieldPart I021_040_ATP = { 3, 1.0, FIELD_PART_UINT, &hf_021_040_ATP, NULL };
static const FieldPart I021_040_v0_2_ATP = { 3, 1.0, FIELD_PART_UINT, &hf_021_040_v0_2_ATP, NULL };
static const FieldPart I021_040_ARC = { 2, 1.0, FIELD_PART_UINT, &hf_021_040_ARC, NULL };
static const FieldPart I021_040_v0_2_ARC = { 2, 1.0, FIELD_PART_UINT, &hf_021_040_v0_2_ARC, NULL };
static const FieldPart I021_040_RC = { 1, 1.0, FIELD_PART_UINT, &hf_021_040_RC, NULL };
static const FieldPart I021_040_RAB = { 1, 1.0, FIELD_PART_UINT, &hf_021_040_RAB, NULL };
static const FieldPart I021_040_v0_2_RAB = { 1, 1.0, FIELD_PART_UINT, &hf_021_040_v0_2_RAB, NULL };
static const FieldPart I021_040_DCR = { 1, 1.0, FIELD_PART_UINT, &hf_021_040_DCR, NULL };
static const FieldPart I021_040_GBS = { 1, 1.0, FIELD_PART_UINT, &hf_021_040_GBS, NULL };
static const FieldPart I021_040_SIM = { 1, 1.0, FIELD_PART_UINT, &hf_021_040_SIM, NULL };
static const FieldPart I021_040_TST = { 1, 1.0, FIELD_PART_UINT, &hf_021_040_TST, NULL };
static const FieldPart I021_040_SAA = { 1, 1.0, FIELD_PART_UINT, &hf_021_040_SAA, NULL };
static const FieldPart I021_040_v0_2_SAA = { 1, 1.0, FIELD_PART_UINT, &hf_021_040_v0_2_SAA, NULL };
static const FieldPart I021_040_SPI = { 1, 1.0, FIELD_PART_UINT, &hf_021_040_SPI, NULL };
static const FieldPart I021_040_CL = { 2, 1.0, FIELD_PART_UINT, &hf_021_040_CL, NULL };
static const FieldPart I021_040_LLC = { 1, 1.0, FIELD_PART_UINT, &hf_021_040_LLC, NULL };
static const FieldPart I021_040_IPC = { 1, 1.0, FIELD_PART_UINT, &hf_021_040_IPC, NULL };
static const FieldPart I021_040_NOGO = { 1, 1.0, FIELD_PART_UINT, &hf_021_040_NOGO, NULL };
static const FieldPart I021_040_CPR = { 1, 1.0, FIELD_PART_UINT, &hf_021_040_CPR, NULL };
static const FieldPart I021_040_LDPJ = { 1, 1.0, FIELD_PART_UINT, &hf_021_040_LDPJ, NULL };
static const FieldPart I021_040_RCF = { 1, 1.0, FIELD_PART_UINT, &hf_021_040_RCF, NULL };
static const FieldPart *I021_040_PARTS[] = { &I021_040_ATP, &I021_040_ARC, &I021_040_RC, &I021_040_RAB, &IXXX_FX,
                                             &I021_040_DCR, &I021_040_GBS, &I021_040_SIM, &I021_040_TST, &I021_040_SAA, &I021_040_CL, &IXXX_FX,
                                             &IXXX_1bit_spare, &I021_040_LLC, &I021_040_IPC, &I021_040_NOGO, &I021_040_CPR, &I021_040_LDPJ, &I021_040_RCF, &IXXX_FX, NULL };
static const FieldPart *I021_040_PARTS_v2_1[] = { &I021_040_ATP, &I021_040_ARC, &I021_040_RC, &I021_040_RAB, &IXXX_FX,
                                             &I021_040_DCR, &I021_040_GBS, &I021_040_SIM, &I021_040_TST, &I021_040_SAA, &I021_040_CL, &IXXX_FX,
                                             &IXXX_2bit_spare, &I021_040_IPC, &I021_040_NOGO, &I021_040_CPR, &I021_040_LDPJ, &I021_040_RCF, &IXXX_FX, NULL };
static const FieldPart *I021_040_PARTS_v0_2[] = { &I021_040_DCR, &I021_040_GBS, &I021_040_SIM, &I021_040_TST, &I021_040_v0_2_RAB, &I021_040_v0_2_SAA,
                                             &I021_040_SPI, &IXXX_1bit_spare, &I021_040_v0_2_ATP, &I021_040_v0_2_ARC, &IXXX_3bit_spare, NULL };

/* Mode 3/A Code in Octal Representation */
static const value_string valstr_021_070_V[] = {
    { 0, "Code Validated" },
    { 1, "Code not validated" },
    { 0, NULL }
};
static const value_string valstr_021_070_G[] = {
    { 0, "Default" },
    { 1, "Garbled code" },
    { 0, NULL }
};
static const value_string valstr_021_070_L[] = {
    { 0, "Mode-3/A code derived during last update" },
    { 1, "Mode-3/A code not extracted during the last update" },
    { 0, NULL }
};
static const FieldPart I021_070_SQUAWK = { 12, 1.0, FIELD_PART_SQUAWK, &hf_021_070_SQUAWK, NULL };
static const FieldPart I021_070_V = { 1, 1.0, FIELD_PART_UINT, &hf_021_070_V, NULL };
static const FieldPart I021_070_G = { 1, 1.0, FIELD_PART_UINT, &hf_021_070_G, NULL };
static const FieldPart I021_070_L = { 1, 1.0, FIELD_PART_UINT, &hf_021_070_L, NULL };
static const FieldPart *I021_070_PARTS[] = { &IXXX_4bit_spare, &I021_070_SQUAWK, NULL };
static const FieldPart *I021_070_PARTS_v0_2[] = { &I021_070_V, &I021_070_G, &I021_070_L, &IXXX_1bit_spare, &I021_070_SQUAWK, NULL };

/* Time of Message Reception of Position-High Precision */
static const value_string valstr_021_074_FSI[] = {
    { 3, "Reserved" },
    { 2, "TOMRp whole seconds = (I021/073) Whole seconds - 1" },
    { 1, "TOMRp whole seconds = (I021/073) Whole seconds + 1" },
    { 0, "TOMRp whole seconds = (I021/073) Whole seconds" },
    { 0, NULL }
};
static const FieldPart I021_074_FSI = { 2, 1.0, FIELD_PART_UINT, &hf_021_074_FSI, NULL };
static const FieldPart I021_074_TOMRP = { 30, 1.0/1073741824.0, FIELD_PART_UFLOAT, &hf_021_074_TOMRP, NULL };
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
static const FieldPart I021_076_TOMRV = { 30, 1.0/1073741824.0, FIELD_PART_UFLOAT, &hf_021_076_TOMRV, NULL };
static const FieldPart *I021_076_PARTS[] = { &I021_076_FSI, &I021_076_TOMRV, NULL };

/* Quality Indicators */
static const value_string valstr_021_090_SILS[] = {
    { 0, "Measured per flight-hour" },
    { 1, "Measured per sample" },
    { 0, NULL }
};
static const value_string valstr_021_090_AC[] = {
    { 0, "Unknown" },
    { 1, "ACAS not operational" },
    { 2, "ACAS operational" },
    { 3, "Invalid"},
    { 0, NULL }
};
static const value_string valstr_021_090_MN[] = {
    { 0, "Unknown" },
    { 1, "Multiple navigational aids not operating" },
    { 2, "Multiple navigational aids operating" },
    { 3, "Invalid" },
    { 0, NULL }
};
static const value_string valstr_021_090_DC[] = {
    { 0, "Unknown" },
    { 1, "Differential correction" },
    { 2, "No differential correction" },
    { 3, "Invalid" },
    { 0, NULL }
};
static const FieldPart I021_090_NUCR_NACV = { 3, 1.0, FIELD_PART_UINT, &hf_021_090_NUCR_NACV, NULL };
static const FieldPart I021_090_NUCP_NIC = { 4, 1.0, FIELD_PART_UINT, &hf_021_090_NUCP_NIC, NULL };
static const FieldPart I021_090_NIC_BARO = { 1, 1.0, FIELD_PART_UINT, &hf_021_090_NIC_BARO, NULL };
static const FieldPart I021_090_SIL = { 2, 1.0, FIELD_PART_UINT, &hf_021_090_SIL, NULL };
static const FieldPart I021_090_NACP = { 4, 1.0, FIELD_PART_UINT, &hf_021_090_NACP, NULL };
static const FieldPart I021_090_SILS = { 1, 1.0, FIELD_PART_UINT, &hf_021_090_SILS, NULL };
static const FieldPart I021_090_SDA = { 2, 1.0, FIELD_PART_UINT, &hf_021_090_SDA, NULL };
static const FieldPart I021_090_GVA = { 2, 1.0, FIELD_PART_UINT, &hf_021_090_GVA, NULL };
static const FieldPart I021_090_PIC = { 4, 1.0, FIELD_PART_UINT, &hf_021_090_PIC, NULL };
static const FieldPart I021_090_AC = { 2, 1.0, FIELD_PART_UINT, &hf_021_090_AC, NULL };
static const FieldPart I021_090_MN = { 2, 1.0, FIELD_PART_UINT, &hf_021_090_MN, NULL };
static const FieldPart I021_090_DC = { 2, 1.0, FIELD_PART_UINT, &hf_021_090_DC, NULL };
static const FieldPart I021_090_PA = { 4, 1.0, FIELD_PART_UINT, &hf_021_090_PA, NULL };
static const FieldPart *I021_090_PARTS[] = { &I021_090_NUCR_NACV, &I021_090_NUCP_NIC, &IXXX_FX,
                                             &I021_090_NIC_BARO, &I021_090_SIL, &I021_090_NACP, &IXXX_FX,
                                             &IXXX_2bit_spare, &I021_090_SILS, &I021_090_SDA, &I021_090_GVA, &IXXX_FX,
                                             &I021_090_PIC, &IXXX_3bit_spare, &IXXX_FX, NULL };
static const FieldPart *I021_090_PARTS_v0_2[] = { &I021_090_AC, &I021_090_MN, &I021_090_DC, &IXXX_6bit_spare, &I021_090_PA, NULL };

/* Velocity Accuracy */
static const FieldPart I021_095_VUC = { 8, 1.0, FIELD_PART_UINT, &hf_021_095_VUC, NULL };
static const FieldPart *I021_095_PARTS[] = { &I021_095_VUC, NULL };

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
static const FieldPart I021_130_v0_2_LAT = { 32, 180.0/33554432.0, FIELD_PART_FLOAT, &hf_021_130_LAT, NULL };
static const FieldPart I021_130_LON = { 24, 180.0/8388608.0, FIELD_PART_FLOAT, &hf_021_130_LON, NULL };
static const FieldPart I021_130_v0_2_LON = { 32, 180.0/33554432.0, FIELD_PART_FLOAT, &hf_021_130_LON, NULL };
static const FieldPart *I021_130_PARTS[] = { &I021_130_LAT, &I021_130_LON, NULL };
static const FieldPart *I021_130_PARTS_v0_2[] = { &I021_130_v0_2_LAT, &I021_130_v0_2_LON, NULL };

/* High-Resolution Position in WGS-84 Co-ordinates */
static const FieldPart I021_131_LAT = { 32, 180.0/1073741824.0, FIELD_PART_FLOAT, &hf_021_131_LAT, NULL };
static const FieldPart I021_131_LON = { 32, 180.0/1073741824.0, FIELD_PART_FLOAT, &hf_021_131_LON, NULL };
static const FieldPart *I021_131_PARTS[] = { &I021_131_LAT, &I021_131_LON, NULL };

/* Signal Amplitude */
static const FieldPart I021_131_SAM = { 8, 1.0, FIELD_PART_UINT, &hf_021_131_SAM , NULL };
static const FieldPart *I021_131_PARTS_v0_2[] = { &I021_131_SAM , NULL };

/* Message Amplitude */
static const FieldPart I021_132_MAM = { 8, 1.0, FIELD_PART_FLOAT, &hf_021_132_MAM, NULL };
static const FieldPart *I021_132_PARTS[] = { &I021_132_MAM, NULL };

/* Geometric Height */
static const FieldPart I021_140_GH = { 16, 6.25, FIELD_PART_FLOAT, &hf_021_140_GH, NULL };
static const FieldPart I021_140_ALT = { 16, 6.25, FIELD_PART_FLOAT, &hf_021_140_ALT , NULL };
static const FieldPart *I021_140_PARTS[] = { &I021_140_GH, NULL };
static const FieldPart *I021_140_PARTS_v0_2[] = { &I021_140_ALT, NULL };

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
static const value_string valstr_021_146_v0_2_Source[] = {
    { 0, "Unknown" },
    { 1, "Aircraft Altitude" },
    { 2, "FCU/MSP Selected Altitude" },
    { 3, "FMS Selected Altitude" },
    { 0, NULL }
};
static const FieldPart I021_146_SAS = { 1, 1.0, FIELD_PART_UINT, &hf_021_146_SAS, NULL };
static const FieldPart I021_146_Source = { 2, 1.0, FIELD_PART_UINT, &hf_021_146_Source, NULL };
static const FieldPart I021_146_v0_2_Source = { 2, 1.0, FIELD_PART_UINT, &hf_021_146_v0_2_Source, NULL };
static const FieldPart I021_146_ALT = { 13, 25.0, FIELD_PART_FLOAT, &hf_021_146_ALT, NULL };
static const FieldPart *I021_146_PARTS[] = { &I021_146_SAS, &I021_146_Source, &I021_146_ALT, NULL };
static const FieldPart *I021_146_PARTS_v0_2[] = { &I021_146_SAS, &I021_146_v0_2_Source, &I021_146_ALT, NULL };

/* Final State Selected Altitude */
static const value_string valstr_021_148_MV[] = {
    { 0, "Not active or unknown" },
    { 1, "Active" },
    { 0, NULL }
};
static const value_string valstr_021_148_v0_2_MV[] = {
    { 0, "Not active" },
    { 1, "Active" },
    { 0, NULL }
};
static const value_string valstr_021_148_AH[] = {
    { 0, "Not active or unknown" },
    { 1, "Active" },
    { 0, NULL }
};
static const value_string valstr_021_148_v0_2_AH[] = {
    { 0, "Not active" },
    { 1, "Active" },
    { 0, NULL }
};
static const value_string valstr_021_148_AM[] = {
    { 0, "Not active or unknown" },
    { 1, "Active" },
    { 0, NULL }
};
static const value_string valstr_021_148_v0_2_AM[] = {
    { 0, "Not active" },
    { 1, "Active" },
    { 0, NULL }
};
static const FieldPart I021_148_MV = { 1, 1.0, FIELD_PART_UINT, &hf_021_148_MV, NULL };
static const FieldPart I021_148_v0_2_MV = { 1, 1.0, FIELD_PART_UINT, &hf_021_148_v0_2_MV, NULL };
static const FieldPart I021_148_AH = { 1, 1.0, FIELD_PART_UINT, &hf_021_148_AH, NULL };
static const FieldPart I021_148_v0_2_AH = { 1, 1.0, FIELD_PART_UINT, &hf_021_148_v0_2_AH, NULL };
static const FieldPart I021_148_AM = { 1, 1.0, FIELD_PART_UINT, &hf_021_148_AM, NULL };
static const FieldPart I021_148_v0_2_AM = { 1, 1.0, FIELD_PART_UINT, &hf_021_148_v0_2_AM, NULL };
static const FieldPart I021_148_ALT = { 13, 25.0, FIELD_PART_FLOAT, &hf_021_148_ALT, NULL };
static const FieldPart *I021_148_PARTS[] = { &I021_148_MV, &I021_148_AH, &I021_148_AM, &I021_148_ALT, NULL };
static const FieldPart *I021_148_PARTS_V0_2[] = { &I021_148_v0_2_MV, &I021_148_v0_2_AH, &I021_148_v0_2_AM, &I021_148_ALT, NULL };

/* Air Speed */
static const value_string valstr_021_150_IM[] = {
    { 0, "Air Speed = IAS" },
    { 1, "Air Speed = Mach" },
    { 0, NULL }
};
static const FieldPart I021_150_IM = { 1, 1.0, FIELD_PART_IAS_IM, &hf_021_150_IM, NULL };
static const FieldPart I021_150_ASPD = { 15, 1.0, FIELD_PART_IAS_ASPD, &hf_021_150_ASPD, NULL };
static const FieldPart *I021_150_PARTS[] = { &I021_150_IM, &I021_150_ASPD, NULL };

/* True Airspeed */
static const value_string valstr_021_151_RE[] = {
    { 0, "Value in defined range" },
    { 1, "Value exceeds defined range" },
    { 0, NULL }
};
static const FieldPart I021_151_RE = { 1, 1.0, FIELD_PART_UINT, &hf_021_151_RE, NULL };
static const FieldPart I021_151_TASPD = { 15, 1.0, FIELD_PART_UFLOAT, &hf_021_151_TASPD, NULL };
static const FieldPart I021_151_v0_2_TASPD = { 16, 1.0, FIELD_PART_UFLOAT, &hf_021_151_TASPD, NULL };
static const FieldPart *I021_151_PARTS[] = { &I021_151_RE, &I021_151_TASPD, NULL };
static const FieldPart *I021_151_PARTS_v0_2[] = { &I021_151_v0_2_TASPD, NULL };

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
static const FieldPart I021_155_v0_2_BVR = { 16, 6.25, FIELD_PART_FLOAT, &hf_021_155_BVR, NULL };
static const FieldPart *I021_155_PARTS[] = { &I021_155_RE, &I021_155_BVR, NULL };
static const FieldPart *I021_155_PARTS_v0_2[] = { &I021_155_v0_2_BVR, NULL };

/* Geometric Vertical Rate */
static const value_string valstr_021_157_RE[] = {
    { 0, "Value in defined range" },
    { 1, "Value exceeds defined range" },
    { 0, NULL }
};
static const FieldPart I021_157_RE = { 1, 1.0, FIELD_PART_UINT, &hf_021_157_RE, NULL };
static const FieldPart I021_157_GVR = { 15, 6.25, FIELD_PART_FLOAT, &hf_021_157_GVR, NULL };
static const FieldPart I021_157_v0_2_GVR = { 16, 6.25, FIELD_PART_FLOAT, &hf_021_157_GVR, NULL };
static const FieldPart *I021_157_PARTS[] = { &I021_157_RE, &I021_157_GVR, NULL };
static const FieldPart *I021_157_PARTS_v0_2[] = { &I021_157_v0_2_GVR, NULL };

/* Airborne Ground Vector */
static const value_string valstr_021_160_RE[] = {
    { 0, "Value in defined range" },
    { 1, "Value exceeds defined range" },
    { 0, NULL }
};
static const FieldPart I021_160_RE = { 1, 1.0, FIELD_PART_UINT, &hf_021_160_RE, NULL };
static const FieldPart I021_160_GSPD = { 15, 1.0/16384.0, FIELD_PART_UFLOAT, &hf_021_160_GSPD, NULL };
static const FieldPart I021_160_v0_2_GSPD = { 16, 1.0/16384.0, FIELD_PART_UFLOAT, &hf_021_160_GSPD, NULL };
static const FieldPart I021_160_TA = { 16, 360.0/65536.0, FIELD_PART_UFLOAT, &hf_021_160_TA, NULL };
static const FieldPart *I021_160_PARTS[] = { &I021_160_RE, &I021_160_GSPD, &I021_160_TA, NULL };
static const FieldPart *I021_160_PARTS_v0_2[] = { &I021_160_v0_2_GSPD, &I021_160_TA, NULL };

/* Track Number */
static const FieldPart I021_161_TN = { 12, 1.0, FIELD_PART_UINT, &hf_021_161_TN, NULL };
static const FieldPart *I021_161_PARTS[] = { &IXXX_4bit_spare, &I021_161_TN, NULL };

/* Track Angle Rate */
static const value_string valstr_021_165_TI[] = {
    { 0, "Not available" },
    { 1, "Left" },
    { 2, "Right" },
    { 3, "Straight" },
    { 0, NULL }
};
static const FieldPart I021_165_TAR = { 10, 1.0/32.0, FIELD_PART_FLOAT, &hf_021_165_TAR, NULL };
static const FieldPart I021_165_TI = { 2, 1.0, FIELD_PART_UINT, &hf_021_165_TI, NULL };
static const FieldPart I021_165_ROT = { 7, 1.0/4.0, FIELD_PART_UINT, &hf_021_165_ROT, NULL };
static const FieldPart *I021_165_PARTS[] = { &IXXX_6bit_spare, &I021_165_TAR, NULL };
static const FieldPart *I021_165_PARTS_v0_2[] = { &I021_165_TI, &IXXX_5bit_spare, &IXXX_FX,
                                                  &I021_165_ROT, &IXXX_FX, NULL };

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
static const value_string valstr_021_200_ME[] = {
    { 0, "No military emergency" },
    { 1, "Military emergency" },
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
static const value_string valstr_021_200_TS[] = {
    { 0, "No emergency / not reported" },
    { 1, "General emergency" },
    { 2, "Lifeguard / medical" },
    { 3, "Minimum fuel" },
    { 4, "No communications" },
    { 5, "Unlawful interference" },
    { 0, NULL }
};
static const FieldPart I021_200_ICF = { 1, 1.0, FIELD_PART_UINT, &hf_021_200_ICF, NULL };
static const FieldPart I021_200_LNAV = { 1, 1.0, FIELD_PART_UINT, &hf_021_200_LNAV, NULL };
static const FieldPart I021_200_ME = { 1, 1.0, FIELD_PART_UINT, &hf_021_200_ME, NULL };
static const FieldPart I021_200_PS = { 3, 1.0, FIELD_PART_UINT, &hf_021_200_PS, NULL };
static const FieldPart I021_200_SS = { 2, 1.0, FIELD_PART_UINT, &hf_021_200_SS, NULL };
static const FieldPart I021_200_TS = { 8, 1.0, FIELD_PART_UINT, &hf_021_200_TS, NULL };
static const FieldPart *I021_200_PARTS[] = { &I021_200_ICF, &I021_200_LNAV, &I021_200_ME, &I021_200_PS, &I021_200_SS, NULL };
static const FieldPart *I021_200_PARTS_v2_1[] = { &I021_200_ICF, &I021_200_LNAV, &I021_200_PS, &I021_200_SS, NULL };
static const FieldPart *I021_200_PARTS_v0_2[] = { &I021_200_TS, NULL };

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
static const value_string valstr_021_210_DTI[] = {
    { 0, "Unknown" },
    { 1, "Aircraft equiped with CDTI" },
    { 0, NULL }
};
static const value_string valstr_021_210_MDS[] = {
    { 0, "Not used" },
    { 1, "Used" },
    { 0, NULL }
};
static const value_string valstr_021_210_UAT[] = {
    { 0, "Not used" },
    { 1, "Used" },
    { 0, NULL }
};
static const value_string valstr_021_210_VDL[] = {
    { 0, "Not used" },
    { 1, "Used" },
    { 0, NULL }
};
static const value_string valstr_021_210_OTR[] = {
    { 0, "Not used" },
    { 1, "Used" },
    { 0, NULL }
};
static const FieldPart I021_210_VNS = { 1, 1.0, FIELD_PART_UINT, &hf_021_210_VNS, NULL };
static const FieldPart I021_210_VN = { 3, 1.0, FIELD_PART_UINT, &hf_021_210_VN, NULL };
static const FieldPart I021_210_LTT = { 2, 1.0, FIELD_PART_UINT, &hf_021_210_LTT, NULL };
static const FieldPart I021_210_DTI = { 1, 1.0, FIELD_PART_UINT, &hf_021_210_DTI, NULL };
static const FieldPart I021_210_MDS = { 1, 1.0, FIELD_PART_UINT, &hf_021_210_MDS, NULL };
static const FieldPart I021_210_UAT = { 1, 1.0, FIELD_PART_UINT, &hf_021_210_UAT, NULL };
static const FieldPart I021_210_OTR = { 1, 1.0, FIELD_PART_UINT, &hf_021_210_OTR, NULL };
static const FieldPart I021_210_VDL = { 1, 1.0, FIELD_PART_UINT, &hf_021_210_VDL, NULL };
static const FieldPart *I021_210_PARTS[] = { &I021_210_VNS, &I021_210_VN, &I021_210_LTT, NULL };
static const FieldPart *I021_210_PARTS_v0_2[] = { &IXXX_3bit_spare, &I021_210_DTI, &I021_210_MDS, &I021_210_UAT,
                                                  &I021_210_VDL, &I021_210_OTR, NULL };

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
static const FieldPart I021_271_LW_v2_1 = { 4, 1.0, FIELD_PART_UINT, &hf_021_271_LW_v2_1, NULL };
static const FieldPart *I021_271_PARTS[] = { &IXXX_2bit_spare, &I021_271_POA, &I021_271_CDTIS, &I021_271_B2low, &I021_271_RAS, &I021_271_IDENT, &IXXX_FX,
                                             &I021_271_LW, &IXXX_3bit_spare, &IXXX_FX, NULL };
static const FieldPart *I021_271_PARTS_v2_1[] = { &IXXX_2bit_spare, &I021_271_POA, &I021_271_CDTIS, &I021_271_B2low, &I021_271_RAS, &I021_271_IDENT, &IXXX_FX,
                                                  &IXXX_4bit_spare, &I021_271_LW_v2_1, NULL };

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

/* Barometric Pressure Setting 'BPS' */
static const FieldPart I021_RE_BPS_BPS = { 12, 0.1, FIELD_PART_UFLOAT, &hf_021_RE_BPS_BPS, NULL };
static const FieldPart *I021_RE_BPS_PARTS[] = { &IXXX_4bit_spare, &I021_RE_BPS_BPS, NULL };

/* Selected Heading 'SelH' */
static const value_string valstr_021_RE_SelH_HRD[] = {
    { 0, "True North" },
    { 1, "Magnetic North" },
    { 0, NULL }
};
static const value_string valstr_021_RE_SelH_Stat[] = {
    { 0, "Data is either unavailable or invalid" },
    { 1, "Data is available and valid" },
    { 0, NULL }
};
static const FieldPart I021_RE_SelH_HRD = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_SelH_HRD, NULL };
static const FieldPart I021_RE_SelH_Stat = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_SelH_Stat, NULL };
static const FieldPart I021_RE_SelH_SelH = { 10, 360.0/512.0, FIELD_PART_UFLOAT, &hf_021_RE_SelH_SelH, NULL };
static const FieldPart *I021_RE_SelH_PARTS[] = { &IXXX_4bit_spare, &I021_RE_SelH_HRD, &I021_RE_SelH_Stat, &I021_RE_SelH_SelH, NULL };

/* Navigation Mode 'NAV' */
static const value_string valstr_021_RE_NAV_AP[] = {
    { 0, "Autopilot disengaged" },
    { 1, "Autopilot engaged" },
    { 0, NULL }
};
static const value_string valstr_021_RE_NAV_VN[] = {
    { 0, "VNAV Inactive" },
    { 1, "VNAV Active (Vertical Navigation)" },
    { 0, NULL }
};
static const value_string valstr_021_RE_NAV_AH[] = {
    { 0, "Altitude Hold disengaged" },
    { 1, "Altitude Hold engaged" },
    { 0, NULL }
};
static const value_string valstr_021_RE_NAV_AM[] = {
    { 0, "Approach Mode inactive" },
    { 1, "Approach Mode active" },
    { 0, NULL }
};
static const FieldPart I021_RE_NAV_AP = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_NAV_AP, NULL };
static const FieldPart I021_RE_NAV_VN = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_NAV_VN, NULL };
static const FieldPart I021_RE_NAV_AH = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_NAV_AH, NULL };
static const FieldPart I021_RE_NAV_AM = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_NAV_AM, NULL };
static const FieldPart *I021_RE_NAV_PARTS[] = { &I021_RE_NAV_AP, &I021_RE_NAV_VN, &I021_RE_NAV_AH, &I021_RE_NAV_AM, &IXXX_4bit_spare, NULL };

/* GPS Antenna Offset 'GAO' */
static const FieldPart I021_RE_GAO_GAO = { 8, 1.0, FIELD_PART_UINT, &hf_021_RE_GAO_GAO, NULL };
static const FieldPart *I021_RE_GAO_PARTS[] = { &I021_RE_GAO_GAO, NULL };

/* Surface Ground Vector 'SGV' */
static const value_string valstr_021_RE_SGV_STP[] = {
    { 0, "Aircraft has not stopped" },
    { 1, "Aircraft has stopped" },
    { 0, NULL }
};
static const value_string valstr_021_RE_SGV_HTS[] = {
    { 0, "Heading/Ground Track data is not valid" },
    { 1, "Heading/Ground Track data is valid" },
    { 0, NULL }
};
static const value_string valstr_021_RE_SGV_HTT[] = {
    { 0, "Heading data provided" },
    { 1, "Ground Track provided" },
    { 0, NULL }
};
static const value_string valstr_021_RE_SGV_HRD[] = {
    { 0, "True North" },
    { 1, "Magnetic North" },
    { 0, NULL }
};
static const FieldPart I021_RE_SGV_STP = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_SGV_STP, NULL };
static const FieldPart I021_RE_SGV_HTS = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_SGV_HTS, NULL };
static const FieldPart I021_RE_SGV_HTT = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_SGV_HTT, NULL };
static const FieldPart I021_RE_SGV_HRD = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_SGV_HRD, NULL };
static const FieldPart I021_RE_SGV_GSS = { 11, 1.0/8.0, FIELD_PART_UFLOAT, &hf_021_RE_SGV_GSS, NULL };
static const FieldPart I021_RE_SGV_HGT = { 7, 360.0/128.0, FIELD_PART_UFLOAT, &hf_021_RE_SGV_HGT, NULL };
static const FieldPart *I021_RE_SGV_PARTS[] = { &I021_RE_SGV_STP, &I021_RE_SGV_HTS, &I021_RE_SGV_HTT,
                                                &I021_RE_SGV_HRD, &I021_RE_SGV_GSS, &IXXX_FX,
                                                &I021_RE_SGV_HGT, &IXXX_FX, NULL };

/* Aircraft Status 'STA' */
static const value_string valstr_021_RE_STA_ES[] = {
    { 0, "Target is not 1090 ES IN capable" },
    { 1, "Target is 1090 ES IN capable" },
    { 0, NULL }
};
static const value_string valstr_021_RE_STA_UAT[] = {
    { 0, "Target is not UAT IN capable" },
    { 1, "Target is UAT IN capable" },
    { 0, NULL }
};
static const FieldPart I021_RE_STA_ES = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_STA_ES, NULL };
static const FieldPart I021_RE_STA_UAT = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_STA_UAT, NULL };
static const FieldPart *I021_RE_STA_PARTS[] = { &I021_RE_STA_ES, &I021_RE_STA_UAT, &IXXX_5bit_spare, &IXXX_FX, NULL };

/* True North Heading 'TNH' */
static const FieldPart I021_RE_TNH_TNH = { 16, 360.0/65536.0, FIELD_PART_UFLOAT, &hf_021_RE_TNH_TNH, NULL };
static const FieldPart *I021_RE_TNH_PARTS[] = { &I021_RE_TNH_TNH, NULL };

/* Military Extended Squitter 'MES' */

/* Mode 5 Summary */
static const value_string valstr_021_RE_MES_01_M5[] = {
    { 0, "No Mode 5 interrogation" },
    { 1, "Mode 5 interrogation" },
    { 0, NULL }
};
static const value_string valstr_021_RE_MES_01_ID[] = {
    { 0, "No authenticated Mode 5 ID reply/report" },
    { 1, "Authenticated Mode 5 ID reply/report" },
    { 0, NULL }
};
static const value_string valstr_021_RE_MES_01_DA[] = {
    { 0, "No authenticated Mode 5 Data reply/report" },
    { 1, "Authenticated Mode 5 Data reply/report (i.e any valid Mode 5 reply type other than ID)" },
    { 0, NULL }
};
static const value_string valstr_021_RE_MES_01_M1[] = {
    { 0, "Mode 1 code not present or not from Mode 5 reply/report" },
    { 1, "Mode 1 code from Mode 5 reply/report" },
    { 0, NULL }
};
static const value_string valstr_021_RE_MES_01_M2[] = {
    { 0, "Mode 2 code not present or not from Mode 5 reply/report" },
    { 1, "Mode 2 code from Mode 5 reply/report" },
    { 0, NULL }
};
static const value_string valstr_021_RE_MES_01_M3[] = {
    { 0, "Mode 3 code not present or not from Mode 5 reply/report" },
    { 1, "Mode 3 code from Mode 5 reply/report" },
    { 0, NULL }
};
static const value_string valstr_021_RE_MES_01_MC[] = {
    { 0, "Flightlevel not present or not from Mode 5 reply/report" },
    { 1, "Flightlevel from Mode 5 reply/report" },
    { 0, NULL }
};
static const value_string valstr_021_RE_MES_01_PO[] = {
    { 0, "Position not from Mode 5 report (ADS-B report)" },
    { 1, "Position from Mode 5 report" },
    { 0, NULL }
};
static const FieldPart I021_RE_MES_01_M5 = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_MES_01_M5, NULL };
static const FieldPart I021_RE_MES_01_ID = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_MES_01_ID, NULL };
static const FieldPart I021_RE_MES_01_DA = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_MES_01_DA, NULL };
static const FieldPart I021_RE_MES_01_M1 = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_MES_01_M1, NULL };
static const FieldPart I021_RE_MES_01_M2 = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_MES_01_M2, NULL };
static const FieldPart I021_RE_MES_01_M3 = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_MES_01_M3, NULL };
static const FieldPart I021_RE_MES_01_MC = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_MES_01_MC, NULL };
static const FieldPart I021_RE_MES_01_PO = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_MES_01_PO, NULL };
static const FieldPart *I021_RE_MES_01_PARTS[] = { &I021_RE_MES_01_M5,
                                                    &I021_RE_MES_01_ID,
                                                    &I021_RE_MES_01_DA,
                                                    &I021_RE_MES_01_M1,
                                                    &I021_RE_MES_01_M2,
                                                    &I021_RE_MES_01_M3,
                                                    &I021_RE_MES_01_MC,
                                                    &I021_RE_MES_01_PO,
                                                    NULL };

/* Mode 5 PIN /National Origin */
static const FieldPart I021_RE_MES_02_PIN = { 14, 1.0, FIELD_PART_UINT, &hf_021_RE_MES_02_PIN, NULL };
static const FieldPart I021_RE_MES_02_NO = { 11, 1.0, FIELD_PART_UINT, &hf_021_RE_MES_02_NO, NULL };
static const FieldPart *I021_RE_MES_02_PARTS[] = { &IXXX_2bit_spare,
                                                    &I021_RE_MES_02_PIN,
                                                    &IXXX_5bit_spare,
                                                    &I021_RE_MES_02_NO,
                                                    NULL };

/* Extended Mode 1 Code in Octal Representation */
static const value_string valstr_021_RE_MES_03_V[] = {
    { 0, "Code validated" },
    { 1, "Code not validated" },
    { 0, NULL }
};
static const value_string valstr_021_RE_MES_03_L[] = {
    { 0, "Mode 1 code as derived from the report of the transponder" },
    { 1, "Smoothed Mode 1 code as provided by a local tracker" },
    { 0, NULL }
};
static const FieldPart I021_RE_MES_03_V = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_MES_03_V, NULL };
static const FieldPart I021_RE_MES_03_L = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_MES_03_L, NULL };
static const FieldPart I021_RE_MES_03_SQUAWK = { 12, 1.0, FIELD_PART_UINT, &hf_021_RE_MES_03_SQUAWK, NULL };
static const FieldPart *I021_RE_MES_03_PARTS[] = { &I021_RE_MES_03_V,
                                                    &IXXX_1bit_spare,
                                                    &I021_RE_MES_03_L,
                                                    &IXXX_1bit_spare,
                                                    &I021_RE_MES_03_SQUAWK,
                                                    NULL };

/* X Pulse Presence */
static const value_string valstr_021_RE_MES_04_XP[] = {
    { 0, "X-Pulse not present" },
    { 1, "X-pulse present" },
    { 0, NULL }
};
static const value_string valstr_021_RE_MES_04_X5[] = {
    { 0, "X-pulse set to zero or no authenticated Data reply or Report received" },
    { 1, "X-pulse set to one (present)" },
    { 0, NULL }
};
static const value_string valstr_021_RE_MES_04_XC[] = {
    { 0, "X-pulse set to zero or no Mode C reply" },
    { 1, "X-pulse set to one (present)" },
    { 0, NULL }
};
static const value_string valstr_021_RE_MES_04_X3[] = {
    { 0, "X-pulse set to zero or no Mode 3/A reply" },
    { 1, "X-pulse set to one (present)" },
    { 0, NULL }
};
static const value_string valstr_021_RE_MES_04_X2[] = {
    { 0, "X-pulse set to zero or no Mode 2 reply" },
    { 1, "X-pulse set to one (present)" },
    { 0, NULL }
};
static const value_string valstr_021_RE_MES_04_X1[] = {
    { 0, "X-pulse set to zero or no Mode 1 reply" },
    { 1, "X-pulse set to one (present)" },
    { 0, NULL }
};
static const FieldPart I021_RE_MES_04_XP = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_MES_04_XP, NULL };
static const FieldPart I021_RE_MES_04_X5 = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_MES_04_X5, NULL };
static const FieldPart I021_RE_MES_04_XC = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_MES_04_XC, NULL };
static const FieldPart I021_RE_MES_04_X3 = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_MES_04_X3, NULL };
static const FieldPart I021_RE_MES_04_X2 = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_MES_04_X2, NULL };
static const FieldPart I021_RE_MES_04_X1 = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_MES_04_X1, NULL };
static const FieldPart *I021_RE_MES_04_PARTS[] = { &IXXX_2bit_spare,
                                                   &I021_RE_MES_04_XP,
                                                   &I021_RE_MES_04_X5,
                                                   &I021_RE_MES_04_XC,
                                                   &I021_RE_MES_04_X3,
                                                   &I021_RE_MES_04_X2,
                                                   &I021_RE_MES_04_X1,
                                                   NULL };

/* Figure of Merit */
static const FieldPart I021_RE_MES_05_FOM = { 5, 1.0, FIELD_PART_UINT, &hf_021_RE_MES_05_FOM, NULL };
static const FieldPart *I021_RE_MES_05_PARTS[] = { &IXXX_3bit_spare,
                                                    &I021_RE_MES_05_FOM,
                                                    NULL };

/* Mode 2 Code in Octal Representation */
static const value_string valstr_021_RE_MES_06_V[] = {
    { 0, "Code validated" },
    { 1, "Code not validated" },
    { 0, NULL }
};
static const value_string valstr_021_RE_MES_06_L[] = {
    { 0, "Mode-2 code as derived from the reply of the transponder" },
    { 1, "Smoothed Mode-2 code as provided by a local tracker" },
    { 0, NULL }
};
static const FieldPart I021_RE_MES_06_V = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_MES_06_V, NULL };
static const FieldPart I021_RE_MES_06_L = { 1, 1.0, FIELD_PART_UINT, &hf_021_RE_MES_06_L, NULL };
static const FieldPart I021_RE_MES_06_SQUAWK = { 12, 1.0, FIELD_PART_UINT, &hf_021_RE_MES_06_SQUAWK, NULL };
static const FieldPart *I021_RE_MES_06_PARTS[] = { &I021_RE_MES_06_V,
                                                    &IXXX_1bit_spare,
                                                    &I021_RE_MES_06_L,
                                                    &IXXX_1bit_spare,
                                                    &I021_RE_MES_06_SQUAWK,
                                                    NULL };


/* Items */
DIAG_OFF_PEDANTIC
static const AsterixField I021_008 = { FIXED, 1, 0, 0, &hf_021_008, I021_008_PARTS, { NULL } };
static const AsterixField I021_010 = { FIXED, 2, 0, 0, &hf_021_010, IXXX_SAC_SIC, { NULL } };
static const AsterixField I021_015 = { FIXED, 1, 0, 0, &hf_021_015, I021_015_PARTS, { NULL } };
static const AsterixField I021_016 = { FIXED, 1, 0, 0, &hf_021_016, I021_016_PARTS, { NULL } };
static const AsterixField I021_020 = { FIXED, 1, 0, 0, &hf_021_020, I021_020_PARTS, { NULL } };
static const AsterixField I021_020_v0_2 = { FIXED, 1, 0, 0, &hf_021_020, I021_020_PARTS_v0_2, { NULL }};
static const AsterixField I021_030 = { FIXED, 3, 0, 0, &hf_021_030, IXXX_TOD, { NULL } };
static const AsterixField I021_032 = { FIXED, 1, 0, 0, &hf_021_032, I021_032_PARTS, { NULL } };
static const AsterixField I021_040 = { FX, 1, 0, 0, &hf_021_040, I021_040_PARTS, { NULL } };
static const AsterixField I021_040_v2_1 = { FX, 1, 0, 0, &hf_021_040, I021_040_PARTS_v2_1, { NULL } };
static const AsterixField I021_040_v0_2 = { FIXED, 2, 0, 0, &hf_021_040, I021_040_PARTS_v0_2, { NULL } };
static const AsterixField I021_070 = { FIXED, 2, 0, 0, &hf_021_070, I021_070_PARTS, { NULL } };
static const AsterixField I021_070_v0_2 = { FIXED, 2, 0, 0, &hf_021_070, I021_070_PARTS_v0_2, { NULL } };
static const AsterixField I021_071 = { FIXED, 3, 0, 0, &hf_021_071, IXXX_TOD, { NULL } };
static const AsterixField I021_072 = { FIXED, 3, 0, 0, &hf_021_072, IXXX_TOD, { NULL } };
static const AsterixField I021_073 = { FIXED, 3, 0, 0, &hf_021_073, IXXX_TOD, { NULL } };
static const AsterixField I021_074 = { FIXED, 4, 0, 0, &hf_021_074, I021_074_PARTS, { NULL } };
static const AsterixField I021_075 = { FIXED, 3, 0, 0, &hf_021_075, IXXX_TOD, { NULL } };
static const AsterixField I021_076 = { FIXED, 4, 0, 0, &hf_021_076, I021_076_PARTS, { NULL } };
static const AsterixField I021_077 = { FIXED, 3, 0, 0, &hf_021_077, IXXX_TOD, { NULL } };
static const AsterixField I021_080 = { FIXED, 3, 0, 0, &hf_021_080, IXXX_AA_PARTS, { NULL } };
static const AsterixField I021_090 = { FX, 1, 0, 0, &hf_021_090, I021_090_PARTS, { NULL } };
static const AsterixField I021_090_v0_2 = { FIXED, 2, 0, 0, &hf_021_090_v0_2, I021_090_PARTS_v0_2, { NULL } };
static const AsterixField I021_095 = { FIXED, 1, 0, 0, &hf_021_095, I021_095_PARTS, { NULL} };
static const AsterixField I021_110_01 = { FX, 1, 0, 0, &hf_021_110_01, I021_110_01_PARTS, { NULL } };
static const AsterixField I021_110_02 = { REPETITIVE, 15, 1, 0, &hf_021_110_02, I021_110_02_PARTS, { NULL } };
static const AsterixField I021_110 = { COMPOUND, 0, 0, 0, &hf_021_110, NULL, { &I021_110_01,
                                                                               &I021_110_02,
                                                                               NULL} };
static const AsterixField I021_130 = { FIXED, 6, 0, 0, &hf_021_130, I021_130_PARTS, { NULL } };
static const AsterixField I021_130_v0_2 = { FIXED, 8, 0, 0, &hf_021_130, I021_130_PARTS_v0_2, { NULL } };
static const AsterixField I021_131 = { FIXED, 8, 0, 0, &hf_021_131, I021_131_PARTS, { NULL } };
static const AsterixField I021_131_v0_2 = { FIXED, 1, 0, 0, &hf_021_131_v0_2, I021_131_PARTS_v0_2, { NULL } };
static const AsterixField I021_132 = { FIXED, 1, 0, 0, &hf_021_132, I021_132_PARTS, { NULL } };
static const AsterixField I021_140 = { FIXED, 2, 0, 0, &hf_021_140, I021_140_PARTS, { NULL } };
static const AsterixField I021_140_v0_2 = {FIXED, 2, 0, 0, &hf_021_140_v0_2, I021_140_PARTS_v0_2, { NULL } };
static const AsterixField I021_145 = { FIXED, 2, 0, 0, &hf_021_145, I021_145_PARTS, { NULL } };
static const AsterixField I021_146 = { FIXED, 2, 0, 0, &hf_021_146, I021_146_PARTS, { NULL } };
static const AsterixField I021_146_v0_2 = { FIXED, 2, 0, 0, &hf_021_146_v0_2, I021_146_PARTS_v0_2, { NULL }};
static const AsterixField I021_148 = { FIXED, 2, 0, 0, &hf_021_148, I021_148_PARTS, { NULL } };
static const AsterixField I021_148_v0_2 = { FIXED, 2, 0, 0, &hf_021_148, I021_148_PARTS_V0_2, { NULL } };
static const AsterixField I021_150 = { FIXED, 2, 0, 0, &hf_021_150, I021_150_PARTS, { NULL } };
static const AsterixField I021_151 = { FIXED, 2, 0, 0, &hf_021_151, I021_151_PARTS, { NULL } };
static const AsterixField I021_151_v0_2 = { FIXED, 2, 0, 0, &hf_021_151, I021_151_PARTS_v0_2, {NULL } };
static const AsterixField I021_152 = { FIXED, 2, 0, 0, &hf_021_152, I021_152_PARTS, { NULL } };
static const AsterixField I021_155 = { FIXED, 2, 0, 0, &hf_021_155, I021_155_PARTS, { NULL } };
static const AsterixField I021_155_v0_2 = { FIXED, 2, 0, 0, &hf_021_155, I021_155_PARTS_v0_2, { NULL } };
static const AsterixField I021_157 = { FIXED, 2, 0, 0, &hf_021_157, I021_157_PARTS, { NULL } };
static const AsterixField I021_157_v0_2 = { FIXED, 2, 0, 0, &hf_021_157, I021_157_PARTS_v0_2, { NULL } };
static const AsterixField I021_160 = { FIXED, 4, 0, 0, &hf_021_160, I021_160_PARTS, { NULL } };
static const AsterixField I021_160_v0_2 = { FIXED, 4, 0, 0, &hf_021_160_v0_2, I021_160_PARTS_v0_2, { NULL } };
static const AsterixField I021_161 = { FIXED, 2, 0, 0, &hf_021_161, I021_161_PARTS, { NULL } };
static const AsterixField I021_165 = { FIXED, 2, 0, 0, &hf_021_165, I021_165_PARTS, { NULL } };
static const AsterixField I021_165_v0_2 = { FX, 1, 0, 0, &hf_021_165_v0_2, I021_165_PARTS_v0_2, { NULL } };
static const AsterixField I021_170 = { FIXED, 6, 0, 0, &hf_021_170, IXXX_AI_PARTS, { NULL } };
static const AsterixField I021_200 = { FIXED, 1, 0, 0, &hf_021_200, I021_200_PARTS, { NULL } };
static const AsterixField I021_200_v2_1 = { FIXED, 1, 0, 0, &hf_021_200, I021_200_PARTS_v2_1, { NULL } };
static const AsterixField I021_200_v0_2 = { FIXED, 1, 0, 0, &hf_021_200, I021_200_PARTS_v0_2, { NULL } };
static const AsterixField I021_210 = { FIXED, 1, 0, 0, &hf_021_210, I021_210_PARTS, { NULL } };
static const AsterixField I021_210_v0_2 = { FIXED, 1, 0, 0, &hf_021_210_v0_2, I021_210_PARTS_v0_2, { NULL } };
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
static const AsterixField I021_271_v2_1 = { FX_1, 1, 0, 0, &hf_021_271, I021_271_PARTS_v2_1, { NULL } };
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
static const AsterixField I021_RE_BPS = { FIXED, 2, 0, 0, &hf_021_RE_BPS, I021_RE_BPS_PARTS, { NULL } };
static const AsterixField I021_RE_SelH = { FIXED, 2, 0, 0, &hf_021_RE_SelH, I021_RE_SelH_PARTS, { NULL } };
static const AsterixField I021_RE_NAV = { FIXED, 1, 0, 0, &hf_021_RE_NAV, I021_RE_NAV_PARTS, { NULL } };
static const AsterixField I021_RE_GAO = { FIXED, 1, 0, 0, &hf_021_RE_GAO, I021_RE_GAO_PARTS, { NULL } };
static const AsterixField I021_RE_SGV = { FX, 1, 0, 1, &hf_021_RE_SGV, I021_RE_SGV_PARTS, { NULL } };
static const AsterixField I021_RE_STA = { FX, 1, 0, 0, &hf_021_RE_STA, I021_RE_STA_PARTS, { NULL } };
static const AsterixField I021_RE_TNH = { FIXED, 2, 0, 0, &hf_021_RE_TNH, I021_RE_TNH_PARTS, { NULL } };
static const AsterixField I021_RE_MES_01 = { FX, 1, 0, 0, &hf_021_RE_MES_01, I021_RE_MES_01_PARTS, { NULL } };
static const AsterixField I021_RE_MES_02 = { FIXED, 4, 0, 0, &hf_021_RE_MES_02, I021_RE_MES_02_PARTS, { NULL } };
static const AsterixField I021_RE_MES_03 = { FIXED, 2, 0, 0, &hf_021_RE_MES_03, I021_RE_MES_03_PARTS, { NULL } };
static const AsterixField I021_RE_MES_04 = { FIXED, 1, 0, 0, &hf_021_RE_MES_04, I021_RE_MES_04_PARTS, { NULL } };
static const AsterixField I021_RE_MES_05 = { FIXED, 1, 0, 0, &hf_021_RE_MES_05, I021_RE_MES_05_PARTS, { NULL } };
static const AsterixField I021_RE_MES_06 = { FIXED, 2, 0, 0, &hf_021_RE_MES_06, I021_RE_MES_06_PARTS, { NULL } };
static const AsterixField I021_RE_MES = { COMPOUND, 0, 0, 0, &hf_021_RE_MES, NULL, { &I021_RE_MES_01,
                                                                                     &I021_RE_MES_02,
                                                                                     &I021_RE_MES_03,
                                                                                     &I021_RE_MES_04,
                                                                                     &I021_RE_MES_05,
                                                                                     &I021_RE_MES_06,
                                                                                     NULL } };
static const AsterixField I021_RE = { RE, 0, 0, 1, &hf_021_RE, NULL, { &I021_RE_BPS,
                                                                       &I021_RE_SelH,
                                                                       &I021_RE_NAV,
                                                                       &I021_RE_GAO,
                                                                       &I021_RE_SGV,
                                                                       &I021_RE_STA,
                                                                       &I021_RE_TNH,
                                                                       &I021_RE_MES,
                                                                       NULL } };
static const AsterixField I021_SP = { SP, 0, 0, 1, &hf_021_SP, NULL, { NULL } };

static const AsterixField *I021_v2_3_uap[] = { &I021_010, &I021_040, &I021_161, &I021_015, &I021_071, &I021_130, &I021_131,
                                               &I021_072, &I021_150, &I021_151, &I021_080, &I021_073, &I021_074, &I021_075,
                                               &I021_076, &I021_140, &I021_090, &I021_210, &I021_070, &I021_230, &I021_145,
                                               &I021_152, &I021_200, &I021_155, &I021_157, &I021_160, &I021_165, &I021_077,
                                               &I021_170, &I021_020, &I021_220, &I021_146, &I021_148, &I021_110, &I021_016,
                                               &I021_008, &I021_271, &I021_132, &I021_250, &I021_260, &I021_400, &I021_295,
                                               &IX_SPARE, &IX_SPARE, &IX_SPARE, &IX_SPARE, &IX_SPARE, &I021_RE,  &I021_SP, NULL };
static const AsterixField *I021_v2_1_uap[] = { &I021_010, &I021_040_v2_1, &I021_161, &I021_015, &I021_071, &I021_130, &I021_131,
                                               &I021_072, &I021_150, &I021_151, &I021_080, &I021_073, &I021_074, &I021_075,
                                               &I021_076, &I021_140, &I021_090, &I021_210, &I021_070, &I021_230, &I021_145,
                                               &I021_152, &I021_200_v2_1, &I021_155, &I021_157, &I021_160, &I021_165, &I021_077,
                                               &I021_170, &I021_020, &I021_220, &I021_146, &I021_148, &I021_110, &I021_016,
                                               &I021_008, &I021_271_v2_1, &I021_132, &I021_250, &I021_260, &I021_400, &I021_295,
                                               &IX_SPARE, &IX_SPARE, &IX_SPARE, &IX_SPARE, &IX_SPARE, &I021_RE,  &I021_SP, NULL };
static const AsterixField *I021_v0_26_uap[] = { &I021_010, &I021_040_v0_2, &I021_030, &I021_130_v0_2, &I021_080, &I021_140_v0_2, &I021_090_v0_2,
                                                &I021_210_v0_2, &I021_230, &I021_145, &I021_150, &I021_151_v0_2, &I021_152, &I021_155_v0_2,
                                                &I021_157_v0_2, &I021_160_v0_2, &I021_165_v0_2, &I021_170, &I021_095, &I021_032, &I021_200_v0_2,
                                                &I021_020_v0_2, &I021_220, &I021_146_v0_2, &I021_148_v0_2, &I021_110, &I021_070_v0_2, &I021_131_v0_2,
                                                &IX_SPARE, &IX_SPARE, &IX_SPARE, &IX_SPARE, &IX_SPARE, &I021_RE,  &I021_SP, NULL };
static const AsterixField *I021_v0_23_uap[] = { &I021_010, &I021_040_v0_2, &I021_030, &I021_130, &I021_080, &I021_140_v0_2, &I021_090_v0_2,
                                                &I021_210_v0_2, &I021_230, &I021_145, &I021_150, &I021_151_v0_2, &I021_152, &I021_155_v0_2,
                                                &I021_157_v0_2, &I021_160_v0_2, &I021_165_v0_2, &I021_170, &I021_095, &I021_032, &I021_200_v0_2,
                                                &I021_020_v0_2, &I021_220, &I021_146_v0_2, &I021_148_v0_2, &I021_110, &IX_SPARE, &IX_SPARE,
                                                &IX_SPARE, &IX_SPARE, &IX_SPARE, &IX_SPARE, &IX_SPARE, &I021_RE,  &I021_SP, NULL };
static const AsterixField **I021_v2_3[] = { I021_v2_3_uap, NULL };
static const AsterixField **I021_v2_1[] = { I021_v2_1_uap, NULL };
static const AsterixField **I021_v0_26[] = { I021_v0_26_uap, NULL };
static const AsterixField **I021_v0_23[] = { I021_v0_23_uap, NULL };
static const AsterixField ***I021[] = { I021_v2_3, I021_v2_1, I021_v0_26, I021_v0_23 };
DIAG_ON_PEDANTIC

static const enum_val_t I021_versions[] = {
    { "I021_v2_3", "Version 2.3", 0 },
    { "I021_v2_1", "Version 2.1", 1 },
    { "I021_v0_26", "Version 0.26", 2 },
    { "I021_v0_23", "Version 0.23", 3 },
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
    { 0, "Valid" },
    { 1, "Invalid" },
    { 0, NULL }
};
static const value_string valstr_023_100_SPO[] = {
    { 0, "No spoofing detected" },
    { 1, "Potential spoofing attack" },
    { 0, NULL }
};
static const value_string valstr_023_100_RN[] = {
    { 0, "Default" },
    { 1, "Track numbering has restarted" },
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
    { 2, "Reserved for future use" },
    { 3, "Reserved for future use" },
    { 4, "Reserved for future use" },
    { 5, "Reserved for future use" },
    { 6, "Reserved for future use" },
    { 7, "Reserved for future use" },
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
DIAG_OFF_PEDANTIC
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
DIAG_ON_PEDANTIC

static const enum_val_t I023_versions[] = {
    { "I023_v1_2", "Version 1.2", 0 },
    { NULL, NULL, 0 }
};

/* *********************** */
/*      Category 025       */
/* *********************** */
/* Fields */

/* Report Type */
static const value_string valstr_025_000_RT[] = {
    { 1, "Service and System Status report" },
    { 2, "Component Status report" },
    { 3, "Service Statistics report" },
    { 0, NULL }
};
static const value_string valstr_025_000_RG[] = {
    { 0, "Periodic Report" },
    { 1, "Event Driven Report" },
    { 0, NULL }
};
static const FieldPart I025_000_RT = { 7, 1.0, FIELD_PART_UINT, &hf_025_000_RT, NULL };
static const FieldPart I025_000_RG = { 1, 1.0, FIELD_PART_UINT, &hf_025_000_RG, NULL };
static const FieldPart *I025_000_PARTS[] = { &I025_000_RT, &I025_000_RG, NULL };

/* Service Identification */
static const FieldPart I025_015_SID = { 8, 1.0, FIELD_PART_UINT, &hf_025_015_SID, NULL };
static const FieldPart *I025_015_PARTS[] = { &I025_015_SID, NULL };

/* Service Designator */
static const FieldPart I025_020_SD = { 48, 1.0, FIELD_PART_CALLSIGN, &hf_025_020_SD, NULL };
static const FieldPart *I025_020_PARTS[] = { &I025_020_SD, NULL };

/* System and Service Status */
static const value_string valstr_025_100_NOGO[] = {
    { 0, "Data is released for operational use" },
    { 1, "Data must not be used operationally" },
    { 0, NULL }
};
static const value_string valstr_025_100_OPS[] = {
    { 0, "Operational" },
    { 1, "Operational but in Standby" },
    { 2, "Maintenance" },
    { 3, "reserved for future use" },
    { 0, NULL }
};
static const value_string valstr_025_100_SSTAT[] = {
    { 0, "Running" },
    { 1, "Failed" },
    { 2, "Degraded" },
    { 3, "Undefined" },
    { 0, NULL }
};
static const FieldPart I025_100_NOGO = { 1, 1.0, FIELD_PART_UINT, &hf_025_100_NOGO, NULL };
static const FieldPart I025_100_OPS = { 2, 1.0, FIELD_PART_UINT, &hf_025_100_OPS, NULL };
static const FieldPart I025_100_SSTAT = { 4, 1.0, FIELD_PART_UINT, &hf_025_100_SSTAT, NULL };
static const FieldPart *I025_100_PARTS[] = { &I025_100_NOGO, &I025_100_OPS, &I025_100_SSTAT, &IXXX_FX, NULL };

/* System and Service Error Codes */
static const value_string valstr_025_105_ERR[] = {
    { 0, "No error detected (shall not be sent)" },
    { 1, "Error Code Undefined" },
    { 2, "Time Source Invalid" },
    { 3, "Time Source Coasting" },
    { 4, "Track ID numbering has restarted" },
    { 5, "Data Processor Overload" },
    { 6, "Ground Interface Data Communications Overload" },
    { 7, "System stopped by operator" },
    { 8, "CBIT failed" },
    { 9, "Test Target Failure" },
    { 0, NULL }
};
static const FieldPart I025_105_ERR = { 1, 1.0, FIELD_PART_UINT, &hf_025_105_ERR, NULL };
static const FieldPart *I025_105_PARTS[] = { &I025_105_ERR, NULL };

/* Component Status */
static const value_string valstr_025_120_EC[] = {
    { 0, "No Error Detected" },
    { 1, "Error Code Undefined" },
    { 0, NULL }
};
static const value_string valstr_025_120_CS[] = {
    { 0, "Running" },
    { 1, "Failed" },
    { 2, "Maintenance" },
    { 3, "reserved" },
    { 0, NULL }
};
static const FieldPart I025_120_CID = { 16, 1.0, FIELD_PART_UINT, &hf_025_120_CID, NULL };
static const FieldPart I025_120_EC = { 6, 1.0, FIELD_PART_UINT, &hf_025_120_EC, NULL };
static const FieldPart I025_120_CS = { 2, 1.0, FIELD_PART_UINT, &hf_025_120_CS, NULL };
static const FieldPart *I025_120_PARTS[] = { &I025_120_CID, &I025_120_EC, &I025_120_CS, NULL };

/* Service Statistics */
static const value_string valstr_025_140_TYPE[] = {
    { 0, "Number of unknown messages received" },
    { 1, "Number of \'too old\' messages received" },
    { 2, "Number of failed message conversions" },
    { 3, "Total Number of messages received" },
    { 4, "Total number of messages transmitted" },
    { 0, NULL }
};
static const value_string valstr_025_140_REF[] = {
    { 0, "From UTC midnight" },
    { 1, "From the previous report" },
    { 0, NULL }
};
static const FieldPart I025_140_TYPE = { 8, 1.0, FIELD_PART_UINT, &hf_025_140_TYPE, NULL };
static const FieldPart I025_140_REF = { 1, 1.0, FIELD_PART_UINT, &hf_025_140_REF, NULL };
static const FieldPart I025_140_COUNTER = { 32, 1.0, FIELD_PART_UINT, &hf_025_140_COUNTER, NULL };
static const FieldPart *I025_140_PARTS[] = { &I025_140_TYPE, &I025_140_REF, &IXXX_7bit_spare, &I025_140_COUNTER, NULL };

/* Message Identification */
static const FieldPart I025_200_MID = { 24, 1.0, FIELD_PART_UINT, &hf_025_200_MID, NULL };
static const FieldPart *I025_200_PARTS[] = { &I025_200_MID, NULL };

/* Items */
DIAG_OFF_PEDANTIC
static const AsterixField I025_000 = { FIXED, 1, 0, 0, &hf_025_000, I025_000_PARTS, { NULL } };
static const AsterixField I025_010 = { FIXED, 2, 0, 0, &hf_025_010, IXXX_SAC_SIC, { NULL } };
static const AsterixField I025_015 = { FIXED, 1, 0, 0, &hf_025_015, I025_015_PARTS, { NULL } };
static const AsterixField I025_020 = { FIXED, 6, 0, 0, &hf_025_020, I025_020_PARTS, { NULL } };
static const AsterixField I025_070 = { FIXED, 3, 0, 0, &hf_025_070, IXXX_TOD, { NULL } };
static const AsterixField I025_100 = { FX, 1, 0, 0, &hf_025_100, I025_100_PARTS, { NULL } };
static const AsterixField I025_105 = { REPETITIVE, 1, 1, 0, &hf_025_105, I025_105_PARTS, { NULL } };
static const AsterixField I025_120 = { REPETITIVE, 3, 1, 0, &hf_025_120, I025_120_PARTS, { NULL } };
static const AsterixField I025_140 = { REPETITIVE, 6, 1, 0, &hf_025_140, I025_140_PARTS, { NULL } };
static const AsterixField I025_200 = { FIXED, 3, 0, 0, &hf_025_200, I025_200_PARTS, { NULL } };
static const AsterixField I025_SP = { SP, 0, 0, 1, &hf_025_SP, NULL, { NULL } };

static const AsterixField *I025_v1_1_uap[] = { &I025_010, &I025_000, &I025_200, &I025_015, &I025_020, &I025_070, &I025_100,
                                               &I025_105, &I025_120, &I025_140, &I025_SP, NULL };
static const AsterixField **I025_v1_1[] = { I025_v1_1_uap, NULL };
static const AsterixField ***I025[] = { I025_v1_1 };
DIAG_ON_PEDANTIC

static const enum_val_t I025_versions[] = {
    { "I025_v1_1", "Version 1.1", 0 },
    { NULL, NULL, 0 }
};

/* *********************** */
/*      Category 032       */
/* *********************** */
static const value_string valstr_032_035_NAT[] = {
    { 1, "Flight Plan to Track Initial Correlation" },
    { 2, "Miniplan Update" },
    { 3, "End of Correlation" },
    { 4, "Miniplan Cancellation" },
    { 5, "Retained Miniplan" },
    { 0, NULL }
};

static const value_string valstr_032_420_GAT[] = {
    { 0, "Unknown" },
    { 1, "General Air Traffic" },
    { 2, "Operational Air Traffic" },
    { 3, "Not Applicable" },
    { 0, NULL }
};

static const value_string valstr_032_420_FR[] = {
    { 0, "Instrument Flight Rules"},
    { 1, "Visual Flight Rules"},
    { 2, "Not Applicable"},
    { 3, "Controlled Visual Flight Rules"},
    { 0, NULL}
};

static const value_string valstr_032_435_CAT[] = {
    { 76, "L: Light" },
    { 77, "M: Medium" },
    { 78, "H: Heavy" },
    { 79, "J: Super" },
    { 0, NULL }
};

static const value_string valstr_032_500_PLN[] = {
    { 0, "Plan Number" },
    { 1, "Unit 1 Internal Flight Number" },
    { 2, "Unit 2 Internal Flight Number" },
    { 3, "Unit 3 Internal Flight Number" },
    { 0, NULL }
};

static const value_string valstr_032_500_RVSM[] = {
    { 0, "Unknown" },
    { 1, "Approved" },
    { 2, "Exempt" },
    { 3, "Not Approved" },
    { 0, NULL }
};

static const value_string valstr_032_500_HPR[] = {
    { 0, "Normal Priority Flight" },
    { 1, "High Priority Flight" },
    { 0, NULL }
};

static const value_string valstr_032_500_TYP[] = {
    { 0, "Scheduled Off-Block Time" },
    { 1, "Estimated Off-Block Time" },
    { 2, "Estimated Take-Off Time" },
    { 3, "Actual Off-Block Time" },
    { 4, "Predicted Time At Runway Hold" },
    { 5, "Actual Time at Runway Hold" },
    { 6, "Actual Line-up Time" },
    { 7, "Actual Take-Off Time" },
    { 8, "Estimated Time of Arrival" },
    { 9, "Predicted Landing Time" },
    { 10, "Actual Landing Time" },
    { 11, "Actual Time Off Runway" },
    { 12, "Predicted Time To Gate" },
    { 13, "Actual On Block Time" },
    { 0, NULL }
};

static const value_string valstr_032_500_DAY[] = {
    { 0, "Today" },
    { 1, "Yesterday" },
    { 2, "Tomorrow" },
    { 3, "Invalid" },
    { 0, NULL }
};

static const value_string valstr_032_500_STS_EMP[] = {
    { 0, "Empty" },
    { 1, "Occupied" },
    { 2, "Unknown" },
    { 3, "Invalid" },
    { 0, NULL }
};

static const value_string valstr_032_500_STS_AVL[] = {
    { 0, "Available" },
    { 1, "Not Available" },
    { 2, "Unknown" },
    { 3, "Invalid" },
    { 0, NULL }
};

static const value_string valstr_032_500_AVS[] = {
    { 0, "Seconds Available" },
    { 1, "Seconds Not Available" },
    { 0, NULL }
};

/* Fields */
/* I032/015 - User Number */
static const FieldPart I032_015_USR = { 16, 1.0, FIELD_PART_UINT, &hf_032_015_UN, NULL };
static const FieldPart *I032_015_PARTS[] = { &I032_015_USR, NULL };

/* I032/035 - Type of Message */
static const FieldPart I032_035_FAM = { 4, 1.0, FIELD_PART_UINT, &hf_032_035_FAM, NULL };
static const FieldPart I032_035_NAT = { 4, 1.0, FIELD_PART_UINT, &hf_032_035_NAT, NULL };
static const FieldPart *I032_035_PARTS[] = { &I032_035_FAM, &I032_035_NAT, NULL };

/* I032/040 - Track Number */
static const FieldPart I032_040_TRK = { 12, 1.0, FIELD_PART_UINT, &hf_032_040_TRK, NULL };
static const FieldPart *I032_040_PARTS[] = { &I032_040_TRK, NULL };

/* I032/050 - Composed Track Number */
static const FieldPart I032_050_SUI = { 8, 1.0, FIELD_PART_UINT, &hf_032_050_SUI, NULL };
static const FieldPart I032_050_STN = { 11, 1.0, FIELD_PART_UINT, &hf_032_050_STN, NULL };
static const FieldPart *I032_050_PARTS[] = { &I032_050_SUI, &I032_050_STN, &IXXX_FX, NULL };

/* I032/060 - Track Mode 3A */
static const FieldPart I032_060_MD3 = { 12, 1.0, FIELD_PART_SQUAWK, &hf_032_060_M3, NULL };
static const FieldPart *I032_060_PARTS[] = { &I032_060_MD3, NULL };

/* I032/400 - Callsign */
static const FieldPart I032_400_CAL = { 56, 1.0, FIELD_PART_ASCII, &hf_032_400_CALL, NULL };
static const FieldPart *I032_400_PARTS[] = { &I032_400_CAL, NULL };

/* I032/410 - Plan Number */
static const FieldPart I032_410_PLN = { 16, 1.0, FIELD_PART_UINT, &hf_032_410_PLN, NULL };
static const FieldPart *I032_410_PARTS[] = { &I032_410_PLN, NULL };

/* I032/420 - Flight Category */
static const FieldPart I032_420_GAT = { 2, 1.0, FIELD_PART_UINT, &hf_032_420_GAT, NULL };
static const FieldPart I032_420_FR = { 2, 1.0, FIELD_PART_UINT, &hf_032_420_FR, NULL };
static const FieldPart I032_420_SP = { 3, 1.0, FIELD_PART_UINT, &hf_032_420_SP, NULL };
static const FieldPart *I032_420_PARTS[] = { &I032_420_GAT, &I032_420_FR, &I032_420_SP, NULL };

/* I032/430 - Type of Aircraft */
static const FieldPart I032_430_TYP = { 32, 1.0, FIELD_PART_ASCII, &hf_032_430_TYP, NULL };
static const FieldPart *I032_430_PARTS[] = { &I032_430_TYP, NULL };

/* I032/435 - Category of Turbulance */
static const FieldPart I032_435_TURB = { 8, 1.0, FIELD_PART_UINT, &hf_032_435_TUR, NULL };
static const FieldPart *I032_435_PARTS[] = { &I032_435_TURB, NULL };

/* I032/440 - Departure Airport */
static const FieldPart I032_440_DEP = { 32, 1.0, FIELD_PART_ASCII, &hf_032_440_DEP, NULL };
static const FieldPart *I032_440_PARTS[] = { &I032_440_DEP, NULL };

/* I032/450 - Destination Airport */
static const FieldPart I032_450_DEST = { 32, 1.0, FIELD_PART_ASCII, &hf_032_450_DEST, NULL };
static const FieldPart *I032_450_PARTS[] = { &I032_450_DEST, NULL };

/* I032/460 - Allocated SSR Codes */
static const FieldPart I032_460_SSR = { 12, 1.0, FIELD_PART_SQUAWK, &hf_032_460_SSR, NULL };
static const FieldPart *I032_460_PARTS[] = { &IXXX_4bit_spare, &I032_460_SSR, NULL };

/* I032/480 - Current Cleared Flight Level */
static const FieldPart I032_480_CCFL = { 16, 25, FIELD_PART_UINT, &hf_032_480_CFL, NULL };
static const FieldPart *I032_480_PARTS[] = { &I032_480_CCFL, NULL };

/* I032/490 - Current Control Position */
static const FieldPart I032_490_CEN = { 4, 1.0, FIELD_PART_UINT, &hf_032_490_CEN, NULL };
static const FieldPart I032_490_POS = { 4, 1.0, FIELD_PART_UINT, &hf_032_490_POS, NULL };
static const FieldPart *I032_490_PARTS[] = { &I032_490_CEN, &I032_490_POS, NULL };

/* I032/500/1 - IFPS Flight ID */
static const FieldPart I032_500_IFI_TYP = { 2, 1.0, FIELD_PART_UINT, &hf_032_500_IFI_TYP, NULL };
static const FieldPart I032_500_IFI_NBR = { 30, 1.0, FIELD_PART_UINT, &hf_032_500_IFI_NBR, NULL };
static const FieldPart *I032_500_IFI_PARTS[] = { &I032_500_IFI_TYP, &I032_500_IFI_NBR, NULL };

/* I032/500/2 - RVSM & Flight Priority */
static const FieldPart I032_500_RVSM_RVSM = { 2, 1.0, FIELD_PART_UINT, &hf_032_500_RVSM_RVSM, NULL };
static const FieldPart I032_500_RVSM_HPR = { 1, 1.0, FIELD_PART_UINT, &hf_032_500_RVSM_HPR, NULL };
static const FieldPart *I032_500_RVSM_PARTS[] = { &I032_500_RVSM_RVSM, &I032_500_RVSM_HPR, NULL };

/* I032/500/3 - Runway Desigination */
static const FieldPart I032_500_RUNWAY_NU1 = { 8, 1.0, FIELD_PART_ASCII, &hf_032_500_RUNWAY_NU1, NULL };
static const FieldPart I032_500_RUNWAY_NU2 = { 8, 1.0, FIELD_PART_ASCII, &hf_032_500_RUNWAY_NU2, NULL };
static const FieldPart I032_500_RUNWAY_LTR = { 8, 1.0, FIELD_PART_ASCII, &hf_032_500_RUNWAY_LTR, NULL };
static const FieldPart *I032_500_RUNWAY_PARTS[] = { &I032_500_RUNWAY_NU1, &I032_500_RUNWAY_NU2, &I032_500_RUNWAY_LTR, NULL };

/* I032/500/4 - Time of Departure Arrival */
static const FieldPart I032_500_TIME_TYP = { 5, 1.0, FIELD_PART_UINT, &hf_032_500_TIME_TYP, NULL };
static const FieldPart I032_500_TIME_DAY = { 2, 1.0, FIELD_PART_UINT, &hf_032_500_TIME_DAY, NULL };
static const FieldPart I032_500_TIME_HOR = { 4, 1.0, FIELD_PART_UINT, &hf_032_500_TIME_HOR, NULL };
static const FieldPart I032_500_TIME_MIN = { 6, 1.0, FIELD_PART_UINT, &hf_032_500_TIME_MIN, NULL };
static const FieldPart I032_500_TIME_AVS = { 1, 1.0, FIELD_PART_UINT, &hf_032_500_TIME_AVS, NULL };
static const FieldPart I032_500_TIME_SECS = { 5, 1.0, FIELD_PART_UINT, &hf_032_500_TIME_SEC, NULL };
static const FieldPart *I032_500_TIME_PARTS[] = { &I032_500_TIME_TYP, &I032_500_TIME_DAY, &I032_500_TIME_HOR, &I032_500_TIME_MIN, &I032_500_TIME_AVS, &I032_500_TIME_SECS, NULL };

/* I032/500/5 - Aircraft Stand */
static const FieldPart I032_500_AIR_STD = { 48, 1.0, FIELD_PART_ASCII, &hf_032_500_AIR_STD, NULL };
static const FieldPart *I032_500_AIR_STD_PARTS[] = { &I032_500_AIR_STD, NULL };

/* I032/500/6 - Stand Status */
static const FieldPart I032_500_STS_EMP = { 2, 1.0, FIELD_PART_UINT, &hf_032_500_STS_EMP, NULL };
static const FieldPart I032_500_STS_AVL = { 2, 1.0, FIELD_PART_UINT, &hf_032_500_STS_AVL, NULL };
static const FieldPart *I032_500_STS_PARTS[] = { &I032_500_STS_EMP, &I032_500_STS_AVL, NULL };

/* I032/500/7 - Standard Instrument Departure */
static const FieldPart I032_500_SID = { 56, 1.0, FIELD_PART_ASCII, &hf_032_500_SID, NULL };
static const FieldPart *I032_500_SID_PARTS[] = { &I032_500_SID, NULL };

/* I032/500/8 - Standard Instrument Arrival */
static const FieldPart I032_500_SIA = { 56, 1.0, FIELD_PART_ASCII, &hf_032_500_SIA, NULL };
static const FieldPart *I032_500_SIA_PARTS[] = { &I032_500_SIA, NULL };

DIAG_OFF_PEDANTIC
/*AsterixField Definitions*/
static const AsterixField I032_010 = { FIXED, 2, 0, 0, &hf_032_010, IXXX_SAC_SIC, { NULL } };
static const AsterixField I032_015 = { FIXED, 2, 0, 0, &hf_032_015, I032_015_PARTS, { NULL } };
static const AsterixField I032_018 = { FIXED, 2, 0, 0, &hf_032_018, IXXX_SAC_SIC, { NULL } };
static const AsterixField I032_035 = { FIXED, 1, 0, 0, &hf_032_035, I032_035_PARTS, { NULL } };
static const AsterixField I032_020 = { FIXED, 3, 0, 0, &hf_032_020, IXXX_TOD, { NULL } };
static const AsterixField I032_040 = { FIXED, 2, 0, 0, &hf_032_040, I032_040_PARTS, { NULL } };
static const AsterixField I032_050 = { FX, 3, 0, 0, &hf_032_050, I032_050_PARTS, { NULL } };
static const AsterixField I032_060 = { FIXED, 2, 0, 0, &hf_032_060, I032_060_PARTS, { NULL } };
static const AsterixField I032_400 = { FIXED, 7, 0, 0, &hf_032_400, I032_400_PARTS, { NULL } };
static const AsterixField I032_410 = { FIXED, 2, 0, 0, &hf_032_410, I032_410_PARTS, { NULL } };
static const AsterixField I032_420 = { FIXED, 1, 0, 0, &hf_032_420, I032_420_PARTS, { NULL } };
static const AsterixField I032_440 = { FIXED, 4, 0, 0, &hf_032_440, I032_440_PARTS, { NULL } };
static const AsterixField I032_450 = { FIXED, 4, 0, 0, &hf_032_450, I032_450_PARTS, { NULL } };
static const AsterixField I032_480 = { FIXED, 2, 0, 0, &hf_032_480, I032_480_PARTS, { NULL } };
static const AsterixField I032_490 = { FIXED, 2, 0, 0, &hf_032_490, I032_490_PARTS, { NULL } };
static const AsterixField I032_430 = { FIXED, 4, 0, 0, &hf_032_430, I032_430_PARTS, { NULL } };
static const AsterixField I032_435 = { FIXED, 1, 0, 0, &hf_032_435, I032_435_PARTS, { NULL } };
static const AsterixField I032_460 = { REPETITIVE, 2, 1, 0, &hf_032_460, I032_460_PARTS, { NULL } };
static const AsterixField I032_500_01 = { FIXED, 4, 0, 0, &hf_032_500_01, I032_500_IFI_PARTS, { NULL } };
static const AsterixField I032_500_02 = { FIXED, 1, 0, 0, &hf_032_500_02, I032_500_RVSM_PARTS, { NULL } };
static const AsterixField I032_500_03 = { FIXED, 3, 0, 0, &hf_032_500_03, I032_500_RUNWAY_PARTS, { NULL } };
static const AsterixField I032_500_04 = { REPETITIVE, 4, 1, 0, &hf_032_500_04, I032_500_TIME_PARTS, { NULL } };
static const AsterixField I032_500_05 = { FIXED, 6, 0, 0, &hf_032_500_05, I032_500_AIR_STD_PARTS, { NULL } };
static const AsterixField I032_500_06 = { FIXED, 1, 0, 0, &hf_032_500_06, I032_500_STS_PARTS, { NULL } };
static const AsterixField I032_500_07 = { FIXED, 7, 0, 0, &hf_032_500_07, I032_500_SID_PARTS, { NULL } };
static const AsterixField I032_500_08 = { FIXED, 7, 0, 0, &hf_032_500_08, I032_500_SIA_PARTS, { NULL } };
static const AsterixField I032_500 = { COMPOUND, 0, 0, 0, &hf_032_500, NULL, {  &I032_500_01,
                                                                                &I032_500_02,
                                                                                &I032_500_03,
                                                                                &I032_500_04,
                                                                                &I032_500_05,
                                                                                &I032_500_06,
                                                                                &I032_500_07,
                                                                                &I032_500_08,
                                                                                NULL } };
static const AsterixField I032_RE = { RE, 0, 0, 1, &hf_032_RE, NULL, { NULL } };

/* Define the UAP */
static const AsterixField *I032_v1_0_uap[] = {  &I032_010, &I032_015, &I032_018, &I032_035, &I032_020, &I032_040,
                                                &I032_050, &I032_060, &I032_400, &I032_410, &I032_420, &I032_440,
                                                &I032_450, &I032_480, &I032_490, &I032_430, &I032_435, &I032_460,
                                                &I032_500, &IX_SPARE, &I032_RE,  NULL };
static const AsterixField **I032_v1_0[] = { I032_v1_0_uap, NULL };
static const AsterixField ***I032[] = { I032_v1_0 };

DIAG_ON_PEDANTIC

static const enum_val_t I032_versions[] = {
                { "I032_v1_0", "Version 1.0", 0 },
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
    { 0, "Valid" },
    { 1, "Invalid" },
    { 0, NULL }
};
static const value_string valstr_034_050_02_ANT[] = {
    { 0, "Antenna 1" },
    { 1, "Antenna 2" },
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
    { 0, "Antenna 1" },
    { 1, "Antenna 2" },
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
    { 0, "Antenna 1" },
    { 1, "Antenna 2" },
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
static const FieldPart I034_100_RHOS = { 16, 1.0/256.0, FIELD_PART_UFLOAT, &hf_034_100_RHOS, NULL };
static const FieldPart I034_100_RHOE = { 16, 1.0/256.0, FIELD_PART_UFLOAT, &hf_034_100_RHOE, NULL };
static const FieldPart I034_100_THETAS = { 16, 360.0/65536.0, FIELD_PART_UFLOAT, &hf_034_100_THETAS, NULL };
static const FieldPart I034_100_THETAE = { 16, 360.0/65536.0, FIELD_PART_UFLOAT, &hf_034_100_THETAE, NULL };
static const FieldPart *I034_100_PARTS[] = { &I034_100_RHOS, &I034_100_RHOE, &I034_100_THETAS, &I034_100_THETAE, NULL };

/* Data Filter */
static const value_string valstr_034_110_TYP[] = {
    { 0, "Invalid value" },
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
DIAG_OFF_PEDANTIC
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
DIAG_ON_PEDANTIC

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
static const value_string valstr_048_020_ERR[] = {
    { 0, "No extended range" },
    { 1, "Extended range present" },
    { 0, NULL }
};
static const value_string valstr_048_020_XPP[] = {
    { 0, "No X-Pulse present" },
    { 1, "X-Pulse present" },
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
static const FieldPart I048_020_ERR = { 1, 1.0, FIELD_PART_UINT, &hf_048_020_ERR, NULL }; /* v1.23 */
static const FieldPart I048_020_XPP = { 1, 1.0, FIELD_PART_UINT, &hf_048_020_XPP, NULL }; /* v1.21 */
static const FieldPart I048_020_ME = { 1, 1.0, FIELD_PART_UINT, &hf_048_020_ME, NULL };
static const FieldPart I048_020_MI = { 1, 1.0, FIELD_PART_UINT, &hf_048_020_MI, NULL };
static const FieldPart I048_020_FOE = { 2, 1.0, FIELD_PART_UINT, &hf_048_020_FOE, NULL };
static const FieldPart *I048_020_PARTS[] = { &I048_020_TYP, &I048_020_SIM, &I048_020_RDP, &I048_020_SPI, &I048_020_RAB, &IXXX_FX,
                                             &I048_020_TST, &I048_020_ERR, &I048_020_XPP, &I048_020_ME, &I048_020_MI, &I048_020_FOE, &IXXX_FX, NULL };
static const FieldPart *I048_020_PARTS_v1_21[] = { &I048_020_TYP, &I048_020_SIM, &I048_020_RDP, &I048_020_SPI, &I048_020_RAB, &IXXX_FX,
                                                   &I048_020_TST, &IXXX_1bit_spare, &I048_020_XPP, &I048_020_ME, &I048_020_MI, &I048_020_FOE, &IXXX_FX, NULL };
static const FieldPart *I048_020_PARTS_v1_17[] = { &I048_020_TYP, &I048_020_SIM, &I048_020_RDP, &I048_020_SPI, &I048_020_RAB, &IXXX_FX,
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
    { 21, "Mode 1 was present in original reply" },
    { 22, "Mode 2 was present in original reply" },
    { 23, "Plot potentially caused by Wind Turbine" },
    { 0, NULL }
};
/* Note: I048/030 is an FX field that has no limit on the number of extensions.
 * There is currently no function available for us to deal dynamically with that so we
 * will just hardcode support for a maximum of 10 extensions.
 **/
static const FieldPart I048_030_WE = { 7, 1.0, FIELD_PART_UINT, &hf_048_030_WE, NULL };
static const FieldPart I048_030_1_WE = { 7, 1.0, FIELD_PART_UINT, &hf_048_030_1_WE, NULL };
static const FieldPart I048_030_2_WE = { 7, 1.0, FIELD_PART_UINT, &hf_048_030_2_WE, NULL };
static const FieldPart I048_030_3_WE = { 7, 1.0, FIELD_PART_UINT, &hf_048_030_3_WE, NULL };
static const FieldPart I048_030_4_WE = { 7, 1.0, FIELD_PART_UINT, &hf_048_030_4_WE, NULL };
static const FieldPart I048_030_5_WE = { 7, 1.0, FIELD_PART_UINT, &hf_048_030_5_WE, NULL };
static const FieldPart I048_030_6_WE = { 7, 1.0, FIELD_PART_UINT, &hf_048_030_6_WE, NULL };
static const FieldPart I048_030_7_WE = { 7, 1.0, FIELD_PART_UINT, &hf_048_030_7_WE, NULL };
static const FieldPart I048_030_8_WE = { 7, 1.0, FIELD_PART_UINT, &hf_048_030_8_WE, NULL };
static const FieldPart I048_030_9_WE = { 7, 1.0, FIELD_PART_UINT, &hf_048_030_9_WE, NULL };
static const FieldPart *I048_030_PARTS[] = {
    &I048_030_WE, &IXXX_FX,
    &I048_030_1_WE, &IXXX_FX,
    &I048_030_2_WE, &IXXX_FX,
    &I048_030_3_WE, &IXXX_FX,
    &I048_030_4_WE, &IXXX_FX,
    &I048_030_5_WE, &IXXX_FX,
    &I048_030_6_WE, &IXXX_FX,
    &I048_030_7_WE, &IXXX_FX,
    &I048_030_8_WE, &IXXX_FX,
    &I048_030_9_WE, &IXXX_FX,
    NULL };

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
static const FieldPart I048_120_01_CAL = { 10, 1.0, FIELD_PART_INT, &hf_048_120_01_CAL, NULL };
static const FieldPart *I048_120_01_PARTS[] = { &I048_120_01_D, &IXXX_5bit_spare, &I048_120_01_CAL, NULL };

static const FieldPart I048_120_02_DOP = { 16, 1.0, FIELD_PART_INT, &hf_048_120_02_DOP, NULL };
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
    { 3, "Unknown" } ,
    { 0, NULL }
};
static const value_string valstr_048_170_CDM_v1_21[] = {
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
    { 0, "No" } ,
    { 1, "Yes" } ,
    { 0, NULL }
};
static const value_string valstr_048_170_TCC[] = {
    { 0, "Tracking performed in so-called 'Radar Plane', i.e. neither slant range correction nor stereographical projection was applied." } ,
    { 1, "Slant range correction and a suitable projection technique are used to track in a 2D.reference plane, tangential to the earth model at the Radar Site co-ordinates." } ,
    { 0, NULL }
};
static const FieldPart I048_170_CNF = { 1, 1.0, FIELD_PART_UINT, &hf_048_170_CNF, NULL };
static const FieldPart I048_170_RAD = { 2, 1.0, FIELD_PART_UINT, &hf_048_170_RAD, NULL };
static const FieldPart I048_170_DOU = { 1, 1.0, FIELD_PART_UINT, &hf_048_170_DOU, NULL };
static const FieldPart I048_170_MAH = { 1, 1.0, FIELD_PART_UINT, &hf_048_170_MAH, NULL };
static const FieldPart I048_170_CDM = { 2, 1.0, FIELD_PART_UINT, &hf_048_170_CDM, NULL };
static const FieldPart I048_170_CDM_v1_21 = { 2, 1.0, FIELD_PART_UINT, &hf_048_170_CDM_v1_21, NULL };
static const FieldPart I048_170_TRE = { 1, 1.0, FIELD_PART_UINT, &hf_048_170_TRE, NULL };
static const FieldPart I048_170_GHO = { 1, 1.0, FIELD_PART_UINT, &hf_048_170_GHO, NULL };
static const FieldPart I048_170_SUP = { 1, 1.0, FIELD_PART_UINT, &hf_048_170_SUP, NULL };
static const FieldPart I048_170_TCC = { 1, 1.0, FIELD_PART_UINT, &hf_048_170_TCC, NULL };
static const FieldPart *I048_170_PARTS[] = { &I048_170_CNF, &I048_170_RAD, &I048_170_DOU, &I048_170_MAH, &I048_170_CDM, &IXXX_FX,
                                             &I048_170_TRE, &I048_170_GHO, &I048_170_SUP, &I048_170_TCC, &IXXX_3bit_spare, &IXXX_FX, NULL };
static const FieldPart *I048_170_PARTS_v1_21[] = { &I048_170_CNF, &I048_170_RAD, &I048_170_DOU, &I048_170_MAH, &I048_170_CDM_v1_21, &IXXX_FX,
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

/* Reserved Expansion Field */

/* MD5 - Mode 5 Reports */

/* Mode 5 Summary */
static const value_string valstr_048_RE_MD5_01_M5[] = {
    { 0, "No Mode 5 interrogation" },
    { 1, "Mode 5 interrogation" },
    { 0, NULL }
};
static const value_string valstr_048_RE_MD5_01_ID[] = {
    { 0, "No authenticated Mode 5 ID reply/report" },
    { 1, "Authenticated Mode 5 ID reply/report" },
    { 0, NULL }
};
static const value_string valstr_048_RE_MD5_01_DA[] = {
    { 0, "No authenticated Mode 5 Data reply/report" },
    { 1, "Authenticated Mode 5 Data reply/report (i.e any valid Mode 5 reply type other than ID)" },
    { 0, NULL }
};
static const value_string valstr_048_RE_MD5_01_M1[] = {
    { 0, "Mode 1 code not present or not from Mode 5 reply/report" },
    { 1, "Mode 1 code from Mode 5 reply/report" },
    { 0, NULL }
};
static const value_string valstr_048_RE_MD5_01_M2[] = {
    { 0, "Mode 2 code not present or not from Mode 5 reply/report" },
    { 1, "Mode 2 code from Mode 5 reply/report." },
    { 0, NULL }
};
static const value_string valstr_048_RE_MD5_01_M3[] = {
    { 0, "Mode 3 code not present or not from Mode 5 reply/report" },
    { 1, "Mode 3 code from Mode 5 reply/report." },
    { 0, NULL }
};
static const value_string valstr_048_RE_MD5_01_MC[] = {
    { 0, "Mode C altitude not present or not from Mode 5 reply/report" },
    { 1, "Mode C altitude from Mode 5 reply/report" },
    { 0, NULL }
};
static const FieldPart I048_RE_MD5_01_M5 = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_MD5_01_M5, NULL };
static const FieldPart I048_RE_MD5_01_ID = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_MD5_01_ID, NULL };
static const FieldPart I048_RE_MD5_01_DA = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_MD5_01_DA, NULL };
static const FieldPart I048_RE_MD5_01_M1 = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_MD5_01_M1, NULL };
static const FieldPart I048_RE_MD5_01_M2 = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_MD5_01_M2, NULL };
static const FieldPart I048_RE_MD5_01_M3 = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_MD5_01_M3, NULL };
static const FieldPart I048_RE_MD5_01_MC = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_MD5_01_MC, NULL };
static const FieldPart *I048_RE_MD5_01_PARTS[] = { &I048_RE_MD5_01_M5,
                                                    &I048_RE_MD5_01_ID,
                                                    &I048_RE_MD5_01_DA,
                                                    &I048_RE_MD5_01_M1,
                                                    &I048_RE_MD5_01_M2,
                                                    &I048_RE_MD5_01_M3,
                                                    &I048_RE_MD5_01_MC,
                                                    NULL };

/* Mode 5 PIN /National Origin/ Mission Code */
static const value_string valstr_048_RE_MD5_02_NAV[] = {
    { 0, "National Origin is valid" },
    { 1, "National Origin is invalid" },
    { 0, NULL }
};
static const FieldPart I048_RE_MD5_02_PIN = { 14, 1.0, FIELD_PART_UINT, &hf_048_RE_MD5_02_PIN, NULL };
static const FieldPart I048_RE_MD5_02_NAV = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_MD5_02_NAV, NULL };
static const FieldPart I048_RE_MD5_02_NAT = { 5, 1.0, FIELD_PART_UINT, &hf_048_RE_MD5_02_NAT, NULL };
static const FieldPart I048_RE_MD5_02_MIS = { 6, 1.0, FIELD_PART_UINT, &hf_048_RE_MD5_02_MIS, NULL };
static const FieldPart *I048_RE_MD5_02_PARTS[] = { &IXXX_2bit_spare,
                                                    &I048_RE_MD5_02_PIN,
                                                    &IXXX_2bit_spare,
                                                    &I048_RE_MD5_02_NAV,
                                                    &I048_RE_MD5_02_NAT,
                                                    &IXXX_2bit_spare,
                                                    &I048_RE_MD5_02_MIS,
                                                    NULL };

/* Mode 5 Reported Position */
static const FieldPart I048_RE_MD5_03_LAT = { 24, 180.0/8388608.0, FIELD_PART_FLOAT, &hf_048_RE_MD5_03_LAT, NULL };
static const FieldPart I048_RE_MD5_03_LON = { 24, 180.0/8388608.0, FIELD_PART_FLOAT, &hf_048_RE_MD5_03_LON, NULL };
static const FieldPart *I048_RE_MD5_03_PARTS[] = { &I048_RE_MD5_03_LAT,
                                                    &I048_RE_MD5_03_LON,
                                                    NULL };

/* Mode 5 GNSS-derived Altitude */
static const value_string valstr_048_RE_MD5_04_RES[] = {
    { 0, "GA reported in 100 ft increments" },
    { 1, "GA reported in 25 ft increments" },
    { 0, NULL }
};
static const FieldPart I048_RE_MD5_04_RES = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_MD5_04_RES, NULL };
static const FieldPart I048_RE_MD5_04_GA = { 14, 25.0, FIELD_PART_FLOAT, &hf_048_RE_MD5_04_GA, NULL };
static const FieldPart *I048_RE_MD5_04_PARTS[] = { &IXXX_1bit_spare,
                                                   &I048_RE_MD5_04_RES,
                                                   &I048_RE_MD5_04_GA,
                                                   NULL };

/* Extended Mode 1 Code in Octal Representation */
static const value_string valstr_048_RE_MD5_05_V[] = {
    { 0, "Code not validated (see note 2)" },
    { 1, "Code validated (see note 2)" },
    { 0, NULL }
};
static const value_string valstr_048_RE_MD5_05_G[] = {
    { 0, "Default" },
    { 1, "Garbled code" },
    { 0, NULL }
};
static const value_string valstr_048_RE_MD5_05_L[] = {
    { 0, "Mode-1 code derived from the reply of the transponder" },
    { 1, "Mode-1 code not extracted during the last scan" },
    { 0, NULL }
};
static const FieldPart I048_RE_MD5_05_V = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_MD5_05_V, NULL };
static const FieldPart I048_RE_MD5_05_G = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_MD5_05_G, NULL };
static const FieldPart I048_RE_MD5_05_L = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_MD5_05_L, NULL };
static const FieldPart I048_RE_MD5_05_SQUAWK = { 12, 1.0, FIELD_PART_UINT, &hf_048_RE_MD5_05_SQUAWK, NULL };
static const FieldPart *I048_RE_MD5_05_PARTS[] = { &I048_RE_MD5_05_V,
                                                    &I048_RE_MD5_05_G,
                                                    &I048_RE_MD5_05_L,
                                                    &IXXX_1bit_spare,
                                                    &I048_RE_MD5_05_SQUAWK,
                                                    NULL };

/* Time Offset for POS and GA */
static const FieldPart I048_RE_MD5_06_TOS = { 8, 1.0/128.0, FIELD_PART_FLOAT, &hf_048_RE_MD5_06_TOS, NULL };
static const FieldPart *I048_RE_MD5_06_PARTS[] = { &I048_RE_MD5_06_TOS, NULL };

/* X Pulse Presence */
static const value_string valstr_048_RE_MD5_07_XP[] = {
    { 0, "X-Pulse not present" },
    { 1, "X-pulse present" },
    { 0, NULL }
};
static const value_string valstr_048_RE_MD5_07_X5[] = {
    { 0, "X-pulse set to zero or no authenticated Data reply or Report received" },
    { 1, "X-pulse set to one (present)" },
    { 0, NULL }
};
static const value_string valstr_048_RE_MD5_07_XC[] = {
    { 0, "X-pulse set to zero or no Mode C reply" },
    { 1, "X-pulse set to one (present)" },
    { 0, NULL }
};
static const value_string valstr_048_RE_MD5_07_X3[] = {
    { 0, "X-pulse set to zero or no Mode 3/A reply" },
    { 1, "X-pulse set to one (present)" },
    { 0, NULL }
};
static const value_string valstr_048_RE_MD5_07_X2[] = {
    { 0, "X-pulse set to zero or no Mode 2 reply" },
    { 1, "X-pulse set to one (present)" },
    { 0, NULL }
};
static const value_string valstr_048_RE_MD5_07_X1[] = {
    { 0, "X-pulse set to zero or no Mode 1 reply" },
    { 1, "X-pulse set to one (present)" },
    { 0, NULL }
};
static const FieldPart I048_RE_MD5_07_XP = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_MD5_07_XP, NULL };
static const FieldPart I048_RE_MD5_07_X5 = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_MD5_07_X5, NULL };
static const FieldPart I048_RE_MD5_07_XC = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_MD5_07_XC, NULL };
static const FieldPart I048_RE_MD5_07_X3 = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_MD5_07_X3, NULL };
static const FieldPart I048_RE_MD5_07_X2 = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_MD5_07_X2, NULL };
static const FieldPart I048_RE_MD5_07_X1 = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_MD5_07_X1, NULL };
static const FieldPart *I048_RE_MD5_07_PARTS[] = { &IXXX_2bit_spare,
                                                   &I048_RE_MD5_07_XP,
                                                   &I048_RE_MD5_07_X5,
                                                   &I048_RE_MD5_07_XC,
                                                   &I048_RE_MD5_07_X3,
                                                   &I048_RE_MD5_07_X2,
                                                   &I048_RE_MD5_07_X1,
                                                   NULL };

/* M5N - Mode 5 Reports, New Format */

/* Mode 5 Summary */
static const value_string valstr_048_RE_M5N_01_M5[] = {
    { 0, "No Mode 5 interrogation" },
    { 1, "Mode 5 interrogation" },
    { 0, NULL }
};
static const value_string valstr_048_RE_M5N_01_ID[] = {
    { 0, "No authenticated Mode 5 ID reply/report" },
    { 1, "Authenticated Mode 5 ID reply/report" },
    { 0, NULL }
};
static const value_string valstr_048_RE_M5N_01_DA[] = {
    { 0, "No authenticated Mode 5 Data reply/report" },
    { 1, "Authenticated Mode 5 Data reply/report (i.e any valid Mode 5 reply type other than ID)" },
    { 0, NULL }
};
static const value_string valstr_048_RE_M5N_01_M1[] = {
    { 0, "Mode 1 code not present or not from Mode 5 reply/report" },
    { 1, "Mode 1 code from Mode 5 reply/report" },
    { 0, NULL }
};
static const value_string valstr_048_RE_M5N_01_M2[] = {
    { 0, "Mode 2 code not present or not from Mode 5 reply/report" },
    { 1, "Mode 2 code from Mode 5 reply/report." },
    { 0, NULL }
};
static const value_string valstr_048_RE_M5N_01_M3[] = {
    { 0, "Mode 3 code not present or not from Mode 5 reply/report" },
    { 1, "Mode 3 code from Mode 5 reply/report." },
    { 0, NULL }
};
static const value_string valstr_048_RE_M5N_01_MC[] = {
    { 0, "Mode C altitude not present or not from Mode 5 reply/report" },
    { 1, "Mode C altitude from Mode 5 reply/report" },
    { 0, NULL }
};
static const FieldPart I048_RE_M5N_01_M5 = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_M5N_01_M5, NULL };
static const FieldPart I048_RE_M5N_01_ID = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_M5N_01_ID, NULL };
static const FieldPart I048_RE_M5N_01_DA = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_M5N_01_DA, NULL };
static const FieldPart I048_RE_M5N_01_M1 = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_M5N_01_M1, NULL };
static const FieldPart I048_RE_M5N_01_M2 = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_M5N_01_M2, NULL };
static const FieldPart I048_RE_M5N_01_M3 = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_M5N_01_M3, NULL };
static const FieldPart I048_RE_M5N_01_MC = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_M5N_01_MC, NULL };
static const FieldPart *I048_RE_M5N_01_PARTS[] = { &I048_RE_M5N_01_M5,
                                                    &I048_RE_M5N_01_ID,
                                                    &I048_RE_M5N_01_DA,
                                                    &I048_RE_M5N_01_M1,
                                                    &I048_RE_M5N_01_M2,
                                                    &I048_RE_M5N_01_M3,
                                                    &I048_RE_M5N_01_MC,
                                                    NULL };

/* Mode 5 PIN /National Origin/ Mission Code */
static const value_string valstr_048_RE_M5N_02_NOV[] = {
    { 0, "National Origin is valid" },
    { 1, "National Origin is invalid" },
    { 0, NULL }
};
static const FieldPart I048_RE_M5N_02_PIN = { 14, 1.0, FIELD_PART_UINT, &hf_048_RE_M5N_02_PIN, NULL };
static const FieldPart I048_RE_M5N_02_NOV = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_M5N_02_NOV, NULL };
static const FieldPart I048_RE_M5N_02_NO = { 11, 1.0, FIELD_PART_UINT, &hf_048_RE_M5N_02_NO, NULL };
static const FieldPart *I048_RE_M5N_02_PARTS[] = { &IXXX_2bit_spare,
                                                    &I048_RE_M5N_02_PIN,
                                                    &IXXX_4bit_spare,
                                                    &I048_RE_M5N_02_NOV,
                                                    &I048_RE_M5N_02_NO,
                                                    NULL };

/* Mode 5 Reported Position */
static const FieldPart I048_RE_M5N_03_LAT = { 24, 180.0/8388608.0, FIELD_PART_FLOAT, &hf_048_RE_M5N_03_LAT, NULL };
static const FieldPart I048_RE_M5N_03_LON = { 24, 180.0/8388608.0, FIELD_PART_FLOAT, &hf_048_RE_M5N_03_LON, NULL };
static const FieldPart *I048_RE_M5N_03_PARTS[] = { &I048_RE_M5N_03_LAT,
                                                    &I048_RE_M5N_03_LON,
                                                    NULL };

/* Mode 5 GNSS-derived Altitude */
static const value_string valstr_048_RE_M5N_04_RES[] = {
    { 0, "GA reported in 100 ft increments" },
    { 1, "GA reported in 25 ft increments" },
    { 0, NULL }
};
static const FieldPart I048_RE_M5N_04_RES = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_M5N_04_RES, NULL };
static const FieldPart I048_RE_M5N_04_GA = { 14, 25.0, FIELD_PART_FLOAT, &hf_048_RE_M5N_04_GA, NULL };
static const FieldPart *I048_RE_M5N_04_PARTS[] = { &IXXX_1bit_spare,
                                                   &I048_RE_M5N_04_RES,
                                                   &I048_RE_M5N_04_GA,
                                                   NULL };

/* Extended Mode 1 Code in Octal Representation */
static const value_string valstr_048_RE_M5N_05_V[] = {
    { 0, "Code not validated (see note 2)" },
    { 1, "Code validated (see note 2)" },
    { 0, NULL }
};
static const value_string valstr_048_RE_M5N_05_G[] = {
    { 0, "Default" },
    { 1, "Garbled code" },
    { 0, NULL }
};
static const value_string valstr_048_RE_M5N_05_L[] = {
    { 0, "Mode-1 code derived from the reply of the transponder" },
    { 1, "Mode-1 code not extracted during the last scan" },
    { 0, NULL }
};
static const FieldPart I048_RE_M5N_05_V = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_M5N_05_V, NULL };
static const FieldPart I048_RE_M5N_05_G = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_M5N_05_G, NULL };
static const FieldPart I048_RE_M5N_05_L = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_M5N_05_L, NULL };
static const FieldPart I048_RE_M5N_05_SQUAWK = { 12, 1.0, FIELD_PART_UINT, &hf_048_RE_M5N_05_SQUAWK, NULL };
static const FieldPart *I048_RE_M5N_05_PARTS[] = { &I048_RE_M5N_05_V,
                                                    &I048_RE_M5N_05_G,
                                                    &I048_RE_M5N_05_L,
                                                    &IXXX_1bit_spare,
                                                    &I048_RE_M5N_05_SQUAWK,
                                                    NULL };

/* Time Offset for POS and GA */
static const FieldPart I048_RE_M5N_06_TOS = { 8, 1.0/128.0, FIELD_PART_FLOAT, &hf_048_RE_M5N_06_TOS, NULL };
static const FieldPart *I048_RE_M5N_06_PARTS[] = { &I048_RE_M5N_06_TOS, NULL };

/* X Pulse Presence */
static const value_string valstr_048_RE_M5N_07_XP[] = {
    { 0, "X-Pulse not present" },
    { 1, "X-pulse present" },
    { 0, NULL }
};
static const value_string valstr_048_RE_M5N_07_X5[] = {
    { 0, "X-pulse set to zero or no authenticated Data reply or Report received" },
    { 1, "X-pulse set to one (present)" },
    { 0, NULL }
};
static const value_string valstr_048_RE_M5N_07_XC[] = {
    { 0, "X-pulse set to zero or no Mode C reply" },
    { 1, "X-pulse set to one (present)" },
    { 0, NULL }
};
static const value_string valstr_048_RE_M5N_07_X3[] = {
    { 0, "X-pulse set to zero or no Mode 3/A reply" },
    { 1, "X-pulse set to one (present)" },
    { 0, NULL }
};
static const value_string valstr_048_RE_M5N_07_X2[] = {
    { 0, "X-pulse set to zero or no Mode 2 reply" },
    { 1, "X-pulse set to one (present)" },
    { 0, NULL }
};
static const value_string valstr_048_RE_M5N_07_X1[] = {
    { 0, "X-pulse set to zero or no Mode 1 reply" },
    { 1, "X-pulse set to one (present)" },
    { 0, NULL }
};
static const FieldPart I048_RE_M5N_07_XP = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_M5N_07_XP, NULL };
static const FieldPart I048_RE_M5N_07_X5 = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_M5N_07_X5, NULL };
static const FieldPart I048_RE_M5N_07_XC = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_M5N_07_XC, NULL };
static const FieldPart I048_RE_M5N_07_X3 = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_M5N_07_X3, NULL };
static const FieldPart I048_RE_M5N_07_X2 = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_M5N_07_X2, NULL };
static const FieldPart I048_RE_M5N_07_X1 = { 1, 1.0, FIELD_PART_UINT, &hf_048_RE_M5N_07_X1, NULL };
static const FieldPart *I048_RE_M5N_07_PARTS[] = { &IXXX_2bit_spare,
                                                   &I048_RE_M5N_07_XP,
                                                   &I048_RE_M5N_07_X5,
                                                   &I048_RE_M5N_07_XC,
                                                   &I048_RE_M5N_07_X3,
                                                   &I048_RE_M5N_07_X2,
                                                   &I048_RE_M5N_07_X1,
                                                   NULL };

/* Figure of Merit */
static const FieldPart I048_RE_M5N_08_FOM = { 5, 1.0, FIELD_PART_UINT, &hf_048_RE_M5N_08_FOM, NULL };
static const FieldPart *I048_RE_M5N_08_PARTS[] = { &IXXX_3bit_spare,
                                                    &I048_RE_M5N_08_FOM,
                                                    NULL };

/* M4E - Extended Mode 4 Report */
static const value_string valstr_048_RE_M4E_FOE_FRI[] = {
    { 0, "No Mode 4 identification" },
    { 1, "Possibly friendly target" },
    { 2, "Probably friendly target" },
    { 3, "Friendly target" },
    { 0, NULL }
};
static const FieldPart I048_RE_M4E_FOE_FRI = { 2, 1.0, FIELD_PART_UINT, &hf_048_RE_M4E_FOE_FRI, NULL };
static const FieldPart *I048_RE_M4E_PARTS[] = { &IXXX_5bit_spare,
                                                &I048_RE_M4E_FOE_FRI,
                                                &IXXX_FX,
                                                NULL };

/* Radar Plot Characteristics */

/* Score */
static const FieldPart I048_RE_RPC_01_SCO = { 8, 1.0, FIELD_PART_UINT, &hf_048_RE_RPC_01_SCO, NULL };
static const FieldPart *I048_RE_RPC_01_PARTS[] = { &I048_RE_RPC_01_SCO, NULL };

/* Signal / Clutter Ratio */
static const FieldPart I048_RE_RPC_02_SCR = { 16, 0.1, FIELD_PART_UFLOAT, &hf_048_RE_RPC_02_SCR, NULL };
static const FieldPart *I048_RE_RPC_02_PARTS[] = { &I048_RE_RPC_02_SCR, NULL };

/* Range Width */
static const FieldPart I048_RE_RPC_03_RW = { 16, 1.0/256.0, FIELD_PART_UFLOAT, &hf_048_RE_RPC_03_RW, NULL };
static const FieldPart *I048_RE_RPC_03_PARTS[] = { &I048_RE_RPC_03_RW, NULL };

/* Ambiguous Range */
static const FieldPart I048_RE_RPC_04_AR = { 16, 1.0/256.0, FIELD_PART_UFLOAT, &hf_048_RE_RPC_04_AR, NULL };
static const FieldPart *I048_RE_RPC_04_PARTS[] = { &I048_RE_RPC_04_AR, NULL };

/* Extended Range Report */
static const FieldPart I048_RE_ERR_RHO = { 24, 1.0/256.0, FIELD_PART_UFLOAT, &hf_048_RE_ERR_RHO, NULL };
static const FieldPart *I048_RE_ERR_PARTS[] = { &I048_RE_ERR_RHO, NULL };

/* Items */
DIAG_OFF_PEDANTIC
static const AsterixField I048_010 = { FIXED, 2, 0, 0, &hf_048_010, IXXX_SAC_SIC, { NULL } };
static const AsterixField I048_020 = { FX, 1, 0, 0, &hf_048_020, I048_020_PARTS, { NULL } };
static const AsterixField I048_020_v1_21 = { FX, 1, 0, 0, &hf_048_020, I048_020_PARTS_v1_21, { NULL } };
static const AsterixField I048_020_v1_17 = { FX, 1, 0, 0, &hf_048_020, I048_020_PARTS_v1_17, { NULL } };
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
static const AsterixField I048_170_v1_21 = { FX, 1, 0, 0, &hf_048_170, I048_170_PARTS_v1_21, { NULL } };
static const AsterixField I048_200 = { FIXED, 4, 0, 0, &hf_048_200, I048_200_PARTS, { NULL } };
static const AsterixField I048_210 = { FIXED, 4, 0, 0, &hf_048_210, I048_210_PARTS, { NULL } };
static const AsterixField I048_220 = { FIXED, 3, 0, 0, &hf_048_220, IXXX_AA_PARTS, { NULL } };
static const AsterixField I048_230 = { FIXED, 2, 0, 0, &hf_048_230, I048_230_PARTS, { NULL } };
static const AsterixField I048_240 = { FIXED, 6, 0, 0, &hf_048_240, IXXX_AI_PARTS, { NULL } };
static const AsterixField I048_250 = { REPETITIVE, 8, 1, 0, &hf_048_250, IXXX_MB, { NULL } };
static const AsterixField I048_260 = { FIXED, 7, 0, 0, &hf_048_260, I048_260_PARTS, { NULL } };
static const AsterixField I048_RE_MD5_01 = { FX, 1, 0, 0, &hf_048_RE_MD5_01, I048_RE_MD5_01_PARTS, { NULL } };
static const AsterixField I048_RE_MD5_02 = { FIXED, 4, 0, 0, &hf_048_RE_MD5_02, I048_RE_MD5_02_PARTS, { NULL } };
static const AsterixField I048_RE_MD5_03 = { FIXED, 6, 0, 0, &hf_048_RE_MD5_03, I048_RE_MD5_03_PARTS, { NULL } };
static const AsterixField I048_RE_MD5_04 = { FIXED, 2, 0, 0, &hf_048_RE_MD5_04, I048_RE_MD5_04_PARTS, { NULL } };
static const AsterixField I048_RE_MD5_05 = { FIXED, 2, 0, 0, &hf_048_RE_MD5_05, I048_RE_MD5_05_PARTS, { NULL } };
static const AsterixField I048_RE_MD5_06 = { FIXED, 1, 0, 0, &hf_048_RE_MD5_06, I048_RE_MD5_06_PARTS, { NULL } };
static const AsterixField I048_RE_MD5_07 = { FIXED, 1, 0, 0, &hf_048_RE_MD5_07, I048_RE_MD5_07_PARTS, { NULL } };
static const AsterixField I048_RE_MD5 = { COMPOUND, 0, 0, 0, &hf_048_RE_MD5, NULL, { &I048_RE_MD5_01,
                                                                                     &I048_RE_MD5_02,
                                                                                     &I048_RE_MD5_03,
                                                                                     &I048_RE_MD5_04,
                                                                                     &I048_RE_MD5_05,
                                                                                     &I048_RE_MD5_06,
                                                                                     &I048_RE_MD5_07,
                                                                                     NULL } };
static const AsterixField I048_RE_M5N_01 = { FX, 1, 0, 0, &hf_048_RE_M5N_01, I048_RE_M5N_01_PARTS, { NULL } };
static const AsterixField I048_RE_M5N_02 = { FIXED, 4, 0, 0, &hf_048_RE_M5N_02, I048_RE_M5N_02_PARTS, { NULL } };
static const AsterixField I048_RE_M5N_03 = { FIXED, 6, 0, 0, &hf_048_RE_M5N_03, I048_RE_M5N_03_PARTS, { NULL } };
static const AsterixField I048_RE_M5N_04 = { FIXED, 2, 0, 0, &hf_048_RE_M5N_04, I048_RE_M5N_04_PARTS, { NULL } };
static const AsterixField I048_RE_M5N_05 = { FIXED, 2, 0, 0, &hf_048_RE_M5N_05, I048_RE_M5N_05_PARTS, { NULL } };
static const AsterixField I048_RE_M5N_06 = { FIXED, 1, 0, 0, &hf_048_RE_M5N_06, I048_RE_M5N_06_PARTS, { NULL } };
static const AsterixField I048_RE_M5N_07 = { FIXED, 1, 0, 0, &hf_048_RE_M5N_07, I048_RE_M5N_07_PARTS, { NULL } };
static const AsterixField I048_RE_M5N_08 = { FIXED, 1, 0, 0, &hf_048_RE_M5N_08, I048_RE_M5N_08_PARTS, { NULL } };
static const AsterixField I048_RE_M5N = { COMPOUND, 0, 0, 0, &hf_048_RE_M5N, NULL, { &I048_RE_M5N_01,
                                                                                     &I048_RE_M5N_02,
                                                                                     &I048_RE_M5N_03,
                                                                                     &I048_RE_M5N_04,
                                                                                     &I048_RE_M5N_05,
                                                                                     &I048_RE_M5N_06,
                                                                                     &I048_RE_M5N_07,
                                                                                     &I048_RE_M5N_08,
                                                                                     NULL } };
static const AsterixField I048_RE_M4E = { FX, 1, 0, 0, &hf_048_RE_M4E, I048_RE_M4E_PARTS, { NULL } };
static const AsterixField I048_RE_RPC_01 = { FIXED, 1, 0, 0, &hf_048_RE_RPC_01, I048_RE_RPC_01_PARTS, { NULL } };
static const AsterixField I048_RE_RPC_02 = { FIXED, 2, 0, 0, &hf_048_RE_RPC_02, I048_RE_RPC_02_PARTS, { NULL } };
static const AsterixField I048_RE_RPC_03 = { FIXED, 2, 0, 0, &hf_048_RE_RPC_03, I048_RE_RPC_03_PARTS, { NULL } };
static const AsterixField I048_RE_RPC_04 = { FIXED, 2, 0, 0, &hf_048_RE_RPC_04, I048_RE_RPC_04_PARTS, { NULL } };
static const AsterixField I048_RE_RPC = { COMPOUND, 0, 0, 0, &hf_048_RE_RPC, NULL, { &I048_RE_RPC_01,
                                                                                     &I048_RE_RPC_02,
                                                                                     &I048_RE_RPC_03,
                                                                                     &I048_RE_RPC_04,
                                                                                     NULL } };
static const AsterixField I048_RE_ERR = { FIXED, 3, 0, 0, &hf_048_RE_ERR, I048_RE_ERR_PARTS, { NULL } };
static const AsterixField I048_RE = { RE, 0, 0, 1, &hf_048_RE, NULL, { &I048_RE_MD5, &I048_RE_M5N, &I048_RE_M4E, &I048_RE_RPC, &I048_RE_ERR, NULL } };
static const AsterixField I048_SP = { SP, 0, 0, 1, &hf_048_SP, NULL, { NULL } };

static const AsterixField *I048_v1_23_uap[] = { &I048_010, &I048_140, &I048_020, &I048_040, &I048_070, &I048_090, &I048_130,
                                                &I048_220, &I048_240, &I048_250, &I048_161, &I048_042, &I048_200, &I048_170,
                                                &I048_210, &I048_030, &I048_080, &I048_100, &I048_110, &I048_120, &I048_230,
                                                &I048_260, &I048_055, &I048_050, &I048_065, &I048_060, &I048_SP,  &I048_RE, NULL };
static const AsterixField *I048_v1_21_uap[] = { &I048_010, &I048_140, &I048_020_v1_21, &I048_040, &I048_070, &I048_090, &I048_130,
                                                &I048_220, &I048_240, &I048_250, &I048_161, &I048_042, &I048_200, &I048_170_v1_21,
                                                &I048_210, &I048_030, &I048_080, &I048_100, &I048_110, &I048_120, &I048_230,
                                                &I048_260, &I048_055, &I048_050, &I048_065, &I048_060, &I048_SP,  &I048_RE, NULL };
static const AsterixField *I048_v1_17_uap[] = { &I048_010, &I048_140, &I048_020_v1_17, &I048_040, &I048_070, &I048_090, &I048_130,
                                                &I048_220, &I048_240, &I048_250, &I048_161, &I048_042, &I048_200, &I048_170_v1_21,
                                                &I048_210, &I048_030, &I048_080, &I048_100, &I048_110, &I048_120, &I048_230,
                                                &I048_260, &I048_055, &I048_050, &I048_065, &I048_060, &I048_SP,  &I048_RE, NULL };
static const AsterixField **I048_v1_23[] = { I048_v1_23_uap, NULL };
static const AsterixField **I048_v1_21[] = { I048_v1_21_uap, NULL };
static const AsterixField **I048_v1_17[] = { I048_v1_17_uap, NULL };
static const AsterixField ***I048[] = { I048_v1_23, I048_v1_21, I048_v1_17 };
DIAG_ON_PEDANTIC

static const enum_val_t I048_versions[] = {
    { "I048_v1_23", "Version 1.23", 0 },
    { "I048_v1_21", "Version 1.21", 1 },
    { "I048_v1_17", "Version 1.17", 2 },
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
static const value_string valstr_062_060_V[] = {
    { 0, "Code validated" },
    { 1, "Code not validated" },
    { 0, NULL }
};
static const value_string valstr_062_060_G[] = {
    { 0, "Default" },
    { 1, "Garbled code" },
    { 0, NULL }
};
static const value_string valstr_062_060_CH[] = {
    { 0, "No change" },
    { 1, "Mode 3/A has changed" },
    { 0, NULL }
};

static const FieldPart I062_060_V = { 1, 1.0, FIELD_PART_UINT, &hf_062_060_V, NULL };
static const FieldPart I062_060_G = { 1, 1.0, FIELD_PART_UINT, &hf_062_060_G, NULL };
static const FieldPart I062_060_CH = { 1, 1.0, FIELD_PART_UINT, &hf_062_060_CH, NULL };
static const FieldPart I062_060_SQUAWK = { 12, 1.0, FIELD_PART_SQUAWK, &hf_062_060_SQUAWK, NULL };
static const FieldPart *I062_060_PARTS[] = { &I062_060_V, &I062_060_G, &I062_060_CH, &IXXX_1bit_spare, &I062_060_SQUAWK, NULL };
static const FieldPart *I062_060_PARTS_v1_16[] = { &IXXX_2bit_spare, &I062_060_CH, &IXXX_1bit_spare, &I062_060_SQUAWK, NULL };
static const FieldPart *I062_060_PARTS_v0_17[] = { &IXXX_4bit_spare, &I062_060_SQUAWK, NULL };

/* Track Status */
static const value_string valstr_062_080_MON[] = {
    { 0, "Multisensor" },
    { 1, "Monosensor track track" },
    { 0, NULL }
};
static const value_string valstr_062_080_SPI[] = {
    { 0, "Default value" },
    { 1, "SPI present in the last report received from a sensor capable of decoding this data" },
    { 0, NULL }
};
static const value_string valstr_062_080_MRH[] = {
    { 0, "Barometric altitude (Mode C) more reliable" },
    { 1, "Geometric altitude more reliable" },
    { 0, NULL }
};
static const value_string valstr_062_080_SRC[] = {
    { 0, "No source" },
    { 1, "GNSS" },
    { 2, "3D radar" },
    { 3, "Triangulation" },
    { 4, "Height from coverage" },
    { 5, "Speed look-up table" },
    { 6, "Default height" },
    { 7, "Multilateration" },
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
    { 0, "Default value" },
    { 1, "Last message transmitted to the user for the track" },
    { 0, NULL }
};
static const value_string valstr_062_080_TSB[] = {
    { 0, "Default value" },
    { 1, "First message transmitted to the user for the track" },
    { 0, NULL }
};
static const value_string valstr_062_080_FPC[] = {
    { 0, "Not flight-plan correlated" },
    { 1, "Flight plan correlated" },
    { 0, NULL }
};
static const value_string valstr_062_080_AFF[] = {
    { 0, "Default value" },
    { 1, "ADS-B data inconsistent with other surveillance information" },
    { 0, NULL }
};
static const value_string valstr_062_080_STP[] = {
    { 0, "Default value" },
    { 1, "Slave Track Promotion" },
    { 0, NULL }
};
static const value_string valstr_062_080_KOS[] = {
    { 0, "Complementary service used" },
    { 1, "Background service used" },
    { 0, NULL }
};
static const value_string valstr_062_080_AMA[] = {
    { 0, "Track not resulting from amalgamation process" },
    { 1, "Track resulting from amalgamation process" },
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
    { 0, "Default value" },
    { 1, "Military Emergency present in the last report received from a sensor capable of decoding this data" },
    { 0, NULL }
};
static const value_string valstr_062_080_MI[] = {
    { 0, "Default value" },
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
static const value_string valstr_062_080_SFC[] = {
    { 0, "Default value" },
    { 1, "Surface target" },
    { 0, NULL }
};
static const value_string valstr_062_080_IDD[] = {
    { 0, "Default value" },
    { 1, "Duplicate Flight-ID" },
    { 0, NULL }
};
static const value_string valstr_062_080_IEC[] = {
    { 0, "Default value" },
    { 1, "Inconsistent Emergency Code" },
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
static const FieldPart I062_080_FPLT = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_FPLT, NULL };
static const FieldPart I062_080_DUPT = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_DUPT, NULL };
static const FieldPart I062_080_DUPF = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_DUPF, NULL };
static const FieldPart I062_080_DUPM = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_DUPM, NULL };
static const FieldPart I062_080_SFC = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_SFC, NULL };
static const FieldPart I062_080_IDD = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_IDD, NULL };
static const FieldPart I062_080_IEC = { 1, 1.0, FIELD_PART_UINT, &hf_062_080_IEC, NULL };
static const FieldPart I062_080_FRIFOE = { 2, 1.0, FIELD_PART_UINT, &hf_062_080_FRIFOE, NULL };
static const FieldPart I062_080_COA = { 2, 1.0, FIELD_PART_UINT, &hf_062_080_COA, NULL };
static const FieldPart *I062_080_PARTS[] = { &I062_080_MON, &I062_080_SPI, &I062_080_MRH, &I062_080_SRC, &I062_080_CNF, &IXXX_FX,
                                             &I062_080_SIM, &I062_080_TSE, &I062_080_TSB, &I062_080_FPC, &I062_080_AFF, &I062_080_STP, &I062_080_KOS, &IXXX_FX,
                                             &I062_080_AMA, &I062_080_MD4, &I062_080_ME, &I062_080_MI, &I062_080_MD5, &IXXX_FX,
                                             &I062_080_CST, &I062_080_PSR, &I062_080_SSR, &I062_080_MDS, &I062_080_ADS, &I062_080_SUC, &I062_080_AAC, &IXXX_FX,
                                             &I062_080_SDS, &I062_080_EMS, &I062_080_PFT, &I062_080_FPLT, &IXXX_FX,
                                             &I062_080_DUPT, &I062_080_DUPF, &I062_080_DUPM, &I062_080_SFC, &I062_080_IDD, &I062_080_IEC, &IXXX_1bit_spare, &IXXX_FX, NULL };
static const FieldPart *I062_080_PARTS_v1_17[] = { &I062_080_MON, &I062_080_SPI, &I062_080_MRH, &I062_080_SRC, &I062_080_CNF, &IXXX_FX,
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
static const FieldPart *I062_110_04_PARTS[] = { &IXXX_1bit_spare, &I062_110_04_RES, &I062_110_04_GA, NULL };

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
static const FieldPart I062_135_ALT = { 15, 1.0/4.0, FIELD_PART_FLOAT, &hf_062_135_ALT, NULL };
static const FieldPart *I062_135_PARTS[] = { &I062_135_QNH, &I062_135_ALT, NULL };

/* Measured Flight Level */
static const FieldPart I062_136_MFL = { 16, 1.0/4.0, FIELD_PART_FLOAT, &hf_062_136_MFL, NULL };
static const FieldPart *I062_136_PARTS[] = { &I062_136_MFL, NULL };

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

/* Target Identification */
static const value_string valstr_062_245_STI[] = {
    { 0, "Callsign or registration downlinked from target" },
    { 1, "Callsign not downlinked from target" },
    { 2, "Registration not downlinked from target" },
    { 3, "Invalid" },
    { 0, NULL }
};
static const FieldPart I062_245_STI = { 2, 1.0, FIELD_PART_UINT, &hf_062_245_STI, NULL };
static const FieldPart *I062_245_PARTS[] = { &I062_245_STI, &IXXX_6bit_spare, &IXXX_AI, NULL };

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
static const FieldPart I062_295_07_MHG = { 8, 0.25, FIELD_PART_UFLOAT, &hf_062_295_07_MHG, NULL };
static const FieldPart *I062_295_07_PARTS[] = { &I062_295_07_MHG, NULL };
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
static const FieldPart I062_380_04_IM = { 1, 1.0, FIELD_PART_IAS_IM, &hf_062_380_04_IM, NULL };
static const FieldPart I062_380_04_IAS = { 15, 1.0, FIELD_PART_IAS_ASPD, &hf_062_380_04_IAS, NULL };
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
static const FieldPart I062_380_06_ALT = { 13, 25.0, FIELD_PART_FLOAT, &hf_062_380_06_ALT, NULL };
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
static const FieldPart I062_380_07_ALT = { 13, 25.0, FIELD_PART_FLOAT, &hf_062_380_07_ALT, NULL };
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
static const FieldPart I062_380_09_TD = { 2, 1.0, FIELD_PART_UINT, &hf_062_380_09_TD, NULL };
static const FieldPart I062_380_09_TRA = { 1, 1.0, FIELD_PART_UINT, &hf_062_380_09_TRA, NULL };
static const FieldPart I062_380_09_TOA = { 1, 1.0, FIELD_PART_UINT, &hf_062_380_09_TOA, NULL };
static const FieldPart I062_380_09_TOV = { 24, 1.0, FIELD_PART_UFLOAT, &hf_062_380_09_TOV, NULL };
static const FieldPart I062_380_09_TTR = { 16, 0.01, FIELD_PART_UFLOAT, &hf_062_380_09_TTR, NULL };
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
    { 6, "Not defined" },
    { 7, "Unknown or not yet extracted" },
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
    { 0, "Unknown" },
    { 1, "ACAS not operational" },
    { 2, "ACAS operational" },
    { 3, "Invalid" },
    { 0, NULL }
};
static const value_string valstr_062_380_11_MN[] = {
    { 0, "Unknown" },
    { 1, "Multiple navigational aids not operating" },
    { 2, "Multiple navigational aids operating" },
    { 3, "Invalid" },
    { 0, NULL }
};
static const value_string valstr_062_380_11_DC[] = {
    { 0, "Unknown" },
    { 1, "Differential correction" },
    { 2, "No differential correction" },
    { 3, "Invalid" },
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
static const FieldPart I062_380_17_TA = { 16, 360.0/65536.0, FIELD_PART_UFLOAT, &hf_062_380_17_TA, NULL };
static const FieldPart *I062_380_17_PARTS[] = { &I062_380_17_TA, NULL };

/* Ground Speed */
static const FieldPart I062_380_18_GS = { 16, 1.0/16384.0, FIELD_PART_FLOAT, &hf_062_380_18_GS, NULL };
static const FieldPart *I062_380_18_PARTS[] = { &I062_380_18_GS, NULL };

/* Velocity Uncertainty */
static const FieldPart I062_380_19_VUC = { 8, 1.0, FIELD_PART_UINT, &hf_062_380_19_VUC, NULL };
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
    {  2, "Reserved" },
    {  3, "7000 kg < medium aircraft < 136000 kg" },
    {  4, "Reserved" },
    {  5, "136000 kg <= heavy aircraft" },
    {  6, "Highly manoeuvrable (5g acceleration capability) and high speed (>400 knots cruise)" },
    {  7, "Reserved" },
    {  8, "Reserved" },
    {  9, "Reserved" },
    { 10, "Rotocraft" },
    { 11, "Glider / sailplane" },
    { 12, "Lighter-than-air" },
    { 13, "Unmanned aerial vehicle" },
    { 14, "Space / transatmospheric vehicle" },
    { 15, "Ultralight / handglider / paraglider" },
    { 16, "Parachutist / skydiver" },
    { 17, "Reserved" },
    { 18, "Reserved" },
    { 19, "Reserved" },
    { 20, "Surface emergency vehicle" },
    { 21, "Surface service vehicle" },
    { 22, "Fixed ground or tethered obstruction" },
    { 23, "Reserved" },
    { 24, "Reserved" },
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
static const FieldPart I062_390_09_RWY = { 24, 1.0, FIELD_PART_ASCII, &hf_062_390_09_RWY, NULL };
static const FieldPart *I062_390_09_PARTS[] = { &I062_390_09_RWY, NULL };

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
static const FieldPart I062_500_03_APWLAT = { 16, 180.0/33554432.0, FIELD_PART_UFLOAT, &hf_062_500_03_APWLAT, NULL };
static const FieldPart I062_500_03_APWLON = { 16, 180.0/33554432.0, FIELD_PART_UFLOAT, &hf_062_500_03_APWLON, NULL };
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

/* Note: I062/510 is an FX field that has no limit on the number of extensions.
 * There is currently no function available for us to deal dynamically with that so we
 * will just hardcode support for a maximum of 5 extensions (4 slaves).
 **/

/* Composed Track Number */
static const FieldPart I062_510_SUD = { 8, 1.0, FIELD_PART_UINT, &hf_062_510_SUD, NULL };
static const FieldPart I062_510_STN = { 15, 1.0, FIELD_PART_UINT, &hf_062_510_STN, NULL };
static const FieldPart I062_510_SLV_01_SUD = { 8, 1.0, FIELD_PART_UINT, &hf_062_510_SLV_01_SUD, NULL };
static const FieldPart I062_510_SLV_01_STN = { 15, 1.0, FIELD_PART_UINT, &hf_062_510_SLV_01_STN, NULL };
static const FieldPart I062_510_SLV_02_SUD = { 8, 1.0, FIELD_PART_UINT, &hf_062_510_SLV_02_SUD, NULL };
static const FieldPart I062_510_SLV_02_STN = { 15, 1.0, FIELD_PART_UINT, &hf_062_510_SLV_02_STN, NULL };
static const FieldPart I062_510_SLV_03_SUD = { 8, 1.0, FIELD_PART_UINT, &hf_062_510_SLV_03_SUD, NULL };
static const FieldPart I062_510_SLV_03_STN = { 15, 1.0, FIELD_PART_UINT, &hf_062_510_SLV_03_STN, NULL };
static const FieldPart I062_510_SLV_04_SUD = { 8, 1.0, FIELD_PART_UINT, &hf_062_510_SLV_04_SUD, NULL };
static const FieldPart I062_510_SLV_04_STN = { 15, 1.0, FIELD_PART_UINT, &hf_062_510_SLV_04_STN, NULL };
static const FieldPart *I062_510_PARTS[] = {
    &I062_510_SUD, &I062_510_STN, &IXXX_3FX,
    &I062_510_SLV_01_SUD, &I062_510_SLV_01_STN, &IXXX_3FX,
    &I062_510_SLV_02_SUD, &I062_510_SLV_02_STN, &IXXX_3FX,
    &I062_510_SLV_03_SUD, &I062_510_SLV_03_STN, &IXXX_3FX,
    &I062_510_SLV_04_SUD, &I062_510_SLV_04_STN, &IXXX_3FX,
    NULL };

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
static const FieldPart I062_RE_CST_TYPE = { 8, 1.0, FIELD_PART_UINT, &hf_062_RE_CST_TYP, NULL };
static const FieldPart I062_RE_CST_TRK_NUM = { 16, 1.0, FIELD_PART_UINT, &hf_062_RE_CST_TRK_NUM, NULL };
static const FieldPart *I062_RE_CST_PARTS[] = { &IXXX_SAC, &IXXX_SIC, &I062_RE_CST_TYPE, &I062_RE_CST_TRK_NUM, NULL };

/*Contributing Sensors with No Local Track Numbers*/
static const FieldPart I062_RE_CSNT_TYPE = { 8, 1.0, FIELD_PART_UINT, &hf_062_RE_CSNT_TYP, NULL };
static const FieldPart *I062_RE_CSNT_PARTS[] = { &IXXX_SAC, &IXXX_SIC, &I062_RE_CSNT_TYPE, NULL };

/*Calculated Track Velocity Relative to System Reference Point*/
static const FieldPart I062_RE_TVS_VX = { 16, 0.25, FIELD_PART_FLOAT, &hf_062_RE_TVS_VX, NULL };
static const FieldPart I062_RE_TVS_VY = { 16, 0.25, FIELD_PART_FLOAT, &hf_062_RE_TVS_VY, NULL };
static const FieldPart *I062_RE_TVS_PARTS[] = { &I062_RE_TVS_VX, &I062_RE_TVS_VY, NULL };

/*Supplementary Track Status*/
static const FieldPart I062_RE_STS_FDR = { 1, 1.0, FIELD_PART_UINT, &hf_062_RE_STS_FDR, NULL };
static const FieldPart *I062_RE_STS_PARTS[] = { &I062_RE_STS_FDR, &IXXX_6bit_spare, &IXXX_FX, NULL };


/* Items */
DIAG_OFF_PEDANTIC
static const AsterixField I062_010 = { FIXED, 2, 0, 0, &hf_062_010, IXXX_SAC_SIC, { NULL } };
static const AsterixField I062_015 = { FIXED, 1, 0, 0, &hf_062_015, I062_015_PARTS, { NULL } };
static const AsterixField I062_040 = { FIXED, 2, 0, 0, &hf_062_040, IXXX_TN_16_PARTS, { NULL } };
static const AsterixField I062_060 = { FIXED, 2, 0, 0, &hf_062_060, I062_060_PARTS, { NULL } };
static const AsterixField I062_060_v1_16 = { FIXED, 2, 0, 0, &hf_062_060, I062_060_PARTS_v1_16, { NULL } };
static const AsterixField I062_060_v0_17 = { FIXED, 2, 0, 0, &hf_062_060, I062_060_PARTS_v0_17, { NULL } };
static const AsterixField I062_070 = { FIXED, 3, 0, 0, &hf_062_070, IXXX_TOD, { NULL } };
static const AsterixField I062_080 = { FX, 1, 0, 0, &hf_062_080, I062_080_PARTS, { NULL } };
static const AsterixField I062_080_v1_17 = { FX, 1, 0, 0, &hf_062_080, I062_080_PARTS_v1_17, { NULL } };
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
static const AsterixField I062_245 = { FIXED, 7, 0, 0, &hf_062_245, I062_245_PARTS, { NULL } };
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

static const AsterixField *I062_v1_18_uap[] = { &I062_010, &IX_SPARE, &I062_015, &I062_070, &I062_105, &I062_100, &I062_185,
                                                &I062_210, &I062_060, &I062_245, &I062_380, &I062_040, &I062_080, &I062_290,
                                                &I062_200, &I062_295, &I062_136, &I062_130, &I062_135, &I062_220, &I062_390,
                                                &I062_270, &I062_300, &I062_110, &I062_120, &I062_510, &I062_500, &I062_340,
                                                &IX_SPARE, &IX_SPARE, &IX_SPARE, &IX_SPARE, &IX_SPARE, &I062_RE,  &I062_SP, NULL };
static const AsterixField *I062_v1_17_uap[] = { &I062_010, &IX_SPARE, &I062_015, &I062_070, &I062_105, &I062_100, &I062_185,
                                                &I062_210, &I062_060, &I062_245, &I062_380, &I062_040, &I062_080_v1_17, &I062_290,
                                                &I062_200, &I062_295, &I062_136, &I062_130, &I062_135, &I062_220, &I062_390,
                                                &I062_270, &I062_300, &I062_110, &I062_120, &I062_510, &I062_500, &I062_340,
                                                &IX_SPARE, &IX_SPARE, &IX_SPARE, &IX_SPARE, &IX_SPARE, &I062_RE,  &I062_SP, NULL };
static const AsterixField *I062_v1_16_uap[] = { &I062_010, &IX_SPARE, &I062_015, &I062_070, &I062_105, &I062_100, &I062_185,
                                                &I062_210, &I062_060_v1_16, &I062_245, &I062_380, &I062_040, &I062_080, &I062_290,
                                                &I062_200, &I062_295, &I062_136, &I062_130, &I062_135, &I062_220, &I062_390,
                                                &I062_270, &I062_300, &I062_110, &I062_120, &I062_510, &I062_500, &I062_340,
                                                &IX_SPARE, &IX_SPARE, &IX_SPARE, &IX_SPARE, &IX_SPARE, &I062_RE,  &I062_SP, NULL };
static const AsterixField *I062_v0_17_uap[] = { &I062_010, &I062_015, &I062_070, &I062_040, &I062_105_v0_17, &I062_100_v0_17, &I062_060_v0_17,
                                                &I062_130, &I062_135, &I062_136, &I062_180, &I062_200_v0_17, &I062_220, &I062_240,
                                                &I062_210_v0_17, &I062_080_v0_17, &I062_290_v0_17, &I062_340, &I062_380_v0_17, &I062_500_v0_17, &I062_390,
                                                &I062_110_v0_17, &I062_120, &I062_510, &IX_SPARE, &IX_SPARE, &I062_RE,  &I062_SP, NULL };
static const AsterixField **I062_v1_18[] = { I062_v1_18_uap, NULL };
static const AsterixField **I062_v1_17[] = { I062_v1_17_uap, NULL };
static const AsterixField **I062_v1_16[] = { I062_v1_16_uap, NULL };
static const AsterixField **I062_v0_17[] = { I062_v0_17_uap, NULL };
static const AsterixField ***I062[] = { I062_v1_18, I062_v1_17, I062_v1_16, I062_v0_17 };
DIAG_ON_PEDANTIC

static const enum_val_t I062_versions[] = {
    { "I062_v1_18", "Version 1.18", 0 },
    { "I062_v1_17", "Version 1.17", 1 },
    { "I062_v1_16", "Version 1.16", 2 },
    { "I062_v0_17", "Version 0.17", 3 },
    { NULL, NULL, 0 }
};

/* *********************** */
/*      Category 063       */
/* *********************** */
/* Fields */

/* Service Identification */
static const FieldPart I063_015_SI = { 8, 1.0, FIELD_PART_UINT, &hf_063_015_SI, NULL };
static const FieldPart *I063_015_PARTS[] = { &I063_015_SI, NULL };

/* Sensor Configuration and Status */
static const value_string valstr_063_060_CON[] = {
    { 0, "Operational"},
    { 1, "Degraded"},
    { 2, "Initialization"},
    { 3, "Not currently connected"},
    { 0, NULL}
};

static const value_string valstr_063_060_PSR[] = {
    { 0, "PSR GO"},
    { 1, "PSR NOGO"},
    { 0, NULL}
};

static const value_string valstr_063_060_SSR[] = {
    { 0, "SSR GO"},
    { 1, "SSR NOGO"},
    { 0, NULL}
};

static const value_string valstr_063_060_MDS[] = {
    { 0, "Mode S GO"},
    { 1, "Mode S NOGO"},
    { 0, NULL}
};

static const value_string valstr_063_060_ADS[] = {
    { 0, "ADS GO"},
    { 1, "ADS NOGO"},
    { 0, NULL}
};

static const value_string valstr_063_060_MLT[] = {
    { 0, "MLT GO"},
    { 1, "MLT NOGO"},
    { 0, NULL}
};

static const value_string valstr_063_060_OPS[] = {
    { 0, "System is released for operational use"},
    { 1, "Operational use of System is inhibited"},
    { 0, NULL}
};

static const value_string valstr_063_060_ODP[] = {
    { 0, "Default, no overload"},
    { 1, "Overload in DP"},
    { 0, NULL}
};

static const value_string valstr_063_060_OXT[] = {
    { 0, "Default, no overload"},
    { 1, "Overload in transmission subsystem"},
    { 0, NULL}
};

static const value_string valstr_063_060_MSC[] = {
    { 0, "Monitoring system connected"},
    { 1, "Monitoring system disconnected"},
    { 0, NULL}
};

static const value_string valstr_063_060_TSV[] = {
    { 0, "Valid"},
    { 1, "Invalid"},
    { 0, NULL}
};

static const value_string valstr_063_060_NPW[] = {
    { 0, "Default (no meaning)"},
    { 1, "No plots being received"},
    { 0, NULL}
};

static const FieldPart I063_060_CON = { 2, 1.0, FIELD_PART_UINT, &hf_063_060_CON, NULL };
static const FieldPart I063_060_PSR = { 1, 1.0, FIELD_PART_UINT, &hf_063_060_PSR, NULL };
static const FieldPart I063_060_SSR = { 1, 1.0, FIELD_PART_UINT, &hf_063_060_SSR, NULL };
static const FieldPart I063_060_MDS = { 1, 1.0, FIELD_PART_UINT, &hf_063_060_MDS, NULL };
static const FieldPart I063_060_ADS = { 1, 1.0, FIELD_PART_UINT, &hf_063_060_ADS, NULL };
static const FieldPart I063_060_MLT = { 1, 1.0, FIELD_PART_UINT, &hf_063_060_MLT, NULL };
static const FieldPart I063_060_OPS = { 1, 1.0, FIELD_PART_UINT, &hf_063_060_OPS, NULL };
static const FieldPart I063_060_ODP = { 1, 1.0, FIELD_PART_UINT, &hf_063_060_ODP, NULL };
static const FieldPart I063_060_OXT = { 1, 1.0, FIELD_PART_UINT, &hf_063_060_OXT, NULL };
static const FieldPart I063_060_MSC = { 1, 1.0, FIELD_PART_UINT, &hf_063_060_MSC, NULL };
static const FieldPart I063_060_TSV = { 1, 1.0, FIELD_PART_UINT, &hf_063_060_TSV, NULL };
static const FieldPart I063_060_NPW = { 1, 1.0, FIELD_PART_UINT, &hf_063_060_NPW, NULL };
static const FieldPart *I063_060_PARTS[] = { &I063_060_CON, &I063_060_PSR, &I063_060_SSR, &I063_060_MDS, &I063_060_ADS, &I063_060_MLT, &IXXX_FX,
                                             &I063_060_OPS, &I063_060_ODP, &I063_060_OXT, &I063_060_MSC, &I063_060_TSV, &I063_060_NPW, &IXXX_1bit_spare, &IXXX_FX, NULL };

/* Time Stamping Bias */
static const FieldPart I063_070_TSB = { 16, 1.0, FIELD_PART_UFLOAT, &hf_063_070_TSB, NULL };
static const FieldPart *I063_070_PARTS[] = { &I063_070_TSB, NULL };

/* SSR / Mode S Range Gain and Bias */
static const FieldPart I063_080_SRG = { 16, 0.00001, FIELD_PART_FLOAT, &hf_063_080_SRG, NULL };
static const FieldPart I063_080_SRB = { 16, 1.0 / 128.0, FIELD_PART_FLOAT, &hf_063_080_SRB, NULL };
static const FieldPart *I063_080_PARTS[] = { &I063_080_SRG, &I063_080_SRB, NULL };

/* SSR / MOde S Azimuth Bias */
static const FieldPart I063_081_SAB = { 16, 360.0 / 65536.0, FIELD_PART_FLOAT, &hf_063_081_SAB, NULL };
static const FieldPart *I063_081_PARTS[] = { &I063_081_SAB, NULL };

/* PSR Range Gain and Bias */
static const FieldPart I063_090_PRG = { 16, 0.00001, FIELD_PART_FLOAT, &hf_063_090_PRG, NULL };
static const FieldPart I063_090_PRB = { 16, 1.0 / 128.0, FIELD_PART_FLOAT, &hf_063_090_PRB, NULL };
static const FieldPart *I063_090_PARTS[] = { &I063_090_PRG, &I063_090_PRB, NULL };

/* PSR Azimuth Bias */
static const FieldPart I063_091_PAB = { 16, 360.0 / 65536.0, FIELD_PART_FLOAT, &hf_063_091_PAB, NULL };
static const FieldPart *I063_091_PARTS[] = { &I063_091_PAB, NULL };

/* PSR Elevation Bias */
static const FieldPart I063_092_PEB = { 16, 360.0 / 65536.0, FIELD_PART_FLOAT, &hf_063_092_PEB, NULL };
static const FieldPart *I063_092_PARTS[] = { &I063_092_PEB, NULL };

/* Items */
DIAG_OFF_PEDANTIC
static const AsterixField I063_010 = { FIXED, 2, 0, 0, &hf_063_010, IXXX_SAC_SIC, { NULL } };
static const AsterixField I063_015 = { FIXED, 1, 0, 0, &hf_063_015, I063_015_PARTS, { NULL } };
static const AsterixField I063_030 = { FIXED, 3, 0, 0, &hf_063_030, IXXX_TOD, { NULL } };
static const AsterixField I063_050 = { FIXED, 2, 0, 0, &hf_063_050, IXXX_SAC_SIC, { NULL } };
static const AsterixField I063_060 = { FX, 1, 0, 0, &hf_063_060, I063_060_PARTS, { NULL } };
static const AsterixField I063_070 = { FIXED, 2, 0, 0, &hf_063_070, I063_070_PARTS, { NULL } };
static const AsterixField I063_080 = { FIXED, 4, 0, 0, &hf_063_080, I063_080_PARTS, { NULL } };
static const AsterixField I063_081 = { FIXED, 2, 0, 0, &hf_063_081, I063_081_PARTS, { NULL } };
static const AsterixField I063_090 = { FIXED, 4, 0, 0, &hf_063_090, I063_090_PARTS, { NULL } };
static const AsterixField I063_091 = { FIXED, 2, 0, 0, &hf_063_091, I063_091_PARTS, { NULL } };
static const AsterixField I063_092 = { FIXED, 2, 0, 0, &hf_063_092, I063_092_PARTS, { NULL } };
static const AsterixField I063_RE = { RE, 0, 0, 1, &hf_063_RE, NULL, { NULL } };
static const AsterixField I063_SP = { SP, 0, 0, 1, &hf_063_SP, NULL, { NULL } };

static const AsterixField *I063_v1_4_uap[] = { &I063_010, &I063_015, &I063_030, &I063_050, &I063_060, &I063_070, &I063_080,
                                               &I063_081, &I063_090, &I063_091, &I063_092, &IX_SPARE, &I063_RE,  &I063_SP, NULL };
static const AsterixField **I063_v1_4[] = { I063_v1_4_uap, NULL };
static const AsterixField ***I063[] = { I063_v1_4 };
DIAG_ON_PEDANTIC

static const enum_val_t I063_versions[] = {
    { "I063_v1_4", "Version 1.4", 0 },
    { NULL, NULL, 0 }
};

/* *********************** */
/*      Category 065       */
/* *********************** */
/* Fields */

/* Message Type */
static const value_string valstr_065_000_MT[] = {
    { 0, "Undefined" },
    { 1, "SDPS Status" },
    { 2, "End of Batch" },
    { 3, "Service Status Report" },
    { 0, NULL }
};

static const FieldPart I065_000_MT = { 8, 1.0, FIELD_PART_UINT, &hf_065_000_MT, NULL };
static const FieldPart *I065_000_PARTS[] = { &I065_000_MT, NULL };

/* Service Identification */
static const FieldPart I065_015_SI = { 8, 1.0, FIELD_PART_UINT, &hf_065_015_SI, NULL };
static const FieldPart *I065_015_PARTS[] = { &I065_015_SI, NULL };

/* Batch Number */
static const FieldPart I065_020_BTN = { 8, 1.0, FIELD_PART_UINT, &hf_065_020_BTN, NULL };
static const FieldPart *I065_020_PARTS[] = { &I065_020_BTN, NULL };

/* SDPS Configuration and Status */
static const value_string valstr_065_040_NOGO[] = {
    { 0, "Operational" },
    { 1, "Degraded" },
    { 2, "Not currently connected" },
    { 3, "Unknown" },
    { 0, NULL }
};

static const value_string valstr_065_040_OVL[] = {
    { 0, "Default" },
    { 1, "Overload" },
    { 0, NULL }
};

static const value_string valstr_065_040_TSV[] = {
    { 0, "Default" },
    { 1, "Invalid time source" },
    { 0, NULL }
};

static const value_string valstr_065_040_PSS[] = {
    { 0, "Not applicable" },
    { 1, "SDPS-1 selected" },
    { 2, "SDPS-2 selected" },
    { 3, "SDPS-3 selected" },
    { 0, NULL }
};

static const value_string valstr_065_040_STTN[] = {
    { 0, "Toggle OFF" },
    { 1, "Toggle ON" },
    { 0, NULL }
};

static const FieldPart I065_040_NOGO = { 2, 1.0, FIELD_PART_UINT, &hf_065_040_NOGO, NULL };
static const FieldPart I065_040_OVL = { 1, 1.0, FIELD_PART_UINT, &hf_065_040_OVL, NULL };
static const FieldPart I065_040_TSV = { 1, 1.0, FIELD_PART_UINT, &hf_065_040_TSV, NULL };
static const FieldPart I065_040_PSS = { 2, 1.0, FIELD_PART_UINT, &hf_065_040_PSS, NULL };
static const FieldPart I065_040_STTN = { 1, 1.0, FIELD_PART_UINT, &hf_065_040_STTN, NULL };
static const FieldPart *I065_040_PARTS_v1_3[] = { &I065_040_NOGO, &I065_040_OVL, &I065_040_TSV, &I065_040_PSS, &IXXX_2bit_spare, NULL };
static const FieldPart *I065_040_PARTS_v1_4[] = { &I065_040_NOGO, &I065_040_OVL, &I065_040_TSV, &I065_040_PSS, &I065_040_STTN, &IXXX_1bit_spare, NULL };

/* Service Status Report */
static const value_string valstr_065_050_REP[] = {
    { 1, "service degradation" },
    { 2, "service degradation ended" },
    { 3, "main radar out of service" },
    { 4, "service interrupted by the operator" },
    { 5, "service interrupted due to contingency" },
    { 6, "ready for service restart after contingency" },
    { 7, "service ended by the operator" },
    { 8, "failure of user main radar" },
    { 9, "service restarted by the operator" },
    { 10, "main radar becoming operational" },
    { 11, "main radar becoming degraded" },
    { 12, "service continuity interrupted due to disconnection with adjacent unit" },
    { 13, "service continuity restarted" },
    { 14, "service synchronised on backup radar" },
    { 15, "service synchronised on main radar" },
    { 16, "main and backup radar, if any, failed" },
    { 0, NULL }
};

static const FieldPart I065_050_REP = { 8, 1.0, FIELD_PART_UINT, &hf_065_050_REP, NULL };
static const FieldPart *I065_050_PARTS[] = { &I065_050_REP, NULL };

/* Position of the System Reference Point */
static const FieldPart I065_RE_SRP_Latitude = { 32, 180.0/1073741824.0, FIELD_PART_FLOAT, &hf_065_RE_SRP_Latitude, NULL };
static const FieldPart I065_RE_SRP_Longitude = { 32, 180.0/1073741824.0, FIELD_PART_FLOAT, &hf_065_RE_SRP_Longitude, NULL };

static const FieldPart *I065_RE_SRP_PARTS[] = { &I065_RE_SRP_Latitude, &I065_RE_SRP_Longitude, NULL };

/* ASTERIX Record Length */
static const FieldPart I065_RE_ARL_ARL = { 16, 1.0, FIELD_PART_UINT, &hf_065_RE_ARL_ARL, NULL };
static const FieldPart *I065_RE_ARL_PARTS[] = { &I065_RE_ARL_ARL, NULL };

/* Items */
DIAG_OFF_PEDANTIC
static const AsterixField I065_000 = { FIXED, 1, 0, 0, &hf_065_000, I065_000_PARTS, { NULL } };
static const AsterixField I065_010 = { FIXED, 2, 0, 0, &hf_065_010, IXXX_SAC_SIC, { NULL } };
static const AsterixField I065_015 = { FIXED, 1, 0, 0, &hf_065_015, I065_015_PARTS, { NULL } };
static const AsterixField I065_020 = { FIXED, 1, 0, 0, &hf_065_020, I065_020_PARTS, { NULL } };
static const AsterixField I065_030 = { FIXED, 3, 0, 0, &hf_065_030, IXXX_TOD, { NULL } };
static const AsterixField I065_040_v1_3 = { FIXED, 1, 0, 0, &hf_065_040, I065_040_PARTS_v1_3, { NULL } };
static const AsterixField I065_040_v1_4 = { FIXED, 1, 0, 0, &hf_065_040, I065_040_PARTS_v1_4, { NULL } };
static const AsterixField I065_050 = { FIXED, 1, 0, 0, &hf_065_050, I065_050_PARTS, { NULL } };
static const AsterixField I065_RE_SRP = { FIXED, 4, 0, 0, &hf_065_RE_SRP, I065_RE_SRP_PARTS, { NULL } };
static const AsterixField I065_RE_ARL = { FIXED, 2, 0, 0, &hf_065_RE_ARL, I065_RE_ARL_PARTS, { NULL } };
static const AsterixField I065_RE = { RE, 0, 0, 1, &hf_065_RE, NULL, { &I065_RE_SRP, &I065_RE_ARL, NULL } };
static const AsterixField I065_SP = { SP, 0, 0, 1, &hf_065_SP, NULL, { NULL } };

static const AsterixField *I065_v1_3_uap[] = { &I065_010, &I065_000, &I065_015, &I065_030, &I065_020, &I065_040_v1_3, &I065_050,
                                               &IX_SPARE, &IX_SPARE, &IX_SPARE, &IX_SPARE, &IX_SPARE, &I065_RE,  &I065_SP, NULL };
static const AsterixField *I065_v1_4_uap[] = { &I065_010, &I065_000, &I065_015, &I065_030, &I065_020, &I065_040_v1_4, &I065_050,
                                               &IX_SPARE, &IX_SPARE, &IX_SPARE, &IX_SPARE, &IX_SPARE, &I065_RE,  &I065_SP, NULL };
static const AsterixField **I065_v1_3[] = { I065_v1_3_uap, NULL };
static const AsterixField **I065_v1_4[] = { I065_v1_4_uap, NULL };
static const AsterixField ***I065[] = { I065_v1_4, I065_v1_3 };
DIAG_ON_PEDANTIC

static const enum_val_t I065_versions[] = {
    { "I065_v1_4", "Version 1.4", 0 },
    { "I065_v1_3", "Version 1.3", 1 },
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
    I004, /* 004 */
    NULL, /* 005 */
    NULL, /* 006 */
    NULL, /* 007 */
    I008, /* 008 */
    I009, /* 009 */
    I010, /* 010 */
    I011, /* 011 */
    NULL, /* 012 */
    NULL, /* 013 */
    NULL, /* 014 */
    NULL, /* 015 */
    NULL, /* 016 */
    NULL, /* 017 */
    NULL, /* 018 */
    I019, /* 019 */
    I020, /* 020 */
    I021, /* 021 */
    NULL, /* 022 */
    I023, /* 023 */
    NULL, /* 024 */
    I025, /* 025 */
    NULL, /* 026 */
    NULL, /* 027 */
    NULL, /* 028 */
    NULL, /* 029 */
    NULL, /* 030 */
    NULL, /* 031 */
    I032, /* 032 */
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


static int dissect_asterix (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    col_set_str (pinfo->cinfo, COL_PROTOCOL, "ASTERIX");
    col_clear (pinfo->cinfo, COL_INFO);

    if (tree) { /* we are being asked for details */
        dissect_asterix_packet (tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}

static void dissect_asterix_packet (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint i;
    guint8 category;
    guint16 length;
    proto_item *asterix_packet_item;
    proto_tree *asterix_packet_tree;

    for (i = 0; i < tvb_reported_length (tvb); i += length + 3) {
        /* all ASTERIX messages have the same structure:
         *
         * header:
         *
         *   1 byte   category  even though a category is referenced as I019,
         *                      this is just stored as decimal 19 (i.e. 0x13)
         *   2 bytes  length    the total length of this ASTERIX message, the
         *                      length includes the size of the header.
         *
         *                      Note that the there was a structural change at
         *                      one point that changes whether multiple
         *                      records can occur after the header or not
         *                      (each category specifies this explicitly. All
         *                      of the currently supported categories can have
         *                      multiple records so this implementation just
         *                      assumes that is always the case)
         *
         * record (multiple records can exists):
         *
         *   n bytes  FSPEC     the field specifier is a bit mask where the
         *                      lowest bit of each byte is called the FX bit.
         *                      When the FX bit is set this indicates that
         *                      the FSPEC extends into the next byte.
         *                      Any other bit indicates the presence of the
         *                      field that owns that bit (as per the User
         *                      Application Profile (UAP)).
         *   X bytes  Field Y   X is as per the specification for field Y.
         *   etc.
         *
         * The User Application Profile (UAP) is simply a mapping from the
         * FSPEC to fields. Each category has its own UAP.
         */
        category = tvb_get_guint8 (tvb, i);
        length = (tvb_get_guint8 (tvb, i + 1) << 8) + tvb_get_guint8 (tvb, i + 2) - 3; /* -3 for category and length */

        asterix_packet_item = proto_tree_add_item (tree, proto_asterix, tvb, i, length + 3, ENC_NA);
        proto_item_append_text (asterix_packet_item, ", Category %03d", category);
        asterix_packet_tree = proto_item_add_subtree (asterix_packet_item, ett_asterix);
        proto_tree_add_item (asterix_packet_tree, hf_asterix_category, tvb, i, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (asterix_packet_tree, hf_asterix_length, tvb, i + 1, 2, ENC_BIG_ENDIAN);

        dissect_asterix_data_block (tvb, pinfo, i + 3, asterix_packet_tree, category, length);
    }
}

static void dissect_asterix_data_block (tvbuff_t *tvb, packet_info *pinfo, guint offset, proto_tree *tree, guint8 category, gint length)
{
    guint8 active_uap;
    int fspec_len, inner_offset, size, counter;
    proto_item *asterix_message_item = NULL;
    proto_tree *asterix_message_tree = NULL;

    for (counter = 1, inner_offset = 0; inner_offset < length; counter++) {

        /* This loop handles parsing of each ASTERIX record */

        active_uap = asterix_get_active_uap (tvb, offset + inner_offset, category);
        size = asterix_message_length (tvb, offset + inner_offset, category, active_uap);
        if (size > 0) {
            asterix_message_item = proto_tree_add_item (tree, hf_asterix_message, tvb, offset + inner_offset, size, ENC_NA);
            proto_item_append_text (asterix_message_item, ", #%02d, length: %d", counter, size);
            asterix_message_tree = proto_item_add_subtree (asterix_message_item, ett_asterix_message);
            fspec_len = asterix_fspec_len (tvb, offset + inner_offset);
            /*show_fspec (tvb, asterix_message_tree, offset + inner_offset, fspec_len);*/
            proto_tree_add_item (asterix_message_tree, hf_asterix_fspec, tvb, offset + inner_offset, fspec_len, ENC_NA);

            size = dissect_asterix_fields (tvb, pinfo, offset + inner_offset, asterix_message_tree, category, categories[category][global_categories_version[category]][active_uap]);

            inner_offset += size + fspec_len;
        }
        else {
            inner_offset = length;
        }
    }
}

static gint dissect_asterix_fields (tvbuff_t *tvb, packet_info *pinfo, guint offset, proto_tree *tree, guint8 category, const AsterixField *current_uap[])
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
            switch(current_uap[i]->type) {
                case COMPOUND:
                    asterix_field_item = proto_tree_add_item (tree, *current_uap[i]->hf, tvb, offset + start, len, ENC_NA);
                    asterix_field_tree = proto_item_add_subtree (asterix_field_item, ett_asterix_subtree);
                    fspec_len = asterix_fspec_len (tvb, offset + start);
                    proto_tree_add_item (asterix_field_tree, hf_asterix_fspec, tvb, offset + start, fspec_len, ENC_NA);
                    dissect_asterix_fields (tvb, pinfo, offset + start, asterix_field_tree, category, (const AsterixField **)current_uap[i]->field);
                    break;
                case REPETITIVE:
                    asterix_field_item = proto_tree_add_item (tree, *current_uap[i]->hf, tvb, offset + start, len, ENC_NA);
                    asterix_field_tree = proto_item_add_subtree (asterix_field_item, ett_asterix_subtree);
                    for (j = 0, counter = 0; j < current_uap[i]->repetition_counter_size; j++) {
                        counter = (counter << 8) + tvb_get_guint8 (tvb, offset + start + j);
                    }
                    proto_tree_add_item (asterix_field_tree, hf_counter, tvb, offset + start, current_uap[i]->repetition_counter_size, ENC_BIG_ENDIAN);
                    for (j = 0, inner_offset = 0; j < counter; j++, inner_offset += current_uap[i]->length) {
                        asterix_field_item2 = proto_tree_add_item (asterix_field_tree, *current_uap[i]->hf, tvb, offset + start + current_uap[i]->repetition_counter_size + inner_offset, current_uap[i]->length, ENC_NA);
                        asterix_field_tree2 = proto_item_add_subtree (asterix_field_item2, ett_asterix_subtree);
                        asterix_build_subtree (tvb, pinfo, offset + start + current_uap[i]->repetition_counter_size + inner_offset, asterix_field_tree2, current_uap[i]);
                    }
                    break;
                case RE:
                    asterix_field_item = proto_tree_add_item (tree, *current_uap[i]->hf, tvb, offset + start, len, ENC_NA);
                    asterix_field_tree = proto_item_add_subtree (asterix_field_item, ett_asterix_subtree);
                    proto_tree_add_item (asterix_field_tree, hf_re_field_len, tvb, offset + start, 1, ENC_BIG_ENDIAN);
                    start++;
                    fspec_len = asterix_fspec_len (tvb, offset + start);
                    proto_tree_add_item (asterix_field_tree, hf_asterix_fspec, tvb, offset + start, fspec_len, ENC_NA);
                    dissect_asterix_fields (tvb, pinfo, offset + start, asterix_field_tree, category, (const AsterixField **)current_uap[i]->field);
                    break;
                default: /* FIXED, FX, FX_1, SP, FX_UAP */
                    asterix_field_item = proto_tree_add_item (tree, *current_uap[i]->hf, tvb, offset + start, len, ENC_NA);
                    asterix_field_tree = proto_item_add_subtree (asterix_field_item, ett_asterix_subtree);
                    asterix_build_subtree (tvb, pinfo, offset + start, asterix_field_tree, current_uap[i]);
                    break;
            }
        }
    }
    return size;
}

static void asterix_build_subtree (tvbuff_t *tvb, packet_info *pinfo, guint offset, proto_tree *parent, const AsterixField *field)
{
    header_field_info* hfi;
    int bytes_in_type, byte_offset_of_mask;
    gint i, inner_offset, offset_in_tvb, length_in_tvb;
    guint8 go_on;
    gint64 value;
    char *str_buffer = NULL;
    double scaling_factor = 1.0;
    guint8 *air_speed_im_bit;
    if (field->part != NULL) {
        for (i = 0, inner_offset = 0, go_on = 1; go_on && field->part[i] != NULL; i++) {
            value = tvb_get_bits64 (tvb, offset * 8 + inner_offset, field->part[i]->bit_length, ENC_BIG_ENDIAN);
            if (field->part[i]->hf != NULL) {
                offset_in_tvb = offset + inner_offset / 8;
                length_in_tvb = (inner_offset % 8 + field->part[i]->bit_length + 7) / 8;
                switch (field->part[i]->type) {
                    case FIELD_PART_FX:
                        if (!value) go_on = 0;
                        /* Fall through */
                    case FIELD_PART_INT:
                    case FIELD_PART_UINT:
                    case FIELD_PART_HEX:
                    case FIELD_PART_ASCII:
                    case FIELD_PART_SQUAWK:
                        hfi = proto_registrar_get_nth (*field->part[i]->hf);
                        if (hfi->bitmask)
                        {
                            // for a small bit field to decode correctly with
                            // a mask that belongs to a large(r) one we need to
                            // re-adjust offset_in_tvb and length_in_tvb to
                            // correctly align with the given hf mask.
                            //
                            // E.g. the following would not decode correctly:
                            //   { &hf_020_050_V, ... FT_UINT16, ... 0x8000, ...
                            // instead one would have to use
                            //   { &hf_020_050_V, ... FT_UINT8, ... 0x80, ...
                            //
                            bytes_in_type = ftype_length (hfi->type);
                            if (bytes_in_type > 1)
                            {
                                byte_offset_of_mask = bytes_in_type - (ws_ilog2 (hfi->bitmask) + 8)/8;
                                if (byte_offset_of_mask >= 0)
                                {
                                    offset_in_tvb -= byte_offset_of_mask;
                                    length_in_tvb = bytes_in_type;
                                }
                            }
                        }
                        proto_tree_add_item (parent, *field->part[i]->hf, tvb, offset_in_tvb, length_in_tvb, ENC_BIG_ENDIAN);
                        break;
                    case FIELD_PART_FLOAT:
                        twos_complement (&value, field->part[i]->bit_length);
                        /* Fall through */
                    case FIELD_PART_UFLOAT:
                        scaling_factor = field->part[i]->scaling_factor;
                        if (field->part[i]->format_string != NULL)
                            proto_tree_add_double_format_value (parent, *field->part[i]->hf, tvb, offset_in_tvb, length_in_tvb, value * scaling_factor, field->part[i]->format_string, value * scaling_factor);
                        else
                            proto_tree_add_double (parent, *field->part[i]->hf, tvb, offset_in_tvb, length_in_tvb, value * scaling_factor);
                        break;
                    case FIELD_PART_CALLSIGN:
                        str_buffer = wmem_strdup_printf(
                            wmem_packet_scope (),
                            "%c%c%c%c%c%c%c%c",
                            AISCode[(value >> 42) & 63],
                            AISCode[(value >> 36) & 63],
                            AISCode[(value >> 30) & 63],
                            AISCode[(value >> 24) & 63],
                            AISCode[(value >> 18) & 63],
                            AISCode[(value >> 12) & 63],
                            AISCode[(value >> 6) & 63],
                            AISCode[value & 63]);
                        proto_tree_add_string (parent, *field->part[i]->hf, tvb, offset_in_tvb, length_in_tvb, str_buffer);
                        break;
                    case FIELD_PART_IAS_IM:
                        /* special processing for I021/150 and I062/380#4 because Air Speed depends on IM subfield */
                        air_speed_im_bit = wmem_new (wmem_packet_scope (), guint8);
                        *air_speed_im_bit = (tvb_get_guint8 (tvb, offset_in_tvb) & 0x80) >> 7;
                        /* Save IM info for the packet. key = 21150. */
                        p_add_proto_data (pinfo->pool, pinfo, proto_asterix, 21150, air_speed_im_bit);
                        proto_tree_add_item (parent, *field->part[i]->hf, tvb, offset_in_tvb, length_in_tvb, ENC_BIG_ENDIAN);
                        break;
                    case FIELD_PART_IAS_ASPD:
                        /* special processing for I021/150 and I062/380#4 because Air Speed depends on IM subfield */
                        air_speed_im_bit = (guint8 *)p_get_proto_data (pinfo->pool, pinfo, proto_asterix, 21150);
                        if (!air_speed_im_bit || *air_speed_im_bit == 0)
                            scaling_factor = 1.0/16384.0;
                        else
                            scaling_factor = 0.001;
                        proto_tree_add_double (parent, *field->part[i]->hf, tvb, offset_in_tvb, length_in_tvb, value * scaling_factor);
                        break;
                }
            }
            inner_offset += field->part[i]->bit_length;
        }
    } /* if not null */
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

static guint asterix_fspec_len (tvbuff_t *tvb, guint offset)
{
    guint i;
    guint max_length = tvb_reported_length (tvb) - offset;
    for (i = 0; (tvb_get_guint8 (tvb, offset + i) & 1) && i < max_length; i++);
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
    switch(field->type) {
        case FIXED:
            size = field->length;
            break;
        case REPETITIVE:
            for (i = 0, count = 0; i < field->repetition_counter_size && i < sizeof (count); i++)
                count = (count << 8) + tvb_get_guint8 (tvb, offset + i);
            size = (guint)(field->repetition_counter_size + count * field->length);
            break;
        case FX_UAP:
        case FX:
            for (size = field->length + field->header_length; tvb_get_guint8 (tvb, offset + size - 1) & 1; size += field->length);
            break;
        case FX_1:
            size = field->length + field->header_length + ( ( tvb_get_guint8 (tvb, offset + size - 1) & 1 ) ? field->length : 0 );
            break;
        case RE:
            for (i = 0, size = 0; i < field->header_length; i++) {
                size = (size << 8) + tvb_get_guint8 (tvb, offset + i);
            }
            break;
        case SP:
            for (i = 0, size = 0; i < field->header_length; i++) {
                size = (size << 8) + tvb_get_guint8 (tvb, offset + i);
            }
            break;
        case COMPOUND:
            /* FSPEC */
            for (size = 0; tvb_get_guint8 (tvb, offset + size) & 1; size++);
            size++;

            for (i = 0; field->field[i] != NULL; i++) {
                if (asterix_field_exists (tvb, offset, i))
                    size += asterix_field_length (tvb, offset + size, field->field[i]);
            }
            break;
    }
    return size;
}

/* This works for category 001. For other it may require changes. */
static guint8 asterix_get_active_uap (tvbuff_t *tvb, guint offset, guint8 category)
{
    int i, inner_offset;
    AsterixField **current_uap;

    if ((category == 1) && (categories[category] != NULL)) { /* if category is supported */
        if (categories[category][global_categories_version[category]][1] != NULL) { /* if exists another uap */
            current_uap = (AsterixField **)categories[category][global_categories_version[category]][0];
            if (current_uap != NULL) {
                inner_offset = asterix_fspec_len (tvb, offset);
                for (i = 0; current_uap[i] != NULL; i++) {
                    if (asterix_field_exists (tvb, offset, i)) {
                        if (current_uap[i]->type == FX_UAP) {
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
        { &hf_XXX_SAC, { "SAC", "asterix.SAC", FT_UINT16, BASE_DEC, NULL, 0xff00, "SAC code of the source", HFILL } },
        { &hf_XXX_SIC, { "SIC", "asterix.SIC", FT_UINT16, BASE_DEC, NULL, 0x00ff, "SIC code of the source", HFILL } },
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
        { &hf_001_050_V, { "V", "asterix.001_050_V", FT_UINT8, BASE_DEC, VALS (valstr_001_050_V), 0x80, NULL, HFILL } },
        { &hf_001_050_G, { "G", "asterix.001_050_G", FT_UINT8, BASE_DEC, VALS (valstr_001_050_G), 0x40, NULL, HFILL } },
        { &hf_001_050_L, { "L", "asterix.001_050_L", FT_UINT8, BASE_DEC, VALS (valstr_001_050_L), 0x20, NULL, HFILL } },
        { &hf_001_050_SQUAWK, { "SQUAWK", "asterix.001_050_SQUAWK", FT_UINT16, BASE_OCT, NULL, 0x0fff, NULL, HFILL } },
        { &hf_001_060, { "060, Mode-2 Code Confidence Indicator", "asterix.001_060", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_060_QA4, { "QA4", "asterix.001_060_QA4", FT_UINT8, BASE_DEC, VALS (valstr_001_060_Q), 0x08, NULL, HFILL } },
        { &hf_001_060_QA2, { "QA2", "asterix.001_060_QA2", FT_UINT8, BASE_DEC, VALS (valstr_001_060_Q), 0x04, NULL, HFILL } },
        { &hf_001_060_QA1, { "QA1", "asterix.001_060_QA1", FT_UINT8, BASE_DEC, VALS (valstr_001_060_Q), 0x02, NULL, HFILL } },
        { &hf_001_060_QB4, { "QB4", "asterix.001_060_QB4", FT_UINT8, BASE_DEC, VALS (valstr_001_060_Q), 0x01, NULL, HFILL } },
        { &hf_001_060_QB2, { "QB2", "asterix.001_060_QB2", FT_UINT8, BASE_DEC, VALS (valstr_001_060_Q), 0x80, NULL, HFILL } },
        { &hf_001_060_QB1, { "QB1", "asterix.001_060_QB1", FT_UINT8, BASE_DEC, VALS (valstr_001_060_Q), 0x40, NULL, HFILL } },
        { &hf_001_060_QC4, { "QC4", "asterix.001_060_QC4", FT_UINT8, BASE_DEC, VALS (valstr_001_060_Q), 0x20, NULL, HFILL } },
        { &hf_001_060_QC2, { "QC2", "asterix.001_060_QC2", FT_UINT8, BASE_DEC, VALS (valstr_001_060_Q), 0x10, NULL, HFILL } },
        { &hf_001_060_QC1, { "QC1", "asterix.001_060_QC1", FT_UINT8, BASE_DEC, VALS (valstr_001_060_Q), 0x08, NULL, HFILL } },
        { &hf_001_060_QD4, { "QD4", "asterix.001_060_QD4", FT_UINT8, BASE_DEC, VALS (valstr_001_060_Q), 0x04, NULL, HFILL } },
        { &hf_001_060_QD2, { "QD2", "asterix.001_060_QD2", FT_UINT8, BASE_DEC, VALS (valstr_001_060_Q), 0x02, NULL, HFILL } },
        { &hf_001_060_QD1, { "QD1", "asterix.001_060_QD1", FT_UINT8, BASE_DEC, VALS (valstr_001_060_Q), 0x01, NULL, HFILL } },
        { &hf_001_070, { "070, Mode-3/A Code in Octal Representation", "asterix.001_070", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_070_V, { "V", "asterix.001_070_V", FT_UINT8, BASE_DEC, VALS (valstr_001_070_V), 0x80, NULL, HFILL } },
        { &hf_001_070_G, { "G", "asterix.001_070_G", FT_UINT8, BASE_DEC, VALS (valstr_001_070_G), 0x40, NULL, HFILL } },
        { &hf_001_070_L, { "L", "asterix.001_070_L", FT_UINT8, BASE_DEC, VALS (valstr_001_070_L), 0x20, NULL, HFILL } },
        { &hf_001_070_SQUAWK, { "SQUAWK", "asterix.001_070_SQUAWK", FT_UINT16, BASE_OCT, NULL, 0x0fff, NULL, HFILL } },
        { &hf_001_080, { "080, Mode-3/A Code Confidence Indicator", "asterix.001_080", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_080_QA4, { "QA4", "asterix.001_080_QA4", FT_UINT8, BASE_DEC, VALS (valstr_001_080_Q), 0x08, NULL, HFILL } },
        { &hf_001_080_QA2, { "QA2", "asterix.001_080_QA2", FT_UINT8, BASE_DEC, VALS (valstr_001_080_Q), 0x04, NULL, HFILL } },
        { &hf_001_080_QA1, { "QA1", "asterix.001_080_QA1", FT_UINT8, BASE_DEC, VALS (valstr_001_080_Q), 0x02, NULL, HFILL } },
        { &hf_001_080_QB4, { "QB4", "asterix.001_080_QB4", FT_UINT8, BASE_DEC, VALS (valstr_001_080_Q), 0x01, NULL, HFILL } },
        { &hf_001_080_QB2, { "QB2", "asterix.001_080_QB2", FT_UINT8, BASE_DEC, VALS (valstr_001_080_Q), 0x80, NULL, HFILL } },
        { &hf_001_080_QB1, { "QB1", "asterix.001_080_QB1", FT_UINT8, BASE_DEC, VALS (valstr_001_080_Q), 0x40, NULL, HFILL } },
        { &hf_001_080_QC4, { "QC4", "asterix.001_080_QC4", FT_UINT8, BASE_DEC, VALS (valstr_001_080_Q), 0x20, NULL, HFILL } },
        { &hf_001_080_QC2, { "QC2", "asterix.001_080_QC2", FT_UINT8, BASE_DEC, VALS (valstr_001_080_Q), 0x10, NULL, HFILL } },
        { &hf_001_080_QC1, { "QC1", "asterix.001_080_QC1", FT_UINT8, BASE_DEC, VALS (valstr_001_080_Q), 0x08, NULL, HFILL } },
        { &hf_001_080_QD4, { "QD4", "asterix.001_080_QD4", FT_UINT8, BASE_DEC, VALS (valstr_001_080_Q), 0x04, NULL, HFILL } },
        { &hf_001_080_QD2, { "QD2", "asterix.001_080_QD2", FT_UINT8, BASE_DEC, VALS (valstr_001_080_Q), 0x02, NULL, HFILL } },
        { &hf_001_080_QD1, { "QD1", "asterix.001_080_QD1", FT_UINT8, BASE_DEC, VALS (valstr_001_080_Q), 0x01, NULL, HFILL } },
        { &hf_001_090, { "090, Mode-C Code in Binary Representation", "asterix.001_090", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_090_V, { "V", "asterix.001_090_V", FT_UINT8, BASE_DEC, VALS (valstr_001_090_V), 0x80, NULL, HFILL } },
        { &hf_001_090_G, { "G", "asterix.001_090_G", FT_UINT8, BASE_DEC, VALS (valstr_001_090_G), 0x40, NULL, HFILL } },
        { &hf_001_090_FL, { "FL", "asterix.001_090_FL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_100, { "100, Mode-C Code and Code Confidence Indicator", "asterix.001_100", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_100_V, { "V", "asterix.001_100_V", FT_UINT8, BASE_DEC, VALS (valstr_001_100_V), 0x80, NULL, HFILL } },
        { &hf_001_100_G, { "G", "asterix.001_100_G", FT_UINT8, BASE_DEC, VALS (valstr_001_100_G), 0x40, NULL, HFILL } },
        { &hf_001_100_C1, { "C1", "asterix.001_100_C1", FT_UINT8, BASE_DEC, NULL, 0x08, NULL, HFILL } },
        { &hf_001_100_A1, { "A1", "asterix.001_100_A1", FT_UINT8, BASE_DEC, NULL, 0x04, NULL, HFILL } },
        { &hf_001_100_C2, { "C2", "asterix.001_100_C2", FT_UINT8, BASE_DEC, NULL, 0x02, NULL, HFILL } },
        { &hf_001_100_A2, { "A2", "asterix.001_100_A2", FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL } },
        { &hf_001_100_C4, { "C4", "asterix.001_100_C4", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL } },
        { &hf_001_100_A4, { "A4", "asterix.001_100_A4", FT_UINT8, BASE_DEC, NULL, 0x40, NULL, HFILL } },
        { &hf_001_100_B1, { "B1", "asterix.001_100_B1", FT_UINT8, BASE_DEC, NULL, 0x20, NULL, HFILL } },
        { &hf_001_100_D1, { "D1", "asterix.001_100_D1", FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL } },
        { &hf_001_100_B2, { "B2", "asterix.001_100_B2", FT_UINT8, BASE_DEC, NULL, 0x08, NULL, HFILL } },
        { &hf_001_100_D2, { "D2", "asterix.001_100_D2", FT_UINT8, BASE_DEC, NULL, 0x04, NULL, HFILL } },
        { &hf_001_100_B4, { "B4", "asterix.001_100_B4", FT_UINT8, BASE_DEC, NULL, 0x02, NULL, HFILL } },
        { &hf_001_100_D4, { "D4", "asterix.001_100_D4", FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL } },
        { &hf_001_100_QC1, { "QC1", "asterix.001_100_QC1", FT_UINT8, BASE_DEC, VALS (valstr_001_100_Q), 0x08, NULL, HFILL } },
        { &hf_001_100_QA1, { "QA1", "asterix.001_100_QA1", FT_UINT8, BASE_DEC, VALS (valstr_001_100_Q), 0x04, NULL, HFILL } },
        { &hf_001_100_QC2, { "QC2", "asterix.001_100_QC2", FT_UINT8, BASE_DEC, VALS (valstr_001_100_Q), 0x02, NULL, HFILL } },
        { &hf_001_100_QA2, { "QA2", "asterix.001_100_QA2", FT_UINT8, BASE_DEC, VALS (valstr_001_100_Q), 0x01, NULL, HFILL } },
        { &hf_001_100_QC4, { "QC4", "asterix.001_100_QC4", FT_UINT8, BASE_DEC, VALS (valstr_001_100_Q), 0x80, NULL, HFILL } },
        { &hf_001_100_QA4, { "QA4", "asterix.001_100_QA4", FT_UINT8, BASE_DEC, VALS (valstr_001_100_Q), 0x40, NULL, HFILL } },
        { &hf_001_100_QB1, { "QB1", "asterix.001_100_QB1", FT_UINT8, BASE_DEC, VALS (valstr_001_100_Q), 0x20, NULL, HFILL } },
        { &hf_001_100_QD1, { "QD1", "asterix.001_100_QD1", FT_UINT8, BASE_DEC, VALS (valstr_001_100_Q), 0x10, NULL, HFILL } },
        { &hf_001_100_QB2, { "QB2", "asterix.001_100_QB2", FT_UINT8, BASE_DEC, VALS (valstr_001_100_Q), 0x08, NULL, HFILL } },
        { &hf_001_100_QD2, { "QD2", "asterix.001_100_QD2", FT_UINT8, BASE_DEC, VALS (valstr_001_100_Q), 0x04, NULL, HFILL } },
        { &hf_001_100_QB4, { "QB4", "asterix.001_100_QB4", FT_UINT8, BASE_DEC, VALS (valstr_001_100_Q), 0x02, NULL, HFILL } },
        { &hf_001_100_QD4, { "QD4", "asterix.001_100_QD4", FT_UINT8, BASE_DEC, VALS (valstr_001_100_Q), 0x01, NULL, HFILL } },
        { &hf_001_120, { "120, Measured Radial Doppler Speed", "asterix.001_120", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_120_MRDS, { "[NM/s]", "asterix.001_120_MRDS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_130, { "130, Radar Plot Characteristics", "asterix.001_130", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_130_RPC, { "Radar Plot Characteristics", "asterix.001_130_RPC", FT_UINT8, BASE_DEC, NULL, 0xfe, NULL, HFILL } },
        { &hf_001_131, { "131, Received Power", "asterix.001_131", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_131_RP, { "[dBm]", "asterix.001_131_RP", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_001_141, { "141, Truncated Time of Day", "asterix.001_141", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_141_TTOD, { "TTOD", "asterix.001_141_TTOD", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_150, { "150, Presence of X-Pulse", "asterix.001_150", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_150_XA, { "XA", "asterix.001_150_XA", FT_UINT8, BASE_DEC, VALS (valstr_001_150_XA), 0x80, NULL, HFILL } },
        { &hf_001_150_XC, { "XC", "asterix.001_150_XC", FT_UINT8, BASE_DEC, VALS (valstr_001_150_XC), 0x20, NULL, HFILL } },
        { &hf_001_150_X2, { "XA", "asterix.001_150_X2", FT_UINT8, BASE_DEC, VALS (valstr_001_150_X2), 0x04, NULL, HFILL } },
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
        { &hf_001_200_CGS, { "[NM/s]", "asterix.001_200_CGS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_200_CH, { "[degrees]", "asterix.001_200_CH", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_210, { "210, Track Quality", "asterix.001_210", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_001_210_TQ, { "Track Quality", "asterix.001_210_TQ", FT_UINT8, BASE_DEC, NULL, 0xfe, NULL, HFILL } },
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
        { &hf_002_070, { "070, Plot Count Values", "asterix.002_070", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_002_070_A, { "A", "asterix.002_070_A", FT_UINT8, BASE_DEC, VALS (valstr_002_070_A), 0x80, NULL, HFILL } },
        { &hf_002_070_IDENT, { "IDENT", "asterix.002_070_V", FT_UINT8, BASE_DEC, VALS (valstr_002_070_IDENT), 0x7c, NULL, HFILL } },
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
        /* Category 004 */
        { &hf_004_000, { "000, Message Type", "asterix.004_000", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_000_MT, { "MT", "asterix.004_000_MT", FT_UINT8, BASE_DEC, VALS (valstr_004_000_MT), 0x0, NULL, HFILL } },
        { &hf_004_010, { "010, Data Source Identifier", "asterix.004_010", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_015, { "015, SDPS Identifier", "asterix.004_015", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_020, { "020, Time of Message", "asterix.004_020", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_030, { "030, Track Number 1", "asterix.004_030", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_030_TN1, { "TN1", "asterix.004_030_TN1", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_004_035, { "035, Track Number 1", "asterix.004_035", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_035_TN2, { "TN2", "asterix.004_035_TN1", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_004_040, { "040, Alert Identifier", "asterix.004_040", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_040_AI, { "AI", "asterix.004_040_AI", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_004_045, { "045, Alert Status", "asterix.004_045", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_045_AS, { "AS", "asterix.004_045_AS", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_004_060, { "060, Safety Net Function & System Status", "asterix.004_060", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_060_MRVA, { "MRVA", "asterix.004_060_MRVA", FT_UINT8, BASE_DEC, VALS (valstr_004_060_MRVA), 0x80, NULL, HFILL } },
        { &hf_004_060_RAMLD, { "RAMLD", "asterix.004_060_RAMLD", FT_UINT8, BASE_DEC, VALS (valstr_004_060_RAMLD), 0x40, NULL, HFILL } },
        { &hf_004_060_RAMHD, { "RAMHD", "asterix.004_060_RAMHD", FT_UINT8, BASE_DEC, VALS (valstr_004_060_RAMHD), 0x20, NULL, HFILL } },
        { &hf_004_060_MSAW, { "MSAW", "asterix.004_060_MSAW", FT_UINT8, BASE_DEC, VALS (valstr_004_060_MSAW), 0x10, NULL, HFILL } },
        { &hf_004_060_APW, { "APW", "asterix.004_060_APW", FT_UINT8, BASE_DEC, VALS (valstr_004_060_APW), 0x08, NULL, HFILL } },
        { &hf_004_060_CLAM, { "CLAM", "asterix.004_060_CLAM", FT_UINT8, BASE_DEC, VALS (valstr_004_060_CLAM), 0x04, NULL, HFILL } },
        { &hf_004_060_STCA, { "STCA", "asterix.004_060_STCA", FT_UINT8, BASE_DEC, VALS (valstr_004_060_STCA), 0x02, NULL, HFILL } },
        { &hf_004_060_AFDA, { "AFDA", "asterix.004_060_AFDA", FT_UINT8, BASE_DEC, VALS (valstr_004_060_AFDA), 0x80, NULL, HFILL } },
        { &hf_004_060_RIMCA, { "RIMCA", "asterix.004_060_RIMCA", FT_UINT8, BASE_DEC, VALS (valstr_004_060_RIMCA), 0x40, NULL, HFILL } },
        { &hf_004_060_ACASRA, { "ACASRA", "asterix.004_060_ACASRA", FT_UINT8, BASE_DEC, VALS (valstr_004_060_ACASRA), 0x20, NULL, HFILL } },
        { &hf_004_060_NTCA, { "NTCA", "asterix.004_060_NTCA", FT_UINT8, BASE_DEC, VALS (valstr_004_060_NTCA), 0x10, NULL, HFILL } },
        { &hf_004_060_DG, { "DG", "asterix.004_060_DG", FT_UINT8, BASE_DEC, VALS (valstr_004_060_DG), 0x08, NULL, HFILL } },
        { &hf_004_060_OF, { "OF", "asterix.004_060_OF", FT_UINT8, BASE_DEC, VALS (valstr_004_060_OF), 0x04, NULL, HFILL } },
        { &hf_004_060_OL, { "OL", "asterix.004_060_OL", FT_UINT8, BASE_DEC, VALS (valstr_004_060_OL), 0x02, NULL, HFILL } },
        { &hf_004_070, { "070, Conflict Timing and Separation", "asterix.004_070", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_070_01, { "#1: Time to Conflict", "asterix.004_070_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_070_01_TC, { "TC[s]", "asterix.004_070_01_TC", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_070_02, { "#2: Time to Closest Approach", "asterix.004_070_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_070_02_TCA, { "TCA[s]", "asterix.004_070_02_TCA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_070_03, { "#3: Current Horizontal Separation", "asterix.004_070_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_070_03_CHS, { "CHS[m]", "asterix.004_070_03_CHS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_070_04, { "#4: Estimated Minimum Horizontal Separation", "asterix.004_070_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_070_04_MHS, { "MHS[m]", "asterix.004_070_04_MHS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_070_05, { "#5: Current Vertical Separation", "asterix.004_070_05", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_070_05_CVS, { "CVS[ft]", "asterix.004_070_05_CVS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_070_06, { "#6: Estimated Minimum Vertical Separation", "asterix.004_070_06", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_070_06_MVS, { "MVS[ft]", "asterix.004_070_06_MVS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_074, { "074, Longitudinal Deviation", "asterix.004_074", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_074_LD, { "LD[m]", "asterix.004_074_LD", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_075, { "075, Transversal Distance Deviation", "asterix.004_075", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_075_TDD, { "TDD[m]", "asterix.004_074_TDD", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_076, { "076, Vertical Deviation", "asterix.004_076", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_076_VD, { "VD[ft]", "asterix.004_076_VD", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_100, { "100, Area Definition", "asterix.004_100", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_100_01, { "#1: Area Name", "asterix.004_100_", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_100_01_AN, { "AN", "asterix.004_100_01_AN", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_100_02, { "#2: Crossing Area Name", "asterix.004_100_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_100_02_CAN, { "CAN", "asterix.004_100_02_CAN", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_100_03, { "#3: Runway/Taxiway Designator 1", "asterix.004_100_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_100_03_RT1, { "RT1", "asterix.004_100_03_RT1", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_100_04, { "#4: Runway/Taxiway Designator 2", "asterix.004_100_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_100_04_RT2, { "RT2", "asterix.004_100_04_RT2", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_100_05, { "#5: Stop Bar Designator", "asterix.004_100_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_100_05_SB, { "SB", "asterix.004_100_05_SB", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_100_06, { "#6: Gate Designator", "asterix.004_100_05", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_100_06_G, { "G", "asterix.004_100_06_G", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_110, { "110, FDPS Sector Control Identification", "asterix.004_110", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_110_Centre, { "Centre", "asterix.004_110_Centre", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_004_110_Position, { "Position", "asterix.004_110_Position", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_004_120, { "120, Conflict Characteristics", "asterix.004_120", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_120_01, { "#1: Conflict Nature", "asterix.004_120_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_120_01_MAS, { "MAS", "asterix.004_120_01_MAS", FT_UINT8, BASE_DEC, VALS (valstr_004_120_01_MAS), 0x80, NULL, HFILL } },
        { &hf_004_120_01_CAS, { "CAS", "asterix.004_120_01_CAS", FT_UINT8, BASE_DEC, VALS (valstr_004_120_01_CAS), 0x40, NULL, HFILL } },
        { &hf_004_120_01_FLD, { "FLD", "asterix.004_120_01_FLD", FT_UINT8, BASE_DEC, VALS (valstr_004_120_01_FLD), 0x20, NULL, HFILL } },
        { &hf_004_120_01_FVD, { "FVD", "asterix.004_120_01_FVD", FT_UINT8, BASE_DEC, VALS (valstr_004_120_01_FVD), 0x10, NULL, HFILL } },
        { &hf_004_120_01_Type, { "Type", "asterix.004_120_01_Type", FT_UINT8, BASE_DEC, VALS (valstr_004_120_01_Type), 0x08, NULL, HFILL } },
        { &hf_004_120_01_Cross, { "Cross", "asterix.004_120_01_Cross", FT_UINT8, BASE_DEC, VALS (valstr_004_120_01_Cross), 0x04, NULL, HFILL } },
        { &hf_004_120_01_Div, { "Div", "asterix.004_120_01_Div", FT_UINT8, BASE_DEC, VALS (valstr_004_120_01_Div), 0x02, NULL, HFILL } },
        { &hf_004_120_01_RRC, { "RRC", "asterix.004_120_01_RRC", FT_UINT8, BASE_DEC, VALS (valstr_004_120_01_RRC), 0x80, NULL, HFILL } },
        { &hf_004_120_01_RTC, { "RTC", "asterix.004_120_01_RTC", FT_UINT8, BASE_DEC, VALS (valstr_004_120_01_RTC), 0x40, NULL, HFILL } },
        { &hf_004_120_01_MRVA, { "MRVA", "asterix.004_120_01_MRVA", FT_UINT8, BASE_DEC, VALS (valstr_004_120_01_MRVA), 0x20, NULL, HFILL } },
        { &hf_004_120_02, { "#2: Conflict Classification", "asterix.004_120_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_120_02_TID, { "TID", "asterix.004_120_02_TID", FT_UINT8, BASE_DEC, NULL, 0xf0, NULL, HFILL } },
        { &hf_004_120_02_SC, { "SC", "asterix.004_120_02_SC", FT_UINT8, BASE_DEC, NULL, 0x0e, NULL, HFILL } },
        { &hf_004_120_02_CS, { "CS", "asterix.004_120_02_CS", FT_UINT8, BASE_DEC, VALS (valstr_004_120_02_CS), 0x01, NULL, HFILL } },
        { &hf_004_120_03, { "#3: Conflict Probability", "asterix.004_120_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_120_03_Probability, { "Probatility[%]", "asterix.004_120_03_Probability", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_120_04, { "#4: Conflict Duration", "asterix.004_120_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_120_04_Duration, { "Duration[s]", "asterix.004_120_04_Duration", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_170, { "170, Aircraft Identification & Characteristics 1", "asterix.004_170", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_170_01, { "#1: Aircraft Identifier 1", "asterix.004_170_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_170_01_AI1, { "AI1", "asterix.004_170_01_AI1", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_170_02, { "#2: Mode 3/A Code Aircraft 1", "asterix.004_170_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_170_02_M31, { "M31", "asterix.001_170_02_M31", FT_UINT16, BASE_OCT, NULL, 0x0fff, NULL, HFILL } },
        { &hf_004_170_03, { "#3: Predicted Conflict Position 1 (WGS84)", "asterix.004_170_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_170_03_LAT, { "LAT[degrees]", "asterix.004_170_03_LAT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_170_03_LON, { "LON[degrees]", "asterix.004_170_03_LON", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_170_03_ALT, { "ALT[ft]", "asterix.004_170_03_ALT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_170_04, { "#4: Predicted Conflict Position 1 (Cartesian Coordinates)", "asterix.004_170_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_170_04_X, { "X[m]", "asterix.004_170_04_X", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_170_04_Y, { "Y[m]", "asterix.004_170_04_Y", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_170_04_Z, { "Z[ft]", "asterix.004_170_04_Z", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_170_05, { "#5: Time to Threshold Aircraft 1", "asterix.004_170_05", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_170_05_TT1, { "TT1[s]", "asterix.004_070_05_TT1", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_170_06, { "#6: Distance to Threshold Aircraft 1", "asterix.004_170_06", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_170_06_DT1, { "DT1[m]", "asterix.004_070_06_DT1", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_170_07, { "#7: Aircraft Characteristics Aircraft 1", "asterix.004_170_07", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_170_07_GATOAT, { "GATOAT", "asterix.004_170_07_GATOAT", FT_UINT8, BASE_DEC, VALS (valstr_004_170_07_GATOAT), 0xc0, NULL, HFILL } },
        { &hf_004_170_07_FR1FR2, { "FR1FR2", "asterix.004_170_07_FR1FR2", FT_UINT8, BASE_DEC, VALS (valstr_004_170_07_FR1FR2), 0x30, NULL, HFILL } },
        { &hf_004_170_07_RVSM, { "RVSM", "asterix.004_170_07_RVSM", FT_UINT8, BASE_DEC, VALS (valstr_004_170_07_RVSM), 0x0c, NULL, HFILL } },
        { &hf_004_170_07_HPR, { "HPR", "asterix.004_170_07_HPR", FT_UINT8, BASE_DEC, VALS (valstr_004_170_07_HPR), 0x02, NULL, HFILL } },
        { &hf_004_170_07_CDM, { "CDM", "asterix.004_170_07_CDM", FT_UINT8, BASE_DEC, VALS (valstr_004_170_07_CDM), 0xc0, NULL, HFILL } },
        { &hf_004_170_07_PRI, { "PRI", "asterix.004_170_07_PRI", FT_UINT8, BASE_DEC, VALS (valstr_004_170_07_PRI), 0x20, NULL, HFILL } },
        { &hf_004_170_07_GV, { "GV", "asterix.004_170_07_GV", FT_UINT8, BASE_DEC, VALS (valstr_004_170_07_GV), 0x10, NULL, HFILL } },
        { &hf_004_170_08, { "#8: Mode S Identifier Aircraft 1", "asterix.004_170_08", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_170_08_MS1, { "MS1", "asterix.004_170_08_MS1", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_170_09, { "#9: Flight Plan Number Aircraft 1", "asterix.004_170_09", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_170_09_FP1, { "FP1", "asterix.004_170_09_FP1", FT_UINT32, BASE_DEC, NULL, 0x07ffffff, NULL, HFILL } },
        { &hf_004_170_10, { "#10: Cleared Flight Level Aircraft 1", "asterix.004_170_10", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_170_10_CF1, { "CF1[FL]", "asterix.004_170_10_CF1", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_171, { "171, Aircraft Identification & Characteristics 2", "asterix.004_171", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_171_01, { "#1: Aircraft Identifier 2", "asterix.004_171_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_171_01_AI2, { "AI2", "asterix.004_171_01_AI2", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_171_02, { "#2: Mode 3/A Code Aircraft 2", "asterix.004_171_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_171_02_M32, { "M32", "asterix.001_171_02_M32", FT_UINT16, BASE_OCT, NULL, 0x0fff, NULL, HFILL } },
        { &hf_004_171_03, { "#3: Predicted Conflict Position 2 (WGS84)", "asterix.004_171_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_171_03_LAT, { "LAT[degrees]", "asterix.004_171_03_LAT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_171_03_LON, { "LON[degrees]", "asterix.004_171_03_LON", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_171_03_ALT, { "ALT[ft]", "asterix.004_171_03_ALT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_171_04, { "#4: Predicted Conflict Position 2 (Cartesian Coordinates)", "asterix.004_171_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_171_04_X, { "X[m]", "asterix.004_171_04_X", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_171_04_Y, { "Y[m]", "asterix.004_171_04_Y", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_171_04_Z, { "Z[ft]", "asterix.004_171_04_Z", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_171_05, { "#5: Time to Threshold Aircraft 2", "asterix.004_171_05", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_171_05_TT2, { "TT2[s]", "asterix.004_070_05_TT2", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_171_06, { "#6: Distance to Threshold Aircraft 2", "asterix.004_171_06", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_171_06_DT2, { "DT2[m]", "asterix.004_070_06_DT2", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_171_07, { "#7: Aircraft Characteristics Aircraft 2", "asterix.004_171_07", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_171_07_GATOAT, { "GATOAT", "asterix.004_171_07_GATOAT", FT_UINT8, BASE_DEC, VALS (valstr_004_171_07_GATOAT), 0xc0, NULL, HFILL } },
        { &hf_004_171_07_FR1FR2, { "FR1FR2", "asterix.004_171_07_FR1FR2", FT_UINT8, BASE_DEC, VALS (valstr_004_171_07_FR1FR2), 0x30, NULL, HFILL } },
        { &hf_004_171_07_RVSM, { "RVSM", "asterix.004_171_07_RVSM", FT_UINT8, BASE_DEC, VALS (valstr_004_171_07_RVSM), 0x0c, NULL, HFILL } },
        { &hf_004_171_07_HPR, { "HPR", "asterix.004_171_07_HPR", FT_UINT8, BASE_DEC, VALS (valstr_004_171_07_HPR), 0x02, NULL, HFILL } },
        { &hf_004_171_07_CDM, { "CDM", "asterix.004_171_07_CDM", FT_UINT8, BASE_DEC, VALS (valstr_004_171_07_CDM), 0xc0, NULL, HFILL } },
        { &hf_004_171_07_PRI, { "PRI", "asterix.004_171_07_PRI", FT_UINT8, BASE_DEC, VALS (valstr_004_171_07_PRI), 0x20, NULL, HFILL } },
        { &hf_004_171_07_GV, { "GV", "asterix.004_171_07_GV", FT_UINT8, BASE_DEC, VALS (valstr_004_171_07_GV), 0x10, NULL, HFILL } },
        { &hf_004_171_08, { "#8: Mode S Identifier Aircraft 2", "asterix.004_171_08", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_171_08_MS2, { "MS2", "asterix.004_171_08_MS2", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_171_09, { "#9: Flight Plan Number Aircraft 2", "asterix.004_171_09", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_171_09_FP2, { "FP2", "asterix.004_171_09_FP2", FT_UINT32, BASE_DEC, NULL, 0x07ffffff, NULL, HFILL } },
        { &hf_004_171_10, { "#10: Cleared Flight Level Aircraft 2", "asterix.004_171_10", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_171_10_CF2, { "CF2[FL]", "asterix.004_171_10_CF2", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_RE, { "Reserved Field", "asterix.004_RE", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_004_SP, { "Special Field", "asterix.004_SP", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
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
        { &hf_009_080_SCALE, { "Scaling factor", "asterix.009_080_SCALE", FT_UINT8, BASE_DEC, NULL, 0xf8, NULL, HFILL } },
        { &hf_009_080_R, { "R", "asterix.009_080_R", FT_UINT8, BASE_DEC, NULL, 0x07, NULL, HFILL } },
        { &hf_009_080_Q, { "Q", "asterix.009_080_Q", FT_UINT16, BASE_DEC, NULL, 0xfffe, NULL, HFILL } },
        { &hf_009_090, { "090, Radar Configuration and Status", "asterix.009_090", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_009_090_CP, { "CP", "asterix.009_090_CP", FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL } },
        { &hf_009_090_WO, { "WO", "asterix.009_090_WO", FT_UINT8, BASE_DEC, NULL, 0x08, NULL, HFILL } },
        { &hf_009_090_RS, { "RS", "asterix.009_090_RS", FT_UINT8, BASE_DEC, NULL, 0x07, NULL, HFILL } },
        { &hf_009_100, { "100, Vector Count", "asterix.009_100", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_009_100_VC, { "VC", "asterix.009_030_VC", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        /* Category 010 */
        { &hf_010_000, { "000, Message Type", "asterix.010_000", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_000_MT, { "MT", "asterix.010_000_MT", FT_UINT8, BASE_DEC, VALS(valstr_010_000_MT), 0x0, NULL, HFILL } },
        { &hf_010_010, { "010, Data Source Identifier", "asterix.010_010", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_020, { "020, Target Report Descriptor", "asterix.010_020", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_020_TYP, { "TYP", "asterix.010_020_TYP", FT_UINT8, BASE_DEC, VALS(valstr_010_020_TYP), 0xe0, NULL, HFILL } },
        { &hf_010_020_DCR, { "DCR", "asterix.010_020_DCR", FT_UINT8, BASE_DEC, VALS(valstr_010_020_DCR), 0x10, NULL, HFILL } },
        { &hf_010_020_CHN, { "CHN", "asterix.010_020_CHN", FT_UINT8, BASE_DEC, VALS(valstr_010_020_CHN), 0x08, NULL, HFILL } },
        { &hf_010_020_GBS, { "GBS", "asterix.010_020_GBS", FT_UINT8, BASE_DEC, VALS(valstr_010_020_GBS), 0x04, NULL, HFILL } },
        { &hf_010_020_CRT, { "CRT", "asterix.010_020_CRT", FT_UINT8, BASE_DEC, VALS(valstr_010_020_CRT), 0x02, NULL, HFILL } },
        { &hf_010_020_SIM, { "SIM", "asterix.010_020_SIM", FT_UINT8, BASE_DEC, VALS(valstr_010_020_SIM), 0x80, NULL, HFILL } },
        { &hf_010_020_TST, { "TST", "asterix.010_020_TST", FT_UINT8, BASE_DEC, VALS(valstr_010_020_TST), 0x40, NULL, HFILL } },
        { &hf_010_020_RAB, { "RAB", "asterix.010_020_RAB", FT_UINT8, BASE_DEC, VALS(valstr_010_020_RAB), 0x20, NULL, HFILL } },
        { &hf_010_020_LOP, { "LOP", "asterix.010_020_LOP", FT_UINT8, BASE_DEC, VALS(valstr_010_020_LOP), 0x18, NULL, HFILL } },
        { &hf_010_020_TOT, { "TOT", "asterix.010_020_TOT", FT_UINT8, BASE_DEC, VALS(valstr_010_020_TOT), 0x06, NULL, HFILL } },
        { &hf_010_020_SPI, { "SPI", "asterix.010_020_SPI", FT_UINT8, BASE_DEC, VALS(valstr_010_020_SPI), 0x80, NULL, HFILL } },
        { &hf_010_040, { "040, Measured Position in Polar Co-ordinates", "asterix.010_040", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_040_RHO, { "Rho[M]", "asterix.010_040_RHO", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_040_THETA, { "Theta[deg]", "asterix.010_040_THETA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_041, { "041, Position in WGS-84 Coordinates", "asterix.010_041", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_041_LAT, { "Latitude in WGS-84 [deg]", "asterix.010_041_LAT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_041_LON, { "Longitude in WGS-84 [deg]", "asterix.010_041_LON", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_042, { "042, Position in Cartesian Coordinates", "asterix.010_042", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_042_X, { "X [m]", "asterix.010_042_X", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_042_Y, { "Y [m]", "asterix.010_042_Y", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_060, { "060, Mode-3/A Code in Octal Representation", "asterix.010_060", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_060_V, { "V", "asterix.010_060_V", FT_UINT16, BASE_DEC, VALS(valstr_010_060_V), 0x8000, NULL, HFILL } },
        { &hf_010_060_G, { "G", "asterix.010_060_G", FT_UINT16, BASE_DEC, VALS(valstr_010_060_G), 0x4000, NULL, HFILL } },
        { &hf_010_060_L, { "L", "asterix.010_060_L", FT_UINT16, BASE_DEC, VALS(valstr_010_060_L), 0x2000, NULL, HFILL } },
        { &hf_010_060_SQUAWK, { "SQUAWK", "asterix.010_060_SQUAWK", FT_UINT16, BASE_OCT, NULL, 0x0fff, NULL, HFILL } },
        { &hf_010_090, { "090, Flight Level in Binary Representation", "asterix.010_090", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_090_V, { "V", "asterix.010_090_V", FT_UINT16, BASE_DEC, VALS(valstr_010_090_V), 0x8000, NULL, HFILL } },
        { &hf_010_090_G, { "G", "asterix.010_090_G", FT_UINT16, BASE_DEC, VALS(valstr_010_090_G), 0x4000, NULL, HFILL } },
        { &hf_010_090_FL, { "FL", "asterix.010_090_FL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_091, { "110, Measured Height", "asterix.010_091", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_091_MH, { "MH [ft]", "asterix.010_091_MH", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_131, { "131, Amplitude of Primary Plot", "asterix.010_131", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_131_PAM, { "PAM [dBm]", "asterix.010_131_PAM", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_010_140, { "140, Time of Day", "asterix.010_140", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_161, { "161, Track Number", "asterix.010_161", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_161_TN, { "TN", "asterix.010_161_TN", FT_UINT16, BASE_DEC, NULL, 0x0fff, NULL, HFILL } },
        { &hf_010_170, { "170, Track Status", "asterix.010_170", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_170_CNF, { "CNF", "asterix.010_170_CNF", FT_UINT8, BASE_DEC, VALS(valstr_010_170_CNF), 0x80, NULL, HFILL } },
        { &hf_010_170_TRE, { "TRE", "asterix.010_170_TRE", FT_UINT8, BASE_DEC, VALS(valstr_010_170_TRE), 0x40, NULL, HFILL } },
        { &hf_010_170_CST, { "CST", "asterix.010_170_CST", FT_UINT8, BASE_DEC, VALS(valstr_010_170_CST), 0x30, NULL, HFILL } },
        { &hf_010_170_MAH, { "MAH", "asterix.010_170_MAH", FT_UINT8, BASE_DEC, VALS(valstr_010_170_MAH), 0x08, NULL, HFILL } },
        { &hf_010_170_TCC, { "TCC", "asterix.010_170_TCC", FT_UINT8, BASE_DEC, VALS(valstr_010_170_TCC), 0x04, NULL, HFILL } },
        { &hf_010_170_STH, { "STH", "asterix.010_170_STH", FT_UINT8, BASE_DEC, VALS(valstr_010_170_STH), 0x02, NULL, HFILL } },
        { &hf_010_170_TOM, { "TOM", "asterix.010_170_TOM", FT_UINT8, BASE_DEC, VALS(valstr_010_170_TOM), 0xC0, NULL, HFILL } },
        { &hf_010_170_DOU, { "DOU", "asterix.010_170_DOU", FT_UINT8, BASE_DEC, VALS(valstr_010_170_DOU), 0x38, NULL, HFILL } },
        { &hf_010_170_MRS, { "MRS", "asterix.010_170_MRS", FT_UINT8, BASE_DEC, VALS(valstr_010_170_MRS), 0x06, NULL, HFILL } },
        { &hf_010_170_GHO, { "GHO", "asterix.010_170_GHO", FT_UINT8, BASE_DEC, VALS(valstr_010_170_GHO), 0x80, NULL, HFILL } },
        { &hf_010_200, { "200, Calculated Track Velocity in Polar Co-ordinates", "asterix.010_200", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_200_GS, { "Ground Speed [NM/s]", "asterix.010_200_GS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_200_TA, { "Track Angle [deg]", "asterix.010_200_TA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_202, { "202, Calculated Track Velocity in Cartesian Coordinates", "asterix.010_202", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_202_VX, { "VX [m/s]", "asterix.010_202_VX", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_202_VY, { "VX [m/s]", "asterix.010_202_VY", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_210, { "210, Calculated Acceleration", "asterix.010_210", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_210_AX, { "AX [m/s^2]", "asterix.010_210_AX", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_210_AY, { "AY [m/s^2]", "asterix.010_210_AY", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_220, { "220, Target Address", "asterix.010_220", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_245, { "245, Target Identification", "asterix.010_245", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_245_STI, { "STI", "asterix.010_245_STI", FT_UINT8, BASE_DEC, VALS(valstr_010_245_STI), 0xc0, NULL, HFILL } },
        { &hf_010_250, { "250, Mode S MB Data", "asterix.010_250", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_270, { "270, Target Size & Orientation", "asterix.010_270", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_270_LENGTH, { "Length[m]", "asterix.010_270_LENGTH", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_270_ORIENTATION, { "Orientation[m]", "asterix.010_270_ORIENTATION", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_270_WIDTH, { "Width[m]", "asterix.010_270_WIDTH", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_280, { "280, Presence", "asterix.010_280", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_280_DRHO, { "DRHO [m]", "asterix.010_280_DRHO", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_280_DTHETA, { "DTHETA [deg]", "asterix.010_280_DTHETA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_300, { "300, Vehicle Fleet Identification", "asterix.010_300", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_300_VFI, { "VFI", "asterix.010_300_VFI", FT_UINT8, BASE_DEC, VALS(valstr_010_300_VFI), 0x0, NULL, HFILL } },
        { &hf_010_310, { "310, Pre-programmed Message", "asterix.010_310", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_310_TRB, { "TRB", "asterix.010_310_TRB", FT_UINT8, BASE_DEC, VALS(valstr_010_310_TRB), 0x80, NULL, HFILL } },
        { &hf_010_310_MSG, { "MSG", "asterix.010_310_MSG", FT_UINT8, BASE_DEC, VALS(valstr_010_310_MSG), 0x7f, NULL, HFILL } },
        { &hf_010_500, { "Standard Deviation of Position", "asterix.010_500", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_500_SDPx, { "SDPx [m]", "asterix.010_500_SDPx", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_500_SDPy, { "SDPy [m]", "asterix.010_500_SDPy", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_500_SDPxy, { "SDPxy", "asterix.010_500_SDPxy", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_550, { "550, System Status", "asterix.010_550", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_550_NOGO, { "NOGO", "asterix.010_550_NOGO", FT_UINT8, BASE_DEC, VALS(valstr_010_550_NOGO), 0xc0, NULL, HFILL } },
        { &hf_010_550_OVL, { "OVL", "asterix.010_550_OVL", FT_UINT8, BASE_DEC, VALS(valstr_010_550_OVL), 0x20, NULL, HFILL } },
        { &hf_010_550_TSV, { "TSV", "asterix.010_550_TSV", FT_UINT8, BASE_DEC, VALS(valstr_010_550_TSV), 0x10, NULL, HFILL } },
        { &hf_010_550_DIV, { "DIV", "asterix.010_550_DIV", FT_UINT8, BASE_DEC, VALS(valstr_010_550_DIV), 0x08, NULL, HFILL } },
        { &hf_010_550_TTF, { "TTF", "asterix.010_550_TTF", FT_UINT8, BASE_DEC, VALS(valstr_010_550_TTF), 0x04, NULL, HFILL } },
        { &hf_010_SP, { "Special Purpose Field", "asterix.010_SP", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_010_RE, { "Reserved Expansion Field", "asterix.010_RE", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        /* Category 011 */
        { &hf_011_000, { "000, Message Type", "asterix.011_000", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_000_MT, { "MT", "asterix.011_000_MT", FT_UINT8, BASE_DEC, VALS(valstr_011_000_MT), 0x0, NULL, HFILL } },
        { &hf_011_010, { "010, Data Source Identification", "asterix.011_010", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_015, { "015, Service Identification", "asterix.011_015", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_015_SI, { "SI", "asterix.011_015_SI", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_011_041, { "041, Position in WGS-84 Co-ordinates", "asterix.011_041", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_041_LAT, { "Latitude [deg]", "asterix.011_041_LAT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_041_LON, { "Longitude [deg]", "asterix.011_041_LON", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_042, { "042, Calculated Position in Cartesian Co-ordinates", "asterix.011_042", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_042_X, { "X-Component [NM]", "asterix.011_042_X", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_042_Y, { "Y-Component [NM]", "asterix.011_042_Y", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_060, { "060, Mode-3/A Code in Octal Representation", "asterix.011_060", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_060_SQUAWK, { "SQUAWK", "asterix.011_060_SQUAWK", FT_UINT16, BASE_OCT, NULL, 0x0fff, NULL, HFILL } },
        { &hf_011_090, { "090, Measured Flight Level", "asterix.011_090", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_090_MFL, { "Measured Flight Level [FL]", "asterix.011_090_MFL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_092, { "092, Calculated Track Geometric Altitude", "asterix.011_092", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_092_ALT, { "Altitude [ft]", "asterix.011_092_ALT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_093, { "093, Calculated Track Barometric Altitude", "asterix.011_093", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_093_QNH, { "QNH", "asterix.011_093_QNH", FT_UINT8, BASE_DEC, VALS(valstr_011_093_QNH), 0x80, NULL, HFILL } },
        { &hf_011_093_ALT, { "Altitude [FL]", "asterix.011_093_ALT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_140, { "140, Time Of Track Information", "asterix.011_140", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_161, { "161, Track Number", "asterix.011_161", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_161_TN, { "TN", "asterix.011_161_TN", FT_UINT16, BASE_DEC, NULL, 0x0fff, NULL, HFILL } },
        { &hf_011_170, { "170, Track Status", "asterix.011_170", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_170_MON, { "MON", "asterix.011_170_MON", FT_UINT8, BASE_DEC, VALS(valstr_011_170_MON), 0x80, NULL, HFILL } },
        { &hf_011_170_GBS, { "GBS", "asterix.011_170_GBS", FT_UINT8, BASE_DEC, VALS(valstr_011_170_GBS), 0x40, NULL, HFILL } },
        { &hf_011_170_MRH, { "MRH", "asterix.011_170_MRH", FT_UINT8, BASE_DEC, VALS(valstr_011_170_MRH), 0x20, NULL, HFILL } },
        { &hf_011_170_SRC, { "SRC", "asterix.011_170_SRC", FT_UINT8, BASE_DEC, VALS(valstr_011_170_SRC), 0x1c, NULL, HFILL } },
        { &hf_011_170_CNF, { "CNF", "asterix.011_170_CNF", FT_UINT8, BASE_DEC, VALS(valstr_011_170_CNF), 0x02, NULL, HFILL } },
        { &hf_011_170_SIM, { "SIM", "asterix.011_170_SIM", FT_UINT8, BASE_DEC, VALS(valstr_011_170_SIM), 0x80, NULL, HFILL } },
        { &hf_011_170_TSE, { "TSE", "asterix.011_170_TSE", FT_UINT8, BASE_DEC, VALS(valstr_011_170_TSE), 0x40, NULL, HFILL } },
        { &hf_011_170_TSB, { "TSB", "asterix.011_170_TSB", FT_UINT8, BASE_DEC, VALS(valstr_011_170_TSB), 0x20, NULL, HFILL } },
        { &hf_011_170_FRIFOE, { "FRI/FOE", "asterix.011_170_FRIFOE", FT_UINT8, BASE_DEC, VALS(valstr_011_170_FRIFOE), 0x18, NULL, HFILL } },
        { &hf_011_170_ME, { "ME", "asterix.011_170_ME", FT_UINT8, BASE_DEC, VALS(valstr_011_170_ME), 0x04, NULL, HFILL } },
        { &hf_011_170_MI, { "MI", "asterix.011_170_MI", FT_UINT8, BASE_DEC, VALS(valstr_011_170_MI), 0x02, NULL, HFILL } },
        { &hf_011_170_AMA, { "AMA", "asterix.011_170_AMA", FT_UINT8, BASE_DEC, VALS(valstr_011_170_AMA), 0x80, NULL, HFILL } },
        { &hf_011_170_SPI, { "SPI", "asterix.011_170_SPI", FT_UINT8, BASE_DEC, VALS(valstr_011_170_SPI), 0x40, NULL, HFILL } },
        { &hf_011_170_CST, { "CST", "asterix.011_170_CST", FT_UINT8, BASE_DEC, VALS(valstr_011_170_CST), 0x20, NULL, HFILL } },
        { &hf_011_170_FPC, { "FPC", "asterix.011_170_FPC", FT_UINT8, BASE_DEC, VALS(valstr_011_170_FPC), 0x10, NULL, HFILL } },
        { &hf_011_170_AFF, { "AFF", "asterix.011_170_AFF", FT_UINT8, BASE_DEC, VALS(valstr_011_170_AFF), 0x08, NULL, HFILL } },
        { &hf_011_170_PSR, { "PSR", "asterix.011_170_PSR", FT_UINT8, BASE_DEC, VALS(valstr_011_170_PSR), 0x40, NULL, HFILL } },
        { &hf_011_170_SSR, { "SSR", "asterix.011_170_SSR", FT_UINT8, BASE_DEC, VALS(valstr_011_170_SSR), 0x20, NULL, HFILL } },
        { &hf_011_170_MDS, { "MDS", "asterix.011_170_MDS", FT_UINT8, BASE_DEC, VALS(valstr_011_170_MDS), 0x10, NULL, HFILL } },
        { &hf_011_170_ADS, { "ADS", "asterix.011_170_ADS", FT_UINT8, BASE_DEC, VALS(valstr_011_170_ADS), 0x08, NULL, HFILL } },
        { &hf_011_170_SUC, { "SUC", "asterix.011_170_SUC", FT_UINT8, BASE_DEC, VALS(valstr_011_170_SUC), 0x04, NULL, HFILL } },
        { &hf_011_170_AAC, { "AAC", "asterix.011_170_AAC", FT_UINT8, BASE_DEC, VALS(valstr_011_170_AAC), 0x02, NULL, HFILL } },
        { &hf_011_202, { "202, Calculated Track Velocity in Cartesian Coordinates", "asterix.011_202", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_202_VX, { "Vx [m/s]", "asterix.011_202_VX", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_202_VY, { "Vy [m/s]", "asterix.011_202_VY", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_210, { "210, Calculated Acceleration", "asterix.011_210", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_210_AX, { "Ax [m/s^2]", "asterix.011_210_AX", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_210_AY, { "Ay [m/s^2]", "asterix.011_210_AY", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_215, { "215, Calculated Rate Of Climb/Descent", "asterix.011_215", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_215_ROCD, { "ROCD [ft/min]", "asterix.011_215_ROCD", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_245, { "245, Target Identification", "asterix.011_245", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_245_STI, { "STI", "asterix.011_245_STI", FT_UINT8, BASE_DEC, VALS(valstr_011_245_STI), 0xc0, NULL, HFILL } },
        { &hf_011_270, { "270, Target Size & Orientation", "asterix.011_270", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_270_LENGTH, { "Length [m]", "asterix.011_270_LENGTH", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_270_ORIENTATION, { "Orientation [deg]", "asterix.011_270_ORIENTATION", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_270_WIDTH, { "Width [m]", "asterix.011_270_WIDTH", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_290, { "290, System Track Update Ages", "asterix.011_290", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_290_01, { "#1: PSR Age", "asterix.011_290_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_290_01_PSR, { "PSR [s]", "asterix.011_290_01_PSR", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_290_02, { "#2: SSR Age", "asterix.011_290_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_290_02_SSR, { "SSR [s]", "asterix.011_290_02_SSR", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_290_03, { "#3: Mode 3/A Age", "asterix.011_290_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_290_03_MDA, { "MDA [s]", "asterix.011_290_03_MDA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_290_04, { "#4: Meausered Flight Level Age", "asterix.011_290_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_290_04_MFL, { "MFL [s]", "asterix.011_290_04_MFL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_290_05, { "#5: Mode S Age", "asterix.011_290_05", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_290_05_MDS, { "MDS [s]", "asterix.011_290_05_MDS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_290_06, { "#6: ADS Age", "asterix.011_290_06", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_290_06_ADS, { "ADS [s]", "asterix.011_290_06_ADS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_290_07, { "#7: ADS-B Age", "asterix.011_290_07", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_290_07_ADB, { "ADB [s]", "asterix.011_290_07_ADB", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_290_08, { "#8: Mode 1 Age", "asterix.011_290_08", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_290_08_MD1, { "MD1 [s]", "asterix.011_290_08_MD1", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_290_09, { "#9: Mode 2 Age", "asterix.011_290_09", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_290_09_MD2, { "MD2 [s]", "asterix.011_290_09_MD2", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_290_10, { "#10: Loop Age", "asterix.011_290_10", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_290_10_LOP, { "LOP [s]", "asterix.011_290_10_LOP", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_290_11, { "#11: Track Age", "asterix.011_290_11", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_290_11_TRK, { "TRK [s]", "asterix.011_290_11_TRK", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_290_12, { "#12: Multilateration Age", "asterix.011_290_12", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_290_12_MUL, { "MUL [s]", "asterix.011_290_12_MUL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_300, { "300, Vehicle Fleet Identification", "asterix.011_300", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_300_VFI, { "VFI", "asterix.011_300_VFI", FT_UINT8, BASE_DEC, VALS(valstr_011_300_VFI), 0x0, NULL, HFILL } },
        { &hf_011_310, { "310, Pre-programmed Message", "asterix.011_310", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_310_TRB, { "TRB", "asterix.011_310_TRB", FT_UINT8, BASE_DEC, VALS(valstr_011_310_TRB), 0x80, NULL, HFILL } },
        { &hf_011_310_MSG, { "MSG", "asterix.011_310_MSG", FT_UINT8, BASE_DEC, VALS(valstr_011_310_MSG), 0x7f, NULL, HFILL } },
        { &hf_011_380, { "380, Mode S / ADS-B Related Data", "asterix.011_380", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_380_01, { "#1: Mode S MB Data", "asterix.011_380_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_380_02, { "#2: Aircraft Address", "asterix.011_380_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        /* #3 Never Sent */
        { &hf_011_380_04, { "#4: Communications/ACAS Capability and Flight Status", "asterix.011_380_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_380_04_COM, { "COM", "asterix.011_380_04_COM", FT_UINT8, BASE_DEC, VALS(valstr_011_380_04_COM), 0xe0, NULL, HFILL } },
        { &hf_011_380_04_STAT, { "STAT", "asterix.011_380_04_STAT", FT_UINT8, BASE_DEC, VALS(valstr_011_380_04_STAT), 0x1e, NULL, HFILL } },
        { &hf_011_380_04_SSC, { "SSC", "asterix.011_380_04_SSC", FT_UINT8, BASE_DEC, VALS(valstr_011_380_04_SSC), 0x80, NULL, HFILL } },
        { &hf_011_380_04_ARC, { "ARC", "asterix.011_380_04_ARC", FT_UINT8, BASE_DEC, VALS(valstr_011_380_04_ARC), 0x40, NULL, HFILL } },
        { &hf_011_380_04_AIC, { "AIC", "asterix.011_380_04_AIC", FT_UINT8, BASE_DEC, VALS(valstr_011_380_04_AIC), 0x20, NULL, HFILL } },
        { &hf_011_380_04_B1A, { "B1A", "asterix.011_380_04_B1A", FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL } },
        { &hf_011_380_04_B1B, { "B1B", "asterix.011_380_04_B1B", FT_UINT8, BASE_HEX, NULL, 0x0f, NULL, HFILL } },
        { &hf_011_380_04_AC, { "AC", "asterix.011_380_04_AC", FT_UINT16, BASE_DEC, VALS(valstr_011_380_04_AC), 0xc000, NULL, HFILL } },
        { &hf_011_380_04_MN, { "MN", "asterix.011_380_04_MN", FT_UINT16, BASE_DEC, VALS(valstr_011_380_04_MN), 0x3000, NULL, HFILL } },
        { &hf_011_380_04_DC, { "DC", "asterix.011_380_04_DC", FT_UINT16, BASE_DEC, VALS(valstr_011_380_04_DC), 0x0c00, NULL, HFILL } },
        /* #5 to #7 Never Sent */
        { &hf_011_380_08, { "#8: Aircraft Derived Aircraft Type", "asterix.011_380_08", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_380_08_ADAT, { "ADAT", "asterix.011_380_08_ADAT", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_380_09, { "#9 Emitter Category", "asterix.011_380_09", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_380_09_ECAT, { "ECAT", "asterix.011_380_09_ECAT", FT_UINT8, BASE_DEC, VALS(valstr_011_380_09_ECAT), 0x0, NULL, HFILL } },
        /* #10 Never Sent */
        { &hf_011_380_11, { "#11 Available Technologies", "asterix.011_380_11", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_380_11_VDL, { "VDL", "asterix.011_380_11_VDL", FT_UINT8, BASE_DEC, VALS(valstr_011_380_11_VDL), 0x80, NULL, HFILL } },
        { &hf_011_380_11_MDS, { "MDS", "asterix.011_380_11_MDS", FT_UINT8, BASE_DEC, VALS(valstr_011_380_11_MDS), 0x40, NULL, HFILL } },
        { &hf_011_380_11_UAT, { "UAT", "asterix.011_380_11_UAT", FT_UINT8, BASE_DEC, VALS(valstr_011_380_11_UAT), 0x20, NULL, HFILL } },
        { &hf_011_390, { "390, Flight Plan Related Data", "asterix.011_390", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_390_01, { "#1: FPPS Identification Tag", "asterix.011_390_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_390_02, { "#2: Callsign", "asterix.011_390_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_390_02_CSN, { "CSN", "asterix.011_390_02_CSN", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_390_03, { "#3: IFPS_FLIGHT_ID", "asterix.011_390_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_390_03_TYP, { "TYP", "asterix.011_390_03_TYP", FT_UINT32, BASE_DEC, VALS(valstr_011_390_03_TYP), 0xc0000000, NULL, HFILL } },
        { &hf_011_390_03_NBR, { "NBR", "asterix.011_390_03_NBR", FT_UINT32, BASE_DEC, NULL, 0x07ffffff, NULL, HFILL } },
        { &hf_011_390_04, { "#4: Flight Category", "asterix.011_390_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_390_04_GAT_OAT, { "GAT/OAT", "asterix.011_390_04_GAT_OAT", FT_UINT8, BASE_DEC, VALS(valstr_011_390_04_GAT_OAT), 0xc0, NULL, HFILL } },
        { &hf_011_390_04_FR12, { "FR1/FR2", "asterix.011_390_04_FR12", FT_UINT8, BASE_DEC, VALS(valstr_011_390_04_FR12), 0x30, NULL, HFILL } },
        { &hf_011_390_04_RVSM, { "RVSM", "asterix.011_390_04_RVSM", FT_UINT8, BASE_DEC, VALS(valstr_011_390_04_RVSM), 0x0c, NULL, HFILL } },
        { &hf_011_390_04_HPR, { "HPR", "asterix.011_390_04_HPR", FT_UINT8, BASE_DEC, VALS(valstr_011_390_04_HPR), 0x02, NULL, HFILL } },
        { &hf_011_390_05, { "#5: Type of Aircraft", "asterix.011_390_05", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_390_05_ACTYP, { "ACTYP", "asterix.011_390_05_ACTYP", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_390_06, { "#6: Wake Turbulence Category", "asterix.011_390_06", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_390_06_WTC, { "WTC", "asterix.011_390_06_WTC", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_390_07, { "#7: Departure Airport", "asterix.011_390_07", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_390_07_ADEP, { "ADEP", "asterix.011_390_07_ADEP", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_390_08, { "#8: Destination Airport", "asterix.011_390_08", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_390_08_ADES, { "ADES", "asterix.011_390_08_ADES", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_390_09, { "#9: Runway Designation", "asterix.011_390_09", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_390_09_RWY, { "RWY", "asterix.011_390_09_RWY", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_390_10, { "#10: Current Cleared Flight Level", "asterix.011_390_10", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_390_10_CFL, { "CFL [FL]", "asterix.011_390_10_CFL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_390_11, { "#11: Current Control Position", "asterix.011_390_11", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_390_11_CNTR, { "CNTR", "asterix.011_390_11_CNTR", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_011_390_11_POS, { "POS", "asterix.011_390_11_POS", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_011_390_12, { "#12: Time of Departure", "asterix.011_390_12", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_390_12_TYP, { "TYP", "asterix.011_390_12_TYP", FT_UINT32, BASE_DEC, VALS(valstr_011_390_12_TYP), 0xf8000000, NULL, HFILL } },
        { &hf_011_390_12_DAY, { "DAY", "asterix.011_390_12_DAY", FT_UINT32, BASE_DEC, VALS(valstr_011_390_12_DAY), 0x06000000, NULL, HFILL } },
        { &hf_011_390_12_HOR, { "HOUR", "asterix.011_390_12_HOR", FT_UINT32, BASE_DEC, NULL, 0x001f0000, NULL, HFILL } },
        { &hf_011_390_12_MIN, { "MIN", "asterix.011_390_12_MIN", FT_UINT32, BASE_DEC, NULL, 0x00003f00, NULL, HFILL } },
        { &hf_011_390_12_AVS, { "AVS", "asterix.011_390_12_AVS", FT_UINT32, BASE_DEC, VALS(valstr_011_390_12_AVS), 0x00000080, NULL, HFILL } },
        { &hf_011_390_12_SEC, { "SEC", "asterix.011_390_12_SEC", FT_UINT32, BASE_DEC, NULL, 0x0000003f, NULL, HFILL } },
        { &hf_011_390_13, { "#13: Aircraft Stand", "asterix.011_390_13", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_390_13_STAND, { "STAND", "asterix.011_390_13_STAND", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_390_14, { "#14: Stand Status", "asterix.011_390_14", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_390_14_EMP, { "EMP", "asterix.011_390_14_EMP", FT_UINT8, BASE_DEC, VALS(valstr_011_390_14_EMP), 0xc0, NULL, HFILL } },
        { &hf_011_390_14_AVL, { "AVL", "asterix.011_390_14_AVL", FT_UINT8, BASE_DEC, VALS(valstr_011_390_14_AVL), 0x30, NULL, HFILL } },
        { &hf_011_430, { "430, Phase of Flight", "asterix.011_430", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_430_FLS, { "FLS", "asterix.011_430_FLS", FT_UINT8, BASE_DEC, VALS(valstr_011_430_FLS), 0x0, NULL, HFILL } },
        { &hf_011_500, { "500, Estimated Accuracies", "asterix.011_500", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_500_01, { "#1: Estimated Accuracy Of Track Position (Cartesian)", "asterix.011_500_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_500_01_APCX, { "APC-X [m]", "asterix.011_500_01_APCX", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_500_01_APCY, { "APC-Y [m]", "asterix.011_500_01_APCY", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_500_02, { "#2: Estimated Accuracy Of Track Position (WGS-84)", "asterix.011_500_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_500_02_APWLAT, { "APW LAT [deg]", "asterix.011_500_02_APWLAT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_500_02_APWLON, { "APW LON [deg]", "asterix.011_500_02_APWLON", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_500_03, { "#3: Estimated Accuracy Of Height", "asterix.011_500_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_500_03_ATA, { "ATA [m]", "asterix.011_500_03_ATA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_500_04, { "#4: Estimated Accuracy of Track Velocity (Cartesian)", "asterix.011_500_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_500_04_AVCX, { "AVC-X [m/s]", "asterix.011_500_04_AVCX", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_500_04_AVCY, { "AVC-Y [m/s]", "asterix.011_500_04_AVCY", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_500_05, { "#5: Estimated Accuracy Of Rate Of Climb/Descent", "asterix.011_500_05", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_500_05_ARC, { "ARC [m/s]", "asterix.011_500_05_ARC", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_500_06, { "#6: Estimated Accuracy Of Acceleration (Cartesian)", "asterix.011_500_06", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_500_06_AACX, { "AAC-X [m/s^2]", "asterix.011_500_06_AAX", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_500_06_AACY, { "AAC-Y [m/s^2]", "asterix.011_500_06_AAY", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_600, { "600, Alert Messages", "asterix.011_600", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_600_ACK, { "ACK", "asterix.011_600_ACK", FT_UINT8, BASE_DEC, VALS(valstr_011_600_ACK), 0x80, NULL, HFILL } },
        { &hf_011_600_SVR, { "SVR", "asterix.011_600_SVR", FT_UINT8, BASE_DEC, VALS(valstr_011_600_SVR), 0x60, NULL, HFILL } },
        { &hf_011_600_ALT, { "Alert Type", "asterix.011_600_ALT", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_011_600_ALN, { "Alert Number", "asterix.011_600_ALN", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_011_605, { "605, Tracks in Alert", "asterix.011_605", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_605_FTN, { "Fusion Track Number", "asterix.011_605_FTN", FT_UINT16, BASE_DEC, NULL, 0x0fff, NULL, HFILL } },
        { &hf_011_610, { "610, Holdbar Status", "asterix.011_610", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_610_BKN, { "Bank Number", "asterix.011_610_BKN", FT_UINT8, BASE_DEC, NULL, 0xf0, NULL, HFILL } },
        { &hf_011_610_I01, { "I1", "asterix.011_610_I01", FT_UINT16, BASE_DEC, VALS(valstr_011_610_I01), 0x800, NULL, HFILL } },
        { &hf_011_610_I02, { "I2", "asterix.011_610_I02", FT_UINT16, BASE_DEC, VALS(valstr_011_610_I02), 0x400, NULL, HFILL } },
        { &hf_011_610_I03, { "I3", "asterix.011_610_I03", FT_UINT16, BASE_DEC, VALS(valstr_011_610_I03), 0x200, NULL, HFILL } },
        { &hf_011_610_I04, { "I4", "asterix.011_610_I04", FT_UINT16, BASE_DEC, VALS(valstr_011_610_I04), 0x100, NULL, HFILL } },
        { &hf_011_610_I05, { "I5", "asterix.011_610_I05", FT_UINT16, BASE_DEC, VALS(valstr_011_610_I05), 0x80, NULL, HFILL } },
        { &hf_011_610_I06, { "I6", "asterix.011_610_I06", FT_UINT16, BASE_DEC, VALS(valstr_011_610_I06), 0x40, NULL, HFILL } },
        { &hf_011_610_I07, { "I7", "asterix.011_610_I07", FT_UINT16, BASE_DEC, VALS(valstr_011_610_I07), 0x20, NULL, HFILL } },
        { &hf_011_610_I08, { "I8", "asterix.011_610_I08", FT_UINT16, BASE_DEC, VALS(valstr_011_610_I08), 0x10, NULL, HFILL } },
        { &hf_011_610_I09, { "I9", "asterix.011_610_I09", FT_UINT16, BASE_DEC, VALS(valstr_011_610_I09), 0x08, NULL, HFILL } },
        { &hf_011_610_I10, { "I10", "asterix.011_610_I10", FT_UINT16, BASE_DEC, VALS(valstr_011_610_I10), 0x04, NULL, HFILL } },
        { &hf_011_610_I11, { "I11", "asterix.011_610_I11", FT_UINT16, BASE_DEC, VALS(valstr_011_610_I11), 0x02, NULL, HFILL } },
        { &hf_011_610_I12, { "I12", "asterix.011_610_I12", FT_UINT16, BASE_DEC, VALS(valstr_011_610_I12), 0x01, NULL, HFILL } },
        { &hf_011_SP, { "Special Purpose Field", "asterix.011_SP", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_011_RE, { "Reserved Expansion Field", "asterix.011_RE", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        /* Category 019 */
        { &hf_019_000, { "000, Message Type", "asterix.019_000", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_019_000_MT, { "MT", "asterix.019_000_MT", FT_UINT8, BASE_DEC, VALS(valstr_019_000_MT), 0x0, NULL, HFILL } },
        { &hf_019_010, { "010, Data Source Identification", "asterix.019_010", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_019_140, { "140, Time of Day", "asterix.019_140", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_019_550, { "550, System Status", "asterix.019_550", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_019_550_NOGO, { "NOGO", "asterix.019_550_NOGO", FT_UINT8, BASE_DEC, VALS(valstr_019_550_NOGO), 0xc0, NULL, HFILL } },
        { &hf_019_550_OVL, { "OVL", "asterix.019_550_OVL", FT_UINT8, BASE_DEC, VALS(valstr_019_550_OVL), 0x20, NULL, HFILL } },
        { &hf_019_550_TSV, { "TSV", "asterix.019_550_TSV", FT_UINT8, BASE_DEC, VALS(valstr_019_550_TSV), 0x10, NULL, HFILL } },
        { &hf_019_550_TTF, { "TTF", "asterix.019_550_TTF", FT_UINT8, BASE_DEC, VALS(valstr_019_550_TTF), 0x08, NULL, HFILL } },
        { &hf_019_551, { "551, Tracking Processor Detailed Status", "asterix.019_551", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_019_551_TP1_EXEC, { "SP1", "asterix.019_551_SP1_EXEC", FT_UINT8, BASE_DEC, VALS(valstr_019_551_TPX_EXEC), 0x80, NULL, HFILL } },
        { &hf_019_551_TP1_GOOD, { "SP1", "asterix.019_551_SP1_GOOD", FT_UINT8, BASE_DEC, VALS(valstr_019_551_TPX_GOOD), 0x40, NULL, HFILL } },
        { &hf_019_551_TP2_EXEC, { "SP2", "asterix.019_551_SP2_EXEC", FT_UINT8, BASE_DEC, VALS(valstr_019_551_TPX_EXEC), 0x20, NULL, HFILL } },
        { &hf_019_551_TP2_GOOD, { "SP2", "asterix.019_551_SP2_GOOD", FT_UINT8, BASE_DEC, VALS(valstr_019_551_TPX_GOOD), 0x10, NULL, HFILL } },
        { &hf_019_551_TP3_EXEC, { "SP3", "asterix.019_551_SP3_EXEC", FT_UINT8, BASE_DEC, VALS(valstr_019_551_TPX_EXEC), 0x08, NULL, HFILL } },
        { &hf_019_551_TP3_GOOD, { "SP3", "asterix.019_551_SP3_GOOD", FT_UINT8, BASE_DEC, VALS(valstr_019_551_TPX_GOOD), 0x04, NULL, HFILL } },
        { &hf_019_551_TP4_EXEC, { "SP4", "asterix.019_551_SP4_EXEC", FT_UINT8, BASE_DEC, VALS(valstr_019_551_TPX_EXEC), 0x02, NULL, HFILL } },
        { &hf_019_551_TP4_GOOD, { "SP4", "asterix.019_551_SP4_GOOD", FT_UINT8, BASE_DEC, VALS(valstr_019_551_TPX_GOOD), 0x01, NULL, HFILL } },
        { &hf_019_552, { "552, Remote Sensor Detailed Status", "asterix.019_552", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_019_552_RS_Identification, { "RS Identification", "asterix.019_552_RS_Identification", FT_UINT16, BASE_DEC, NULL, 0xff00, NULL, HFILL } },
        { &hf_019_552_Receiver_1090_MHz, { "Receiver 1090 MHz", "asterix.019_552_Receiver_1090_MHz", FT_UINT16, BASE_DEC, VALS(valstr_019_552_present), 0x0040, NULL, HFILL } },
        { &hf_019_552_Transmitter_1030_MHz, { "Transmitter 1030 MHz", "asterix.019_552_Transmitter_1030_MHz", FT_UINT16, BASE_DEC, VALS(valstr_019_552_present), 0x0020, NULL, HFILL } },
        { &hf_019_552_Transmitter_1090_MHz, { "Transmitter 1090 MHz", "asterix.019_552_Transmitter_1090_MHz", FT_UINT16, BASE_DEC, VALS(valstr_019_552_present), 0x0010, NULL, HFILL } },
        { &hf_019_552_RS_Status, { "RS Status", "asterix.019_552_RS_Status", FT_UINT16, BASE_DEC, VALS(valstr_019_552_RS_Status), 0x0008, NULL, HFILL } },
        { &hf_019_552_RS_Operational, { "RS Operational", "asterix.019_552_RS_Operational", FT_UINT16, BASE_DEC, VALS(valstr_019_552_RS_Operational), 0x0004, NULL, HFILL } },
        { &hf_019_553, { "553, Reference Transponder Detailed Status", "asterix.019_553", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_019_553_Ref_Trans_1_Status, { "RT1", "asterix.019_553_Ref_Trans_1_Status", FT_UINT8, BASE_DEC, VALS (valstr_019_553_Ref_Trans_Status), 0xc0, NULL, HFILL } },
        { &hf_019_553_Ref_Trans_2_Status, { "RT2", "asterix.019_553_Ref_Trans_2_Status", FT_UINT8, BASE_DEC, VALS (valstr_019_553_Ref_Trans_Status), 0x0c, NULL, HFILL } },
        { &hf_019_553_Ref_Trans_3_Status, { "RT3", "asterix.019_553_Ref_Trans_3_Status", FT_UINT8, BASE_DEC, VALS (valstr_019_553_Ref_Trans_Status), 0xc0, NULL, HFILL } },
        { &hf_019_553_Ref_Trans_4_Status, { "RT4", "asterix.019_553_Ref_Trans_4_Status", FT_UINT8, BASE_DEC, VALS (valstr_019_553_Ref_Trans_Status), 0x0c, NULL, HFILL } },
        { &hf_019_553_Ref_Trans_5_Status, { "RT5", "asterix.019_553_Ref_Trans_5_Status", FT_UINT8, BASE_DEC, VALS (valstr_019_553_Ref_Trans_Status), 0xc0, NULL, HFILL } },
        { &hf_019_553_Ref_Trans_6_Status, { "RT6", "asterix.019_553_Ref_Trans_6_Status", FT_UINT8, BASE_DEC, VALS (valstr_019_553_Ref_Trans_Status), 0x0c, NULL, HFILL } },
        { &hf_019_553_Ref_Trans_7_Status, { "RT7", "asterix.019_553_Ref_Trans_7_Status", FT_UINT8, BASE_DEC, VALS (valstr_019_553_Ref_Trans_Status), 0xc0, NULL, HFILL } },
        { &hf_019_553_Ref_Trans_8_Status, { "RT8", "asterix.019_553_Ref_Trans_8_Status", FT_UINT8, BASE_DEC, VALS (valstr_019_553_Ref_Trans_Status), 0x0c, NULL, HFILL } },
        { &hf_019_553_Ref_Trans_9_Status, { "RT9", "asterix.019_553_Ref_Trans_9_Status", FT_UINT8, BASE_DEC, VALS (valstr_019_553_Ref_Trans_Status), 0xc0, NULL, HFILL } },
        { &hf_019_553_Ref_Trans_10_Status, { "RT10", "asterix.019_553_Ref_Trans_10_Status", FT_UINT8, BASE_DEC, VALS (valstr_019_553_Ref_Trans_Status), 0x0c, NULL, HFILL } },
        { &hf_019_553_Ref_Trans_11_Status, { "RT11", "asterix.019_553_Ref_Trans_11_Status", FT_UINT8, BASE_DEC, VALS (valstr_019_553_Ref_Trans_Status), 0xc0, NULL, HFILL } },
        { &hf_019_553_Ref_Trans_12_Status, { "RT12", "asterix.019_553_Ref_Trans_12_Status", FT_UINT8, BASE_DEC, VALS (valstr_019_553_Ref_Trans_Status), 0x0c, NULL, HFILL } },
        { &hf_019_553_Ref_Trans_13_Status, { "RT13", "asterix.019_553_Ref_Trans_13_Status", FT_UINT8, BASE_DEC, VALS (valstr_019_553_Ref_Trans_Status), 0xc0, NULL, HFILL } },
        { &hf_019_553_Ref_Trans_14_Status, { "RT14", "asterix.019_553_Ref_Trans_14_Status", FT_UINT8, BASE_DEC, VALS (valstr_019_553_Ref_Trans_Status), 0x0c, NULL, HFILL } },
        { &hf_019_553_Ref_Trans_15_Status, { "RT15", "asterix.019_553_Ref_Trans_15_Status", FT_UINT8, BASE_DEC, VALS (valstr_019_553_Ref_Trans_Status), 0xc0, NULL, HFILL } },
        { &hf_019_553_Ref_Trans_16_Status, { "RT16", "asterix.019_553_Ref_Trans_16_Status", FT_UINT8, BASE_DEC, VALS (valstr_019_553_Ref_Trans_Status), 0x0c, NULL, HFILL } },
        { &hf_019_553_Ref_Trans_17_Status, { "RT17", "asterix.019_553_Ref_Trans_17_Status", FT_UINT8, BASE_DEC, VALS (valstr_019_553_Ref_Trans_Status), 0xc0, NULL, HFILL } },
        { &hf_019_553_Ref_Trans_18_Status, { "RT18", "asterix.019_553_Ref_Trans_18_Status", FT_UINT8, BASE_DEC, VALS (valstr_019_553_Ref_Trans_Status), 0x0c, NULL, HFILL } },
        { &hf_019_553_Ref_Trans_19_Status, { "RT19", "asterix.019_553_Ref_Trans_19_Status", FT_UINT8, BASE_DEC, VALS (valstr_019_553_Ref_Trans_Status), 0xc0, NULL, HFILL } },
        { &hf_019_553_Ref_Trans_20_Status, { "RT20", "asterix.019_553_Ref_Trans_20_Status", FT_UINT8, BASE_DEC, VALS (valstr_019_553_Ref_Trans_Status), 0x0c, NULL, HFILL } },
        { &hf_019_600, { "600, Position of the MLT System Reference Point (WGS-84)", "asterix.019_600", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_019_600_Latitude, { "Latitude [deg]", "asterix.019_600_Latitude", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_019_600_Longitude, { "Longitude [deg]", "asterix.019_600_Longitude", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_019_610, { "610, Height of the MLT System Reference Point (WGS-84)", "asterix.019_610", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_019_610_Height, { "Height [m]", "asterix.019_610_Height", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_019_620, { "620, WGS-84 Undulation", "asterix.019_620", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_019_620_Undulation, { "Undulation [m]", "asterix.019_620_Undulation", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_019_RE, { "Reserved Field", "asterix.019_RE", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_019_SP, { "Special Field", "asterix.019_SP", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        /* Category 020 */
        { &hf_020_010, { "010, Data Source Identifier", "asterix.020_010", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_020, { "020, Target Report Descriptor", "asterix.020_020", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_020_SSR, { "SSR", "asterix.020_020_SSR", FT_UINT8, BASE_DEC, VALS (valstr_020_020_SSR), 0x80, NULL, HFILL } },
        { &hf_020_020_MS, { "MS", "asterix.020_020_MS", FT_UINT8, BASE_DEC, VALS (valstr_020_020_MS), 0x40, NULL, HFILL } },
        { &hf_020_020_HF, { "HF", "asterix.020_020_HF", FT_UINT8, BASE_DEC, VALS (valstr_020_020_HF), 0x20, NULL, HFILL } },
        { &hf_020_020_VDL4, { "VDL4", "asterix.020_020_VDL4", FT_UINT8, BASE_DEC, VALS (valstr_020_020_VDL4), 0x10, NULL, HFILL } },
        { &hf_020_020_UAT, { "UAT", "asterix.020_020_UAT", FT_UINT8, BASE_DEC, VALS (valstr_020_020_UAT), 0x08, NULL, HFILL } },
        { &hf_020_020_DME, { "DME", "asterix.020_020_DME", FT_UINT8, BASE_DEC, VALS (valstr_020_020_DME), 0x04, NULL, HFILL } },
        { &hf_020_020_OT, { "OT", "asterix.020_020_OT", FT_UINT8, BASE_DEC, VALS (valstr_020_020_OT), 0x02, NULL, HFILL } },
        { &hf_020_020_RAB, { "RAB", "asterix.020_020_RAB", FT_UINT8, BASE_DEC, VALS (valstr_020_020_RAB), 0x80, NULL, HFILL } },
        { &hf_020_020_SPI, { "SPI", "asterix.020_020_SPI", FT_UINT8, BASE_DEC, VALS (valstr_020_020_SPI), 0x40, NULL, HFILL } },
        { &hf_020_020_CHN, { "CHN", "asterix.020_020_CHN", FT_UINT8, BASE_DEC, VALS (valstr_020_020_CHN), 0x20, NULL, HFILL } },
        { &hf_020_020_GBS, { "GBS", "asterix.020_020_GBS", FT_UINT8, BASE_DEC, VALS (valstr_020_020_GBS), 0x10, NULL, HFILL } },
        { &hf_020_020_CRT, { "CRT", "asterix.020_020_CRT", FT_UINT8, BASE_DEC, VALS (valstr_020_020_CRT), 0x08, NULL, HFILL } },
        { &hf_020_020_SIM, { "SIM", "asterix.020_020_SIM", FT_UINT8, BASE_DEC, VALS (valstr_020_020_SIM), 0x04, NULL, HFILL } },
        { &hf_020_020_TST, { "TST", "asterix.020_020_TST", FT_UINT8, BASE_DEC, VALS (valstr_020_020_TST), 0x02, NULL, HFILL } },
        { &hf_020_030, { "030, Warning/Error Conditions", "asterix.020_030", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_030_WE, { "WE", "asterix.020_030_WE", FT_UINT8, BASE_DEC, VALS (valstr_020_030_WE), 0xfe, NULL, HFILL } },
        { &hf_020_041, { "041, Position in WGS-84 Coordinates", "asterix.020_041", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_041_LAT, { "Latitude in WGS-84 [deg]", "asterix.020_041_LAT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_041_LON, { "Longitude in WGS-84 [deg]", "asterix.020_041_LON", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_042, { "042, Position in Cartesian Coordinates", "asterix.020_042", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_042_X, { "X [m]", "asterix.020_042_X", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_042_Y, { "Y [m]", "asterix.020_042_Y", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_050, { "050, Mode-2 Code in Octal Representation", "asterix.020_050", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_050_V, { "V", "asterix.020_050_V", FT_UINT16, BASE_DEC, VALS (valstr_020_050_V), 0x8000, NULL, HFILL } },
        { &hf_020_050_G, { "G", "asterix.020_050_G", FT_UINT16, BASE_DEC, VALS (valstr_020_050_G), 0x4000, NULL, HFILL } },
        { &hf_020_050_L, { "L", "asterix.020_050_L", FT_UINT16, BASE_DEC, VALS (valstr_020_050_L), 0x2000, NULL, HFILL } },
        { &hf_020_050_SQUAWK, { "SQUAWK", "asterix.020_050_SQUAWK", FT_UINT16, BASE_OCT, NULL, 0x0fff, NULL, HFILL } },
        { &hf_020_055, { "055, Mode-1 Code in Octal Representation", "asterix.020_055", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_055_V, { "V", "asterix.020_055_V", FT_UINT8, BASE_DEC, VALS (valstr_020_055_V), 0x80, NULL, HFILL } },
        { &hf_020_055_G, { "G", "asterix.020_055_G", FT_UINT8, BASE_DEC, VALS (valstr_020_055_G), 0x40, NULL, HFILL } },
        { &hf_020_055_L, { "L", "asterix.020_055_L", FT_UINT8, BASE_DEC, VALS (valstr_020_055_L), 0x20, NULL, HFILL } },
        { &hf_020_055_A, { "A", "asterix.020_055_A", FT_UINT8, BASE_OCT, NULL, 0x1c, NULL, HFILL } },
        { &hf_020_055_B, { "B", "asterix.020_055_B", FT_UINT8, BASE_OCT, NULL, 0x03, NULL, HFILL } },
        { &hf_020_070, { "070, Mode-3/A Code in Octal Representation", "asterix.020_070", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_070_V, { "V", "asterix.020_070_V", FT_UINT16, BASE_DEC, VALS (valstr_020_070_V), 0x8000, NULL, HFILL } },
        { &hf_020_070_G, { "G", "asterix.020_070_G", FT_UINT16, BASE_DEC, VALS (valstr_020_070_G), 0x4000, NULL, HFILL } },
        { &hf_020_070_L, { "L", "asterix.020_070_L", FT_UINT16, BASE_DEC, VALS (valstr_020_070_L), 0x2000, NULL, HFILL } },
        { &hf_020_070_SQUAWK, { "SQUAWK", "asterix.020_070_SQUAWK", FT_UINT16, BASE_OCT, NULL, 0x0fff, NULL, HFILL } },
        { &hf_020_090, { "090, Flight Level in Binary Representation", "asterix.020_090", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_090_V, { "V", "asterix.020_090_V", FT_UINT16, BASE_DEC, VALS (valstr_020_090_V), 0x8000, NULL, HFILL } },
        { &hf_020_090_G, { "G", "asterix.020_090_G", FT_UINT16, BASE_DEC, VALS (valstr_020_090_G), 0x4000, NULL, HFILL } },
        { &hf_020_090_FL, { "FL", "asterix.020_090_FL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_100, { "100, Mode-C Code", "asterix.020_100", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_100_V, { "V", "asterix.020_100_V", FT_UINT32, BASE_DEC, VALS (valstr_020_100_V), 0x80000000, NULL, HFILL } },
        { &hf_020_100_G, { "G", "asterix.020_100_G", FT_UINT32, BASE_DEC, VALS (valstr_020_100_G), 0x40000000, NULL, HFILL } },
        { &hf_020_100_C1, { "C1", "asterix.020_100_C1", FT_UINT32, BASE_DEC, NULL, 0x08000000, NULL, HFILL } },
        { &hf_020_100_A1, { "A1", "asterix.020_100_A1", FT_UINT32, BASE_DEC, NULL, 0x04000000, NULL, HFILL } },
        { &hf_020_100_C2, { "C2", "asterix.020_100_C2", FT_UINT32, BASE_DEC, NULL, 0x02000000, NULL, HFILL } },
        { &hf_020_100_A2, { "A2", "asterix.020_100_A2", FT_UINT32, BASE_DEC, NULL, 0x01000000, NULL, HFILL } },
        { &hf_020_100_C4, { "C4", "asterix.020_100_C4", FT_UINT32, BASE_DEC, NULL, 0x00800000, NULL, HFILL } },
        { &hf_020_100_A4, { "A4", "asterix.020_100_A4", FT_UINT32, BASE_DEC, NULL, 0x00400000, NULL, HFILL } },
        { &hf_020_100_B1, { "B1", "asterix.020_100_B1", FT_UINT32, BASE_DEC, NULL, 0x00200000, NULL, HFILL } },
        { &hf_020_100_D1, { "D1", "asterix.020_100_D1", FT_UINT32, BASE_DEC, NULL, 0x00100000, NULL, HFILL } },
        { &hf_020_100_B2, { "B2", "asterix.020_100_B2", FT_UINT32, BASE_DEC, NULL, 0x00080000, NULL, HFILL } },
        { &hf_020_100_D2, { "D2", "asterix.020_100_D2", FT_UINT32, BASE_DEC, NULL, 0x00040000, NULL, HFILL } },
        { &hf_020_100_B4, { "B4", "asterix.020_100_B4", FT_UINT32, BASE_DEC, NULL, 0x00020000, NULL, HFILL } },
        { &hf_020_100_D4, { "D4", "asterix.020_100_D4", FT_UINT32, BASE_DEC, NULL, 0x00010000, NULL, HFILL } },
        { &hf_020_100_QC1, { "QC1", "asterix.020_100_QC1", FT_UINT32, BASE_DEC, VALS (valstr_020_100_QA), 0x00000800, NULL, HFILL } },
        { &hf_020_100_QA1, { "QA1", "asterix.020_100_QA1", FT_UINT32, BASE_DEC, VALS (valstr_020_100_QA), 0x00000400, NULL, HFILL } },
        { &hf_020_100_QC2, { "QC2", "asterix.020_100_QC2", FT_UINT32, BASE_DEC, VALS (valstr_020_100_QA), 0x00000200, NULL, HFILL } },
        { &hf_020_100_QA2, { "QA2", "asterix.020_100_QA2", FT_UINT32, BASE_DEC, VALS (valstr_020_100_QA), 0x00000100, NULL, HFILL } },
        { &hf_020_100_QC4, { "QC4", "asterix.020_100_QC4", FT_UINT32, BASE_DEC, VALS (valstr_020_100_QA), 0x00000080, NULL, HFILL } },
        { &hf_020_100_QA4, { "QA4", "asterix.020_100_QA4", FT_UINT32, BASE_DEC, VALS (valstr_020_100_QA), 0x00000040, NULL, HFILL } },
        { &hf_020_100_QB1, { "QB1", "asterix.020_100_QB1", FT_UINT32, BASE_DEC, VALS (valstr_020_100_QA), 0x00000020, NULL, HFILL } },
        { &hf_020_100_QD1, { "QD1", "asterix.020_100_QD1", FT_UINT32, BASE_DEC, VALS (valstr_020_100_QA), 0x00000010, NULL, HFILL } },
        { &hf_020_100_QB2, { "QB2", "asterix.020_100_QB2", FT_UINT32, BASE_DEC, VALS (valstr_020_100_QA), 0x00000008, NULL, HFILL } },
        { &hf_020_100_QD2, { "2D2", "asterix.020_100_QD2", FT_UINT32, BASE_DEC, VALS (valstr_020_100_QA), 0x00000004, NULL, HFILL } },
        { &hf_020_100_QB4, { "QB4", "asterix.020_100_QB4", FT_UINT32, BASE_DEC, VALS (valstr_020_100_QA), 0x00000002, NULL, HFILL } },
        { &hf_020_100_QD4, { "QD4", "asterix.020_100_QD4", FT_UINT32, BASE_DEC, VALS (valstr_020_100_QA), 0x00000001, NULL, HFILL } },
        { &hf_020_105, { "105, Geometric Height (WGS-84)", "asterix.020_105", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_105_GH, { "GH [ft]", "asterix.020_105_GH", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_110, { "110, Measured Height (Local Cartesian Coordinates)", "asterix.020_110", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_110_MH, { "MH [ft]", "asterix.020_110_MH", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_140, { "140, Time of Day", "asterix.020_140", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_161, { "161, Track Number", "asterix.020_161", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_161_TN, { "TN", "asterix.020_161_TN", FT_UINT16, BASE_DEC, NULL, 0x0fff, NULL, HFILL } },
        { &hf_020_170, { "170, Track Status", "asterix.020_170", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_170_CNF, { "CNF", "asterix.020_170_CNF", FT_UINT8, BASE_DEC, VALS (valstr_020_170_CNF), 0x80, NULL, HFILL } },
        { &hf_020_170_TRE, { "TRE", "asterix.020_170_TRE", FT_UINT8, BASE_DEC, VALS (valstr_020_170_TRE), 0x40, NULL, HFILL } },
        { &hf_020_170_CST, { "CST", "asterix.020_170_CST", FT_UINT8, BASE_DEC, VALS (valstr_020_170_CST), 0x20, NULL, HFILL } },
        { &hf_020_170_CDM, { "CDM", "asterix.020_170_CDM", FT_UINT8, BASE_DEC, VALS (valstr_020_170_CDM), 0x18, NULL, HFILL } },
        { &hf_020_170_MAH, { "MAH", "asterix.020_170_MAH", FT_UINT8, BASE_DEC, VALS (valstr_020_170_MAH), 0x04, NULL, HFILL } },
        { &hf_020_170_STH, { "STH", "asterix.020_170_STH", FT_UINT8, BASE_DEC, VALS (valstr_020_170_STH), 0x02, NULL, HFILL } },
        { &hf_020_170_GHO, { "GHO", "asterix.020_170_GHO", FT_UINT8, BASE_DEC, VALS (valstr_020_170_GHO), 0x80, NULL, HFILL } },
        { &hf_020_202, { "202, Calculated Track Velocity in Cartesian Coordinates", "asterix.020_202", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_202_VX, { "VX [m/s]", "asterix.020_202_VX", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_202_VY, { "VX [m/s]", "asterix.020_202_VY", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_210, { "210, Calculated Acceleration", "asterix.020_210", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_210_AX, { "AX [m/s^2]", "asterix.020_210_AX", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_210_AY, { "AY [m/s^2]", "asterix.020_210_AY", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_220, { "220, Target Address", "asterix.020_220", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_230, { "230, Communications/ACAS Capability and Flight Status", "asterix.020_230", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_230_COM, { "COM", "asterix.020_230_COM", FT_UINT16, BASE_DEC, VALS (valstr_020_230_COM), 0xe000, NULL, HFILL } },
        { &hf_020_230_STAT, { "STAT", "asterix.020_230_STAT", FT_UINT16, BASE_DEC, VALS (valstr_020_230_STAT), 0x1c00, NULL, HFILL } },
        { &hf_020_230_MSSC, { "MSSC", "asterix.020_230_MSSC", FT_UINT16, BASE_DEC, VALS (valstr_020_230_MSSC), 0x0080, NULL, HFILL } },
        { &hf_020_230_ARC, { "ARC", "asterix.020_230_ARC", FT_UINT16, BASE_DEC, VALS (valstr_020_230_ARC), 0x0040, NULL, HFILL } },
        { &hf_020_230_AIC, { "AIC", "asterix.020_230_AIC", FT_UINT16, BASE_DEC, VALS (valstr_020_230_AIC), 0x0020, NULL, HFILL } },
        { &hf_020_230_B1A, { "B1A", "asterix.020_230_B1A", FT_UINT16, BASE_DEC, NULL, 0x0010, NULL, HFILL } },
        { &hf_020_230_B1B, { "B1B", "asterix.020_230_B1B", FT_UINT16, BASE_DEC, NULL, 0x000f, NULL, HFILL } },
        { &hf_020_245, { "245, Target Identification", "asterix.020_245", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_245_STI, { "STI", "asterix.020_245_STI", FT_UINT8, BASE_DEC, VALS (valstr_020_245_STI), 0xc0, NULL, HFILL } },
        { &hf_020_250, { "250, Mode S MB Data", "asterix.020_250", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_260, { "260, ACAS Resolution Advisory Report", "asterix.020_260", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_300, { "300, Vehicle Fleet Identification", "asterix.020_300", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_300_VFI, { "VFI", "asterix.020_300_VFI", FT_UINT8, BASE_DEC, VALS (valstr_020_300_VFI), 0x0, NULL, HFILL } },
        { &hf_020_310, { "310, Pre-programmed Message", "asterix.020_310", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_310_TRB, { "TRB", "asterix.020_310_TRB", FT_UINT8, BASE_DEC, VALS (valstr_020_310_TRB), 0x80, NULL, HFILL } },
        { &hf_020_310_MSG, { "MSG", "asterix.020_310_MSG", FT_UINT8, BASE_DEC, VALS (valstr_020_310_MSG), 0x7f, NULL, HFILL } },
        { &hf_020_400, { "400, Contributing Devices", "asterix.020_400", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_400_TU8RU8, { "TU8RU8", "asterix.020_400_TU8RU8", FT_UINT8, BASE_DEC, VALS (valstr_020_400_TUxRUx), 0x80, NULL, HFILL } },
        { &hf_020_400_TU7RU7, { "TU7RU7", "asterix.020_400_TU7RU7", FT_UINT8, BASE_DEC, VALS (valstr_020_400_TUxRUx), 0x40, NULL, HFILL } },
        { &hf_020_400_TU6RU6, { "TU6RU6", "asterix.020_400_TU6RU6", FT_UINT8, BASE_DEC, VALS (valstr_020_400_TUxRUx), 0x20, NULL, HFILL } },
        { &hf_020_400_TU5RU5, { "TU5RU5", "asterix.020_400_TU5RU5", FT_UINT8, BASE_DEC, VALS (valstr_020_400_TUxRUx), 0x10, NULL, HFILL } },
        { &hf_020_400_TU4RU4, { "TU4RU4", "asterix.020_400_TU4RU4", FT_UINT8, BASE_DEC, VALS (valstr_020_400_TUxRUx), 0x08, NULL, HFILL } },
        { &hf_020_400_TU3RU3, { "TU3RU3", "asterix.020_400_TU3RU3", FT_UINT8, BASE_DEC, VALS (valstr_020_400_TUxRUx), 0x04, NULL, HFILL } },
        { &hf_020_400_TU2RU2, { "TU2RU2", "asterix.020_400_TU2RU2", FT_UINT8, BASE_DEC, VALS (valstr_020_400_TUxRUx), 0x02, NULL, HFILL } },
        { &hf_020_400_TU1RU1, { "TU1RU1", "asterix.020_400_TU1RU1", FT_UINT8, BASE_DEC, VALS (valstr_020_400_TUxRUx), 0x01, NULL, HFILL } },
        { &hf_020_500, { "500, Position Accuracy", "asterix.020_500", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_500_01, { "#01: DOP of Position", "asterix.020_500_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_500_01_DOPx, { "DOPx", "asterix.020_500_01_DOPx", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_500_01_DOPy, { "DOPy", "asterix.020_500_01_DOPy", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_500_01_DOPxy, { "DOPxy", "asterix.020_500_01_DOPxy", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_500_02, { "#02: Standard Deviation of Position", "asterix.020_500_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_500_02_SDPx, { "SDPx [m]", "asterix.020_500_02_SDPx", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_500_02_SDPy, { "SDPy [m]", "asterix.020_500_02_SDPy", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_500_02_SDPxy, { "SDPxy", "asterix.020_500_02_SDPxy", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_500_03, { "#03: Standard Deviation of Geometric Height", "asterix.020_500_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_500_03_SDH, { "SDH [m]", "asterix.020_500_03_SDH", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE, { "Reserved Field", "asterix.020_RE", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_PA, { "Position Accuracy", "asterix.020_RE_PA", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_PA_01, { "#1: DOP of Position", "asterix.020_RE_PA_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_PA_01_DOPx, { "DOPx", "asterix.020_RE_PA_01_DOPx", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_PA_01_DOPy, { "DOPy", "asterix.020_RE_PA_01_DOPy", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_PA_01_DOPxy, { "DOPxy", "asterix.020_RE_PA_01_DOPxy", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_PA_02, { "#2: Standard Deviation of Position (Cartesian)", "asterix.020_RE_PA_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_PA_02_SDCx, { "SDCx [m]", "asterix.020_RE_PA_02_SDCx", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_PA_02_SDCy, { "SDCy [m]", "asterix.020_RE_PA_02_SDCy", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_PA_02_SDCxy, { "SDCxy", "asterix.020_RE_PA_02_SDCxy", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_PA_03, { "#3: Standard Deviation of Geometric Height", "asterix.020_RE_PA_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_PA_03_SDH, { "SDH [ft]", "asterix.020_RE_PA_03_SDH", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_PA_04, { "#4: Standard Deviation of Position (WGS-84)", "asterix.020_RE_PA_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_PA_04_LAT, { "LAT [deg]", "asterix.020_RE_PA_04_LAT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_PA_04_LON, { "LON [deg]", "asterix.020_RE_PA_04_LON", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_PA_04_COV, { "COV", "asterix.020_RE_PA_04_COV", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_GVV, { "Ground Velocity Vector", "asterix.020_RE_GVV", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_GVV_RE, { "RE", "asterix.020_RE_GVV_RE", FT_UINT16, BASE_DEC, VALS (valstr_020_RE_GVV_RE), 0x8000, NULL, HFILL } },
        { &hf_020_RE_GVV_GS, { "GS [NM/s]", "asterix.020_RE_GVV_GS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_GVV_TA, { "TA [deg]", "asterix.020_RE_GVV_TA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_GVA, { "Ground Velocity Accuracy", "asterix.020_RE_GVA", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_GVA_GSSD, { "GSSD [NM/s]", "asterix.020_RE_GVA_GSSD", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_GVA_TASD, { "TASD [deg]", "asterix.020_RE_GVA_TASD", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_TRT, { "Time of ASTERIX Report Transmission", "asterix.020_RE_TRT", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA, { "Data-Ages", "asterix.020_RE_DA", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_01, { "#1:Special Position Identification age", "asterix.020_RE_DA_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_01_SPI, { "SPI [s]", "asterix.020_RE_DA_01_SPI", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_02, { "#2: Target Identification age", "asterix.020_RE_DA_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_02_TI, { "TI [s]", "asterix.020_RE_DA_02_TI", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_03, { "#3: Mode S MB age", "asterix.020_RE_DA_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_03_BDS1, { "BDS1", "asterix.020_RE_DA_03_BDS1", FT_UINT16, BASE_DEC, NULL, 0xf000, NULL, HFILL } },
        { &hf_020_RE_DA_03_BDS2, { "BDS2", "asterix.020_RE_DA_03_BDS2", FT_UINT16, BASE_DEC, NULL, 0x0f00, NULL, HFILL } },
        { &hf_020_RE_DA_03_MBA, { "MBA [s]", "asterix.020_RE_DA_03_MBA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_04, { "#4: Mode 3/A Code age", "asterix.020_RE_DA_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_04_M3A, { "M3A [s]", "asterix.020_RE_DA_04_M3A", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_05, { "#5: Flight Level age", "asterix.020_RE_DA_05", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_05_FL, { "FL [s]", "asterix.020_RE_DA_05_FL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_06, { "#6: Flight Status age", "asterix.020_RE_DA_06", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_06_STAT, { "STAT [s]", "asterix.020_RE_DA_06_STAT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_07, { "#7: Geometric / Measured Height age", "asterix.020_RE_DA_07", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_07_GH, { "GH [s]", "asterix.020_RE_DA_07_GH", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_08, { "#8: Target Address age", "asterix.020_RE_DA_08", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_08_TA, { "TA [s]", "asterix.020_RE_DA_08_TA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_09, { "#9: Mode C code age", "asterix.020_RE_DA_09", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_09_MC, { "MC [s]", "asterix.020_RE_DA_09_MC", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_10, { "#10: Mode-S Specific Service Capability age", "asterix.020_RE_DA_10", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_10_MSSC, { "10 [s]", "asterix.020_RE_DA_10_MSSC", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_11, { "#11: Altitude reporting capability age", "asterix.020_RE_DA_11", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_11_ARC, { "ARC [s]", "asterix.020_RE_DA_11_ARC", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_12, { "#12: Aircraft identification capability age", "asterix.020_RE_DA_12", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_12_AIC, { "AIC [s]", "asterix.020_RE_DA_12_AIC", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_13, { "#13: Mode-2 Code age", "asterix.020_RE_DA_13", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_13_M2, { "M2 [s]", "asterix.020_RE_DA_13_M2", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_14, { "#14: Mode-1 Code age", "asterix.020_RE_DA_14", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_14_M1, { "M1 [s]", "asterix.020_RE_DA_14_M1", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_15, { "#15: ACAS Resolution Advisory age", "asterix.020_RE_DA_15", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_15_ARA, { "ARA [s]", "asterix.020_RE_DA_15_ARA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_16, { "#16: Vehicle Fleet Identification age", "asterix.020_RE_DA_16", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_16_VI, { "VI [s]", "asterix.020_RE_DA_16_VI", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_17, { "#17: Pre-programmed message age", "asterix.020_RE_DA_17", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_RE_DA_17_MSG, { "MSG [s]", "asterix.020_RE_DA_17_MSG", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_020_SP, { "Special Field", "asterix.020_SP", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        /* Category 021 */
        { &hf_021_008, { "008, Aircraft Operational Status", "asterix.021_008", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_008_RA, { "RA", "asterix.021_008_RA", FT_UINT8, BASE_DEC, VALS (valstr_021_008_RA), 0x80, NULL, HFILL } },
        { &hf_021_008_TC, { "TC", "asterix.021_008_TC", FT_UINT8, BASE_DEC, VALS (valstr_021_008_TC), 0x60, NULL, HFILL } },
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
        { &hf_021_020_v0_2_ECAT, { "ECAT", "asterix.021_020_ECAT", FT_UINT8, BASE_DEC, VALS (valstr_021_020_v0_2_ECAT), 0x0, NULL, HFILL } },
        { &hf_021_030, { "030, Time of Day", "asterix.021_030", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_032, { "032, Time of Day Accuracy", "asterix.021_032", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_032_TODA, { "TODA", "asterix.021_032_TODA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_040, { "040, Target Report Descriptor", "asterix.021_040", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_040_ATP, { "ATP", "asterix.021_040_ATP", FT_UINT8, BASE_DEC, VALS (valstr_021_040_ATP), 0xe0, NULL, HFILL } },
        { &hf_021_040_v0_2_ATP, { "ATP", "asterix.021_040_ATP", FT_UINT8, BASE_DEC, VALS (valstr_021_040_v0_2_ATP), 0xe0, NULL, HFILL } },
        { &hf_021_040_ARC, { "ARC", "asterix.021_040_ARC", FT_UINT8, BASE_DEC, VALS (valstr_021_040_ARC), 0x18, NULL, HFILL } },
        { &hf_021_040_v0_2_ARC, { "ARC", "asterix.021_040_ARC", FT_UINT8, BASE_DEC, VALS (valstr_021_040_v0_2_ARC), 0x18, NULL, HFILL } },
        { &hf_021_040_RC, { "RC", "asterix.021_040_RC", FT_UINT8, BASE_DEC, VALS (valstr_021_040_RC), 0x04, NULL, HFILL } },
        { &hf_021_040_RAB, { "RAB", "asterix.021_040_RAB", FT_UINT8, BASE_DEC, VALS (valstr_021_040_RAB), 0x02, NULL, HFILL } },
        { &hf_021_040_v0_2_RAB, { "RAB", "asterix.021_040_RAB", FT_UINT8, BASE_DEC, VALS (valstr_021_040_RAB), 0x08, NULL, HFILL } },
        { &hf_021_040_DCR, { "DCR", "asterix.021_040_DCR", FT_UINT8, BASE_DEC, VALS (valstr_021_040_DCR), 0x80, NULL, HFILL } },
        { &hf_021_040_GBS, { "GBS", "asterix.021_040_GBS", FT_UINT8, BASE_DEC, VALS (valstr_021_040_GBS), 0x40, NULL, HFILL } },
        { &hf_021_040_SIM, { "SIM", "asterix.021_040_SIM", FT_UINT8, BASE_DEC, VALS (valstr_021_040_SIM), 0x20, NULL, HFILL } },
        { &hf_021_040_TST, { "TST", "asterix.021_040_TST", FT_UINT8, BASE_DEC, VALS (valstr_021_040_TST), 0x10, NULL, HFILL } },
        { &hf_021_040_SAA, { "SAA", "asterix.021_040_SAA", FT_UINT8, BASE_DEC, VALS (valstr_021_040_SAA), 0x08, NULL, HFILL } },
        { &hf_021_040_v0_2_SAA, { "SAA", "asterix.021_040_SAA", FT_UINT8, BASE_DEC, VALS (valstr_021_040_SAA), 0x04, NULL, HFILL } },
        { &hf_021_040_SPI, { "SPI", "asterix.021_040_SPI", FT_UINT8, BASE_DEC, VALS (valstr_021_040_SPI), 0x02, NULL, HFILL } },
        { &hf_021_040_CL, { "CL", "asterix.021_040_CL", FT_UINT8, BASE_DEC, VALS (valstr_021_040_CL), 0x06, NULL, HFILL } },
        { &hf_021_040_LLC, { "LLC", "asterix.021_040_LLC", FT_UINT8, BASE_DEC, VALS (valstr_021_040_LLC), 0x40, NULL, HFILL } },
        { &hf_021_040_IPC, { "IPC", "asterix.021_040_IPC", FT_UINT8, BASE_DEC, VALS (valstr_021_040_IPC), 0x20, NULL, HFILL } },
        { &hf_021_040_NOGO, { "NOGO", "asterix.021_040_NOGO", FT_UINT8, BASE_DEC, VALS (valstr_021_040_NOGO), 0x10, NULL, HFILL } },
        { &hf_021_040_CPR, { "CPR", "asterix.021_040_CPR", FT_UINT8, BASE_DEC, VALS (valstr_021_040_CPR), 0x08, NULL, HFILL } },
        { &hf_021_040_LDPJ, { "LDPJ", "asterix.021_040_LDPJ", FT_UINT8, BASE_DEC, VALS (valstr_021_040_LDPJ), 0x04, NULL, HFILL } },
        { &hf_021_040_RCF, { "RCF", "asterix.021_040_RCF", FT_UINT8, BASE_DEC, VALS (valstr_021_040_RCF), 0x02, NULL, HFILL } },
        { &hf_021_070, { "070, Mode 3/A Code in Octal Representation", "asterix.021_070", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_070_V, { "V", "asterix.021_070_V", FT_UINT8, BASE_DEC, VALS (valstr_021_070_V), 0x80, NULL, HFILL } },
        { &hf_021_070_G, { "G", "asterix.021_070_G", FT_UINT8, BASE_DEC, VALS (valstr_021_070_G), 0x40, NULL, HFILL } },
        { &hf_021_070_L, { "L", "asterix.021_070_L", FT_UINT8, BASE_DEC, VALS (valstr_021_070_L), 0x20, NULL, HFILL } },
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
        { &hf_021_090_v0_2, { "090, Figure of Merit", "asterix.021_090", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_090_NUCR_NACV, { "NUCr or NACv", "asterix.021_090_NUCR_NACV", FT_UINT8, BASE_DEC, NULL, 0xe0, NULL, HFILL } },
        { &hf_021_090_NUCP_NIC, { "NUCp or NIC", "asterix.021_090_NUCP_NIC", FT_UINT8, BASE_DEC, NULL, 0x1e, NULL, HFILL } },
        { &hf_021_090_NIC_BARO, { "NIC BARO", "asterix.021_090_NIC_BARO", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL } },
        { &hf_021_090_SIL, { "SIL", "asterix.021_090_SIL", FT_UINT8, BASE_DEC, NULL, 0x60, NULL, HFILL } },
        { &hf_021_090_NACP, { "NACP", "asterix.021_090_NACP", FT_UINT8, BASE_DEC, NULL, 0x1e, NULL, HFILL } },
        { &hf_021_090_SILS, { "SILS", "asterix.021_090_SILS", FT_UINT8, BASE_DEC, VALS (valstr_021_090_SILS), 0x20, NULL, HFILL } },
        { &hf_021_090_SDA, { "SDA", "asterix.021_090_SDA", FT_UINT8, BASE_DEC, NULL, 0x18, NULL, HFILL } },
        { &hf_021_090_GVA, { "GVA", "asterix.021_090_GVA", FT_UINT8, BASE_DEC, NULL, 0x06, NULL, HFILL } },
        { &hf_021_090_PIC, { "PIC", "asterix.021_090_PIC", FT_UINT8, BASE_DEC, NULL, 0xf0, NULL, HFILL } },
        { &hf_021_090_AC, { "AC", "asterix.021_090_AC", FT_UINT8, BASE_DEC, VALS (valstr_021_090_AC), 0xc0, NULL, HFILL } },
        { &hf_021_090_MN, { "MN", "asterix.021_090_MN", FT_UINT8, BASE_DEC, VALS (valstr_021_090_MN), 0x30, NULL, HFILL } },
        { &hf_021_090_DC, { "DC", "asterix.021_090_DC", FT_UINT8, BASE_DEC, VALS (valstr_021_090_DC), 0x0c, NULL, HFILL } },
        { &hf_021_090_PA, { "PA", "asterix.021_090_PA", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_021_095, {"095, Velocity Accuracy", "asterix.021_095", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_095_VUC, { "VUC", "asterix.021_095_VUC", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_110, { "110, Trajectory Intent", "asterix.021_110", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_110_01, { "#01: Trajectory Intent Status", "asterix.021_110_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_110_01_NAV, { "NAV", "asterix.021_110_01_NAV", FT_UINT8, BASE_DEC, VALS (valstr_021_110_01_NAV), 0x80, NULL, HFILL } },
        { &hf_021_110_01_NVB, { "NVB", "asterix.021_110_01_NVB", FT_UINT8, BASE_DEC, VALS (valstr_021_110_01_NVB), 0x40, NULL, HFILL } },
        { &hf_021_110_02, { "#02: Trajectory Intent Data", "asterix.021_110_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_110_02_TCA, { "TCA", "asterix.021_110_02_TCA", FT_UINT8, BASE_DEC, VALS (valstr_021_110_02_TCA), 0x80, NULL, HFILL } },
        { &hf_021_110_02_NC, { "NC", "asterix.021_110_02_NC", FT_UINT8, BASE_DEC, VALS (valstr_021_110_02_NC), 0x40, NULL, HFILL } },
        { &hf_021_110_02_TCPNo, { "TCP number", "asterix.021_110_02_TCPNo", FT_UINT8, BASE_DEC, NULL, 0x3f, NULL, HFILL } },
        { &hf_021_110_02_ALT, { "Altitude [ft]", "asterix.021_110_02_ALT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_110_02_LAT, { "Latitude [deg]", "asterix.021_110_02_LAT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_110_02_LON, { "Longitude [deg]", "asterix.021_110_02_LON", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_110_02_PT, { "PT", "asterix.021_110_02_PT", FT_UINT8, BASE_DEC, VALS (valstr_021_110_02_PT), 0xf0, NULL, HFILL } },
        { &hf_021_110_02_TD, { "TD", "asterix.021_110_02_TD", FT_UINT8, BASE_DEC, VALS (valstr_021_110_02_TD), 0x0c, NULL, HFILL } },
        { &hf_021_110_02_TRA, { "TRA", "asterix.021_110_02_TRA", FT_UINT8, BASE_DEC, VALS (valstr_021_110_02_TRA), 0x02, NULL, HFILL } },
        { &hf_021_110_02_TOA, { "TOA", "asterix.021_110_02_TOA", FT_UINT8, BASE_DEC, VALS (valstr_021_110_02_TOA), 0x01, NULL, HFILL } },
        { &hf_021_110_02_TOV, { "Time Over Point [s]", "asterix.021_110_02_TOV", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_110_02_TTR, { "TCP Turn radius [Nm]", "asterix.021_110_02_TTR", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_130, { "130, Position in WGS-84 Co-ordinates", "asterix.021_130", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_130_LAT, { "Latitude [deg]", "asterix.021_130_LAT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_130_LON, { "Longitude [deg]", "asterix.021_130_LON", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_131, { "131, High-Resolution Position in WGS-84 Co-ordinates", "asterix.021_131", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_131_v0_2, {"131, Signal Amplitude", "asterix.021_131", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL} },
        { &hf_021_131_LAT, { "Latitude [deg]", "asterix.021_131_LAT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_131_LON, { "Longitude [deg]", "asterix.021_131_LON", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_131_SAM, { "SAM", "asterix.021_131_SAM", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_132, { "132, Message Amplitude", "asterix.021_132", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_132_MAM, { "MAM [dBm]", "asterix.021_132_MAM", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_140, { "140, Geometric Height", "asterix.021_140", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_140_v0_2, {"140, Geometric Altitude", "asterix.021_140", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_140_GH, { "GH [ft]", "asterix.021_140_GH", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_140_ALT, { "AL [ft]", "asterix.021_140_AL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_145, { "145, Flight Level", "asterix.021_145", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_145_FL, { "FL", "asterix.021_145_FL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_146, { "146, Selected Altitude", "asterix.021_146", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_146_v0_2, { "146, Intermediate State Selected Altitude", "asterix.021_146", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_146_SAS, { "SAS", "asterix.021_146_SAS", FT_UINT8, BASE_DEC, VALS (valstr_021_146_SAS), 0x80, NULL, HFILL } },
        { &hf_021_146_Source, { "Source", "asterix.021_146_Source", FT_UINT8, BASE_DEC, VALS (valstr_021_146_Source), 0x60, NULL, HFILL } },
        { &hf_021_146_v0_2_Source, { "Source", "asterix.021_146_Source", FT_UINT8, BASE_DEC, VALS(valstr_021_146_v0_2_Source), 0x60, NULL, HFILL } },
        { &hf_021_146_ALT, { "Altitude [ft]", "asterix.021_146_ALT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_148, { "148, Final State Selected Altitude", "asterix.021_148", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_148_MV, { "MV", "asterix.021_148_MV", FT_UINT8, BASE_DEC, VALS (valstr_021_148_MV), 0x80, NULL, HFILL } },
        { &hf_021_148_v0_2_MV, { "MV", "asterix.021_148_MV", FT_UINT8, BASE_DEC, VALS (valstr_021_148_v0_2_MV), 0x80, NULL, HFILL } },
        { &hf_021_148_AH, { "AH", "asterix.021_148_AH", FT_UINT8, BASE_DEC, VALS (valstr_021_148_AH), 0x40, NULL, HFILL } },
        { &hf_021_148_v0_2_AH, { "AH", "asterix.021_148_AH", FT_UINT8, BASE_DEC, VALS (valstr_021_148_v0_2_AH), 0x40, NULL, HFILL } },
        { &hf_021_148_AM, { "AM", "asterix.021_148_AM", FT_UINT8, BASE_DEC, VALS (valstr_021_148_AM), 0x20, NULL, HFILL } },
        { &hf_021_148_v0_2_AM, { "AM", "asterix.021_148_AM", FT_UINT8, BASE_DEC, VALS (valstr_021_148_v0_2_AM), 0x20, NULL, HFILL } },
        { &hf_021_148_ALT, { "Altitude [ft]", "asterix.021_148_ALT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_150, { "150, Air Speed", "asterix.021_150", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_150_IM, { "IM", "asterix.021_150_IM", FT_UINT8, BASE_DEC, VALS (valstr_021_150_IM), 0x80, NULL, HFILL } },
        { &hf_021_150_ASPD, { "ASPD [IAS (0) => NM/s or IAS (1) => Mach]", "asterix.021_150_ASPD", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
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
        { &hf_021_160_v0_2, { "160, Ground Vector", "asterix.021_160", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_160_RE, { "RE", "asterix.021_160_RE", FT_UINT8, BASE_DEC, VALS (valstr_021_160_RE), 0x80, NULL, HFILL } },
        { &hf_021_160_GSPD, { "Ground speed [NM/s]", "asterix.021_160_GSPD", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_160_TA, { "Track angle [deg]", "asterix.021_160_TA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_161, { "161, Track Number", "asterix.021_161", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_161_TN, { "TN", "asterix.021_161_TN", FT_UINT8, BASE_DEC, NULL, 0x0fff, NULL, HFILL } },
        { &hf_021_165, { "165, Track Angle Rate", "asterix.021_165", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_165_v0_2, { "165, Rate of Turn", "asterix.021_165", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_165_TAR, { "TAR [deg/s]", "asterix.021_165_TAR", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_165_TI, { "TI", "asterix.021_165_TI", FT_UINT8, BASE_DEC, VALS (valstr_021_165_TI), 0xc0, NULL, HFILL } },
        { &hf_021_165_ROT, { "ROT", "asterix.021_165_ROT", FT_UINT8, BASE_DEC, NULL, 0xfe, NULL, HFILL } },
        { &hf_021_170, { "170, Target Identification", "asterix.021_170", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_200, { "200, Target Status", "asterix.021_200", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_200_ICF, { "ICF", "asterix.021_200_ICF", FT_UINT8, BASE_DEC, VALS (valstr_021_200_ICF), 0x80, NULL, HFILL } },
        { &hf_021_200_LNAV, { "LNAV", "asterix.021_200_LNAV", FT_UINT8, BASE_DEC, VALS (valstr_021_200_LNAV), 0x40, NULL, HFILL } },
        { &hf_021_200_ME, { "ME", "asterix.021_200_ME", FT_UINT8, BASE_DEC, VALS (valstr_021_200_ME), 0x20, NULL, HFILL } },
        { &hf_021_200_PS, { "PS", "asterix.021_200_PS", FT_UINT8, BASE_DEC, VALS (valstr_021_200_PS), 0x1c, NULL, HFILL } },
        { &hf_021_200_SS, { "SS", "asterix.021_200_SS", FT_UINT8, BASE_DEC, VALS (valstr_021_200_SS), 0x03, NULL, HFILL } },
        { &hf_021_200_TS , { "TS", "asterix.021_200_TS", FT_UINT8, BASE_DEC, VALS (valstr_021_200_TS), 0x0, NULL, HFILL } },
        { &hf_021_210, { "210, MOPS Version", "asterix.021_210", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_210_v0_2, { "210, Link Technology Indicator", "asterix.021_210", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_210_VNS, { "VNS", "asterix.021_210_VNS", FT_UINT8, BASE_DEC, VALS (valstr_021_210_VNS), 0x40, NULL, HFILL } },
        { &hf_021_210_VN, { "VN", "asterix.021_210_VN", FT_UINT8, BASE_DEC, VALS (valstr_021_210_VN), 0x38, NULL, HFILL } },
        { &hf_021_210_LTT, { "LTT", "asterix.021_210_LTT", FT_UINT8, BASE_DEC, VALS (valstr_021_210_LTT), 0x07, NULL, HFILL } },
        { &hf_021_210_DTI, { "DTI", "asterix.021_210_DTI", FT_UINT8, BASE_DEC, VALS (valstr_021_210_DTI), 0x10, NULL, HFILL } },
        { &hf_021_210_MDS, { "MDS", "asterix.021_210_MDS", FT_UINT8, BASE_DEC, VALS (valstr_021_210_MDS), 0x08, NULL, HFILL } },
        { &hf_021_210_UAT, { "UAT", "asterix.021_210_UAT", FT_UINT8, BASE_DEC, VALS (valstr_021_210_UAT), 0x04, NULL, HFILL } },
        { &hf_021_210_VDL, { "VDL", "asterix.021_210_VDL", FT_UINT8, BASE_DEC, VALS (valstr_021_210_VDL), 0x02, NULL, HFILL } },
        { &hf_021_210_OTR, { "OTR", "asterix.021_210_OTR", FT_UINT8, BASE_DEC, VALS (valstr_021_210_OTR), 0x01, NULL, HFILL } },
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
        { &hf_021_230_RA, { "RA [deg]", "asterix.021_230_RA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_250, { "250, Mode S MB Data", "asterix.021_250", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_260, { "260, ACAS Resolution Advisory Report", "asterix.021_260", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_260_TYP, { "TYP", "asterix.021_260_TYP", FT_UINT56, BASE_DEC, NULL, G_GINT64_CONSTANT(0xf8000000000000), NULL, HFILL } },
        { &hf_021_260_STYP, { "STYP", "asterix.021_260_STYP", FT_UINT56, BASE_DEC, NULL, G_GINT64_CONSTANT(0x07000000000000), NULL, HFILL } },
        { &hf_021_260_ARA, { "ARA", "asterix.021_260_ARA", FT_UINT56, BASE_DEC, NULL, G_GINT64_CONSTANT(0x00fffc00000000), NULL, HFILL } },
        { &hf_021_260_RAC, { "RAC", "asterix.021_260_RAC", FT_UINT56, BASE_DEC, NULL, G_GINT64_CONSTANT(0x000003c0000000), NULL, HFILL } },
        { &hf_021_260_RAT, { "RAT", "asterix.021_260_RAT", FT_UINT56, BASE_DEC, NULL, G_GINT64_CONSTANT(0x00000020000000), NULL, HFILL } },
        { &hf_021_260_MTE, { "MTE", "asterix.021_260_MTE", FT_UINT56, BASE_DEC, NULL, G_GINT64_CONSTANT(0x00000010000000), NULL, HFILL } },
        { &hf_021_260_TTI, { "TTI", "asterix.021_260_TTI", FT_UINT56, BASE_DEC, NULL, G_GINT64_CONSTANT(0x0000000c000000), NULL, HFILL } },
        { &hf_021_260_TID, { "TID", "asterix.021_260_TID", FT_UINT56, BASE_DEC, NULL, G_GINT64_CONSTANT(0x00000003ffffff), NULL, HFILL } },
        { &hf_021_271, { "271, Surface Capabilities and Characteristics", "asterix.021_271", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_271_POA, { "POA", "asterix.021_271_POA", FT_UINT8, BASE_DEC, VALS (valstr_021_271_POA), 0x20, NULL, HFILL } },
        { &hf_021_271_CDTIS, { "CDTI/S", "asterix.021_271_CDTIS", FT_UINT8, BASE_DEC, VALS (valstr_021_271_CDTIS), 0x10, NULL, HFILL } },
        { &hf_021_271_B2low, { "B2low", "asterix.021_271_B2low", FT_UINT8, BASE_DEC, VALS (valstr_021_271_B2low), 0x08, NULL, HFILL } },
        { &hf_021_271_RAS, { "RAS", "asterix.021_271_RAS", FT_UINT8, BASE_DEC, VALS (valstr_021_271_RAS), 0x04, NULL, HFILL } },
        { &hf_021_271_IDENT, { "IDENT", "asterix.021_271_IDENT", FT_UINT8, BASE_DEC, VALS (valstr_021_271_IDENT), 0x02, NULL, HFILL } },
        { &hf_021_271_LW, { "L+W", "asterix.021_271_LW", FT_UINT8, BASE_DEC, NULL, 0xf0, NULL, HFILL } },
        { &hf_021_271_LW_v2_1, { "L+W", "asterix.021_271_LW", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL } },
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
        { &hf_021_RE_BPS, { "BPS, Barometric Pressure Setting", "asterix.021_RE_BPS", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_RE_BPS_BPS, { "BPS[hPa]", "asterix.021_RE_BPS_BPS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_RE_SelH, { "SelH, Selected Heading", "asterix.021_RE_SelH", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_RE_SelH_HRD, { "HRD", "asterix.021_RE_SelH_HRD", FT_UINT8, BASE_DEC, VALS (valstr_021_RE_SelH_HRD), 0x08, NULL, HFILL } },
        { &hf_021_RE_SelH_Stat, { "Stat", "asterix.021_RE_SelH_Stat", FT_UINT8, BASE_DEC, VALS (valstr_021_RE_SelH_Stat), 0x04, NULL, HFILL } },
        { &hf_021_RE_SelH_SelH, { "SelH[deg]", "asterix.021_RE_SelH_SelH", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_RE_NAV, { "NAV, Navigation Mode", "asterix.021_RE_NAV", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_RE_NAV_AP, { "AP", "asterix.021_RE_NAV_AP", FT_UINT8, BASE_DEC, VALS (valstr_021_RE_NAV_AP), 0x80, NULL, HFILL } },
        { &hf_021_RE_NAV_VN, { "VN", "asterix.021_RE_NAV_VN", FT_UINT8, BASE_DEC, VALS (valstr_021_RE_NAV_VN), 0x40, NULL, HFILL } },
        { &hf_021_RE_NAV_AH, { "AH", "asterix.021_RE_NAV_AH", FT_UINT8, BASE_DEC, VALS (valstr_021_RE_NAV_AH), 0x20, NULL, HFILL } },
        { &hf_021_RE_NAV_AM, { "AM", "asterix.021_RE_NAV_AM", FT_UINT8, BASE_DEC, VALS (valstr_021_RE_NAV_AM), 0x10, NULL, HFILL } },
        { &hf_021_RE_GAO, { "GAO, GPS Antenna Offset", "asterix.021_RE_GAO", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_RE_GAO_GAO, { "GAO", "asterix.021_RE_GAO_GAO", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_021_RE_SGV, { "SGV, Surface Ground Vector", "asterix.021_RE_SGV", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_RE_SGV_STP, { "STP", "asterix.021_RE_SGV_STP", FT_UINT8, BASE_DEC, VALS (valstr_021_RE_SGV_STP), 0x80, NULL, HFILL } },
        { &hf_021_RE_SGV_HTS, { "HTS", "asterix.021_RE_SGV_HTS", FT_UINT8, BASE_DEC, VALS (valstr_021_RE_SGV_HTS), 0x40, NULL, HFILL } },
        { &hf_021_RE_SGV_HTT, { "HTT", "asterix.021_RE_SGV_HTT", FT_UINT8, BASE_DEC, VALS (valstr_021_RE_SGV_HTT), 0x20, NULL, HFILL } },
        { &hf_021_RE_SGV_HRD, { "HRD", "asterix.021_RE_SGV_HRD", FT_UINT8, BASE_DEC, VALS (valstr_021_RE_SGV_HRD), 0x10, NULL, HFILL } },
        { &hf_021_RE_SGV_GSS, { "GSS", "asterix.021_RE_SGV_GSS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_RE_SGV_HGT, { "HGT", "asterix.021_RE_SGV_HGT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_RE_STA, { "STA, Aircraft Status", "asterix.021_RE_STA", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_RE_STA_ES, { "ES", "asterix.021_RE_STA_ES", FT_UINT8, BASE_DEC, VALS (valstr_021_RE_STA_ES), 0x80, NULL, HFILL } },
        { &hf_021_RE_STA_UAT, { "UAT", "asterix.021_RE_STA_UAT", FT_UINT8, BASE_DEC, VALS (valstr_021_RE_STA_UAT), 0x40, NULL, HFILL } },
        { &hf_021_RE_TNH, { "TNH, True North Heading", "asterix.021_RE_TNH", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_RE_TNH_TNH, { "TNH[deg]", "asterix.021_RE_TNH_TNH", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_RE_MES, { "M5N, Mode 5 Reports, New Format", "asterix.021_RE_MES", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_RE_MES_01, { "#1, Mode 5 Summary", "asterix.021_RE_MES_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_RE_MES_01_M5, { "M5", "asterix.021_RE_MES_01_M5", FT_UINT8, BASE_DEC, VALS (valstr_021_RE_MES_01_M5), 0x80, NULL, HFILL } },
        { &hf_021_RE_MES_01_ID, { "ID", "asterix.021_RE_MES_01_ID", FT_UINT8, BASE_DEC, VALS (valstr_021_RE_MES_01_ID), 0x40, NULL, HFILL } },
        { &hf_021_RE_MES_01_DA, { "DA", "asterix.021_RE_MES_01_DA", FT_UINT8, BASE_DEC, VALS (valstr_021_RE_MES_01_DA), 0x20, NULL, HFILL } },
        { &hf_021_RE_MES_01_M1, { "M1", "asterix.021_RE_MES_01_M1", FT_UINT8, BASE_DEC, VALS (valstr_021_RE_MES_01_M1), 0x10, NULL, HFILL } },
        { &hf_021_RE_MES_01_M2, { "M2", "asterix.021_RE_MES_01_M2", FT_UINT8, BASE_DEC, VALS (valstr_021_RE_MES_01_M2), 0x08, NULL, HFILL } },
        { &hf_021_RE_MES_01_M3, { "M3", "asterix.021_RE_MES_01_M3", FT_UINT8, BASE_DEC, VALS (valstr_021_RE_MES_01_M3), 0x04, NULL, HFILL } },
        { &hf_021_RE_MES_01_MC, { "MC", "asterix.021_RE_MES_01_MC", FT_UINT8, BASE_DEC, VALS (valstr_021_RE_MES_01_MC), 0x02, NULL, HFILL } },
        { &hf_021_RE_MES_01_PO, { "PO", "asterix.021_RE_MES_01_PO", FT_UINT8, BASE_DEC, VALS (valstr_021_RE_MES_01_PO), 0x01, NULL, HFILL } },
        { &hf_021_RE_MES_02, { "#2, Mode 5 PIN /National Origin/ Mission Code", "asterix.021_RE_MES_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_RE_MES_02_PIN, { "PIN", "asterix.021_RE_MES_02_PIN", FT_UINT32, BASE_DEC, NULL, 0x3fff0000, NULL, HFILL } },
        { &hf_021_RE_MES_02_NO, { "NO", "asterix.021_RE_MES_02_NO", FT_UINT32, BASE_DEC, NULL, 0x000007ff, NULL, HFILL } },
        { &hf_021_RE_MES_03, { "#3, Extended Mode 1 Code in Octal Representation", "asterix.021_RE_MES_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_RE_MES_03_V, { "V", "asterix.021_RE_MES_03_V", FT_UINT16, BASE_DEC, VALS (valstr_021_RE_MES_03_V), 0x8000, NULL, HFILL } },
        { &hf_021_RE_MES_03_L, { "L", "asterix.021_RE_MES_03_L", FT_UINT16, BASE_DEC, VALS (valstr_021_RE_MES_03_L), 0x2000, NULL, HFILL } },
        { &hf_021_RE_MES_03_SQUAWK, { "SQUAWK", "asterix.021_RE_MES_03_SQUAWK", FT_UINT16, BASE_OCT, NULL, 0x0fff, NULL, HFILL } },
        { &hf_021_RE_MES_04, { "#4, X Pulse Presence", "asterix.021_RE_MES_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_RE_MES_04_XP, { "XP", "asterix.021_RE_MES_04_XP", FT_UINT8, BASE_DEC, VALS (valstr_021_RE_MES_04_XP), 0x20, NULL, HFILL } },
        { &hf_021_RE_MES_04_X5, { "X5", "asterix.021_RE_MES_04_X5", FT_UINT8, BASE_DEC, VALS (valstr_021_RE_MES_04_X5), 0x10, NULL, HFILL } },
        { &hf_021_RE_MES_04_XC, { "XC", "asterix.021_RE_MES_04_XC", FT_UINT8, BASE_DEC, VALS (valstr_021_RE_MES_04_XC), 0x08, NULL, HFILL } },
        { &hf_021_RE_MES_04_X3, { "X3", "asterix.021_RE_MES_04_X3", FT_UINT8, BASE_DEC, VALS (valstr_021_RE_MES_04_X3), 0x04, NULL, HFILL } },
        { &hf_021_RE_MES_04_X2, { "X2", "asterix.021_RE_MES_04_X2", FT_UINT8, BASE_DEC, VALS (valstr_021_RE_MES_04_X2), 0x02, NULL, HFILL } },
        { &hf_021_RE_MES_04_X1, { "X1", "asterix.021_RE_MES_04_X1", FT_UINT8, BASE_DEC, VALS (valstr_021_RE_MES_04_X1), 0x01, NULL, HFILL } },
        { &hf_021_RE_MES_05, { "#5, Figure of Merit", "asterix.021_RE_MES_05", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_RE_MES_05_FOM, { "FOM", "asterix.021_RE_MES_05_FOM", FT_UINT8, BASE_DEC, NULL, 0x1f, NULL, HFILL } },
        { &hf_021_RE_MES_06, { "#6, Mode 2 Code in Octal Representation", "asterix.021_RE_MES_06", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_021_RE_MES_06_V, { "V", "asterix.021_RE_MES_06_V", FT_UINT16, BASE_DEC, VALS (valstr_021_RE_MES_06_V), 0x8000, NULL, HFILL } },
        { &hf_021_RE_MES_06_L, { "L", "asterix.021_RE_MES_06_L", FT_UINT16, BASE_DEC, VALS (valstr_021_RE_MES_06_L), 0x2000, NULL, HFILL } },
        { &hf_021_RE_MES_06_SQUAWK, { "SQUAWK", "asterix.021_RE_MES_06_SQUAWK", FT_UINT16, BASE_OCT, NULL, 0x0fff, NULL, HFILL } },
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
        /* Category 025 */
        { &hf_025_000, { "000, Report Type", "asterix.025_000", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_025_000_RT, { "RT", "asterix.025_000_RT", FT_UINT8, BASE_DEC, VALS (valstr_025_000_RT), 0xFE, NULL, HFILL } },
        { &hf_025_000_RG, { "RG", "asterix.025_000_RG", FT_UINT8, BASE_DEC, VALS (valstr_025_000_RG), 0x01, NULL, HFILL } },
        { &hf_025_010, { "010, Data Source Identifier", "asterix.025_010", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_025_015, { "015, Service Identification", "asterix.025_015", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_025_015_SID, { "SID", "asterix.025_015_SID", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_025_020, { "020, Service Designator", "asterix.025_020", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_025_020_SD, { "Service Designator", "asterix.025_020_SD", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_025_070, { "070, Time of Day", "asterix.025_070", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_025_100, { "100, System and Service Status", "asterix.025_100", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_025_100_NOGO, { "NOGO", "asterix.025_100_NOGO", FT_UINT8, BASE_DEC, VALS (valstr_025_100_NOGO), 0x80, NULL, HFILL } },
        { &hf_025_100_OPS, { "OPS", "asterix.025_100_OPS", FT_UINT8, BASE_DEC, VALS (valstr_025_100_OPS), 0x60, NULL, HFILL } },
        { &hf_025_100_SSTAT, { "SSTAT", "asterix.025_100_SSTAT", FT_UINT8, BASE_DEC, VALS (valstr_025_100_SSTAT), 0x1E, NULL, HFILL } },
        { &hf_025_105, { "105, System and Service Error Codes", "asterix.025_105", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_025_105_ERR, { "ERR", "asterix.025_105_ERR", FT_UINT8, BASE_DEC, VALS (valstr_025_105_ERR), 0x0, NULL, HFILL } },
        { &hf_025_120, { "120, Component Status", "asterix.025_120", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_025_120_CID, { "CID", "asterix.025_120_CID", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_025_120_EC, { "EC", "asterix.025_120_EC", FT_UINT8, BASE_DEC, VALS (valstr_025_120_EC), 0xFC, NULL, HFILL } },
        { &hf_025_120_CS, { "CS", "asterix.025_120_CS", FT_UINT8, BASE_DEC, VALS (valstr_025_120_CS), 0x03, NULL, HFILL } },
        { &hf_025_140, { "140, Service Statistics", "asterix.025_140", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_025_140_TYPE, { "TYPE", "asterix.025_140_TYPE", FT_UINT8, BASE_DEC, VALS (valstr_025_140_TYPE), 0x0, NULL, HFILL } },
        { &hf_025_140_REF, { "REF", "asterix.025_140_REF", FT_UINT8, BASE_DEC, VALS (valstr_025_140_REF), 0x80, NULL, HFILL } },
        { &hf_025_140_COUNTER, { "COUNTER", "asterix.025_140_COUNTER", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_025_200, { "200, Message Identification", "asterix.025_200", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_025_200_MID, { "MID", "asterix.025_200_MID", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_025_SP, { "Special Field", "asterix.025_SP", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        /* Category 032 */
        { &hf_032_010, { "010, Data Source Identifier", "asterix.032_010", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_015, { "015, User Number", "asterix.032_015", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_015_UN, { "User Number", "asterix.032_015_UN", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_032_018, { "018, Data Source Identification Tag", "asterix.032_018", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_020, { "020, Time Of Message", "asterix.032_020", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_035, { "035, Type Of Message", "asterix.032_035", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_035_FAM, { "Family", "asterix.032_035_FAM", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL } },
        { &hf_032_035_NAT, { "Nature", "asterix.032_035_NAT", FT_UINT8, BASE_DEC, VALS(valstr_032_035_NAT), 0x0F, NULL, HFILL } },
        { &hf_032_040, { "040, Track Number", "asterix.032_040", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_040_TRK, { "TN", "asterix.032_040_TN", FT_UINT16, BASE_DEC, NULL, 0xFFFF, NULL, HFILL } },
        { &hf_032_050, { "050, Composed Track Number", "asterix.032_050", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_050_SUI, { "SUI", "asterix.032_050_SUI", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_032_050_STN, { "STN", "asterix.032_050_STN", FT_UINT16, BASE_DEC, NULL, 0x1FFE, NULL, HFILL } },
        { &hf_032_060, { "060, Track Mode 3/A", "asterix.032_060", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_060_M3, { "M3A", "asterix.032_060_M3", FT_UINT16, BASE_OCT, NULL, 0x0FFF, NULL, HFILL } },
        { &hf_032_400, { "400, Callsign", "asterix.032_400", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_400_CALL, { "CS", "asterix.032_400_CALL", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_410, { "410, Plan Number", "asterix.032_410", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_410_PLN, { "PLN", "asterix.032_410_PLN", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_032_420, { "420, Flight Category", "asterix.032_420", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_420_GAT, { "GAT", "asterix.032_420_GAT", FT_UINT8, BASE_DEC, VALS(valstr_032_420_GAT), 0xC0, NULL, HFILL } },
        { &hf_032_420_FR, { "FR", "asterix.032_420_FR", FT_UINT8, BASE_DEC, VALS(valstr_032_420_FR), 0x30, NULL, HFILL } },
        { &hf_032_420_SP, { "SP", "asterix.032_420_SP", FT_UINT8, BASE_HEX, NULL, 0x0E, NULL, HFILL } },
        { &hf_032_430, { "430, Type of Aircraft", "asterix.032_430", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_032_430_TYP, { "TYP", "asterix.032_430_TYP", FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_032_435, { "435, Category of Turbulance", "asterix.032_435", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_032_435_TUR, { "TURB", "asterix.032_435_TUR", FT_UINT8, BASE_DEC, VALS(valstr_032_435_CAT), 0x00, NULL, HFILL } },
        { &hf_032_440, { "440, Departure Airport", "asterix.032_440", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_440_DEP, { "DEP", "asterix.032_440_DEP", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_450, { "450, Destination Airport", "asterix.032_450", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_450_DEST, { "DEST", "asterix.032_450_DEST", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_460, { "460, Allocated SSR Codes", "asterix.032_460", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_460_SSR, { "SSR", "asterix.032_460_SSR", FT_UINT16, BASE_OCT, NULL, 0x0FFF, NULL, HFILL } },
        { &hf_032_480, { "480, Current Cleared Flight Level", "asterix.032_480", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_480_CFL, { "CFL [ft]", "asterix.032_480_CFL", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_032_490, { "490, Current Control Position", "asterix.032_490", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_490_CEN, { "CEN", "asterix.032_490_CEN", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_032_490_POS, { "POS", "asterix.032_490_POS", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_032_500, { "500, Supplementary Flight Data", "asterix.032_500", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_500_01, { "IFPS Flight ID", "asterix.032_500_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_500_IFI_TYP, { "TYP", "asterix.032_500_01_TYP", FT_UINT32, BASE_DEC, VALS(valstr_032_500_PLN), 0x90000000, NULL, HFILL } },
        { &hf_032_500_IFI_NBR, { "NBR", "asterix.032_500_01_NBR", FT_UINT32, BASE_DEC, NULL, 0x07FFFFFF, NULL, HFILL } },
        { &hf_032_500_02, { "RVSM & Flight Priority", "asterix.032_500_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_500_RVSM_RVSM, { "RVSM", "asterix.032_500_02_RVSM", FT_UINT8, BASE_DEC, VALS(valstr_032_500_RVSM), 0x06, NULL, HFILL } },
        { &hf_032_500_RVSM_HPR, { "HPR", "asterix.032_500_02_HPR", FT_UINT8, BASE_DEC, VALS(valstr_032_500_HPR), 0x01, NULL, HFILL } },
        { &hf_032_500_03, { "Runway Designation", "asterix.032_500_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_500_RUNWAY_NU1, { "NU1", "asterix.032_500_03_NU1", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_500_RUNWAY_NU2, { "NU2", "asterix.032_500_03_NU2", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_500_RUNWAY_LTR, { "LTR", "asterix.032_500_03_LTR", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_500_04, { "Time of Departure / Arrival", "asterix.032_500_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_500_TIME_TYP, { "TYP", "asterix.032_500_04_TYP", FT_UINT8, BASE_DEC, VALS(valstr_032_500_TYP), 0xFE, NULL, HFILL } },
        { &hf_032_500_TIME_DAY, { "DAY", "asterix.032_500_04_DAY", FT_UINT8, BASE_DEC, VALS(valstr_032_500_DAY), 0x06, NULL, HFILL } },
        { &hf_032_500_TIME_HOR, { "HOR", "asterix.032_500_04_HOR", FT_UINT8, BASE_DEC, NULL, 0x01E, NULL, HFILL } },
        { &hf_032_500_TIME_MIN, { "MIN", "asterix.032_500_04_MIN", FT_UINT8, BASE_DEC, NULL, 0x3F, NULL, HFILL } },
        { &hf_032_500_TIME_AVS, { "AVS", "asterix.032_500_04_AVS", FT_UINT8, BASE_DEC, VALS(valstr_032_500_AVS), 0x80, NULL, HFILL } },
        { &hf_032_500_TIME_SEC, { "SEC", "asterix.032_500_04_SEC", FT_UINT8, BASE_DEC, NULL, 0x3E, NULL, HFILL } },
        { &hf_032_500_05, { "Aircraft Stand", "asterix.032_500_05", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_500_AIR_STD, { "STND", "asterix.032_500_05_STND", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_500_06, { "Stand Status", "asterix.032_500_06", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_500_STS_EMP, { "EMP", "asterix.032_500_06_EMP", FT_UINT8, BASE_DEC, VALS(valstr_032_500_STS_EMP), 0xC0, NULL, HFILL } },
        { &hf_032_500_STS_AVL, { "AVL", "asterix.032_500_06_AVL", FT_UINT8, BASE_DEC, VALS(valstr_032_500_STS_AVL), 0x30, NULL, HFILL } },
        { &hf_032_500_07, { "Standard Instrument Departure", "asterix.032_500_07", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_500_SID, { "SID", "asterix.032_500_07_SID", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_500_08, { "Standard Instrument Arrival", "asterix.032_500_08", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_500_SIA, { "SIA", "asterix.032_500_08_SIA", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_032_RE, { "Reserved Expansion Field", "asterix.032_RE", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        /* Category 034 */
        { &hf_034_000, { "000, Message Type", "asterix.034_000", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_000_MT, { "MT", "asterix.034_000_MT", FT_UINT8, BASE_DEC, VALS (valstr_034_000_MT), 0x0, NULL, HFILL } },
        { &hf_034_010, { "010, Data Source Identifier", "asterix.034_010", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_020, { "020, Sector Number", "asterix.034_020", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_020_SN, { "Sector number", "asterix.034_020_SN", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_030, { "030, Time of Day", "asterix.034_030", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_041, { "041, Antenna Rotation Speed", "asterix.034_041", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_041_ARS, { "Antenna Rotation Speed", "asterix.034_041_ARS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_050, { "050, System Configuration and Status", "asterix.034_050", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_050_01, { "#1: COM", "asterix.034_050_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_050_01_NOGO, { "Operational Release Status of the System", "asterix.034_050_01_NOGO", FT_UINT8, BASE_DEC, VALS (valstr_034_050_01_NOGO), 0x80, NULL, HFILL } },
        { &hf_034_050_01_RDPC, { "Radar Data Processor Chain Selection Status", "asterix.034_050_01_RDPC", FT_UINT8, BASE_DEC, VALS (valstr_034_050_01_RDPC), 0x40, NULL, HFILL } },
        { &hf_034_050_01_RDPR, { "Event to signal a reset/restart of the selected Radar Data Processor Chain, i.e. expect a new assignment of track numbers", "asterix.034_050_01_RDPR", FT_UINT8, BASE_DEC, VALS (valstr_034_050_01_RDPR), 0x20, NULL, HFILL } },
        { &hf_034_050_01_OVL_RDP, { "Radar Data Processor Overload Indicator", "asterix.034_050_01_OVL_RDP", FT_UINT8, BASE_DEC, VALS (valstr_034_050_01_OVL_RDP), 0x10, NULL, HFILL } },
        { &hf_034_050_01_OVL_XMT, { "Transmission Subsystem Overload Status", "asterix.034_050_01_OVL_XMT", FT_UINT8, BASE_DEC, VALS (valstr_034_050_01_OVL_XMT), 0x08, NULL, HFILL } },
        { &hf_034_050_01_MSC, { "Monitoring System Connected Status", "asterix.034_050_01_MSC", FT_UINT8, BASE_DEC, VALS (valstr_034_050_01_MSC), 0x04, NULL, HFILL } },
        { &hf_034_050_01_TSV, { "Time Source Validity", "asterix.034_050_01_TSV", FT_UINT8, BASE_DEC, VALS (valstr_034_050_01_TSV), 0x02, NULL, HFILL } },
        { &hf_034_050_02, { "#2: Specific Status information for a PSR sensor", "asterix.034_050_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_050_02_ANT, { "Selected antenna", "asterix.034_050_02_ANT", FT_UINT8, BASE_DEC, VALS (valstr_034_050_02_ANT), 0x80, NULL, HFILL } },
        { &hf_034_050_02_CHAB, { "Channel A/B selection status", "asterix.034_050_02_CHAB", FT_UINT8, BASE_DEC, VALS (valstr_034_050_02_CHAB), 0x60, NULL, HFILL } },
        { &hf_034_050_02_OVL, { "Overload condition", "asterix.034_050_02_OVL", FT_UINT8, BASE_DEC, VALS (valstr_034_050_02_OVL), 0x10, NULL, HFILL } },
        { &hf_034_050_02_MSC, { "Monitoring System Connected Status", "asterix.034_050_02_MSC", FT_UINT8, BASE_DEC, VALS (valstr_034_050_02_MSC), 0x08, NULL, HFILL } },
        { &hf_034_050_03, { "#3: Specific Status information for a SSR sensor", "asterix.034_050_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_050_03_ANT, { "Selected antenna", "asterix.034_050_03_ANT", FT_UINT8, BASE_DEC, VALS (valstr_034_050_03_ANT), 0x80, NULL, HFILL } },
        { &hf_034_050_03_CHAB, { "Channel A/B selection status", "asterix.034_050_03_CHAB", FT_UINT8, BASE_DEC, VALS (valstr_034_050_03_CHAB), 0x60, NULL, HFILL } },
        { &hf_034_050_03_OVL, { "Overload condition", "asterix.034_050_03_OVL", FT_UINT8, BASE_DEC, VALS (valstr_034_050_03_OVL), 0x10, NULL, HFILL } },
        { &hf_034_050_03_MSC, { "Monitoring System Connected Status", "asterix.034_050_03_MSC", FT_UINT8, BASE_DEC, VALS (valstr_034_050_03_MSC), 0x08, NULL, HFILL } },
        { &hf_034_050_04, { "#4: Specific Status information for a Mode S sensor", "asterix.034_050_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_050_04_ANT, { "Selected antenna", "asterix.034_050_04_ANT", FT_UINT16, BASE_DEC, VALS (valstr_034_050_04_ANT), 0x8000, NULL, HFILL } },
        { &hf_034_050_04_CHAB, { "Channel A/B selection status for surveillance", "asterix.034_050_04_CHAB", FT_UINT16, BASE_DEC, VALS (valstr_034_050_04_CHAB), 0x6000, NULL, HFILL } },
        { &hf_034_050_04_OVL_SUR, { "Overload condition", "asterix.034_050_04_OVL_SUR", FT_UINT16, BASE_DEC, VALS (valstr_034_050_04_OVL_SUR), 0x1000, NULL, HFILL } },
        { &hf_034_050_04_MSC, { "Monitoring System Connected Status", "asterix.034_050_04_MSC", FT_UINT16, BASE_DEC, VALS (valstr_034_050_04_MSC), 0x0800, NULL, HFILL } },
        { &hf_034_050_04_SCF, { "Channel A/B selection status for Surveillance Co-ordination Function", "asterix.034_050_04_SCF", FT_UINT16, BASE_DEC, VALS (valstr_034_050_04_SCF), 0x0400, NULL, HFILL } },
        { &hf_034_050_04_DLF, { "Channel A/B selection status for Data Link Function", "asterix.034_050_04_DLF", FT_UINT16, BASE_DEC, VALS (valstr_034_050_04_DLF), 0x0200, NULL, HFILL } },
        { &hf_034_050_04_OVL_SCF, { "Overload in Surveillance", "asterix.034_050_04_OVL_SCF", FT_UINT16, BASE_DEC, VALS (valstr_034_050_04_OVL_SCF), 0x0100, NULL, HFILL } },
        { &hf_034_050_04_OVL_DLF, { "Overload in Data Link Function", "asterix.034_050_04_OVL_DLF", FT_UINT16, BASE_DEC, VALS (valstr_034_050_04_OVL_DLF), 0x0080, NULL, HFILL } },
        { &hf_034_060, { "060, System Processing Mode", "asterix.034_060", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_060_01, { "#1: COM", "asterix.034_060_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_060_01_RED_RDP, { "Reduction Steps in use for an overload of the RDP", "asterix.034_060_01_RED_RDP", FT_UINT8, BASE_DEC, VALS (valstr_034_060_RED), 0x70, NULL, HFILL } },
        { &hf_034_060_01_RED_XMT, { "Reduction Steps in use for an overload of the Transmission subsystem", "asterix.034_060_01_RED_XMT", FT_UINT8, BASE_DEC, VALS (valstr_034_060_RED), 0x0e, NULL, HFILL } },
        { &hf_034_060_02, { "#2: Specific Processing Mode information for a PSR sensor", "asterix.034_060_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_060_02_POL, { "Polarization in use by PSR", "asterix.034_060_02_POL", FT_UINT8, BASE_DEC, VALS (valstr_034_060_02_POL), 0x80, NULL, HFILL } },
        { &hf_034_060_02_RED_RAD, { "Reduction Steps in use as result of an overload within the PSR subsystem", "asterix.034_060_02_RED_RAD", FT_UINT8, BASE_DEC, VALS (valstr_034_060_RED), 0x70, NULL, HFILL } },
        { &hf_034_060_02_STC, { "Sensitivity Time Control Map in use", "asterix.034_060_02_STC", FT_UINT8, BASE_DEC, VALS (valstr_034_060_02_STC), 0x0c, NULL, HFILL } },
        { &hf_034_060_03, { "#3: Specific Processing Mode information for a SSR sensor", "asterix.034_060_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_060_03_RED_RAD, { "Reduction Steps in use as result of an overload within the SSR subsystem", "asterix.034_060_03_RED_RAD", FT_UINT8, BASE_DEC, VALS (valstr_034_060_RED), 0xe0, NULL, HFILL } },
        { &hf_034_060_04, { "#4: Specific Processing Mode information for a Mode S Sensor", "asterix.034_060_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_060_04_RED_RAD, { "Reduction Steps in use as result of an overload within the Mode S subsystem", "asterix.034_060_04_RED_RAD", FT_UINT8, BASE_DEC, VALS (valstr_034_060_RED), 0xe0, NULL, HFILL } },
        { &hf_034_060_04_CLU, { "Cluster State", "asterix.034_060_04_CLU", FT_UINT8, BASE_DEC, VALS (valstr_034_060_04_CLU), 0x10, NULL, HFILL } },
        { &hf_034_070, { "070, Message Count Values", "asterix.034_070", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_070_TYP, { "Type of message counter", "asterix.034_070_TYP", FT_UINT16, BASE_DEC, VALS (valstr_034_070_TYP), 0xf800, NULL, HFILL } },
        { &hf_034_070_COUNTER, { "COUNTER", "asterix.034_070_COUNTER", FT_UINT16, BASE_DEC, NULL, 0x07ff, NULL, HFILL } },
        { &hf_034_090, { "090, Collimation Error", "asterix.034_090", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_090_RE, { "Range error[NM]", "asterix.034_090_RE", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_090_AE, { "Azimuth error[deg]", "asterix.034_090_AE", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_100, { "100, Generic Polar Window", "asterix.034_100", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_100_RHOS, { "Rho start[NM]", "asterix.034_100_RHOS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_100_RHOE, { "Rho end[NM]", "asterix.034_100_RHOE", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_100_THETAS, { "Theta start[deg]", "asterix.034_100_THETAS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_100_THETAE, { "Theta end[deg]", "asterix.034_100_THETAE", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_110, { "110, Data Filter", "asterix.034_110", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_034_110_TYP, { "TYP", "asterix.034_110_TYP", FT_UINT8, BASE_DEC, VALS (valstr_034_110_TYP), 0x0, NULL, HFILL } },
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
        { &hf_048_020_SIM, { "SIM", "asterix.048_020_SIM", FT_UINT8, BASE_DEC, VALS (valstr_048_020_SIM), 0x10, "Simulated or Actual target", HFILL } },
        { &hf_048_020_RDP, { "RDP", "asterix.048_020_RDP", FT_UINT8, BASE_DEC, VALS (valstr_048_020_RDP), 0x08, "RDP Chain", HFILL } },
        { &hf_048_020_SPI, { "SPI", "asterix.048_020_SPI", FT_UINT8, BASE_DEC, VALS (valstr_048_020_SPI), 0x04, "Special Position Identification", HFILL } },
        { &hf_048_020_RAB, { "RAB", "asterix.048_020_RAB", FT_UINT8, BASE_DEC, VALS (valstr_048_020_RAB), 0x02, "Report from aircraft or field monitor", HFILL } },
        { &hf_048_020_TST, { "TST", "asterix.048_020_TST", FT_UINT8, BASE_DEC, VALS (valstr_048_020_TST), 0x80, "Real or test target", HFILL } },
        { &hf_048_020_ERR, { "ERR", "asterix.048_020_ERR", FT_UINT8, BASE_DEC, VALS (valstr_048_020_ERR), 0x40, "Extended range present or not", HFILL } },
        { &hf_048_020_XPP, { "XPP", "asterix.048_020_XPP", FT_UINT8, BASE_DEC, VALS (valstr_048_020_XPP), 0x20, "X-Pulse present or not", HFILL } },
        { &hf_048_020_ME, { "ME", "asterix.048_020_ME", FT_UINT8, BASE_DEC, VALS (valstr_048_020_ME), 0x10, "Military emergency", HFILL } },
        { &hf_048_020_MI, { "MI", "asterix.048_020_MI", FT_UINT8, BASE_DEC, VALS (valstr_048_020_MI), 0x08, "Military identification", HFILL } },
        { &hf_048_020_FOE, { "FOE/FRI", "asterix.048_020_FOE", FT_UINT8, BASE_DEC, VALS (valstr_048_020_FOE), 0x06, "Foe or friend", HFILL } },
        { &hf_048_030, { "030, Warning/Error Conditions", "asterix.048_030", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_030_WE, { "W/E value", "asterix.048_030_WE", FT_UINT8, BASE_DEC, VALS (valstr_048_030_WE), 0xfe, NULL, HFILL } },
        { &hf_048_030_1_WE, { "W/E value", "asterix.048_030_1_WE", FT_UINT8, BASE_DEC, VALS (valstr_048_030_WE), 0xfe, NULL, HFILL } },
        { &hf_048_030_2_WE, { "W/E value", "asterix.048_030_2_WE", FT_UINT8, BASE_DEC, VALS (valstr_048_030_WE), 0xfe, NULL, HFILL } },
        { &hf_048_030_3_WE, { "W/E value", "asterix.048_030_3_WE", FT_UINT8, BASE_DEC, VALS (valstr_048_030_WE), 0xfe, NULL, HFILL } },
        { &hf_048_030_4_WE, { "W/E value", "asterix.048_030_4_WE", FT_UINT8, BASE_DEC, VALS (valstr_048_030_WE), 0xfe, NULL, HFILL } },
        { &hf_048_030_5_WE, { "W/E value", "asterix.048_030_5_WE", FT_UINT8, BASE_DEC, VALS (valstr_048_030_WE), 0xfe, NULL, HFILL } },
        { &hf_048_030_6_WE, { "W/E value", "asterix.048_030_6_WE", FT_UINT8, BASE_DEC, VALS (valstr_048_030_WE), 0xfe, NULL, HFILL } },
        { &hf_048_030_7_WE, { "W/E value", "asterix.048_030_7_WE", FT_UINT8, BASE_DEC, VALS (valstr_048_030_WE), 0xfe, NULL, HFILL } },
        { &hf_048_030_8_WE, { "W/E value", "asterix.048_030_8_WE", FT_UINT8, BASE_DEC, VALS (valstr_048_030_WE), 0xfe, NULL, HFILL } },
        { &hf_048_030_9_WE, { "W/E value", "asterix.048_030_9_WE", FT_UINT8, BASE_DEC, VALS (valstr_048_030_WE), 0xfe, NULL, HFILL } },
        { &hf_048_040, { "040, Measured Position in Polar Co-ordinates", "asterix.048_040", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_040_RHO, { "RHO[NM]", "asterix.048_040_RHO", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_040_THETA, { "THETA[deg]", "asterix.048_040_THETA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_042, { "042, Calculated Position in Cartesian Co-ordinates", "asterix.048_042", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_042_X, { "X[NM]", "asterix.048_042_X", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_042_Y, { "Y[NM]", "asterix.048_042_Y", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_050, { "050, Mode-2 Code in Octal Representation", "asterix.048_050", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_050_V, { "V", "asterix.048_050_V", FT_UINT16, BASE_DEC, VALS (valstr_048_050_V), 0x8000, NULL, HFILL } },
        { &hf_048_050_G, { "G", "asterix.048_050_G", FT_UINT16, BASE_DEC, VALS (valstr_048_050_G), 0x4000, NULL, HFILL } },
        { &hf_048_050_L, { "L", "asterix.048_050_L", FT_UINT16, BASE_DEC, VALS (valstr_048_050_L), 0x2000, NULL, HFILL } },
        { &hf_048_050_SQUAWK, { "SQUAWK", "asterix.048_050_SQUAWK", FT_UINT16, BASE_OCT, NULL, 0x0fff, NULL, HFILL } },
        { &hf_048_055, { "055, Mode-1 Code in Octal Representation", "asterix.048_055", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_055_V, { "V", "asterix.048_055_V", FT_UINT8, BASE_DEC, VALS (valstr_048_055_V), 0x80, NULL, HFILL } },
        { &hf_048_055_G, { "G", "asterix.048_055_G", FT_UINT8, BASE_DEC, VALS (valstr_048_055_G), 0x40, NULL, HFILL } },
        { &hf_048_055_L, { "L", "asterix.048_055_L", FT_UINT8, BASE_DEC, VALS (valstr_048_055_L), 0x20, NULL, HFILL } },
        { &hf_048_055_CODE, { "CODE", "asterix.048_055_CODE", FT_UINT8, BASE_OCT, NULL, 0x1f, NULL, HFILL } },
        { &hf_048_060, { "060, Mode-2 Code Confidence Indicator", "asterix.048_060", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_060_QA4, { "QA4", "asterix.048_060_QA4", FT_UINT16, BASE_DEC, VALS (valstr_048_060_QA), 0x0800, NULL, HFILL } },
        { &hf_048_060_QA2, { "QA2", "asterix.048_060_QA2", FT_UINT16, BASE_DEC, VALS (valstr_048_060_QA), 0x0400, NULL, HFILL } },
        { &hf_048_060_QA1, { "QA1", "asterix.048_060_QA1", FT_UINT16, BASE_DEC, VALS (valstr_048_060_QA), 0x0200, NULL, HFILL } },
        { &hf_048_060_QB4, { "QB4", "asterix.048_060_QB4", FT_UINT16, BASE_DEC, VALS (valstr_048_060_QA), 0x0100, NULL, HFILL } },
        { &hf_048_060_QB2, { "QB2", "asterix.048_060_QB2", FT_UINT16, BASE_DEC, VALS (valstr_048_060_QA), 0x0080, NULL, HFILL } },
        { &hf_048_060_QB1, { "QB1", "asterix.048_060_QB1", FT_UINT16, BASE_DEC, VALS (valstr_048_060_QA), 0x0040, NULL, HFILL } },
        { &hf_048_060_QC4, { "QC4", "asterix.048_060_QC4", FT_UINT16, BASE_DEC, VALS (valstr_048_060_QA), 0x0020, NULL, HFILL } },
        { &hf_048_060_QC2, { "QC2", "asterix.048_060_QC2", FT_UINT16, BASE_DEC, VALS (valstr_048_060_QA), 0x0010, NULL, HFILL } },
        { &hf_048_060_QC1, { "QC1", "asterix.048_060_QC1", FT_UINT16, BASE_DEC, VALS (valstr_048_060_QA), 0x0008, NULL, HFILL } },
        { &hf_048_060_QD4, { "QD4", "asterix.048_060_QD4", FT_UINT16, BASE_DEC, VALS (valstr_048_060_QA), 0x0004, NULL, HFILL } },
        { &hf_048_060_QD2, { "QD2", "asterix.048_060_QD2", FT_UINT16, BASE_DEC, VALS (valstr_048_060_QA), 0x0002, NULL, HFILL } },
        { &hf_048_060_QD1, { "QD1", "asterix.048_060_QD1", FT_UINT16, BASE_DEC, VALS (valstr_048_060_QA), 0x0001, NULL, HFILL } },
        { &hf_048_065, { "065, Mode-1 Code Confidence Indicator", "asterix.048_065", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_065_QA4, { "QA4", "asterix.048_065_QA4", FT_UINT8, BASE_DEC, VALS (valstr_048_065_QA), 0x10, NULL, HFILL } },
        { &hf_048_065_QA2, { "QA2", "asterix.048_065_QA2", FT_UINT8, BASE_DEC, VALS (valstr_048_065_QA), 0x08, NULL, HFILL } },
        { &hf_048_065_QA1, { "QA1", "asterix.048_065_QA1", FT_UINT8, BASE_DEC, VALS (valstr_048_065_QA), 0x04, NULL, HFILL } },
        { &hf_048_065_QB2, { "QB2", "asterix.048_065_QB2", FT_UINT8, BASE_DEC, VALS (valstr_048_065_QA), 0x02, NULL, HFILL } },
        { &hf_048_065_QB1, { "QB1", "asterix.048_065_QB1", FT_UINT8, BASE_DEC, VALS (valstr_048_065_QA), 0x01, NULL, HFILL } },
        { &hf_048_070, { "070, Mode-3/A Code in Octal Representation", "asterix.048_070", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_070_V, { "V", "asterix.048_070_V", FT_UINT16, BASE_DEC, VALS (valstr_048_070_V), 0x8000, NULL, HFILL } },
        { &hf_048_070_G, { "G", "asterix.048_070_G", FT_UINT16, BASE_DEC, VALS (valstr_048_070_G), 0x4000, NULL, HFILL } },
        { &hf_048_070_L, { "L", "asterix.048_070_L", FT_UINT16, BASE_DEC, VALS (valstr_048_070_L), 0x2000, NULL, HFILL } },
        { &hf_048_070_SQUAWK, { "SQUAWK", "asterix.048_070_SQUAWK", FT_UINT16, BASE_OCT, NULL, 0x0fff, NULL, HFILL } },
        { &hf_048_080, { "080, Mode-3/A Code Confidence Indicator", "asterix.048_080", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_080_QA4, { "QA4", "asterix.048_080_QA4", FT_UINT16, BASE_DEC, VALS (valstr_048_080_QA), 0x0800, NULL, HFILL } },
        { &hf_048_080_QA2, { "QA2", "asterix.048_080_QA2", FT_UINT16, BASE_DEC, VALS (valstr_048_080_QA), 0x0400, NULL, HFILL } },
        { &hf_048_080_QA1, { "QA1", "asterix.048_080_QA1", FT_UINT16, BASE_DEC, VALS (valstr_048_080_QA), 0x0200, NULL, HFILL } },
        { &hf_048_080_QB4, { "QB4", "asterix.048_080_QB4", FT_UINT16, BASE_DEC, VALS (valstr_048_080_QA), 0x0100, NULL, HFILL } },
        { &hf_048_080_QB2, { "QB2", "asterix.048_080_QB2", FT_UINT16, BASE_DEC, VALS (valstr_048_080_QA), 0x0080, NULL, HFILL } },
        { &hf_048_080_QB1, { "QB1", "asterix.048_080_QB1", FT_UINT16, BASE_DEC, VALS (valstr_048_080_QA), 0x0040, NULL, HFILL } },
        { &hf_048_080_QC4, { "QC4", "asterix.048_080_QC4", FT_UINT16, BASE_DEC, VALS (valstr_048_080_QA), 0x0020, NULL, HFILL } },
        { &hf_048_080_QC2, { "QC2", "asterix.048_080_QC2", FT_UINT16, BASE_DEC, VALS (valstr_048_080_QA), 0x0010, NULL, HFILL } },
        { &hf_048_080_QC1, { "QC1", "asterix.048_080_QC1", FT_UINT16, BASE_DEC, VALS (valstr_048_080_QA), 0x0008, NULL, HFILL } },
        { &hf_048_080_QD4, { "QD4", "asterix.048_080_QD4", FT_UINT16, BASE_DEC, VALS (valstr_048_080_QA), 0x0004, NULL, HFILL } },
        { &hf_048_080_QD2, { "QD2", "asterix.048_080_QD2", FT_UINT16, BASE_DEC, VALS (valstr_048_080_QA), 0x0002, NULL, HFILL } },
        { &hf_048_080_QD1, { "QD1", "asterix.048_080_QD1", FT_UINT16, BASE_DEC, VALS (valstr_048_080_QA), 0x0001, NULL, HFILL } },
        { &hf_048_090, { "090, Flight Level in Binary Representation", "asterix.048_090", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_090_V, { "V", "asterix.048_090_V", FT_UINT8, BASE_DEC, VALS (valstr_048_090_V), 0x80, NULL, HFILL } },
        { &hf_048_090_G, { "G", "asterix.048_090_G", FT_UINT8, BASE_DEC, VALS (valstr_048_090_G), 0x40, NULL, HFILL } },
        { &hf_048_090_FL, { "FL", "asterix.048_090_FL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_100, { "100, Mode-C Code and Code Confidence Indicator", "asterix.048_100", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_100_V, { "V", "asterix.048_100_V", FT_UINT16, BASE_DEC, VALS (valstr_048_100_V), 0x8000, NULL, HFILL } },
        { &hf_048_100_G, { "G", "asterix.048_100_G", FT_UINT16, BASE_DEC, VALS (valstr_048_100_G), 0x4000, NULL, HFILL } },
        { &hf_048_100_C1, { "C1", "asterix.048_100_C1", FT_UINT16, BASE_DEC, NULL, 0x0800, NULL, HFILL } },
        { &hf_048_100_A1, { "A1", "asterix.048_100_A1", FT_UINT16, BASE_DEC, NULL, 0x0400, NULL, HFILL } },
        { &hf_048_100_C2, { "C2", "asterix.048_100_C2", FT_UINT16, BASE_DEC, NULL, 0x0200, NULL, HFILL } },
        { &hf_048_100_A2, { "A2", "asterix.048_100_A2", FT_UINT16, BASE_DEC, NULL, 0x0100, NULL, HFILL } },
        { &hf_048_100_C4, { "C4", "asterix.048_100_C4", FT_UINT16, BASE_DEC, NULL, 0x0080, NULL, HFILL } },
        { &hf_048_100_A4, { "A4", "asterix.048_100_A4", FT_UINT16, BASE_DEC, NULL, 0x0040, NULL, HFILL } },
        { &hf_048_100_B1, { "B1", "asterix.048_100_B1", FT_UINT16, BASE_DEC, NULL, 0x0020, NULL, HFILL } },
        { &hf_048_100_D1, { "D1", "asterix.048_100_D1", FT_UINT16, BASE_DEC, NULL, 0x0010, NULL, HFILL } },
        { &hf_048_100_B2, { "B2", "asterix.048_100_B2", FT_UINT16, BASE_DEC, NULL, 0x0008, NULL, HFILL } },
        { &hf_048_100_D2, { "D2", "asterix.048_100_D2", FT_UINT16, BASE_DEC, NULL, 0x0004, NULL, HFILL } },
        { &hf_048_100_B4, { "B4", "asterix.048_100_B4", FT_UINT16, BASE_DEC, NULL, 0x0002, NULL, HFILL } },
        { &hf_048_100_D4, { "D4", "asterix.048_100_D4", FT_UINT16, BASE_DEC, NULL, 0x0001, NULL, HFILL } },
        { &hf_048_100_QC1, { "QC1", "asterix.048_100_QC1", FT_UINT16, BASE_DEC, VALS (valstr_048_100_QA), 0x0800, NULL, HFILL } },
        { &hf_048_100_QA1, { "QA1", "asterix.048_100_QA1", FT_UINT16, BASE_DEC, VALS (valstr_048_100_QA), 0x0400, NULL, HFILL } },
        { &hf_048_100_QC2, { "QC2", "asterix.048_100_QC2", FT_UINT16, BASE_DEC, VALS (valstr_048_100_QA), 0x0200, NULL, HFILL } },
        { &hf_048_100_QA2, { "QA2", "asterix.048_100_QA2", FT_UINT16, BASE_DEC, VALS (valstr_048_100_QA), 0x0100, NULL, HFILL } },
        { &hf_048_100_QC4, { "QC4", "asterix.048_100_QC4", FT_UINT16, BASE_DEC, VALS (valstr_048_100_QA), 0x0080, NULL, HFILL } },
        { &hf_048_100_QA4, { "QA4", "asterix.048_100_QA4", FT_UINT16, BASE_DEC, VALS (valstr_048_100_QA), 0x0040, NULL, HFILL } },
        { &hf_048_100_QB1, { "QB1", "asterix.048_100_QB1", FT_UINT16, BASE_DEC, VALS (valstr_048_100_QA), 0x0020, NULL, HFILL } },
        { &hf_048_100_QD1, { "QD1", "asterix.048_100_QD1", FT_UINT16, BASE_DEC, VALS (valstr_048_100_QA), 0x0010, NULL, HFILL } },
        { &hf_048_100_QB2, { "QB2", "asterix.048_100_QB2", FT_UINT16, BASE_DEC, VALS (valstr_048_100_QA), 0x0008, NULL, HFILL } },
        { &hf_048_100_QD2, { "QD2", "asterix.048_100_QD2", FT_UINT16, BASE_DEC, VALS (valstr_048_100_QA), 0x0004, NULL, HFILL } },
        { &hf_048_100_QB4, { "QB4", "asterix.048_100_QB4", FT_UINT16, BASE_DEC, VALS (valstr_048_100_QA), 0x0002, NULL, HFILL } },
        { &hf_048_100_QD4, { "QD4", "asterix.048_100_QD4", FT_UINT16, BASE_DEC, VALS (valstr_048_100_QA), 0x0001, NULL, HFILL } },
        { &hf_048_110, { "110, Height Measured by a 3D Radar", "asterix.048_110", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_110_3DHEIGHT, { "3D-Height [feet]", "asterix.048_110_3DHEIGHT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_120, { "120, Radial Doppler Speed", "asterix.048_120", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_120_01, { "Subfield #1: Calculated Doppler Speed", "asterix.048_120_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_120_01_D, { "D", "asterix.048_120_01_D", FT_UINT16, BASE_DEC, VALS (valstr_048_120_01_D), 0x8000, NULL, HFILL } },
        { &hf_048_120_01_CAL, { "CAL[m/s]", "asterix.048_120_01_CAL", FT_INT16, BASE_DEC, NULL, 0x3ff, NULL, HFILL } },
        { &hf_048_120_02, { "Subfield # 2: Raw Doppler Speed", "asterix.048_120_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_120_02_DOP, { "DOP[m/s]", "asterix.048_120_02_DOP", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_048_120_02_AMB, { "AMB[m/s]", "asterix.048_120_02_AMB", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_048_120_02_FRQ, { "FRQ[MHz]", "asterix.048_120_02_FRQ", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
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
        { &hf_048_170_CDM_v1_21, { "CDM", "asterix.048_170_CDM", FT_UINT8, BASE_DEC, VALS (valstr_048_170_CDM_v1_21), 0x06, "Climbing / Descending Mode", HFILL } },
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
        { &hf_048_230_COM, { "COM", "asterix.048_230_COM", FT_UINT16, BASE_DEC, VALS (valstr_048_230_COM), 0xe000, "Communications capabiltiy of the transponder", HFILL } },
        { &hf_048_230_STAT, { "STAT", "asterix.048_230_STAT", FT_UINT16, BASE_DEC, VALS (valstr_048_230_STAT), 0x1c00, "Flight status", HFILL } },
        { &hf_048_230_SI, { "SI", "asterix.048_230_SI", FT_UINT16, BASE_DEC, VALS (valstr_048_230_SI), 0x0200, "SI/II Transponder Capability", HFILL } },
        { &hf_048_230_MSSC, { "MSSC", "asterix.048_230_MSSC", FT_UINT16, BASE_DEC, VALS (valstr_048_230_MSSC), 0x0080, "Mode-S Specific Service Capability", HFILL } },
        { &hf_048_230_ARC, { "ARC", "asterix.048_230_ARC", FT_UINT16, BASE_DEC, VALS (valstr_048_230_ARC), 0x0040, "Altitude reporting capability", HFILL } },
        { &hf_048_230_AIC, { "AIC", "asterix.048_230_AIC", FT_UINT16, BASE_DEC, VALS (valstr_048_230_AIC), 0x0020, "Aircraft identification capability", HFILL } },
        { &hf_048_230_B1A, { "B1A", "asterix.048_230_B1A", FT_UINT16, BASE_DEC, NULL, 0x0010, "BDS 1,0 bit 16", HFILL } },
        { &hf_048_230_B1B, { "B1B", "asterix.048_230_B1B", FT_UINT16, BASE_DEC, NULL, 0x000f, "BDS 1,0 bits 37/40", HFILL } },
        { &hf_048_240, { "240, Aircraft Identification", "asterix.048_240", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_250, { "250, Mode S MB Data", "asterix.048_250", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_260, { "260, ACAS Resolution Advisory Report", "asterix.048_260", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_260_ACAS, { "ACAS", "asterix.048_260_ACAS", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE, { "Reserved Expansion Field", "asterix.048_RE", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_MD5, { "MD5, Mode 5 Reports", "asterix.048_RE_MD5", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_MD5_01, { "#1: Mode 5 Summary", "asterix.048_RE_MD5_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_MD5_01_M5, { "M5", "asterix.048_RE_MD5_01_M5", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_MD5_01_M5), 0x80, NULL, HFILL } },
        { &hf_048_RE_MD5_01_ID, { "ID", "asterix.048_RE_MD5_01_ID", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_MD5_01_ID), 0x40, NULL, HFILL } },
        { &hf_048_RE_MD5_01_DA, { "DA", "asterix.048_RE_MD5_01_DA", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_MD5_01_DA), 0x20, NULL, HFILL } },
        { &hf_048_RE_MD5_01_M1, { "M1", "asterix.048_RE_MD5_01_M1", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_MD5_01_M1), 0x10, NULL, HFILL } },
        { &hf_048_RE_MD5_01_M2, { "M2", "asterix.048_RE_MD5_01_M2", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_MD5_01_M2), 0x08, NULL, HFILL } },
        { &hf_048_RE_MD5_01_M3, { "M3", "asterix.048_RE_MD5_01_M3", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_MD5_01_M3), 0x04, NULL, HFILL } },
        { &hf_048_RE_MD5_01_MC, { "MC", "asterix.048_RE_MD5_01_MC", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_MD5_01_MC), 0x02, NULL, HFILL } },
        { &hf_048_RE_MD5_02, { "#2: Mode 5 PIN /National Origin/ Mission Code", "asterix.048_RE_MD5_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_MD5_02_PIN, { "PIN", "asterix.048_RE_MD5_02_PIN", FT_UINT32, BASE_DEC, NULL, 0x3fff0000, NULL, HFILL } },
        { &hf_048_RE_MD5_02_NAV, { "NAV", "asterix.048_RE_MD5_02_NAV", FT_UINT32, BASE_DEC, VALS (valstr_048_RE_MD5_02_NAV), 0x00002000, NULL, HFILL } },
        { &hf_048_RE_MD5_02_NAT, { "NAT", "asterix.048_RE_MD5_02_NAT", FT_UINT32, BASE_DEC, NULL, 0x00001f00, NULL, HFILL } },
        { &hf_048_RE_MD5_02_MIS, { "MIS", "asterix.048_RE_MD5_02_MIS", FT_UINT32, BASE_DEC, NULL, 0x0000003f, NULL, HFILL } },
        { &hf_048_RE_MD5_03, { "#3: Mode 5 Reported Position", "asterix.048_RE_MD5_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_MD5_03_LAT, { "LAT[deg]", "asterix.048_RE_MD5_03_LAT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_MD5_03_LON, { "LON[deg]", "asterix.048_RE_MD5_03_LON", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_MD5_04, { "#4: Mode 5 GNSS-derived Altitude", "asterix.048_RE_MD5_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_MD5_04_RES, { "RES", "asterix.048_RE_MD5_04_RES", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_MD5_04_RES), 0x40, NULL, HFILL } },
        { &hf_048_RE_MD5_04_GA, { "GA[ft]", "asterix.048_RE_MD5_04_GA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_MD5_05, { "#5: Extended Mode 1 Code in Octal Representation", "asterix.048_RE_MD5_05", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_MD5_05_V, { "V", "asterix.048_RE_MD5_05_V", FT_UINT16, BASE_DEC, VALS (valstr_048_RE_MD5_05_V), 0x8000, NULL, HFILL } },
        { &hf_048_RE_MD5_05_G, { "G", "asterix.048_RE_MD5_05_G", FT_UINT16, BASE_DEC, VALS (valstr_048_RE_MD5_05_G), 0x4000, NULL, HFILL } },
        { &hf_048_RE_MD5_05_L, { "L", "asterix.048_RE_MD5_05_L", FT_UINT16, BASE_DEC, VALS (valstr_048_RE_MD5_05_L), 0x2000, NULL, HFILL } },
        { &hf_048_RE_MD5_05_SQUAWK, { "SQUAWK", "asterix.048_RE_MD5_05_SQUAWK", FT_UINT16, BASE_OCT, NULL, 0x0fff, NULL, HFILL } },
        { &hf_048_RE_MD5_06, { "#6: Time Offset for POS and GA", "asterix.048_RE_MD5_06", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_MD5_06_TOS, { "TOS[s]", "asterix.048_RE_MD5_06_TOS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_MD5_07, { "#7: X Pulse Presence,", "asterix.048_RE_MD5_07", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_MD5_07_XP, { "XP", "asterix.048_RE_MD5_07_XP", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_MD5_07_XP), 0x20, NULL, HFILL } },
        { &hf_048_RE_MD5_07_X5, { "X5", "asterix.048_RE_MD5_07_X5", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_MD5_07_X5), 0x10, NULL, HFILL } },
        { &hf_048_RE_MD5_07_XC, { "XC", "asterix.048_RE_MD5_07_XC", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_MD5_07_XC), 0x08, NULL, HFILL } },
        { &hf_048_RE_MD5_07_X3, { "X3", "asterix.048_RE_MD5_07_X3", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_MD5_07_X3), 0x04, NULL, HFILL } },
        { &hf_048_RE_MD5_07_X2, { "X2", "asterix.048_RE_MD5_07_X2", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_MD5_07_X2), 0x02, NULL, HFILL } },
        { &hf_048_RE_MD5_07_X1, { "X1", "asterix.048_RE_MD5_07_X1", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_MD5_07_X1), 0x01, NULL, HFILL } },
        { &hf_048_RE_M5N, { "M5N, Mode 5 Reports, New Format", "asterix.048_RE_M5N", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_M5N_01, { "#1: Mode 5 Summary", "asterix.048_RE_M5N_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_M5N_01_M5, { "M5", "asterix.048_RE_M5N_01_M5", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_M5N_01_M5), 0x80, NULL, HFILL } },
        { &hf_048_RE_M5N_01_ID, { "ID", "asterix.048_RE_M5N_01_ID", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_M5N_01_ID), 0x40, NULL, HFILL } },
        { &hf_048_RE_M5N_01_DA, { "DA", "asterix.048_RE_M5N_01_DA", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_M5N_01_DA), 0x20, NULL, HFILL } },
        { &hf_048_RE_M5N_01_M1, { "M1", "asterix.048_RE_M5N_01_M1", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_M5N_01_M1), 0x10, NULL, HFILL } },
        { &hf_048_RE_M5N_01_M2, { "M2", "asterix.048_RE_M5N_01_M2", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_M5N_01_M2), 0x08, NULL, HFILL } },
        { &hf_048_RE_M5N_01_M3, { "M3", "asterix.048_RE_M5N_01_M3", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_M5N_01_M3), 0x04, NULL, HFILL } },
        { &hf_048_RE_M5N_01_MC, { "MC", "asterix.048_RE_M5N_01_MC", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_M5N_01_MC), 0x02, NULL, HFILL } },
        { &hf_048_RE_M5N_02, { "#2: Mode 5 PIN /National Origin/ Mission Code", "asterix.048_RE_M5N_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_M5N_02_PIN, { "PIN", "asterix.048_RE_M5N_02_PIN", FT_UINT32, BASE_DEC, NULL, 0x3fff0000, NULL, HFILL } },
        { &hf_048_RE_M5N_02_NOV, { "NOV", "asterix.048_RE_M5N_02_NOV", FT_UINT32, BASE_DEC, VALS (valstr_048_RE_M5N_02_NOV), 0x00000800, NULL, HFILL } },
        { &hf_048_RE_M5N_02_NO, { "NO", "asterix.048_RE_M5N_02_NO", FT_UINT32, BASE_DEC, NULL, 0x000007ff, NULL, HFILL } },
        { &hf_048_RE_M5N_03, { "#3: Mode 5 Reported Position", "asterix.048_RE_M5N_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_M5N_03_LAT, { "LAT[deg]", "asterix.048_RE_M5N_03_LAT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_M5N_03_LON, { "LON[deg]", "asterix.048_RE_M5N_03_LON", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_M5N_04, { "#4: Mode 5 GNSS-derived Altitude", "asterix.048_RE_M5N_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_M5N_04_RES, { "RES", "asterix.048_RE_M5N_04_RES", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_M5N_04_RES), 0x40, NULL, HFILL } },
        { &hf_048_RE_M5N_04_GA, { "GA[ft]", "asterix.048_RE_M5N_04_GA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_M5N_05, { "#5: Extended Mode 1 Code in Octal Representation", "asterix.048_RE_M5N_05", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_M5N_05_V, { "V", "asterix.048_RE_M5N_05_V", FT_UINT16, BASE_DEC, VALS (valstr_048_RE_M5N_05_V), 0x8000, NULL, HFILL } },
        { &hf_048_RE_M5N_05_G, { "G", "asterix.048_RE_M5N_05_G", FT_UINT16, BASE_DEC, VALS (valstr_048_RE_M5N_05_G), 0x4000, NULL, HFILL } },
        { &hf_048_RE_M5N_05_L, { "L", "asterix.048_RE_M5N_05_L", FT_UINT16, BASE_DEC, VALS (valstr_048_RE_M5N_05_L), 0x2000, NULL, HFILL } },
        { &hf_048_RE_M5N_05_SQUAWK, { "SQUAWK", "asterix.048_RE_M5N_05_SQUAWK", FT_UINT16, BASE_OCT, NULL, 0x0fff, NULL, HFILL } },
        { &hf_048_RE_M5N_06, { "#6: Time Offset for POS and GA", "asterix.048_RE_M5N_06", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_M5N_06_TOS, { "TOS[s]", "asterix.048_RE_M5N_06_TOS", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_M5N_07, { "#7: X Pulse Presence", "asterix.048_RE_M5N_07", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_M5N_07_XP, { "XP", "asterix.048_RE_M5N_07_XP", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_M5N_07_XP), 0x20, NULL, HFILL } },
        { &hf_048_RE_M5N_07_X5, { "X5", "asterix.048_RE_M5N_07_X5", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_M5N_07_X5), 0x10, NULL, HFILL } },
        { &hf_048_RE_M5N_07_XC, { "XC", "asterix.048_RE_M5N_07_XC", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_M5N_07_XC), 0x08, NULL, HFILL } },
        { &hf_048_RE_M5N_07_X3, { "X3", "asterix.048_RE_M5N_07_X3", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_M5N_07_X3), 0x04, NULL, HFILL } },
        { &hf_048_RE_M5N_07_X2, { "X2", "asterix.048_RE_M5N_07_X2", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_M5N_07_X2), 0x02, NULL, HFILL } },
        { &hf_048_RE_M5N_07_X1, { "X1", "asterix.048_RE_M5N_07_X1", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_M5N_07_X1), 0x01, NULL, HFILL } },
        { &hf_048_RE_M5N_08, { "#8, Figure of Merit", "asterix.048_RE_M5N_08", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_M5N_08_FOM, { "FOM", "asterix.048_RE_M5N_08_FOM", FT_UINT8, BASE_DEC, NULL, 0x1f, NULL, HFILL } },
        { &hf_048_RE_M4E, { "M4E, Extended Mode 4 Report", "asterix.048_RE_M4E", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_M4E_FOE_FRI, { "FOE/FRI", "asterix.048_RE_M4E_FOE_FRI", FT_UINT8, BASE_DEC, VALS (valstr_048_RE_M4E_FOE_FRI), 0x06, NULL, HFILL } },
        { &hf_048_RE_RPC, { "RPC, Radar Plot Characteristics", "asterix.048_RE_RPC", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_RPC_01, { "#1: Score", "asterix.048_RE_RPC_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_RPC_01_SCO, { "SCO", "asterix.048_RE_RPC_01_SCO", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_RPC_02, { "#2: Signal / Clutter Ratio", "asterix.048_RE_RPC_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_RPC_02_SCR, { "SCR[dB]", "asterix.048_RE_RPC_02_SCR", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_RPC_03, { "#3: Range Width", "asterix.048_RE_RPC_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_RPC_03_RW, { "RW[NM]", "asterix.048_RE_RPC_03_RW", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_RPC_04, { "#4: Ambiguous Range", "asterix.048_RE_RPC_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_RPC_04_AR, { "AR[NM]", "asterix.048_RE_RPC_04_AR", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_ERR, { "ERR, Extended Range Report", "asterix.048_RE_ERR", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_RE_ERR_RHO, { "RHO[NM]", "asterix.048_RE_ERR_RHO", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_048_SP, { "Special Purpose Field", "asterix.048_SP", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        /* Category 062*/
        { &hf_062_010, { "010, Data Source Identifier", "asterix.062_010", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_015, { "015, Service Identification", "asterix.062_015", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_015_SI, { "SI", "asterix.062_015_SI", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_062_040, { "040, Track Number", "asterix.062_040", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_060, { "060, Track Mode 3/A Code", "asterix.062_060", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_060_V, { "V", "asterix.062_060_V", FT_UINT16, BASE_DEC, VALS (valstr_062_060_V), 0x8000, "Validated", HFILL } },
        { &hf_062_060_G, { "G", "asterix.062_060_G", FT_UINT16, BASE_DEC, VALS (valstr_062_060_G), 0x4000, "Garbled", HFILL } },
        { &hf_062_060_CH, { "CH", "asterix.062_060_CH", FT_UINT16, BASE_DEC, VALS (valstr_062_060_CH), 0x2000, "Change in Mode 3/A", HFILL } },
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
        { &hf_062_080_SDS, { "SDS", "asterix.062_080_SDS", FT_UINT8, BASE_DEC, VALS (valstr_062_080_SDS), 0xc0, NULL, HFILL } },
        { &hf_062_080_EMS, { "EMS", "asterix.062_080_EMS", FT_UINT8, BASE_DEC, VALS (valstr_062_080_EMS), 0x38, NULL, HFILL } },
        { &hf_062_080_PFT, { "PFT", "asterix.062_080_PFT", FT_UINT8, BASE_DEC, VALS (valstr_062_080_PFT), 0x04, NULL, HFILL } },
        { &hf_062_080_FPLT, { "FPLT", "asterix.062_080_FPLT", FT_UINT8, BASE_DEC, VALS (valstr_062_080_FPLT), 0x02, NULL, HFILL } },
        { &hf_062_080_DUPT, { "DUPT", "asterix.062_080_DUPT", FT_UINT8, BASE_DEC, VALS (valstr_062_080_DUPT), 0x80, NULL, HFILL } },
        { &hf_062_080_DUPF, { "DUPF", "asterix.062_080_DUPF", FT_UINT8, BASE_DEC, VALS (valstr_062_080_DUPF), 0x40, NULL, HFILL } },
        { &hf_062_080_DUPM, { "DUPM", "asterix.062_080_DUPM", FT_UINT8, BASE_DEC, VALS (valstr_062_080_DUPM), 0x20, NULL, HFILL } },
        { &hf_062_080_SFC, { "SFC", "asterix.062_080_SFC", FT_UINT8, BASE_DEC, VALS (valstr_062_080_SFC), 0x10, NULL, HFILL } },
        { &hf_062_080_IDD, { "IDD", "asterix.062_080_IDD", FT_UINT8, BASE_DEC, VALS (valstr_062_080_IDD), 0x08, NULL, HFILL } },
        { &hf_062_080_IEC, { "IEC", "asterix.062_080_IEC", FT_UINT8, BASE_DEC, VALS (valstr_062_080_IEC), 0x04, NULL, HFILL } },
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
        { &hf_062_110_01_M5, { "M5", "asterix.062_110_01_M5", FT_UINT8, BASE_DEC, VALS (valstr_062_110_01_M5), 0x80, NULL, HFILL } },
        { &hf_062_110_01_ID, { "ID", "asterix.062_110_01_ID", FT_UINT8, BASE_DEC, VALS (valstr_062_110_01_ID), 0x40, NULL, HFILL } },
        { &hf_062_110_01_DA, { "DA", "asterix.062_110_01_DA", FT_UINT8, BASE_DEC, VALS (valstr_062_110_01_DA), 0x20, NULL, HFILL } },
        { &hf_062_110_01_M1, { "M1", "asterix.062_110_01_M1", FT_UINT8, BASE_DEC, VALS (valstr_062_110_01_M1), 0x10, NULL, HFILL } },
        { &hf_062_110_01_M2, { "M2", "asterix.062_110_01_M2", FT_UINT8, BASE_DEC, VALS (valstr_062_110_01_M2), 0x08, NULL, HFILL } },
        { &hf_062_110_01_M3, { "M3", "asterix.062_110_01_M3", FT_UINT8, BASE_DEC, VALS (valstr_062_110_01_M3), 0x04, NULL, HFILL } },
        { &hf_062_110_01_MC, { "MC", "asterix.062_110_01_MC", FT_UINT8, BASE_DEC, VALS (valstr_062_110_01_MC), 0x02, NULL, HFILL } },
        { &hf_062_110_01_X, { "X", "asterix.062_110_01_X", FT_UINT8, BASE_DEC, VALS (valstr_062_110_01_X), 0x01, NULL, HFILL } },
        { &hf_062_110_02, { "#2: Mode 5 PIN /National Origin/ Mission Code", "asterix.062_110_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_110_02_PIN, { "PIN", "asterix.062_110_02_PIN", FT_UINT32, BASE_DEC, NULL, 0x3fff0000, NULL, HFILL } },
        { &hf_062_110_02_NAT, { "NAT", "asterix.062_110_02_NAT", FT_UINT32, BASE_DEC, NULL, 0x00001f00, NULL, HFILL } },
        { &hf_062_110_02_MIS, { "MIS", "asterix.062_110_02_MIS", FT_UINT32, BASE_DEC, NULL, 0x0000003f, NULL, HFILL } },
        { &hf_062_110_03, { "#3: Mode 5 Reported Position", "asterix.062_110_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_110_03_LAT, { "LAT[deg]", "asterix.062_110_03_LAT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_110_03_LON, { "LON[deg]", "asterix.062_110_03_LON", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_110_04, { "#4: Mode 5 GNSS-derived Altitude", "asterix.062_110_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_110_04_RES, { "RES", "asterix.062_110_04_RES", FT_UINT8, BASE_DEC, VALS (valstr_062_110_04_RES), 0x40, NULL, HFILL } },
        { &hf_062_110_04_GA, { "GA[feet]", "asterix.062_110_04_GA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_110_05, { "#5: Extended Mode 1 Code in Octal Representation", "asterix.062_110_05", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_110_05_SQUAWK, { "SQUAWK", "asterix.062_110_05_SQUAWK", FT_UINT16, BASE_OCT, NULL, 0x0fff, NULL, HFILL } },
        { &hf_062_110_06, { "#6: Time Offset for POS and GA", "asterix.062_110_06", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
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
        { &hf_062_136_MFL, { "Measured Flight Level[FL]", "asterix.062_136_MFL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
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
        { &hf_062_245_STI, { "STI", "asterix.062_245_STI", FT_UINT8, BASE_DEC, VALS (valstr_062_245_STI), 0xc0, NULL, HFILL } },
        { &hf_062_270, { "270, Target Size & Orientation", "asterix.062_270", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_270_LENGTH, { "Length[m]", "asterix.062_270_LENGTH", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_270_ORIENTATION, { "Orientation[m]", "asterix.062_270_ORIENTATION", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_270_WIDTH, { "Width[m]", "asterix.062_270_WIDTH", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_290, { "290, System Track Update Ages", "asterix.062_290", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
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
        { &hf_062_295_07_MHG, { "MHG[s]", "asterix.062_295_07_MHG", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
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
        { &hf_062_340_04, { "#4: Last Measured Mode C Code", "asterix.062_340_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_340_04_V, { "V", "asterix.062_340_04_V", FT_UINT8, BASE_DEC, VALS (valstr_062_340_04_V), 0x80, NULL, HFILL } },
        { &hf_062_340_04_G, { "G", "asterix.062_340_04_G", FT_UINT8, BASE_DEC, VALS (valstr_062_340_04_G), 0x40, NULL, HFILL } },
        { &hf_062_340_04_FL, { "HEIGHT[FL]", "asterix.062_340_04_FL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_340_05, { "#5: Last Measured Mode 3/A Code", "asterix.062_340_05", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_340_05_V, { "V", "asterix.062_340_05_V", FT_UINT16, BASE_DEC, VALS (valstr_062_340_05_V), 0x8000, NULL, HFILL } },
        { &hf_062_340_05_G, { "G", "asterix.062_340_05_G", FT_UINT16, BASE_DEC, VALS (valstr_062_340_05_G), 0x4000, NULL, HFILL } },
        { &hf_062_340_05_L, { "L", "asterix.062_340_05_L", FT_UINT16, BASE_DEC, VALS (valstr_062_340_05_L), 0x2000, NULL, HFILL } },
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
        { &hf_062_380_04, { "#4: Indicated Airspeed / Mach No", "asterix.062_380_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
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
        { &hf_062_380_09_NC, { "NC", "asterix.062_380_09_NC", FT_UINT8, BASE_DEC, VALS (valstr_062_380_09_NC), 0x40, NULL, HFILL } },
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
        { &hf_062_380_10_COM, { "COM", "asterix.062_380_10_COM", FT_UINT16, BASE_DEC, VALS (valstr_062_380_10_COM), 0xe000, NULL, HFILL } },
        { &hf_062_380_10_STAT, { "STAT", "asterix.062_380_10_STAT", FT_UINT16, BASE_DEC, VALS (valstr_062_380_10_STAT), 0x1c00, NULL, HFILL } },
        { &hf_062_380_10_SSC, { "SSC", "asterix.062_380_10_SSC", FT_UINT16, BASE_DEC, VALS (valstr_062_380_10_SSC), 0x0080, NULL, HFILL } },
        { &hf_062_380_10_ARC, { "ARC", "asterix.062_380_10_ARC", FT_UINT16, BASE_DEC, VALS (valstr_062_380_10_ARC), 0x0040, NULL, HFILL } },
        { &hf_062_380_10_AIC, { "AIC", "asterix.062_380_10_AIC", FT_UINT16, BASE_DEC, VALS (valstr_062_380_10_AIC), 0x0020, NULL, HFILL } },
        { &hf_062_380_10_B1A, { "B1A", "asterix.062_380_10_B1A", FT_UINT16, BASE_DEC, NULL, 0x0010, NULL, HFILL } },
        { &hf_062_380_10_B1B, { "B1B", "asterix.062_380_10_B1B", FT_UINT16, BASE_DEC, NULL, 0x000f, NULL, HFILL } },
        { &hf_062_380_11, { "#11: Status reported by ADS-B", "asterix.062_380_11", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_380_11_AC, { "AC", "asterix.062_380_11_AC", FT_UINT16, BASE_DEC, VALS (valstr_062_380_11_AC), 0xc000, NULL, HFILL } },
        { &hf_062_380_11_MN, { "MN", "asterix.062_380_11_MN", FT_UINT16, BASE_DEC, VALS (valstr_062_380_11_MN), 0x3000, NULL, HFILL } },
        { &hf_062_380_11_DC, { "DC", "asterix.062_380_11_DC", FT_UINT16, BASE_DEC, VALS (valstr_062_380_11_DC), 0x0c00, NULL, HFILL } },
        { &hf_062_380_11_GBS, { "GBS", "asterix.062_380_11_GBS", FT_UINT16, BASE_DEC, VALS (valstr_062_380_11_GBS), 0x0200, NULL, HFILL } },
        { &hf_062_380_11_STAT, { "STAT", "asterix.062_380_11_STAT", FT_UINT16, BASE_DEC, VALS (valstr_062_380_11_STAT), 0x0007, NULL, HFILL } },
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
        { &hf_062_390_01, { "#1: FPPS Identification Tag", "asterix.062_390_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_02, { "#2: Callsign", "asterix.062_390_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_02_CS, { "CS", "asterix.062_390_02_CS", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_03, { "#3: IFPS_FLIGHT_ID", "asterix.062_390_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_03_TYP, { "TYP", "asterix.062_390_03_TYP", FT_UINT32, BASE_DEC, VALS (valstr_062_390_03_TYP), 0xc0000000, NULL, HFILL } },
        { &hf_062_390_03_NBR, { "NBR", "asterix.062_390_03_NBR", FT_UINT32, BASE_DEC, NULL, 0x07ffffff, NULL, HFILL } },
        { &hf_062_390_04, { "#4: Flight Category", "asterix.062_390_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_04_GAT_OAT, { "GAT/OAT", "asterix.062_390_04_GAT_OAT", FT_UINT8, BASE_DEC, VALS (valstr_062_390_04_GAT_OAT), 0xc0, NULL, HFILL } },
        { &hf_062_390_04_FR12, { "FR1/FR2", "asterix.062_390_04_FR12", FT_UINT8, BASE_DEC, VALS (valstr_062_390_04_FR12), 0x30, NULL, HFILL } },
        { &hf_062_390_04_RVSM, { "RVSM", "asterix.062_390_04_RVSM", FT_UINT8, BASE_DEC, VALS (valstr_062_390_04_RVSM), 0x0c, NULL, HFILL } },
        { &hf_062_390_04_HPR, { "HPR", "asterix.062_390_04_HPR", FT_UINT8, BASE_DEC, VALS (valstr_062_390_04_HPR), 0x02, NULL, HFILL } },
        { &hf_062_390_05, { "#5: Type of Aircraft", "asterix.062_390_05", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_05_ACTYP, { "ACTYP", "asterix.062_390_05_ACTYP", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_06, { "#6: Wake Turbulence Category", "asterix.062_390_06", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_06_WTC, { "WTC", "asterix.062_390_06_WTC", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_07, { "#7: Departure Airport", "asterix.062_390_07", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_07_ADEP, { "ADEP", "asterix.062_390_07_ADEP", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_08, { "#8: Destination Airport", "asterix.062_390_08", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_08_ADES, { "ADES", "asterix.062_390_08_ADES", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_09, { "#9: Runway Designation", "asterix.062_390_09", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_09_RWY, { "RWY", "asterix.062_390_09_RWY", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_10, { "#10: Current Cleared Flight Level", "asterix.062_390_10", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_10_CFL, { "CFL[FL]", "asterix.062_390_10_CFL", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_11, { "#11: Current Control Position", "asterix.062_390_11", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_11_CNTR, { "CNTR", "asterix.062_390_11_CNTR", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_11_POS, { "POS", "asterix.062_390_11_POS", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_12, { "#12: Time of Departure / Arrival", "asterix.062_390_12", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_12_TYP, { "TYP", "asterix.062_390_12_TYP", FT_UINT32, BASE_DEC, VALS (valstr_062_390_12_TYP), 0xf8000000, NULL, HFILL } },
        { &hf_062_390_12_DAY, { "DAY", "asterix.062_390_12_DAY", FT_UINT32, BASE_DEC, VALS (valstr_062_390_12_DAY), 0x06000000, NULL, HFILL } },
        { &hf_062_390_12_HOR, { "HOUR", "asterix.062_390_12_HOR", FT_UINT32, BASE_DEC, NULL, 0x001f0000, NULL, HFILL } },
        { &hf_062_390_12_MIN, { "MIN", "asterix.062_390_12_MIN", FT_UINT32, BASE_DEC, NULL, 0x00003f00, NULL, HFILL } },
        { &hf_062_390_12_AVS, { "AVS", "asterix.062_390_12_AVS", FT_UINT32, BASE_DEC, VALS (valstr_062_390_12_AVS), 0x00000080, NULL, HFILL } },
        { &hf_062_390_12_SEC, { "SEC", "asterix.062_390_12_SEC", FT_UINT32, BASE_DEC, NULL, 0x0000003f, NULL, HFILL } },
        { &hf_062_390_13, { "#13: Aircraft Stand", "asterix.062_390_13", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_13_STAND, { "STAND", "asterix.062_390_13_STAND", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_14, { "#14: Stand Status", "asterix.062_390_14", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_14_EMP, { "EMP", "asterix.062_390_14_EMP", FT_UINT8, BASE_DEC, VALS (valstr_062_390_14_EMP), 0xc0, NULL, HFILL } },
        { &hf_062_390_14_AVL, { "AVL", "asterix.062_390_14_AVL", FT_UINT8, BASE_DEC, VALS (valstr_062_390_14_AVL), 0x30, NULL, HFILL } },
        { &hf_062_390_15, { "#15: Standard Instrument Departure", "asterix.062_390_15", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_15_SID, { "SID", "asterix.062_390_15_SID", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_16, { "#16: Standard Instrument Arrival", "asterix.062_390_16", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_16_STAR, { "STAR", "asterix.062_390_16_STAR", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_17, { "#17: Pre-Emergency Mode 3/A", "asterix.062_390_17", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_17_VA, { "VA", "asterix.062_390_17_VA", FT_UINT16, BASE_DEC, VALS (valstr_062_390_17_VA), 0x1000, NULL, HFILL } },
        { &hf_062_390_17_SQUAWK, { "SQUAWK", "asterix.062_390_17_SQUAWK", FT_UINT16, BASE_OCT, NULL, 0x0fff, NULL, HFILL } },
        { &hf_062_390_18, { "#18: Pre-Emergency Callsign", "asterix.062_390_18", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_390_18_CS, { "CS", "asterix.062_390_18_CS", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500, { "500, Estimated Accuracies", "asterix.062_500", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_01, { "#1: Estimated Accuracy Of Track Position (Cartesian)", "asterix.062_500_01", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_01_APCX, { "APC X[m]", "asterix.062_500_01_APCX", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_01_APCY, { "APC Y[m]", "asterix.062_500_01_APCY", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_02, { "#2: XY covariance component", "asterix.062_500_02", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_02_COV, { "COV[m]", "asterix.062_500_02_COV", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_03, { "#3: Estimated Accuracy Of Track Position (WGS-84)", "asterix.062_500_03", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_03_APWLAT, { "APW LAT[deg]", "asterix.062_500_03_APWLAT", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_03_APWLON, { "APW LON[deg]", "asterix.062_500_03_APWLON", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_04, { "#4: Estimated Accuracy Of Calculated Track Geometric Altitude", "asterix.062_500_04", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_04_AGA, { "AGA[feet]", "asterix.062_500_04_AGA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_05, { "#5: Estimated Accuracy Of Calculated Track Barometric Altitude", "asterix.062_500_05", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_05_ABA, { "ABA[FL]", "asterix.062_500_05_ABA", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_06, { "#6: ", "asterix.062_500_06", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_06_ATVX, { "ATV X[m/s]", "asterix.062_500_06_ATVX", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_06_ATVY, { "ATV Y[m/s]", "asterix.062_500_06_ATVY", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_07, { "#7: Estimated Accuracy Of Acceleration (Cartesian)", "asterix.062_500_07", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_07_AAX, { "AA X[m/s^2]", "asterix.062_500_07_AAX", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_07_AAY, { "AA X[m/s^2]", "asterix.062_500_07_AAY", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_500_08, { "#8: Estimated Accuracy Of Rate Of Climb/Descent", "asterix.062_500_08", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
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
        { &hf_062_510_SUD, { "SUD", "asterix.062_510_SUD", FT_UINT24, BASE_DEC, NULL, 0xff0000, NULL, HFILL } },
        { &hf_062_510_STN, { "STN", "asterix.062_510_STN", FT_UINT24, BASE_DEC, NULL, 0x00fffe, NULL, HFILL } },
        { &hf_062_510_SLV_01_SUD, { "SLV1_SUD", "asterix.062_510_SLV_01_SUD", FT_UINT24, BASE_DEC, NULL, 0xff0000, NULL, HFILL } },
        { &hf_062_510_SLV_01_STN, { "SLV1_STN", "asterix.062_510_SLV_01_STN", FT_UINT24, BASE_DEC, NULL, 0x00fffe, NULL, HFILL } },
        { &hf_062_510_SLV_02_SUD, { "SLV2_SUD", "asterix.062_510_SLV_02_SUD", FT_UINT24, BASE_DEC, NULL, 0xff0000, NULL, HFILL } },
        { &hf_062_510_SLV_02_STN, { "SLV2_STN", "asterix.062_510_SLV_02_STN", FT_UINT24, BASE_DEC, NULL, 0x00fffe, NULL, HFILL } },
        { &hf_062_510_SLV_03_SUD, { "SLV3_SUD", "asterix.062_510_SLV_03_SUD", FT_UINT24, BASE_DEC, NULL, 0xff0000, NULL, HFILL } },
        { &hf_062_510_SLV_03_STN, { "SLV3_STN", "asterix.062_510_SLV_03_STN", FT_UINT24, BASE_DEC, NULL, 0x00fffe, NULL, HFILL } },
        { &hf_062_510_SLV_04_SUD, { "SLV4_SUD", "asterix.062_510_SLV_04_SUD", FT_UINT24, BASE_DEC, NULL, 0xff0000, NULL, HFILL } },
        { &hf_062_510_SLV_04_STN, { "SLV4_STN", "asterix.062_510_SLV_04_STN", FT_UINT24, BASE_DEC, NULL, 0x00fffe, NULL, HFILL } },
        { &hf_062_RE, { "Reserved Expansion Field", "asterix.062_RE", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_RE_CST, {"CST", "asterix.062_RE_CST", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_RE_CST_TYP, {"TYP", "asterix.062_RE_CST_TYP", FT_UINT24, BASE_DEC, VALS(valstr_062_RE_CST_TYPE), 0x0f0000, NULL, HFILL } },
        { &hf_062_RE_CST_TRK_NUM, {"TRK NUM", "asterix.062_RE_CST_TRK_NUM", FT_UINT24, BASE_DEC, NULL, 0x00ffff, NULL, HFILL } },
        { &hf_062_RE_CSNT, {"CSNT", "asterix.062_RE_CSNT", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_RE_CSNT_TYP, {"TYP", "asterix.062_RE_CSNT_TYP", FT_UINT8, BASE_DEC, VALS(valstr_062_RE_CST_TYPE), 0x0f, NULL, HFILL } },
        { &hf_062_RE_TVS, {"TVS", "asterix.062_RE_TVS", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_RE_TVS_VX, {"VX[m/s]", "asterix.062_RE_TVS_VX", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_RE_TVS_VY, {"VY[m/s]", "asterix.062_RE_TVS_VY", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_RE_STS, {"STS", "asterix.062_RE_STS", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_062_RE_STS_FDR, {"FDR", "asterix.062_RE_STS_FDR", FT_UINT8, BASE_DEC, VALS(valstr_062_RE_STS_FDR), 0x80, NULL, HFILL } },
        { &hf_062_SP, { "Special Purpose Field", "asterix.062_SP", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        /* Category 063 */
        { &hf_063_010, { "010, Data Source Identifier", "asterix.063_010", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_015, { "015, Service Identification", "asterix.063_015", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_015_SI, { "SI", "asterix.063_015_SI", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_063_030, { "030, Time of Message", "asterix.063_030", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_050, { "050, Sensor Identifier", "asterix.063_050", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_060, { "060, Sensor Configuration and Status", "asterix.063_060", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_060_CON, { "CON", "asterix.063_060_CON", FT_UINT8, BASE_DEC, VALS(valstr_063_060_CON), 0xc0, NULL, HFILL } },
        { &hf_063_060_PSR, { "PSR", "asterix.063_060_PSR", FT_UINT8, BASE_DEC, VALS(valstr_063_060_PSR), 0x20, NULL, HFILL } },
        { &hf_063_060_SSR, { "SSR", "asterix.063_060_SSR", FT_UINT8, BASE_DEC, VALS(valstr_063_060_SSR), 0x10, NULL, HFILL } },
        { &hf_063_060_MDS, { "MDS", "asterix.063_060_MDS", FT_UINT8, BASE_DEC, VALS(valstr_063_060_MDS), 0x08, NULL, HFILL } },
        { &hf_063_060_ADS, { "ADS", "asterix.063_060_ADS", FT_UINT8, BASE_DEC, VALS(valstr_063_060_ADS), 0x04, NULL, HFILL } },
        { &hf_063_060_MLT, { "MLT", "asterix.063_060_MLT", FT_UINT8, BASE_DEC, VALS(valstr_063_060_MLT), 0x02, NULL, HFILL } },
        { &hf_063_060_OPS, { "OPS", "asterix.063_060_OPS", FT_UINT8, BASE_DEC, VALS(valstr_063_060_OPS), 0x80, NULL, HFILL } },
        { &hf_063_060_ODP, { "ODP", "asterix.063_060_ODP", FT_UINT8, BASE_DEC, VALS(valstr_063_060_ODP), 0x40, NULL, HFILL } },
        { &hf_063_060_OXT, { "OXT", "asterix.063_060_OXT", FT_UINT8, BASE_DEC, VALS(valstr_063_060_OXT), 0x20, NULL, HFILL } },
        { &hf_063_060_MSC, { "MSC", "asterix.063_060_MSC", FT_UINT8, BASE_DEC, VALS(valstr_063_060_MSC), 0x10, NULL, HFILL } },
        { &hf_063_060_TSV, { "TSV", "asterix.063_060_TSV", FT_UINT8, BASE_DEC, VALS(valstr_063_060_TSV), 0x08, NULL, HFILL } },
        { &hf_063_060_NPW, { "NPW", "asterix.063_060_NPW", FT_UINT8, BASE_DEC, VALS(valstr_063_060_NPW), 0x04, NULL, HFILL } },
        { &hf_063_070, { "070, Time Stamping Bias", "asterix.063_070", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_070_TSB, {"TSB[ms]", "asterix.063_070_TSB", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_080, { "080, SSR / Mode S Range Gain and Bias", "asterix.063_080", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_080_SRG, {"SRG", "asterix.063_080_SRG", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_080_SRB, {"SRB", "asterix.063_080_SRB", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_081, { "081, SSR / Mode S Azimuth Bias", "asterix.063_081", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_081_SAB, {"SAB", "asterix.063_081_SAB", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_090, { "090, PSR Range Gain and Bias", "asterix.063_090", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_090_PRG, {"PRG", "asterix.063_090_PRG", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_090_PRB, {"PRB", "asterix.063_090_PRB", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_091, { "091, PSR Azimuth Bias", "asterix.063_091", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_091_PAB, {"PAB", "asterix.063_091_PAB", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_092, { "092, PSR Elevation Bias", "asterix.063_092", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_092_PEB, {"PEB", "asterix.063_092_PEB", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_RE, { "Reserved Expansion Field", "asterix.063_RE", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_063_SP, { "Special Purpose Field", "asterix.063_SP", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        /* Category 065 */
        { &hf_065_000, { "000, Message Type", "asterix.065_000", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_065_000_MT, { "MT", "asterix.065_000_MT", FT_UINT8, BASE_DEC, VALS(valstr_065_000_MT), 0x0, NULL, HFILL } },
        { &hf_065_010, { "010, Data Source Identifier", "asterix.065_010", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_065_015, { "015, Service Identification", "asterix.065_015", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_065_015_SI, { "SI", "asterix.065_015_SI", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_065_020, { "020, Batch Number", "asterix.065_020", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_065_020_BTN, { "BTN", "asterix.065_020_BTN", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_065_030, { "030, Time of Message", "asterix.065_030", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_065_040, { "040, SDPS Configuration and Status", "asterix.065_040", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_065_040_NOGO, { "NOGO", "asterix.065_040_NOGO", FT_UINT8, BASE_DEC, VALS(valstr_065_040_NOGO), 0xc0, NULL, HFILL } },
        { &hf_065_040_OVL, { "OVL", "asterix.065_040_OVL", FT_UINT8, BASE_DEC, VALS(valstr_065_040_OVL), 0x20, NULL, HFILL } },
        { &hf_065_040_TSV, { "TSV", "asterix.065_040_TSV", FT_UINT8, BASE_DEC, VALS(valstr_065_040_TSV), 0x10, NULL, HFILL } },
        { &hf_065_040_PSS, { "PSS", "asterix.065_040_PSS", FT_UINT8, BASE_DEC, VALS(valstr_065_040_PSS), 0x0c, NULL, HFILL } },
        { &hf_065_040_STTN, { "STTN", "asterix.065_040_STTN", FT_UINT8, BASE_DEC, VALS(valstr_065_040_STTN), 0x02, NULL, HFILL } },
        { &hf_065_050, { "050, Service Status Report", "asterix.065_050", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_065_050_REP, { "REP", "asterix.065_050_REP", FT_UINT8, BASE_DEC, VALS(valstr_065_050_REP), 0x0, NULL, HFILL } },
        { &hf_065_RE, { "Reserved Expansion Field", "asterix.065_RE", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_065_RE_SRP, { "SRP, Position of the System Reference Point (WGS-84)", "asterix.065_RE_SRP", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_065_RE_SRP_Latitude, { "Latitude [deg]", "asterix.065_RE_SRP_Latitude", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_065_RE_SRP_Longitude, { "Longitude [deg]", "asterix.065_RE_SRP_Longitude", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_065_RE_ARL, { "ARL, ASTERIX Record Length", "asterix.065_RE_ARL", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_065_RE_ARL_ARL, { "ARL", "asterix.065_RE_ARL_ARL", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_065_SP, { "Special Purpose Field", "asterix.065_SP", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_asterix,
        &ett_asterix_category,
        &ett_asterix_length,
        &ett_asterix_message,
        &ett_asterix_subtree
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

    asterix_prefs_module = prefs_register_protocol (proto_asterix, NULL);

    prefs_register_enum_preference (asterix_prefs_module, "i001_version", "I001 version", "Select the CAT001 version", &global_categories_version[1],  I001_versions, FALSE);
    prefs_register_enum_preference (asterix_prefs_module, "i002_version", "I002 version", "Select the CAT002 version", &global_categories_version[2],  I002_versions, FALSE);
    prefs_register_enum_preference (asterix_prefs_module, "i004_version", "I004 version", "Select the CAT004 version", &global_categories_version[4],  I004_versions, FALSE);
    prefs_register_enum_preference (asterix_prefs_module, "i008_version", "I008 version", "Select the CAT008 version", &global_categories_version[8],  I008_versions, FALSE);
    prefs_register_enum_preference (asterix_prefs_module, "i009_version", "I009 version", "Select the CAT009 version", &global_categories_version[9],  I009_versions, FALSE);
    prefs_register_enum_preference (asterix_prefs_module, "i010_version", "I010 version", "Select the CAT010 version", &global_categories_version[10], I010_versions, FALSE);
    prefs_register_enum_preference (asterix_prefs_module, "i011_version", "I011 version", "Select the CAT011 version", &global_categories_version[11], I011_versions, FALSE);
    prefs_register_enum_preference (asterix_prefs_module, "i019_version", "I019 version", "Select the CAT019 version", &global_categories_version[19], I019_versions, FALSE);
    prefs_register_enum_preference (asterix_prefs_module, "i020_version", "I020 version", "Select the CAT020 version", &global_categories_version[20], I020_versions, FALSE);
    prefs_register_enum_preference (asterix_prefs_module, "i021_version", "I021 version", "Select the CAT021 version", &global_categories_version[21], I021_versions, FALSE);
    prefs_register_enum_preference (asterix_prefs_module, "i023_version", "I023 version", "Select the CAT023 version", &global_categories_version[23], I023_versions, FALSE);
    prefs_register_enum_preference (asterix_prefs_module, "i025_version", "I025 version", "Select the CAT025 version", &global_categories_version[25], I025_versions, FALSE);
    prefs_register_enum_preference (asterix_prefs_module, "i032_version", "I032 version", "Select the CAT032 version", &global_categories_version[32], I032_versions, FALSE);
    prefs_register_enum_preference (asterix_prefs_module, "i034_version", "I034 version", "Select the CAT034 version", &global_categories_version[34], I034_versions, FALSE);
    prefs_register_enum_preference (asterix_prefs_module, "i048_version", "I048 version", "Select the CAT048 version", &global_categories_version[48], I048_versions, FALSE);
    prefs_register_enum_preference (asterix_prefs_module, "i062_version", "I062 version", "Select the CAT062 version", &global_categories_version[62], I062_versions, FALSE);
    prefs_register_enum_preference (asterix_prefs_module, "i063_version", "I063 version", "Select the CAT063 version", &global_categories_version[63], I063_versions, FALSE);
    prefs_register_enum_preference (asterix_prefs_module, "i065_version", "I065 version", "Select the CAT065 version", &global_categories_version[65], I065_versions, FALSE);
}

void proto_reg_handoff_asterix (void)
{
    dissector_add_uint_with_preference("udp.port", ASTERIX_PORT, asterix_handle);
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
