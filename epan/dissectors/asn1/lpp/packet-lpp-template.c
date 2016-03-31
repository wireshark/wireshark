/* packet-lpp.c
 * Routines for 3GPP LTE Positioning Protocol (LPP) packet dissection
 * Copyright 2011-2016 Pascal Quantin <pascal.quantin@gmail.com>
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
 *
 * Ref 3GPP TS 36.355 version 13.1.0 Release 13
 * http://www.3gpp.org
 */

#include "config.h"

#include "math.h"

#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/tfs.h>

#include "packet-per.h"
#include "packet-lpp.h"

#define PNAME  "LTE Positioning Protocol (LPP)"
#define PSNAME "LPP"
#define PFNAME "lpp"

void proto_register_lpp(void);
void proto_reg_handoff_lpp(void);

/* Initialize the protocol and registered fields */
static int proto_lpp = -1;

#include "packet-lpp-hf.c"
static int hf_lpp_svHealthExt_v1240_e5bhs = -1;
static int hf_lpp_svHealthExt_v1240_e1_bhs = -1;
static int hf_lpp_kepSV_StatusINAV_e5bhs = -1;
static int hf_lpp_kepSV_StatusINAV_e1_bhs = -1;
static int hf_lpp_kepSV_StatusFNAV_e5ahs = -1;
static int hf_lpp_bdsSvHealth_r12_sat_clock = -1;
static int hf_lpp_bdsSvHealth_r12_b1i = -1;
static int hf_lpp_bdsSvHealth_r12_b2i = -1;
static int hf_lpp_bdsSvHealth_r12_nav = -1;

static dissector_handle_t lppe_handle = NULL;

static guint32 lpp_epdu_id = -1;

/* Initialize the subtree pointers */
static gint ett_lpp = -1;
static gint ett_lpp_bitmap = -1;
static gint ett_lpp_svHealthExt_v1240 = -1;
static gint ett_kepSV_StatusINAV = -1;
static gint ett_kepSV_StatusFNAV = -1;
static gint ett_lpp_bdsSvHealth_r12 = -1;
#include "packet-lpp-ett.c"

/* Include constants */
#include "packet-lpp-val.h"

static const value_string lpp_ePDU_ID_vals[] = {
  { 1, "OMA LPP extensions (LPPe)"},
  { 0, NULL}
};

static void
lpp_degreesLatitude_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%f degrees (%u)",
             ((float)v/8388607.0)*90, v);
}

static void
lpp_degreesLongitude_fmt(gchar *s, guint32 v)
{
  gint32 longitude = (gint32) v;

  g_snprintf(s, ITEM_LABEL_LENGTH, "%f degrees (%d)",
             ((float)longitude/8388608.0)*180, longitude);
}

static void
lpp_uncertainty_fmt(gchar *s, guint32 v)
{
  double uncertainty = 10*(pow(1.1, (double)v)-1);

  if (uncertainty < 1000) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "%f m (%u)", uncertainty, v);
  } else {
    g_snprintf(s, ITEM_LABEL_LENGTH, "%f km (%u)", uncertainty/1000, v);
  }
}

static void
lpp_angle_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%u degrees (%u)", 2*v, v);
}

static void
lpp_confidence_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "no information (0)");
  } else {
    g_snprintf(s, ITEM_LABEL_LENGTH, "%u %%", v);
  }
}

static void
lpp_altitude_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%u m", v);
}

static void
lpp_uncertaintyAltitude_fmt(gchar *s, guint32 v)
{
  double uncertainty = 45*(pow(1.025, (double)v)-1);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%f m (%u)", uncertainty, v);
}

static void
lpp_radius_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%u m (%u)", 5*v, v);
}

static void
lpp_expectedRSTD_fmt(gchar *s, guint32 v)
{
  gint32 rstd = 3*((gint32)v-8192);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%d Ts (%u)", rstd, v);
}

static void
lpp_expectedRSTD_Uncertainty_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%u Ts (%u)", 3*v, v);
}

static void
lpp_rstd_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "RSTD < -15391 Ts (0)");
  } else if (v < 2260) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "-%u Ts <= RSTD < -%u Ts (%u)", 15391-5*(v-1), 15391-5*v, v);
  } else if (v < 6355) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "-%u Ts <= RSTD < -%u Ts (%u)", 6356-v, 6355-v, v);
  } else if (v == 6355) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "-1 Ts <= RSTD <= 0 Ts (6355)");
  } else if (v < 10452) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "%u Ts < RSTD <= %u Ts (%u)", v-6356, v-6355, v);
  } else if (v < 12711) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "%u Ts < RSTD <= %u Ts (%u)", 5*(v-1)-48159, 5*v-48159, v);
  } else {
    g_snprintf(s, ITEM_LABEL_LENGTH, "15391 Ts < RSTD (12711)");
  }
}

static const value_string lpp_error_Resolution_vals[] = {
  { 0, "5 meters"},
  { 1, "10 meters"},
  { 2, "20 meters"},
  { 3, "30 meters"},
  { 0, NULL}
};

static const value_string lpp_error_Value_vals[] = {
  {  0, "0 to (R*1-1) meters"},
  {  1, "R*1 to (R*2-1) meters"},
  {  2, "R*2 to (R*3-1) meters"},
  {  3, "R*3 to (R*4-1) meters"},
  {  4, "R*4 to (R*5-1) meters"},
  {  5, "R*5 to (R*6-1) meters"},
  {  6, "R*6 to (R*7-1) meters"},
  {  7, "R*7 to (R*8-1) meters"},
  {  8, "R*8 to (R*9-1) meters"},
  {  9, "R*9 to (R*10-1) meters"},
  { 10, "R*10 to (R*11-1) meters"},
  { 11, "R*11 to (R*12-1) meters"},
  { 12, "R*12 to (R*13-1) meters"},
  { 13, "R*13 to (R*14-1) meters"},
  { 14, "R*14 to (R*15-1) meters"},
  { 15, "R*15 to (R*16-1) meters"},
  { 16, "R*16 to (R*17-1) meters"},
  { 17, "R*17 to (R*18-1) meters"},
  { 18, "R*18 to (R*19-1) meters"},
  { 19, "R*19 to (R*20-1) meters"},
  { 20, "R*20 to (R*21-1) meters"},
  { 21, "R*21 to (R*22-1) meters"},
  { 22, "R*22 to (R*23-1) meters"},
  { 23, "R*23 to (R*24-1) meters"},
  { 24, "R*24 to (R*25-1) meters"},
  { 25, "R*25 to (R*26-1) meters"},
  { 26, "R*26 to (R*27-1) meters"},
  { 27, "R*27 to (R*28-1) meters"},
  { 28, "R*28 to (R*29-1) meters"},
  { 29, "R*29 to (R*30-1) meters"},
  { 30, "R*30 to (R*31-1) meters"},
  { 31, "R*31 meters or more"},
  { 0, NULL}
};
static value_string_ext lpp_error_Value_vals_ext = VALUE_STRING_EXT_INIT(lpp_error_Value_vals);

static const value_string lpp_error_NumSamples_vals[] = {
  {  0, "Not the baseline metric"},
  {  1, "5-9"},
  {  2, "10-14"},
  {  3, "15-24"},
  {  4, "25-34"},
  {  5, "35-44"},
  {  6, "45-54"},
  {  7, "55 or more"},
  { 0, NULL}
};

static void
lpp_referenceTimeUnc_fmt(gchar *s, guint32 v)
{
  double referenceTimeUnc = 0.5*(pow(1.14, (double)v)-1);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%f us (%u)", referenceTimeUnc, v);
}

static const value_string lpp_kp_vals[] = {
  { 0, "No UTC correction at the end of current quarter"},
  { 1, "UTC correction by plus (+1 s) in the end of current quarter"},
  { 3, "UTC correction by minus (-1 s) in the end of current quarter"},
  { 0, NULL}
};

static void
lpp_fractionalSecondsFromFrameStructureStart_fmt(gchar *s, guint32 v)
{
  float frac = ((float)v)/4;

  g_snprintf(s, ITEM_LABEL_LENGTH, "%f us (%u)", frac, v);
}

static void
lpp_frameDrift_fmt(gchar *s, guint32 v)
{
  double drift = (double)((gint32)v)*pow(2, -30);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s/s (%d)", drift, (gint32)v);
}

static const value_string lpp_dataID_vals[] = {
  { 0, "Parameters are applicable worldwide"},
  { 1, "Parameters have been generated by BDS"},
  { 3, "Parameters have been generated by QZSS"},
  { 0, NULL}
};

static void
lpp_alpha0_fmt(gchar *s, guint32 v)
{
  double alpha = (double)((gint32)v)*pow(2, -30);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s (%d)", alpha, (gint32)v);
}

static void
lpp_alpha1_fmt(gchar *s, guint32 v)
{
  double alpha = (double)((gint32)v)*pow(2, -27);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s/semi-circle (%d)", alpha, (gint32)v);
}

static void
lpp_alpha2_3_fmt(gchar *s, guint32 v)
{
  double alpha = (double)((gint32)v)*pow(2, -24);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s/semi-circle (%d)", alpha, (gint32)v);
}

static void
lpp_beta0_fmt(gchar *s, guint32 v)
{
  double beta = (double)((gint32)v)*pow(2, 11);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s (%d)", beta, (gint32)v);
}

static void
lpp_beta1_fmt(gchar *s, guint32 v)
{
  double beta = (double)((gint32)v)*pow(2, 14);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s/semi-circle (%d)", beta, (gint32)v);
}

static void
lpp_beta2_3_fmt(gchar *s, guint32 v)
{
  double beta = (double)((gint32)v)*pow(2, 16);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s/semi-circle (%d)", beta, (gint32)v);
}

static void
lpp_ai0_fmt(gchar *s, guint32 v)
{
  double ai = (double)v*pow(2, -2);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g sfu (%u)", ai, v);
}

static void
lpp_ai1_fmt(gchar *s, guint32 v)
{
  double ai = (double)v*pow(2, -8);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g sfu/degree (%u)", ai, v);
}

static void
lpp_ai2_fmt(gchar *s, guint32 v)
{
  double ai = (double)v*pow(2, -15);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g sfu/degree2 (%u)", ai, v);
}

static void
lpp_teop_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%u s (%u)", 16*v, v);
}

static void
lpp_pmX_Y_fmt(gchar *s, guint32 v)
{
  double pm = (double)((gint32)v)*pow(2, -20);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g arc-seconds (%d)", pm, (gint32)v);
}

static void
lpp_pmX_Ydot_fmt(gchar *s, guint32 v)
{
  double pmDot = (double)((gint32)v)*pow(2, -21);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g arc-seconds/day (%d)", pmDot, (gint32)v);
}

static void
lpp_deltaUT1_fmt(gchar *s, guint32 v)
{
  double deltaUT1 = (double)((gint32)v)*pow(2, -24);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s (%d)", deltaUT1, (gint32)v);
}

static void
lpp_deltaUT1dot_fmt(gchar *s, guint32 v)
{
  double deltaUT1dot = (double)((gint32)v)*pow(2, -25);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s/day (%d)", deltaUT1dot, (gint32)v);
}

static void
lpp_gnss_TimeModelRefTime_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%u s (%u)", v*16, v);
}

static void
lpp_tA0_fmt(gchar *s, guint32 v)
{
  double tA0 = (double)((gint32)v)*pow(2, -35);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s (%d)", tA0, (gint32)v);
}

static void
lpp_tA1_fmt(gchar *s, guint32 v)
{
  double tA1 = (double)((gint32)v)*pow(2, -51);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s/s (%d)", tA1, (gint32)v);
}

static void
lpp_tA2_fmt(gchar *s, guint32 v)
{
  double tA2 = (double)((gint32)v)*pow(2, -68);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s/s2 (%d)", tA2, (gint32)v);
}

static const value_string lpp_gnss_TO_ID_vals[] = {
  { 1, "GPS"},
  { 2, "Galileo"},
  { 3, "QZSS"},
  { 4, "GLONASS"},
  { 0, NULL}
};

static const value_string lpp_gnss_StatusHealth_vals[] = {
  { 0, "UDRE Scale Factor = 1.0"},
  { 1, "UDRE Scale Factor = 0.75"},
  { 2, "UDRE Scale Factor = 0.5"},
  { 3, "UDRE Scale Factor = 0.3"},
  { 4, "UDRE Scale Factor = 0.2"},
  { 5, "UDRE Scale Factor = 0.1"},
  { 6, "Reference Station Transmission Not Monitored"},
  { 7, "Data is invalid - disregard"},
  { 0, NULL}
};

static const value_string lpp_udre_vals[] = {
  { 0, "UDRE <= 1.0 m"},
  { 1, "1.0 m < UDRE <= 4.0 m"},
  { 2, "4.0 m < UDRE <= 8.0 m"},
  { 3, "8.0 m < UDRE"},
  { 0, NULL}
};

static void
lpp_pseudoRangeCor_fmt(gchar *s, guint32 v)
{
  double pseudoRangeCor = ((double)(gint32)v)*0.32;

  g_snprintf(s, ITEM_LABEL_LENGTH, "%f m (%d)", pseudoRangeCor, (gint32)v);
}

static void
lpp_rangeRateCor_fmt(gchar *s, guint32 v)
{
  double rangeRateCor = ((double)(gint32)v)*0.032;

  g_snprintf(s, ITEM_LABEL_LENGTH, "%f m/s (%d)", rangeRateCor, (gint32)v);
}

static const value_string lpp_udreGrowthRate_vals[] = {
  { 0, "1.5"},
  { 1, "2"},
  { 2, "4"},
  { 3, "6"},
  { 4, "8"},
  { 5, "10"},
  { 6, "12"},
  { 7, "16"},
  { 0, NULL}
};

static const value_string lpp_udreValidityTime_vals[] = {
  { 0, "20 s"},
  { 1, "40 s"},
  { 2, "80 s"},
  { 3, "160 s"},
  { 4, "320 s"},
  { 5, "640 s"},
  { 6, "1280 s"},
  { 7, "2560 s"},
  { 0, NULL}
};

static const value_string lpp_signal_health_status_vals[] = {
  { 0, "Signal OK"},
  { 1, "Signal out of service"},
  { 2, "Signal will be out of service"},
  { 3, "Signal Component currently in Test"},
  { 0, NULL}
};
static void
lpp_stanClockToc_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%u m/s (%u)", 60*v, v);
}

static void
lpp_stanClockAF2_fmt(gchar *s, guint32 v)
{
  double stanClockAF2 = (double)((gint32)v)*pow(2, -59);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s/s2 (%d)", stanClockAF2, (gint32)v);
}

static void
lpp_stanClockAF1_fmt(gchar *s, guint32 v)
{
  double stanClockAF1 = (double)((gint32)v)*pow(2, -46);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s/s (%d)", stanClockAF1, (gint32)v);
}

static void
lpp_stanClockAF0_fmt(gchar *s, guint32 v)
{
  double stanClockAF0 = (double)((gint32)v)*pow(2, -34);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s (%d)", stanClockAF0, (gint32)v);
}

static void
lpp_stanClockTgd_fmt(gchar *s, guint32 v)
{
  double stanClockTgd = (double)((gint32)v)*pow(2, -32);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s (%d)", stanClockTgd, (gint32)v);
}

static void
lpp_sisa_fmt(gchar *s, guint32 v)
{
  if (v < 50) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "%u cm (%u)", v, v);
  } else if (v < 75) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "%u cm (%u)", 50+((v-50)*2), v);
  } else if (v < 100) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "%u cm (%u)", 100+((v-75)*4), v);
  } else if (v < 126) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "%u cm (%u)", 200+((v-100)*16), v);
  } else if (v < 255) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "Spare (%u)", v);
  } else {
    g_snprintf(s, ITEM_LABEL_LENGTH, "No Accuracy Prediction Available (255)");
  }
}

static const value_string lpp_stanModelID_vals[] = {
  { 0, "I/Nav"},
  { 1, "F/Nav"},
  { 0, NULL}
};

static void
lpp_navToc_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%u s (%u)", 16*v, v);
}

static void
lpp_navaf2_fmt(gchar *s, guint32 v)
{
  double navaf2 = (double)((gint32)v)*pow(2, -55);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s/s2 (%d)", navaf2, (gint32)v);
}

static void
lpp_navaf1_fmt(gchar *s, guint32 v)
{
  double navaf1 = (double)((gint32)v)*pow(2, -43);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s/s (%d)", navaf1, (gint32)v);
}

static void
lpp_navaf0_navTgd_fmt(gchar *s, guint32 v)
{
  double navaf0_navTgd = (double)((gint32)v)*pow(2, -31);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s/s (%d)", navaf0_navTgd, (gint32)v);
}

static void
lpp_cnavToc_cnavTop_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%u s (%u)", 300*v, v);
}

static void
lpp_cnavAf2_fmt(gchar *s, guint32 v)
{
  double cnavAf2 = (double)((gint32)v)*pow(2, -60);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s/s2 (%d)", cnavAf2, (gint32)v);
}

static void
lpp_cnavAf1_fmt(gchar *s, guint32 v)
{
  double cnavAf1 = (double)((gint32)v)*pow(2, -48);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s/s (%d)", cnavAf1, (gint32)v);
}

static void
lpp_cnavX_fmt(gchar *s, guint32 v)
{
  double cnavX = (double)((gint32)v)*pow(2, -35);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s (%d)", cnavX, (gint32)v);
}

static void
lpp_gloTau_gloDeltaTau_fmt(gchar *s, guint32 v)
{
  double gloTau_gloDeltaTau = (double)((gint32)v)*pow(2, -30);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s (%d)", gloTau_gloDeltaTau, (gint32)v);
}

static void
lpp_gloGamma_fmt(gchar *s, guint32 v)
{
  double gloGamma = (double)((gint32)v)*pow(2, -40);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g (%d)", gloGamma, (gint32)v);
}

static void
lpp_sbasTo_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%u s (%u)", 16*v, v);
}

static void
lpp_sbasAgfo_fmt(gchar *s, guint32 v)
{
  double sbasAgfo = (double)((gint32)v)*pow(2, -31);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s (%d)", sbasAgfo, (gint32)v);
}

static void
lpp_sbasAgf1_fmt(gchar *s, guint32 v)
{
  double sbasAgf1 = (double)((gint32)v)*pow(2, -40);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s/s (%d)", sbasAgf1, (gint32)v);
}

static void
lpp_bdsAODC_AODE_r12_fmt(gchar *s, guint32 v)
{
  if (v < 25) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "Age of the satellite clock correction parameters is %u hours (%u)", v, v);
  } else if (v < 31) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "Age of the satellite clock correction parameters is %u days (%u)", v-23, v);
  } else {
    g_snprintf(s, ITEM_LABEL_LENGTH, "Age of the satellite clock correction parameters is over 7 days (%u)", v);
  }
}


static void
lpp_bdsToc_Toe_r12_fmt(gchar *s, guint32 v)
{
  double bdsToc = (double)((gint32)v)*pow(2, 3);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s (%d)", bdsToc, (gint32)v);
}

static void
lpp_bdsA0_r12_fmt(gchar *s, guint32 v)
{
  double bdsA0 = (double)((gint32)v)*pow(2, -33);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s (%d)", bdsA0, (gint32)v);
}

static void
lpp_bdsA1_r12_fmt(gchar *s, guint32 v)
{
  double bdsA1 = (double)((gint32)v)*pow(2, -50);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s/s (%d)", bdsA1, (gint32)v);
}

static void
lpp_bdsA2_r12_fmt(gchar *s, guint32 v)
{
  double bdsA2 = (double)((gint32)v)*pow(2, -66);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s/s2 (%d)", bdsA2, (gint32)v);
}

static void
lpp_bdsTgd1_r12_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%g ns (%d)", (float)((gint32)v)*0.1, (gint32)v);
}

static void
lpp_keplerToe_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%u s (%u)", 60*v, v);
}

static void
lpp_keplerW_M0_I0_Omega0_fmt(gchar *s, guint32 v)
{
  double keplerW_M0_I0_Omega0 = (double)((gint32)v)*pow(2, -31);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles (%d)", keplerW_M0_I0_Omega0, (gint32)v);
}

static void
lpp_keplerDeltaN_OmegaDot_IDot_fmt(gchar *s, guint32 v)
{
  double keplerDeltaN_OmegaDot_IDot = (double)((gint32)v)*pow(2, -43);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles/s (%d)", keplerDeltaN_OmegaDot_IDot, (gint32)v);
}

static void
lpp_keplerE_fmt(gchar *s, guint32 v)
{
  double keplerE = (double)v*pow(2, -33);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g (%u)", keplerE, v);
}

static void
lpp_keplerAPowerHalf_fmt(gchar *s, guint32 v)
{
  double keplerAPowerHalf = (double)v*pow(2, -19);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g m1/2 (%u)", keplerAPowerHalf, v);
}

static void
lpp_keplerCrs_Crc_fmt(gchar *s, guint32 v)
{
  double keplerCrs_Crc = (double)((gint32)v)*pow(2, -5);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g m (%d)", keplerCrs_Crc, (gint32)v);
}

static void
lpp_keplerCx_fmt(gchar *s, guint32 v)
{
  double keplerCx = (double)((gint32)v)*pow(2, -29);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g rad (%d)", keplerCx, (gint32)v);
}

static void
lpp_navToe_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%u s (%u)", 16*v, v);
}

static void
lpp_navOmega_M0_I0_OmegaA0_fmt(gchar *s, guint32 v)
{
  double navOmega_M0_I0_OmegaA0 = (double)((gint32)v)*pow(2, -31);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles (%d)", navOmega_M0_I0_OmegaA0, (gint32)v);
}

static void
lpp_navDeltaN_OmegaADot_IDot_fmt(gchar *s, guint32 v)
{
  double navDeltaN_OmegaADot_IDot = (double)((gint32)v)*pow(2, -43);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles/s (%d)", navDeltaN_OmegaADot_IDot, (gint32)v);
}

static void
lpp_navE_fmt(gchar *s, guint32 v)
{
  double navE = (double)v*pow(2, -33);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g (%u)", navE, v);
}

static void
lpp_navAPowerHalf_fmt(gchar *s, guint32 v)
{
  double navAPowerHalf = (double)v*pow(2, -19);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g m1/2 (%u)", navAPowerHalf, v);
}

static void
lpp_navCrs_Crc_fmt(gchar *s, guint32 v)
{
  double navCrs_Crc = (double)((gint32)v)*pow(2, -5);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g m (%d)", navCrs_Crc, (gint32)v);
}

static void
lpp_navCx_fmt(gchar *s, guint32 v)
{
  double navCx = (double)((gint32)v)*pow(2, -29);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g rad (%d)", navCx, (gint32)v);
}

static void
lpp_cnavDeltaA_fmt(gchar *s, guint32 v)
{
  double cnavDeltaA = (double)((gint32)v)*pow(2, -9);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g m (%d)", cnavDeltaA, (gint32)v);
}

static void
lpp_cnavAdot_fmt(gchar *s, guint32 v)
{
  double cnavAdot = (double)((gint32)v)*pow(2, -21);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g m/s (%d)", cnavAdot, (gint32)v);
}

static void
lpp_cnavDeltaNo_fmt(gchar *s, guint32 v)
{
  double cnavDeltaNo = (double)((gint32)v)*pow(2, -44);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles/s (%d)", cnavDeltaNo, (gint32)v);
}

static void
lpp_cnavDeltaNoDot_fmt(gchar *s, guint32 v)
{
  double cnavDeltaNoDot = (double)((gint32)v)*pow(2, -57);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles/s2 (%d)", cnavDeltaNoDot, (gint32)v);
}

static void
lpp_cnavDeltaOmegaDot_IoDot_fmt(gchar *s, guint32 v)
{
  double cnavDeltaOmegaDot_IoDot = (double)((gint32)v)*pow(2, -44);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles/s (%d)", cnavDeltaOmegaDot_IoDot, (gint32)v);
}

static void
lpp_cnavCx_fmt(gchar *s, guint32 v)
{
  double cnavCx = (double)((gint32)v)*pow(2, -30);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g rad (%d)", cnavCx, (gint32)v);
}

static void
lpp_cnavCrs_Crc_fmt(gchar *s, guint32 v)
{
  double cnavCrs_Crc = (double)((gint32)v)*pow(2, -8);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g m (%d)", cnavCrs_Crc, (gint32)v);
}

static void
lpp_gloX_Y_Z_fmt(gchar *s, guint32 v)
{
  double gloX_Y_Z = (double)((gint32)v)*pow(2, -11);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g km (%d)", gloX_Y_Z, (gint32)v);
}

static void
lpp_gloXdot_Ydot_Zdot_fmt(gchar *s, guint32 v)
{
  double gloXdot_Ydot_Zdot = (double)((gint32)v)*pow(2, -20);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g km/s (%d)", gloXdot_Ydot_Zdot, (gint32)v);
}

static void
lpp_gloXdotdot_Ydotdot_Zdotdot_fmt(gchar *s, guint32 v)
{
  double gloXdotdot_Ydotdot_Zdotdot = (double)((gint32)v)*pow(2, -30);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g km/s2 (%d)", gloXdotdot_Ydotdot_Zdotdot, (gint32)v);
}

static void
lpp_sbasXg_Yg_fmt(gchar *s, guint32 v)
{
  double sbasXg_Yg = (double)((gint32)v)*0.08;

  g_snprintf(s, ITEM_LABEL_LENGTH, "%f m (%d)", sbasXg_Yg, (gint32)v);
}

static void
lpp_sbasZg_fmt(gchar *s, guint32 v)
{
  double sbasZg = (double)((gint32)v)*0.4;

  g_snprintf(s, ITEM_LABEL_LENGTH, "%f m (%d)", sbasZg, (gint32)v);
}

static void
lpp_sbasXgDot_YgDot_fmt(gchar *s, guint32 v)
{
  double sbasXgDot_YgDot = (double)((gint32)v)*0.000625;

  g_snprintf(s, ITEM_LABEL_LENGTH, "%f m/s (%d)", sbasXgDot_YgDot, (gint32)v);
}

static void
lpp_sbasZgDot_fmt(gchar *s, guint32 v)
{
  double sbasZgDot = (double)((gint32)v)*0.004;

  g_snprintf(s, ITEM_LABEL_LENGTH, "%f m/s (%d)", sbasZgDot, (gint32)v);
}

static void
lpp_sbasXgDotDot_YgDotDot_fmt(gchar *s, guint32 v)
{
  double sbasXgDotDot_YgDotDot = (double)((gint32)v)*0.0000125;

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g m/s2 (%d)", sbasXgDotDot_YgDotDot, (gint32)v);
}

static void
lpp_sbasZgDotDot_fmt(gchar *s, guint32 v)
{
  double sbasZgDotDot = (double)((gint32)v)*0.0000625;

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g m/s2 (%d)", sbasZgDotDot, (gint32)v);
}

static void
lpp_bdsAPowerHalf_r12_fmt(gchar *s, guint32 v)
{
  double bdsAPowerHalf = (double)v*pow(2, -19);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g m1/2 (%u)", bdsAPowerHalf, v);
}

static void
lpp_bdsE_r12_fmt(gchar *s, guint32 v)
{
  double bdsE = (double)v*pow(2, -33);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g (%u)", bdsE, v);
}

static void
lpp_bdsW_M0_Omega0_I0_r12_fmt(gchar *s, guint32 v)
{
  double bdsW_M0_Omega0_I0 = (double)((gint32)v)*pow(2, -31);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles (%d)", bdsW_M0_Omega0_I0, (gint32)v);
}

static void
lpp_bdsDeltaN_OmegaDot_IDot_r12_fmt(gchar *s, guint32 v)
{
  double bdsDeltaN_OmegaDot_IDot = (double)((gint32)v)*pow(2, -43);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles/s (%d)", bdsDeltaN_OmegaDot_IDot, (gint32)v);
}

static void
lpp_bdsCuc_Cus_Cic_Cis_r12_fmt(gchar *s, guint32 v)
{
  double bdsCuc_Cus_Cic_Cis = (double)((gint32)v)*pow(2, -31);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g rad (%d)", bdsCuc_Cus_Cic_Cis, (gint32)v);
}

static void
lpp_bdsCrc_Crs_r12_fmt(gchar *s, guint32 v)
{
  double bdsCrc_Crs = (double)((gint32)v)*pow(2, -6);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g rad (%d)", bdsCrc_Crs, (gint32)v);
}

static void
lpp_doppler0_fmt(gchar *s, guint32 v)
{
  double doppler0 = (double)((gint32)v)*0.5;

  g_snprintf(s, ITEM_LABEL_LENGTH, "%f m/s (%d)", doppler0, (gint32)v);
}

static void
lpp_doppler1_fmt(gchar *s, guint32 v)
{
  double doppler1 = (double)((gint32)(v-42))/210;

  g_snprintf(s, ITEM_LABEL_LENGTH, "%f m/s2 (%u)", doppler1, v);
}

static const value_string lpp_dopplerUncertainty_vals[] = {
  { 0, "40 m/s"},
  { 1, "20 m/s"},
  { 2, "10 m/s"},
  { 3, "5 m/s"},
  { 4, "2.5 m/s"},
  { 0, NULL}
};

static void
lpp_codePhase_fmt(gchar *s, guint32 v)
{
  double codePhase = (double)v*pow(2, -10);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g ms (%u)", codePhase, v);
}

static const value_string lpp_codePhaseSearchWindow_vals[] = {
  {  0, "No information"},
  {  1, "0.002 ms"},
  {  2, "0.004 ms"},
  {  3, "0.008 ms"},
  {  4, "0.012 ms"},
  {  5, "0.016 ms"},
  {  6, "0.024 ms"},
  {  7, "0.032 ms"},
  {  8, "0.048 ms"},
  {  9, "0.064 ms"},
  { 10, "0.096 ms"},
  { 11, "0.128 ms"},
  { 12, "0.164 ms"},
  { 13, "0.200 ms"},
  { 14, "0.250 ms"},
  { 15, "0.300 ms"},
  { 16, "0.360 ms"},
  { 17, "0.420 ms"},
  { 18, "0.480 ms"},
  { 19, "0.540 ms"},
  { 20, "0.600 ms"},
  { 21, "0.660 ms"},
  { 22, "0.720 ms"},
  { 23, "0.780 ms"},
  { 24, "0.850 ms"},
  { 25, "1.000 ms"},
  { 26, "1.150 ms"},
  { 27, "1.300 ms"},
  { 28, "1.450 ms"},
  { 29, "1.600 ms"},
  { 30, "1.800 ms"},
  { 31, "2.000 ms"},
  { 0, NULL}
};
static value_string_ext lpp_codePhaseSearchWindow_vals_ext = VALUE_STRING_EXT_INIT(lpp_codePhaseSearchWindow_vals);

static void
lpp_azimuth_elevation_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%f degrees (%u)", (float)v*0.703125, v);
}

static void
lpp_kepAlmanacE_fmt(gchar *s, guint32 v)
{
  double kepAlmanacE = (double)v*pow(2, -16);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g (%u)", kepAlmanacE, v);
}

static void
lpp_kepAlmanacDeltaI_fmt(gchar *s, guint32 v)
{
  double kepAlmanacDeltaI = (double)((gint32)v)*pow(2, -14);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles (%d)", kepAlmanacDeltaI, (gint32)v);
}

static void
lpp_kepAlmanacOmegaDot_fmt(gchar *s, guint32 v)
{
  double kepAlmanacOmegaDot = (double)((gint32)v)*pow(2, -33);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles/s (%d)", kepAlmanacOmegaDot, (gint32)v);
}

static void
lpp_kepAlmanacAPowerHalf_fmt(gchar *s, guint32 v)
{
  double kepAlmanacAPowerHalf = (double)((gint32)v)*pow(2, -9);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g m1/2 (%d)", kepAlmanacAPowerHalf, (gint32)v);
}

static void
lpp_kepAlmanacOmega0_W_M0_fmt(gchar *s, guint32 v)
{
  double kepAlmanacOmega0_W_M0 = (double)((gint32)v)*pow(2, -15);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles (%d)", kepAlmanacOmega0_W_M0, (gint32)v);
}

static void
lpp_kepAlmanacAF0_fmt(gchar *s, guint32 v)
{
  double kepAlmanacAF0 = (double)((gint32)v)*pow(2, -19);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s (%d)", kepAlmanacAF0, (gint32)v);
}

static void
lpp_kepAlmanacAF1_fmt(gchar *s, guint32 v)
{
  double kepAlmanacAF1 = (double)((gint32)v)*pow(2, -38);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s/s (%d)", kepAlmanacAF1, (gint32)v);
}

static void
lpp_navAlmE_fmt(gchar *s, guint32 v)
{
  double navAlmE = (double)v*pow(2, -21);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g (%u)", navAlmE, v);
}

static void
lpp_navAlmDeltaI_fmt(gchar *s, guint32 v)
{
  double navAlmDeltaI = (double)((gint32)v)*pow(2, -19);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles (%d)", navAlmDeltaI, (gint32)v);
}

static void
lpp_navAlmOMEGADOT_fmt(gchar *s, guint32 v)
{
  double navAlmOMEGADOT = (double)((gint32)v)*pow(2, -38);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles/s (%d)", navAlmOMEGADOT, (gint32)v);
}

static void
lpp_navAlmSqrtA_fmt(gchar *s, guint32 v)
{
  double navAlmSqrtA = (double)v*pow(2, -11);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g m1/2 (%u)", navAlmSqrtA, v);
}

static void
lpp_navAlmOMEGAo_Omega_Mo_fmt(gchar *s, guint32 v)
{
  double navAlmOMEGAo_Omega_Mo = (double)((gint32)v)*pow(2, -23);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles (%d)", navAlmOMEGAo_Omega_Mo, (gint32)v);
}

static void
lpp_navAlmaf0_fmt(gchar *s, guint32 v)
{
  double navAlmaf0 = (double)((gint32)v)*pow(2, -20);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s (%d)", navAlmaf0, (gint32)v);
}

static void
lpp_navAlmaf1_fmt(gchar *s, guint32 v)
{
  double navAlmaf1 = (double)((gint32)v)*pow(2, -38);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s/s (%d)", navAlmaf1, (gint32)v);
}

static void
lpp_redAlmDeltaA_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%d m (%d)", 512*(gint)v, (gint)v);
}

static void
lpp_redAlmOmega0_Phi0_fmt(gchar *s, guint32 v)
{
  double redAlmOmega0_Phi0 = (double)((gint32)v)*pow(2, -6);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles (%d)", redAlmOmega0_Phi0, (gint32)v);
}

static void
lpp_midiAlmE_fmt(gchar *s, guint32 v)
{
  double midiAlmE = (double)v*pow(2, -16);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g (%u)", midiAlmE, v);
}

static void
lpp_midiAlmDeltaI_fmt(gchar *s, guint32 v)
{
  double midiAlmDeltaI = (double)((gint32)v)*pow(2, -14);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles (%d)", midiAlmDeltaI, (gint32)v);
}

static void
lpp_midiAlmOmegaDot_fmt(gchar *s, guint32 v)
{
  double midiAlmOmegaDot = (double)((gint32)v)*pow(2, -33);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles/s (%d)", midiAlmOmegaDot, (gint32)v);
}

static void
lpp_midiAlmSqrtA_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%f m1/2 (%u)", (float)v*0.0625, v);
}

static void
lpp_midiAlmOmega0_Omega_Mo_fmt(gchar *s, guint32 v)
{
  double midiAlmOmega0_Omega_Mo = (double)((gint32)v)*pow(2, -15);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles (%d)", midiAlmOmega0_Omega_Mo, (gint32)v);
}

static void
lpp_midiAlmaf0_fmt(gchar *s, guint32 v)
{
  double midiAlmaf0 = (double)((gint32)v)*pow(2, -20);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s (%d)", midiAlmaf0, (gint32)v);
}

static void
lpp_midiAlmaf1_fmt(gchar *s, guint32 v)
{
  double midiAlmaf1 = (double)((gint32)v)*pow(2, -37);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s/s (%d)", midiAlmaf1, (gint32)v);
}

static void
lpp_gloAlmLambdaA_DeltaIa_fmt(gchar *s, guint32 v)
{
  double gloAlmLambdaA_DeltaIa = (double)((gint32)v)*pow(2, -20);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles (%d)", gloAlmLambdaA_DeltaIa, (gint32)v);
}

static void
lpp_gloAlmtlambdaA_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%f s (%u)", (float)v*0.03125, v);
}

static void
lpp_gloAlmDeltaTA_fmt(gchar *s, guint32 v)
{
  double gloAlmDeltaTA = (double)((gint32)v)*pow(2, -9);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s/orbit period (%d)", gloAlmDeltaTA, (gint32)v);
}

static void
lpp_gloAlmDeltaTdotA_fmt(gchar *s, guint32 v)
{
  double gloAlmDeltaTdotA = (double)((gint32)v)*pow(2, -14);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s/orbit period (%d)", gloAlmDeltaTdotA, (gint32)v);
}

static void
lpp_gloAlmEpsilonA_fmt(gchar *s, guint32 v)
{
  double gloAlmEpsilonA = (double)v*pow(2, -20);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g (%u)", gloAlmEpsilonA, (gint32)v);
}

static void
lpp_gloAlmOmegaA_fmt(gchar *s, guint32 v)
{
  double gloAlmOmegaA = (double)((gint32)v)*pow(2, -15);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles (%d)", gloAlmOmegaA, (gint32)v);
}

static void
lpp_gloAlmTauA_fmt(gchar *s, guint32 v)
{
  double gloAlmTauA = (double)((gint32)v)*pow(2, -18);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s (%d)", gloAlmTauA, (gint32)v);
}

static void
lpp_sbasAlmXg_Yg_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%f km (%d)", (gint32)v*2.6, (gint32)v);
}

static void
lpp_sbasAlmZg_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%d km (%d)", (gint32)v*26, (gint32)v);
}

static void
lpp_sbasAlmXgdot_YgDot_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%d m/s (%d)", (gint32)v*10, (gint32)v);
}

static void
lpp_sbasAlmZgDot_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%f m/s (%d)", (gint32)v*40.96, (gint32)v);
}

static void
lpp_sbasAlmTo_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%u m/s (%u)", v*64, v);
}

static void
lpp_bdsAlmToa_r12_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%u s (%u)", v*4096, v);
}

static void
lpp_bdsAlmSqrtA_r12_fmt(gchar *s, guint32 v)
{
  double bdsAlmSqrtA = (double)v*pow(2, -11);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g m1/2 (%u)", bdsAlmSqrtA, v);
}

static void
lpp_bdsAlmE_r12_fmt(gchar *s, guint32 v)
{
  double bdsAlmE = (double)v*pow(2, -21);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g m1/2 (%u)", bdsAlmE, v);
}

static void
lpp_bdsAlmW_M0_Omega0_r12_fmt(gchar *s, guint32 v)
{
  double bdsAlmW_M0_Omega0 = (double)((gint32)v)*pow(2, -23);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles (%d)", bdsAlmW_M0_Omega0, (gint32)v);
}

static void
lpp_bdsAlmOmegaDot_r12_fmt(gchar *s, guint32 v)
{
  double bdsAlmOmegaDot = (double)((gint32)v)*pow(2, -38);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles/s (%d)", bdsAlmOmegaDot, (gint32)v);
}

static void
lpp_bdsAlmDeltaI_r12_fmt(gchar *s, guint32 v)
{
  double bdsAlmDeltaI = (double)((gint32)v)*pow(2, -19);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g semi-circles (%d)", bdsAlmDeltaI, (gint32)v);
}

static void
lpp_bdsAlmA0_r12_fmt(gchar *s, guint32 v)
{
  double bdsAlmA0 = (double)((gint32)v)*pow(2, -20);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s (%d)", bdsAlmA0, (gint32)v);
}

static void
lpp_bdsAlmA1_r12_fmt(gchar *s, guint32 v)
{
  double bdsAlmA1 = (double)((gint32)v)*pow(2, -38);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s/s (%d)", bdsAlmA1, (gint32)v);
}

static const true_false_string lpp_bdsSvHealth_r12_b1i_b2i_value = {
  "OK",
  "Weak"
};

static const true_false_string lpp_bdsSvHealth_r12_nav_value = {
  "OK",
  "Bad (IOD over limit)"
};

static void
lpp_gnss_Utc_A1_fmt(gchar *s, guint32 v)
{
  double gnss_Utc_A1 = (double)((gint32)v)*pow(2, -50);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s/s (%d)", gnss_Utc_A1, (gint32)v);
}

static void
lpp_gnss_Utc_A0_fmt(gchar *s, guint32 v)
{
  double gnss_Utc_A0 = (double)((gint32)v)*pow(2, -30);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s (%d)", gnss_Utc_A0, (gint32)v);
}

static void
lpp_gnss_Utc_Tot_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%u s (%u)", v*4096, v);
}

static const value_string lpp_bds_UDREI_vals[] = {
  {  0, "1 meter"},
  {  1, "1.5 meters"},
  {  2, "2 meters"},
  {  3, "3 meters"},
  {  4, "4 meters"},
  {  5, "5 meters"},
  {  6, "6 meters"},
  {  7, "8 meters"},
  {  8, "10 meters"},
  {  9, "15 meters"},
  { 10, "20 meters"},
  { 11, "50 meters"},
  { 12, "100 meters"},
  { 13, "150 meters"},
  { 14, "Not monitored"},
  { 15, "Not available"},
  { 0, NULL}
};
static value_string_ext lpp_bds_UDREI_vals_ext = VALUE_STRING_EXT_INIT(lpp_bds_UDREI_vals);

static const value_string lpp_bds_RURAI_vals[] = {
  {  0, "0.75 meter"},
  {  1, "1 meter"},
  {  2, "1.25 meters"},
  {  3, "1.75 meters"},
  {  4, "2.25 meters"},
  {  5, "3 meters"},
  {  6, "3.75 meters"},
  {  7, "4.5 meters"},
  {  8, "5.25 meters"},
  {  9, "6 meters"},
  { 10, "7.5 meters"},
  { 11, "15 meters"},
  { 12, "50 meters"},
  { 13, "150 meters"},
  { 14, "300 meters"},
  { 15, "> 300 meters"},
  { 0, NULL}
};
static value_string_ext lpp_bds_RURAI_vals_ext = VALUE_STRING_EXT_INIT(lpp_bds_RURAI_vals);

static void
lpp_bds_ECC_DeltaT_r12_fmt(gchar *s, guint32 v)
{
  if ((gint32)v == -4096) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "Not available (%d)", (gint32)v);
  } else {
    g_snprintf(s, ITEM_LABEL_LENGTH, "%g m (%d)", (float)((gint32)v)*0.1, (gint32)v);
  }
}

static void
lpp_bds_GridIonElement_dt_r12_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%g m (%d)", (float)((gint32)v)*0.125, (gint32)v);
}

static const value_string lpp_bds_givei_vals[] = {
  {  0, "0.3 meter"},
  {  1, "0.6 meter"},
  {  2, "0.9 meter"},
  {  3, "1.2 meters"},
  {  4, "1.5 meters"},
  {  5, "1.8 meters"},
  {  6, "2.1 meters"},
  {  7, "2.4 meters"},
  {  8, "2.7 meters"},
  {  9, "3 meters"},
  { 10, "3.6 meters"},
  { 11, "4.5 meters"},
  { 12, "6 meters"},
  { 13, "9 meters"},
  { 14, "15 meters"},
  { 15, "45 meters"},
  { 0, NULL}
};
static value_string_ext lpp_bds_givei_vals_ext = VALUE_STRING_EXT_INIT(lpp_bds_givei_vals);

static void
lpp_tauC_fmt(gchar *s, guint32 v)
{
  double tauC = (double)((gint32)v)*pow(2, -31);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s (%d)", tauC, (gint32)v);
}

static void
lpp_b1_fmt(gchar *s, guint32 v)
{
  double b1 = (double)((gint32)v)*pow(2, -10);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s (%d)", b1, (gint32)v);
}

static void
lpp_b2_fmt(gchar *s, guint32 v)
{
  double b2 = (double)((gint32)v)*pow(2, -16);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g s/msd (%d)", b2, (gint32)v);
}

static const value_string lpp_utcStandardID_vals[] = {
  { 0, "UTC as operated by the Communications Research Laboratory (CRL), Tokyo, Japan"},
  { 1, "UTC as operated by the National Institute of Standards and Technology (NIST)"},
  { 2, "UTC as operated by the U. S. Naval Observatory (USNO)"},
  { 3, "UTC as operated by the International Bureau of Weights and Measures (BIPM)"},
  { 0, NULL}
};

static const value_string lpp_dataBitInterval_vals[] = {
  {  0, "0.1"},
  {  1, "0.2"},
  {  2, "0.4"},
  {  3, "0.8"},
  {  4, "1.6"},
  {  5, "3.2"},
  {  6, "6.4"},
  {  7, "12.8"},
  {  8, "25.6"},
  {  9, "51.2"},
  { 10, "102.4"},
  { 11, "204.8"},
  { 12, "409.6"},
  { 13, "819.2"},
  { 14, "1638.4"},
  { 15, "Not specified"},
  { 0, NULL}
};
static value_string_ext lpp_dataBitInterval_vals_ext = VALUE_STRING_EXT_INIT(lpp_dataBitInterval_vals);

static const value_string lpp_carrierQualityInd_vals[] = {
  { 0, "Data direct, carrier phase not continuous"},
  { 1, "Data inverted, carrier phase not continuous"},
  { 2, "Data direct, carrier phase continuous"},
  { 3, "Data inverted, carrier phase continuous"},
  { 0, NULL}
};

static void
lpp_GNSS_SatMeas_codePhase_fmt(gchar *s, guint32 v)
{
  double codePhase = (double)v*pow(2, -21);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g ms (%u)", codePhase, v);
}

static void
lpp_codePhaseRMSError_fmt(gchar *s, guint32 v)
{
  guint8 mantissa = v & 0x07;
  guint8 exponent = (v & 0x38) >> 3;
  guint8 mantissa_1 = (v - 1) & 0x07;
  guint8 exponent_1 = ((v - 1) & 0x38) >> 3;

  if (v == 0) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "P < 0.5 (0)");
  } else if (v < 63) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "%f <= P < %f (%u)", 0.5*(1+mantissa_1/8)*pow(2, exponent_1),
               0.5*(1+mantissa/8)*pow(2, exponent), v);
  } else {
    g_snprintf(s, ITEM_LABEL_LENGTH, "112 <= P (63)");
  }
}

static void
lpp_doppler_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%g m/s (%d)", (gint32)v*0.04, (gint32)v);
}

static void
lpp_adr_fmt(gchar *s, guint32 v)
{
  double adr = (double)v*pow(2, -10);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g m (%u)", adr, v);
}

static void
lpp_rsrp_Result_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%d dBm (%u)", v-140, v);
}

static void
lpp_rsrq_Result_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "RSRQ < -19.5 dB (0)");
  } else if (v < 34) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "%.1f dB <= RSRQ < %.1f dB (%u)", ((float)v/2)-20, (((float)v+1)/2)-20, v);
  } else {
    g_snprintf(s, ITEM_LABEL_LENGTH, "-3 dB <= RSRQ (34)");
  }
}

static void
lpp_ue_RxTxTimeDiff_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "T < 2 Ts (0)");
  } else if (v < 2048) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "%u Ts <= T < %u Ts (%u)", v*2, (v+1)*2, v);
  } else if (v < 4095) {
    g_snprintf(s, ITEM_LABEL_LENGTH, "%u Ts <= T < %u Ts (%u)", (v*8)-12288, ((v+1)*8)-12288, v);
  } else {
    g_snprintf(s, ITEM_LABEL_LENGTH, "20472 Ts <= T (4095)");
  }
}

static void
lpp_mbs_beaconMeasElt_codePhase_fmt(gchar *s, guint32 v)
{
  double codePhase = (double)v*pow(2, -21);

  g_snprintf(s, ITEM_LABEL_LENGTH, "%g ms (%u)", codePhase, v);
}

#include "packet-lpp-fn.c"

static int dissect_lpp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
  proto_tree *subtree;
  proto_item *it;

  it = proto_tree_add_item(tree, proto_lpp, tvb, 0, -1, ENC_NA);
  col_append_sep_str(pinfo->cinfo, COL_PROTOCOL, "/", "LPP");
  subtree = proto_item_add_subtree(it, ett_lpp);

  return dissect_LPP_Message_PDU(tvb, pinfo, subtree, NULL);
}

/*--- proto_register_lpp -------------------------------------------*/
void proto_register_lpp(void) {

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-lpp-hfarr.c"
    { &hf_lpp_svHealthExt_v1240_e5bhs,
      { "E5b Signal Health Status", "lpp.svHealthExt_v1240.e5bhs",
        FT_UINT8, BASE_DEC, VALS(lpp_signal_health_status_vals), 0,
        NULL, HFILL }},
    { &hf_lpp_svHealthExt_v1240_e1_bhs,
      { "E1-B Signal Health Status", "lpp.svHealthExt_v1240.e1_bhs",
        FT_UINT8, BASE_DEC, VALS(lpp_signal_health_status_vals), 0,
        NULL, HFILL }},
    { &hf_lpp_kepSV_StatusINAV_e5bhs,
      { "E5b Signal Health Status", "lpp.kepSV_StatusINAV.e5bhs",
        FT_UINT8, BASE_DEC, VALS(lpp_signal_health_status_vals), 0,
        NULL, HFILL }},
    { &hf_lpp_kepSV_StatusINAV_e1_bhs,
      { "E1-B Signal Health Status", "lpp.kepSV_StatusINAV.e1_bhs",
        FT_UINT8, BASE_DEC, VALS(lpp_signal_health_status_vals), 0,
        NULL, HFILL }},
    { &hf_lpp_kepSV_StatusFNAV_e5ahs,
      { "E5a Signal Health Status", "lpp.kepSV_StatusFNAV.e5ahs",
        FT_UINT8, BASE_DEC, VALS(lpp_signal_health_status_vals), 0,
        NULL, HFILL }},
    { &hf_lpp_bdsSvHealth_r12_sat_clock,
      { "Satellite Clock", "lpp.bdsSvHealth_r12.sat_clock",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_ok_error), 0,
        NULL, HFILL }},
    { &hf_lpp_bdsSvHealth_r12_b1i,
      { "B1I Signal", "lpp.bdsSvHealth_r12.b1i",
        FT_BOOLEAN, BASE_NONE, TFS(&lpp_bdsSvHealth_r12_b1i_b2i_value), 0,
        NULL, HFILL }},
    { &hf_lpp_bdsSvHealth_r12_b2i,
      { "B2I Signal", "lpp.bdsSvHealth_r12.b2i",
        FT_BOOLEAN, BASE_NONE, TFS(&lpp_bdsSvHealth_r12_b1i_b2i_value), 0,
        NULL, HFILL }},
    { &hf_lpp_bdsSvHealth_r12_nav,
      { "NAV Message", "lpp.bdsSvHealth_r12.nav",
        FT_BOOLEAN, BASE_NONE, TFS(&lpp_bdsSvHealth_r12_nav_value), 0,
        NULL, HFILL }}
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_lpp,
    &ett_lpp_bitmap,
    &ett_lpp_svHealthExt_v1240,
    &ett_kepSV_StatusINAV,
    &ett_kepSV_StatusFNAV,
    &ett_lpp_bdsSvHealth_r12,
#include "packet-lpp-ettarr.c"
  };


  /* Register protocol */
  proto_lpp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("lpp", dissect_lpp, proto_lpp);

  /* Register fields and subtrees */
  proto_register_field_array(proto_lpp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));


}


/*--- proto_reg_handoff_lpp ---------------------------------------*/
void
proto_reg_handoff_lpp(void)
{
  lppe_handle = find_dissector_add_dependency("lppe", proto_lpp);
}


