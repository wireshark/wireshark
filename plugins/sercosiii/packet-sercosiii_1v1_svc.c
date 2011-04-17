/* packet-sercosiii_1v1_svc.c
 * Routines for SERCOS III dissection
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

#include <glib.h>

#include <epan/packet.h>

#include "packet-sercosiii.h"

static gint hf_siii_mdt_svch_dbe = -1;
static gint hf_siii_mdt_svch_eot = -1;
static gint hf_siii_mdt_svch_rw = -1;
static gint hf_siii_mdt_svch_mhs = -1;
static gint hf_siii_mdt_svch_info = -1;

static gint hf_siii_at_svch_valid = -1;
static gint hf_siii_at_svch_error = -1;
static gint hf_siii_at_svch_busy = -1;
static gint hf_siii_at_svch_ahs = -1;
static gint hf_siii_at_svch_info = -1;

static gint hf_siii_mdt_svch_idn = -1;
static gint hf_siii_mdt_svch_ctrl = -1;
static gint hf_siii_at_svch_stat = -1;

static gint ett_siii_mdt_svcctrl = -1;
static gint ett_siii_mdt_svcinfo = -1;
static gint ett_siii_at_svcstat = -1;
static gint ett_siii_at_svcinfo = -1;
static gint ett_siii_mdt_svch_data_error_info = -1;
static gint ett_siii_mdt_svch_data = -1;
static gint hf_siii_svch_data_telofs_telno = -1;
static gint hf_siii_svch_data_telofs_mdt_at = -1;
static gint hf_siii_svch_data_telofs_offset = -1;

static gint hf_siii_svch_data_proccmd_proccmdexec = -1;
static gint hf_siii_svch_data_proccmd_proccmd = -1;

#define IDN(SI, SE, type, paramset, datablock) ((SI<<24)|(SE<<16)|(type<<15)|(paramset<<12)|(datablock))

static const value_string siii_svch_data_proccmd_proccmdexec_text[]=
{
  {0, "Interrupt procedure command execution"},
  {1, "Enable procedure command execution"},
  {0, NULL}
};

static const value_string siii_svch_data_proccmd_proccmd_text[]=
{
  {0, "Cancel procedure command"},
  {1, "Set procedure command"},
  {0, NULL}
};

static const value_string siii_svch_data_mdt_at_text[]=
{
  {0, "AT-telegram"},
  {1, "MDT-telegram"},
  {0, NULL}
};

static const value_string siii_mdt_idn_text[]=
{
  {IDN(0,0,0,0,   0), "Dummy-Parameter"},
  {IDN(0,0,0,0,   1), "Control unit cycle time (tNcyc)"},
  {IDN(0,0,0,0,   2), "Communication cycle time (tScyc)"},
  {IDN(0,0,0,0,  11), "Class 1 diagnostic"},
  {IDN(0,0,0,0,  12), "Class 2 diagnostic"},
  {IDN(0,0,0,0,  14), "Interface status"},
  {IDN(0,0,0,0,  15), "Telegram Type"},
  {IDN(0,0,0,0,  16), "Configuration list of AT"},
  {IDN(0,0,0,0,  17), "IDN-list of all operation data"},
  {IDN(0,0,0,0,  18), "IDN-list of operation data for CP2"},
  {IDN(0,0,0,0,  19), "IDN-list of operation data for CP3"},
  {IDN(0,0,0,0,  21), "IDN-list of invalid operation data for CP2"},
  {IDN(0,0,0,0,  22), "IDN-list of invalid operation data for CP3"},
  {IDN(0,0,0,0,  24), "Configuration list of MDT"},
  {IDN(0,0,0,0,  25), "IDN-list of all procedure commands"},
  {IDN(0,0,0,0,  26), "Configuration list for signal status word"},
  {IDN(0,0,0,0,  27), "Configuration list for signal control word"},
  {IDN(0,0,0,0,  28), "MST error counter"},
  {IDN(0,0,0,0,  29), "MDT error counter"},
  {IDN(0,0,0,0,  32), "Primary operation mode"},
  {IDN(0,0,0,0,  36), "Velocity command value"},
  {IDN(0,0,0,0,  37), "Additive velocity command value"},
  {IDN(0,0,0,0,  38), "Positive velocity limit value"},
  {IDN(0,0,0,0,  39), "Negative velocity limit value"},
  {IDN(0,0,0,0,  40), "Velocity feedback value 1"},
  {IDN(0,0,0,0,  41), "Homing velocity"},
  {IDN(0,0,0,0,  42), "Homing acceleration"},
  {IDN(0,0,0,0,  43), "Velocity polarity parameter"},
  {IDN(0,0,0,0,  44), "Velocity data scaling type"},
  {IDN(0,0,0,0,  45), "Velocity data scaling factor"},
  {IDN(0,0,0,0,  46), "Velocity data scaling exponent"},
  {IDN(0,0,0,0,  47), "Position command value"},
  {IDN(0,0,0,0,  48), "Additive position command value"},
  {IDN(0,0,0,0,  49), "Positive position limit value"},
  {IDN(0,0,0,0,  50), "Negative position limit value"},
  {IDN(0,0,0,0,  51), "Position feedback value 1 (motor feedback)"},
  {IDN(0,0,0,0,  52), "Reference distance 1"},
  {IDN(0,0,0,0,  53), "Position feedback value 2 (external feedback)"},
  {IDN(0,0,0,0,  54), "Reference distance 2"},
  {IDN(0,0,0,0,  55), "Position polarity parameter"},
  {IDN(0,0,0,0,  57), "Position window"},
  {IDN(0,0,0,0,  58), "Reversal clearance"},
  {IDN(0,0,0,0,  59), "Position switch flag parameter"},
  {IDN(0,0,0,0,  60), "Position switches (position switch points on 1-16)"},
  {IDN(0,0,0,0,  76), "Position data scaling type"},
  {IDN(0,0,0,0,  77), "Linear position data scaling factor"},
  {IDN(0,0,0,0,  78), "Linear position data scaling exponent"},
  {IDN(0,0,0,0,  79), "Rotational position resolution"},
  {IDN(0,0,0,0,  80), "Torque command value"},
  {IDN(0,0,0,0,  81), "Additive torque command value"},
  {IDN(0,0,0,0,  82), "Positive torque limit value"},
  {IDN(0,0,0,0,  83), "Negative torque limit value"},
  {IDN(0,0,0,0,  84), "Torque feedback value"},
  {IDN(0,0,0,0,  85), "Torque polarity parameter"},
  {IDN(0,0,0,0,  86), "Torque/force data scaling type"},
  {IDN(0,0,0,0,  91), "Bipolar velocity limit value"},
  {IDN(0,0,0,0,  92), "Bipolar torque limit value"},
  {IDN(0,0,0,0,  93), "Torque/force scaling data factor"},
  {IDN(0,0,0,0,  94), "Torque/force scaling data exponent"},
  {IDN(0,0,0,0,  95), "Diagnostic message"},
  {IDN(0,0,0,0,  96), "Slave arrangement (SLKN)"},
  {IDN(0,0,0,0,  97), "Mask class 2 diagnostic"},
  {IDN(0,0,0,0,  98), "Mask class 3 diagnostic"},
  {IDN(0,0,0,0,  99), "Reset class 1 diagnostic"},
  {IDN(0,0,0,0, 100), "Velocity loop proportional gain"},
  {IDN(0,0,0,0, 101), "Velocity loop integral action time"},
  {IDN(0,0,0,0, 102), "Velocity loop differential time"},
  {IDN(0,0,0,0, 103), "Modulo value"},
  {IDN(0,0,0,0, 104), "Position loop KV-factor"},
  {IDN(0,0,0,0, 105), "Position loop integral action time"},
  {IDN(0,0,0,0, 106), "Current loop proportional gain 1"},
  {IDN(0,0,0,0, 107), "Current loop integral action time 1"},
  {IDN(0,0,0,0, 108), "Feedrate override"},
  {IDN(0,0,0,0, 109), "Motor peak current"},
  {IDN(0,0,0,0, 110), "Amplifier peak current"},
  {IDN(0,0,0,0, 111), "Motor continuous stall current"},
  {IDN(0,0,0,0, 112), "Amplifier rated current"},
  {IDN(0,0,0,0, 113), "Maximum motor speed"},
  {IDN(0,0,0,0, 114), "Load limit of the motor"},
  {IDN(0,0,0,0, 115), "Position feedback 2 type"},
  {IDN(0,0,0,0, 116), "Resolution of feedback 1"},
  {IDN(0,0,0,0, 117), "Resolution of feedback 2"},
  {IDN(0,0,0,0, 118), "Resolution of linear feedback"},
  {IDN(0,0,0,0, 119), "Current loop proportional gain 2"},
  {IDN(0,0,0,0, 120), "Current loop integral action time 2"},
  {IDN(0,0,0,0, 121), "Input revolutions of load gear"},
  {IDN(0,0,0,0, 122), "Output revolutions of load gear"},
  {IDN(0,0,0,0, 123), "Feed constant"},
  {IDN(0,0,0,0, 124), "Standstill window"},
  {IDN(0,0,0,0, 125), "Velocity threshold (nx)"},
  {IDN(0,0,0,0, 126), "Torque threshold (Tx)"},
  {IDN(0,0,0,0, 127), "CP3 transition check"},
  {IDN(0,0,0,0, 128), "CP4 transition check"},
  {IDN(0,0,0,0, 129), "Manufacturer class 1 diagnostic"},
  {IDN(0,0,0,0, 130), "Probe value 1 positive edge"},
  {IDN(0,0,0,0, 131), "Probe value 1 negative edge"},
  {IDN(0,0,0,0, 132), "Probe value 2 positive edge"},
  {IDN(0,0,0,0, 133), "Probe value 2 negative edge"},
  {IDN(0,0,0,0, 134), "Drive control"},
  {IDN(0,0,0,0, 135), "Drive status"},
  {IDN(0,0,0,0, 136), "Positive acceleration limit value"},
  {IDN(0,0,0,0, 137), "Negative acceleration limit value"},
  {IDN(0,0,0,0, 138), "Bipolar acceleration limit value"},
  {IDN(0,0,0,0, 139), "Park axis procedure command"},
  {IDN(0,0,0,0, 143), "SERCOS Interface version"},
  {IDN(0,0,0,0, 144), "Signal status word"},
  {IDN(0,0,0,0, 145), "Signal control word"},
  {IDN(0,0,0,0, 146), "Control unit controlled homing procedure command"},
  {IDN(0,0,0,0, 147), "Homing parameter"},
  {IDN(0,0,0,0, 148), "Drive controlled homing procedure command"},
  {IDN(0,0,0,0, 149), "Position drive stop procedure command"},
  {IDN(0,0,0,0, 150), "Reference offset 1"},
  {IDN(0,0,0,0, 151), "Reference offset 2"},
  {IDN(0,0,0,0, 152), "Position spindle procedure command"},
  {IDN(0,0,0,0, 153), "Spindle angle position"},
  {IDN(0,0,0,0, 154), "Spindle positioning parameter"},
  {IDN(0,0,0,0, 155), "Friction torque compensation"},
  {IDN(0,0,0,0, 156), "Velocity feedback value 2"},
  {IDN(0,0,0,0, 157), "Velocity window"},
  {IDN(0,0,0,0, 158), "Power threshold (Px)"},
  {IDN(0,0,0,0, 159), "Monitoring window"},
  {IDN(0,0,0,0, 161), "Acceleration data scaling factor"},
  {IDN(0,0,0,0, 162), "Acceleration data scaling exponent"},
  {IDN(0,0,0,0, 163), "Weight counterbalance"},
  {IDN(0,0,0,0, 164), "Acceleration feedback value 1"},
  {IDN(0,0,0,0, 165), "Distance-coded reference marks A"},
  {IDN(0,0,0,0, 166), "Distance-coded reference marks B"},
  {IDN(0,0,0,0, 167), "Frequency limit of feedback 1"},
  {IDN(0,0,0,0, 169), "Probe control"},
  {IDN(0,0,0,0, 170), "Probing cycle procedure command"},
  {IDN(0,0,0,0, 171), "Calculate displacement procedure command"},
  {IDN(0,0,0,0, 172), "Displacement to the referenced system procedure command"},
  {IDN(0,0,0,0, 173), "Marker position A"},
  {IDN(0,0,0,0, 174), "Marker position B"},
  {IDN(0,0,0,0, 175), "Displacement parameter 1"},
  {IDN(0,0,0,0, 176), "Displacement parameter 2"},
  {IDN(0,0,0,0, 177), "Absolute distance 1"},
  {IDN(0,0,0,0, 178), "Absolute distance 2"},
  {IDN(0,0,0,0, 179), "Probe status"},
  {IDN(0,0,0,0, 180), "Spindle relative offset"},
  {IDN(0,0,0,0, 181), "Manufacturer class 2 diagnostic"},
  {IDN(0,0,0,0, 183), "Synchronization velocity window"},
  {IDN(0,0,0,0, 184), "Synchronization velocity error limit"},
  {IDN(0,0,0,0, 185), "Length of the configurable data record in the AT"},
  {IDN(0,0,0,0, 186), "Length of the configurable data record in the MDT"},
  {IDN(0,0,0,0, 187), "IDN list of configurable data in the AT"},
  {IDN(0,0,0,0, 188), "IDN list of configurable data in the MDT"},
  {IDN(0,0,0,0, 189), "Following distance"},
  {IDN(0,0,0,0, 190), "Drive controlled gear engaging procedure command"},
  {IDN(0,0,0,0, 191), "Cancel reference point procedure command"},
  {IDN(0,0,0,0, 192), "IDN-list of all backup operation data"},
  {IDN(0,0,0,0, 193), "Positioning jerk"},
  {IDN(0,0,0,0, 194), "Acceleration command time"},
  {IDN(0,0,0,0, 195), "Acceleration feedback value 2"},
  {IDN(0,0,0,0, 196), "Motor rated current"},
  {IDN(0,0,0,0, 197), "Set coordinate system procedure command"},
  {IDN(0,0,0,0, 198), "Initial coordinate value"},
  {IDN(0,0,0,0, 199), "Shift coordinate system procedure command"},
  {IDN(0,0,0,0, 200), "Amplifier warning temperature"},
  {IDN(0,0,0,0, 201), "Motor warning temperature"},
  {IDN(0,0,0,0, 202), "Cooling error warning temperature"},
  {IDN(0,0,0,0, 203), "Amplifier shut-down temperature"},
  {IDN(0,0,0,0, 204), "Motor shut-down temperature"},
  {IDN(0,0,0,0, 205), "Cooling error shut-down temperature"},
  {IDN(0,0,0,0, 206), "Drive on delay time"},
  {IDN(0,0,0,0, 207), "Drive off delay time"},
  {IDN(0,0,0,0, 208), "Temperature data scaling type"},
  {IDN(0,0,0,0, 209), "Lower adaptation limit"},
  {IDN(0,0,0,0, 210), "Upper adaptation limit"},
  {IDN(0,0,0,0, 211), "Adaptation proportional gain"},
  {IDN(0,0,0,0, 212), "Adaptation integral action time"},
  {IDN(0,0,0,0, 213), "Engaging dither amplitude"},
  {IDN(0,0,0,0, 214), "Average engaging speed"},
  {IDN(0,0,0,0, 215), "Engaging dither period"},
  {IDN(0,0,0,0, 216), "Switch parameter set procedure command"},
  {IDN(0,0,0,0, 217), "Parameter set preselection"},
  {IDN(0,0,0,0, 218), "Gear-ration preselection"},
  {IDN(0,0,0,0, 219), "IDN-list of parameter set"},
  {IDN(0,0,0,0, 220), "Minimum spindle speed"},
  {IDN(0,0,0,0, 221), "Maximum spindle speed"},
  {IDN(0,0,0,0, 222), "Spindle positioning speed"},
  {IDN(0,0,0,0, 223), "Drive controlled synchronous operation procedure command"},
  {IDN(0,0,0,0, 224), "Lead Spindle Address"},
  {IDN(0,0,0,0, 225), "Synchronous spindle revolutions"},
  {IDN(0,0,0,0, 226), "Lead spindle revolutions"},
  {IDN(0,0,0,0, 227), "Synchronous spindle revolutions"},
  {IDN(0,0,0,0, 228), "Synchronization position window"},
  {IDN(0,0,0,0, 229), "Synchronization position error limit"},
  {IDN(0,0,0,0, 230), "Synchronization position offset"},
  {IDN(0,0,0,0, 254), "Actual parameter set"},
  {IDN(0,0,0,0, 255), "Actual gear ration"},
  {IDN(0,0,0,0, 256), "Multiplication factor 1"},
  {IDN(0,0,0,0, 257), "Multiplication factor 2"},
  {IDN(0,0,0,0, 258), "Target position"},
  {IDN(0,0,0,0, 259), "Positioning velocity"},
  {IDN(0,0,0,0, 260), "Positioning acceleration"},
  {IDN(0,0,0,0, 261), "Coarse position window"},
  {IDN(0,0,0,0, 262), "Load defaults procedure command"},
  {IDN(0,0,0,0, 263), "Load working memory procedure command"},
  {IDN(0,0,0,0, 264), "Backup working memory procedure command"},
  {IDN(0,0,0,0, 265), "Language selection"},
  {IDN(0,0,0,0, 266), "List of available languages"},
  {IDN(0,0,0,0, 267), "Password"},
  {IDN(0,0,0,0, 268), "Angular setting"},
  {IDN(0,0,0,0, 269), "Storage mode"},
  {IDN(0,0,0,0, 270), "IDN-list of selected backup operation data"},
  {IDN(0,0,0,0, 272), "Velocity window percentage"},
  {IDN(0,0,0,0, 273), "Maximum drive off delay time"},
  {IDN(0,0,0,0, 275), "Coordinate offset value"},
  {IDN(0,0,0,0, 276), "Return to Modulo range procedure command"},
  {IDN(0,0,0,0, 277), "Position feedback 1 type"},
  {IDN(0,0,0,0, 278), "Maximum travel range"},
  {IDN(0,0,0,0, 279), "IDN list of password protected data"},
  {IDN(0,0,0,0, 280), "Underflow threshold"},
  {IDN(0,0,0,0, 282), "Positioning command value"},
  {IDN(0,0,0,0, 283), "Current coordinate offset"},
  {IDN(0,0,0,0, 292), "List of supported operation modes"},
  {IDN(0,0,0,0, 293), "Selectively backup working memory procedure command"},
  {IDN(0,0,0,0, 294), "Divider modulo value"},
  {IDN(0,0,0,0, 295), "Drive enable delay time"},
  {IDN(0,0,0,0, 296), "Velocity feed forward gain"},
  {IDN(0,0,0,0, 297), "Homing distance"},
  {IDN(0,0,0,0, 298), "Suggest home switch distance"},
  {IDN(0,0,0,0, 299), "Home switch offset 1"},
  {IDN(0,0,0,0, 300), "Real-time control bit 1"},
  {IDN(0,0,0,0, 301), "Allocation of real-time control bit 1",},
  {IDN(0,0,0,0, 302), "Real-time control bit 2"},
  {IDN(0,0,0,0, 303), "Allocation of real-time control bit 2"},
  {IDN(0,0,0,0, 304), "Real-time status bit 1"},
  {IDN(0,0,0,0, 305), "Allocation of real-time status bit 1"},
  {IDN(0,0,0,0, 306), "Real-time status-bit 2"},
  {IDN(0,0,0,0, 307), "Allocation of real-time status bit 2"},
  {IDN(0,0,0,0, 308), "Synchronization operation status"},
  {IDN(0,0,0,0, 309), "Synchronization error status"},
  {IDN(0,0,0,0, 310), "Overload warning"},
  {IDN(0,0,0,0, 311), "Amplifier overtemperature warning"},
  {IDN(0,0,0,0, 312), "Motor overtemperature warning"},
  {IDN(0,0,0,0, 313), "Cooling error warning"},
  {IDN(0,0,0,0, 315), "Positioning velocity higher than n Limit"},
  {IDN(0,0,0,0, 323), "Target position outside of travel range"},
  {IDN(0,0,0,0, 326), "Parameter checksum"},
  {IDN(0,0,0,0, 327), "IDN list of checksum parameter"},
  {IDN(0,0,0,0, 328), "Bit number allocation list for signal status word"},
  {IDN(0,0,0,0, 329), "Bit number allocation list for signal control word"},
  {IDN(0,0,0,0, 330), "Status 'nfeedback = ncommand'"},
  {IDN(0,0,0,0, 331), "Status 'nfeedback = 0'"},
  {IDN(0,0,0,0, 332), "Status 'nfeedback less then nx'"},
  {IDN(0,0,0,0, 333), "Status 'T higher than Tx'"},
  {IDN(0,0,0,0, 334), "Status 'T greater than Tlimit '"},
  {IDN(0,0,0,0, 335), "Status 'ncommand greater than nlimit'"},
  {IDN(0,0,0,0, 336), "Status 'In position'"},
  {IDN(0,0,0,0, 337), "Status 'P greater Px'"},
  {IDN(0,0,0,0, 338), "Status 'Position feedback = active target position'"},
  {IDN(0,0,0,0, 339), "Status 'nfeedback less than minimum spindle speed'"},
  {IDN(0,0,0,0, 340), "Status 'nfeedback exceeds maximum spindle speed'"},
  {IDN(0,0,0,0, 341), "Status 'In Coarse position'"},
  {IDN(0,0,0,0, 342), "Status 'Target position attained'"},
  {IDN(0,0,0,0, 343), "Status 'Interpolator halted'"},
  {IDN(0,0,0,0, 346), "Positioning control"},
  {IDN(0,0,0,0, 347), "Velocity error"},
  {IDN(0,0,0,0, 348), "Acceleration feed forward gain"},
  {IDN(0,0,0,0, 349), "Bipolar jerk limit"},
  {IDN(0,0,0,0, 356), "Distance home switch - marker puls"},
  {IDN(0,0,0,0, 357), "Marker pulse distance"},
  {IDN(0,0,0,0, 358), "Home switch offset 2"},
  {IDN(0,0,0,0, 359), "Positioning deceleration"},
  {IDN(0,0,0,0, 360), "MDT data container"},
  {IDN(0,0,0,0, 362), "MDT data container A list index"},
  {IDN(0,0,0,0, 364), "AT data container A1"},
  {IDN(0,0,0,0, 366), "AT data container A list index"},
  {IDN(0,0,0,0, 368), "Data container A pointer"},
  {IDN(0,0,0,0, 370), "MDT data container A/B configuration list"},
  {IDN(0,0,0,0, 371), "AT data container A/B configuration list"},
  {IDN(0,0,0,0, 372), "Drive Halt acceleration bipolar"},
  {IDN(0,0,0,0, 377), "Velocity feedback monitoring window"},
  {IDN(0,0,0,0, 378), "Absolute encoder range 1"},
  {IDN(0,0,0,0, 379), "Absolute encoder range 2"},
  {IDN(0,0,0,0, 380), "DC bus voltage"},
  {IDN(0,0,0,0, 381), "DC bus current"},
  {IDN(0,0,0,0, 382), "DC bus power"},
  {IDN(0,0,0,0, 383), "Motor temperature"},
  {IDN(0,0,0,0, 384), "Amplifier temperature"},
  {IDN(0,0,0,0, 385), "Active power"},
  {IDN(0,0,0,0, 386), "Active position feedback value"},
  {IDN(0,0,0,0, 387), "Power overload"},
  {IDN(0,0,0,0, 388), "Braking current limit"},
  {IDN(0,0,0,0, 389), "Effective current"},
  {IDN(0,0,0,0, 390), "DiagnosticNumber"},
  {IDN(0,0,0,0, 391), "Position feedback monitoring window"},
  {IDN(0,0,0,0, 392), "Velocity feedback filter"},
  {IDN(0,0,0,0, 393), "Command value mode"},
  {IDN(0,0,0,0, 398), "IDN list of configurable real-time/status bits"},
  {IDN(0,0,0,0, 399), "IDN list of configurable real-time/control bits"},
  {IDN(0,0,0,0, 400), "Home switch"},
  {IDN(0,0,0,0, 401), "Probe 1"},
  {IDN(0,0,0,0, 402), "Probe 2"},
  {IDN(0,0,0,0, 403), "Position feedback value status"},
  {IDN(0,0,0,0, 404), "Position command value status"},
  {IDN(0,0,0,0, 405), "Probe 1 enable"},
  {IDN(0,0,0,0, 406), "Probe 2 enable"},
  {IDN(0,0,0,0, 407), "Homing enable"},
  {IDN(0,0,0,0, 408), "Reference marker pulse registered"},
  {IDN(0,0,0,0, 409), "Probe 1 positive latched"},
  {IDN(0,0,0,0, 410), "Probe 1 negative latched"},
  {IDN(0,0,0,0, 411), "Probe 2 positive latched"},
  {IDN(0,0,0,0, 412), "Probe 2 negative latched"},
  {IDN(0,0,0,0, 413), "Bit number allocation of real-time control bit 1"},
  {IDN(0,0,0,0, 414), "Bit number allocation of real-time control bit 2"},
  {IDN(0,0,0,0, 415), "Bit number allocation of real-time status bit 1"},
  {IDN(0,0,0,0, 416), "Bit number allocation of real-time status bit 2"},
  {IDN(0,0,0,0, 417), "Positioning velocity threshold in modulo mode"},
  {IDN(0,0,0,0, 418), "Target position window in modulo mode"},
  {IDN(0,0,0,0, 419), "Positioning acknowledge"},
  {IDN(0,0,0,0, 420), "Activate parametrization level procedure command (PL)"},
  {IDN(0,0,0,0, 422), "Exit parameterization level procedure command"},
  {IDN(0,0,0,0, 423), "IDN-list of invalid data for parameterization level"},
  {IDN(0,0,0,0, 426), "Measuring data allocation 1"},
  {IDN(0,0,0,0, 427), "Measuring data allocation 2"},
  {IDN(0,0,0,0, 428), "IDN list of configurable measuring data"},
  {IDN(0,0,0,0, 429), "Emergency stop deceleration"},
  {IDN(0,0,0,0, 430), "Active target position"},
  {IDN(0,0,0,0, 431), "Spindle positioning acceleration bipolar"},
  {IDN(0,0,0,0, 437), "Positioning status"},
  {IDN(0,0,0,0, 446), "Ramp reference velocity"},
  {IDN(0,0,0,0, 447), "Set absolute position procedure command"},
  {IDN(0,0,0,0, 448), "Set absolute position control word"},
  {IDN(0,0,0,0, 460), "Position switches (position switch points off 1-16)"},
  {IDN(0,0,0,0, 476), "Position switch control"},
  {IDN(0,0,0,0, 477), "Position switch hysteresis"},
  {IDN(0,0,0,0, 478), "Limit switch status"},
  {IDN(0,0,0,0, 509), "Extended probe control"},
  {IDN(0,0,0,0, 510), "Difference value probe 1"},
  {IDN(0,0,0,0, 511), "Difference value probe 2"},
  {IDN(0,0,0,0, 512), "Start position probing window 1"},
  {IDN(0,0,0,0, 513), "End position probing window 1"},
  {IDN(0,0,0,0, 514), "Start position probing window 2"},
  {IDN(0,0,0,0, 515), "End position probing window 2"},
  {IDN(0,0,0,0, 516), "Marker losses probe 1"},
  {IDN(0,0,0,0, 517), "Marker losses probe 2"},
  {IDN(0,0,0,0, 518), "Maximum marker losses probe 1"},
  {IDN(0,0,0,0, 519), "Maximum marker losses probe 2"},
  {IDN(0,0,0,0, 520), "Axis control word"},
  {IDN(0,0,0,0, 521), "Axis status word"},
  {IDN(0,0,0,0, 522), "Difference value 1 latched"},
  {IDN(0,0,0,0, 523), "Difference value 2 latched"},
  {IDN(0,0,0,0, 524), "Probe 1 delay positive"},
  {IDN(0,0,0,0, 525), "Delay Negative Edge, Probe 1"},
  {IDN(0,0,0,0, 526), "Delay positive Edge, Probe 2"},
  {IDN(0,0,0,0, 527), "Delay Negative Edge, Probe 2"},
  {IDN(0,0,0,0, 530), "Clamping torque"},
  {IDN(0,0,0,0, 531), "Checksum for backup operation data"},
  {IDN(0,0,0,0, 532), "Limit switch control"},
  {IDN(0,0,0,0, 533), "Motor continuous stall torque/force"},
  {IDN(0,0,0,0,1000), "SCP Type & Version"},
  {IDN(0,0,0,0,1001), "SERCOS III: Control unit cycle time (tNcyc)"},
  {IDN(0,0,0,0,1002), "SERCOS III: Communication cycle time (tScyc)"},
  {IDN(0,0,0,0,1003), "SERCOS III: Number of successive MDT errors"},
  {IDN(0,0,0,0,1005), "SERCOS III: Feedback value computation time (t5)"},
  {IDN(0,0,0,0,1006), "SERCOS III: AT transmission starting time (t1)"},
  {IDN(0,0,0,0,1007), "SERCOS III: Synchronization time (t8)"},
  {IDN(0,0,0,0,1008), "SERCOS III: Command value valid time (t3)"},
  {IDN(0,0,0,0,1009), "SERCOS III: Device Control offset in MDT"},
  {IDN(0,0,0,0,1010), "SERCOS III: Length of MDT"},
  {IDN(0,0,0,0,1011), "SERCOS III: Device Status offset in AT"},
  {IDN(0,0,0,0,1012), "SERCOS III: Length of AT"},
  {IDN(0,0,0,0,1013), "SERCOS III: SVC offset in MDT"},
  {IDN(0,0,0,0,1014), "SERCOS III: SVC offset in AT"},
  {IDN(0,0,0,0,1015), "SERCOS III: Ring delay"},
  {IDN(0,0,0,0,1016), "SERCOS III: Slave delay"},
  {IDN(0,0,0,0,1017), "SERCOS III: Transmission starting time IP channel"},
  {IDN(0,0,0,0,1018), "SERCOS III: SYNC delay"},
  {IDN(0,0,0,0,1019), "SERCOS III: MAC address"},
  {IDN(0,0,0,0,1020), "SERCOS III: IP address"},
  {IDN(0,0,0,0,1021), "SERCOS III: Network mask"},
  {IDN(0,0,0,0,1022), "SERCOS III: Gateway address"},
  {IDN(0,0,0,0,1023), "SERCOS III: Sync jitter"},
  {IDN(0,0,0,0,1024), "SERCOS III: Ring control - node control"},
  {IDN(0,0,0,0,1025), "SERCOS III: Ring status - node status"},
  {IDN(0,0,0,0,1026), "SERCOS III: Hardware identification"},
  {IDN(1,0,0,0,1027), "Requested MTU"},
  {IDN(2,0,0,0,1027), "Effective MTU"},
  {IDN(0,0,0,0,1028), "SERCOS III: Error counter MDT0 MST"},
  {IDN(0,0,0,0,1029), "SERCOS III: Error counter MDT0-3"},
  {IDN(0,0,0,0,1030), "SERCOS III: Error counter AT0-3"},
  {IDN(0,0,0,0,1031), "Signal assignment Port 1 & Port 2"},
  {IDN(0,0,0,0,1035), "Error counter Port1 and Port2"},
  {IDN(0,0,0,0,1040), "SERCOSAddress"},
  {IDN(0,0,0,0,1041), "AT Command value valid time (t9)"},
  {IDN(0,0,0,0,1044), "Device Control"},
  {IDN(0,0,0,0,1045), "Device Status"},
  {IDN(0,0,0,0,1046), "IDN-list of SERCOS addresses in device"},
  {IDN(0,0,0,0,1134), "SERCOS III: Device control"},
  {IDN(0,0,0,0,1135), "SERCOS III: Device status"},
  {0, NULL}
};


static const value_string siii_mdt_svch_dbe_text[]=
{
  {0x00, "Element 0: Closed SVC"},
  {0x01, "Element 1: Opening IDN"},
  {0x02, "Element 2: Name of operation data"},
  {0x03, "Element 3: Attribute of operation data"},
  {0x04, "Element 4: Unit of operation data"},
  {0x05, "Element 5: Minimum value of operation data"},
  {0x06, "Element 6: Maximum value of operation data"},
  {0x07, "Element 7: Operation data"},
  {0, NULL}
};

static const value_string siii_mdt_svch_eot_text[]=
{
  {0x00, "Transmission in progress"},
  {0x01, "Last transmission"},
  {0, NULL}
};

static const value_string siii_mdt_svch_rw_text[]=
{
  {0x00, "Read SVC INFO"},
  {0x01, "Write SVC INFO"},
  {0, NULL}
};

static const value_string siii_at_svch_valid_text[]=
{
  {0x00, "SVC not valid"},
  {0x01, "SVC valid"},
  {0, NULL}
};

static const value_string siii_at_svch_error_text[]=
{
  {0x00, "No error"},
  {0x01, "Error in SVC"},
  {0, NULL}
};

static const value_string siii_at_svch_busy_text[]=
{
  {0x00, "Step finished, slave ready for new step"},
  {0x01, "Step in process, new step not allowed"},
  {0, NULL}
};

void dissect_siii_mdt_svc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint devno _U_) /* devno will be needed in later versions */
{
  proto_tree* subtree;
  proto_item* ti;

  guint16 svc_ctrl = tvb_get_letohs(tvb, 0); /* service channel header */
  guint32 svc_info = tvb_get_letohl(tvb, 2); /* service channel data */
  guint8  svc_dbe  = (svc_ctrl>>3) & 7;      /* accessed data block element */

  ti = proto_tree_add_item(tree, hf_siii_mdt_svch_ctrl, tvb, 0, 2, TRUE);
  subtree = proto_item_add_subtree(ti, ett_siii_mdt_svcctrl);

  proto_tree_add_item(subtree, hf_siii_mdt_svch_dbe, tvb, 0, 2, TRUE); /* data block element */
  proto_tree_add_item(subtree, hf_siii_mdt_svch_eot, tvb, 0, 2, TRUE); /* end of transmission */
  proto_tree_add_item(subtree, hf_siii_mdt_svch_rw, tvb, 0, 2, TRUE);  /* read or write */
  proto_tree_add_item(subtree, hf_siii_mdt_svch_mhs, tvb, 0, 2, TRUE); /* master hand shake */

  ti = proto_tree_add_item(tree, hf_siii_mdt_svch_info, tvb, 2, 4, TRUE);

  if(1 == svc_dbe)
  {
    subtree = proto_item_add_subtree(ti, ett_siii_mdt_svcinfo);
    proto_tree_add_text(subtree, tvb, 2, 4, "IDN code: %c-%u-%04d.%d.%d",
      ((0xFFFF & svc_info)>>15)?'P':'S', /* private or sercos IDN */
      (svc_info>>12)&7, /* parameter record */
      (svc_info&4095), /* IDN */
      (svc_info>>24) & 0xFF, /* structure index */
      (svc_info>>16) & 0xFF); /* structure element */
    proto_tree_add_item(subtree, hf_siii_mdt_svch_idn, tvb, 2, 4, TRUE);
  }
}

void dissect_siii_at_svc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint devno _U_) /* devno will be used in later versions */
{
  proto_tree* subtree;
  proto_item* ti;

  ti = proto_tree_add_item(tree, hf_siii_at_svch_stat, tvb, 0, 2, TRUE);
  subtree = proto_item_add_subtree(ti, ett_siii_at_svcstat);

  proto_tree_add_item(subtree, hf_siii_at_svch_valid, tvb, 0, 2, TRUE);
  proto_tree_add_item(subtree, hf_siii_at_svch_error, tvb, 0, 2, TRUE);
  proto_tree_add_item(subtree, hf_siii_at_svch_busy, tvb, 0, 2, TRUE);
  proto_tree_add_item(subtree, hf_siii_at_svch_ahs, tvb, 0, 2, TRUE);

  proto_tree_add_item(tree, hf_siii_at_svch_info, tvb, 2, 4, TRUE);
}

void dissect_siii_svc_init(gint proto_siii)
{
/* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf_siii_header[] = {
    { &hf_siii_mdt_svch_ctrl,
      {"SvcCtrl", "siii.mdt.svch.ctrl",
      FT_UINT16, BASE_HEX, NULL, 0,
      NULL, HFILL }
    },
    { &hf_siii_at_svch_stat,
      {"SvcStat", "siii.mdt.svch.stat",
      FT_UINT16, BASE_HEX, NULL, 0,
      NULL, HFILL }
    },
    { &hf_siii_mdt_svch_info,
      {"Svc Info", "siii.mdt.svch.info",
      FT_BYTES, BASE_NONE, NULL, 0,
      NULL, HFILL }
    },
    { &hf_siii_at_svch_info,
      {"Svc Info", "siii.at.svch.info",
      FT_BYTES, BASE_NONE, NULL, 0,
      NULL, HFILL }
    },
    { &hf_siii_mdt_svch_idn,
      {"IDN", "siii.mdt.svch.idn",
      FT_UINT32, BASE_HEX, VALS(siii_mdt_idn_text), 0,
      NULL, HFILL }
    },
    { &hf_siii_mdt_svch_dbe,
      { "Data block element", "siii.mdt.svch.dbe",
      FT_UINT16, BASE_DEC, VALS(siii_mdt_svch_dbe_text), 0x38,
      NULL, HFILL }
    },
    { &hf_siii_mdt_svch_eot,
      {"End of element transmission", "siii.mdt.svch.eot",
      FT_UINT16, BASE_DEC, VALS(siii_mdt_svch_eot_text), 0x04,
      NULL, HFILL }
    },
    { &hf_siii_mdt_svch_rw,
      {"Read/Write", "siii.mdt.svch.rw",
      FT_UINT16, BASE_DEC, VALS(siii_mdt_svch_rw_text), 0x02,
      NULL, HFILL }
    },
    { &hf_siii_mdt_svch_mhs,
      {"Master Handshake", "siii.mdt.svch.mhs",
      FT_UINT16, BASE_DEC, NULL, 0x01,
      NULL, HFILL }
    },
    { &hf_siii_at_svch_valid,
      { "SVC process", "siii.mdt.svch.proc",
      FT_UINT16, BASE_DEC, VALS(siii_at_svch_valid_text), 0x08,
      NULL, HFILL }
    },
    { &hf_siii_at_svch_error,
      {"SVC Error", "siii.mdt.svch.error",
      FT_UINT16, BASE_DEC, VALS(siii_at_svch_error_text), 0x04,
      NULL, HFILL }
    },
    { &hf_siii_at_svch_busy,
      {"Busy", "siii.mdt.svch.busy",
      FT_UINT16, BASE_DEC, VALS(siii_at_svch_busy_text), 0x02,
      NULL, HFILL }
    },
    { &hf_siii_at_svch_ahs,
      {"Handshake", "siii.at.svch.ahs",
      FT_UINT16, BASE_DEC, NULL, 0x01,
      NULL, HFILL }
    },
    { &hf_siii_svch_data_telofs_telno,
      {"Telegram Number", "siii.mdt.svch.data.telassign.telno",
      FT_UINT16, BASE_DEC, NULL, 0xF000,
      NULL, HFILL }
    },
    { &hf_siii_svch_data_telofs_mdt_at,
      {"Telegram Type", "siii.mdt.svch.data.telassign.mdt_at",
      FT_UINT16, BASE_DEC, VALS(siii_svch_data_mdt_at_text), 0x0800,
      NULL, HFILL }
    },
    { &hf_siii_svch_data_telofs_offset,
      {"Telegram Offset", "siii.mdt.svch.data.telassign.offset",
      FT_UINT16, BASE_DEC, NULL, 0x07FF,
      NULL, HFILL }
    },
    { &hf_siii_svch_data_proccmd_proccmdexec,
      {"Procedure Command Execution", "siii.mdt.svch.data.proccmd.interrupt",
      FT_UINT16, BASE_DEC, VALS(siii_svch_data_proccmd_proccmdexec_text), 0x0002,
      NULL, HFILL }
    },
    { &hf_siii_svch_data_proccmd_proccmd,
      {"Procedure Command", "siii.mdt.svch.data.proccmd.set",
      FT_UINT16, BASE_DEC, VALS(siii_svch_data_proccmd_proccmd_text), 0x0001,
      NULL, HFILL }
    }
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_siii_mdt_svcctrl,
    &ett_siii_mdt_svcinfo,
    &ett_siii_at_svcstat,
    &ett_siii_at_svcinfo,
    &ett_siii_mdt_svch_data_error_info,
    &ett_siii_mdt_svch_data
  };

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_siii, hf_siii_header, array_length(hf_siii_header));
  proto_register_subtree_array(ett, array_length(ett));
}
