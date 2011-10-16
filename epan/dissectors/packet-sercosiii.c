/* packet-sercosiii.c
 * Routines for SERCOS III dissection
 *
 * Initial plugin code by,
 * Bosch Rexroth
 * Hilscher
 *
 * Hans-Peter Bock <hpbock@avaapgh.de>
 *
 * Convert to built-in dissector
 *   Michael Mann * Copyright 2011
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
#include <epan/etypes.h>

#define MAX_SERCOS_DEVICES (512)
#define SERCOS_SLAVE_GROUP_SIZE (128)

#define COMMUNICATION_PHASE_0 (0x0)
#define COMMUNICATION_PHASE_1 (0x1)
#define COMMUNICATION_PHASE_2 (0x2)
#define COMMUNICATION_PHASE_3 (0x3)
#define COMMUNICATION_PHASE_4 (0x4)


/* Initialize the protocol and registered fields */
static gint proto_siii = -1;

/* Initialize the subtree pointers */
static gint ett_siii = -1;
static gint ett_siii_header = -1;
static gint ett_siii_mst = -1;
static gint ett_siii_mst_teltype = -1;
static gint ett_siii_mst_phase = -1;
static gint ett_siii_mdt = -1;
static gint ett_siii_mdt_svc = -1;
static gint ett_siii_mdt_devctrls = -1;
static gint ett_siii_mdt_version = -1;
static gint ett_siii_mdt_svc_channel = -1;
static gint ett_siii_mdt_dev_control = -1;
static gint ett_siii_mdt_devctrl = -1;
static gint ett_siii_mdt_svcctrl = -1;
static gint ett_siii_mdt_svcinfo = -1;
static gint ett_siii_at_svcstat = -1;
static gint ett_siii_at_svcinfo = -1;
static gint ett_siii_mdt_svch_data_error_info = -1;
static gint ett_siii_mdt_svch_data = -1;
static gint ett_siii_at_devstatus = -1;
static gint ett_siii_at = -1;
static gint ett_siii_at_svc = -1;
static gint ett_siii_at_devstats = -1;
static gint ett_siii_at_svc_channel = -1;
static gint ett_siii_at_dev_status = -1;
static gint ett_siii_mdt_hp = -1;
static gint ett_siii_at_hp = -1;
static gint ett_siii_mdt_hp_ctrl = -1;
static gint ett_siii_mdt_hp_info = -1;
static gint ett_siii_at_hp_stat = -1;
static gint ett_siii_at_hp_info = -1;

static gint hf_siii_mdt_version = -1;
static gint hf_siii_mdt_version_initprocvers = -1;
static gint hf_siii_mdt_version_num_mdt_at_cp1_2 = -1;
static gint hf_siii_mdt_version_revision = -1;
static gint hf_siii_mdt_dev_control_top_control = -1;
static gint hf_siii_at_dev_control_ident = -1;
static gint hf_siii_mdt_dev_control_change_topology = -1;
static gint hf_siii_mdt_dev_control = -1;
static gint hf_siii_mst_channel = -1;
static gint hf_siii_mst_type = -1;
static gint hf_siii_mst_cyclecntvalid = -1;
static gint hf_siii_mst_telno = -1;
static gint hf_siii_mst_phase = -1;
static gint hf_siii_mst_cyclecnt = -1;
static gint hf_siii_mst_crc32 = -1;
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
static gint hf_siii_svch_data_telofs_telno = -1;
static gint hf_siii_svch_data_telofs_mdt_at = -1;
static gint hf_siii_svch_data_telofs_offset = -1;
static gint hf_siii_svch_data_proccmd_proccmdexec = -1;
static gint hf_siii_svch_data_proccmd_proccmd = -1;
static gint hf_siii_at_dev_status = -1;
static gint hf_siii_at_dev_status_commwarning = -1;
static gint hf_siii_at_dev_status_change_topology = -1;
static gint hf_siii_at_dev_status_top_status = -1;
static gint hf_siii_at_dev_status_inactive_port_status = -1;
static gint hf_siii_at_dev_status_errorconnection = -1;
static gint hf_siii_at_dev_status_slave_valid = -1;
static gint hf_siii_at_dev_status_proc_command_change = -1;
static gint hf_siii_at_dev_status_parameterization_level_active = -1;
static gint hf_siii_mdt_hotplug_address = -1;
static gint hf_siii_mdt_hp_ctrl = -1;
static gint hf_siii_mdt_hp_info = -1;
static gint hf_siii_at_hotplug_address = -1;
static gint hf_siii_at_hp_stat = -1;
static gint hf_siii_at_hp_info = -1;
static gint hf_siii_mdt_hotplug_control_param = -1;
static gint hf_siii_mdt_hotplug_control_svc_switch = -1;
static gint hf_siii_at_hotplug_status_param = -1;
static gint hf_siii_at_hotplug_status_hp0_finished = -1;
static gint hf_siii_at_hotplug_status_error = -1;

/* Allow heuristic dissection */
static heur_dissector_list_t heur_subdissector_list;

static const value_string siii_mdt_version_num_mdtat_cp1_2_text[]=
{
  {0x00, "2 MDTs/ATs in CP1/2"},
  {0x01, "4 MDTs/ATs in CP1/2"},
  {0, NULL}
};

static const value_string siii_mdt_version_initprocvers_text[]=
{
  {0x00, "No remote address allocation"},
  {0x01, "Remote address allocation"},
  {0, NULL}
};

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

#define IDN(SI, SE, type, paramset, datablock) ((SI<<24)|(SE<<16)|(type<<15)|(paramset<<12)|(datablock))

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

static const value_string siii_mdt_devcontrol_topcontrol_text[]=
{
  {0x00, "Fast Forward on P/S-Channel"},
  {0x01, "Loopback on P-Channel and Fast Forward"},
  {0x02, "Loopback on S-Channel and Fast Forward"},
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


static const value_string siii_mst_phase_text[]=
{
  {0x00, "CP0"},
  {0x01, "CP1"},
  {0x02, "CP2"},
  {0x03, "CP3"},
  {0x04, "CP4"},
  {0x80, "CP0 (Phase Change)"},
  {0x81, "CP1 (Phase Change)"},
  {0x82, "CP2 (Phase Change)"},
  {0x83, "CP3 (Phase Change)"},
  {0x84, "CP4 (Phase Change)"},
  {0, NULL}
};

static const value_string siii_mst_teltype_text[]=
{
  {0x00, "CP0"},
  {0x01, "CP1"},
  {0x02, "CP2"},
  {0x03, "CP3"},
  {0x04, "CP4"},
  {0x80, "CP0 (Phase Change)"},
  {0x81, "CP1 (Phase Change)"},
  {0x82, "CP2 (Phase Change)"},
  {0x83, "CP3 (Phase Change)"},
  {0x84, "CP4 (Phase Change)"},
  {0, NULL}
};

static const value_string siii_mst_channel_text[]=
{
  {0x00, "P-Telegram"},
  {0x01, "S-Telegram"},
  {0, NULL}
};

static const value_string siii_mst_type_text[]=
{
  {0x00, "MDT"},
  {0x01, "AT"},
  {0, NULL}
};

static const value_string siii_mst_cyclecntvalid_text[]=
{
  {0x00, "Invalid"},
  {0x01, "Valid"},
  {0, NULL}
};


static const value_string siii_at_devstatus_errorconnection_text[]=
{
  {0x00, "Error-free connection"},
  {0x01, "Error in the connection occurs"},
  {0, NULL}
};

static const value_string siii_at_devstatus_topstatus_text[]=
{
  {0x00, "Fast Forward on P/S-Channel"},
  {0x01, "Loopback on P-Channel and Fast Forward"},
  {0x02, "Loopback on S-Channel and Fast Forward"},
  {0, NULL}
};

static const value_string siii_at_devstatus_inactiveportstatus_text[]=
{
  {0x00, "No link on port"},
  {0x01, "Link on port"},
  {0x02, "S III P-Telegram on port"},
  {0x03, "S III S-Telegram on port"},
  {0, NULL}
};

static const value_string siii_at_dev_status_proc_command_change_text[]=
{
  {0x00, "No change in procedure command acknowledgement"},
  {0x01, "Changing procedure command acknowledgement"},
  {0, NULL}
};


static const value_string siii_mdt_hotplug_control_functioncode_text[]=
{
  {0x00, "No data"},
  {0x01, "tScyc"},
  {0x02, "t1"},
  {0x03, "t6"},
  {0x04, "t7"},
  {0x05, "Communication Version"},
  {0x06, "Communication timeout"},
  {0x10, "MDT0 Length"},
  {0x11, "MDT1 Length"},
  {0x12, "MDT2 Length"},
  {0x13, "MDT3 Length"},
  {0x20, "AT0 Length"},
  {0x21, "AT1 Length"},
  {0x22, "AT2 Length"},
  {0x23, "AT3 Length"},
  {0x80, "MDT-SVC pointer"},
  {0x81, "MDT-RTD pointer"},
  {0x82, "AT-SVC pointer"},
  {0x83, "AT-RTD pointer"},
  {0, NULL}
};

static const value_string siii_mdt_hotplug_control_svc_switch_text[]=
{
  {0, "Transmission via HP-field"},
  {1, "Switch to SVC"},
  {0, NULL}
};

static const value_string siii_mdt_hotplug_status_ackcode_text[]=
{
  {0x80, "MDT-SVC pointer"},
  {0x81, "MDT-RTD pointer"},
  {0x82, "AT-SVC pointer"},
  {0x83, "AT-RTD pointer"},
  {255, "Next Sercos Slave has same address"},
  {0, NULL}
};

static const value_string siii_at_hotplug_status_error_text[]=
{
  {0, "Acknowledgement in HP-1"},
  {1, "Error in HP-1"},
  {0, NULL}
};





void dissect_siii_mst(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item*  ti;
  proto_tree* subtree;
  proto_tree* subtree2;

  ti = proto_tree_add_text(tree, tvb, 0, 6, "MST");
  subtree = proto_item_add_subtree(ti, ett_siii_mst);

  ti = proto_tree_add_text(subtree, tvb, 0, 1, "Telegram Type");
  subtree2 = proto_item_add_subtree(ti, ett_siii_mst_teltype);

  proto_tree_add_item(subtree2, hf_siii_mst_channel, tvb, 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(subtree2, hf_siii_mst_type, tvb, 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(subtree2, hf_siii_mst_cyclecntvalid, tvb, 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(subtree2, hf_siii_mst_telno, tvb, 0, 1, ENC_LITTLE_ENDIAN);

  ti = proto_tree_add_text(subtree, tvb, 1, 1, "Phase Field");
  subtree2 = proto_item_add_subtree(ti, ett_siii_mst_phase);

  proto_tree_add_item(subtree2, hf_siii_mst_phase, tvb, 1, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(subtree2, hf_siii_mst_cyclecnt, tvb, 1, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(subtree, hf_siii_mst_crc32, tvb, 2, 4, ENC_LITTLE_ENDIAN);

}

void dissect_siii_mdt_hp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_tree* subtree;
  proto_tree* subtree2;
  proto_item* ti;

  ti = proto_tree_add_text(tree, tvb, 0, 8, "Hot-Plug");
  subtree = proto_item_add_subtree(ti, ett_siii_mdt_hp);

  proto_tree_add_item(subtree, hf_siii_mdt_hotplug_address, tvb, 2, 2, ENC_LITTLE_ENDIAN);

  ti = proto_tree_add_item(subtree, hf_siii_mdt_hp_ctrl, tvb, 2, 2, ENC_LITTLE_ENDIAN);
  subtree2 = proto_item_add_subtree(ti, ett_siii_mdt_hp_ctrl);

  proto_tree_add_item(subtree2, hf_siii_mdt_hotplug_control_svc_switch, tvb, 2, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(subtree2, hf_siii_mdt_hotplug_control_param, tvb, 2, 2, ENC_LITTLE_ENDIAN);

  proto_tree_add_item(subtree, hf_siii_mdt_hp_info, tvb, 4, 4, ENC_NA);
}

void dissect_siii_mdt_devctrl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_tree* subtree;
  proto_item* ti;

  ti = proto_tree_add_item(tree, hf_siii_mdt_dev_control, tvb, 0, 2, ENC_LITTLE_ENDIAN);
  subtree = proto_item_add_subtree(ti, ett_siii_mdt_devctrl);

  proto_tree_add_item(subtree, hf_siii_at_dev_control_ident, tvb, 0, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(subtree, hf_siii_mdt_dev_control_change_topology, tvb, 0, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(subtree, hf_siii_mdt_dev_control_top_control, tvb, 0, 2, ENC_LITTLE_ENDIAN);
}

void dissect_siii_mdt_svc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint devno _U_) /* devno will be needed in later versions */
{
  proto_tree* subtree;
  proto_item* ti;

  guint16 svc_ctrl = tvb_get_letohs(tvb, 0); /* service channel header */
  guint32 svc_info = tvb_get_letohl(tvb, 2); /* service channel data */
  guint8  svc_dbe  = (svc_ctrl>>3) & 7;      /* accessed data block element */

  ti = proto_tree_add_item(tree, hf_siii_mdt_svch_ctrl, tvb, 0, 2, ENC_LITTLE_ENDIAN);
  subtree = proto_item_add_subtree(ti, ett_siii_mdt_svcctrl);

  proto_tree_add_item(subtree, hf_siii_mdt_svch_dbe, tvb, 0, 2, ENC_LITTLE_ENDIAN); /* data block element */
  proto_tree_add_item(subtree, hf_siii_mdt_svch_eot, tvb, 0, 2, ENC_LITTLE_ENDIAN); /* end of transmission */
  proto_tree_add_item(subtree, hf_siii_mdt_svch_rw, tvb, 0, 2, ENC_LITTLE_ENDIAN);  /* read or write */
  proto_tree_add_item(subtree, hf_siii_mdt_svch_mhs, tvb, 0, 2, ENC_LITTLE_ENDIAN); /* master hand shake */

  ti = proto_tree_add_item(tree, hf_siii_mdt_svch_info, tvb, 2, 4, ENC_NA);

  if(1 == svc_dbe)
  {
    subtree = proto_item_add_subtree(ti, ett_siii_mdt_svcinfo);
    proto_tree_add_text(subtree, tvb, 2, 4, "IDN code: %c-%u-%04d.%d.%d",
      ((0xFFFF & svc_info)>>15)?'P':'S', /* private or sercos IDN */
      (svc_info>>12)&7, /* parameter record */
      (svc_info&4095), /* IDN */
      (svc_info>>24) & 0xFF, /* structure index */
      (svc_info>>16) & 0xFF); /* structure element */
    proto_tree_add_item(subtree, hf_siii_mdt_svch_idn, tvb, 2, 4, ENC_LITTLE_ENDIAN);
  }
}

static void dissect_siii_mdt_cp0(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item* ti;
  proto_tree* subtree;
  ti = proto_tree_add_item(tree, hf_siii_mdt_version, tvb, 0, 4, ENC_LITTLE_ENDIAN);
  subtree = proto_item_add_subtree(ti, ett_siii_mdt_version);

  proto_tree_add_item(subtree, hf_siii_mdt_version_num_mdt_at_cp1_2, tvb, 0, 4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(subtree, hf_siii_mdt_version_initprocvers, tvb, 0, 4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(subtree, hf_siii_mdt_version_revision, tvb, 0, 4, ENC_LITTLE_ENDIAN);

}

static void dissect_siii_mdt_cp1_2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint telno)
{
  guint devstart = telno * SERCOS_SLAVE_GROUP_SIZE; /* MDT0: slaves 0-127; MDT1: slaves 128-255; ... */
  tvbuff_t* tvb_n;

  guint idx;

  proto_item* ti;
  proto_tree* subtree;
  proto_tree* subtree_svc;
  proto_tree* subtree_devctrl;

  ti = proto_tree_add_text(tree, tvb, 0, SERCOS_SLAVE_GROUP_SIZE * 6, "Service Channels");
  subtree_svc = proto_item_add_subtree(ti, ett_siii_mdt_svc);

  ti = proto_tree_add_text(tree, tvb, SERCOS_SLAVE_GROUP_SIZE * 6, 512, "Device Control");
  subtree_devctrl = proto_item_add_subtree(ti, ett_siii_mdt_svc);

  for(idx = 0; idx < SERCOS_SLAVE_GROUP_SIZE; ++idx) /* each MDT of CP1/2 has data for 128 different slaves */
  {
    tvb_n = tvb_new_subset(tvb, 6 * idx, 6, 6); /* subset for service channel data */

    ti = proto_tree_add_text(subtree_svc, tvb_n, 0, 6, "Device %u", idx + devstart);
    subtree = proto_item_add_subtree(ti, ett_siii_mdt_svc_channel);
    dissect_siii_mdt_svc(tvb_n, pinfo, subtree, idx + devstart);

    tvb_n = tvb_new_subset(tvb, SERCOS_SLAVE_GROUP_SIZE * 6 + 4 * idx, 2, 2); /* subset for device control information */

    ti = proto_tree_add_text(subtree_devctrl, tvb_n, 0, 2, "Device %u", idx + devstart);
    subtree = proto_item_add_subtree(ti, ett_siii_mdt_dev_control);

    dissect_siii_mdt_devctrl(tvb_n, pinfo, subtree);
  }
}

static void dissect_siii_mdt_cp3_4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint telno)
{
  guint devstart _U_ = telno * SERCOS_SLAVE_GROUP_SIZE;

  if(0 == telno) /* dissect hotplug field in MDT0 only */
    dissect_siii_mdt_hp(tvb, pinfo, tree);

  /* offsets of service channel, device status and connections are unknown
   * this data could be extracted from svc communication during CP2
   */
  proto_tree_add_text(tree, tvb, 0, 0, "Service Channels");
  
  proto_tree_add_text(tree, tvb, 0, 0, "Device Controls");
}

void dissect_siii_mdt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item* ti;
  proto_tree* subtree;
  tvbuff_t* tvb_n;

  guint t_phase;
  guint telno;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SIII MDT");

  t_phase = (tvb_get_guint8(tvb, 1)&0x8F); /* read communication phase out of SERCOS III header */
  telno = (tvb_get_guint8(tvb, 0) & 0xF); /* read number of MDT out of SERCOS III header */

  if(t_phase & 0x80) /* communication phase switching in progress */
  {
    col_append_fstr(pinfo->cinfo, COL_INFO, " Phase=CP?s -> CP%u",
          (t_phase&0x0f));
  }
  else /* communication as usual */
  {
    col_append_fstr(pinfo->cinfo, COL_INFO, " Phase=CP%u",
          (t_phase&0x0f));
  }

  ti = proto_tree_add_text(tree, tvb, 0, -1, "MDT%u", telno);
  subtree = proto_item_add_subtree(ti, ett_siii_mdt);

  dissect_siii_mst(tvb, pinfo, subtree); /* dissect SERCOS III header */

  switch(t_phase) /* call the MDT dissector depending on the current communication phase */
  {
  case COMMUNICATION_PHASE_0: /* CP0 */
    tvb_n = tvb_new_subset(tvb, 6, 40, 40);
    dissect_siii_mdt_cp0(tvb_n, pinfo, subtree);
  break;

  case COMMUNICATION_PHASE_1: /* CP1 */
  case COMMUNICATION_PHASE_2: /* CP2 */
    tvb_n = tvb_new_subset(tvb, 6, 1280, 1280);
    dissect_siii_mdt_cp1_2(tvb_n, pinfo, subtree, telno);
  break;

  case COMMUNICATION_PHASE_3: /* CP3 */
  case COMMUNICATION_PHASE_4: /* CP4 */
    tvb_n = tvb_new_subset_remaining(tvb, 6);
    dissect_siii_mdt_cp3_4(tvb_n, pinfo, subtree, telno);
  break;

  default:
    proto_tree_add_text(tree, tvb, 6, -1, "CP is unknown");
  }
}

void dissect_siii_at_svc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint devno _U_) /* devno will be used in later versions */
{
  proto_tree* subtree;
  proto_item* ti;

  ti = proto_tree_add_item(tree, hf_siii_at_svch_stat, tvb, 0, 2, ENC_LITTLE_ENDIAN);
  subtree = proto_item_add_subtree(ti, ett_siii_at_svcstat);

  proto_tree_add_item(subtree, hf_siii_at_svch_valid, tvb, 0, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(subtree, hf_siii_at_svch_error, tvb, 0, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(subtree, hf_siii_at_svch_busy, tvb, 0, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(subtree, hf_siii_at_svch_ahs, tvb, 0, 2, ENC_LITTLE_ENDIAN);

  proto_tree_add_item(tree, hf_siii_at_svch_info, tvb, 2, 4, ENC_NA);
}

void dissect_siii_at_devstat(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_tree* subtree;
  proto_item* ti;

  ti = proto_tree_add_item(tree, hf_siii_at_dev_status, tvb, 0, 2, ENC_LITTLE_ENDIAN);
  subtree = proto_item_add_subtree(ti, ett_siii_at_devstatus);

  proto_tree_add_item(subtree, hf_siii_at_dev_status_commwarning, tvb, 0, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(subtree, hf_siii_at_dev_status_change_topology, tvb, 0, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(subtree, hf_siii_at_dev_status_top_status, tvb, 0, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(subtree, hf_siii_at_dev_status_inactive_port_status, tvb, 0, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(subtree, hf_siii_at_dev_status_errorconnection, tvb, 0, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(subtree, hf_siii_at_dev_status_slave_valid, tvb, 0, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(subtree, hf_siii_at_dev_status_proc_command_change, tvb, 0, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(subtree, hf_siii_at_dev_status_parameterization_level_active, tvb, 0, 2, ENC_LITTLE_ENDIAN);
}

void dissect_siii_at_hp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_tree* subtree;
  proto_tree* subtree2;
  proto_item* ti;

  ti = proto_tree_add_text(tree, tvb, 0, 8, "Hot-Plug");
  subtree = proto_item_add_subtree(ti, ett_siii_at_hp);

  proto_tree_add_item(subtree, hf_siii_at_hotplug_address, tvb, 2, 2, ENC_LITTLE_ENDIAN);

  ti = proto_tree_add_item(subtree, hf_siii_at_hp_stat, tvb, 2, 2, ENC_LITTLE_ENDIAN);
  subtree2 = proto_item_add_subtree(ti, ett_siii_at_hp_stat);

  proto_tree_add_item(subtree2, hf_siii_at_hotplug_status_error, tvb, 2, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(subtree2, hf_siii_at_hotplug_status_hp0_finished, tvb, 2, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(subtree2, hf_siii_at_hotplug_status_param, tvb, 2, 2, ENC_LITTLE_ENDIAN);

  proto_tree_add_item(subtree, hf_siii_at_hp_info, tvb, 4, 4, ENC_NA);
}

static void dissect_siii_at_cp0(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  guint16 seqcnt; /* sequence counter */
  guint16 tfield; /* topology field for sercos addresses */
  guint16 i;
  char devices[]="Recognized Devices"; /* fixme: it would be nice to have this as subtree */
  static char outbuf[200];

  proto_tree_add_text(tree, tvb, 0, 1024, "%s", devices);

  /* check sequence count field */
  seqcnt = tvb_get_letohs(tvb, 0);
  g_snprintf(outbuf, sizeof(outbuf), "Number of Devices: %u", (0x1FF & seqcnt)-1);
  proto_tree_add_text(tree, tvb, 0, 2, "%s", outbuf);

  /* check SERCOS address of each topology field */
  for(i=1;i < MAX_SERCOS_DEVICES; ++i)
  {
    tfield = tvb_get_letohs(tvb, i*2);

    if(tfield == 0)
    {
      g_snprintf(outbuf, sizeof(outbuf), "Device Address %u: No SERCOS Address", i);
    }
    else if(tfield == 0xFFFF)
    {
      g_snprintf(outbuf, sizeof(outbuf), "Device Address %u: No Device", i);
    }
    else
    {
      g_snprintf(outbuf, sizeof(outbuf), "Device Address %u: %u", i, tfield);
    }
    proto_tree_add_text(tree, tvb, i*2, 2, "%s", outbuf);
  }
}

static void dissect_siii_at_cp1_2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint telno)
{
  guint devstart = telno * SERCOS_SLAVE_GROUP_SIZE; /* AT0: slaves 0-127; AT1: slaves 128-255; ... */
  tvbuff_t* tvb_n;

  guint idx;

  proto_item* ti; /* temporary item */
  proto_tree* subtree;
  proto_tree* subtree_svc;
  proto_tree* subtree_devstat;

  ti = proto_tree_add_text(tree, tvb, 0, SERCOS_SLAVE_GROUP_SIZE * 6, "Service Channel");
  subtree_svc = proto_item_add_subtree(ti, ett_siii_at_svc);

  ti = proto_tree_add_text(tree, tvb, SERCOS_SLAVE_GROUP_SIZE * 6, 512, "Device Status");
  subtree_devstat = proto_item_add_subtree(ti, ett_siii_at_devstats);

  for(idx = 0; idx < SERCOS_SLAVE_GROUP_SIZE; ++idx) /* each AT of CP1/2 has data of 128 different slaves */
  {
    tvb_n = tvb_new_subset(tvb, 6 * idx, 6, 6); /* subset for service channel data */

    ti = proto_tree_add_text(subtree_svc, tvb_n, 0, 6, "Device %u", idx + devstart);
    subtree = proto_item_add_subtree(ti, ett_siii_at_svc_channel);
    dissect_siii_at_svc(tvb_n, pinfo, subtree, idx + devstart);

    tvb_n = tvb_new_subset(tvb, SERCOS_SLAVE_GROUP_SIZE * 6 + 4 * idx, 2, 2); /* subset for device status information */

    ti = proto_tree_add_text(subtree_devstat, tvb_n, 0, 2, "Device %u", idx + devstart);
    subtree = proto_item_add_subtree(ti, ett_siii_at_dev_status);
    dissect_siii_at_devstat(tvb_n, pinfo, subtree);
  }
}

static void dissect_siii_at_cp3_4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint telno)
{
  if(0 == telno) /* dissect hotplug field in AT0 only */
    dissect_siii_at_hp(tvb, pinfo, tree);

  /* offsets of service channel, device status and connections are unknown
   * this data could be extracted from svc communication during CP2
   */
  proto_tree_add_text(tree, tvb, 0, 0, "Service Channels");  
  proto_tree_add_text(tree, tvb, 0, 0, "Device Status");
}


void dissect_siii_at(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item*  ti; /* temporary item */
  proto_tree* subtree;
  tvbuff_t* tvb_n;

  guint8 phase;
  guint telno;

  phase = (tvb_get_guint8(tvb, 1)&0x8F); /* read communication phase out of SERCOS III header*/
  telno = (tvb_get_guint8(tvb, 0) & 0xF); /* read number of AT out of SERCOS III header */

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SIII AT");

  if(phase & 0x80) /* communication phase switching in progress */
  {
    col_append_fstr(pinfo->cinfo, COL_INFO, " Phase=CP?s -> CP%u",
          (phase&0x0f));
  }
  else /* communication as usual */
  {
     col_append_fstr(pinfo->cinfo, COL_INFO, " Phase=CP%u",
          (phase&0x0f));
  }

  ti = proto_tree_add_text(tree, tvb, 0, -1, "AT%u", telno);
  subtree = proto_item_add_subtree(ti, ett_siii_at);

  dissect_siii_mst(tvb, pinfo, subtree); /* dissect SERCOS III header */

    switch(phase) /* call the AT dissector depending on the current communication phase */
    {
    case COMMUNICATION_PHASE_0: /* CP0 */
      tvb_n = tvb_new_subset(tvb, 6, 1024, 1024);
      dissect_siii_at_cp0(tvb_n, pinfo, subtree);
    break;

    case COMMUNICATION_PHASE_1: /* CP1 */
    case COMMUNICATION_PHASE_2: /* CP2 */
      tvb_n = tvb_new_subset(tvb, 6, 1280, 1280);
      dissect_siii_at_cp1_2(tvb_n, pinfo, subtree, telno);
    break;

    case COMMUNICATION_PHASE_3: /* CP3 */
    case COMMUNICATION_PHASE_4: /* CP4 */
      tvb_n = tvb_new_subset_remaining(tvb, 6);
      dissect_siii_at_cp3_4(tvb_n, pinfo, subtree, telno);
    break;

    default:
      proto_tree_add_text(tree, tvb, 6, -1, "CP is unknown");
    break;
    }
}

/* Main dissector entry */
static void
dissect_siii(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item*  ti;
  proto_tree*  siii_tree;
  guint    type;
  char* tel_ch="?";
  char* tel_type="?";
  guint tel_no = 0;

  /* setup columns */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SERCOS III V1.1");
  col_clear(pinfo->cinfo, COL_INFO);

  /*
   * In case the packet is a protocol encoded in the basic SercosIII transport stream,
   * give that protocol a chance to make a heuristic dissection, before we continue
   * to dissect it as a normal SercosIII packet.
   */
  if (dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, tree))
    return;

  /* check what we got on our hand */
  type = tvb_get_guint8(tvb, 0);
  if(type&0x80) /* primary or secondary channel */
    tel_ch="S";
  else
    tel_ch="P";

  if(type&0x40) /* master data telegram (mdt) or slave telegram (at) */
    tel_type="AT ";
  else
    tel_type="MDT";

  tel_no = type &0xF; /* even though it's reserved (the V1.1 spec states that it is reserved for additional MDT/AT) */

  col_append_fstr(pinfo->cinfo, COL_INFO, "%s%u Channel=%s", tel_type, tel_no, tel_ch);

  ti = proto_tree_add_item(tree, proto_siii, tvb, 0, -1, FALSE);

  siii_tree = proto_item_add_subtree(ti, ett_siii);

   /* enter the specific dissector for AT or MDT */
  if(type & 0x40)
    dissect_siii_at(tvb, pinfo, siii_tree);
  else
    dissect_siii_mdt(tvb, pinfo, siii_tree);
}

void
proto_register_sercosiii(void)
{
  static hf_register_info hf[] = {

    { &hf_siii_mdt_version,
      { "Communication Version", "siii.mdt.version",
      FT_UINT32, BASE_HEX, NULL, 0,
      NULL, HFILL }
    },
    { &hf_siii_mdt_version_revision,
      { "Revision Number", "siii.mdt.version.revision",
      FT_UINT32, BASE_HEX, NULL, 0x7F,
      NULL, HFILL }
    },
    { &hf_siii_mdt_version_num_mdt_at_cp1_2,
      { "Number of MDTs and ATS in CP1 and CP2", "siii.mdt.version.num_mdt_at_cp1_2",
      FT_UINT32, BASE_HEX, VALS(siii_mdt_version_num_mdtat_cp1_2_text), 0x30000,
      NULL, HFILL }
    },
    { &hf_siii_mdt_version_initprocvers,
      { "Initialization Procedure Version Number", "siii.mdt.version.initprocvers",
      FT_UINT32, BASE_HEX, VALS(siii_mdt_version_initprocvers_text), 0xFF00,
      NULL, HFILL }
    },

    { &hf_siii_mdt_dev_control_top_control,
      { "Topology Control", "siii.mdt.devcontrol.topcontrol",
      FT_UINT16, BASE_DEC, VALS(siii_mdt_devcontrol_topcontrol_text), 3<<(12),
      NULL, HFILL }
    },
    { &hf_siii_at_dev_control_ident,
      { "Identification", "siii.mdt.devcontrol.identrequest",
      FT_UINT16, BASE_DEC, NULL, 0x8000,
      NULL, HFILL }
    },
    { &hf_siii_mdt_dev_control_change_topology,
      { "Changing Topology", "siii.mdt.devcontrol.topologychange",
      FT_UINT16, BASE_DEC, NULL, 1<<14,
      NULL, HFILL }
    },
    { &hf_siii_mdt_dev_control,
      { "Word", "siii.mdt.devcontrol",
      FT_UINT16, BASE_DEC, NULL, 0,
      NULL, HFILL }
    },

    { &hf_siii_at_dev_status,
      { "Word", "siii.at.devstatus",
      FT_UINT16, BASE_HEX, NULL, 0,
      NULL, HFILL }
    },

    { &hf_siii_at_dev_status_commwarning,
      { "Communication Warning", "siii.at.devstatus.commwarning",
      FT_UINT16, BASE_DEC, NULL, 1<<15,
      NULL, HFILL }
    },

    { &hf_siii_at_dev_status_change_topology,
      { "Topology Change", "siii.at.devstatus.topologychanged",
      FT_UINT16, BASE_DEC, NULL, 1<<14,
      NULL, HFILL }
    },
    { &hf_siii_at_dev_status_top_status,
      { "Topology Status", "siii.at.devstatus.topstatus",
      FT_UINT16, BASE_DEC, VALS(siii_at_devstatus_topstatus_text), 0x3<<(12),
      NULL, HFILL }
    },
    { &hf_siii_at_dev_status_inactive_port_status,
      { "Port 1 Status", "siii.at.devstatus.inactportstatus",
      FT_UINT16, BASE_DEC, VALS(siii_at_devstatus_inactiveportstatus_text), 0x3<<(10),
      NULL, HFILL }
    },
    { &hf_siii_at_dev_status_errorconnection,
      { "Topology Status", "siii.at.devstatus.errorconnection",
      FT_UINT16, BASE_DEC, VALS(siii_at_devstatus_errorconnection_text), 1<<9,
      NULL, HFILL }
    },
    { &hf_siii_at_dev_status_slave_valid,
      { "Slave data valid", "siii.at.devstatus.slavevalid",
      FT_UINT16, BASE_DEC, NULL, 1<<8,
      NULL, HFILL }
    },
    { &hf_siii_at_dev_status_proc_command_change,
      { "Procedure Command Change", "siii.at.devstatus.proccmdchange",
      FT_UINT16, BASE_DEC, VALS(siii_at_dev_status_proc_command_change_text), 1<<5,
      NULL, HFILL }
    },
    { &hf_siii_at_dev_status_parameterization_level_active,
      { "Parameterization level active", "siii.at.devstatus.paralevelactive",
      FT_UINT16, BASE_DEC, NULL, 1<<4,
      NULL, HFILL }
    },

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
    },

    { &hf_siii_mst_channel,
      { "Channel", "siii.channel",
        FT_UINT8, BASE_DEC, VALS(siii_mst_channel_text), 0x80,
        NULL, HFILL }
    },
    { &hf_siii_mst_type,
      { "Telegram Type" , "siii.type",
        FT_UINT8, BASE_DEC, VALS(siii_mst_type_text), 0x40,
        NULL, HFILL }
    },
    { &hf_siii_mst_cyclecntvalid,
      { "Cycle Count Valid", "siii.cyclecntvalid",
        FT_UINT8, BASE_DEC, VALS(siii_mst_cyclecntvalid_text), 0x20,
        NULL, HFILL }
    },
    { &hf_siii_mst_telno,
      { "Telegram Number", "siii.telno",
        FT_UINT8, BASE_DEC, NULL, 0x0F,
        NULL, HFILL }
    },
    { &hf_siii_mst_phase,
      { "Phase", "siii.mst.phase",
        FT_UINT8, BASE_HEX, VALS(siii_mst_phase_text), 0x8F,    /* CHANGED: SB: new value is 0x8F for masking out phase */
        NULL, HFILL }
    },
    { &hf_siii_mst_cyclecnt,
      { "Cycle Cnt", "siii.mst.cyclecnt",
        FT_UINT8, BASE_DEC, NULL, 0x70,    /* CHANGED: SB: new value is 0x70 for masking out cycle cnt */
        NULL, HFILL }
    },
    { &hf_siii_mst_crc32,
      { "CRC32", "siii.mst.crc32",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },

    { &hf_siii_mdt_hotplug_address,
      {"Sercos address", "siii.mdt.hp.sercosaddress",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
    { &hf_siii_mdt_hp_ctrl,
      {"HP control", "siii.mdt.hp.ctrl",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
    { &hf_siii_mdt_hp_info,
      {"HP info", "siii.mdt.hp.info",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_siii_at_hotplug_address,
      {"Sercos address", "siii.at.hp.sercosaddress",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
    { &hf_siii_at_hp_stat,
      {"HP status", "siii.mdt.hp.stat",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
    { &hf_siii_at_hp_info,
      {"HP info", "siii.at.hp.info",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }
    },
    { &hf_siii_mdt_hotplug_control_param,
      {"Parameter", "siii.mdt.hp.parameter",
        FT_UINT16, BASE_DEC, VALS(siii_mdt_hotplug_control_functioncode_text), 0xFF,
        NULL, HFILL }
    },
    { &hf_siii_mdt_hotplug_control_svc_switch,
      {"Switch to SVC", "siii.mdt.hp.switch",
        FT_UINT16, BASE_DEC, VALS(siii_mdt_hotplug_control_svc_switch_text), 0x100,
        NULL, HFILL }
    },

    { &hf_siii_at_hotplug_status_param,
      {"Parameter Received", "siii.at.hp.parameter",
        FT_UINT16, BASE_DEC, VALS(siii_mdt_hotplug_status_ackcode_text), 0xFF,
        NULL, HFILL }
    },
    { &hf_siii_at_hotplug_status_hp0_finished,
      {"HP/SVC", "siii.at.hp.hp0_finished",
        FT_UINT16, BASE_DEC, NULL, 0x100,
        NULL, HFILL }
    },
    { &hf_siii_at_hotplug_status_error,
      {"Error", "siii.at.hp.error",
        FT_UINT16, BASE_DEC, VALS(siii_at_hotplug_status_error_text), 0x200,
        NULL, HFILL }
    }
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_siii,
    &ett_siii_header,

    &ett_siii_mdt,
    &ett_siii_mdt_version,
    &ett_siii_mdt_svc,
    &ett_siii_mdt_devctrls,
    &ett_siii_mdt_svc_channel,
    &ett_siii_mdt_dev_control,

    &ett_siii_at,
    &ett_siii_at_svc,
    &ett_siii_at_devstats,
    &ett_siii_at_svc_channel,
    &ett_siii_at_dev_status,

    &ett_siii_mdt_devctrl,
    &ett_siii_at_devstatus,

    &ett_siii_mdt_svcctrl,
    &ett_siii_mdt_svcinfo,
    &ett_siii_at_svcstat,
    &ett_siii_at_svcinfo,
    &ett_siii_mdt_svch_data_error_info,
    &ett_siii_mdt_svch_data,

    &ett_siii_mst,
    &ett_siii_mst_teltype,
    &ett_siii_mst_phase,

    &ett_siii_mdt_hp,
    &ett_siii_at_hp,
    &ett_siii_mdt_hp_ctrl,
    &ett_siii_mdt_hp_info,
    &ett_siii_at_hp_stat,
    &ett_siii_at_hp_info
  };


  /* Register the protocol name and description */
  proto_siii = proto_register_protocol("SERCOS III V1.1",
      "SERCOS III V1.1", "siii");

  register_dissector("sercosiii", dissect_siii, proto_siii);

  /* subdissector code */
  register_heur_dissector_list("sercosiii", &heur_subdissector_list);

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_siii, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_sercosiii(void)
{
  dissector_handle_t siii_handle;

  siii_handle = create_dissector_handle(dissect_siii, proto_siii);
  dissector_add_uint("ethertype", ETHERTYPE_SERCOS, siii_handle);
}
