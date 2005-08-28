/* packet-gnm.c
 * Routines for GENERIC NETWORK INFORMATION MODEL Data dissection
 *
 * Copyright 2005 , Anders Broman <anders.broman [AT] ericsson.com>
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
 *
 *
 * References:
 * ITU-T recommendatiom M.3100
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>
#include "packet-cmip.h"
#include "packet-ber.h"
#include "packet-gnm.h"

#define PNAME  "ITU M.3100 Generic Network Information Model"
#define PSNAME "GNM"
#define PFNAME "gnm"

/* Initialize the protocol and registered fields */
int proto_gnm = -1;

static int hf_gnm_AdministrativeState = -1;
#include "packet-gnm-hf.c"

/* Initialize the subtree pointers */
#include "packet-gnm-ett.c"

#include "packet-gnm-fn.c"



static void
dissect_gnm_attribute_1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_gnm_RelatedObjectInstance(FALSE, tvb, 0, pinfo, parent_tree, -1);

}

static void
dissect_gnm_attribute_ObjectList(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_gnm_ObjectList(FALSE, tvb, 0, pinfo, parent_tree, -1);

}

static void
dissect_gnm_attribute_3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_gnm_AlarmSeverityAssignmentList(FALSE, tvb, 0, pinfo, parent_tree, -1);

}

static void
dissect_gnm_attribute_6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_gnm_AlarmStatus(FALSE, tvb, 0, pinfo, parent_tree, hf_gnm_alarmStatus);

}

static void
dissect_gnm_attribute_7(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_gnm_ChannelNumber(FALSE, tvb, 0, pinfo, parent_tree, hf_gnm_alarmStatus);

}
static void
dissect_gnm_attribute_8(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_gnm_CharacteristicInformation(FALSE, tvb, 0, pinfo, parent_tree, hf_gnm_alarmStatus);

}
static void
dissect_gnm_attribute_15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_gnm_CrossConnectionName(FALSE, tvb, 0, pinfo, parent_tree, -1);

}
static void
dissect_gnm_attribute_16(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_gnm_CrossConnectionObjectPointer(FALSE, tvb, 0, pinfo, parent_tree, -1);

}
static void
dissect_gnm_attribute_17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_gnm_CurrentProblemList(FALSE, tvb, 0, pinfo, parent_tree, -1);

}
static void
dissect_gnm_attribute_18(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_gnm_Directionality(FALSE, tvb, 0, pinfo, parent_tree, -1);

}
static void
dissect_gnm_attribute_19(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_gnm_DownstreamConnectivityPointer(FALSE, tvb, 0, pinfo, parent_tree, -1);

}
static void
dissect_gnm_attribute_21(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_gnm_ExternalTime(FALSE, tvb, 0, pinfo, parent_tree, -1);

}

static void
dissect_gnm_attribute_26(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_gnm_ListOfCharacteristicInformation(FALSE, tvb, 0, pinfo, parent_tree, -1);

}
static void
dissect_gnm_attribute_27(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_gnm_LocationName(FALSE, tvb, 0, pinfo, parent_tree, -1);

}
static void
dissect_gnm_attribute_34(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_gnm_Replaceable(FALSE, tvb, 0, pinfo, parent_tree, -1);

}
static void
dissect_gnm_attribute_SequenceOfObjectInstance(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_gnm_SequenceOfObjectInstance(FALSE, tvb, 0, pinfo, parent_tree, -1);

}
static void
dissect_gnm_attribute_PointerOrNull(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_gnm_PointerOrNull(FALSE, tvb, 0, pinfo, parent_tree, -1);

}

static void
dissect_gnm_attribute_NameType(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_gnm_NameType(FALSE, tvb, 0, pinfo, parent_tree, -1);

}

static void
dissect_gnm_attribute_ObjectInstance(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_cmip_ObjectInstance(FALSE, tvb, 0, pinfo, parent_tree, -1);

}
static void
dissect_gnm_attribute_Count(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_gnm_Count(FALSE, tvb, 0, pinfo, parent_tree, -1);

}
static void
dissect_gnm_attribute_Boolean(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_gnm_Boolean(FALSE, tvb, 0, pinfo, parent_tree, -1);

}
static void
dissect_smi_attribute_31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_gnm_AdministrativeState(FALSE, tvb, 0, pinfo, parent_tree, hf_gnm_AdministrativeState);

}

static void
dissect_smi_attribute_34(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_gnm_ControlStatus(FALSE, tvb, 0, pinfo, parent_tree, -1);

}

static void
dissect_smi_attribute_66(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_gnm_Packages(FALSE, tvb, 0, pinfo, parent_tree, -1);

}

static void
dissect_part12AttributeId_7(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_gnm_SupportedTOClasses(FALSE, tvb, 0, pinfo, parent_tree, -1);

}


void
dissect_gnm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
  /* Dymmy function */
}

/*--- proto_register_gnm -------------------------------------------*/
void proto_register_gnm(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_gnm_AdministrativeState,
      { "AdministrativeState", "gnm.AdministrativeState",
        FT_UINT32, BASE_DEC, VALS(gnm_AdministrativeState_vals), 0,
        "", HFILL }},

#include "packet-gnm-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-gnm-ettarr.c"
  };

  /* Register protocol */
  proto_gnm = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("gnm", dissect_gnm, proto_gnm);
  /* Register fields and subtrees */
  proto_register_field_array(proto_gnm, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_gnm ---------------------------------------*/
void proto_reg_handoff_gnm(void) {
	register_ber_oid_dissector("0.0.13.3100.0.7.1", dissect_gnm_attribute_1, proto_gnm, "a-TPInstance(1)");
	register_ber_oid_dissector("0.0.13.3100.0.7.2", dissect_gnm_attribute_ObjectList, proto_gnm, "affectedObjectList(2)");
	register_ber_oid_dissector("0.0.13.3100.0.7.3", dissect_gnm_attribute_3, proto_gnm, "alarmSeverityAssignmentList(3)");
	register_ber_oid_dissector("0.0.13.3100.0.7.4", dissect_gnm_attribute_NameType, proto_gnm, "alarmSeverityAssignmentProfileId(4)");
	register_ber_oid_dissector("0.0.13.3100.0.7.5", dissect_gnm_attribute_PointerOrNull, proto_gnm, "alarmSeverityAssignmentProfilePointer(5)");
	register_ber_oid_dissector("0.0.13.3100.0.7.6", dissect_gnm_attribute_6, proto_gnm, "alarmStatus(6)");
	register_ber_oid_dissector("0.0.13.3100.0.7.7", dissect_gnm_attribute_7, proto_gnm, "channelNumber(7)");
	register_ber_oid_dissector("0.0.13.3100.0.7.8", dissect_gnm_attribute_8, proto_gnm, "characteristicInformation(8)");
	register_ber_oid_dissector("0.0.13.3100.0.7.9", dissect_gnm_attribute_ObjectInstance, proto_gnm, "clientConnection(9)");
	register_ber_oid_dissector("0.0.13.3100.0.7.10", dissect_gnm_attribute_ObjectInstance, proto_gnm, "clientTrail(10)");

	register_ber_oid_dissector("0.0.13.3100.0.7.11", dissect_gnm_attribute_Count, proto_gnm, "connectedTpCount(11)");
	register_ber_oid_dissector("0.0.13.3100.0.7.12", dissect_gnm_attribute_NameType, proto_gnm, "connectionId(12)");
	register_ber_oid_dissector("0.0.13.3100.0.7.13", dissect_gnm_attribute_NameType, proto_gnm, "cTPId(13)");
	register_ber_oid_dissector("0.0.13.3100.0.7.14", dissect_gnm_attribute_NameType, proto_gnm, "crossConnectionId(14)");
	register_ber_oid_dissector("0.0.13.3100.0.7.15", dissect_gnm_attribute_15, proto_gnm, "crossConnectionName(15)");
	register_ber_oid_dissector("0.0.13.3100.0.7.16", dissect_gnm_attribute_16, proto_gnm, "crossConnectionObjectPointer(16)");
	register_ber_oid_dissector("0.0.13.3100.0.7.17", dissect_gnm_attribute_17, proto_gnm, "currentProblemList(17)");
	register_ber_oid_dissector("0.0.13.3100.0.7.18", dissect_gnm_attribute_18, proto_gnm, "directionality(18)");
	register_ber_oid_dissector("0.0.13.3100.0.7.19", dissect_gnm_attribute_19, proto_gnm, "downstreamConnectivityPointer(19)");
	
	register_ber_oid_dissector("0.0.13.3100.0.7.20", dissect_gnm_attribute_NameType, proto_gnm, "equipmentId(20)");
	register_ber_oid_dissector("0.0.13.3100.0.7.21", dissect_gnm_attribute_19, proto_gnm, "externalTime(21)");
	register_ber_oid_dissector("0.0.13.3100.0.7.22", dissect_gnm_attribute_NameType, proto_gnm, "fabricId(22)");
	register_ber_oid_dissector("0.0.13.3100.0.7.23", dissect_gnm_attribute_PointerOrNull, proto_gnm, "fromTermination(23)");
	register_ber_oid_dissector("0.0.13.3100.0.7.24", dissect_gnm_attribute_NameType, proto_gnm, "gtpId(24)");
	register_ber_oid_dissector("0.0.13.3100.0.7.25", dissect_gnm_attribute_Count, proto_gnm, "idleTpCount(25)");
	register_ber_oid_dissector("0.0.13.3100.0.7.26", dissect_gnm_attribute_26, proto_gnm, "listOfCharacteristicInfo(26)");
	register_ber_oid_dissector("0.0.13.3100.0.7.27", dissect_gnm_attribute_27, proto_gnm, "locationName(27)");
	register_ber_oid_dissector("0.0.13.3100.0.7.28", dissect_gnm_attribute_NameType, proto_gnm, "managedElementId(28)");
	register_ber_oid_dissector("0.0.13.3100.0.7.29", dissect_gnm_attribute_NameType, proto_gnm, "mpCrossConnectionId(29)");
	register_ber_oid_dissector("0.0.13.3100.0.7.30", dissect_gnm_attribute_NameType, proto_gnm, "networkId(30)");

	register_ber_oid_dissector("0.0.13.3100.0.7.31", dissect_gnm_attribute_ObjectInstance, proto_gnm, "networkLevelPointer(31)");
	register_ber_oid_dissector("0.0.13.3100.0.7.32", dissect_gnm_attribute_Boolean, proto_gnm, "protected(32)");
	register_ber_oid_dissector("0.0.13.3100.0.7.33", dissect_gnm_attribute_Boolean, proto_gnm, "redline(33)");
	register_ber_oid_dissector("0.0.13.3100.0.7.34", dissect_gnm_attribute_34, proto_gnm, "replaceable(34)");
	register_ber_oid_dissector("0.0.13.3100.0.7.35", dissect_gnm_attribute_SequenceOfObjectInstance, proto_gnm, "serverConnectionList(35)");
	register_ber_oid_dissector("0.0.13.3100.0.7.36", dissect_gnm_attribute_ObjectList, proto_gnm, "serverTrailList(36)");

	register_ber_oid_dissector("2.9.3.2.7.31", dissect_smi_attribute_31, proto_gnm, "smi2AttributeID (7) administrativeState(31)");
	register_ber_oid_dissector("2.9.3.2.7.34", dissect_smi_attribute_34, proto_gnm, "smi2AttributeID (7) controlStatus(34)");
	register_ber_oid_dissector("2.9.3.2.7.66", dissect_smi_attribute_66, proto_gnm, "smi2AttributeID (7) packages(66)");

	register_ber_oid_dissector("2.9.2.12.7.7", dissect_part12AttributeId_7, proto_gnm, "part12AttributeId (7) supportedTOClasses(7)");


}
