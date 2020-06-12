/* packet-isobus-vt.c
 * Routines for ISObus VT dissection (Based on CANOpen Dissector)
 * Copyright 2016, Jeroen Sack <jsack@lely.com>
 * ISO 11783-6
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <wsutil/file_util.h>

#define MAX_OBJECT_ID_DB_SIZE 10000

void proto_register_isobus_vt(void);
void proto_reg_handoff_isobus_vt(void);

static guint8 current_vt_version = 0;

/* Initialize the protocol and registered fields */
static int proto_vt = -1;
static int hf_isobus_vt = -1;
static int hf_isobus_vt_command = -1;
static int hf_isobus_vt_objectid = -1;
static int hf_isobus_vt_softkey_keyactcode = -1;
static int hf_isobus_vt_softkey_objectid = -1;
static int hf_isobus_vt_softkey_parentobjectid = -1;
static int hf_isobus_vt_softkey_keynumber = -1;
static int hf_isobus_vt_button_keyactcode = -1;
static int hf_isobus_vt_button_objectid = -1;
static int hf_isobus_vt_button_parentobjectid = -1;
static int hf_isobus_vt_button_keynumber = -1;
static int hf_isobus_vt_pointing_xposition = -1;
static int hf_isobus_vt_pointing_yposition = -1;
static int hf_isobus_vt_pointing_touchstate = -1;
static int hf_isobus_vt_vtselectinputobject_objectid = -1;
static int hf_isobus_vt_vtselectinputobject_selection = -1;
static int hf_isobus_vt_vtselectinputobject_openforinput = -1;
static int hf_isobus_vt_vtescmessage_objectid = -1;
static int hf_isobus_vt_vtescmessage_errorcodes = -1;
static int hf_isobus_vt_vtchgnumval_objectid = -1;
static int hf_isobus_vt_vtchgnumval_value = -1;
static int hf_isobus_vt_vtchgactivemask_maskobjectid = -1;
static int hf_isobus_vt_vtchgactivemask_errorcodes = -1;
static int hf_isobus_vt_vtchgactivemask_errorobjectid = -1;
static int hf_isobus_vt_vtchgactivemask_errorobjectidparent = -1;
static int hf_isobus_vt_vtchgstrval_objectid = -1;
static int hf_isobus_vt_vtchgstrval_length = -1;
static int hf_isobus_vt_vtchgstrval_value = -1;
static int hf_isobus_vt_vtonuserlayouthideshow_objectid_1 = -1;
static int hf_isobus_vt_vtonuserlayouthideshow_status_1 = -1;
static int hf_isobus_vt_vtonuserlayouthideshow_objectid_2 = -1;
static int hf_isobus_vt_vtonuserlayouthideshow_status_2 = -1;
static int hf_isobus_vt_vtcontrolaudiosignaltermination_terminationcause = -1;
static int hf_isobus_vt_endofobjectpool_errorcodes = -1;
static int hf_isobus_vt_endofobjectpool_faultyobjectid = -1;
static int hf_isobus_vt_endofobjectpool_faultyparentobjectid = -1;
static int hf_isobus_vt_endofobjectpool_objectpoolerrorcodes = -1;
static int hf_isobus_vt_auxiliaryassignmenttype1_sourceaddressauxinputdevice = -1;
static int hf_isobus_vt_auxiliaryassignmenttype1_auxinputnumber = -1;
static int hf_isobus_vt_auxiliaryassignmenttype1_objectidauxinputdevice = -1;
static int hf_isobus_vt_auxiliaryinputtype1status_inputnumber = -1;
static int hf_isobus_vt_auxiliaryinputtype1status_analyzevalue = -1;
static int hf_isobus_vt_auxiliaryinputtype1status_numberoftransitions = -1;
static int hf_isobus_vt_auxiliaryinputtype1status_booleanvalue = -1;
static int hf_isobus_vt_preferredassignment_numberofinputunits = -1;
static int hf_isobus_vt_preferredassignment_auxinputunit_name = -1;
static int hf_isobus_vt_preferredassignment_auxinputunit_modelidentificationcode = -1;
static int hf_isobus_vt_preferredassignment_auxinputunit_numberofpreferredfunctions = -1;
static int hf_isobus_vt_preferredassignment_auxinputunit_preferredfunctions_auxfunctionobjectid = -1;
static int hf_isobus_vt_preferredassignment_auxinputunit_preferredfunctions_auxinputobjectid = -1;
static int hf_isobus_vt_preferredassignment_errorcodes = -1;
static int hf_isobus_vt_preferredassignment_faultyauxiliaryfunctionobjectid = -1;
static int hf_isobus_vt_auxiliaryinputtype2maintenance_modelidentificationcode = -1;
static int hf_isobus_vt_auxiliaryinputtype2maintenance_status = -1;
static int hf_isobus_vt_auxiliaryassignmenttype2_name = -1;
static int hf_isobus_vt_auxiliaryassignmenttype2_flags = -1;
static int hf_isobus_vt_auxiliaryassignmenttype2_flags_preferredassignment = -1;
static int hf_isobus_vt_auxiliaryassignmenttype2_flags_auxiliaryfunctiontype = -1;
static int hf_isobus_vt_auxiliaryassignmenttype2_auxinputobjectid = -1;
static int hf_isobus_vt_auxiliaryassignmenttype2_auxfunctionobjectid = -1;
static int hf_isobus_vt_auxiliaryassignmenttype2_errorcodes = -1;
static int hf_isobus_vt_auxiliaryinputstatustype2enable_auxiliaryinputobjectid = -1;
static int hf_isobus_vt_auxiliaryinputstatustype2enable_enable = -1;
static int hf_isobus_vt_auxiliaryinputstatustype2enable_status = -1;
static int hf_isobus_vt_auxiliaryinputstatustype2enable_errorcodes = -1;
static int hf_isobus_vt_auxiliaryinputtype2status_auxiliaryinputobjectid = -1;
static int hf_isobus_vt_auxiliaryinputtype2status_value1 = -1;
static int hf_isobus_vt_auxiliaryinputtype2status_value2 = -1;
static int hf_isobus_vt_auxiliaryinputtype2status_operatingstate = -1;
static int hf_isobus_vt_auxiliaryinputtype2status_operatingstate_learnmodeactive = -1;
static int hf_isobus_vt_auxiliaryinputtype2status_operatingstate_inputactivatedinlearnmode = -1;
static int hf_isobus_vt_auxiliarycapabilities_requesttype = -1;
static int hf_isobus_vt_auxiliarycapabilities_numberofauxiliaryunits = -1;
static int hf_isobus_vt_auxiliarycapabilities_auxiliaryunit_name = -1;
static int hf_isobus_vt_auxiliarycapabilities_auxiliaryunit_numberofdifferentsets = -1;
static int hf_isobus_vt_auxiliarycapabilities_auxiliaryunit_set_numberofinstances = -1;
static int hf_isobus_vt_auxiliarycapabilities_auxiliaryunit_set_functionattribute = -1;
static int hf_isobus_vt_auxiliarycapabilities_auxiliaryunit_set_assignedattribute = -1;
static int hf_isobus_vt_esc_objectid = -1;
static int hf_isobus_vt_esc_errorcodes = -1;
static int hf_isobus_vt_hideshowobj_objectid = -1;
static int hf_isobus_vt_hideshowobj_action = -1;
static int hf_isobus_vt_hideshowobj_errorcodes = -1;
static int hf_isobus_vt_enabledisableobj_objectid = -1;
static int hf_isobus_vt_enabledisableobj_enabledisable = -1;
static int hf_isobus_vt_enabledisableobj_errorcodes = -1;
static int hf_isobus_vt_selectinputobject_objectid = -1;
static int hf_isobus_vt_selectinputobject_option = -1;
static int hf_isobus_vt_selectinputobject_response = -1;
static int hf_isobus_vt_selectinputobject_errorcodes = -1;
static int hf_isobus_vt_controlaudiosignal_activations = -1;
static int hf_isobus_vt_controlaudiosignal_frequency = -1;
static int hf_isobus_vt_controlaudiosignal_ontime = -1;
static int hf_isobus_vt_controlaudiosignal_offtime = -1;
static int hf_isobus_vt_controlaudiosignal_errorcodes = -1;
static int hf_isobus_vt_setaudiovolume_volume = -1;
static int hf_isobus_vt_setaudiovolume_errorcodes = -1;
static int hf_isobus_vt_changechildlocation_parentobjectid = -1;
static int hf_isobus_vt_changechildlocation_objectid = -1;
static int hf_isobus_vt_changechildlocation_relativexpos = -1;
static int hf_isobus_vt_changechildlocation_relativeypos = -1;
static int hf_isobus_vt_changechildlocation_errorcodes = -1;
static int hf_isobus_vt_changesize_objectid = -1;
static int hf_isobus_vt_changesize_newwidth = -1;
static int hf_isobus_vt_changesize_newheight = -1;
static int hf_isobus_vt_changesize_errorcodes = -1;
static int hf_isobus_vt_changebackgroundcolour_objectid = -1;
static int hf_isobus_vt_changebackgroundcolour_colour = -1;
static int hf_isobus_vt_changebackgroundcolour_errorcodes = -1;
static int hf_isobus_vt_chgnumval_objectid = -1;
static int hf_isobus_vt_chgnumval_errorcodes = -1;
static int hf_isobus_vt_chgnumval_value = -1;
static int hf_isobus_vt_changeendpoint_objectid = -1;
static int hf_isobus_vt_changeendpoint_width = -1;
static int hf_isobus_vt_changeendpoint_height = -1;
static int hf_isobus_vt_changeendpoint_linedirection = -1;
static int hf_isobus_vt_changefontattributes_objectid = -1;
static int hf_isobus_vt_changefontattributes_fontcolour = -1;
static int hf_isobus_vt_changefontattributes_fontsize = -1;
static int hf_isobus_vt_changefontattributes_fonttype = -1;
static int hf_isobus_vt_changefontattributes_fontstyle = -1;
static int hf_isobus_vt_changefontattributes_errorcodes = -1;
static int hf_isobus_vt_changelineattributes_objectid = -1;
static int hf_isobus_vt_changelineattributes_linecolour = -1;
static int hf_isobus_vt_changelineattributes_linewidth = -1;
static int hf_isobus_vt_changelineattributes_lineart = -1;
static int hf_isobus_vt_changelineattributes_errorcodes = -1;
static int hf_isobus_vt_changefillattributes_objectid = -1;
static int hf_isobus_vt_changefillattributes_filltype = -1;
static int hf_isobus_vt_changefillattributes_fillcolour = -1;
static int hf_isobus_vt_changefillattributes_fillpatternobjectid = -1;
static int hf_isobus_vt_changefillattributes_errorcodes = -1;
static int hf_isobus_vt_changeactivemask_workingset = -1;
static int hf_isobus_vt_changeactivemask_newactivemask = -1;
static int hf_isobus_vt_changeactivemask_errorcodes = -1;
static int hf_isobus_vt_changesoftkeymask_masktype = -1;
static int hf_isobus_vt_changesoftkeymask_datamaskobjectid = -1;
static int hf_isobus_vt_changesoftkeymask_newsoftkeymaskobjectid = -1;
static int hf_isobus_vt_changesoftkeymask_errorcodes = -1;
static int hf_isobus_vt_changeattributes_objectid = -1;
static int hf_isobus_vt_changeattributes_attributeid = -1;
static int hf_isobus_vt_changeattributes_newvalue = -1;
static int hf_isobus_vt_changeattributes_errorcodes = -1;
static int hf_isobus_vt_changepriority_objectid = -1;
static int hf_isobus_vt_changepriority_newpriority = -1;
static int hf_isobus_vt_changepriority_errorcodes = -1;
static int hf_isobus_vt_changelistitem_listobjectid = -1;
static int hf_isobus_vt_changelistitem_listindex = -1;
static int hf_isobus_vt_changelistitem_newobjectid = -1;
static int hf_isobus_vt_changelistitem_errorcodes = -1;
static int hf_isobus_vt_deleteobjectpool_errorcodes = -1;
static int hf_isobus_vt_chgstrval_objectid = -1;
static int hf_isobus_vt_chgstrval_length = -1;
static int hf_isobus_vt_chgstrval_errorcodes = -1;
static int hf_isobus_vt_chgstrval_value = -1;
static int hf_isobus_vt_changechildposition_parentobjectid = -1;
static int hf_isobus_vt_changechildposition_objectid = -1;
static int hf_isobus_vt_changechildposition_xpos = -1;
static int hf_isobus_vt_changechildposition_ypos = -1;
static int hf_isobus_vt_changechildposition_errorcodes = -1;
static int hf_isobus_vt_changeobjectlabel_objectid = -1;
static int hf_isobus_vt_changeobjectlabel_stringobjectid = -1;
static int hf_isobus_vt_changeobjectlabel_fonttype = -1;
static int hf_isobus_vt_changeobjectlabel_graphicobjectid = -1;
static int hf_isobus_vt_changeobjectlabel_errorcodes = -1;
static int hf_isobus_vt_changepolygonpoint_objectid = -1;
static int hf_isobus_vt_changepolygonpoint_pointindex = -1;
static int hf_isobus_vt_changepolygonpoint_xvalue = -1;
static int hf_isobus_vt_changepolygonpoint_yvalue = -1;
static int hf_isobus_vt_changepolygonpoint_errorcodes = -1;
static int hf_isobus_vt_changepolygonscale_objectid = -1;
static int hf_isobus_vt_changepolygonscale_newwidth = -1;
static int hf_isobus_vt_changepolygonscale_newheight = -1;
static int hf_isobus_vt_changepolygonscale_errorcodes = -1;
static int hf_isobus_vt_graphicscontext_objectid = -1;
static int hf_isobus_vt_graphicscontext_subcommandid = -1;
static int hf_isobus_vt_graphicscontext_setgraphicscursor_xposition = -1;
static int hf_isobus_vt_graphicscontext_setgraphicscursor_yposition = -1;
static int hf_isobus_vt_graphicscontext_movegraphicscursor_xoffset = -1;
static int hf_isobus_vt_graphicscontext_movegraphicscursor_yoffset = -1;
static int hf_isobus_vt_graphicscontext_setforegroundcolour_colour = -1;
static int hf_isobus_vt_graphicscontext_setbackgroundcolour_colour = -1;
static int hf_isobus_vt_graphicscontext_setlineattributesobjectid_objectid = -1;
static int hf_isobus_vt_graphicscontext_setfillattributesobjectid_objectid = -1;
static int hf_isobus_vt_graphicscontext_setfontattributesobjectid_objectid = -1;
static int hf_isobus_vt_graphicscontext_eraserectangle_width = -1;
static int hf_isobus_vt_graphicscontext_eraserectangle_height = -1;
static int hf_isobus_vt_graphicscontext_drawpoint_xoffset = -1;
static int hf_isobus_vt_graphicscontext_drawpoint_yoffset = -1;
static int hf_isobus_vt_graphicscontext_drawline_xoffset = -1;
static int hf_isobus_vt_graphicscontext_drawline_yoffset = -1;
static int hf_isobus_vt_graphicscontext_drawrectangle_width = -1;
static int hf_isobus_vt_graphicscontext_drawrectangle_height = -1;
static int hf_isobus_vt_graphicscontext_drawclosedellipse_width = -1;
static int hf_isobus_vt_graphicscontext_drawclosedellipse_height = -1;
static int hf_isobus_vt_graphicscontext_drawpolygon_numberofpoints = -1;
static int hf_isobus_vt_graphicscontext_drawpolygon_point_xoffset = -1;
static int hf_isobus_vt_graphicscontext_drawpolygon_point_yoffset = -1;
static int hf_isobus_vt_graphicscontext_drawtext_background = -1;
static int hf_isobus_vt_graphicscontext_drawtext_numberofbytes = -1;
static int hf_isobus_vt_graphicscontext_drawtext_textstring = -1;
static int hf_isobus_vt_graphicscontext_panviewport_viewportx = -1;
static int hf_isobus_vt_graphicscontext_panviewport_viewporty = -1;
static int hf_isobus_vt_graphicscontext_zoomviewport_zoomvalue = -1;
static int hf_isobus_vt_graphicscontext_panandzoomviewport_viewportx = -1;
static int hf_isobus_vt_graphicscontext_panandzoomviewport_viewporty = -1;
static int hf_isobus_vt_graphicscontext_panandzoomviewport_zoomvalue = -1;
static int hf_isobus_vt_graphicscontext_changeviewportsize_newwidth = -1;
static int hf_isobus_vt_graphicscontext_changeviewportsize_newheight = -1;
static int hf_isobus_vt_graphicscontext_drawvtobject_objectid = -1;
static int hf_isobus_vt_graphicscontext_copycanvastopicturegraphic_objectidpicturegraphic = -1;
static int hf_isobus_vt_graphicscontext_copyviewporttopicturegraphic_objectidpicturegraphic = -1;
static int hf_isobus_vt_getattributevalue_objectid = -1;
static int hf_isobus_vt_getattributevalue_attributeid = -1;
static int hf_isobus_vt_getattributevalue_value = -1;
static int hf_isobus_vt_getattributevalue_errorcodes = -1;
static int hf_isobus_vt_selectcolourmap_objectid = -1;
static int hf_isobus_vt_selectcolourmap_errorcodes = -1;
static int hf_isobus_vt_executeextendedmacro_objectid = -1;
static int hf_isobus_vt_executeextendedmacro_errorcodes = -1;
static int hf_isobus_vt_lockunlockmask_command = -1;
static int hf_isobus_vt_lockunlockmask_objectid = -1;
static int hf_isobus_vt_lockunlockmask_locktimeout = -1;
static int hf_isobus_vt_lockunlockmask_errorcodes = -1;
static int hf_isobus_vt_executemacro_objectid = -1;
static int hf_isobus_vt_executemacro_errorcodes = -1;
static int hf_isobus_vt_getmemory_memoryrequired = -1;
static int hf_isobus_vt_getmemory_vtversion = -1;
static int hf_isobus_vt_getmemory_status = -1;
static int hf_isobus_vt_getsupportedwidechars_codeplane = -1;
static int hf_isobus_vt_getsupportedwidechars_firstwidechar = -1;
static int hf_isobus_vt_getsupportedwidechars_lastwidechar = -1;
static int hf_isobus_vt_getsupportedwidechars_errorcodes = -1;
static int hf_isobus_vt_getsupportedwidechars_numberofranges = -1;
static int hf_isobus_vt_getsupportedwidechars_firstavailablewidechar = -1;
static int hf_isobus_vt_getsupportedwidechars_lastavailablewidechar = -1;
static int hf_isobus_vt_getnumberofsoftkeys_navigationsoftkeys = -1;
static int hf_isobus_vt_getnumberofsoftkeys_xdots = -1;
static int hf_isobus_vt_getnumberofsoftkeys_ydots = -1;
static int hf_isobus_vt_getnumberofsoftkeys_virtualsoftkeys = -1;
static int hf_isobus_vt_getnumberofsoftkeys_physicalsoftkeys = -1;
static int hf_isobus_vt_gettextfontdata_smallfontsizes = -1;
static int hf_isobus_vt_gettextfontdata_smallfontsizes_font8x8 = -1;
static int hf_isobus_vt_gettextfontdata_smallfontsizes_font8x12 = -1;
static int hf_isobus_vt_gettextfontdata_smallfontsizes_font12x16 = -1;
static int hf_isobus_vt_gettextfontdata_smallfontsizes_font16x16 = -1;
static int hf_isobus_vt_gettextfontdata_smallfontsizes_font16x24 = -1;
static int hf_isobus_vt_gettextfontdata_smallfontsizes_font24x32 = -1;
static int hf_isobus_vt_gettextfontdata_smallfontsizes_font32x32 = -1;
static int hf_isobus_vt_gettextfontdata_largefontsizes = -1;
static int hf_isobus_vt_gettextfontdata_largefontsizes_font32x48 = -1;
static int hf_isobus_vt_gettextfontdata_largefontsizes_font48x64 = -1;
static int hf_isobus_vt_gettextfontdata_largefontsizes_font64x64 = -1;
static int hf_isobus_vt_gettextfontdata_largefontsizes_font64x96 = -1;
static int hf_isobus_vt_gettextfontdata_largefontsizes_font96x128 = -1;
static int hf_isobus_vt_gettextfontdata_largefontsizes_font128x128 = -1;
static int hf_isobus_vt_gettextfontdata_largefontsizes_font128x192 = -1;
static int hf_isobus_vt_gettextfontdata_typeattributes = -1;
static int hf_isobus_vt_gettextfontdata_typeattributes_boldtext = -1;
static int hf_isobus_vt_gettextfontdata_typeattributes_crossedouttext = -1;
static int hf_isobus_vt_gettextfontdata_typeattributes_underlinedtext = -1;
static int hf_isobus_vt_gettextfontdata_typeattributes_italicstext = -1;
static int hf_isobus_vt_gettextfontdata_typeattributes_invertedtext = -1;
static int hf_isobus_vt_gettextfontdata_typeattributes_flashinverted = -1;
static int hf_isobus_vt_gettextfontdata_typeattributes_flashhidden = -1;
static int hf_isobus_vt_gettextfontdata_typeattributes_proportionalfontrendering = -1;
static int hf_isobus_vt_getwindowmaskdata_backgroundcolourdatamask = -1;
static int hf_isobus_vt_getwindowmaskdata_backgroundcoloursoftkeymask = -1;
static int hf_isobus_vt_getsupportedobjects_numberofbytes = -1;
static int hf_isobus_vt_getsupportedobjects_objecttype = -1;
static int hf_isobus_vt_gethardware_boottime = -1;
static int hf_isobus_vt_gethardware_graphictype = -1;
static int hf_isobus_vt_gethardware_hardware = -1;
static int hf_isobus_vt_gethardware_hardware_touchscreen = -1;
static int hf_isobus_vt_gethardware_hardware_pointingdevice = -1;
static int hf_isobus_vt_gethardware_hardware_multifreqaudiooutput = -1;
static int hf_isobus_vt_gethardware_hardware_adjustvolumeaudiooutput = -1;
static int hf_isobus_vt_gethardware_hardware_simultaneousactivationphysicalsoftkeys = -1;
static int hf_isobus_vt_gethardware_hardware_simultaneousactivationbuttons = -1;
static int hf_isobus_vt_gethardware_hardware_dragoperation = -1;
static int hf_isobus_vt_gethardware_hardware_intermediatecoordinatesdrag = -1;
static int hf_isobus_vt_gethardware_xpixels = -1;
static int hf_isobus_vt_gethardware_ypixels = -1;
static int hf_isobus_vt_storeversion_versionlabel = -1;
static int hf_isobus_vt_storeversion_errorcodes = -1;
static int hf_isobus_vt_loadversion_versionlabel = -1;
static int hf_isobus_vt_loadversion_errorcodes = -1;
static int hf_isobus_vt_deleteversion_versionlabel = -1;
static int hf_isobus_vt_deleteversion_errorcodes = -1;
static int hf_isobus_vt_extendedgetversions_numberofversions = -1;
static int hf_isobus_vt_extendedgetversions_versionlabel = -1;
static int hf_isobus_vt_extendedstoreversion_versionlabel = -1;
static int hf_isobus_vt_extendedstoreversion_errorcodes = -1;
static int hf_isobus_vt_extendedloadversion_versionlabel = -1;
static int hf_isobus_vt_extendedloadversion_errorcodes = -1;
static int hf_isobus_vt_extendeddeleteversion_versionlabel = -1;
static int hf_isobus_vt_extendeddeleteversion_errorcodes = -1;
static int hf_isobus_vt_getversions_numberofversions = -1;
static int hf_isobus_vt_getversions_versionlabel = -1;
static int hf_isobus_vt_unsupportedvtfunction_unsupportedvtfunction = -1;
static int hf_isobus_vt_vtstatus_workingsetmaster = -1;
static int hf_isobus_vt_vtstatus_objectiddatamask = -1;
static int hf_isobus_vt_vtstatus_objectidsoftkeymask = -1;
static int hf_isobus_vt_vtstatus_vtbusycodes = -1;
static int hf_isobus_vt_vtstatus_vtbusycodes_updatingvisiblemask = -1;
static int hf_isobus_vt_vtstatus_vtbusycodes_savingdata = -1;
static int hf_isobus_vt_vtstatus_vtbusycodes_executingcommand = -1;
static int hf_isobus_vt_vtstatus_vtbusycodes_executingmacro = -1;
static int hf_isobus_vt_vtstatus_vtbusycodes_parsingobjectpool = -1;
static int hf_isobus_vt_vtstatus_vtbusycodes_auxcontrolsactive = -1;
static int hf_isobus_vt_vtstatus_vtbusycodes_outofmemory = -1;
static int hf_isobus_vt_vtstatus_vtfunctioncodes = -1;
static int hf_isobus_vt_wrksetmain_bitmask = -1;
static int hf_isobus_vt_wrksetmain_version = -1;


#define VT_SOFT_KEY_ACTIVATION                  0
#define VT_BUTTON_ACTIVATION                    1
#define VT_POINTING_EVENT                       2
#define VT_VT_SELECT_INPUT_OBJECT               3
#define VT_VT_ESC_MESSAGE                       4
#define VT_VT_CHANGE_NUMERIC_VALUE              5
#define VT_VT_CHANGE_ACTIVE_MASK                6
#define VT_VT_CHANGE_SOFT_KEY_MASK              7
#define VT_VT_CHANGE_STRING_VALUE               8
#define VT_VT_ON_USER_LAYOUT_HIDE_SHOW          9
#define VT_VT_CONTROL_AUDIO_SIGNAL_TERMINATION  10
#define VT_OBJECT_POOL_TRANSFER                 17
#define VT_END_OF_OBJECT_POOL                   18
#define VT_AUXILIARY_ASSIGNMENT_TYPE_1          32
#define VT_AUXILIARY_INPUT_TYPE_1_STATUS        33
#define VT_PREFERRED_ASSIGNMENT                 34
#define VT_AUXILIARY_INPUT_TYPE_2_MAINTENANCE   35
#define VT_AUXILIARY_ASSIGNMENT_TYPE_2          36
#define VT_AUXILIARY_INPUT_STATUS_TYPE_2_ENABLE 37
#define VT_AUXILIARY_INPUT_TYPE_2_STATUS        38
#define VT_AUXILIARY_CAPABILITIES               39
#define VT_ESC                                  146
#define VT_HIDE_SHOW_OBJECT                     160
#define VT_ENABLE_DISABLE_COMMAND               161
#define VT_SELECT_INPUT_OBJECT                  162
#define VT_CONTROL_AUDIO_SIGNAL                 163
#define VT_SET_AUDIO_VOLUME                     164
#define VT_CHANGE_CHILD_LOCATION                165
#define VT_CHANGE_SIZE                          166
#define VT_CHANGE_BACKGROUND_COLOUR             167
#define VT_CHANGE_NUMERIC_VALUE                 168
#define VT_CHANGE_END_POINT                     169
#define VT_CHANGE_FONT_ATTRIBUTES               170
#define VT_CHANGE_LINE_ATTRIBUTES               171
#define VT_CHANGE_FILL_ATTRIBUTES               172
#define VT_CHANGE_ACTIVE_MASK                   173
#define VT_CHANGE_SOFT_KEY_MASK                 174
#define VT_CHANGE_ATTRIBUTES                    175
#define VT_CHANGE_PRIORITY                      176
#define VT_CHANGE_LIST_ITEM                     177
#define VT_DELETE_OBJECT_POOL                   178
#define VT_CHANGE_STRING_VALUE                  179
#define VT_CHANGE_CHILD_POSITION                180
#define VT_CHANGE_OBJECT_LABEL                  181
#define VT_CHANGE_POLYGON_POINT                 182
#define VT_CHANGE_POLYGON_SCALE                 183
#define VT_GRAPHICS_CONTEXT                     184
#define VT_GET_ATTRIBUTE_VALUE                  185
#define VT_SELECT_COLOUR_MAP                    186
#define VT_IDENTIFY_VT                          187
#define VT_EXECUTE_EXTENDED_MACRO               188
#define VT_LOCK_UNLOCK_MASK                     189
#define VT_EXECUTE_MACRO                        190
#define VT_GET_MEMORY                           192
#define VT_GET_SUPPORTED_WIDECHARS              193
#define VT_GET_NUMBER_OF_SOFT_KEYS              194
#define VT_GET_TEXT_FONT_DATA                   195
#define VT_GET_WINDOW_MASK_DATA                 196
#define VT_GET_SUPPORTED_OBJECTS                197
#define VT_GET_HARDWARE                         199
#define VT_STORE_VERSION                        208
#define VT_LOAD_VERSION                         209
#define VT_DELETE_VERSION                       210
#define VT_EXTENDED_GET_VERSIONS                211
#define VT_EXTENDED_STORE_VERSION               212
#define VT_EXTENDED_LOAD_VERSION                213
#define VT_EXTENDED_DELETE_VERSION              214
#define VT_GET_VERSIONS_MESSAGE                 223
#define VT_GET_VERSIONS_RESPONSE                224
#define VT_UNSUPPORTED_VT_FUNCTION              253
#define VT_VT_STATUS                            254
#define VT_WORKING_SET_MAINTENANCE              255

static const value_string vt_function_code[] = {
    { VT_SOFT_KEY_ACTIVATION                 , "Soft Key Activation" },
    { VT_BUTTON_ACTIVATION                   , "Button Activation" },
    { VT_POINTING_EVENT                      , "Pointing Event" },
    { VT_VT_SELECT_INPUT_OBJECT              , "VT Select Input Object" },
    { VT_VT_ESC_MESSAGE                      , "VT ESC message" },
    { VT_VT_CHANGE_NUMERIC_VALUE             , "VT Change Numeric Value" },
    { VT_VT_CHANGE_ACTIVE_MASK               , "VT Change Active Mask" },
    { VT_VT_CHANGE_SOFT_KEY_MASK             , "VT Change Soft Key Mask" },
    { VT_VT_CHANGE_STRING_VALUE              , "VT Change String Value" },
    { VT_VT_ON_USER_LAYOUT_HIDE_SHOW         , "VT On User-Layout Hide/Show" },
    { VT_VT_CONTROL_AUDIO_SIGNAL_TERMINATION , "VT Control Audio Signal Termination" },
    { VT_OBJECT_POOL_TRANSFER                , "Object pool transfer" },
    { VT_END_OF_OBJECT_POOL                  , "End of Object Pool" },
    { VT_AUXILIARY_ASSIGNMENT_TYPE_1         , "Auxiliary Assignment Type 1" },
    { VT_AUXILIARY_INPUT_TYPE_1_STATUS       , "Auxiliary Input Type 1" },
    { VT_PREFERRED_ASSIGNMENT                , "Preferred Assignment" },
    { VT_AUXILIARY_INPUT_TYPE_2_MAINTENANCE  , "Auxiliary Input Type 2 Maintenance" },
    { VT_AUXILIARY_ASSIGNMENT_TYPE_2         , "Auxiliary Assignment Type 2" },
    { VT_AUXILIARY_INPUT_STATUS_TYPE_2_ENABLE, "Auxiliary Input Status Type 2 Enable" },
    { VT_AUXILIARY_INPUT_TYPE_2_STATUS       , "Auxiliary Input Type 2 Status" },
    { VT_AUXILIARY_CAPABILITIES              , "Auxiliary Capabilities" },
    { VT_ESC                                 , "ESC" },
    { VT_HIDE_SHOW_OBJECT                    , "Hide/Show Object" },
    { VT_ENABLE_DISABLE_COMMAND              , "Enable/Disable Object" },
    { VT_SELECT_INPUT_OBJECT                 , "Select Input Object" },
    { VT_CONTROL_AUDIO_SIGNAL                , "Control Audio Signal" },
    { VT_SET_AUDIO_VOLUME                    , "Set Audio Volume" },
    { VT_CHANGE_CHILD_LOCATION               , "Change Child Location" },
    { VT_CHANGE_SIZE                         , "Change Size" },
    { VT_CHANGE_BACKGROUND_COLOUR            , "Change Background Colour" },
    { VT_CHANGE_NUMERIC_VALUE                , "Change Numeric Value" },
    { VT_CHANGE_END_POINT                    , "Change End Point" },
    { VT_CHANGE_FONT_ATTRIBUTES              , "Change Font Attributes" },
    { VT_CHANGE_LINE_ATTRIBUTES              , "Change Line Attributes" },
    { VT_CHANGE_FILL_ATTRIBUTES              , "Change Fill Attributes" },
    { VT_CHANGE_ACTIVE_MASK                  , "Change Active Mask" },
    { VT_CHANGE_SOFT_KEY_MASK                , "Change Soft Key Mask" },
    { VT_CHANGE_ATTRIBUTES                   , "Change Attribute" },
    { VT_CHANGE_PRIORITY                     , "Change Priority" },
    { VT_CHANGE_LIST_ITEM                    , "Change List Item" },
    { VT_DELETE_OBJECT_POOL                  , "Delete Object Pool" },
    { VT_CHANGE_STRING_VALUE                 , "Change String Value" },
    { VT_CHANGE_CHILD_POSITION               , "Change Child Position" },
    { VT_CHANGE_OBJECT_LABEL                 , "Change Object Label" },
    { VT_CHANGE_POLYGON_POINT                , "Change Polygon Point" },
    { VT_CHANGE_POLYGON_SCALE                , "Change Polygon Scale" },
    { VT_GRAPHICS_CONTEXT                    , "Graphics Context" },
    { VT_GET_ATTRIBUTE_VALUE                 , "Get Attribute Value" },
    { VT_SELECT_COLOUR_MAP                   , "Select Colour Map" },
    { VT_IDENTIFY_VT                         , "Identify VT" },
    { VT_EXECUTE_EXTENDED_MACRO              , "Execute Extended Macro" },
    { VT_LOCK_UNLOCK_MASK                    , "Lock/Unlock Mask" },
    { VT_EXECUTE_MACRO                       , "Execute Macro" },
    { VT_GET_MEMORY                          , "Get Memory" },
    { VT_GET_SUPPORTED_WIDECHARS             , "Get Supported Widechars" },
    { VT_GET_NUMBER_OF_SOFT_KEYS             , "Get Number of Soft Keys" },
    { VT_GET_TEXT_FONT_DATA                  , "Get Text Font Data" },
    { VT_GET_WINDOW_MASK_DATA                , "Get Window Mask Data" },
    { VT_GET_SUPPORTED_OBJECTS               , "Get Supported Objects" },
    { VT_GET_HARDWARE                        , "Get Hardware" },
    { VT_STORE_VERSION                       , "Store Version" },
    { VT_LOAD_VERSION                        , "Load Version" },
    { VT_DELETE_VERSION                      , "Delete Version" },
    { VT_EXTENDED_GET_VERSIONS               , "Extended Get Versions" },
    { VT_EXTENDED_STORE_VERSION              , "Extended Store Version" },
    { VT_EXTENDED_LOAD_VERSION               , "Extended Load Version" },
    { VT_EXTENDED_DELETE_VERSION             , "Extended Delete Version" },
    { VT_GET_VERSIONS_MESSAGE                , "Get Versions message" },
    { VT_GET_VERSIONS_RESPONSE               , "Get Versions response" },
    { VT_UNSUPPORTED_VT_FUNCTION             , "Unsupported VT Function" },
    { VT_VT_STATUS                           , "VT Status" },
    { VT_WORKING_SET_MAINTENANCE             , "Working Set Maintenance" },
    { 0, NULL }
};
static value_string_ext vt_function_code_ext = VALUE_STRING_EXT_INIT(vt_function_code);

#define SET_GRAPHICS_CURSOR              0
#define MOVE_GRAPHICS_CURSOR             1
#define SET_FOREGROUND_COLOUR            2
#define SET_BACKGROUND_COLOUR            3
#define SET_LINE_ATTRIBUTES_OBJECT_ID    4
#define SET_FILL_ATTRIBUTES_OBJECT_ID    5
#define SET_FONT_ATTRIBUTES_OBJECT_ID    6
#define ERASE_RECTANGLE                  7
#define DRAW_POINT                       8
#define DRAW_LINE                        9
#define DRAW_RECTANGLE                   10
#define DRAW_CLOSED_ELLIPSE              11
#define DRAW_POLYGON                     12
#define DRAW_TEXT                        13
#define PAN_VIEWPORT                     14
#define ZOOM_VIEWPORT                    15
#define PAN_AND_ZOOM_VIEWPORT            16
#define CHANGE_VIEWPORT_SIZE             17
#define DRAW_VT_OBJECT                   18
#define COPY_CANVAS_TO_PICTURE_GRAPHIC   19
#define COPY_VIEWPORT_TO_PICTURE_GRAPHIC 20

static const value_string graphics_context_sub_command_id[] = {
    { SET_GRAPHICS_CURSOR              , "Set Graphics Cursor" },
    { MOVE_GRAPHICS_CURSOR             , "Move Graphics Cursor" },
    { SET_FOREGROUND_COLOUR            , "Set Foreground Colour" },
    { SET_BACKGROUND_COLOUR            , "Set Background Colour" },
    { SET_LINE_ATTRIBUTES_OBJECT_ID    , "Set Line Attributes Object ID" },
    { SET_FILL_ATTRIBUTES_OBJECT_ID    , "Set Fill Attributes Object ID" },
    { SET_FONT_ATTRIBUTES_OBJECT_ID    , "Set Font Attributes Object ID" },
    { ERASE_RECTANGLE                  , "Erase Rectangle" },
    { DRAW_POINT                       , "Draw Point" },
    { DRAW_LINE                        , "Draw Line" },
    { DRAW_RECTANGLE                   , "Draw Rectangle" },
    { DRAW_CLOSED_ELLIPSE              , "Draw Closed Ellipse" },
    { DRAW_POLYGON                     , "Draw Polygon" },
    { DRAW_TEXT                        , "Draw Text" },
    { PAN_VIEWPORT                     , "Pan Viewport" },
    { ZOOM_VIEWPORT                    , "Zoom Viewport" },
    { PAN_AND_ZOOM_VIEWPORT            , "Pan and Zoom Viewport" },
    { CHANGE_VIEWPORT_SIZE             , "Change Viewport Size" },
    { DRAW_VT_OBJECT                   , "Draw VT Object" },
    { COPY_CANVAS_TO_PICTURE_GRAPHIC   , "Copy Canvas to Picture Graphic" },
    { COPY_VIEWPORT_TO_PICTURE_GRAPHIC , "Copy Viewport to Picture Graphic" },
    { 0, NULL }
};
static value_string_ext graphics_context_sub_command_id_ext = VALUE_STRING_EXT_INIT(graphics_context_sub_command_id);

static const value_string vt_hide_show_action[] = {
    { 0, "Hide" },
    { 1, "Show" },
    { 0, NULL }
};

static const value_string vt_hide_show_action_info[] = {
    { 0, "hidden" },
    { 1, "shown" },
    { 0, NULL }
};

static const value_string vt_enable_disable_action[] = {
    { 0, "Disable" },
    { 1, "Enable" },
    { 0, NULL }
};

static const range_string vt_colours[] = {
    { 0  , 0  , "Black" },
    { 1  , 1  , "White" },
    { 2  , 2  , "Green" },
    { 3  , 3  , "Teal" },
    { 4  , 4  , "Maroon" },
    { 5  , 5  , "Purple" },
    { 6  , 6  , "Olive" },
    { 7  , 7  , "Silver" },
    { 8  , 8  , "Grey" },
    { 9  , 9  , "Blue" },
    { 10 , 10 , "Lime" },
    { 11 , 11 , "Cyan" },
    { 12 , 12 , "Red" },
    { 13 , 13 , "Magenta" },
    { 14 , 14 , "Yellow" },
    { 15 , 15 , "Navy" },
    { 16 , 231, "Colour code defined" },
    { 232, 255, "Proprietary" },
    { 0  , 0  , NULL }
};

#define KEY_RELEASED 0
#define KEY_PRESSED 1
#define KEY_STILL_PRESSED 2
#define KEY_PRESS_ABORTED 3

static const value_string key_activation_codes[] = {
    { KEY_RELEASED, "Key has been released (state change)" },
    { KEY_PRESSED, "Key has been pressed (state change)" },
    { KEY_STILL_PRESSED, "Key is still pressed" },
    { KEY_PRESS_ABORTED, "Key press aborted" },
    { 0, NULL }
};

static const value_string key_activation_codes_info_postfix[] = {
    { KEY_RELEASED, "has been released" },
    { KEY_PRESSED, "has been pressed" },
    { KEY_STILL_PRESSED, "is still held" },
    { KEY_PRESS_ABORTED, "press aborted" },
    { 0, NULL }
};

#define BUTTON_RELEASED 0
#define BUTTON_PRESSED 1
#define BUTTON_STILL_HELD 2
#define BUTTON_PRESS_ABORTED 3

static const value_string button_activation_codes[] = {
    { BUTTON_RELEASED, "Button has been unlatched or released (state change)" },
    { BUTTON_PRESSED, "Button has been \"pressed\" or latched (state change)" },
    { BUTTON_STILL_HELD, "Button is still held (latchable buttons do not repeat)" },
    { BUTTON_PRESS_ABORTED, "Button press aborted" },
    { 0, NULL }
};

#define TOUCH_RELEASED 0
#define TOUCH_PRESSED 1
#define TOUCH_HELD 2

static const value_string pointing_touch_state[] = {
    { TOUCH_RELEASED, "Released" },
    { TOUCH_PRESSED, "Pressed" },
    { TOUCH_HELD, "Held" },
    { 0, NULL }
};

static const value_string pointing_touch_state_info_postfix[] = {
    { TOUCH_RELEASED, "has been released" },
    { TOUCH_PRESSED, "has been pressed" },
    { TOUCH_HELD, "is still held" },
    { 0, NULL }
};

static const value_string selection[] = {
    { 0, "Object is deselected" },
    { 1, "Object is selected (has focus)" },
    { 0, NULL }
};

static const range_string vt_versions[] = {
    { 0, 2, "Reserved" },
    { 3, 3, "Compliant with VT Version 3" },
    { 4, 4, "Compliant with VT Version 4" },
    { 5, 5, "Compliant with VT Version 5" },
    { 6, 254, "Reserved" },
    { 255, 255, "Compliant with VT Version 2" },
    { 0, 0, NULL }
};

static const value_string line_direction[] = {
    { 0, "Top left to bottom right" },
    { 1, "Bottom left to top right" },
    { 0, NULL }
};

#define MASK_UNLOCK 0
#define MASK_LOCK 1

static const value_string lock_unlock[] = {
    { MASK_UNLOCK, "Unlock Data Mask or User-Layout Data Mask" },
    { MASK_LOCK  , "Lock Data Mask or User-Layout Data Mask" },
    { 0, NULL }
};

#define ENOUGH_MEMORY 0
#define NOT_ENOUGH_MEMORY 1

static const value_string memory_status[] = {
    { ENOUGH_MEMORY    , "There can be enough memory." },
    { NOT_ENOUGH_MEMORY, "There is not enough memory available. Do not transmit Object Pool." },
    { 0, NULL }
};

static const value_string vt_versions_extended[] = {
    { 0, "Hannover Agritechnica 2001 limited feature set" },
    { 1, "FDIS Version ISO11783-6:2004(E), (Final Draft International Standard)" },
    { 2, "IS Version ISO11783-6:2004(E), First Edition, 2004-06-15" },
    { 3, "IS Version ISO11783-6:2010(E), Second Edition, (ISO11783-6:2004(E) and features specifically noted with version 3 reference)" },
    { 4, "IS Version ISO11783-6:2010(E), Second Edition, (ISO11783-6:2004(E) and features specifically noted with version 4 reference)" },
    { 5, "IS Version ISO11783-6:2014(E), Third Edition" },
    { 0, NULL }
};

static const range_string vt_object_types[] = {
    /* Top level objects */
    { 0,   0,   "Working Set object" },
    { 1,   1,   "Data Mask object" },
    { 2,   2,   "Alarm Mask object" },
    { 3,   3,   "Container object" },
    { 34,  34,  "Window Mask object" },
    /* Key objects */
    { 4,   4,   "Soft Key Mask object" },
    { 5,   5,   "Key object" },
    { 6,   6,   "Button object" },
    { 35,  35,  "Key Group object" },
    /* Input field objects */
    { 7,   7,   "Input Boolean object" },
    { 8,   8,   "Input String object" },
    { 9,   9,   "Input Number object" },
    { 10,  10,  "Input List object" },
    /* Output field objects */
    { 11,  11,  "Output String object" },
    { 12,  12,  "Output Number object" },
    { 37,  37,  "Output List object" },
    /* Output shape objects */
    { 13,  13,  "Output Line object" },
    { 14,  14,  "Output Rectangle object" },
    { 15,  15,  "Output Ellipse object" },
    { 16,  16,  "Output Polygon object" },
    /* Output graphic objects */
    { 17,  17,  "Output Meter object" },
    { 18,  18,  "Output Linear Bar Graph object" },
    { 19,  19,  "Output Arched Bar Graph object" },
    { 36,  36,  "Graphics Context object" },
    { 44,  44,  "Animation object" },
    /* Picture graphic object */
    { 20,  20,  "Picture Graphic object" },
    /* Variable objects */
    { 21,  21,  "Number Variable object" },
    { 22,  22,  "String Variable object" },
    /* Attribute Objects */
    { 23,  23,  "Font Attributes object" },
    { 24,  24,  "Line Attributes object" },
    { 25,  25,  "Fill Attributes object" },
    { 26,  26,  "Input Attributes object" },
    { 38,  38,  "Extended Input Attributes object" },
    { 39,  39,  "Colour Map object" },
    { 40,  40,  "Object Label Reference List object" },
    /* Pointer objects */
    { 27,  27,  "Object Pointer object" },
    { 41,  41,  "External Object Definition object" },
    { 42,  42,  "External Reference NAME object" },
    { 43,  43,  "External Object Pointer object" },
    /* Macro object */
    { 28,  28,  "Macro object" },
    /* Auxiliary control */
    { 29,  29,  "Auxiliary Function Type 1 object" },
    { 30,  30,  "Auxiliary Input Type 1 object" },
    { 31,  31,  "Auxiliary Function Type 2 object" },
    { 32,  32,  "Auxiliary Input Type 2 object" },
    { 33,  33,  "Auxiliary Control Designator Type 2 Object Pointer" },
    /* Proprietary Objects */
    { 240, 254, "Manufacturer Defined Objects" },
    /* Reserved Objects */
    { 45,  239, "Reserved" },
    { 255, 255, "Reserved" },
    { 0, 0, NULL }
};

static const value_string graphic_types[] = {
    { 0, "Monochrome" },
    { 1, "16 Colour" },
    { 2, "256 Colour" },
    { 0, NULL }
};

static const value_string auxiliary_boolean_value[] = {
    { 0, "Disabled" },
    { 1, "Enabled" },
    { 2, "non-latched Boolean held" },
    { 0xFF, "Analog" },
    { 0, NULL }
};

static const value_string auxiliary_maintenance_status[] = {
    { 0, "Initializing, pool is not currently available for assignment." },
    { 1, "Ready, pool has been loaded into the VT and is available for assignments." },
    { 0, NULL }
};

static const value_string auxiliary_capabilities_request_type[] = {
    { 0, "Request capabilities of Auxiliary Input Unit(s)" },
    { 1, "Request capabilities of Auxiliary Function Unit(s)" },
    { 0, NULL }
};

static const value_string auxiliary_assigned_attributes[] = {
    { 0, "auxiliary input" },
    { 1, "auxiliary function" },
    { 2, "Input is assigned" },
    { 0, NULL }
};

static const value_string select_input_object_option[] = {
    { 0xFF, "Set Focus to object referenced by Object ID " },
    { 0   , "Activate for data-input the object reference by Object ID" },
    { 0, NULL },
};

static const value_string select_input_opject_response[] = {
    { 0, "Object referenced by Object ID is not selected or Object ID is the NULL object" },
    { 1, "Object referenced by Object ID is Selected" },
    { 2, "Object referenced by Object ID is Opened for Edit" },
    { 0, NULL }
};

static const value_string draw_text_background[] = {
    { 0, "Opaque" },
    { 1, "Transparent" },
    { 0, NULL }
};

static value_string object_id_strings[MAX_OBJECT_ID_DB_SIZE];

/* Initialize the subtree pointers */
static gint ett_isobus_vt = -1;
static gint ett_isobus_vt_vtstatus_busycodes_subtree = -1;
static gint ett_isobus_vt_getsupportedwidechars_range = -1;
static gint ett_isobus_vt_gettextfontdata_smallfontsizes = -1;
static gint ett_isobus_vt_gettextfontdata_largefontsizes = -1;
static gint ett_isobus_vt_gettextfontdata_typeattributes = -1;
static gint ett_isobus_vt_gethardware_hardware = -1;
static gint ett_isobus_vt_preferredassignment_inputunit = -1;
static gint ett_isobus_vt_preferredassignment_inputunit_preferredfunction = -1;
static gint ett_isobus_vt_auxiliarycapabilities_inputunit = -1;
static gint ett_isobus_vt_auxiliarycapabilities_inputunit_set = -1;
static gint ett_isobus_vt_auxiliaryassignmenttype2_flags = -1;
static gint ett_isobus_vt_auxiliaryinputtype2status_operatingstate = -1;

static const char *object_id_translation = "";

enum vt_direction
{
    vt_to_ecu,
    ecu_to_vt
};

static const gchar* get_object_id_string(guint16 object_id)
{
    const gchar* translated_string;
    if(object_id == 0xFFFF)
    {
        return "NULL Object ID";
    }

    translated_string = val_to_str(object_id, object_id_strings, "Object ID 0x%04X");
    return translated_string;
}

static int
dissect_vt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, enum vt_direction direction)
{
    int offset = 0;
    guint32 function_id;
    proto_item *ti;

    ti = proto_tree_add_item(tree,
        hf_isobus_vt, tvb, 0, 0, ENC_NA);
    proto_item_set_hidden(ti);

    proto_tree_add_item_ret_uint(tree,
        hf_isobus_vt_command, tvb, offset, 1, ENC_LITTLE_ENDIAN, &function_id);
    offset += 1;

    switch(function_id)
    {
    case VT_SOFT_KEY_ACTIVATION:
    {
        guint32 key_activation_code, object_id, parent_object_id;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_softkey_keyactcode, tvb, offset, 1, ENC_LITTLE_ENDIAN, &key_activation_code);
        offset += 1;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_softkey_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_softkey_parentobjectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &parent_object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        proto_tree_add_item(tree,
            hf_isobus_vt_softkey_keynumber, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        col_append_fstr(pinfo->cinfo, COL_INFO, "Key %s of parent %s %s",
            get_object_id_string(object_id), get_object_id_string(parent_object_id),
            val_to_str(key_activation_code, key_activation_codes_info_postfix, "unknown action"));
    }
        break;
    case VT_BUTTON_ACTIVATION:
    {
        guint32 key_activation_code, object_id, parent_object_id;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_button_keyactcode, tvb, offset, 1, ENC_LITTLE_ENDIAN, &key_activation_code);
        offset += 1;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_button_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_button_parentobjectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &parent_object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        proto_tree_add_item(tree,
            hf_isobus_vt_button_keynumber, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        col_append_fstr(pinfo->cinfo, COL_INFO, "Button %s of parent %s %s",
            get_object_id_string(object_id), get_object_id_string(parent_object_id),
            val_to_str(key_activation_code, key_activation_codes_info_postfix, "unknown action"));
    }
        break;
    case VT_POINTING_EVENT:
    {
        guint32 x_position, y_position, touch_state = 0;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_pointing_xposition, tvb, offset, 2, ENC_LITTLE_ENDIAN, &x_position);
        offset += 2;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_pointing_yposition, tvb, offset, 2, ENC_LITTLE_ENDIAN, &y_position);
        offset += 2;

        if(current_vt_version >= 4)
        {
            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_pointing_touchstate, tvb, offset, 1, ENC_LITTLE_ENDIAN, &touch_state);
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, "Touch at [%d;%d]",
            x_position, y_position);

        if(current_vt_version >= 4)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(touch_state, pointing_touch_state_info_postfix, "unknown action"));
        }
    }
        break;
    case VT_VT_SELECT_INPUT_OBJECT:
    {
        guint32 object_id;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_vtselectinputobject_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        proto_tree_add_item(tree,
            hf_isobus_vt_vtselectinputobject_selection, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        if(current_vt_version >= 4)
        {
            proto_tree_add_item(tree,
                hf_isobus_vt_vtselectinputobject_openforinput, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, "%s was selected by VT", get_object_id_string(object_id));
    }
        break;
    case VT_VT_ESC_MESSAGE:
    {
        guint32 object_id;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_vtescmessage_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        if(direction == vt_to_ecu)
        {
            guint32 error_codes;

            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_vtescmessage_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);

            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "No input field is selected ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "Any other error ");

            col_append_fstr(pinfo->cinfo, COL_INFO, "ESC button was pressed while %s was selected", get_object_id_string(object_id));
        }
        else
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "ESC button press was successfully received");
        }
    }
        break;
    case VT_VT_CHANGE_NUMERIC_VALUE:
    {
        guint32 object_id, value;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_vtchgnumval_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        offset += 1; /* byte 4 is reserved */

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_vtchgnumval_value, tvb, offset, 4, ENC_LITTLE_ENDIAN, &value);

        if(direction == ecu_to_vt)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "VT Numeric value of %s has changed to 0x%X",
                get_object_id_string(object_id), value);
        }
        else
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "VT Numeric value of %s should change to 0x%X",
                get_object_id_string(object_id), value);
        }
    }
        break;
    case VT_VT_CHANGE_ACTIVE_MASK:
    {
        guint32 mask_object_id;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_vtchgactivemask_maskobjectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &mask_object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        if(direction == vt_to_ecu)
        {
            guint32 error_object_id, error_codes;

            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_vtchgactivemask_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x04)
                proto_item_append_text(ti, "Missing object ");
            if (error_codes & 0x08)
                proto_item_append_text(ti, "Mask or child object has errors ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "Any other error ");
            if (error_codes & 0x20)
                proto_item_append_text(ti, "Pool being deleted ");
            offset += 1;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_vtchgactivemask_errorobjectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &error_object_id);
            ti = proto_tree_add_item(tree,
                hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_set_hidden(ti);
            offset += 2;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_vtchgactivemask_errorobjectidparent, tvb, offset, 2, ENC_LITTLE_ENDIAN, &error_object_id);
            ti = proto_tree_add_item(tree,
                hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_set_hidden(ti);

            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "VT Active mask changed to %s",
                    get_object_id_string(mask_object_id));
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "VT Active mask changed to %s because of error in %s",
                    get_object_id_string(mask_object_id), get_object_id_string(error_object_id));
            }
        }
        else
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "VT Active mask change to %s acknowledged",
                get_object_id_string(mask_object_id));
        }
    }
        break;
    case VT_VT_CHANGE_STRING_VALUE:
    {
        if(direction == vt_to_ecu)
        {
            guint encoding = ENC_ASCII|ENC_NA;
            guint32 object_id, str_length;
            guint16 firstTwoBytesString;
            const guint8* value;
            guint bomOffset = 0;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_vtchgstrval_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
            ti = proto_tree_add_item(tree,
                hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_set_hidden(ti);
            offset += 2;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_vtchgstrval_length, tvb, offset, 1, ENC_LITTLE_ENDIAN, &str_length);
            offset += 1;

            firstTwoBytesString = tvb_get_letohs(tvb,offset);
            if(firstTwoBytesString == 0xFEFF)
            {
                encoding = ENC_UCS_2|ENC_BIG_ENDIAN;
                bomOffset = 2;
            }

            proto_tree_add_item_ret_string(tree,
                hf_isobus_vt_vtchgstrval_value, tvb, offset + bomOffset, str_length - bomOffset, encoding,
                wmem_packet_scope(), &value);

            col_append_fstr(pinfo->cinfo, COL_INFO, "VT String value of %s should change to %s",
                get_object_id_string(object_id), value);
        }
        else
        {
            guint32 object_id;

            offset += 2;    /* first two bytes are reserved */

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_chgstrval_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
            ti = proto_tree_add_item(tree,
                hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_set_hidden(ti);

            col_append_fstr(pinfo->cinfo, COL_INFO, "VT String value change of %s acknowledged",
                get_object_id_string(object_id));
        }
    }
        break;
    case VT_VT_ON_USER_LAYOUT_HIDE_SHOW:
    {
        guint32 object_id[2], status[2];

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_vtonuserlayouthideshow_objectid_1, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id[0]);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_vtonuserlayouthideshow_status_1, tvb, offset, 1, ENC_LITTLE_ENDIAN, &status[0]);
        offset += 1;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_vtonuserlayouthideshow_objectid_2, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id[1]);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_vtonuserlayouthideshow_status_2, tvb, offset, 1, ENC_LITTLE_ENDIAN, &status[1]);

        col_append_fstr(pinfo->cinfo, COL_INFO, "VT On User-Layout Hide/Show. %s is %s, %s is %s",
            get_object_id_string(object_id[0]), val_to_str(status[0], vt_hide_show_action_info, "unknown"),
            get_object_id_string(object_id[1]), val_to_str(status[1], vt_hide_show_action_info, "unknown"));
    }
        break;
    case VT_VT_CONTROL_AUDIO_SIGNAL_TERMINATION:
    {
        guint32 termination_cause;

        ti = proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_vtcontrolaudiosignaltermination_terminationcause, tvb, offset, 1, ENC_LITTLE_ENDIAN, &termination_cause);

        proto_item_append_text(ti, ": ");
        if (termination_cause & 0x01)
        {
            proto_item_append_text(ti, "Audio was terminated ");
            col_append_fstr(pinfo->cinfo, COL_INFO, "VT Control audio signal termination: Audio was terminated");
        }
        else
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "VT Control audio signal termination: Error in message");
        }
    }
        break;
    case VT_END_OF_OBJECT_POOL:
    {
        if(direction == vt_to_ecu)
        {
            guint32 error_codes, obj_pool_error_codes;

            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_endofobjectpool_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "There are errors in the Object Pool ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "VT ran out of memory during transfer ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "Any other error ");
            offset += 1;

            proto_tree_add_item(tree,
                hf_isobus_vt_endofobjectpool_faultyparentobjectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            ti = proto_tree_add_item(tree,
                hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_set_hidden(ti);
            offset += 2;

            proto_tree_add_item(tree,
                hf_isobus_vt_endofobjectpool_faultyobjectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            ti = proto_tree_add_item(tree,
                hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_set_hidden(ti);
            offset += 2;

            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_endofobjectpool_objectpoolerrorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &obj_pool_error_codes);
            proto_item_append_text(ti, ": ");
            if (obj_pool_error_codes & 0x01)
                proto_item_append_text(ti, "method or Attribute not supported by the VT ");
            if (obj_pool_error_codes & 0x02)
                proto_item_append_text(ti, "unknown object reference (missing object) ");
            if (obj_pool_error_codes & 0x04)
                proto_item_append_text(ti, "any other error ");
            if (obj_pool_error_codes & 0x08)
                proto_item_append_text(ti, "object pool was deleted from volatile memory ");

            if(error_codes & 0x01)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "End of object pool received, object pool contains errors");
            }
            else if(error_codes & 0x02)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "End of object pool received, but VT ran out of memory");
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "End of object pool received, object pool accepted");
            }
        }
    }
        break;
    case VT_AUXILIARY_ASSIGNMENT_TYPE_1:
    {
        guint32 source_address, aux_input_number, object_id;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_auxiliaryassignmenttype1_sourceaddressauxinputdevice, tvb, offset, 1, ENC_LITTLE_ENDIAN, &source_address);
        offset += 1;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_auxiliaryassignmenttype1_auxinputnumber, tvb, offset, 1, ENC_LITTLE_ENDIAN, &aux_input_number);
        offset += 1;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_auxiliaryassignmenttype1_objectidauxinputdevice, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);

        if(direction == ecu_to_vt)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Assign auxiliary input type 1 number %u of device %u to %s",
                aux_input_number, source_address, get_object_id_string(object_id));
        }
        else
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Auxiliary input type 1 number %u of device %u has been assigned to %s",
                aux_input_number, source_address, get_object_id_string(object_id));
        }
    }
        break;
    case VT_AUXILIARY_INPUT_TYPE_1_STATUS:
    {
        guint32 input_number, boolean_value, analyze_value;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_auxiliaryinputtype1status_inputnumber, tvb, offset, 1, ENC_LITTLE_ENDIAN, &input_number);
        offset += 1;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_auxiliaryinputtype1status_analyzevalue, tvb, offset, 2, ENC_LITTLE_ENDIAN, &analyze_value);
        offset += 2;

        proto_tree_add_item(tree,
            hf_isobus_vt_auxiliaryinputtype1status_numberoftransitions, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_auxiliaryinputtype1status_booleanvalue, tvb, offset, 1, ENC_LITTLE_ENDIAN, &boolean_value);

        col_append_fstr(pinfo->cinfo, COL_INFO, "State of input %u is analog %u or digital %s",
            input_number, analyze_value, val_to_str(boolean_value, auxiliary_boolean_value, "unknown"));

    }
        break;
    case VT_PREFERRED_ASSIGNMENT:
    {
        if(direction == ecu_to_vt)
        {
            guint32 number_of_input_units, i;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_preferredassignment_numberofinputunits, tvb, offset, 1, ENC_LITTLE_ENDIAN, &number_of_input_units);
            offset += 1;

            for(i = 0; i < number_of_input_units; i++)
            {
                proto_item *input_unit_item;
                proto_tree *input_unit_subtree;
                guint32 number_of_preferred_functions, j, model_identification_code;
                guint64 name;

                input_unit_subtree = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_isobus_vt_preferredassignment_inputunit, &input_unit_item, "Input Unit");

                proto_tree_add_item_ret_uint64(input_unit_subtree,
                    hf_isobus_vt_preferredassignment_auxinputunit_name, tvb, offset, 8, ENC_LITTLE_ENDIAN, &name);
                offset += 8;

                proto_tree_add_item_ret_uint(input_unit_subtree,
                    hf_isobus_vt_preferredassignment_auxinputunit_modelidentificationcode, tvb, offset, 2, ENC_LITTLE_ENDIAN, &model_identification_code);
                offset += 2;

                proto_tree_add_item_ret_uint(input_unit_subtree,
                    hf_isobus_vt_preferredassignment_auxinputunit_numberofpreferredfunctions, tvb, offset, 1, ENC_LITTLE_ENDIAN, &number_of_preferred_functions);
                offset += 1;

                proto_item_set_text(input_unit_item, "Input Unit name 0x%" G_GINT64_MODIFIER "X model identification code %u", name, model_identification_code);
                proto_item_set_len(input_unit_item, 8 + 2 + 1 + ((2 + 2) * number_of_preferred_functions));

                for(j = 0; j < number_of_preferred_functions; j++)
                {
                    proto_item *preferred_function_item;
                    proto_tree *preferred_function_subtree;
                    guint32 auxiliary_function_object_id, auxiliary_input_object_id;

                    preferred_function_subtree = proto_tree_add_subtree(input_unit_subtree, tvb, offset, 4,
                        ett_isobus_vt_preferredassignment_inputunit_preferredfunction, &preferred_function_item, "Input Unit");

                    proto_tree_add_item_ret_uint(preferred_function_subtree,
                        hf_isobus_vt_preferredassignment_auxinputunit_preferredfunctions_auxfunctionobjectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &auxiliary_function_object_id);
                    ti = proto_tree_add_item(tree,
                        hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    proto_item_set_hidden(ti);
                    offset += 2;

                    proto_tree_add_item_ret_uint(preferred_function_subtree,
                        hf_isobus_vt_preferredassignment_auxinputunit_preferredfunctions_auxinputobjectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &auxiliary_input_object_id);
                    ti = proto_tree_add_item(tree,
                        hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    proto_item_set_hidden(ti);
                    offset += 2;

                    proto_item_set_text(preferred_function_item, "Auxiliary Function %s connects to Auxiliary Input %s",
                        get_object_id_string(auxiliary_function_object_id), get_object_id_string(auxiliary_input_object_id));
                }
            }
            col_append_fstr(pinfo->cinfo, COL_INFO, "Create preferred assignment");
        }
        else
        {
            guint32 error_codes, faulty_auxiliary_function_object_id;

            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_preferredassignment_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "Auxiliary Input Unit(s) not valid ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Function Object ID(s) not valid ");
            if (error_codes & 0x04)
                proto_item_append_text(ti, "Input Object ID(s) not valid ");
            if (error_codes & 0x08)
                proto_item_append_text(ti, "Duplicate Object ID of Auxiliary Function ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "Any other error ");
            offset += 1;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_preferredassignment_faultyauxiliaryfunctionobjectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &faulty_auxiliary_function_object_id);
            ti = proto_tree_add_item(tree,
                hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_set_hidden(ti);

            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Error while creating preferred assignment because of %s", get_object_id_string(faulty_auxiliary_function_object_id));
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Successfully created preferred assignment");
            }
        }
    }
        break;
    case VT_AUXILIARY_INPUT_TYPE_2_MAINTENANCE:
    {
        if(direction == ecu_to_vt)
        {
            guint32 model_identification_code, status;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_auxiliaryinputtype2maintenance_modelidentificationcode, tvb, offset, 2, ENC_LITTLE_ENDIAN, &model_identification_code);
            offset += 2;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_auxiliaryinputtype2maintenance_status, tvb, offset, 1, ENC_LITTLE_ENDIAN, &status);

            if(status == 0)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Auxiliary Input Type 2 Maintenance: Model Identification Code %u, Status is Initializing",
                    model_identification_code);
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Auxiliary Input Type 2 Maintenance: Model Identification Code %u, Status is Ready",
                    model_identification_code);
            }
        }
    }
        break;
    case VT_AUXILIARY_ASSIGNMENT_TYPE_2:
    {
        guint32 error_codes, auxiliary_input_object_id = 0, auxiliary_function_object_id;
        guint64 name = 0;

        if(direction == ecu_to_vt)
        {
            proto_tree *flags_subtree;

            proto_tree_add_item_ret_uint64(tree,
                hf_isobus_vt_auxiliaryassignmenttype2_name, tvb, offset, 8, ENC_LITTLE_ENDIAN, &name);
            offset += 8;

            ti = proto_tree_add_item(tree,
                hf_isobus_vt_auxiliaryassignmenttype2_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            flags_subtree = proto_item_add_subtree(ti, ett_isobus_vt_auxiliaryassignmenttype2_flags);
            ti = proto_tree_add_item(flags_subtree,
                hf_isobus_vt_auxiliaryassignmenttype2_flags_preferredassignment, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_item_set_generated(ti);
            ti = proto_tree_add_item(flags_subtree,
                hf_isobus_vt_auxiliaryassignmenttype2_flags_auxiliaryfunctiontype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_item_set_generated(ti);
            offset += 1;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_auxiliaryassignmenttype2_auxinputobjectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &auxiliary_input_object_id);
            ti = proto_tree_add_item(tree,
                hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_set_hidden(ti);
            offset += 2;
        }

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_auxiliaryassignmenttype2_auxfunctionobjectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &auxiliary_function_object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        if(direction == vt_to_ecu)
        {
            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_auxiliaryassignmenttype2_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "error, assignment not accepted ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "error, this function is already assigned ");
        }

        if(direction == ecu_to_vt)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Assign %s of name 0x%" G_GINT64_MODIFIER "X to function %s",
                get_object_id_string(auxiliary_input_object_id), name, get_object_id_string(auxiliary_function_object_id));
        }
        else if(direction == vt_to_ecu)
        {
            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Error while assigning function %s",
                    get_object_id_string(auxiliary_function_object_id));
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Successfully assigned function %s",
                    get_object_id_string(auxiliary_function_object_id));
            }
        }
    }
        break;
    case VT_AUXILIARY_INPUT_STATUS_TYPE_2_ENABLE:
    {
        guint32 enable, status, error_codes, auxiliary_input_object_id;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_auxiliaryinputstatustype2enable_auxiliaryinputobjectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &auxiliary_input_object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        if(direction == ecu_to_vt)
        {
            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_auxiliaryinputstatustype2enable_enable, tvb, offset, 1, ENC_LITTLE_ENDIAN, &enable);
        }
        else
        {
            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_auxiliaryinputstatustype2enable_status, tvb, offset, 1, ENC_LITTLE_ENDIAN, &status);
            offset += 1;

            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_auxiliaryinputstatustype2enable_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "Invalid Auxiliary Input Object ID ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "any other error ");
        }

        if(direction == ecu_to_vt)
        {
            if(enable == 0)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Auxiliary Input %s should be disabled",
                    get_object_id_string(auxiliary_input_object_id));
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Auxiliary Input %s should be enabled",
                    get_object_id_string(auxiliary_input_object_id));
            }
        }
        else
        {
            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Error while changing status for Auxiliary Input %s",
                    get_object_id_string(auxiliary_input_object_id));
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Status of Auxiliary Input %s was successfully changed to enabled",
                    get_object_id_string(auxiliary_input_object_id));
            }
        }
    }
        break;
    case VT_AUXILIARY_INPUT_TYPE_2_STATUS:
    {
        guint32 auxiliary_input_object_id, value_1, value_2;
        proto_tree* operating_state_subtree;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_auxiliaryinputtype2status_auxiliaryinputobjectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &auxiliary_input_object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_auxiliaryinputtype2status_value1, tvb, offset, 2, ENC_LITTLE_ENDIAN, &value_1);
        offset += 2;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_auxiliaryinputtype2status_value2, tvb, offset, 2, ENC_LITTLE_ENDIAN, &value_2);
        offset += 2;

        ti = proto_tree_add_item(tree,
            hf_isobus_vt_auxiliaryinputtype2status_operatingstate, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        operating_state_subtree = proto_item_add_subtree(ti, ett_isobus_vt_auxiliaryinputtype2status_operatingstate);
        ti = proto_tree_add_item(operating_state_subtree,
            hf_isobus_vt_auxiliaryinputtype2status_operatingstate_learnmodeactive, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_item_set_generated(ti);
        ti = proto_tree_add_item(operating_state_subtree,
            hf_isobus_vt_auxiliaryinputtype2status_operatingstate_inputactivatedinlearnmode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_item_set_generated(ti);

        col_append_fstr(pinfo->cinfo, COL_INFO, "State of input %s value 1 = 0x%X value 2 = 0x%X.",
            get_object_id_string(auxiliary_input_object_id), value_1, value_2);
    }
        break;
    case VT_AUXILIARY_CAPABILITIES:
    {
        if(direction == ecu_to_vt)
        {
            guint32 request_type;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_auxiliarycapabilities_requesttype, tvb, offset, 1, ENC_LITTLE_ENDIAN, &request_type);

            col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
                val_to_str(request_type, auxiliary_capabilities_request_type, "Request capabilities of Unknown"));
        }
        else
        {
            guint32 number_of_auxiliary_units, i;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_auxiliarycapabilities_numberofauxiliaryunits, tvb, offset, 1, ENC_LITTLE_ENDIAN, &number_of_auxiliary_units);
            offset += 1;

            for(i = 0; i < number_of_auxiliary_units; i++)
            {
                proto_item *input_unit_item;
                proto_tree *input_unit_subtree;
                guint32 number_of_different_sets, j;
                guint64 name;

                input_unit_subtree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_isobus_vt_auxiliarycapabilities_inputunit, &input_unit_item, "Auxiliary Unit");

                proto_tree_add_item_ret_uint64(input_unit_subtree,
                    hf_isobus_vt_auxiliarycapabilities_auxiliaryunit_name, tvb, offset, 8, ENC_LITTLE_ENDIAN, &name);
                offset += 8;

                proto_tree_add_item_ret_uint(input_unit_subtree,
                    hf_isobus_vt_auxiliarycapabilities_auxiliaryunit_numberofdifferentsets, tvb, offset, 1, ENC_LITTLE_ENDIAN, &number_of_different_sets);
                offset += 1;

                proto_item_set_text(input_unit_item, "Auxiliary unit name 0x%" G_GINT64_MODIFIER "X", name);
                proto_item_set_len(input_unit_item, 8 + 1 + (3 * number_of_different_sets));

                for(j = 0; j < number_of_different_sets; j++)
                {
                    proto_item *auxiliary_unit_set;
                    proto_tree *preferred_function_subtree;
                    guint32 number_of_instances, function_attribute, assigned_attribute;

                    preferred_function_subtree = proto_tree_add_subtree(input_unit_subtree, tvb, offset, 3, ett_isobus_vt_auxiliarycapabilities_inputunit_set, &auxiliary_unit_set, "Auxiliary Unit");

                    proto_tree_add_item_ret_uint(preferred_function_subtree,
                        hf_isobus_vt_auxiliarycapabilities_auxiliaryunit_set_numberofinstances, tvb, offset, 1, ENC_LITTLE_ENDIAN, &number_of_instances);
                    offset += 1;

                    proto_tree_add_item_ret_uint(preferred_function_subtree,
                        hf_isobus_vt_auxiliarycapabilities_auxiliaryunit_set_functionattribute, tvb, offset, 1, ENC_LITTLE_ENDIAN, &function_attribute);
                    offset += 1;

                    proto_tree_add_item_ret_uint(preferred_function_subtree,
                        hf_isobus_vt_auxiliarycapabilities_auxiliaryunit_set_assignedattribute, tvb, offset, 1, ENC_LITTLE_ENDIAN, &assigned_attribute);
                    offset += 1;

                    proto_item_set_text(input_unit_item, "Auxiliary set containing %u instances with function attribute %u assigned to %s",
                        number_of_instances, function_attribute, val_to_str(assigned_attribute, auxiliary_assigned_attributes, "unknown"));
                }
            }
            col_append_fstr(pinfo->cinfo, COL_INFO, "Received Auxiliary Capabilities");
        }
    }
        break;
    case VT_ESC:
        if(direction == vt_to_ecu)
        {
            guint32 object_id, error_codes;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_esc_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
            ti = proto_tree_add_item(tree,
                hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_set_hidden(ti);
            offset += 2;

            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_esc_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "No input field is open for input, ESC ignored ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "any other error ");

            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "ESC successful, %s", get_object_id_string(object_id));
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "ESC error");
            }
        }
        else
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "End of object pool received, object pool accepted");
        }
        break;
    case VT_HIDE_SHOW_OBJECT:
    {
        guint32 object_id, action;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_hideshowobj_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_hideshowobj_action, tvb, offset, 1, ENC_LITTLE_ENDIAN, &action);
        offset += 1;

        if(direction == vt_to_ecu)
        {
            guint32 error_codes;
            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_hideshowobj_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);

            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "Invalid Object ID ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Invalid Value ");
            if (error_codes & 0x04)
                proto_item_append_text(ti, "Value in use ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "Any other error ");

            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Hide Show Error");
            }
            else
            {
                switch(action)
                {
                case 0:
                    col_append_fstr(pinfo->cinfo, COL_INFO, "%s is now hidden",
                        get_object_id_string(object_id));
                    break;
                case 1:
                    col_append_fstr(pinfo->cinfo, COL_INFO, "%s is now shown",
                        get_object_id_string(object_id));
                    break;
                }
            }
        }
        else
        {
            switch(action)
            {
            case 0:
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s should hide",
                    get_object_id_string(object_id));
                break;
            case 1:
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s should show",
                    get_object_id_string(object_id));
                break;
            }
        }
    }
        break;
    case VT_ENABLE_DISABLE_COMMAND:
    {
        guint32 object_id, enable_disable;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_enabledisableobj_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_enabledisableobj_enabledisable, tvb, offset, 1, ENC_LITTLE_ENDIAN, &enable_disable);
        offset += 1;

        if(direction == ecu_to_vt)
        {
            switch(enable_disable)
            {
            case 0:
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s should disable",
                    get_object_id_string(object_id));
                break;
            case 1:
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s should enable",
                    get_object_id_string(object_id));
                break;
            }
        }
        else
        {
            guint32 error_codes;

            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_enabledisableobj_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);

            proto_item_append_text(ti, ": ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Invalid Object ID ");
            if (error_codes & 0x04)
                proto_item_append_text(ti, "Command error ");
            if (error_codes & 0x08)
                proto_item_append_text(ti, "Could not complete. Operator input is active on this object. ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "Any other error ");

            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Enable Disable Error");
            }
            else
            {
                switch(enable_disable)
                {
                case 0:
                    col_append_fstr(pinfo->cinfo, COL_INFO, "%s is now disabled",
                        get_object_id_string(object_id));
                    break;
                case 1:
                    col_append_fstr(pinfo->cinfo, COL_INFO, "%s is now enabled",
                        get_object_id_string(object_id));
                    break;
                }

            }
        }
    }
        break;
    case VT_SELECT_INPUT_OBJECT:
    {
        guint32 object_id;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_selectinputobject_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        if(direction == ecu_to_vt)
        {
            proto_tree_add_item(tree,
                hf_isobus_vt_selectinputobject_option, tvb, offset, 1, ENC_LITTLE_ENDIAN);

            col_append_fstr(pinfo->cinfo, COL_INFO, "%s should be selected for input",
                get_object_id_string(object_id));
        }
        else
        {
            guint32 response, error_codes;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_selectinputobject_response, tvb, offset, 1, ENC_LITTLE_ENDIAN, &response);
            offset += 1;

            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_selectinputobject_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "Object is disabled ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Invalid Object ID ");
            if (error_codes & 0x04)
                proto_item_append_text(ti, "Object is not on the active mask or object is in a hidden container ");
            if (error_codes & 0x08)
                proto_item_append_text(ti, "Could not complete. Another Input field is currently being modified, or a Button or Soft Key is currently being held. ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "Any other error ");
            if (error_codes & 0x20)
                proto_item_append_text(ti, "Invalid option value ");

            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Error while selecting input object");
            }
            else
            {
                switch(response)
                {
                    case 0:
                        col_append_fstr(pinfo->cinfo, COL_INFO, "%s is not selected",
                            get_object_id_string(object_id));
                        break;
                    case 1:
                        col_append_fstr(pinfo->cinfo, COL_INFO, "%s is selected",
                            get_object_id_string(object_id));
                        break;
                    case 2:
                        col_append_fstr(pinfo->cinfo, COL_INFO, "%s is opened for edit",
                            get_object_id_string(object_id));
                        break;
                }
            }
        }
    }
        break;
    case VT_CONTROL_AUDIO_SIGNAL:
    {
        if(direction == ecu_to_vt)
        {
            guint32 activations, frequency, ontime, offtime;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_controlaudiosignal_activations, tvb, offset, 1, ENC_LITTLE_ENDIAN, &activations);
            offset += 1;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_controlaudiosignal_frequency, tvb, offset, 2, ENC_LITTLE_ENDIAN, &frequency);
            offset += 2;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_controlaudiosignal_ontime, tvb, offset, 2, ENC_LITTLE_ENDIAN, &ontime);
            offset += 2;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_controlaudiosignal_offtime, tvb, offset, 2, ENC_LITTLE_ENDIAN, &offtime);

            col_append_fstr(pinfo->cinfo, COL_INFO, "Control audio signal with %d activations of %d Hz (On-time %d ms, Off-time %d ms.)",
                            activations, frequency, ontime, offtime);
        }
        else
        {
            guint32 error_codes;
            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_controlaudiosignal_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);

            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "Audio device is busy ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "Any other error ");

            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Control audio signal Error");
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Control audio signal successful");
            }
        }
    }
        break;
    case VT_SET_AUDIO_VOLUME:
    {
        if(direction == ecu_to_vt)
        {
            guint32 volume;
            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_setaudiovolume_volume, tvb, offset, 1, ENC_LITTLE_ENDIAN, &volume);

            col_append_fstr(pinfo->cinfo, COL_INFO, "Set audio volume to %d%%", volume);
        }
        else
        {
            guint32 error_codes;
            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_setaudiovolume_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);

            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "Audio device is busy, subsequent commands use the new setting ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Command is not supported ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "Any other error ");

            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Set audio volume Error");
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Set audio volume successful");
            }
        }
    }
        break;
    case VT_CHANGE_CHILD_LOCATION:
    {
        guint32 parent_object_id, object_id;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_changechildlocation_parentobjectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &parent_object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_changechildlocation_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        if(direction == ecu_to_vt)
        {
            guint32 rel_x_location, rel_y_location;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changechildlocation_relativexpos, tvb, offset, 1, ENC_LITTLE_ENDIAN, &rel_x_location);
            offset += 1;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changechildlocation_relativeypos, tvb, offset, 1, ENC_LITTLE_ENDIAN, &rel_y_location);

            col_append_fstr(pinfo->cinfo, COL_INFO, "Change child location of %s in %s to [%u;%u]",
                            get_object_id_string(object_id), get_object_id_string(parent_object_id), rel_x_location, rel_y_location);
        }
        else
        {
            guint32 error_codes;
            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changechildlocation_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);

            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "Invalid Parent Object ID ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Invalid Object ID ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "Any other error ");

            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Change child location error");
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Change child location of %s in %s succeeded",
                    get_object_id_string(object_id), get_object_id_string(parent_object_id));
            }
        }
    }
        break;
    case VT_CHANGE_SIZE:
    {
        guint32 object_id;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_changesize_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        if(direction == ecu_to_vt)
        {
            guint32 new_width, new_height;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changesize_newwidth, tvb, offset, 2, ENC_LITTLE_ENDIAN, &new_width);
            offset += 2;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changesize_newheight, tvb, offset, 2, ENC_LITTLE_ENDIAN, &new_height);

            col_append_fstr(pinfo->cinfo, COL_INFO, "Change size of %s to %u x %u",
                get_object_id_string(object_id), new_width, new_height);
        }
        else
        {
            guint32 error_codes;
            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changesize_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);

            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "Invalid Object ID ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "Any other error ");

            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Change size error");
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Change size of %s succeeded",
                    get_object_id_string(object_id));
            }
        }
    }
        break;
    case VT_CHANGE_BACKGROUND_COLOUR:
    {
        guint32 object_id, colour;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_changebackgroundcolour_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_changebackgroundcolour_colour, tvb, offset, 1, ENC_LITTLE_ENDIAN, &colour);
        offset += 1;

        if(direction == vt_to_ecu)
        {
            guint32 error_codes;
            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changebackgroundcolour_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);

            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "Invalid Object ID ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Invalid Value ");
            if (error_codes & 0x04)
                proto_item_append_text(ti, "Value in use ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "Any other error ");

            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Background colour change error");
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Background colour of %s has changed to %s",
                    get_object_id_string(object_id), rval_to_str(colour, vt_colours, "Unknown"));
            }
        }
        else
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Background colour of %s should change to %s",
                get_object_id_string(object_id), rval_to_str(colour, vt_colours, "Unknown"));
        }
    }
        break;
    case VT_CHANGE_NUMERIC_VALUE:
    {
        guint32 object_id, error_codes, value;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_chgnumval_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        if(direction == vt_to_ecu)
        {
            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_chgnumval_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "Invalid Object ID ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Invalid Value ");
            if (error_codes & 0x04)
                proto_item_append_text(ti, "Value in use ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "Any other error ");
        } /* no else, byte is reserved for ecu_to_vt */
        offset += 1;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_chgnumval_value, tvb, offset, 4, ENC_LITTLE_ENDIAN, &value);

        if(direction == vt_to_ecu)
        {
            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Numeric value change error");
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Numeric value of %s has changed to 0x%X",
                    get_object_id_string(object_id), value);
            }
        }
        else
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Numeric value of %s should change to 0x%X",
                get_object_id_string(object_id), value);
        }
    }
        break;
    case VT_CHANGE_END_POINT:
    {
        guint32 object_id;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_changeendpoint_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        if(direction == ecu_to_vt)
        {
            guint32 width, height;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changeendpoint_width, tvb, offset, 2, ENC_LITTLE_ENDIAN, &width);
            offset += 2;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changeendpoint_height, tvb, offset, 2, ENC_LITTLE_ENDIAN, &height);
            offset += 2;

            proto_tree_add_item(tree,
                hf_isobus_vt_changeendpoint_linedirection, tvb, offset, 1, ENC_LITTLE_ENDIAN);

            col_append_fstr(pinfo->cinfo, COL_INFO, "Change end point of line %s to width %d and height %d",
                get_object_id_string(object_id), width, height);
        }
    }
        break;
    case VT_CHANGE_FONT_ATTRIBUTES:
    {
        guint32 object_id;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_changefontattributes_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        if(direction == ecu_to_vt)
        {
            proto_tree_add_item(tree,
                hf_isobus_vt_changefontattributes_fontcolour, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            proto_tree_add_item(tree,
                hf_isobus_vt_changefontattributes_fontsize, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            proto_tree_add_item(tree,
                hf_isobus_vt_changefontattributes_fonttype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            proto_tree_add_item(tree,
                hf_isobus_vt_changefontattributes_fontstyle, tvb, offset, 1, ENC_LITTLE_ENDIAN);

            col_append_fstr(pinfo->cinfo, COL_INFO, "Change font attributes of %s", get_object_id_string(object_id));
        }
        else
        {
            guint32 error_codes;

            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changefontattributes_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "Invalid Object ID ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Invalid colour ");
            if (error_codes & 0x04)
                proto_item_append_text(ti, "Invalid size ");
            if (error_codes & 0x08)
                proto_item_append_text(ti, "Invalid type ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "Invalid style ");
            if (error_codes & 0x20)
                proto_item_append_text(ti, "Any other error ");

            if(error_codes == 0)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Font attributes of %s successfully changed", get_object_id_string(object_id));
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Error while changing font attributes of %s", get_object_id_string(object_id));
            }
        }
    }
        break;
    case VT_CHANGE_LINE_ATTRIBUTES:
    {
        guint32 object_id;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_changelineattributes_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        if(direction == ecu_to_vt)
        {
            proto_tree_add_item(tree,
                hf_isobus_vt_changelineattributes_linecolour, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            proto_tree_add_item(tree,
                hf_isobus_vt_changelineattributes_linewidth, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            proto_tree_add_item(tree,
                hf_isobus_vt_changelineattributes_lineart, tvb, offset, 2, ENC_LITTLE_ENDIAN);

            col_append_fstr(pinfo->cinfo, COL_INFO, "Change line attributes of %s", get_object_id_string(object_id));
        }
        else
        {
            guint32 error_codes;

            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changelineattributes_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "Invalid Object ID ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Invalid colour ");
            if (error_codes & 0x04)
                proto_item_append_text(ti, "Invalid width ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "Any other error ");

            if(error_codes == 0)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Line attributes of %s successfully changed", get_object_id_string(object_id));
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Error while changing line attributes of %s", get_object_id_string(object_id));
            }
        }
    }
        break;
    case VT_CHANGE_FILL_ATTRIBUTES:
    {
        guint32 object_id;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_changefillattributes_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        if(direction == ecu_to_vt)
        {
            proto_tree_add_item(tree,
                hf_isobus_vt_changefillattributes_filltype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            proto_tree_add_item(tree,
                hf_isobus_vt_changefillattributes_fillcolour, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            proto_tree_add_item(tree,
                hf_isobus_vt_changefillattributes_fillpatternobjectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            ti = proto_tree_add_item(tree,
                hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_set_hidden(ti);

            col_append_fstr(pinfo->cinfo, COL_INFO, "Change fill attributes of %s", get_object_id_string(object_id));
        }
        else
        {
            guint32 error_codes;

            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changefillattributes_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "Invalid Object ID ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Invalid type ");
            if (error_codes & 0x04)
                proto_item_append_text(ti, "Invalid colour ");
            if (error_codes & 0x08)
                proto_item_append_text(ti, "Invalid pattern Object ID ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "Any other error ");

            if(error_codes == 0)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Fill attributes of %s successfully changed", get_object_id_string(object_id));
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Error while changing fill attributes of %s", get_object_id_string(object_id));
            }
        }
    }
        break;
    case VT_CHANGE_ACTIVE_MASK:
    {
        guint32 working_set_object_id, new_active_mask_object_id, error_codes;

        if(direction == ecu_to_vt)
        {
            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changeactivemask_workingset, tvb, offset, 2, ENC_LITTLE_ENDIAN, &working_set_object_id);
            ti = proto_tree_add_item(tree,
                hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_set_hidden(ti);
            offset += 2;
        }
        else
        {
            working_set_object_id = 0;
        }

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_changeactivemask_newactivemask, tvb, offset, 2, ENC_LITTLE_ENDIAN, &new_active_mask_object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        if(direction == vt_to_ecu)
        {
            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changeactivemask_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "Invalid Working Set Object ID ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Invalid Mask Object ID ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "Any other error ");
        }

        if(direction == ecu_to_vt)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Change active mask of working set %s to %s", get_object_id_string(working_set_object_id), get_object_id_string(new_active_mask_object_id));
        }
        else if(direction == vt_to_ecu)
        {
            if(error_codes == 0)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Active mask successfully changed to %s", get_object_id_string(new_active_mask_object_id));
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Error while changing active mask to %s", get_object_id_string(new_active_mask_object_id));
            }
        }
    }
        break;
    case VT_CHANGE_SOFT_KEY_MASK:
    {
        guint32 error_codes, data_mask_object_id, new_soft_key_mask_object_id;

        if(direction == ecu_to_vt)
        {
            proto_tree_add_item(tree,
                hf_isobus_vt_changesoftkeymask_masktype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
        }

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_changesoftkeymask_datamaskobjectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &data_mask_object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_changesoftkeymask_newsoftkeymaskobjectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &new_soft_key_mask_object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        if(direction == vt_to_ecu)
        {
            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changesoftkeymask_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "Invalid Data or Alarm Mask Object ID ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Invalid Soft Key Mask Object ID ");
            if (error_codes & 0x04)
                proto_item_append_text(ti, "Missing Objects ");
            if (error_codes & 0x08)
                proto_item_append_text(ti, "Mask or child object has errors ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "Any other error ");
        }

        if(direction == ecu_to_vt)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Soft key mask of %s should change to %s", get_object_id_string(data_mask_object_id), get_object_id_string(new_soft_key_mask_object_id));
        }
        else if(direction == vt_to_ecu)
        {
            if(error_codes == 0)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Soft key mask of %s successfully changed to %s", get_object_id_string(data_mask_object_id), get_object_id_string(new_soft_key_mask_object_id));
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Error while changing soft key mask of %s to %s", get_object_id_string(data_mask_object_id), get_object_id_string(new_soft_key_mask_object_id));
            }
        }
    }
        break;
    case VT_CHANGE_ATTRIBUTES:
    {
        guint32 attribute_id, error_codes, object_id, new_value;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_changeattributes_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_changeattributes_attributeid, tvb, offset, 1, ENC_LITTLE_ENDIAN, &attribute_id);
        offset += 1;

        if(direction == ecu_to_vt)
        {
            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changeattributes_newvalue, tvb, offset, 1, ENC_LITTLE_ENDIAN, &new_value);
        }
        else if(direction == vt_to_ecu)
        {
            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changeattributes_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "Invalid Object ID ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Invalid Attribute ID ");
            if (error_codes & 0x04)
                proto_item_append_text(ti, "Invalid Value ");
            if (error_codes & 0x08)
                proto_item_append_text(ti, "Value in use ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "Any other error ");
        }

        if(direction == ecu_to_vt)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Attribute ID %u of %s should change to 0x%X", attribute_id, get_object_id_string(object_id), new_value);
        }
        else if(direction == vt_to_ecu)
        {
            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Error while changing Attribute ID %u of %s", attribute_id, get_object_id_string(object_id));
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Attribute ID %u of %s has successfully changed", attribute_id, get_object_id_string(object_id));
            }
        }
    }
        break;
    case VT_CHANGE_PRIORITY:
    {
        guint32 object_id, new_priority, error_codes;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_changepriority_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_changepriority_newpriority, tvb, offset, 1, ENC_LITTLE_ENDIAN, &new_priority);
        offset += 1;

        if(direction == vt_to_ecu)
        {
            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changepriority_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "Invalid Object ID ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Invalid priority ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "Any other error ");
        }

        if(direction == ecu_to_vt)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Priority of alarm mask with %s should change to %u", get_object_id_string(object_id), new_priority);
        }
        else if(direction == vt_to_ecu)
        {
            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Error while changing priority of alarm mask with %s to %u", get_object_id_string(object_id), new_priority);
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Priority of alarm mask with %s has successfully changed to %u", get_object_id_string(object_id), new_priority);
            }
        }
    }
        break;
    case VT_CHANGE_LIST_ITEM:
    {
        guint32 list_object_id, new_object_id, list_index, error_codes;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_changelistitem_listobjectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &list_object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_changelistitem_listindex, tvb, offset, 1, ENC_LITTLE_ENDIAN, &list_index);
        offset += 1;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_changelistitem_newobjectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &new_object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        if(direction == vt_to_ecu)
        {
            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changelistitem_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "Invalid Input List object ID or Output List object ID, Animation object, External Object Definition object ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Invalid List Index ");
            if (error_codes & 0x04)
                proto_item_append_text(ti, "Invalid New List Item Object ID ");
            if (error_codes & 0x08)
                proto_item_append_text(ti, "Value in user ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "Any other error ");
        }

        if(direction == ecu_to_vt)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s should be added to list %s at index %u", get_object_id_string(new_object_id), get_object_id_string(list_object_id), list_index);
        }
        else if(direction == vt_to_ecu)
        {
            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Error while adding %s to list %s at index %u", get_object_id_string(new_object_id), get_object_id_string(list_object_id), list_index);
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "%s was successfully added to %s at index %u", get_object_id_string(new_object_id), get_object_id_string(list_object_id), list_index);
            }
        }
    }
        break;
    case VT_DELETE_OBJECT_POOL:
    {
        if(direction == ecu_to_vt)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Object pool should be deleted from volatile memory");
        }
        else
        {
            guint32 error_codes;

            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_deleteobjectpool_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "Deletion Error ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "Any other error ");

            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Error while deleting object pool from volatile memory");
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Object pool was successfully deleted from volatile memory");
            }
        }
    }
        break;
    case VT_CHANGE_STRING_VALUE:
    {
        if(direction == ecu_to_vt)
        {
            guint encoding = ENC_ASCII|ENC_NA;
            guint32 object_id, str_length;
            guint16 firstTwoBytesString;
            const guint8* value;
            guint bomOffset = 0;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_chgstrval_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
            ti = proto_tree_add_item(tree,
                hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_set_hidden(ti);
            offset += 2;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_chgstrval_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &str_length);
            offset += 2;

            firstTwoBytesString = tvb_get_letohs(tvb,offset);
            if(firstTwoBytesString == 0xFEFF)
            {
                encoding = ENC_UCS_2|ENC_BIG_ENDIAN;
                bomOffset = 2;
            }

            proto_tree_add_item_ret_string(tree,
                hf_isobus_vt_chgstrval_value, tvb, offset + bomOffset, str_length - bomOffset, encoding, wmem_packet_scope(), &value);

            col_append_fstr(pinfo->cinfo, COL_INFO, "String value of %s should change to %s",
                get_object_id_string(object_id), value);
        }
        else
        {
            guint32 object_id, error_codes;

            offset += 2;    /*first two bytes are reserved*/

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_chgstrval_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
            ti = proto_tree_add_item(tree,
                hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_set_hidden(ti);
            offset += 2;

            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_chgstrval_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);

            proto_item_append_text(ti, ": ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Invalid Object ID ");
            if (error_codes & 0x04)
                proto_item_append_text(ti, "String too long ");
            if (error_codes & 0x08)
                proto_item_append_text(ti, "Any other error ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "Value in use ");

            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "String value change error");
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "String value of %s has changed",
                    get_object_id_string(object_id));
            }
        }
    }
        break;
    case VT_CHANGE_CHILD_POSITION:
    {
        guint32 parent_object_id, object_id;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_changechildposition_parentobjectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &parent_object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;


        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_changechildposition_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        if(direction == ecu_to_vt)
        {
            guint32 rel_x_position, rel_y_position;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changechildposition_xpos, tvb, offset, 2, ENC_LITTLE_ENDIAN, &rel_x_position);
            offset += 2;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changechildposition_ypos, tvb, offset, 2, ENC_LITTLE_ENDIAN, &rel_y_position);

            col_append_fstr(pinfo->cinfo, COL_INFO, "Change child position of %s in %s to [%u:%u]",
                get_object_id_string(object_id), get_object_id_string(parent_object_id), rel_x_position, rel_y_position);
        }
        else
        {
            guint32 error_codes;
            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changechildposition_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);

            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "Invalid Parent Object ID ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Invalid Object ID ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "Any other error ");

            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Error while changing child position of %s", get_object_id_string(object_id));
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Change child position of %s in %s succeeded",
                    get_object_id_string(object_id), get_object_id_string(parent_object_id));
            }
        }
    }
        break;
    case VT_CHANGE_OBJECT_LABEL:
    {
        if(direction == ecu_to_vt)
        {
            guint32 object_id, string_object_id;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changeobjectlabel_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
            ti = proto_tree_add_item(tree,
                hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_set_hidden(ti);
            offset += 2;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changeobjectlabel_stringobjectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &string_object_id);
            ti = proto_tree_add_item(tree,
                hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_set_hidden(ti);
            offset += 2;

            proto_tree_add_item(tree,
                hf_isobus_vt_changeobjectlabel_fonttype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            proto_tree_add_item(tree,
                hf_isobus_vt_changeobjectlabel_graphicobjectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            ti = proto_tree_add_item(tree,
                hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_set_hidden(ti);

            col_append_fstr(pinfo->cinfo, COL_INFO, "Change object label of %s to string %s",
                            get_object_id_string(object_id), get_object_id_string(string_object_id));
        }
        else
        {
            guint32 error_codes;
            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changeobjectlabel_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);

            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "Invalid object id ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Invalid String Variable object id ");
            if (error_codes & 0x04)
                proto_item_append_text(ti, "Invalid font type ");
            if (error_codes & 0x08)
                proto_item_append_text(ti, "No Object Label Reference List object available in object pool ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "Designator references invalid objects ");
            if (error_codes & 0x20)
                proto_item_append_text(ti, "Any other error ");

            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Error while changing object label");
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Object label successfully changed");
            }
        }
    }
        break;
    case VT_CHANGE_POLYGON_POINT:
    {
        guint32 object_id;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_changepolygonpoint_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        if(direction == ecu_to_vt)
        {
            guint32 x_value, y_value, point_index;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changepolygonpoint_pointindex, tvb, offset, 1, ENC_LITTLE_ENDIAN, &point_index);
            offset += 1;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changepolygonpoint_xvalue, tvb, offset, 2, ENC_LITTLE_ENDIAN, &x_value);
            offset += 2;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changepolygonpoint_yvalue, tvb, offset, 2, ENC_LITTLE_ENDIAN, &y_value);

            col_append_fstr(pinfo->cinfo, COL_INFO, "Change point %u of polygon %s to location [%u:%u] ",
                point_index, get_object_id_string(object_id), x_value, y_value);
        }
        else
        {
            guint32 error_codes;
            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changepolygonpoint_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "Invalid Object ID ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Invalid point index ");
            if (error_codes & 0x04)
                proto_item_append_text(ti, "Any other error ");

            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Error while changing polygon point");
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Polygon point successfully changed");
            }
        }
    }
        break;
    case VT_CHANGE_POLYGON_SCALE:
    {
        guint32 object_id, new_width, new_height, error_codes;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_changepolygonscale_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_changepolygonscale_newwidth, tvb, offset, 2, ENC_LITTLE_ENDIAN, &new_width);
        offset += 2;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_changepolygonscale_newheight, tvb, offset, 2, ENC_LITTLE_ENDIAN, &new_height);
        offset += 2;

        if(direction == vt_to_ecu)
        {
            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_changepolygonscale_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "Invalid Object ID ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "Any other error ");
        }

        if(direction == ecu_to_vt)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Change scale of polygon %s to width %u and height %u ",
                get_object_id_string(object_id), new_width, new_height);
        }
        else if(direction == vt_to_ecu)
        {
            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Error while changing scale of polygon %s to width %u and height %u ",
                    get_object_id_string(object_id), new_width, new_height);
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Scale of polygon %s scale successfully changed to width %u and height %u ",
                    get_object_id_string(object_id), new_width, new_height);
            }
        }
    }
        break;
    case VT_GRAPHICS_CONTEXT:
    {
        guint32 object_id, sub_command_id;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_graphicscontext_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_graphicscontext_subcommandid, tvb, offset, 1, ENC_LITTLE_ENDIAN, &sub_command_id);
        offset += 1;

        col_append_fstr(pinfo->cinfo, COL_INFO, "Graphic Context of %s: ", get_object_id_string(object_id));

        switch(sub_command_id)
        {
            case SET_GRAPHICS_CURSOR:
            {
                gint32 x_position, y_position;

                proto_tree_add_item_ret_int(tree,
                    hf_isobus_vt_graphicscontext_setgraphicscursor_xposition, tvb, offset, 2, ENC_LITTLE_ENDIAN, &x_position);
                offset += 2;

                proto_tree_add_item_ret_int(tree,
                    hf_isobus_vt_graphicscontext_setgraphicscursor_yposition, tvb, offset, 2, ENC_LITTLE_ENDIAN, &y_position);

                col_append_fstr(pinfo->cinfo, COL_INFO, "Set Graphics Cursor to Position [%d;%d] ",
                    x_position, y_position);
            }
                break;
            case MOVE_GRAPHICS_CURSOR:
            {
                gint32 x_offset, y_offset;

                proto_tree_add_item_ret_int(tree,
                    hf_isobus_vt_graphicscontext_movegraphicscursor_xoffset, tvb, offset, 2, ENC_LITTLE_ENDIAN, &x_offset);
                offset += 2;

                proto_tree_add_item_ret_int(tree,
                    hf_isobus_vt_graphicscontext_movegraphicscursor_yoffset, tvb, offset, 2, ENC_LITTLE_ENDIAN, &y_offset);

                col_append_fstr(pinfo->cinfo, COL_INFO, "Move Graphics Cursor by Offset [%d;%d] ",
                    x_offset, y_offset);
            }
                break;
            case SET_FOREGROUND_COLOUR:
            {
                guint32 colour;

                proto_tree_add_item_ret_uint(tree,
                    hf_isobus_vt_graphicscontext_setforegroundcolour_colour, tvb, offset, 1, ENC_LITTLE_ENDIAN, &colour);

                col_append_fstr(pinfo->cinfo, COL_INFO, "Set Foreground Colour to %u",
                    colour);
            }
                break;
            case SET_BACKGROUND_COLOUR:
            {
                guint32 colour;

                proto_tree_add_item_ret_uint(tree,
                    hf_isobus_vt_graphicscontext_setbackgroundcolour_colour, tvb, offset, 1, ENC_LITTLE_ENDIAN, &colour);

                col_append_fstr(pinfo->cinfo, COL_INFO, "Set Background Colour to %u",
                    colour);
            }
                break;
            case SET_LINE_ATTRIBUTES_OBJECT_ID:
            {
                guint32 line_attr_object_id;

                proto_tree_add_item_ret_uint(tree,
                    hf_isobus_vt_graphicscontext_setlineattributesobjectid_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &line_attr_object_id);
                ti = proto_tree_add_item(tree,
                    hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_item_set_hidden(ti);

                col_append_fstr(pinfo->cinfo, COL_INFO, "Set Line Attributes to %s",
                    get_object_id_string(line_attr_object_id));
            }
                break;
            case SET_FILL_ATTRIBUTES_OBJECT_ID:
            {
                guint32 fill_attr_object_id;

                proto_tree_add_item_ret_uint(tree,
                    hf_isobus_vt_graphicscontext_setfillattributesobjectid_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &fill_attr_object_id);
                ti = proto_tree_add_item(tree,
                    hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_item_set_hidden(ti);

                col_append_fstr(pinfo->cinfo, COL_INFO, "Set Fill Attributes to %s",
                    get_object_id_string(fill_attr_object_id));
            }
                break;
            case SET_FONT_ATTRIBUTES_OBJECT_ID:
            {
                guint32 font_attr_object_id;

                proto_tree_add_item_ret_uint(tree,
                    hf_isobus_vt_graphicscontext_setfontattributesobjectid_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &font_attr_object_id);
                ti = proto_tree_add_item(tree,
                    hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_item_set_hidden(ti);

                col_append_fstr(pinfo->cinfo, COL_INFO, "Set Font Attributes to %s",
                    get_object_id_string(font_attr_object_id));
            }
                break;
            case ERASE_RECTANGLE:
            {
                guint32 width, height;

                proto_tree_add_item_ret_uint(tree,
                    hf_isobus_vt_graphicscontext_eraserectangle_width, tvb, offset, 2, ENC_LITTLE_ENDIAN, &width);
                offset += 2;

                proto_tree_add_item_ret_uint(tree,
                    hf_isobus_vt_graphicscontext_eraserectangle_height, tvb, offset, 2, ENC_LITTLE_ENDIAN, &height);

                col_append_fstr(pinfo->cinfo, COL_INFO, "Erase Rectangle width %u height %u",
                    width, height);
            }
                break;
            case DRAW_POINT:
            {
                gint32 x_offset, y_offset;

                proto_tree_add_item_ret_int(tree,
                    hf_isobus_vt_graphicscontext_drawpoint_xoffset, tvb, offset, 2, ENC_LITTLE_ENDIAN, &x_offset);
                offset += 2;

                proto_tree_add_item_ret_int(tree,
                    hf_isobus_vt_graphicscontext_drawpoint_yoffset, tvb, offset, 2, ENC_LITTLE_ENDIAN, &y_offset);

                col_append_fstr(pinfo->cinfo, COL_INFO, "Draw point at graphics cursor with offset [%d;%d] ",
                    x_offset, y_offset);
            }
                break;
            case DRAW_LINE:
            {
                gint32 x_offset, y_offset;

                proto_tree_add_item_ret_int(tree,
                    hf_isobus_vt_graphicscontext_drawline_xoffset, tvb, offset, 2, ENC_LITTLE_ENDIAN, &x_offset);
                offset += 2;

                proto_tree_add_item_ret_int(tree,
                    hf_isobus_vt_graphicscontext_drawline_yoffset, tvb, offset, 2, ENC_LITTLE_ENDIAN, &y_offset);

                col_append_fstr(pinfo->cinfo, COL_INFO, "Draw line from graphics cursor to offset [%d;%d] ",
                    x_offset, y_offset);
            }
                break;
            case DRAW_RECTANGLE:
            {
                guint32 width, height;

                proto_tree_add_item_ret_uint(tree,
                    hf_isobus_vt_graphicscontext_drawrectangle_width, tvb, offset, 2, ENC_LITTLE_ENDIAN, &width);
                offset += 2;

                proto_tree_add_item_ret_uint(tree,
                    hf_isobus_vt_graphicscontext_drawrectangle_height, tvb, offset, 2, ENC_LITTLE_ENDIAN, &height);

                col_append_fstr(pinfo->cinfo, COL_INFO, "Draw Rectangle width %u height %u",
                    width, height);
            }
                break;
            case DRAW_CLOSED_ELLIPSE:
            {
                guint32 width, height;

                proto_tree_add_item_ret_uint(tree,
                    hf_isobus_vt_graphicscontext_drawclosedellipse_width, tvb, offset, 2, ENC_LITTLE_ENDIAN, &width);
                offset += 2;

                proto_tree_add_item_ret_uint(tree,
                    hf_isobus_vt_graphicscontext_drawclosedellipse_height, tvb, offset, 2, ENC_LITTLE_ENDIAN, &height);

                col_append_fstr(pinfo->cinfo, COL_INFO, "Draw Closed Ellipse width %u height %u",
                    width, height);
            }
                break;
            case DRAW_POLYGON:
            {
                guint32 number_of_points, i;

                proto_tree_add_item_ret_uint(tree,
                    hf_isobus_vt_graphicscontext_drawpolygon_numberofpoints, tvb, offset, 1, ENC_LITTLE_ENDIAN, &number_of_points);
                offset += 1;

                for(i = 0; i < number_of_points; i++)
                {
                    proto_item *point_item;
                    proto_tree *point_subtree;
                    gint32 x_offset, y_offset;

                    point_subtree = proto_tree_add_subtree(tree,
                        tvb, offset, 4, ett_isobus_vt_getsupportedwidechars_range, &point_item, "Point");

                    proto_tree_add_item_ret_int(point_subtree,
                        hf_isobus_vt_graphicscontext_drawpolygon_point_xoffset, tvb, offset, 2, ENC_LITTLE_ENDIAN, &x_offset);
                    offset += 2;

                    proto_tree_add_item_ret_int(point_subtree,
                        hf_isobus_vt_graphicscontext_drawpolygon_point_yoffset, tvb, offset, 2, ENC_LITTLE_ENDIAN, &y_offset);
                    offset += 2;

                    proto_item_set_text(point_item, "Point with offset [%d;%d]", x_offset, y_offset);
                }

                col_append_fstr(pinfo->cinfo, COL_INFO, "Draw Polygon of %u points",
                    number_of_points);
            }
                break;
            case DRAW_TEXT:
            {
                guint encoding = ENC_ASCII|ENC_NA;
                guint16 firstTwoBytesString;
                guint bomOffset = 0;
                guint32 background, number_of_bytes;
                const guint8* value;

                proto_tree_add_item_ret_uint(tree,
                    hf_isobus_vt_graphicscontext_drawtext_background, tvb, offset, 1, ENC_LITTLE_ENDIAN, &background);
                offset += 1;

                proto_tree_add_item_ret_uint(tree,
                    hf_isobus_vt_graphicscontext_drawtext_numberofbytes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &number_of_bytes);
                offset += 1;

                firstTwoBytesString = tvb_get_letohs(tvb,offset);
                if(firstTwoBytesString == 0xFEFF)
                {
                    encoding = ENC_UCS_2|ENC_BIG_ENDIAN;
                    bomOffset = 2;
                }

                proto_tree_add_item_ret_string(tree,
                    hf_isobus_vt_graphicscontext_drawtext_textstring, tvb, offset + bomOffset, number_of_bytes - bomOffset, encoding, wmem_packet_scope(), &value);

                col_append_fstr(pinfo->cinfo, COL_INFO, "Draw string \"%s\" at cursor with a %s background",
                    value, val_to_str(background, draw_text_background, "unknown"));
            }
                break;
            case PAN_VIEWPORT:
            {
                gint32 viewport_x, viewport_y;

                proto_tree_add_item_ret_int(tree,
                    hf_isobus_vt_graphicscontext_panviewport_viewportx, tvb, offset, 2, ENC_LITTLE_ENDIAN, &viewport_x);
                offset += 2;

                proto_tree_add_item_ret_int(tree,
                    hf_isobus_vt_graphicscontext_panviewport_viewporty, tvb, offset, 2, ENC_LITTLE_ENDIAN, &viewport_y);

                col_append_fstr(pinfo->cinfo, COL_INFO, "Pan Viewport by [%d;%d] pixels",
                    viewport_x, viewport_y);
            }
                break;
            case ZOOM_VIEWPORT:
            {
                gfloat zoom_value;

                zoom_value = tvb_get_ieee_float(tvb, offset, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(tree,
                    hf_isobus_vt_graphicscontext_zoomviewport_zoomvalue, tvb, offset, 4, ENC_LITTLE_ENDIAN);

                col_append_fstr(pinfo->cinfo, COL_INFO, "Zoom Viewport by %g",
                    zoom_value);
            }
                break;
            case PAN_AND_ZOOM_VIEWPORT:
            {
                gfloat zoom_value;
                gint32 viewport_x, viewport_y;

                proto_tree_add_item_ret_int(tree,
                    hf_isobus_vt_graphicscontext_panandzoomviewport_viewportx, tvb, offset, 2, ENC_LITTLE_ENDIAN, &viewport_x);
                offset += 2;

                proto_tree_add_item_ret_int(tree,
                    hf_isobus_vt_graphicscontext_panandzoomviewport_viewporty, tvb, offset, 2, ENC_LITTLE_ENDIAN, &viewport_y);
                offset += 2;

                zoom_value = tvb_get_ieee_float(tvb, offset, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(tree,
                    hf_isobus_vt_graphicscontext_panandzoomviewport_zoomvalue, tvb, offset, 2, ENC_LITTLE_ENDIAN);

                col_append_fstr(pinfo->cinfo, COL_INFO, "Pan viewport by [%d;%d] pixels and zoom by %g",
                    viewport_x, viewport_y, zoom_value);
            }
                break;
            case CHANGE_VIEWPORT_SIZE:
            {
                guint32 new_width, new_height;

                proto_tree_add_item_ret_uint(tree,
                    hf_isobus_vt_graphicscontext_changeviewportsize_newwidth, tvb, offset, 2, ENC_LITTLE_ENDIAN, &new_width);
                offset += 2;

                proto_tree_add_item_ret_uint(tree,
                    hf_isobus_vt_graphicscontext_changeviewportsize_newheight, tvb, offset, 2, ENC_LITTLE_ENDIAN, &new_height);

                col_append_fstr(pinfo->cinfo, COL_INFO, "Change viewport size to [%ux%u]",
                    new_width, new_height);
            }
                break;
            case DRAW_VT_OBJECT:
            {
                guint32 draw_object_id;

                proto_tree_add_item_ret_uint(tree,
                    hf_isobus_vt_graphicscontext_drawvtobject_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &draw_object_id);
                ti = proto_tree_add_item(tree,
                    hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_item_set_hidden(ti);

                col_append_fstr(pinfo->cinfo, COL_INFO, "Draw VT %s at graphics cursor",
                    get_object_id_string(draw_object_id));
            }
                break;
            case COPY_CANVAS_TO_PICTURE_GRAPHIC:
            {
                guint32 object_id_picture_graphic;

                proto_tree_add_item_ret_uint(tree,
                    hf_isobus_vt_graphicscontext_copycanvastopicturegraphic_objectidpicturegraphic, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id_picture_graphic);
                ti = proto_tree_add_item(tree,
                    hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_item_set_hidden(ti);

                col_append_fstr(pinfo->cinfo, COL_INFO, "Copy canvas to picture graphics %s",
                    get_object_id_string(object_id_picture_graphic));
            }
                break;
            case COPY_VIEWPORT_TO_PICTURE_GRAPHIC:
            {
                guint32 object_id_picture_graphic;

                proto_tree_add_item_ret_uint(tree,
                    hf_isobus_vt_graphicscontext_copyviewporttopicturegraphic_objectidpicturegraphic, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id_picture_graphic);
                ti = proto_tree_add_item(tree,
                    hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_item_set_hidden(ti);

                col_append_fstr(pinfo->cinfo, COL_INFO, "Copy viewport to picture graphics %s",
                    get_object_id_string(object_id_picture_graphic));
            }
                break;
        }
    }
        break;
    case VT_GET_ATTRIBUTE_VALUE:
    {
        gboolean error_frame;
        guint32 attribute_id, object_id;

        object_id = tvb_get_letohs(tvb, offset);
        if(direction == ecu_to_vt || object_id != 0xFFFF)
        {
            error_frame = FALSE;
            proto_tree_add_item(tree,
                hf_isobus_vt_getattributevalue_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            ti = proto_tree_add_item(tree,
                hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_set_hidden(ti);
        }
        else
        {
            error_frame = TRUE;
        }
        offset += 2;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_getattributevalue_attributeid, tvb, offset, 1, ENC_LITTLE_ENDIAN, &attribute_id);
        offset += 1;

        if(direction == vt_to_ecu)
        {
            if(error_frame == FALSE)
            {
                guint32 value;
                proto_tree_add_item_ret_uint(tree,
                    hf_isobus_vt_getattributevalue_value, tvb, offset, 4, ENC_LITTLE_ENDIAN, &value);

                col_append_fstr(pinfo->cinfo, COL_INFO, "Return value of attribute %u from %s, value is 0x%X ",
                    attribute_id, get_object_id_string(object_id), value);
            }
            else
            {
                guint32 error_codes;

                proto_tree_add_item_ret_uint(tree,
                    hf_isobus_vt_getattributevalue_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
                ti = proto_tree_add_item(tree,
                    hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_item_set_hidden(ti);
                offset += 2;

                ti = proto_tree_add_item_ret_uint(tree,
                    hf_isobus_vt_getattributevalue_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
                proto_item_append_text(ti, ": ");
                if (error_codes & 0x01)
                    proto_item_append_text(ti, "Invalid Object ID ");
                if (error_codes & 0x02)
                    proto_item_append_text(ti, "Invalid Attribute ID ");
                if (error_codes & 0x10)
                    proto_item_append_text(ti, "Any other error ");

                col_append_fstr(pinfo->cinfo, COL_INFO, "Error while requesting value of attribute %u from %s ",
                    attribute_id, get_object_id_string(object_id));
            }
        }
        else
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Get value of attribute %u from %s ",
                attribute_id, get_object_id_string(object_id));
        }
    }
        break;
    case VT_SELECT_COLOUR_MAP:
    {
        guint32 error_codes, object_id;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_selectcolourmap_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        if(direction == vt_to_ecu)
        {
            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_selectcolourmap_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "Invalid Object ID ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Invalid Colour Map ");
            if (error_codes & 0x04)
                proto_item_append_text(ti, "Any other error ");
        }

        if(direction == ecu_to_vt)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Select colour map %s ",
                get_object_id_string(object_id));
        }
        else if(direction == vt_to_ecu)
        {
            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Error while selecting colour map %s ",
                    get_object_id_string(object_id));
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Colour map %s successfully selected ",
                    get_object_id_string(object_id));
            }
        }
    }
        break;
    case VT_IDENTIFY_VT:
    {
        if(direction == ecu_to_vt)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Identify VT");
        }
        else
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Reply Identify VT ");
        }
    }
        break;
    case VT_EXECUTE_EXTENDED_MACRO:
    {
        guint32 error_codes, object_id;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_executeextendedmacro_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        if(direction == vt_to_ecu)
        {
            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_executeextendedmacro_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "Object ID does not exist ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Object ID is not a Macro object ");
            if (error_codes & 0x04)
                proto_item_append_text(ti, "Any other error ");
        }

        if(direction == ecu_to_vt)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Execute extended macro %s ",
                get_object_id_string(object_id));
        }
        else if(direction == vt_to_ecu)
        {
            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Error while executing extended macro %s ",
                    get_object_id_string(object_id));
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Extended macro %s successfully executed ",
                    get_object_id_string(object_id));
            }
        }
    }
        break;
    case VT_LOCK_UNLOCK_MASK:
    {
        guint32 command, error_codes, object_id, lock_timeout;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_lockunlockmask_command, tvb, offset, 1, ENC_LITTLE_ENDIAN, &command);
        offset += 1;

        if(direction == ecu_to_vt)
        {
            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_lockunlockmask_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id);
            ti = proto_tree_add_item(tree,
                hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_set_hidden(ti);
            offset += 2;

            if(command == MASK_LOCK)
            {
                proto_tree_add_item_ret_uint(tree,
                    hf_isobus_vt_lockunlockmask_locktimeout, tvb, offset, 2, ENC_LITTLE_ENDIAN, &lock_timeout);
            }
        }
        else
        {
            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_lockunlockmask_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "Command ignored, no mask is visible or given Object ID does not match the visible mask ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Lock command ignored, already locked ");
            if (error_codes & 0x04)
                proto_item_append_text(ti, "Unlock command ignored, not locked ");
            if (error_codes & 0x08)
                proto_item_append_text(ti, "Lock command ignored, an Alarm Mask is active ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "Unsolicited unlock, timeout occurred ");
            if (error_codes & 0x20)
                proto_item_append_text(ti, "Unsolicited unlock, this mask is hidden ");
            if (error_codes & 0x40)
                proto_item_append_text(ti, "Unsolicited unlock, operator induced, or any other error ");
            if (error_codes & 0x80)
                proto_item_append_text(ti, "Any other error ");
        }

        if(direction == ecu_to_vt)
        {
            if(command == MASK_LOCK)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Lock data mask %s for %ums ",
                    get_object_id_string(object_id), lock_timeout);
            }
            else if(command == MASK_UNLOCK)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Unlock data mask %s ",
                    get_object_id_string(object_id));
            }
        }
        else if(direction == vt_to_ecu)
        {
            if(error_codes)
            {
                if(command == MASK_LOCK)
                {
                    col_append_fstr(pinfo->cinfo, COL_INFO, "Error while locking ");
                }
                else if(command == MASK_UNLOCK)
                {
                    col_append_fstr(pinfo->cinfo, COL_INFO, "Error while unlocking ");
                }
            }
            else
            {
                if(command == MASK_LOCK)
                {
                    col_append_fstr(pinfo->cinfo, COL_INFO, "Locking successful ");
                }
                else if(command == MASK_UNLOCK)
                {
                    col_append_fstr(pinfo->cinfo, COL_INFO, "Unlocking successful ");
                }
            }
        }
    }
        break;
    case VT_EXECUTE_MACRO:
    {
        guint32 object_id;
        guint32 error_codes;

        /* Other than all object IDs macro object IDs are 1 byte in VT 4 */
        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_executemacro_objectid, tvb, offset, 1, ENC_LITTLE_ENDIAN, &object_id);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 1;

        if(direction == vt_to_ecu)
        {
            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_executemacro_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "Object ID does not exist ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Object ID is not a Macro object ");
            if (error_codes & 0x04)
                proto_item_append_text(ti, "Any other error ");
        }

        if(direction == ecu_to_vt)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Execute macro %s ",
                get_object_id_string(object_id));
        }
        else if(direction == vt_to_ecu)
        {
            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Error while executing macro %s ",
                    get_object_id_string(object_id));
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Macro %s successfully executed ",
                    get_object_id_string(object_id));
            }
        }
    }
        break;
    case VT_GET_MEMORY:
    {
        if(direction == ecu_to_vt)
        {
            guint32 memory_required;
            offset += 1; /* reserved byte */

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_getmemory_memoryrequired, tvb, offset, 4, ENC_LITTLE_ENDIAN, &memory_required);

            col_append_fstr(pinfo->cinfo, COL_INFO, "The amount of memory required is %u ",
                memory_required);
        }
        else
        {
            guint32 vt_version, status;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_getmemory_vtversion, tvb, offset, 1, ENC_LITTLE_ENDIAN, &vt_version);
            offset += 1;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_getmemory_status, tvb, offset, 1, ENC_LITTLE_ENDIAN, &status);

            if(status == ENOUGH_MEMORY)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "There can be enough memory, VT Version is %u ",
                    vt_version);
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "There is not enough memory available, VT Version is %u ",
                    vt_version);
            }
        }
    }
        break;
    case VT_GET_SUPPORTED_WIDECHARS:
    {
        guint32 code_plane, first_widechar, last_widechar;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_getsupportedwidechars_codeplane, tvb, offset, 1, ENC_LITTLE_ENDIAN, &code_plane);
        offset += 1;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_getsupportedwidechars_firstwidechar, tvb, offset, 2, ENC_LITTLE_ENDIAN, &first_widechar);
        offset += 2;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_getsupportedwidechars_lastwidechar, tvb, offset, 2, ENC_LITTLE_ENDIAN, &last_widechar);
        offset += 2;

        if(direction == vt_to_ecu)
        {
            guint32 error_codes, number_of_ranges, i;

            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_getsupportedwidechars_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "Too many ranges ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Error in Code plane ");
            if (error_codes & 0x10)
                proto_item_append_text(ti, "Any other error ");
            offset += 1;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_getsupportedwidechars_numberofranges, tvb, offset, 1, ENC_LITTLE_ENDIAN, &number_of_ranges);
            offset += 1;

            for(i = 0; i < number_of_ranges; i++)
            {
                guint32 first_avail_widechar, last_avail_widechar;
                proto_tree* subtree;
                proto_item* item;

                subtree = proto_tree_add_subtree_format(tree,
                    tvb, offset, 4, ett_isobus_vt_getsupportedwidechars_range, &item, "Range");

                proto_tree_add_item_ret_uint(subtree,
                    hf_isobus_vt_getsupportedwidechars_firstavailablewidechar, tvb, offset, 2, ENC_LITTLE_ENDIAN, &first_avail_widechar);
                offset += 2;

                proto_tree_add_item_ret_uint(subtree,
                    hf_isobus_vt_getsupportedwidechars_lastavailablewidechar, tvb, offset, 2, ENC_LITTLE_ENDIAN, &last_avail_widechar);
                offset += 2;

                proto_item_set_text(item, "Range 0x%04X - 0x%04X", first_avail_widechar, last_avail_widechar);
            }

            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Error while getting supported widechars for code plane %u ",
                    code_plane);
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Received supported widechars for code plane %u in %u range",
                    code_plane, number_of_ranges);

                if(number_of_ranges > 1)
                {
                    col_append_fstr(pinfo->cinfo, COL_INFO, "s");
                }
            }
        }
        else if(direction == ecu_to_vt)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Requesting supported widechars for code plane %u from character 0x%04X till 0x%04X ",
                    code_plane, first_widechar, last_widechar);
        }
    }
        break;
    case VT_GET_NUMBER_OF_SOFT_KEYS:
    {
        if(direction == ecu_to_vt)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Requesting number of soft keys");
        }
        else
        {
            guint32 navigation_soft_keys, virtual_soft_keys, physical_soft_keys;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_getnumberofsoftkeys_navigationsoftkeys, tvb, offset, 1, ENC_LITTLE_ENDIAN, &navigation_soft_keys);
            offset += 1;

            offset += 2; /* 2 reserved bytes */

            proto_tree_add_item(tree,
                hf_isobus_vt_getnumberofsoftkeys_xdots, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            proto_tree_add_item(tree,
                hf_isobus_vt_getnumberofsoftkeys_ydots, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_getnumberofsoftkeys_virtualsoftkeys, tvb, offset, 1, ENC_LITTLE_ENDIAN, &virtual_soft_keys);
            offset += 1;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_getnumberofsoftkeys_physicalsoftkeys, tvb, offset, 1, ENC_LITTLE_ENDIAN, &physical_soft_keys);

            col_append_fstr(pinfo->cinfo, COL_INFO, "VT has %u softkeys, %u virtual soft keys and %u physical soft keys",
                navigation_soft_keys, virtual_soft_keys, physical_soft_keys);
        }
    }
        break;
    case VT_GET_TEXT_FONT_DATA:
    {
        if(direction == ecu_to_vt)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Requesting text font data");
        }
        else if(direction == vt_to_ecu)
        {
            proto_tree *ti_smallfonts_subtree, *ti_largefonts_subtree, *ti_typeattribute_subtree;
            proto_item *smallfonts_item, *largefonts_item, *typeattributes_item;

            offset += 4;

            smallfonts_item = proto_tree_add_item(tree,
                hf_isobus_vt_gettextfontdata_smallfontsizes, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            ti_smallfonts_subtree = proto_item_add_subtree(smallfonts_item, ett_isobus_vt_gettextfontdata_smallfontsizes);
            proto_tree_add_item(ti_smallfonts_subtree, hf_isobus_vt_gettextfontdata_smallfontsizes_font8x8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_smallfonts_subtree, hf_isobus_vt_gettextfontdata_smallfontsizes_font8x12, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_smallfonts_subtree, hf_isobus_vt_gettextfontdata_smallfontsizes_font12x16, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_smallfonts_subtree, hf_isobus_vt_gettextfontdata_smallfontsizes_font16x16, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_smallfonts_subtree, hf_isobus_vt_gettextfontdata_smallfontsizes_font16x24, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_smallfonts_subtree, hf_isobus_vt_gettextfontdata_smallfontsizes_font24x32, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_smallfonts_subtree, hf_isobus_vt_gettextfontdata_smallfontsizes_font32x32, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            largefonts_item = proto_tree_add_item(tree,
                hf_isobus_vt_gettextfontdata_largefontsizes, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            ti_largefonts_subtree = proto_item_add_subtree(largefonts_item, ett_isobus_vt_gettextfontdata_largefontsizes);
            proto_tree_add_item(ti_largefonts_subtree, hf_isobus_vt_gettextfontdata_largefontsizes_font32x48, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_largefonts_subtree, hf_isobus_vt_gettextfontdata_largefontsizes_font48x64, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_largefonts_subtree, hf_isobus_vt_gettextfontdata_largefontsizes_font64x64, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_largefonts_subtree, hf_isobus_vt_gettextfontdata_largefontsizes_font64x96, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_largefonts_subtree, hf_isobus_vt_gettextfontdata_largefontsizes_font96x128, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_largefonts_subtree, hf_isobus_vt_gettextfontdata_largefontsizes_font128x128, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_largefonts_subtree, hf_isobus_vt_gettextfontdata_largefontsizes_font128x192, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            typeattributes_item = proto_tree_add_item(tree,
                hf_isobus_vt_gettextfontdata_typeattributes, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            ti_typeattribute_subtree = proto_item_add_subtree(typeattributes_item, ett_isobus_vt_gettextfontdata_typeattributes);
            proto_tree_add_item(ti_typeattribute_subtree, hf_isobus_vt_gettextfontdata_typeattributes_boldtext, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_typeattribute_subtree, hf_isobus_vt_gettextfontdata_typeattributes_crossedouttext, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_typeattribute_subtree, hf_isobus_vt_gettextfontdata_typeattributes_underlinedtext, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_typeattribute_subtree, hf_isobus_vt_gettextfontdata_typeattributes_italicstext, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_typeattribute_subtree, hf_isobus_vt_gettextfontdata_typeattributes_invertedtext, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_typeattribute_subtree, hf_isobus_vt_gettextfontdata_typeattributes_flashinverted, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_typeattribute_subtree, hf_isobus_vt_gettextfontdata_typeattributes_flashhidden, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_typeattribute_subtree, hf_isobus_vt_gettextfontdata_typeattributes_proportionalfontrendering, tvb, offset, 1, ENC_LITTLE_ENDIAN);

            col_append_fstr(pinfo->cinfo, COL_INFO, "Text font data received");
        }
    }
        break;
    case VT_GET_WINDOW_MASK_DATA:
    {
        if(direction == ecu_to_vt)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Request window mask data");
        }
        else
        {
            guint32 background_colour_data_mask, background_colour_soft_key_mask;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_getwindowmaskdata_backgroundcolourdatamask, tvb, offset, 1, ENC_LITTLE_ENDIAN, &background_colour_data_mask);
            offset += 1;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_getwindowmaskdata_backgroundcoloursoftkeymask, tvb, offset, 1, ENC_LITTLE_ENDIAN, &background_colour_soft_key_mask);

            col_append_fstr(pinfo->cinfo, COL_INFO, "Background colour of data mask is %s, soft key mask is %s",
                rval_to_str(background_colour_data_mask, vt_colours, "Unknown"),
                rval_to_str(background_colour_soft_key_mask, vt_colours, "Unknown"));
        }
    }
        break;
    case VT_GET_SUPPORTED_OBJECTS:
    {
        if(direction == ecu_to_vt)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Request supported objects");
        }
        else
        {
            guint32 number_of_bytes, i;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_getsupportedobjects_numberofbytes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &number_of_bytes);
            offset += 1;

            for(i = 0; i < number_of_bytes; i++)
            {
                guint8 object_type;

                object_type = tvb_get_guint8(tvb, offset);
                if(object_type == 0xFF)
                {
                    break;
                }

                proto_tree_add_item(tree,
                    hf_isobus_vt_getsupportedobjects_objecttype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;
            }

            col_append_fstr(pinfo->cinfo, COL_INFO, "Supported objects received");
        }
    }
        break;
    case VT_GET_HARDWARE:
    {
        if(direction == ecu_to_vt)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Request hardware info");
        }
        else
        {
            guint32 graphic_type, x_pixels, y_pixels;
            proto_item *hardware_item;
            proto_tree *hardware_subtree;

            proto_tree_add_item(tree,
                hf_isobus_vt_gethardware_boottime, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_gethardware_graphictype, tvb, offset, 1, ENC_LITTLE_ENDIAN, &graphic_type);
            offset += 1;

            hardware_item = proto_tree_add_item(tree,
                hf_isobus_vt_gethardware_hardware, tvb, offset, 1, ENC_LITTLE_ENDIAN);

            hardware_subtree = proto_item_add_subtree(hardware_item, ett_isobus_vt_gethardware_hardware);
            proto_tree_add_item(hardware_subtree, hf_isobus_vt_gethardware_hardware_touchscreen, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(hardware_subtree, hf_isobus_vt_gethardware_hardware_pointingdevice, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(hardware_subtree, hf_isobus_vt_gethardware_hardware_multifreqaudiooutput, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(hardware_subtree, hf_isobus_vt_gethardware_hardware_adjustvolumeaudiooutput, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(hardware_subtree, hf_isobus_vt_gethardware_hardware_simultaneousactivationphysicalsoftkeys, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(hardware_subtree, hf_isobus_vt_gethardware_hardware_simultaneousactivationbuttons, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(hardware_subtree, hf_isobus_vt_gethardware_hardware_dragoperation, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(hardware_subtree, hf_isobus_vt_gethardware_hardware_intermediatecoordinatesdrag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_gethardware_xpixels, tvb, offset, 2, ENC_LITTLE_ENDIAN, &x_pixels);
            offset += 2;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_gethardware_ypixels, tvb, offset, 2, ENC_LITTLE_ENDIAN, &y_pixels);

            col_append_fstr(pinfo->cinfo, COL_INFO, "Hardware info received. Graphic type is %s, screen is %u by %u pixels",
                val_to_str(graphic_type, graphic_types, "unknown"), x_pixels, y_pixels);
        }
    }
        break;
    case VT_STORE_VERSION:
    {
        if(direction == ecu_to_vt)
        {
            const guint8 *version_label;

            proto_tree_add_item_ret_string(tree,
                hf_isobus_vt_storeversion_versionlabel, tvb, offset, 7, ENC_ASCII|ENC_NA, wmem_packet_scope(), &version_label);

            col_append_fstr(pinfo->cinfo, COL_INFO, "Store version under label %s", version_label);
        }
        else
        {
            guint32 error_codes;
            offset += 4;

            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_storeversion_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Version label is not correct ");
            if (error_codes & 0x04)
                proto_item_append_text(ti, "Insufficient memory available ");
            if (error_codes & 0x08)
                proto_item_append_text(ti, "Any other error ");

            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Error while storing version");
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Version successfully stored");
            }
        }
    }
        break;
    case VT_LOAD_VERSION:
    {
        if(direction == ecu_to_vt)
        {
            const guint8* version_label;

            proto_tree_add_item_ret_string(tree,
                hf_isobus_vt_loadversion_versionlabel, tvb, offset, 7, ENC_ASCII|ENC_NA, wmem_packet_scope(), &version_label);

            col_append_fstr(pinfo->cinfo, COL_INFO, "Load version stored under label \"%s\"", version_label);
        }
        else
        {
            guint32 error_codes;
            offset += 4;

            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_loadversion_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "File system error or pool data corruption ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Version label is not correct or Version label unknown ");
            if (error_codes & 0x04)
                proto_item_append_text(ti, "Insufficient memory available ");
            if (error_codes & 0x08)
                proto_item_append_text(ti, "Any other error ");

            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Error while loading version");
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Version successfully loaded");
            }
        }
    }
        break;
    case VT_DELETE_VERSION:
    {
        if(direction == ecu_to_vt)
        {
            const guint8* version_label;

            proto_tree_add_item_ret_string(tree,
                hf_isobus_vt_deleteversion_versionlabel, tvb, offset, 7, ENC_ASCII|ENC_NA, wmem_packet_scope(), &version_label);

            col_append_fstr(pinfo->cinfo, COL_INFO, "Delete version stored under label \"%s\"", version_label);
        }
        else
        {
            guint32 error_codes;
            offset += 4;

            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_deleteversion_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Version label is not correct or Version label unknown ");
            if (error_codes & 0x08)
                proto_item_append_text(ti, "Any other error ");

            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Error while deleting version");
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Version successfully deleted");
            }
        }
    }
        break;
    case VT_EXTENDED_GET_VERSIONS:
    {
        if(direction == ecu_to_vt)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Request a list of extended versions");
        }
        else
        {
            guint32 number_of_versions, i;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_extendedgetversions_numberofversions, tvb, offset, 1, ENC_LITTLE_ENDIAN, &number_of_versions);
            offset += 1;

            for(i = 0; i < number_of_versions; i++)
            {
                proto_tree_add_item(tree,
                    hf_isobus_vt_extendedgetversions_versionlabel, tvb, offset, 32, ENC_ASCII|ENC_NA);
                offset += 32;
            }

            col_append_fstr(pinfo->cinfo, COL_INFO, "Extended versions received");
        }
    }
        break;
    case VT_EXTENDED_STORE_VERSION:
    {
        if(direction == ecu_to_vt)
        {
            const guint8* version_label;

            proto_tree_add_item_ret_string(tree,
                hf_isobus_vt_extendedstoreversion_versionlabel, tvb, offset, 32, ENC_ASCII|ENC_NA, wmem_packet_scope(), &version_label);

            col_append_fstr(pinfo->cinfo, COL_INFO, "Store extended version under label \"%s\"", version_label);
        }
        else
        {
            guint32 error_codes;
            offset += 4;

            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_extendedstoreversion_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Version label is not correct ");
            if (error_codes & 0x04)
                proto_item_append_text(ti, "Insufficient memory available ");
            if (error_codes & 0x08)
                proto_item_append_text(ti, "Any other error ");

            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Error while storing extended version");
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Extended version successfully stored");
            }
        }
    }
        break;
    case VT_EXTENDED_LOAD_VERSION:
    {
        if(direction == ecu_to_vt)
        {
            const guint8* version_label;

            proto_tree_add_item_ret_string(tree,
                hf_isobus_vt_extendedloadversion_versionlabel, tvb, offset, 32, ENC_ASCII|ENC_NA, wmem_packet_scope(), &version_label);

            col_append_fstr(pinfo->cinfo, COL_INFO, "Store extended version under label \"%s\"", version_label);
        }
        else
        {
            guint32 error_codes;
            offset += 4;

            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_extendedloadversion_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x01)
                proto_item_append_text(ti, "File system error or pool data corruption ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Version label is not correct or Version label unknown ");
            if (error_codes & 0x04)
                proto_item_append_text(ti, "Insufficient memory available ");
            if (error_codes & 0x08)
                proto_item_append_text(ti, "Any other error ");

            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Error while loading extended version");
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Extended version successfully loaded");
            }
        }
    }
        break;
    case VT_EXTENDED_DELETE_VERSION:
    {
        if(direction == ecu_to_vt)
        {
            const guint8* version_label;

            proto_tree_add_item_ret_string(tree,
                hf_isobus_vt_extendeddeleteversion_versionlabel, tvb, offset, 32, ENC_ASCII|ENC_NA, wmem_packet_scope(), &version_label);

            col_append_fstr(pinfo->cinfo, COL_INFO, "Delete version stored under label %s", version_label);
        }
        else
        {
            guint32 error_codes;
            offset += 4;

            ti = proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_extendeddeleteversion_errorcodes, tvb, offset, 1, ENC_LITTLE_ENDIAN, &error_codes);
            proto_item_append_text(ti, ": ");
            if (error_codes & 0x02)
                proto_item_append_text(ti, "Version label is not correct or Version label unknown ");
            if (error_codes & 0x08)
                proto_item_append_text(ti, "Any other error ");

            if(error_codes)
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Error while deleting extended version");
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, "Extended version successfully deleted");
            }
        }
    }
        break;
    case VT_GET_VERSIONS_MESSAGE:
    {
        if(direction == ecu_to_vt)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Extended version successfully deleted");
        }
        /*no else as this message can only be used from ecu to vt*/
    }
        break;
    case VT_GET_VERSIONS_RESPONSE:
    {
        if(direction == vt_to_ecu)
        {
            guint32 number_of_versions, i;

            proto_tree_add_item_ret_uint(tree,
                hf_isobus_vt_getversions_numberofversions, tvb, offset, 1, ENC_LITTLE_ENDIAN, &number_of_versions);
            offset += 1;

            for(i = 0; i < number_of_versions; i++)
            {
                proto_tree_add_item(tree,
                    hf_isobus_vt_getversions_versionlabel, tvb, offset, 7, ENC_ASCII|ENC_NA);
                offset += 7;
            }

            col_append_fstr(pinfo->cinfo, COL_INFO, "Versions received");
        }
        /*no else as this message can only be used from vt to ecu*/
    }
        break;
    case VT_UNSUPPORTED_VT_FUNCTION:
    {
        guint32 unsupported_vt_function;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_unsupportedvtfunction_unsupportedvtfunction, tvb, offset, 1, ENC_LITTLE_ENDIAN, &unsupported_vt_function);

        if(direction == ecu_to_vt)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "VT function %s (%u) is not supported by ECU",
                val_to_str_ext(unsupported_vt_function, &vt_function_code_ext, "unknown"), unsupported_vt_function);
        }
        else
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "VT function %s (%u) is not supported by VT",
                val_to_str_ext(unsupported_vt_function, &vt_function_code_ext, "unknown"), unsupported_vt_function);
        }
    }
        break;
    case VT_VT_STATUS:
    {
        proto_tree *ti_busycodes_subtree;
        proto_item *busycodes_item;
        guint32 working_set_master, object_id_data_mask, object_id_soft_key_mask;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_vtstatus_workingsetmaster, tvb, offset, 1, ENC_LITTLE_ENDIAN, &working_set_master);
        offset += 1;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_vtstatus_objectiddatamask, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id_data_mask);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        proto_tree_add_item_ret_uint(tree,
            hf_isobus_vt_vtstatus_objectidsoftkeymask, tvb, offset, 2, ENC_LITTLE_ENDIAN, &object_id_soft_key_mask);
        ti = proto_tree_add_item(tree,
            hf_isobus_vt_objectid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_item_set_hidden(ti);
        offset += 2;

        busycodes_item = proto_tree_add_item(tree,
            hf_isobus_vt_vtstatus_vtbusycodes, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        ti_busycodes_subtree = proto_item_add_subtree(busycodes_item, ett_isobus_vt_vtstatus_busycodes_subtree);
        proto_tree_add_item(ti_busycodes_subtree, hf_isobus_vt_vtstatus_vtbusycodes_updatingvisiblemask, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ti_busycodes_subtree, hf_isobus_vt_vtstatus_vtbusycodes_savingdata, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ti_busycodes_subtree, hf_isobus_vt_vtstatus_vtbusycodes_executingcommand, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ti_busycodes_subtree, hf_isobus_vt_vtstatus_vtbusycodes_executingmacro, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ti_busycodes_subtree, hf_isobus_vt_vtstatus_vtbusycodes_parsingobjectpool, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ti_busycodes_subtree, hf_isobus_vt_vtstatus_vtbusycodes_auxcontrolsactive, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ti_busycodes_subtree, hf_isobus_vt_vtstatus_vtbusycodes_outofmemory, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        proto_tree_add_item(tree,
            hf_isobus_vt_vtstatus_vtfunctioncodes, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        col_append_fstr(pinfo->cinfo, COL_INFO, "Status: Current master is %d data mask is %s soft key mask is %s",
        working_set_master, get_object_id_string(object_id_data_mask), get_object_id_string(object_id_soft_key_mask));
    }
        break;
    case VT_WORKING_SET_MAINTENANCE:
    {
        guint8 bitmask = tvb_get_guint8(tvb, offset);
        guint8 version = tvb_get_guint8(tvb, offset + 1);
        if(version == 0xFF)
        {
            version = 2;
        }
        if(version > 3)
        {
            proto_tree_add_item(tree,
                hf_isobus_vt_wrksetmain_bitmask, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        }
        offset += 1;

        proto_tree_add_item(tree,
            hf_isobus_vt_wrksetmain_version, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        if(version > 3 && bitmask & 0x80)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Initiate ");
        }
        col_append_fstr(pinfo->cinfo, COL_INFO, "Working Set Maintenance, VT version is %d",
            version);

        current_vt_version = version;
    }
        break;
    }
	return tvb_captured_length(tvb);
}

static int
dissect_vt_to_ecu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    (void)data;
    return dissect_vt(tvb, pinfo, tree, vt_to_ecu);
}

static int
dissect_ecu_to_vt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    (void)data;
    return dissect_vt(tvb, pinfo, tree, ecu_to_vt);
}

/*
 * Simple "get a line" routine, copied from giop dissector who copied it from somewhere :)
 *
 */

static int vt_getline(FILE *fp, gchar *line, int maxlen)
{
    if (fgets(line, maxlen, fp) == NULL)
    {
        return 0;
    }
    else
    {
        line[strcspn(line, "\n")] = '\0';
        return (int)strlen(line);
    }
}


static void read_object_id_file(void)
{
    gchar   buf[500];
    guint16 item_count = 0;
    FILE     *file;

    if ((file = ws_fopen(object_id_translation, "r")) == NULL)
    {
        object_id_strings[0].value = 0;
        object_id_strings[0].strptr = NULL;

        return;
    }

    while ((vt_getline(file, buf, 500)) > 0)
    {
        gchar **split_string = g_strsplit(buf, ",", 2);

        object_id_strings[item_count].value = (guint32)g_ascii_strtoll(split_string[0], NULL, 10);
        object_id_strings[item_count].strptr = wmem_strdup(wmem_epan_scope(), split_string[1]);

        g_strfreev(split_string);
        item_count++;
    }

    fclose(file);

    object_id_strings[item_count].value = 0;
    object_id_strings[item_count].strptr = NULL;
}

static void isobus_vt_init(void)
{
    read_object_id_file();
}

/* Register the protocol with Wireshark */
void
proto_register_isobus_vt(void)
{
    static hf_register_info hf[] = {
        { &hf_isobus_vt,
          { "VT",                       "isobus.vt",
            FT_PROTOCOL, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_command,
          { "Command",                  "isobus.vt.command",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &vt_function_code_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_objectid,
          { "Object ID",                "isobus.vt.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_softkey_keyactcode,
          { "Activation Code",          "isobus.vt.soft_key.act_code",
            FT_UINT8, BASE_DEC, VALS(key_activation_codes), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_softkey_objectid,
          { "Object ID",                "isobus.vt.soft_key.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_softkey_parentobjectid,
          { "Parent Object ID",         "isobus.vt.soft_key.parent_object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_softkey_keynumber,
          { "Key Number",               "isobus.vt.soft_key.key_number",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_button_keyactcode,
          { "Activation Code",          "isobus.vt.button.act_code",
            FT_UINT8, BASE_DEC, VALS(button_activation_codes), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_button_objectid,
          { "Object ID",                "isobus.vt.button.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_button_parentobjectid,
          { "Parent Object ID",         "isobus.vt.button.parent_object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_button_keynumber,
          { "Key Number",               "isobus.vt.button.key_number",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_pointing_xposition,
          { "X Position",               "isobus.vt.pointing_event.x_position",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_pointing_yposition,
          { "Y Position",               "isobus.vt.pointing_event.y_position",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_pointing_touchstate,
          { "Touch State",              "isobus.vt.pointing_event.touch_state",
            FT_UINT8, BASE_DEC, VALS(pointing_touch_state), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtselectinputobject_objectid,
          { "Object ID",                "isobus.vt.vt_select_input_object.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtselectinputobject_selection,
          { "Selection",                "isobus.vt.vt_select_input_object.selection",
            FT_UINT8, BASE_DEC, VALS(selection), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtselectinputobject_openforinput,
          { "Bitmask",                  "isobus.vt.vt_select_input_object.open_for_input",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtescmessage_objectid,
          { "Object ID",                "isobus.vt.vt_esc_message.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtescmessage_errorcodes,
          { "Error Codes",              "isobus.vt.vt_esc_message.error_codes",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtchgnumval_objectid,
          { "Object ID",                "isobus.vt.vt_chg_num_val.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtchgnumval_value,
          { "Value",                    "isobus.vt.vt_chg_num_val.val",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtchgactivemask_maskobjectid,
          { "Mask Object ID",           "isobus.vt.vt_chg_active_mask.mask_object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtchgactivemask_errorcodes,
          { "Error Codes",                "isobus.vt.vt_chg_active_mask.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtchgactivemask_errorobjectid,
          { "Error Object ID",          "isobus.vt.vt_chg_active_mask.error_object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtchgactivemask_errorobjectidparent,
          { "Error Object ID Parent",   "isobus.vt.vt_chg_active_mask.error_object_id_parent",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtchgstrval_objectid,
          { "Object ID",                "isobus.vt.vt_chg_str_val.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtchgstrval_length,
          { "Length",                   "isobus.vt.vt_chg_str_val.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtchgstrval_value,
          { "Value",                    "isobus.vt.vt_chg_str_val.val",
            FT_STRING, STR_UNICODE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtonuserlayouthideshow_objectid_1,
          { "Object ID 1",                 "isobus.vt.vt_on_user_layout_hide_show.object_id_1",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtonuserlayouthideshow_status_1,
          { "Status 1",                    "isobus.vt.vt_on_user_layout_hide_show.status_1",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtonuserlayouthideshow_objectid_2,
          { "Object ID 2",                 "isobus.vt.vt_on_user_layout_hide_show.object_id_2",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtonuserlayouthideshow_status_2,
          { "Status 2",                    "isobus.vt.vt_on_user_layout_hide_show.status_2",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtcontrolaudiosignaltermination_terminationcause,
          { "Termination Cause",           "isobus.vt.vt_control_audio_signal_termination.termination_cause",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_endofobjectpool_errorcodes,
          { "Error Codes",                 "isobus.vt.end_of_object_pool.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_endofobjectpool_faultyparentobjectid,
          { "Faulty Parent Object ID",     "isobus.vt.end_of_object_pool.faulty_parent_object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_endofobjectpool_faultyobjectid,
          { "Faulty Object ID",            "isobus.vt.end_of_object_pool.faulty_object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_endofobjectpool_objectpoolerrorcodes,
          { "Object Pool Error Codes",     "isobus.vt.end_of_object_pool.object_pool_error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliaryassignmenttype1_sourceaddressauxinputdevice,
          { "Source Address Auxiliary Input Device", "isobus.vt.auxiliary_assignment_type_1.source_address_aux_input_device",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliaryassignmenttype1_auxinputnumber,
          { "Auxiliary Input Number",   "isobus.vt.auxiliary_assignment_type_1.aux_input_number",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliaryassignmenttype1_objectidauxinputdevice,
          { "Object ID of Auxiliary Function",                "isobus.vt.auxiliary_assignment_type_1.object_id_of_auxiliary_function",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliaryinputtype1status_inputnumber,
          { "Input Number",             "isobus.vt.auxiliary_input_type_1_status.input_number",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliaryinputtype1status_analyzevalue,
          { "Analyze Value",             "isobus.vt.auxiliary_input_type_1_status.analyze_value",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliaryinputtype1status_numberoftransitions,
          { "Number of transitions",     "isobus.vt.auxiliary_input_type_1_status.number_of_transitions",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliaryinputtype1status_booleanvalue,
          { "Boolean Value",             "isobus.vt.auxiliary_input_type_1_status.boolean_value",
            FT_UINT8, BASE_DEC, VALS(auxiliary_boolean_value), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_preferredassignment_numberofinputunits,
          { "Number of Input Units",             "isobus.vt.preferred_assignment.number_of_input_units",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_preferredassignment_auxinputunit_name,
          { "64-bit NAME of the Auxiliary Input Unit", "isobus.vt.preferred_assignment.auxiliary_input_unit.name",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_preferredassignment_auxinputunit_modelidentificationcode,
          { "Model Identification Code of the Auxiliary Input Unit", "isobus.vt.preferred_assignment.auxiliary_input_unit.model_identification_code",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_preferredassignment_auxinputunit_numberofpreferredfunctions,
          { "Number of Preferred Functions for this Auxiliary Input Unit", "isobus.vt.preferred_assignment.auxiliary_input_unit.number_of_preferred_functions",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_preferredassignment_auxinputunit_preferredfunctions_auxfunctionobjectid,
          { "Object ID of Auxiliary Function", "isobus.vt.preferred_assignment.auxiliary_input_unit.preferred_functions.auxiliary_function_object_id",
            FT_UINT16, BASE_HEX_DEC, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_preferredassignment_auxinputunit_preferredfunctions_auxinputobjectid,
          { "Object ID of Auxiliary Input", "isobus.vt.preferred_assignment.auxiliary_input_unit.preferred_functions.auxiliary_input_object_id",
            FT_UINT16, BASE_HEX_DEC, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_preferredassignment_errorcodes,
          { "Error Codes", "isobus.vt.preferred_assignment.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_preferredassignment_faultyauxiliaryfunctionobjectid,
          { "Faulty Auxiliary Function Object ID", "isobus.vt.preferred_assignment.faulty_auxiliary_function_object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliaryinputtype2maintenance_modelidentificationcode,
          { "Model Identification Code", "isobus.vt.auxiliary_input_type_2_maintenance.model_identification_code",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliaryinputtype2maintenance_status,
          { "Status", "isobus.vt.auxiliary_input_type_2_maintenance.status",
            FT_UINT8, BASE_DEC, VALS(auxiliary_maintenance_status), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliaryassignmenttype2_name,
          { "64-bit NAME of the Auxiliary Input Unit", "isobus.vt.auxiliary_assignment_type_2.name",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliaryassignmenttype2_flags,
          { "Flags", "isobus.vt.auxiliary_assignment_type_2.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliaryassignmenttype2_flags_preferredassignment,
          { "Preferred Assignment", "isobus.vt.auxiliary_assignment_type_2.flags.preferred_assignment",
            FT_UINT8, BASE_HEX, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliaryassignmenttype2_flags_auxiliaryfunctiontype,
          { "Auxiliary Function Type", "isobus.vt.auxiliary_assignment_type_2.flags.auxiliary_function_type",
            FT_UINT8, BASE_DEC, NULL, 0x1F,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliaryassignmenttype2_auxinputobjectid,
          { "Object ID of the Auxiliary Input", "isobus.vt.auxiliary_assignment_type_2.auxiliary_input_object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliaryassignmenttype2_auxfunctionobjectid,
          { "Object ID of Auxiliary Function", "isobus.vt.auxiliary_assignment_type_2.auxiliary_function_object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliaryassignmenttype2_errorcodes,
          { "Error Codes", "isobus.vt.auxiliary_assignment_type_2.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliaryinputstatustype2enable_auxiliaryinputobjectid,
          { "Auxiliary Input Object ID", "isobus.vt.auxiliary_input_status_type_2_enable.auxiliary_input_object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliaryinputstatustype2enable_enable,
          { "Enable", "isobus.vt.auxiliary_input_status_type_2_enable.enable",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliaryinputstatustype2enable_status,
          { "Status", "isobus.vt.auxiliary_input_status_type_2_enable.status",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliaryinputstatustype2enable_errorcodes,
          { "Error Codes", "isobus.vt.auxiliary_input_status_type_2_enable.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliaryinputtype2status_auxiliaryinputobjectid,
          { "Auxiliary Input Object ID", "isobus.vt.auxiliary_input_type_2_status.auxiliary_input_object_id",
            FT_UINT8, BASE_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliaryinputtype2status_value1,
          { "Value 1", "isobus.vt.auxiliary_input_type_2_status.value_1",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliaryinputtype2status_value2,
          { "Value 2", "isobus.vt.auxiliary_input_type_2_status.value_2",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliaryinputtype2status_operatingstate,
          { "Operating State", "isobus.vt.auxiliary_input_type_2_status.operating_state",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliaryinputtype2status_operatingstate_learnmodeactive,
          { "Operating State", "isobus.vt.auxiliary_input_type_2_status.operating_state.learn_mode_active",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliaryinputtype2status_operatingstate_inputactivatedinlearnmode,
          { "Input activated in learn mode", "isobus.vt.auxiliary_input_type_2_status.operating_state.input_activated_in_learn_mode",
            FT_UINT8, BASE_HEX, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliarycapabilities_requesttype,
          { "Request Type", "isobus.vt.auxiliary_capabilities.request_type",
            FT_UINT8, BASE_DEC, VALS(auxiliary_capabilities_request_type), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliarycapabilities_numberofauxiliaryunits,
          { "Number of Auxiliary Unit", "isobus.vt.auxiliary_capabilities.number_of_auxiliary_units",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliarycapabilities_auxiliaryunit_name,
          { "64-bit NAME of the Auxiliary Unit", "isobus.vt.auxiliary_capabilities.auxiliary_unit.name",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliarycapabilities_auxiliaryunit_numberofdifferentsets,
          { "Number of different sets for this Auxiliary Unit", "isobus.vt.auxiliary_capabilities.auxiliary_unit.number_of_different_sets",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliarycapabilities_auxiliaryunit_set_numberofinstances,
          { "Number of Instances", "isobus.vt.auxiliary_capabilities.auxiliary_unit.set.number_of_instances",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliarycapabilities_auxiliaryunit_set_functionattribute,
          { "Function attribute", "isobus.vt.auxiliary_capabilities.auxiliary_unit.set.function_attribute",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_auxiliarycapabilities_auxiliaryunit_set_assignedattribute,
          { "Assigned attribute", "isobus.vt.auxiliary_capabilities.auxiliary_unit.set.assigned_attribute",
            FT_UINT8, BASE_HEX, VALS(auxiliary_assigned_attributes), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_esc_objectid,
          { "Object ID", "isobus.vt.esc.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_esc_errorcodes,
          { "Error Codes", "isobus.vt.esc.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_hideshowobj_objectid,
          { "Object ID", "isobus.vt.hide_show_object.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_hideshowobj_action,
          { "Action", "isobus.vt.hide_show_object.action",
            FT_UINT8, BASE_DEC, VALS(vt_hide_show_action), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_hideshowobj_errorcodes,
          { "Error Codes", "isobus.vt.hide_show_object.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_enabledisableobj_objectid,
          { "Object ID", "isobus.vt.enable_disable_object.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_enabledisableobj_enabledisable,
          { "Action",                   "isobus.vt.enable_disable_object.enable_disable",
            FT_UINT8, BASE_DEC, VALS(vt_enable_disable_action), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_enabledisableobj_errorcodes,
          { "Error Codes",              "isobus.vt.enable_disable_object.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_selectinputobject_objectid,
          { "Object ID",                "isobus.vt.select_input_object.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_selectinputobject_option,
          { "Option",                "isobus.vt.select_input_object.option",
            FT_UINT8, BASE_HEX, VALS(select_input_object_option), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_selectinputobject_response,
          { "Response",                "isobus.vt.select_input_object.response",
            FT_UINT16, BASE_DEC_HEX, VALS(select_input_opject_response), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_selectinputobject_errorcodes,
          { "Object ID", "isobus.vt.select_input_object.error_codes",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_controlaudiosignal_activations,
          { "Activations", "isobus.vt.control_audio_signal.activations",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_controlaudiosignal_frequency,
          { "Frequency", "isobus.vt.control_audio_signal.frequency",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_controlaudiosignal_ontime,
          { "On-time duration", "isobus.vt.control_audio_signal.on_time",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_controlaudiosignal_offtime,
          { "Off-time duration", "isobus.vt.control_audio_signal.off_time",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_controlaudiosignal_errorcodes,
          { "Error Codes", "isobus.vt.control_audio_signal.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_setaudiovolume_volume,
          { "Volume", "isobus.vt.set_audio_volume.volume",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_setaudiovolume_errorcodes,
          { "Error Codes", "isobus.vt.set_audio_volume.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changechildlocation_parentobjectid,
          { "Parent Object ID", "isobus.vt.change_child_location.parent_object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changechildlocation_objectid,
          { "Object ID", "isobus.vt.change_child_location.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changechildlocation_relativexpos,
          { "Relative X Position", "isobus.vt.change_child_location.relative_x_position",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changechildlocation_relativeypos,
          { "Relative Y Position", "isobus.vt.change_child_location.relative_y_position",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changechildlocation_errorcodes,
          { "Errorcode", "isobus.vt.change_child_location.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changechildposition_parentobjectid,
          { "Parent Object ID", "isobus.vt.chg_child_pos.parent_object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changechildposition_objectid,
          { "Object ID", "isobus.vt.chg_child_pos.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changechildposition_xpos,
          { "Relative X Position", "isobus.vt.chg_child_pos.rel_x_pos",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changechildposition_ypos,
          { "Relative Y Position", "isobus.vt.chg_child_pos.rel_y_pos",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changechildposition_errorcodes,
          { "Error codes", "isobus.vt.chg_child_pos.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changesize_objectid,
          { "Object ID", "isobus.vt.change_size.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changesize_newwidth,
          { "New Width", "isobus.vt.change_size.new_width",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changesize_newheight,
          { "New Height", "isobus.vt.change_size.new_height",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changesize_errorcodes,
          { "Errorcode", "isobus.vt.change_size.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_chgnumval_objectid,
          { "Object ID", "isobus.vt.change_numeric_value.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_chgnumval_errorcodes,
          { "Error Codes", "isobus.vt.change_numeric_value.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_chgnumval_value,
          { "Value", "isobus.vt.change_numeric_value.val",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changeendpoint_objectid,
          { "Object ID", "isobus.vt.change_end_point.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changeendpoint_width,
          { "Width", "isobus.vt.change_end_point.width",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changeendpoint_height,
          { "Height", "isobus.vt.change_end_point.height",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changeendpoint_linedirection,
          { "Line Direction", "isobus.vt.change_end_point.line_direction",
            FT_UINT8, BASE_DEC, VALS(line_direction), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changefontattributes_objectid,
          { "Object ID", "isobus.vt.change_font_attributes.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changefontattributes_fontcolour,
          { "Font Colour", "isobus.vt.change_font_attributes.font_colour",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(vt_colours), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changefontattributes_fontsize,
          { "Font Size", "isobus.vt.change_font_attributes.font_size",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changefontattributes_fonttype,
          { "Font Type", "isobus.vt.change_font_attributes.font_type",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changefontattributes_fontstyle,
          { "Font Style", "isobus.vt.change_font_attributes.font_style",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changefontattributes_errorcodes,
          { "Error Codes", "isobus.vt.change_font_attributes.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changelineattributes_objectid,
          { "Object ID", "isobus.vt.change_line_attributes.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changelineattributes_linecolour,
          { "Line Colour", "isobus.vt.change_line_attributes.line_colour",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(vt_colours), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changelineattributes_linewidth,
          { "Line Width", "isobus.vt.change_line_attributes.line_width",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changelineattributes_lineart,
          { "Line Art", "isobus.vt.change_line_attributes.line_art",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changelineattributes_errorcodes,
          { "Error Codes", "isobus.vt.change_line_attributes.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changefillattributes_objectid,
          { "Object ID", "isobus.vt.change_fill_attributes.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changefillattributes_filltype,
          { "Fill Type", "isobus.vt.change_fill_attributes.fill_type",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(vt_colours), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changefillattributes_fillcolour,
          { "Fill Colour", "isobus.vt.change_fill_attributes.fill_colour",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changefillattributes_fillpatternobjectid,
          { "Fill Pattern Object ID", "isobus.vt.change_fill_attributes.fill_pattern_object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changefillattributes_errorcodes,
          { "Error Codes", "isobus.vt.change_fill_attributes.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changeactivemask_workingset,
          { "Working Set Object ID", "isobus.vt.chg_active_mask.working_set_object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changeactivemask_newactivemask,
          { "New Active Mask Object ID", "isobus.vt.chg_active_mask.new_active_mask_object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changeactivemask_errorcodes,
          { "Error Codes", "isobus.vt.chg_active_mask.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changesoftkeymask_masktype,
          { "Mask Type", "isobus.vt.change_soft_key_mask.mask_type",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changesoftkeymask_datamaskobjectid,
          { "Working Set Object ID", "isobus.vt.change_soft_key_mask.data_mask_object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changesoftkeymask_newsoftkeymaskobjectid,
          { "New Active Mask Object ID", "isobus.vt.change_soft_key_mask.new_soft_key_mask_object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changesoftkeymask_errorcodes,
          { "Error Codes", "isobus.vt.change_soft_key_mask.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changeattributes_objectid,
          { "Object ID", "isobus.vt.change_attributes.object_id",
            FT_UINT16, BASE_DEC, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changeattributes_attributeid,
          { "Attribute ID", "isobus.vt.change_attributes.attribute_id",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changeattributes_newvalue,
          { "New Value For Attribute", "isobus.vt.change_attributes.new_active_mask",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changeattributes_errorcodes,
          { "Error Codes", "isobus.vt.change_attributes.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changepriority_objectid,
          { "Object ID", "isobus.vt.change_priority.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changepriority_newpriority,
          { "New Priority", "isobus.vt.change_priority.new_priority",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changepriority_errorcodes,
          { "Error Codes", "isobus.vt.change_priority.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changelistitem_listobjectid,
          { "List Object ID", "isobus.vt.change_list_item.list_object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changelistitem_listindex,
          { "List Index", "isobus.vt.change_list_item.list_index",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changelistitem_newobjectid,
          { "New Object ID", "isobus.vt.change_list_item.new_object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changelistitem_errorcodes,
          { "Error Codes", "isobus.vt.change_list_item.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_deleteobjectpool_errorcodes,
          { "Error Codes", "isobus.vt.delete_object_pool.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_chgstrval_objectid,
          { "Object ID", "isobus.vt.change_string_value.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_chgstrval_length,
          { "Length", "isobus.vt.change_string_value.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_chgstrval_errorcodes,
          { "Error Codes", "isobus.vt.change_string_value.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_chgstrval_value,
          { "Value", "isobus.vt.change_string_value.value",
            FT_STRING, STR_UNICODE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changebackgroundcolour_objectid,
          { "Object ID", "isobus.vt.change_background_colour.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changebackgroundcolour_errorcodes,
          { "Error Codes", "isobus.vt.change_background_colour.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changebackgroundcolour_colour,
          { "Colour", "isobus.vt.change_background_colour.colour",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(vt_colours), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changeobjectlabel_objectid,
          { "Object ID", "isobus.vt.change_object_label.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changeobjectlabel_stringobjectid,
          { "String Object ID", "isobus.vt.change_object_label.string_object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changeobjectlabel_fonttype,
          { "Colour", "isobus.vt.change_object_label.colour",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changeobjectlabel_graphicobjectid,
          { "Graphics Representation Object ID", "isobus.vt.change_object_label.graphic_representation_object_id",
            FT_UINT16, BASE_DEC, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changeobjectlabel_errorcodes,
          { "Error Codes", "isobus.vt.change_object_label.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changepolygonpoint_objectid,
          { "Object ID", "isobus.vt.change_polygon_point.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changepolygonpoint_pointindex,
          { "Point Index", "isobus.vt.change_polygon_point.point_index",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changepolygonpoint_xvalue,
          { "X Value", "isobus.vt.change_polygon_point.x_value",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changepolygonpoint_yvalue,
          { "Y Value", "isobus.vt.change_polygon_point.y_value",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changepolygonpoint_errorcodes,
          { "Error Codes", "isobus.vt.change_polygon_point.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changepolygonscale_objectid,
          { "Object ID", "isobus.vt.change_polygon_scale.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changepolygonscale_newwidth,
          { "New Width", "isobus.vt.change_polygon_scale.new_width",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changepolygonscale_newheight,
          { "New Height", "isobus.vt.change_polygon_scale.new_height",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_changepolygonscale_errorcodes,
          { "Error Codes", "isobus.vt.change_polygon_scale.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_objectid,
          { "Object ID", "isobus.vt.graphics_context.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_subcommandid,
          { "Sub Command ID", "isobus.vt.graphics_context.sub_command_id",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &graphics_context_sub_command_id_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_setgraphicscursor_xposition,
          { "X Position", "isobus.vt.graphics_context.set_graphics_cursor.x_position",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_setgraphicscursor_yposition,
          { "Y Position", "isobus.vt.graphics_context.set_graphics_cursor.y_position",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_movegraphicscursor_xoffset,
          { "X Offset", "isobus.vt.graphics_context.move_graphics_cursor.x_offset",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_movegraphicscursor_yoffset,
          { "Y Offset", "isobus.vt.graphics_context.move_graphics_cursor.y_offset",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_setforegroundcolour_colour,
          { "Colour", "isobus.vt.graphics_context.set_foreground_colour.colour",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_setbackgroundcolour_colour,
          { "Colour", "isobus.vt.graphics_context.set_background_colour.colour",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_setlineattributesobjectid_objectid,
          { "Object ID", "isobus.vt.graphics_context.set_line_attributes_object_id.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_setfillattributesobjectid_objectid,
          { "Object ID", "isobus.vt.graphics_context.set_fill_attributes_object_id.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_setfontattributesobjectid_objectid,
          { "Object ID", "isobus.vt.graphics_context.set_font_attributes_object_id.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_eraserectangle_width,
          { "Width", "isobus.vt.graphics_context.erase_rectangle.width",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_eraserectangle_height,
          { "Height", "isobus.vt.graphics_context.erase_rectangle.height",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_drawpoint_xoffset,
          { "X Offset", "isobus.vt.graphics_context.draw_point.x_offset",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_drawpoint_yoffset,
          { "Y Offset", "isobus.vt.graphics_context.draw_point.y_offset",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_drawline_xoffset,
          { "X Offset", "isobus.vt.graphics_context.draw_line.x_offset",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_drawline_yoffset,
          { "Y Offset", "isobus.vt.graphics_context.draw_line.y_offset",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_drawrectangle_width,
          { "Width", "isobus.vt.graphics_context.draw_rectangle.width",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_drawrectangle_height,
          { "Height", "isobus.vt.graphics_context.draw_rectangle.height",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_drawclosedellipse_width,
          { "Width", "isobus.vt.graphics_context.draw_closed_rectangle.width",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_drawclosedellipse_height,
          { "Height", "isobus.vt.graphics_context.draw_closed_rectangle.height",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_drawpolygon_numberofpoints,
          { "Number of polygon points", "isobus.vt.graphics_context.draw_polygon.number_of_points",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_drawpolygon_point_xoffset,
          { "X Offset", "isobus.vt.graphics_context.draw_polygon.point.x_offset",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_drawpolygon_point_yoffset,
          { "Y Offset", "isobus.vt.graphics_context.draw_polygon.point.y_offset",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_drawtext_background,
          { "Background", "isobus.vt.graphics_context.draw_text.point.background",
            FT_UINT8, BASE_DEC, VALS(draw_text_background), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_drawtext_numberofbytes,
          { "Number of Bytes", "isobus.vt.graphics_context.draw_text.point.number_of_bytes",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_drawtext_textstring,
          { "Text string", "isobus.vt.graphics_context.draw_text.point.text_string",
            FT_STRING, STR_UNICODE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_panviewport_viewportx,
          { "Viewport X", "isobus.vt.graphics_context.pan_viewport.viewport_x",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_panviewport_viewporty,
          { "Viewport Y", "isobus.vt.graphics_context.pan_viewport.viewport_y",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_zoomviewport_zoomvalue,
          { "Zoom Value", "isobus.vt.graphics_context.zoom_viewport.zoom_value",
            FT_FLOAT, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_panandzoomviewport_viewportx,
          { "Viewport X", "isobus.vt.graphics_context.pan_and_zoom_viewport.viewport_x",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_panandzoomviewport_viewporty,
          { "Viewport Y", "isobus.vt.graphics_context.pan_and_zoom_viewport.viewport_y",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_panandzoomviewport_zoomvalue,
          { "Zoom Value", "isobus.vt.graphics_context.pan_and_zoom_viewport.zoom_value",
            FT_FLOAT, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_changeviewportsize_newwidth,
          { "New Width", "isobus.vt.graphics_context.change_viewport_size.new_width",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_changeviewportsize_newheight,
          { "New Height", "isobus.vt.graphics_context.change_viewport_size.new_height",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_drawvtobject_objectid,
          { "Object ID", "isobus.vt.graphics_context.draw_vt_object.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_copycanvastopicturegraphic_objectidpicturegraphic,
          { "Object ID of Picture Grahpic", "isobus.vt.graphics_context.copy_canvas_to_picture_graphic.object_id_picture_graphic",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_graphicscontext_copyviewporttopicturegraphic_objectidpicturegraphic,
          { "Object ID of Picture Grahpic", "isobus.vt.graphics_context.copy_viewport_to_picture_graphic.object_id_picture_graphic",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_getattributevalue_objectid,
          { "Object ID", "isobus.vt.get_attribute_value.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_getattributevalue_attributeid,
          { "Attribute ID", "isobus.vt.get_attribute_value.attribute_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_getattributevalue_value,
          { "Value", "isobus.vt.get_attribute_value.value",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_getattributevalue_errorcodes,
          { "Error Codes", "isobus.vt.get_attribute_value.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_selectcolourmap_objectid,
          { "Object ID", "isobus.vt.select_colour_map.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_selectcolourmap_errorcodes,
          { "Error Codes", "isobus.vt.select_colour_map.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_executeextendedmacro_objectid,
          { "Object ID", "isobus.vt.execute_extended_macro.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_executeextendedmacro_errorcodes,
          { "Error Codes", "isobus.vt.execute_extended_macro.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_lockunlockmask_command,
          { "Command", "isobus.vt.lock_unlock_mask.command",
            FT_UINT8, BASE_DEC, VALS(lock_unlock), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_lockunlockmask_objectid,
          { "Object ID", "isobus.vt.lock_unlock_mask.object_id",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_lockunlockmask_locktimeout,
          { "Lock Timeout", "isobus.vt.lock_unlock_mask.lock_timeout",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_lockunlockmask_errorcodes,
          { "Error Codes", "isobus.vt.lock_unlock_mask.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_executemacro_objectid,
          { "Object ID", "isobus.vt.execute_macro.object_id",
            FT_UINT8, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_executemacro_errorcodes,
          { "Error Codes", "isobus.vt.execute_macro.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_getmemory_memoryrequired,
          { "Memory Required", "isobus.vt.get_memory.memory_required",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_getmemory_vtversion,
          { "VT Version", "isobus.vt.get_memory.vt_version",
            FT_UINT8, BASE_DEC, VALS(vt_versions_extended), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_getmemory_status,
          { "Status", "isobus.vt.get_memory.status",
            FT_UINT8, BASE_DEC, VALS(memory_status), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_getsupportedwidechars_codeplane,
          { "Code Plane", "isobus.vt.get_supported_widechars.code_plane",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_getsupportedwidechars_firstwidechar,
          { "First Widechar", "isobus.vt.get_supported_widechars.first_widechar",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_getsupportedwidechars_lastwidechar,
          { "Last Widechar", "isobus.vt.get_supported_widechars.last_widechar",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_getsupportedwidechars_errorcodes,
          { "Error Codes", "isobus.vt.get_supported_widechars.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_getsupportedwidechars_numberofranges,
          { "Number of Ranges", "isobus.vt.get_supported_widechars.number_of_ranges",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_getsupportedwidechars_firstavailablewidechar,
          { "First Available Widechar", "isobus.vt.get_supported_widechars.first_available_widechar",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_getsupportedwidechars_lastavailablewidechar,
          { "Last Available Widechar", "isobus.vt.get_supported_widechars.last_available_widechar",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_getnumberofsoftkeys_navigationsoftkeys,
          { "Navigation Soft Keys", "isobus.vt.get_number_of_soft_keys.navigation_soft_keys",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_getnumberofsoftkeys_xdots,
          { "X Dots", "isobus.vt.get_number_of_soft_keys.x_dots",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_getnumberofsoftkeys_ydots,
          { "Y Dots", "isobus.vt.get_number_of_soft_keys.y_dots",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_getnumberofsoftkeys_virtualsoftkeys,
          { "Virtual Soft Keys", "isobus.vt.get_number_of_soft_keys.virtual_soft_keys",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_getnumberofsoftkeys_physicalsoftkeys,
          { "Physical Soft Keys", "isobus.vt.get_number_of_soft_keys.physical_soft_keys",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gettextfontdata_smallfontsizes,
          { "Small Font Sizes", "isobus.vt.get_text_font_data.small_font_sizes",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gettextfontdata_smallfontsizes_font8x8,
          { "Font 8 x 8",       "isobus.vt.get_text_font_data.small_font_sizes.font_8x8",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gettextfontdata_smallfontsizes_font8x12,
          { "Font 8 x 12",       "isobus.vt.get_text_font_data.small_font_sizes.font_8x12",
            FT_UINT8, BASE_HEX, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gettextfontdata_smallfontsizes_font12x16,
          { "Font 12 x 16",       "isobus.vt.get_text_font_data.small_font_sizes.font_12x16",
            FT_UINT8, BASE_HEX, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gettextfontdata_smallfontsizes_font16x16,
          { "Font 12 x 16",       "isobus.vt.get_text_font_data.small_font_sizes.font_12x16",
            FT_UINT8, BASE_HEX, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gettextfontdata_smallfontsizes_font16x24,
          { "Font 16 x 24",       "isobus.vt.get_text_font_data.small_font_sizes.font_16x24",
            FT_UINT8, BASE_HEX, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gettextfontdata_smallfontsizes_font24x32,
          { "Font 24 x 32",       "isobus.vt.get_text_font_data.small_font_sizes.font_24x32",
            FT_UINT8, BASE_HEX, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gettextfontdata_smallfontsizes_font32x32,
          { "Font 32 x 32",       "isobus.vt.get_text_font_data.small_font_sizes.font_32x32",
            FT_UINT8, BASE_HEX, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gettextfontdata_largefontsizes,
          { "Large Font Sizes",       "isobus.vt.get_text_font_data.large_font_sizes",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gettextfontdata_largefontsizes_font32x48,
          { "Font 32 x 48",       "isobus.vt.get_text_font_data.large_font_sizes.font_32x48",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gettextfontdata_largefontsizes_font48x64,
          { "Font 48 x 64",       "isobus.vt.get_text_font_data.large_font_sizes.font_48x64",
            FT_UINT8, BASE_HEX, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gettextfontdata_largefontsizes_font64x64,
          { "Font 64 x 64",       "isobus.vt.get_text_font_data.large_font_sizes.font_64x64",
            FT_UINT8, BASE_HEX, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gettextfontdata_largefontsizes_font64x96,
          { "Font 64 x 96",       "isobus.vt.get_text_font_data.large_font_sizes.font_64x96",
            FT_UINT8, BASE_HEX, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gettextfontdata_largefontsizes_font96x128,
          { "Font 96 x 128",       "isobus.vt.get_text_font_data.large_font_sizes.font_96x128",
            FT_UINT8, BASE_HEX, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gettextfontdata_largefontsizes_font128x128,
          { "Font 128 x 128",       "isobus.vt.get_text_font_data.large_font_sizes.font_128x128",
            FT_UINT8, BASE_HEX, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gettextfontdata_largefontsizes_font128x192,
          { "Font 128 x 192",       "isobus.vt.get_text_font_data.large_font_sizes.font_128x192",
            FT_UINT8, BASE_HEX, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gettextfontdata_typeattributes,
          { "Type Attributes",       "isobus.vt.get_text_font_data.type_attributes",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gettextfontdata_typeattributes_boldtext,
          { "Bold text",       "isobus.vt.get_text_font_data.type_attributes.bold_text",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gettextfontdata_typeattributes_crossedouttext,
          { "Crossed out text",       "isobus.vt.get_text_font_data.type_attributes.crossed_out_text",
            FT_UINT8, BASE_HEX, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gettextfontdata_typeattributes_underlinedtext,
          { "Underlined text",       "isobus.vt.get_text_font_data.type_attributes.underlined_text",
            FT_UINT8, BASE_HEX, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gettextfontdata_typeattributes_italicstext,
          { "Italics text",       "isobus.vt.get_text_font_data.type_attributes.italics_text",
            FT_UINT8, BASE_HEX, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gettextfontdata_typeattributes_invertedtext,
          { "Inverted text",       "isobus.vt.get_text_font_data.type_attributes.inverted_text",
            FT_UINT8, BASE_HEX, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gettextfontdata_typeattributes_flashinverted,
          { "Flash inverted",       "isobus.vt.get_text_font_data.type_attributes.flash_inverted",
            FT_UINT8, BASE_HEX, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gettextfontdata_typeattributes_flashhidden,
          { "Flash hidden",       "isobus.vt.get_text_font_data.type_attributes.flash_hidden",
            FT_UINT8, BASE_HEX, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gettextfontdata_typeattributes_proportionalfontrendering,
          { "Proportional font rendering",       "isobus.vt.get_text_font_data.type_attributes.proportional_font_rendering",
            FT_UINT8, BASE_DEC, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_isobus_vt_getwindowmaskdata_backgroundcolourdatamask,
          { "Background Colour Data Mask",      "isobus.vt.get_window_mask_data.background_colour_data_mask",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(vt_colours), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_getwindowmaskdata_backgroundcoloursoftkeymask,
          { "Background Colour Soft Key Mask",      "isobus.vt.get_window_mask_data.background_colour_soft_key_mask",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(vt_colours), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_getsupportedobjects_numberofbytes,
          { "Number of bytes",      "isobus.vt.get_supported_objects.number_of_bytes",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_getsupportedobjects_objecttype,
          { "Object Type",      "isobus.vt.get_supported_objects.object_type",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(vt_object_types), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gethardware_boottime,
          { "Boot time",      "isobus.vt.get_hardware.boot_time",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gethardware_graphictype,
          { "Graphic type",      "isobus.vt.get_hardware.graphic_type",
            FT_UINT8, BASE_DEC, VALS(graphic_types), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gethardware_hardware,
          { "Hardware",      "isobus.vt.get_hardware.hardware",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gethardware_hardware_touchscreen,
          { "Touch Screen",      "isobus.vt.get_hardware.hardware.touch_screen",
            FT_UINT8, BASE_HEX, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gethardware_hardware_pointingdevice,
          { "Pointing Device",      "isobus.vt.get_hardware.hardware.pointing_device",
            FT_UINT8, BASE_HEX, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gethardware_hardware_multifreqaudiooutput,
          { "Multiple frequency audio output",      "isobus.vt.get_hardware.hardware.multiple_frequency_audio_output",
            FT_UINT8, BASE_HEX, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gethardware_hardware_adjustvolumeaudiooutput,
          { "Adjustable volume audio output",      "isobus.vt.get_hardware.hardware.adjustable_volume_audio_output",
            FT_UINT8, BASE_HEX, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gethardware_hardware_simultaneousactivationphysicalsoftkeys,
          { "Simultaneous activation of physical soft keys",      "isobus.vt.get_hardware.hardware.simultaneous_activation_physical_soft_keys",
            FT_UINT8, BASE_HEX, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gethardware_hardware_simultaneousactivationbuttons,
          { "Simultaneous activation of buttons",      "isobus.vt.get_hardware.hardware.simultaneous_activation_buttons",
            FT_UINT8, BASE_HEX, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gethardware_hardware_dragoperation,
          { "Reports drag operation",      "isobus.vt.get_hardware.hardware.drag_operation",
            FT_UINT8, BASE_HEX, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gethardware_hardware_intermediatecoordinatesdrag,
          { "Intermediate coordinates during drag",      "isobus.vt.get_hardware.hardware.intermediate_coordinates_drag",
            FT_UINT8, BASE_HEX, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gethardware_xpixels,
          { "X - Pixels",      "isobus.vt.get_hardware.x_pixels",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_gethardware_ypixels,
          { "Y - Pixels",      "isobus.vt.get_hardware.y_pixels",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_storeversion_versionlabel,
          { "Version Label",       "isobus.vt.store_version.version_label",
            FT_STRING, STR_ASCII, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_storeversion_errorcodes,
          { "Error Codes",       "isobus.vt.store_version.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_loadversion_versionlabel,
          { "Version Label",       "isobus.vt.load_version.version_label",
            FT_STRING, STR_ASCII, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_loadversion_errorcodes,
          { "Error Codes",       "isobus.vt.load_version.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_deleteversion_versionlabel,
          { "Version Label",       "isobus.vt.delete_version.version_label",
            FT_STRING, STR_ASCII, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_deleteversion_errorcodes,
          { "Error Codes",       "isobus.vt.delete_version.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_extendedgetversions_numberofversions,
          { "Number of versions",  "isobus.vt.extended_get_versions.number_of_versions",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_extendedgetversions_versionlabel,
          { "Version label",  "isobus.vt.extended_get_versions.version_label",
            FT_STRING, STR_ASCII, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_extendedstoreversion_versionlabel,
          { "Version Label",       "isobus.vt.extended_store_version.version_label",
            FT_STRING, STR_ASCII, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_extendedstoreversion_errorcodes,
          { "Error Codes",       "isobus.vt.extended_store_version.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_extendedloadversion_versionlabel,
          { "Version Label",       "isobus.vt.extended_load_version.version_label",
            FT_STRING, STR_ASCII, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_extendedloadversion_errorcodes,
          { "Error Codes",       "isobus.vt.extended_load_version.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_extendeddeleteversion_versionlabel,
          { "Version Label",       "isobus.vt.extended_delete_version.version_label",
            FT_STRING, STR_ASCII, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_extendeddeleteversion_errorcodes,
          { "Error Codes",       "isobus.vt.extended_delete_version.error_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_getversions_numberofversions,
          { "Number of versions",  "isobus.vt.get_versions.number_of_versions",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_getversions_versionlabel,
          { "Version label",  "isobus.vt.get_versions.version_label",
            FT_STRING, STR_ASCII, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_unsupportedvtfunction_unsupportedvtfunction,
          { "Unsupported VT function",       "isobus.vt.unsupported_vt_function.unsupported_vt_function",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &vt_function_code_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtstatus_workingsetmaster,
          { "Working Set Master",       "isobus.vt.vtstatus.working_set_master",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtstatus_objectiddatamask,
          { "Object ID Data Mask",      "isobus.vt.vtstatus.object_id_data_mask",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtstatus_objectidsoftkeymask,
          { "Object ID Soft Key Mask",  "isobus.vt.vtstatus.object_id_soft_key_mask",
            FT_UINT16, BASE_DEC_HEX, VALS(object_id_strings), 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtstatus_vtbusycodes,
          { "VT Busy Codes",            "isobus.vt.vtstatus.vt_busy_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtstatus_vtbusycodes_updatingvisiblemask,
          { "VT is busy updating visible mask",            "isobus.vt.vtstatus.vt_busy_codes.updating_visible_mask",
            FT_UINT8, BASE_HEX, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtstatus_vtbusycodes_savingdata,
          { "VT is busy saving data to non-volatile memory","isobus.vt.vtstatus.vt_busy_codes.saving_data",
            FT_UINT8, BASE_HEX, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtstatus_vtbusycodes_executingcommand,
          { "VT is busy executing a command",            "isobus.vt.vtstatus.vt_busy_codes.executing_commands",
            FT_UINT8, BASE_HEX, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtstatus_vtbusycodes_executingmacro,
          { "VT is busy executing a Macro",            "isobus.vt.vtstatus.vt_busy_codes.executing_macro",
            FT_UINT8, BASE_HEX, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtstatus_vtbusycodes_parsingobjectpool,
          { "VT is busy parsing an object pool",            "isobus.vt.vtstatus.vt_busy_codes.parsing_object_pool",
            FT_UINT8, BASE_HEX, NULL, 0x8,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtstatus_vtbusycodes_auxcontrolsactive,
          { "Auxiliary controls learn mode active",        "isobus.vt.vtstatus.vt_function_codes.aux_controls_active",
            FT_UINT8, BASE_HEX, NULL, 0x2,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtstatus_vtbusycodes_outofmemory,
          { "VT is out of memory",        "isobus.vt.vtstatus.vt_function_codes.out_of_memory",
            FT_UINT8, BASE_HEX, NULL, 0x1,
            NULL, HFILL }
        },
        { &hf_isobus_vt_vtstatus_vtfunctioncodes,
          { "VT Function Codes",        "isobus.vt.vtstatus.vt_function_codes",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_isobus_vt_wrksetmain_bitmask,
          { "Bitmask",                   "isobus.vt.working_set_maintenance.bitmask",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_isobus_vt_wrksetmain_version,
          { "Version",                  "isobus.vt.working_set_maintenance.version",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(vt_versions), 0x0,
            NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_isobus_vt,
        &ett_isobus_vt_vtstatus_busycodes_subtree,
        &ett_isobus_vt_getsupportedwidechars_range,
        &ett_isobus_vt_gettextfontdata_smallfontsizes,
        &ett_isobus_vt_gettextfontdata_largefontsizes,
        &ett_isobus_vt_gettextfontdata_typeattributes,
        &ett_isobus_vt_gethardware_hardware,
        &ett_isobus_vt_preferredassignment_inputunit,
        &ett_isobus_vt_preferredassignment_inputunit_preferredfunction,
        &ett_isobus_vt_auxiliarycapabilities_inputunit,
        &ett_isobus_vt_auxiliarycapabilities_inputunit_set,
        &ett_isobus_vt_auxiliaryassignmenttype2_flags,
        &ett_isobus_vt_auxiliaryinputtype2status_operatingstate
    };

    module_t *vt_module;

    register_init_routine(&isobus_vt_init);

    proto_vt = proto_register_protocol("ISObus Virtual Terminal",
                                       "ISObus VT",
                                       "isobus.vt");

    proto_register_field_array(proto_vt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* register preferences */
    vt_module = prefs_register_protocol(proto_vt, NULL);

    /* file to translate opject ids to names, format should be separate line for each object.
     * objects should be specified in the following way: <object ID number>,<object ID name>
     */
    prefs_register_filename_preference(vt_module, "object_ids", "Object ID Translation",
        "File containing a translation from object ID to string", &object_id_translation,
        FALSE);
}

void
proto_reg_handoff_isobus_vt(void)
{
    dissector_handle_t vt_handle_vt_to_ecu;
    dissector_handle_t vt_handle_ecu_to_vt;

    vt_handle_vt_to_ecu = create_dissector_handle( dissect_vt_to_ecu, proto_vt );
    vt_handle_ecu_to_vt = create_dissector_handle( dissect_ecu_to_vt, proto_vt );

    dissector_add_uint("isobus.pdu_format", 230, vt_handle_vt_to_ecu);
    dissector_add_uint("isobus.pdu_format", 231, vt_handle_ecu_to_vt);
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
