/* packet-x11.c
 * Routines for X11 dissection
 * Copyright 2000, Christophe Tronche <ch.tronche@computer.org>
 *
 * $Id: packet-x11.c,v 1.5 2000/06/14 00:24:39 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/* TODO (in no particular order):
 *
 * - keep track of Atom creation by server to be able to display non predefined atoms
 * - Idem for keysym <-> keycode ???
 * - Idem for fonts 
 * - Subtree the request ids (that is x11.create-window.window and x11.change-window.window should be 
 *   distinct), and add hidden fields (so we still have x11.window).
 * - add hidden fields so we can have x11.circulate-window in addition to x11.opcode == 13
 * - add hidden fields so we have x11.listOfStuff.length
 * - use a faster scheme that linear list searching for the opcode.
 * - correct display of unicode chars.
 * - Not everything is homogeneous, in particular the handling of items in list is a total mess.
 */

/* By the way, I wrote a program to generate every request and test
 * that stuff. If you're interested, you can get it at
 * http://tronche.com/gui/x/
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <string.h>
#include <glib.h>
#include "packet.h"

#define cVALS(x) (const value_string*)(x)

/* Initialize the protocol and registered fields */
static int proto_x11 = -1;

#include "packet-x11-declarations.h"

/* Initialize the subtree pointers */
static gint ett_x11 = -1;
static gint ett_x11_request = -1;

#define TCP_PORT_X11			6000
#define TCP_PORT_X11_2			6001
#define TCP_PORT_X11_3			6002

/************************************************************************
 ***                                                                  ***
 ***         E N U M   T A B L E S   D E F I N I T I O N S            ***
 ***                                                                  ***
 ************************************************************************/

static const value_string access_mode_vals[] = {
      { 0, "Disable" },
      { 1, "Enable" },
      { 0, NULL }
};

static const value_string all_temporary_vals[] = {
      { 0, "AllTemporary" },
      { 0, NULL }
};

static const value_string alloc_vals[] = {
      { 0, "None" },
      { 1, "All" },
      { 0, NULL }
};

static const value_string allow_events_mode_vals[] = {
      { 0, "AsyncPointer" },
      { 1, "SyncPointer" },
      { 2, "ReplayPointer" },
      { 3, "AsyncKeyboard" },
      { 4, "SyncKeyboard" },
      { 5, "ReplayKeyboard" },
      { 6, "AsyncBoth" },
      { 7, "SyncBoth" },
      { 0, NULL }
};

static const value_string arc_mode_vals[] = {
      { 0, "Chord" },
      { 1, "PieSlice" },
      { 0, NULL }
};

static const char *atom_predefined_interpretation[] = {
      "<error>",
      "PRIMARY",
      "SECONDARY",
      "ARC",
      "ATOM",
      "BITMAP",
      "CARDINAL",
      "COLORMAP",
      "CURSOR",
      "CUT_BUFFER0",
      "CUT_BUFFER1",
      "CUT_BUFFER2",
      "CUT_BUFFER3",
      "CUT_BUFFER4",
      "CUT_BUFFER5",
      "CUT_BUFFER6",
      "CUT_BUFFER7",
      "DRAWABLE",
      "FONT",
      "INTEGER",
      "PIXMAP",
      "POINT",
      "RECTANGLE",
      "RESOURCE_MANAGER",
      "RGB_COLOR_MAP",
      "RGB_BEST_MAP",
      "RGB_BLUE_MAP",
      "RGB_DEFAULT_MAP",
      "RGB_GRAY_MAP",
      "RGB_GREEN_MAP",
      "RGB_RED_MAP",
      "STRING",
      "VISUALID",
      "WINDOW",
      "WM_COMMAND",
      "WM_HINTS",
      "WM_CLIENT_MACHINE",
      "WM_ICON_NAME",
      "WM_ICON_SIZE",
      "WM_NAME",
      "WM_NORMAL_HINTS",
      "WM_SIZE_HINTS",
      "WM_ZOOM_HINTS",
      "MIN_SPACE",
      "NORM_SPACE",
      "MAX_SPACE",
      "END_SPACE",
      "SUPERSCRIPT_X",
      "SUPERSCRIPT_Y",
      "SUBSCRIPT_X",
      "SUBSCRIPT_Y",
      "UNDERLINE_POSITION",
      "UNDERLINE_THICKNESS",
      "STRIKEOUT_ASCENT",
      "STRIKEOUT_DESCENT",
      "ITALIC_ANGLE",
      "X_HEIGHT",
      "QUAD_WIDTH",
      "WEIGHT",
      "POINT_SIZE",
      "RESOLUTION",
      "COPYRIGHT",
      "NOTICE",
      "FONT_NAME",
      "FAMILY_NAME",
      "FULL_NAME",
      "CAP_HEIGHT",
      "WM_CLASS",
      "WM_TRANSIENT_FOR",
};

static const value_string auto_repeat_mode_vals[] = {
      { 0, "Off" },
      { 1, "On" },
      { 2, "Default" },
      { 0, NULL }
};

static const value_string background_pixmap_vals[] = { 
      { 0, "None" },
      { 1, "ParentRelative" },
      { 0, NULL }
};

static const value_string backing_store_vals[] = {
      { 0, "NotUseful" },
      { 1, "WhenMapped" },
      { 2, "Always" },
      { 0, NULL }
};

static const value_string border_pixmap_vals[] = { 
      { 0, "CopyFromParent" },
      { 0, NULL }
};

static const value_string button_vals[] = {
      { 0x8000, "AnyButton" },
      { 0, NULL }
};

static const value_string cap_style_vals[] = {
      { 0, "NotLast" },
      { 1, "Butt" },
      { 2, "Round" },
      { 3, "Projecting" },
      { 0, NULL }
};

static const value_string class_vals[] = {
      { 0, "Cursor" },
      { 1, "Tile" },
      { 2, "Stipple" },
      { 0, NULL }
};

static const value_string close_down_mode_vals[] = {
      { 0, "Destroy" },
      { 1, "RetainPermanent" },
      { 2, "RetainTemporary" },
      { 0, NULL }
};

static const value_string coordinate_mode_vals[] = {
      { 0, "Origin" },
      { 1, "Previous" },
      { 0, NULL }
};

static const value_string direction_vals[] = { 
      { 0, "RaiseLowest" },
      { 1, "LowerHighest" },
      { 0, NULL }
};

static const value_string family_vals[] = {
      { 0, "Internet" },
      { 1, "DECnet" },
      { 2, "Chaos" },
      { 0, NULL }
};

static const value_string fill_rule_vals[] = {
      { 0, "EvenOdd" },
      { 1, "Winding" },
      { 0, NULL }
};

static const value_string fill_style_vals[] = {
      { 0, "Solid" },
      { 1, "Tiled" },
      { 2, "Stippled" },
      { 3, "OpaqueStippled" },
      { 0, NULL }
};

static const value_string focus_vals[] = {
      { 0, "None" },
      { 1, "PointerRoot" },
      { 0, NULL }
};

static const value_string function_vals[] = {
      {  0, "Clear" },
      {  1, "And" },
      {  2, "AndReverse" },
      {  3, "Copy" },
      {  4, "AndInverted" },
      {  5, "NoOp" },
      {  6, "Xor" },
      {  7, "Or" },
      {  8, "Nor" },
      {  9, "Equiv" },
      { 10, "Invert" },
      { 11, "OrReverse" },
      { 12, "CopyInverted" },
      { 13, "OrInverted" },
      { 14, "Nand" },
      { 15, "Set" },  
      {  0, NULL }
};

static const value_string gravity_vals[] = {
      {  1, "NorthWest" },
      {  2, "North" },
      {  3, "NorthEast" },
      {  4, "West" },
      {  5, "Center" },
      {  6, "East" },
      {  7, "SouthWest" },
      {  8, "South" },
      {  9, "SouthEast" },
      { 10, "Static" },
      {  0, NULL }
};

static const value_string image_format_vals[] = {
      { 0, "Bitmap" },
      { 1, "XYPixmap" },
      { 2, "ZPixmap" },
      { 0, NULL }
};

static const value_string image_pixmap_format_vals[] = {
      { 1, "XYPixmap" },
      { 2, "ZPixmap" },
      { 0, NULL }
};

static const value_string join_style_vals[] = {
      { 0, "Miter" },
      { 1, "Round" },
      { 2, "Bevel" },
      { 0, NULL }
};

static const value_string key_vals[] = {
      { 0, "AnyKey" },
      { 0, NULL }
};

#include "packet-x11-keysym.h"

static const value_string line_style_vals[] = {
      { 0, "Solid" },
      { 1, "OnOffDash" },
      { 2, "DoubleDash" },
      { 0, NULL }
};

static const value_string mode_vals[] = {
      { 0, "Replace" },
      { 1, "Prepend" },
      { 2, "Append" },
      { 0, NULL }
};

static const value_string on_off_vals[] = {
      { 0, "Off" },
      { 1, "On" },
      { 0, NULL }
};

static const value_string opcode_vals[] = {
      {   1, "CreateWindow" },
      {   2, "ChangeWindowAttributes" },
      {   3, "GetWindowAttributes" }, 
      {   4, "DestroyWindow" },
      {   5, "DestroySubwindows" },
      {   6, "ChangeSaveSet" },
      {   7, "ReparentWindow" },
      {   8, "MapWindow" },
      {   9, "MapSubwindows" },
      {  10, "UnmapWindow" },
      {  11, "UnmapSubwindows" },
      {  12, "ConfigureWindow" },
      {  13, "CirculateWindow" },
      {  14, "GetGeometry" },
      {  15, "QueryTree" },
      {  16, "InternAtom" },
      {  17, "GetAtomName" },
      {  18, "ChangeProperty" },
      {  19, "DeleteProperty" },
      {  20, "GetProperty" },
      {  21, "ListProperties" },
      {  22, "SetSelectionOwner" },
      {  23, "GetSelectionOwner" },
      {  24, "ConvertSelection" },

      {  26, "GrabPointer" },
      {  27, "UngrabPointer" },
      {  28, "GrabButton" },
      {  29, "UngrabButton" },
      {  30, "ChangeActivePointerGrab" },
      {  31, "GrabKeyboard" },
      {  32, "UngrabKeyboard" },
      {  33, "GrabKey" },
      {  34, "UngrabKey" },
      {  35, "AllowEvents" },
      {  36, "GrabServer" },
      {  37, "UngrabServer" },
      {  38, "QueryPointer" },
      {  39, "GetMotionEvents" },
      {  40, "TranslateCoordinates" },
      {  41, "WarpPointer" },
      {  42, "SetInputFocus" },
      {  43, "GetInputFocus" },
      {  44, "QueryKeymap" },
      {  45, "OpenFont" },
      {  46, "CloseFont" },
      {  47, "QueryFont" },
      {  48, "QueryTextExtents" },
      {  49, "ListFonts" },
      {  50, "ListFontsWithInfo" },
      {  51, "SetFontPath" },
      {  52, "GetFontPath" },
      {  53, "CreatePixmap" },
      {  54, "FreePixmap" },
      {  55, "CreateGC" },
      {  56, "ChangeGC" },
      {  57, "CopyGC" },
      {  58, "SetDashes" },
      {  59, "SetClipRectangles" },
      {  60, "FreeGC" },
      {  61, "ClearArea" },
      {  62, "CopyArea" },
      {  63, "CopyPlane" },
      {  64, "PolyPoint" },
      {  65, "PolyLine" },
      {  66, "PolySegment" },
      {  67, "PolyRectangle" },
      {  68, "PolyArc" },
      {  69, "FillPoly" },
      {  70, "PolyFillRectangle" },
      {  71, "PolyFillArc" },
      {  72, "PutImage" },
      {  73, "GetImage" },
      {  74, "PolyText8" },
      {  75, "PolyText16" },
      {  76, "ImageText8" },
      {  77, "ImageText16" },
      {  78, "CreateColormap" },
      {  79, "FreeColormap" },
      {  80, "CopyColormapAndFree" },
      {  81, "InstallColormap" },
      {  82, "UninstallColormap" },
      {  83, "ListInstalledColormaps" },
      {  84, "AllocColor" },
      {  85, "AllocNamedColor" },
      {  86, "AllocColorCells" },
      {  87, "AllocColorPlanes" },
      {  88, "FreeColors" },
      {  89, "StoreColors" },
      {  90, "StoreNamedColor" },
      {  91, "QueryColors" },
      {  92, "LookupColor" },
      {  93, "CreateCursor" },
      {  94, "CreateGlyphCursor" },
      {  95, "FreeCursor" },
      {  96, "RecolorCursor" },
      {  97, "QueryBestSize" },
      {  98, "QueryExtension" },
      {  99, "ListExtensions" },
      { 100, "ChangeKeyboardMapping" },
      { 101, "GetKeyboardMapping" },
      { 102, "ChangeKeyboardControl" },
      { 103, "GetKeyboardControl" },
      { 104, "Bell" },
      { 105, "ChangePointerControl" },
      { 106, "GetPointerControl" },
      { 107, "SetScreenSaver" },
      { 108, "GetScreenSaver" },
      { 109, "ChangeHosts" },
      { 110, "ListHosts" },
      { 111, "SetAccessControl" },
      { 112, "SetCloseDownMode" },
      { 113, "KillClient" },
      { 114, "RotateProperties" },
      { 115, "ForceScreenSaver" },
      { 116, "SetPointerMapping" },
      { 117, "GetPointerMapping" },
      { 118, "SetModifierMapping" },
      { 119, "GetModifierMapping" },
      { 127, "NoOperation" },
      { 0, NULL }
};

static const value_string ordering_vals[] = {
      { 0, "UnSorted" },
      { 1, "YSorted" },
      { 2, "YXSorted" },
      { 3, "YXBanded" },
      { 0, NULL }
};

static const value_string plane_mask_vals[] = {
      { 0xFFFFFFFF, "AllPlanes" },
      { 0, NULL }
};

static const value_string pointer_keyboard_mode_vals[] = {
      { 0, "Synchronous" },
      { 1, "Asynchronous" },
      { 0, NULL }
};

static const value_string revert_to_vals[] = {
      { 0, "None" },
      { 1, "PointerRoot" },
      { 2, "Parent" },
      { 0, NULL }
};

static const value_string insert_delete_vals[] = {
      { 0, "Insert" },
      { 1, "Delete" },
      { 0, NULL }
};

static const value_string screen_saver_mode_vals[] = {
      { 0, "Reset" },
      { 1, "Activate" },
      { 0, NULL }
};

static const value_string shape_vals[] = {
      { 0, "Complex" },
      { 1, "Nonconvex" },
      { 2, "Convex" },
      { 0, NULL }
};

static const value_string stack_mode_vals[] = {
      { 0, "Above" },
      { 1, "Below" },
      { 2, "TopIf" },
      { 3, "BottomIf" },
      { 4, "Opposite" },
      { 0, NULL }
};

static const value_string subwindow_mode_vals[] = {
      { 0, "ClipByChildren" },
      { 1, "IncludeInferiors" },
      { 0, NULL }
};

static const value_string window_class_vals[] = {
      { 0, "CopyFromParent" },
      { 1, "InputOutput" },
      { 2, "InputOnly" },
      { 0, NULL }
};

static const value_string yes_no_default_vals[] = {
      { 0, "No" },
      { 1, "Yes" },
      { 2, "Default" },
      { 0, NULL }
};

static const value_string zero_is_any_property_type_vals[] = {
      { 0, "AnyPropertyType" },
      { 0, NULL }
};

static const value_string zero_is_none_vals[] = {
      { 0, "None" },
      { 0, NULL }
};

/************************************************************************
 ***                                                                  ***
 ***         G L O B A L   V A R I A B L E S   ( A R G H H ! )        ***
 ***                                                                  ***
 ************************************************************************/

static int cur_offset;         /* The current offset in the frame */
static int next_offset = 0; /* Offset of the next request in the frame */    
static tvbuff_t *tvb = NULL;
static gboolean little_endian = TRUE;
static proto_tree *t = NULL;

static struct maskStruct {
      guint32 _value;
      int _offset;
      int _zone;
      proto_tree *_tree;
} lastMask = { 0, 0, 0, NULL };

/************************************************************************
 ***                                                                  ***
 ***           F I E L D   D E C O D I N G   M A C R O S              ***
 ***                                                                  ***
 ************************************************************************/

#define VALUE8(tvb, offset) (tvb_get_guint8(tvb, offset))
#define VALUE16(tvb, offset) (little_endian ? tvb_get_letohs(tvb, offset) : tvb_get_ntohs(tvb, offset))
#define VALUE32(tvb, offset) (little_endian ? tvb_get_letohl(tvb, offset) : tvb_get_ntohl(tvb, offset))

#define FIELD8(name)  (field8(hf_x11_##name))
#define FIELD16(name) (field16(hf_x11_##name))
#define FIELD32(name) (field32(hf_x11_##name))

#define BITFIELD(TYPE, position, name) {\
  if (lastMask._value & proto_registrar_get_nth(hf_x11_##position##_##name) -> bitmask) {\
       int unused;\
       int save = cur_offset;\
       proto_tree_add_item(lastMask._tree, hf_x11_##position##_##name, tvb, lastMask._offset, \
                           lastMask._zone, little_endian); \
       TYPE(name);\
       unused = save + 4 - cur_offset;\
       if (unused)\
           proto_tree_add_item(t, hf_x11_unused, tvb, cur_offset, unused, little_endian);\
       cur_offset = save + 4;\
 }\
}

#define FLAG(position, name) {\
  if (lastMask._value & proto_registrar_get_nth(hf_x11_##position##_mask##_##name) -> bitmask)\
       proto_tree_add_boolean(lastMask._tree, hf_x11_##position##_mask##_##name, tvb, lastMask._offset, lastMask._zone, lastMask._value); }

#define ATOM(name)     { atom(t, hf_x11_##name); }
#define BITGRAVITY(name) { gravity(#name, hf_x11_##name, "Forget"); }
#define BITMASK8(name) { bitmask(hf_x11_##name##_mask, 1); }
#define BITMASK16(name) { bitmask(hf_x11_##name##_mask, 2); }
#define BITMASK32(name)  { bitmask(hf_x11_##name##_mask, 4); }
#define BOOL(name)     (boolean(#name, hf_x11_##name))
#define BUTTON(name)   { FIELD8(name); }
#define CARD8(name)    { FIELD8(name); }
#define CARD16(name)   (FIELD16(name))
#define CARD32(name)   (FIELD32(name))
#define COLOR_FLAGS(name) { colorFlags(t); }
#define COLORMAP(name) { FIELD32(name); }
#define CURSOR(name)   { FIELD32(name); }
#define DRAWABLE(name) { FIELD32(name); }
#define ENUM8(name)    { FIELD8(name); }
#define ENUM16(name)   { FIELD16(name); }
#define FONT(name)     { FIELD32(name); }
#define FONTABLE(name) { FIELD32(name); }
#define GCONTEXT(name) { FIELD32(name); }
#define INT8(name)     { FIELD8(name); }
#define INT16(name)    { FIELD16(name); }
#define KEYCODE(name)  { FIELD8(name); }
#define LISTofARC(name) { listOfArc(hf_x11_##name, (next_offset - cur_offset) / 12); }
#define LISTofATOM(name, length) { listOfAtom(hf_x11_##name, (length) / 4); }
#define LISTofBYTE(name, length) { listOfByte(hf_x11_##name, (length)); }
#define LISTofCARD8(name, length) { listOfByte(hf_x11_##name, (length)); }
#define LISTofCARD32(name, length) { listOfCard32(hf_x11_##name, hf_x11_##name##_item, (length) / 4); }
#define LISTofCOLORITEM(name, length) { listOfColorItem(hf_x11_##name, (length) / 12); }
#define LISTofKEYCODE(name, length) { listOfKeycode(hf_x11_##name, (length)); }
#define LISTofKEYSYM(name, keycode_count, keysyms_per_keycode) { \
      listOfKeysyms(hf_x11_##name, hf_x11_##name##_item, (keycode_count), (keysyms_per_keycode)); }
#define LISTofPOINT(name, length) { listOfPoint(hf_x11_##name, (length) / 4); }
#define LISTofRECTANGLE(name) { listOfRectangle(hf_x11_##name, (next_offset - cur_offset) / 8); }
#define LISTofSEGMENT(name) { listOfSegment(hf_x11_##name, (next_offset - cur_offset) / 8); }
#define LISTofSTRING8(name, length) { listOfString8(hf_x11_##name, hf_x11_##name##_string, (length)); }
#define LISTofTEXTITEM8(name) { listOfTextItem(hf_x11_##name, FALSE); }
#define LISTofTEXTITEM16(name) { listOfTextItem(hf_x11_##name, TRUE); }
#define OPCODE()       { opcode = FIELD8(opcode); }
#define PIXMAP(name)   { FIELD32(name); }
#define REQUEST_LENGTH() (requestLength())
#define SETofEVENT(name) { setOfEvent(); }
#define SETofDEVICEEVENT(name) { setOfDeviceEvent();}
#define SETofKEYMASK(name) { setOfKeyMask(); }
#define SETofPOINTEREVENT(name) { setOfPointerEvent(); }
#define STRING8(name, length)  { string8(#name, hf_x11_##name, length); }
#define STRING16(name, length)  { string16(hf_x11_##name, hf_x11_##name##_bytes, length); }
#define TIMESTAMP(name){ timestamp(#name, hf_x11_##name); }
#define UNDECODED(x)   { proto_tree_add_item(t, hf_x11_undecoded, tvb, cur_offset,  x, little_endian); p += x; }
#define UNUSED(x)      { proto_tree_add_item(t, hf_x11_unused, tvb, cur_offset,  x, little_endian); cur_offset += x; }
#define PAD()          { if (next_offset - cur_offset > 0) proto_tree_add_item(t, hf_x11_unused, tvb, cur_offset, next_offset - cur_offset, little_endian); cur_offset = next_offset; }
#define WINDOW(name)   { FIELD32(name); }
#define WINGRAVITY(name) { gravity(#name, hf_x11_##name, "Unmap"); }

#define VISUALID(name) { gint32 v = VALUE32(tvb, cur_offset); \
    proto_tree_add_uint_format(t, hf_x11_##name, tvb, cur_offset, 4, v, "Visualid: 0x%08x%s", v, \
			       v ? "" : " (CopyFromParent)"); cur_offset += 4; }

/************************************************************************
 ***                                                                  ***
 ***                  D E C O D I N G   F I E L D S                   ***
 ***                                                                  ***
 ************************************************************************/

static void atom(proto_tree *t, int hf)
{
      const char *interpretation = NULL;

      guint32 v = VALUE32(tvb, cur_offset);
      if (v >= 1 && v < array_length(atom_predefined_interpretation))
	    interpretation = atom_predefined_interpretation[v];
      else if (v)
	    interpretation = "Not a predefined atom";
      else {
	    struct header_field_info *hfi = proto_registrar_get_nth(hf);
	    if (hfi -> strings)
		  interpretation = match_strval(v, cVALS(hfi -> strings));
      }
      if (!interpretation) interpretation = "error in Xlib client program ?";
      proto_tree_add_uint_format(t, hf, tvb, cur_offset, 4, v, "%s: %d (%s)", 
				 proto_registrar_get_nth(hf) -> name, v, interpretation);
      cur_offset += 4;
}

static void bitmask(int hf, int size)
{
      lastMask._value = size == 2 ? VALUE16(tvb, cur_offset) : VALUE32(tvb, cur_offset);
      lastMask._offset = cur_offset;
      lastMask._zone = size;
      lastMask._tree = proto_tree_add_uint(t, hf, tvb, cur_offset, size, lastMask._value);
      cur_offset += size; 
}

static guint32 boolean(const char *nameAsChar, int hf)
{
      guint32 v = VALUE8(tvb, cur_offset);
      proto_tree_add_boolean(t, hf, tvb, cur_offset, 1, v);
      cur_offset += 1;
      return v;
}

static void colorFlags(proto_tree *t)
{
      unsigned do_red_green_blue = VALUE8(tvb, cur_offset);
      proto_tree *tt;
      
      if (do_red_green_blue) {
	    int sep = FALSE;
	    char buffer[512];
	    char *bp = buffer + sprintf(buffer, "flags: ");

	    if (do_red_green_blue & 0x1) {
		  bp += sprintf(bp, "DoRed");
		  sep = TRUE;
	    }

	    if (do_red_green_blue & 0x2) {
		  if (sep) bp += sprintf(bp, " | ");
		  bp += sprintf(bp, "DoGreen");
		  sep = TRUE;
	    }

	    if (do_red_green_blue & 0x4) {
		  if (sep) bp += sprintf(bp, " | ");
		  bp += sprintf(bp, "DoBlue");
		  sep = TRUE;
	    }

	    if (do_red_green_blue & 0xf8) {
		  if (sep) bp += sprintf(bp, " + ");
		  sprintf(bp, "trash");
	    }

	    tt = proto_tree_add_uint_format(t, hf_x11_coloritem_flags, tvb, cur_offset, 1, do_red_green_blue,
					    "%s", buffer);
	    if (do_red_green_blue & 0x1)
		  proto_tree_add_boolean(tt, hf_x11_coloritem_flags_do_red, tvb, cur_offset, 1, 
					 do_red_green_blue & 0x1);
	    if (do_red_green_blue & 0x2)
		  proto_tree_add_boolean(tt, hf_x11_coloritem_flags_do_green, tvb, cur_offset, 1, 
					 do_red_green_blue & 0x2);
	    if (do_red_green_blue & 0x4)
		  proto_tree_add_boolean(tt, hf_x11_coloritem_flags_do_blue, tvb, cur_offset, 1, 
					 do_red_green_blue & 0x4);
	    if (do_red_green_blue & 0xf8)
		  proto_tree_add_boolean(tt, hf_x11_coloritem_flags_unused, tvb, cur_offset, 1, 
					 do_red_green_blue & 0xf8);
      } else
	    proto_tree_add_uint_format(t, hf_x11_coloritem_flags, tvb, cur_offset, 1, do_red_green_blue,
				       "flags: none");
      cur_offset++;
}

static void gravity(const char *nameAsChar, int hf, const char *nullInterpretation)
{
      guint8 v = VALUE8(tvb, cur_offset);
      if (!v)
	    proto_tree_add_uint_format(t, hf, tvb, cur_offset, 1, v, "%s: 0 (%s)", nameAsChar, 
				       nullInterpretation);
      else
	    proto_tree_add_uint(t, hf, tvb, cur_offset, 1, v);
      cur_offset += 1;
}

static void listOfArc(int hf, int length)
{
      proto_tree *tt = proto_tree_add_item(t, hf, tvb, cur_offset, length * 8, little_endian);
      while(length--) {
	    gint16 x = VALUE16(tvb, cur_offset);
	    gint16 y = VALUE16(tvb, cur_offset + 2);
	    guint16 width = VALUE16(tvb, cur_offset + 4);
	    guint16 height = VALUE16(tvb, cur_offset + 6);
	    gint16 angle1 = VALUE16(tvb, cur_offset + 8);
	    gint16 angle2 = VALUE16(tvb, cur_offset + 10);

	    proto_tree *ttt = proto_tree_add_protocol_format(tt, hf_x11_arc, tvb, cur_offset, 12, 
							     "arc: %dx%d%+d%+d, angle %d -> %d (%f° -> %f°)",
							     width, height, x, y, angle1, angle2,
							     angle1 / 64.0, angle2 / 64.0);
	    proto_tree_add_int(ttt, hf_x11_arc_x, tvb, cur_offset, 2, x); cur_offset += 2;
	    proto_tree_add_int(ttt, hf_x11_arc_y, tvb, cur_offset, 2, y); cur_offset += 2;
	    proto_tree_add_uint(ttt, hf_x11_arc_width, tvb, cur_offset, 2, y); cur_offset += 2;
	    proto_tree_add_uint(ttt, hf_x11_arc_height, tvb, cur_offset, 2, y); cur_offset += 2;
	    proto_tree_add_int(ttt, hf_x11_arc_angle1, tvb, cur_offset, 2, y); cur_offset += 2;
	    proto_tree_add_int(ttt, hf_x11_arc_angle2, tvb, cur_offset, 2, y); cur_offset += 2;
      }
}

static void listOfAtom(int hf, int length)
{
      proto_tree *tt = proto_tree_add_item(t, hf, tvb, cur_offset, length * 4, little_endian);
      while(length--) {
	    if (cur_offset + 4 > next_offset) {
		/* List runs past end of message. */
		return;
	    }
	    atom(tt, hf_x11_properties_item);
      }
}

static void listOfByte(int hf, int length)
{
      if (cur_offset + length > next_offset) {
	    /* List runs past end of message. */
	    length = next_offset -  cur_offset;
      }
      if (length <= 0) length = 1;
      proto_tree_add_bytes(t, hf, tvb, cur_offset, length, tvb_get_ptr(tvb, cur_offset, length));
      cur_offset += length;
}

static void listOfCard32(int hf, int hf_item, int length)
{
      proto_tree *tt = proto_tree_add_item(t, hf, tvb, cur_offset, length * 4, little_endian);
      while(length--) {
	    if (cur_offset + 4 > next_offset) {
		/* List runs past end of message. */
		return;
	    }
	    proto_tree_add_uint(tt, hf_item, tvb, cur_offset, 4, VALUE32(tvb, cur_offset));
	    cur_offset += 4;
      }
}

static void listOfColorItem(int hf, int length)
{
      proto_tree *tt = proto_tree_add_item(t, hf, tvb, cur_offset, length * 8, little_endian);
      while(length--) {
	    proto_tree *ttt;
	    unsigned do_red_green_blue;
	    guint16 red, green, blue;
	    char buffer[1024];
	    char *bp;
	    const char *sep;

	    if (cur_offset + 12 > next_offset) {
		/* List runs past end of message. */
		return;
	    }
	    red = VALUE16(tvb, cur_offset + 4);
	    green = VALUE16(tvb, cur_offset + 6);
	    blue = VALUE16(tvb, cur_offset + 8);
	    do_red_green_blue = VALUE8(tvb, cur_offset + 10);

	    bp = buffer + sprintf(buffer, "colorItem: ");
	    sep = "";
	    if (do_red_green_blue & 0x1) { bp += sprintf(bp, "red = %d", red); sep = ", "; }
	    if (do_red_green_blue & 0x2) { bp += sprintf(bp, "%sgreen = %d", sep, green); sep = ", "; }
	    if (do_red_green_blue & 0x4) bp += sprintf(bp, "%sblue = %d", sep, blue);

	    ttt = proto_tree_add_protocol_format(tt, hf_x11_coloritem, tvb, cur_offset, 12, "%s", buffer);
	    proto_tree_add_item(ttt, hf_x11_coloritem_pixel, tvb, cur_offset, 4, little_endian); cur_offset += 4;
	    proto_tree_add_item(ttt, hf_x11_coloritem_red, tvb, cur_offset, 2, little_endian); cur_offset += 2;
	    proto_tree_add_item(ttt, hf_x11_coloritem_green, tvb, cur_offset, 2, little_endian); cur_offset += 2;
	    proto_tree_add_item(ttt, hf_x11_coloritem_blue, tvb, cur_offset, 2, little_endian); cur_offset += 2;
	    colorFlags(ttt);
	    proto_tree_add_item(ttt, hf_x11_coloritem_unused, tvb, cur_offset, 1, little_endian); cur_offset++;
      }
}

static GTree *keysymTable = NULL;

static gint compareGuint32(gconstpointer a, gconstpointer b)
{
      return GPOINTER_TO_INT(b) - GPOINTER_TO_INT(a);;
}

static const char *keysymString(guint32 v)
{
      gpointer res;
      if (!keysymTable) {

            /* This table is so big that we built it only if necessary */

	    const value_string *p = keysym_vals_source;
	    keysymTable = g_tree_new(compareGuint32);
	    for(; p -> strptr; p++)
		  g_tree_insert(keysymTable, GINT_TO_POINTER(p -> value), p -> strptr);
      }
      res = g_tree_lookup(keysymTable, GINT_TO_POINTER(v));
      return res ? res : "Unknown";
}

static const char *modifiers[] = { "Shift", "Lock", "Control", "Mod1", "Mod2", "Mod3", "Mod4", "Mod5" };

static void listOfKeycode(int hf, int length)
{
      char buffer[1024];
      proto_tree *tt = proto_tree_add_item(t, hf, tvb, cur_offset, length * 8, little_endian);

      while(length--) {
	    char *bp = buffer;
	    const char **m;
	    int i;

	    if (cur_offset + 8 > next_offset) {
		/* List runs past end of message. */
		return;
	    }
	    for(i = 8, m = modifiers; i; i--, m++) {
		  u_char c = tvb_get_guint8(tvb, cur_offset);
		  cur_offset++;
		  if (c) bp += sprintf(bp, "  %s=%d", *m, c);
	    }

	    proto_tree_add_bytes_format(tt, hf_x11_keycodes_item, tvb, cur_offset - 8, 8, tvb_get_ptr(tvb, cur_offset - 8, 8),	"item: %s", buffer);
      }
}

static void listOfKeysyms(int hf, int hf_item, int keycode_count, int keysyms_per_keycode)
{
      proto_tree *tt = proto_tree_add_item(t, hf, tvb, cur_offset, keycode_count * keysyms_per_keycode * 4, little_endian);
      proto_tree *ttt;
      int i;
      char buffer[128];
      char *bp;

      while(keycode_count--) {
	    if (cur_offset + keysyms_per_keycode * 4 > next_offset) {
		/* List runs past end of message. */
		return;
	    }
	    bp = buffer + sprintf(buffer, "keysyms:");
	    for(i = 0; i < keysyms_per_keycode; i++) {
		  bp += sprintf(bp, " %s", keysymString(VALUE32(tvb, cur_offset + i * 4)));
	    }
	    *bp = '\0';
	    ttt = proto_tree_add_protocol_format(tt, hf_item, tvb, cur_offset, keysyms_per_keycode * 4,
						 "%s", buffer);
	    for(i = keysyms_per_keycode; i; i--) {
		  guint32 v = VALUE32(tvb, cur_offset);
		  proto_tree_add_uint_format(ttt, hf_x11_keysyms_item_keysym, tvb, cur_offset, 4, v,
					     "keysym: 0x%08x (%s)", v, keysymString(v));
		  cur_offset += 4;
	    }
      }
}

static void listOfPoint(int hf, int length)
{
      proto_tree *tt = proto_tree_add_item(t, hf, tvb, cur_offset, length * 4, little_endian);
      while(length--) {
	    gint16 x, y;
	    proto_tree *ttt;

	    if (cur_offset + 4 > next_offset) {
		/* List runs past end of message. */
		return;
	    }
	    x = VALUE16(tvb, cur_offset);
	    y = VALUE16(tvb, cur_offset + 2);

	    ttt = proto_tree_add_protocol_format(tt, hf_x11_point, tvb, cur_offset, 4, "point: (%d,%d)", x, y);
	    proto_tree_add_int(ttt, hf_x11_point_x, tvb, cur_offset, 2, x); cur_offset += 2;
	    proto_tree_add_int(ttt, hf_x11_point_y, tvb, cur_offset, 2, y); cur_offset += 2;
      }
}

static void listOfRectangle(int hf, int length)
{
      proto_tree *tt = proto_tree_add_item(t, hf, tvb, cur_offset, length * 8, little_endian);
      while(length--) {
	    gint16 x, y;
	    unsigned width, height;
	    proto_tree *ttt;

	    if (cur_offset + 8 > next_offset) {
		/* List runs past end of message. */
		return;
	    }
	    x = VALUE16(tvb, cur_offset);
	    y = VALUE16(tvb, cur_offset + 2);
	    width = VALUE16(tvb, cur_offset + 4);
	    height = VALUE16(tvb, cur_offset + 6);

	    ttt = proto_tree_add_protocol_format(tt, hf_x11_rectangle, tvb, cur_offset, 8, 
						 "rectangle: %dx%d%+d%+d", width, height, x, y);
	    proto_tree_add_int(ttt, hf_x11_rectangle_x, tvb, cur_offset, 2, x); cur_offset += 2;
	    proto_tree_add_int(ttt, hf_x11_rectangle_y, tvb, cur_offset, 2, y); cur_offset += 2;
	    proto_tree_add_uint(ttt, hf_x11_rectangle_width, tvb, cur_offset, 2, width); cur_offset += 2;
	    proto_tree_add_uint(ttt, hf_x11_rectangle_height, tvb, cur_offset, 2, height); cur_offset += 2;
      }
}

static void listOfSegment(int hf, int length)
{
      proto_tree *tt = proto_tree_add_item(t, hf, tvb, cur_offset, length * 8, little_endian);
      while(length--) {
	    gint16 x1, y1, x2, y2;
	    proto_tree *ttt;

	    if (cur_offset + 8 > next_offset) {
		/* List runs past end of message. */
		return;
	    }
	    x1 = VALUE16(tvb, cur_offset);
	    y1 = VALUE16(tvb, cur_offset + 2);
	    x2 = VALUE16(tvb, cur_offset + 4);
	    y2 = VALUE16(tvb, cur_offset + 6);

	    ttt = proto_tree_add_protocol_format(tt, hf_x11_segment, tvb, cur_offset, 8, 
						 "segment: (%d,%d)-(%d,%d)", x1, y1, x2, y2);
	    proto_tree_add_item(ttt, hf_x11_segment_x1, tvb, cur_offset, 2, little_endian); cur_offset += 2;
	    proto_tree_add_item(ttt, hf_x11_segment_y1, tvb, cur_offset, 2, little_endian); cur_offset += 2;
	    proto_tree_add_item(ttt, hf_x11_segment_x2, tvb, cur_offset, 2, little_endian); cur_offset += 2;
	    proto_tree_add_item(ttt, hf_x11_segment_y2, tvb, cur_offset, 2, little_endian); cur_offset += 2;
      }
}

/* XXX - the protocol tree code should handle non-printable characters.
   Note that "non-printable characters" may depend on your locale.... */
static void stringCopy(char *dest, const char *source, int length)
{
      u_char c;
      while(length--) {
	    c = *source++;
	    if (!isgraph(c) && c != ' ') c = '.';
	    *dest++ = c;
      }
      *dest++ = '\0';
}

static void listOfString8(int hf, int hf_item, int length)
{
      char *s = NULL;
      int allocated = 0;
      proto_tree *tt;
      int i;

      /* Compute total length */
      
      int scanning_offset = cur_offset; /* Scanning pointer */
      int l;
      for(i = length; i; i--) {
	    l = tvb_get_guint8(tvb, scanning_offset);
	    scanning_offset += 1 + l;
      }

      tt = proto_tree_add_item(t, hf, tvb, cur_offset, scanning_offset - cur_offset, little_endian);

      while(length--) {
	    unsigned l = VALUE8(tvb, cur_offset);
	    if (allocated < l + 1) {
		  /* g_realloc doesn't work ??? */
		  g_free(s);
		  s = g_malloc(l + 1);
		  allocated = l + 1;
	    }
	    stringCopy(s, tvb_get_ptr(tvb, cur_offset + 1, l), l); /* Nothing better for now. We need a better string handling API. */
	    proto_tree_add_string_format(tt, hf_item, tvb, cur_offset, l + 1, s, "\"%s\"", s);
	    cur_offset += l + 1;
      }
      g_free(s);
}

#define STRING16_MAX_DISPLAYED_LENGTH 150

static int stringIsActuallyAn8BitString(int offset, unsigned length)
{
      if (length > STRING16_MAX_DISPLAYED_LENGTH) length = STRING16_MAX_DISPLAYED_LENGTH;
      for(; length > 0; cur_offset += 2, length--) {
	    if (tvb_get_guint8(tvb, cur_offset))
		return FALSE;
      }
      return TRUE;
}

/* length is the length of the _byte_zone_ (that is, twice the length of the string) */

static void string16_with_buffer_preallocated(proto_tree *t, int hf, int hf_bytes,
					      int offset, unsigned length,
					      char **s, int *sLength)
{
      int truncated = FALSE;
      unsigned l = length / 2;

      if (stringIsActuallyAn8BitString(offset, l)) {
	    char *dp;
	    int soffset = offset;

	    if (l > STRING16_MAX_DISPLAYED_LENGTH) {
		  truncated = TRUE;
		  l = STRING16_MAX_DISPLAYED_LENGTH;
	    }
	    if (*sLength < l + 3) {
		  g_free(*s);
		  *s = g_malloc(l + 3);
		  *sLength = l + 3;
	    }
	    dp = *s;
	    *dp++ = '"';
	    if (truncated) l -= 3;

	    while(l--) {
		  soffset++;
		  *dp++ = tvb_get_guint8(tvb, soffset);
		  soffset++;
	    }
	    *dp++ = '"';

	    /* If truncated, add an ellipsis */
	    if (truncated) { *dp++ = '.'; *dp++ = '.'; *dp++ = '.'; }

	    *dp++ = '\0';
	    proto_tree_add_string_format(t, hf, tvb, offset, length, tvb_get_ptr(tvb, offset, length), "%s: %s", 
					proto_registrar_get_nth(hf) -> name, *s);
      } else
	    proto_tree_add_bytes(t, hf_bytes, tvb, offset, length, tvb_get_ptr(tvb, offset, length));

}

static void listOfTextItem(int hf, int sizeIs16)
{
      int allocated = 0;
      char *s = NULL;
      proto_tree *tt;
      guint32 fid;

      /* Compute total length */
      
      int scanning_offset = cur_offset; /* Scanning pointer */
      int l;                            /* Length of an individual item */
      int n = 0;                        /* Number of items */

      while(scanning_offset < next_offset) {
	    l = tvb_get_guint8(tvb, scanning_offset);
	    scanning_offset++;
	    if (!l) break;
	    n++;
	    scanning_offset += l == 255 ? 4 : l + (sizeIs16 ? l : 0) + 1;
      }

      tt = proto_tree_add_item(t, hf, tvb, cur_offset, scanning_offset - cur_offset, little_endian);

      while(n--) {
	    unsigned l = VALUE8(tvb, cur_offset);
	    if (l == 255) { /* Item is a font */
		  fid = tvb_get_ntohl(tvb, cur_offset + 1);
		  proto_tree_add_uint(tt, hf_x11_textitem_font, tvb, cur_offset, 5, fid);
		  cur_offset += 5;
	    } else { /* Item is a string */
		  proto_tree *ttt;
		  gint8 delta = VALUE8(tvb, cur_offset + 1);
		  if (sizeIs16) l += l;
		  if (allocated < l + 1) {
			/* g_realloc doesn't work ??? */
			g_free(s);
			s = g_malloc(l + 1);
			allocated = l + 1;
		  }
		  stringCopy(s, tvb_get_ptr(tvb, cur_offset + 2, l), l);
		  ttt = proto_tree_add_protocol_format(tt, hf_x11_textitem_string, tvb, cur_offset, l + 2,
						       "textitem (string): delta = %d, \"%s\"",
						       delta, s);
		  proto_tree_add_item(ttt, hf_x11_textitem_string_delta, tvb, cur_offset + 1, 1, little_endian);
		  if (sizeIs16)
			string16_with_buffer_preallocated(ttt, hf_x11_textitem_string_string16, 
							  hf_x11_textitem_string_string16_bytes,
							  cur_offset + 2, l,
							   &s, &allocated);
		  else
			proto_tree_add_string_format(ttt, hf_x11_textitem_string_string8, tvb, 
						     cur_offset + 2, l, s, "\"%s\"", s);
		  cur_offset += l + 2;
	    }
      }
      g_free(s);
}

static guint32 field8(int hf)
{
      guint32 v = VALUE8(tvb, cur_offset);
      struct header_field_info *hfi = proto_registrar_get_nth(hf);
      gchar *enumValue = NULL;
      gchar *nameAsChar = hfi -> name;

      if (hfi -> strings)
	    enumValue = match_strval(v, cVALS(hfi -> strings));
      if (enumValue)
	    proto_tree_add_uint_format(t, hf, tvb, cur_offset, 1, v, "%s: %d (%s)", nameAsChar, v, enumValue);
      else
	    proto_tree_add_item(t, hf, tvb, cur_offset, 1, little_endian);
      cur_offset += 1;
      return v;
}

static guint32 field16(int hf)
{
      guint32 v = VALUE16(tvb, cur_offset);
      proto_tree_add_item(t, hf, tvb, cur_offset, 2, v);
      cur_offset += 2;
      return v;
}

static guint32 field32(int hf)
{
      guint32 v = VALUE32(tvb, cur_offset);
      struct header_field_info *hfi = proto_registrar_get_nth(hf);
      gchar *enumValue = NULL;
      gchar *nameAsChar = hfi -> name;

      if (hfi -> strings)
	    enumValue = match_strval(v, cVALS(hfi -> strings));
      if (enumValue)
	    proto_tree_add_uint_format(t, hf, tvb, cur_offset, 4, v, "%s: 0x%08x (%s)", nameAsChar, v, enumValue);
      else
	    proto_tree_add_uint_format(t, hf, tvb, cur_offset, 4, v, 
				       hfi -> display == BASE_DEC ? "%s: %d" : "%s : 0x%08x",
				       nameAsChar, v);
      cur_offset += 4;
      return v;
}

static void gcAttributes(void)
{
      BITMASK32(gc_value);
      BITFIELD(ENUM8,  gc_value_mask, function);
      BITFIELD(CARD32, gc_value_mask, plane_mask);
      BITFIELD(CARD32, gc_value_mask, foreground);
      BITFIELD(CARD32, gc_value_mask, background);
      BITFIELD(CARD16, gc_value_mask, line_width);
      BITFIELD(ENUM8,  gc_value_mask, line_style);
      BITFIELD(ENUM8,  gc_value_mask, cap_style);
      BITFIELD(ENUM8,  gc_value_mask, join_style);
      BITFIELD(ENUM8,  gc_value_mask, fill_style);
      BITFIELD(ENUM8,  gc_value_mask, fill_rule);
      BITFIELD(PIXMAP, gc_value_mask, tile);
      BITFIELD(PIXMAP, gc_value_mask, stipple);
      BITFIELD(INT16,  gc_value_mask, tile_stipple_x_origin);
      BITFIELD(INT16,  gc_value_mask, tile_stipple_y_origin);
      BITFIELD(FONT,   gc_value_mask, font);
      BITFIELD(ENUM8,  gc_value_mask, subwindow_mode);
      BITFIELD(BOOL,   gc_value_mask, graphics_exposures);
      BITFIELD(INT16,  gc_value_mask, clip_x_origin);
      BITFIELD(INT16,  gc_value_mask, clip_y_origin);
      BITFIELD(PIXMAP, gc_value_mask, clip_mask);
      BITFIELD(CARD16, gc_value_mask, dash_offset);
      BITFIELD(CARD8,  gc_value_mask, gc_dashes);
      BITFIELD(ENUM8,  gc_value_mask, arc_mode);
}

static void gcMask(void)
{
      BITMASK32(gc_value);
      FLAG(gc_value, function);
      FLAG(gc_value, plane_mask);
      FLAG(gc_value, foreground);
      FLAG(gc_value, background);
      FLAG(gc_value, line_width);
      FLAG(gc_value, line_style);
      FLAG(gc_value, cap_style);
      FLAG(gc_value, join_style);
      FLAG(gc_value, fill_style);
      FLAG(gc_value, fill_rule);
      FLAG(gc_value, tile);
      FLAG(gc_value, stipple);
      FLAG(gc_value, tile_stipple_x_origin);
      FLAG(gc_value, tile_stipple_y_origin);
      FLAG(gc_value, font);
      FLAG(gc_value, subwindow_mode);
      FLAG(gc_value, graphics_exposures);
      FLAG(gc_value, clip_x_origin);
      FLAG(gc_value, clip_y_origin);
      FLAG(gc_value, clip_mask);
      FLAG(gc_value, dash_offset);
      FLAG(gc_value, gc_dashes);
      FLAG(gc_value, arc_mode);
}

static guint32 requestLength(void)
{
      guint32 res = VALUE16(tvb, cur_offset) * 4;
      proto_tree_add_uint(t, hf_x11_request_length, tvb, cur_offset, 2, res);
      cur_offset += 2;
      return res;
}

static void setOfEvent(void)
{
      struct maskStruct save = lastMask;
      BITMASK32(event);
      FLAG(event, KeyPress);
      FLAG(event, KeyRelease);
      FLAG(event, ButtonPress);
      FLAG(event, ButtonRelease);
      FLAG(event, EnterWindow);
      FLAG(event, LeaveWindow);
      FLAG(event, PointerMotion);
      FLAG(event, PointerMotionHint);
      FLAG(event, Button1Motion);
      FLAG(event, Button2Motion);
      FLAG(event, Button3Motion);
      FLAG(event, Button4Motion);
      FLAG(event, Button5Motion);
      FLAG(event, ButtonMotion);
      FLAG(event, KeymapState);
      FLAG(event, Exposure);
      FLAG(event, VisibilityChange);
      FLAG(event, StructureNotify);
      FLAG(event, ResizeRedirect);
      FLAG(event, SubstructureNotify);
      FLAG(event, SubstructureRedirect);
      FLAG(event, FocusChange);
      FLAG(event, PropertyChange);
      FLAG(event, ColormapChange);
      FLAG(event, OwnerGrabButton);
      FLAG(event, erroneous_bits);
      lastMask = save;
}

static void setOfDeviceEvent(void)
{
      struct maskStruct save = lastMask;
      BITMASK32(do_not_propagate);
      FLAG(do_not_propagate, KeyPress);
      FLAG(do_not_propagate, KeyRelease);
      FLAG(do_not_propagate, ButtonPress);
      FLAG(do_not_propagate, ButtonRelease);
      FLAG(do_not_propagate, PointerMotion);
      FLAG(do_not_propagate, Button1Motion);
      FLAG(do_not_propagate, Button2Motion);
      FLAG(do_not_propagate, Button3Motion);
      FLAG(do_not_propagate, Button4Motion);
      FLAG(do_not_propagate, Button5Motion);
      FLAG(do_not_propagate, ButtonMotion);
      FLAG(do_not_propagate, erroneous_bits);
      lastMask = save;
}

static void setOfKeyMask(void)
{
      struct maskStruct save = lastMask;
      lastMask._value = VALUE16(tvb, cur_offset);
      lastMask._offset = cur_offset;
      lastMask._zone = 2;
      if (lastMask._value == 0x8000)
	    proto_tree_add_uint_format(t, hf_x11_modifiers_mask_AnyModifier, tvb, cur_offset, 2, 0x8000,
				       "modifiers-masks: 0x8000 (AnyModifier)");
      else {
	    lastMask._tree = proto_tree_add_uint(t, hf_x11_modifiers_mask, tvb, cur_offset, 2, 
						 lastMask._value);
	    FLAG(modifiers, Shift);
	    FLAG(modifiers, Lock);
	    FLAG(modifiers, Control);
	    FLAG(modifiers, Mod1);
	    FLAG(modifiers, Mod2);
	    FLAG(modifiers, Mod3);
	    FLAG(modifiers, Mod4);
	    FLAG(modifiers, Mod5);
	    FLAG(modifiers, erroneous_bits);
      }
      lastMask = save;
      cur_offset += 2; 
}

static void setOfPointerEvent(void)
{
      struct maskStruct save = lastMask;
      BITMASK16(pointer_event);
      FLAG(pointer_event, ButtonPress);
      FLAG(pointer_event, ButtonRelease);
      FLAG(pointer_event, EnterWindow);
      FLAG(pointer_event, LeaveWindow);
      FLAG(pointer_event, PointerMotion);
      FLAG(pointer_event, PointerMotionHint);
      FLAG(pointer_event, Button1Motion);
      FLAG(pointer_event, Button2Motion);
      FLAG(pointer_event, Button3Motion);
      FLAG(pointer_event, Button4Motion);
      FLAG(pointer_event, Button5Motion);
      FLAG(pointer_event, ButtonMotion);
      FLAG(pointer_event, KeymapState);
      FLAG(pointer_event, erroneous_bits);
      lastMask = save;
}

static void string8(const char *nameAsChar, int hf, unsigned length)
{
      char *s = g_malloc(length + 1);
      stringCopy(s, tvb_get_ptr(tvb, cur_offset, length), length);
      proto_tree_add_string_format(t, hf, tvb, cur_offset, length, s, "%s: %s", nameAsChar, s);
      g_free(s);
      cur_offset += length;
}

/* The length is the length of the _byte_zone_ (twice the length of the string) */

static void string16(int hf, int hf_bytes, unsigned length)
{
      char *s = NULL;
      unsigned l = 0;
      length += length;
      string16_with_buffer_preallocated(t, hf, hf_bytes, cur_offset, length, &s, &l);
      g_free(s);
      cur_offset += length;
}

static void timestamp(const char *nameAsChar, int hf)
{
      guint32 v = VALUE32(tvb, cur_offset);
      if (!v)
	    proto_tree_add_uint_format(t, hf, tvb, cur_offset, 4, 0, "%s: 0 (CurrentTime)", nameAsChar);
      else
	    proto_tree_add_uint(t, hf, tvb, cur_offset, 4, v);
      cur_offset += 4;
}

static void windowAttributes(void)
{
      BITMASK32(window_value);
      BITFIELD(PIXMAP, window_value_mask, background_pixmap);
      BITFIELD(CARD32, window_value_mask, background_pixel);
      BITFIELD(PIXMAP, window_value_mask, border_pixmap);
      BITFIELD(CARD32, window_value_mask, border_pixel);
      BITFIELD(BITGRAVITY, window_value_mask, bit_gravity);
      BITFIELD(WINGRAVITY, window_value_mask, win_gravity);
      BITFIELD(ENUM8, window_value_mask, backing_store);
      BITFIELD(CARD32, window_value_mask, backing_planes);
      BITFIELD(CARD32, window_value_mask, backing_pixel);
      BITFIELD(BOOL,   window_value_mask, override_redirect);
      BITFIELD(BOOL,   window_value_mask, save_under);
      BITFIELD(SETofEVENT, window_value_mask, event_mask);
      BITFIELD(SETofDEVICEEVENT, window_value_mask, do_not_propagate_mask);
      BITFIELD(COLORMAP, window_value_mask, colormap);
      BITFIELD(CURSOR, window_value_mask, cursor);
}

/************************************************************************
 ***                                                                  ***
 ***              D E C O D I N G   O N E   P A C K E T               ***
 ***                                                                  ***
 ************************************************************************/

static int dissect_x11_request_loop(proto_tree *root)
{
      int left = tvb_reported_length(tvb), nextLeft;
      proto_item *ti;
      guint8 v8, v8_2;
      guint16 v16;
      guint32 v32;

      /* The X11 data stream to the server is just a sequence of requests,
         each of which contains a length; for now, we dissect all the
	 requests in this frame until we run out of data in the frame.
	 Eventually, we should handle requests that cross frame
	 boundaries.

	 Note that "in this frame" refers to everything in the frame
	 as it appeared in the wire, not as it was captured; we want
	 an exception to be thrown if we go past the end of the
	 captured data in the frame without going past the end of the
	 data in the frame. */
      for(;;) {
	    int length, opcode;
	    
	    /* fprintf(stderr, "Starting loop, left = %d, cur_offset = %d\n", left, cur_offset); */
	    if (left < 4) {
		/* We ran out of data - we don't have enough data in
		   the frame to get the length of this request. */
		break;
	    }
	    length = VALUE16(tvb, cur_offset + 2) * 4;
	    /*	    fprintf(stderr, "length = %d\n", length);*/
	    if (left < length) {
		/* We ran out of data - we don't have enough data in
		   the frame for the full request. */
		break;
	    }
	    if (length < 4) {
	    	/* Bogus message length? */
		break;
	    }

	    next_offset = cur_offset + length;
	    nextLeft = left - length;

	    ti = proto_tree_add_uint(root, hf_x11_request, tvb, cur_offset, length, tvb_get_guint8(tvb, cur_offset));
	    t = proto_item_add_subtree(ti, ett_x11_request);

	    OPCODE();

	    switch(opcode) {
		case 1: /* CreateWindow */
		  CARD8(depth);
		  REQUEST_LENGTH();
		  WINDOW(wid);
		  WINDOW(parent);
		  INT16(x);
		  INT16(y);
		  CARD16(width);
		  CARD16(height);
		  CARD16(border_width);
		  ENUM16(window_class);
		  VISUALID(visual);
		  windowAttributes();
		  break;

		case 2: /* ChangeWindowAttributes */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  WINDOW(window);
		  windowAttributes();
		  break;

		case 3: /* GetWindowAttributes */
		case 4: /* DestroyWindow */
		case 5: /* DestroySubwindows */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  WINDOW(window);
		  break;

		case 6: /* ChangeSaveSet */
		  ENUM8(save_set_mode);
		  REQUEST_LENGTH();
		  WINDOW(window);
		  break;

		case 7: /* ReparentWindow */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  WINDOW(window);
		  WINDOW(parent);
		  INT16(x);
		  INT16(y);
		  break;

		case 8: /* MapWindow */
		case 9: /* MapSubWindow */
		case 10: /* UnmapWindow */
		case 11: /* UnmapSubwindows */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  WINDOW(window);
		  break;

		case 12: /* ConfigureWindow */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  WINDOW(window);
		  BITMASK16(configure_window);
		  UNUSED(2); 
		  BITFIELD(INT16,  configure_window_mask, x);
		  BITFIELD(INT16,  configure_window_mask, y);
		  BITFIELD(CARD16, configure_window_mask, width);
		  BITFIELD(CARD16, configure_window_mask, height);
		  BITFIELD(CARD16, configure_window_mask, border_width);
		  BITFIELD(WINDOW, configure_window_mask, sibling);
		  BITFIELD(ENUM8,  configure_window_mask, stack_mode);
		  PAD();
		  break;

		case 13: /* CirculateWindow */
		  ENUM8(direction);
		  REQUEST_LENGTH();
		  WINDOW(window);
		  break;

		case 14: /* GetGeometry */
		case 15: /* QueryTree */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  DRAWABLE(drawable);
		  break;

		case 16: /* InternAtom */
		  BOOL(only_if_exists);
		  REQUEST_LENGTH();
		  v16 = FIELD16(name_length);
		  UNUSED(2);
		  STRING8(name, v16);
		  PAD();
		  break;

		case 17: /* GetAtomName */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  ATOM(atom);
		  break;

		case 18: /* ChangeProperty */
		  ENUM8(mode);
		  REQUEST_LENGTH();
		  WINDOW(window);
		  ATOM(property);
		  ATOM(type);
		  CARD8(format);
		  UNUSED(3);
		  v32 = CARD32(data_length);
		  LISTofBYTE(data, v32);
		  PAD();
		  break;

		case 19: /* DeleteProperty */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  WINDOW(window);
		  ATOM(property);
		  break;

		case 20: /* GetProperty */
		  BOOL(delete);
		  REQUEST_LENGTH();
		  WINDOW(window);
		  ATOM(property);
		  ATOM(get_property_type);
		  CARD32(long_offset);
		  CARD32(long_length);
		  break;

		case 21: /* ListProperties */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  WINDOW(window);
		  break;

		case 22: /* SetSelectionOwner */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  WINDOW(owner);
		  ATOM(selection);
		  TIMESTAMP(time);
		  break;

		case 23: /* GetSelectionOwner */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  ATOM(selection);
		  break;

		case 24: /* ConvertSelection */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  WINDOW(requestor);
		  ATOM(selection);
		  ATOM(target);
		  ATOM(property);
		  TIMESTAMP(time);
		  break;

		case 26: /* GrabPointer */
		  BOOL(owner_events);
		  REQUEST_LENGTH();
		  WINDOW(grab_window);
		  SETofPOINTEREVENT(pointer_event_mask);
		  ENUM8(pointer_mode);
		  ENUM8(keyboard_mode);
		  WINDOW(confine_to);
		  CURSOR(cursor);
		  TIMESTAMP(time);
		  break;

		case 27: /* UngrabPointer */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  TIMESTAMP(time);
		  break;

		case 28: /* GrabButton */
		  BOOL(owner_events);
		  REQUEST_LENGTH();
		  WINDOW(grab_window);
		  SETofPOINTEREVENT(event_mask);
		  ENUM8(pointer_mode);
		  ENUM8(keyboard_mode);
		  WINDOW(confine_to);
		  CURSOR(cursor);
		  BUTTON(button);
		  UNUSED(1);
		  SETofKEYMASK(modifiers);
		  break;

		case 29: /* UngrabButton */
		  BUTTON(button);
		  REQUEST_LENGTH();
		  WINDOW(grab_window);
		  SETofKEYMASK(modifiers);
		  UNUSED(2);
		  break;

		case 30: /* ChangeActivePointerGrab */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  CURSOR(cursor);
		  TIMESTAMP(time);
		  SETofPOINTEREVENT(event_mask);
		  UNUSED(2);
		  break;

		case 31: /* GrabKeyboard */
		  BOOL(owner_events);
		  REQUEST_LENGTH();
		  WINDOW(grab_window);
		  TIMESTAMP(time);
		  ENUM8(pointer_mode);
		  ENUM8(keyboard_mode);
		  UNUSED(2);
		  break;

		case 32: /* UngrabKeyboard */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  TIMESTAMP(time);
		  break;

		case 33: /* GrabKey */
		  BOOL(owner_events);
		  REQUEST_LENGTH();
		  WINDOW(grab_window);
		  SETofKEYMASK(modifiers);
		  KEYCODE(key);
		  ENUM8(pointer_mode);
		  ENUM8(keyboard_mode);
		  UNUSED(3);
		  break;

		case 34: /* UngrabKey */
		  KEYCODE(key);
		  REQUEST_LENGTH();
		  WINDOW(grab_window);
		  SETofKEYMASK(modifiers);
		  UNUSED(2);
		  break;

		case 35: /* AllowEvents */
		  ENUM8(allow_events_mode);
		  REQUEST_LENGTH();
		  TIMESTAMP(time);
		  break;

		case 36: /* GrabServer */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  break;

		case 37: /* UngrabServer */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  break;

		case 38: /* QueryPointer */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  WINDOW(window);
		  break;

		case 39: /* GetMotionEvents */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  WINDOW(window);
		  TIMESTAMP(start);
		  TIMESTAMP(stop);
		  break;

		case 40: /* TranslateCoordinates */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  WINDOW(src_window);
		  WINDOW(dst_window);
		  INT16(src_x);
		  INT16(src_y);
		  break;

		case 41: /* WarpPointer */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  WINDOW(warp_pointer_src_window);
		  WINDOW(warp_pointer_dst_window);
		  INT16(src_x);
		  INT16(src_y);
		  CARD16(src_width);
		  CARD16(src_height);
		  INT16(dst_x);
		  INT16(dst_y);
		  break;

		case 42: /* SetInputFocus */
		  ENUM8(revert_to);
		  REQUEST_LENGTH();
		  WINDOW(focus);
		  TIMESTAMP(time);
		  break;

		case 43: /* GetInputFocus */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  break;

		case 44: /* QueryKeymap */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  break;

		case 45: /* OpenFont */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  FONT(fid);
		  v16 = FIELD16(name_length);
		  UNUSED(2);
		  STRING8(name, v16);
		  PAD();
		  break;

		case 46: /* CloseFont */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  FONT(font);
		  break;

		case 47: /* QueryFont */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  FONTABLE(font);
		  break;

		case 48: /* QueryTextExtents */
		  v8 = BOOL(odd_length);
		  REQUEST_LENGTH();
		  FONTABLE(font);
		  STRING16(string16, (next_offset - cur_offset - (v8 ? 2 : 0)) / 2);
		  PAD();
		  break;

		case 49: /* ListFonts */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  CARD16(max_names);
		  v16 = FIELD16(pattern_length);
		  STRING8(pattern, v16);
		  PAD();
		  break;

		case 50: /* ListFontsWithInfo */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  CARD16(max_names);
		  v16 = FIELD16(pattern_length);
		  STRING8(pattern, v16);
		  PAD();
		  break;

		case 51: /* SetFontPath */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  v16 = CARD16(str_number_in_path);
		  UNUSED(2);
		  LISTofSTRING8(path, v16);
		  PAD();
		  break;

		case 52: /* GetFontPath */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  break;

		case 53: /* CreatePixmap */
		  CARD8(depth);
		  REQUEST_LENGTH();
		  PIXMAP(pid);
		  DRAWABLE(drawable);
		  CARD16(width);
		  CARD16(height);
		  break;

		case 54: /* FreePixmap */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  PIXMAP(pixmap);
		  break;

		case 55: /* CreateGC */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  GCONTEXT(cid);
		  DRAWABLE(drawable);
		  gcAttributes();
		  break;

		case 56: /* ChangeGC */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  GCONTEXT(gc);
		  gcAttributes();
		  break;

		case 57: /* CopyGC */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  GCONTEXT(src_gc);
		  GCONTEXT(dst_gc);
		  gcMask();
		  break;

		case 58: /* SetDashes */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  GCONTEXT(gc);
		  CARD16(dash_offset);
		  v16 = FIELD16(dashes_length);
		  LISTofCARD8(dashes, v16);
		  PAD();
		  break;

		case 59: /* SetClipRectangles */
		  ENUM8(ordering);
		  REQUEST_LENGTH();
		  GCONTEXT(gc);
		  INT16(clip_x_origin);
		  INT16(clip_y_origin);
		  LISTofRECTANGLE(rectangles);
		  break;

		case 60: /* FreeGC */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  GCONTEXT(gc);
		  break;

		case 61: /* ClearArea */
		  BOOL(exposures);
		  REQUEST_LENGTH();
		  WINDOW(window);
		  INT16(x);
		  INT16(y);
		  CARD16(width);
		  CARD16(height);
		  break;

		case 62: /* CopyArea */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  DRAWABLE(src_drawable);
		  DRAWABLE(dst_drawable);
		  GCONTEXT(gc);
		  INT16(src_x);
		  INT16(src_y);
		  INT16(dst_x);
		  INT16(dst_y);
		  CARD16(width);
		  CARD16(height);
		  break;

		case 63: /* CopyPlane */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  DRAWABLE(src_drawable);
		  DRAWABLE(dst_drawable);
		  GCONTEXT(gc);
		  INT16(src_x);
		  INT16(src_y);
		  INT16(dst_x);
		  INT16(dst_y);
		  CARD16(width);
		  CARD16(height);
		  CARD32(bit_plane);
		  break;

		case 64: /* PolyPoint */
		  ENUM8(coordinate_mode);
		  v16 = REQUEST_LENGTH();
		  DRAWABLE(drawable);
		  GCONTEXT(gc);
		  LISTofPOINT(points, v16 - 12);
		  break;

		case 65: /* PolyLine */
		  ENUM8(coordinate_mode);
		  v16 = REQUEST_LENGTH();
		  DRAWABLE(drawable);
		  GCONTEXT(gc);
		  LISTofPOINT(points, v16 - 12);
		  break;

		case 66: /* PolySegment */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  DRAWABLE(drawable);
		  GCONTEXT(gc);
		  LISTofSEGMENT(segments);
		  break;

		case 67: /* PolyRectangle */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  DRAWABLE(drawable);
		  GCONTEXT(gc);
		  LISTofRECTANGLE(rectangles);
		  break;

		case 68: /* PolyArc */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  DRAWABLE(drawable);
		  GCONTEXT(gc);
		  LISTofARC(arcs);
		  break;

		case 69: /* FillPoly */
		  UNUSED(1);
		  v16 = REQUEST_LENGTH();
		  DRAWABLE(drawable);
		  GCONTEXT(gc);
		  ENUM8(shape);
		  ENUM8(coordinate_mode);
		  UNUSED(2);
		  LISTofPOINT(points, v16 - 16);
		  break;

		case 70: /* PolyFillRectangle */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  DRAWABLE(drawable);
		  GCONTEXT(gc);
		  LISTofRECTANGLE(rectangles);
		  break;

		case 71: /* PolyFillArc */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  DRAWABLE(drawable);
		  GCONTEXT(gc);
		  LISTofARC(arcs);
		  break;

		case 72: /* PutImage */
		  ENUM8(image_format);
		  v16 = REQUEST_LENGTH();
		  DRAWABLE(drawable);
		  GCONTEXT(gc);
		  CARD16(width);
		  CARD16(height);
		  INT16(dst_x);
		  INT16(dst_y);
		  CARD8(left_pad);
		  CARD8(depth);
		  UNUSED(2);
		  LISTofBYTE(data, v16 - 24);
		  PAD();
		  break;

		case 73: /* GetImage */
		  ENUM8(image_pixmap_format);
		  REQUEST_LENGTH();
		  DRAWABLE(drawable);
		  INT16(x);
		  INT16(y);
		  CARD16(width);
		  CARD16(height);
		  CARD32(plane_mask);
		  break;

		case 74: /* PolyText8 */
		  UNUSED(1);
		  v16 = REQUEST_LENGTH();
		  DRAWABLE(drawable);
		  GCONTEXT(gc);
		  INT16(x);
		  INT16(y);
		  LISTofTEXTITEM8(items);
		  PAD();
		  break;

		case 75: /* PolyText16 */
		  UNUSED(1);
		  v16 = REQUEST_LENGTH();
		  DRAWABLE(drawable);
		  GCONTEXT(gc);
		  INT16(x);
		  INT16(y);
		  LISTofTEXTITEM16(items);
		  PAD();
		  break;

		case 76: /* ImageText8 */
		  v8 = FIELD8(string_length);
		  REQUEST_LENGTH();
		  DRAWABLE(drawable);
		  GCONTEXT(gc);
		  INT16(x);
		  INT16(y);
		  STRING8(string, v8);
		  PAD();
		  break;

		case 77: /* ImageText16 */
		  v8 = FIELD8(string_length);
		  REQUEST_LENGTH();
		  DRAWABLE(drawable);
		  GCONTEXT(gc);
		  INT16(x);
		  INT16(y);
		  STRING16(string16, v8);
		  PAD();
		  break;

		case 78: /* CreateColormap */
		  ENUM8(alloc);
		  REQUEST_LENGTH();
		  COLORMAP(mid);
		  WINDOW(window);
		  VISUALID(visual);
		  break;

		case 79: /* FreeColormap */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  COLORMAP(cmap);
		  break;

		case 80: /* CopyColormapAndFree */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  COLORMAP(mid);
		  COLORMAP(src_cmap);
		  break;

		case 81: /* InstallColormap */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  COLORMAP(cmap);
		  break;

		case 82: /* UninstallColormap */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  COLORMAP(cmap);
		  break;

		case 83: /* ListInstalledColormaps */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  WINDOW(window);
		  break;

		case 84: /* AllocColor */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  COLORMAP(cmap);
		  CARD16(red);
		  CARD16(green);
		  CARD16(blue);
		  UNUSED(2);
		  break;

		case 85: /* AllocNamedColor */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  COLORMAP(cmap);
		  v16 = FIELD16(name_length);
		  UNUSED(2);
		  STRING8(name, v16);
		  PAD();
		  break;

		case 86: /* AllocColorCells */
		  BOOL(contiguous);
		  REQUEST_LENGTH();
		  COLORMAP(cmap);
		  CARD16(colors);
		  CARD16(planes);
		  break;

		case 87: /* AllocColorPlanes */
		  BOOL(contiguous);
		  REQUEST_LENGTH();
		  COLORMAP(cmap);
		  CARD16(colors);
		  CARD16(reds);
		  CARD16(greens);
		  CARD16(blues);
		  break;

		case 88: /* FreeColors */
		  UNUSED(1);
		  v16 = REQUEST_LENGTH();
		  COLORMAP(cmap);
		  CARD32(plane_mask);
		  LISTofCARD32(pixels, v16 - 12);
		  break;

		case 89: /* StoreColors */
		  UNUSED(1);
		  v16 = REQUEST_LENGTH();
		  COLORMAP(cmap);
		  LISTofCOLORITEM(color_items, v16 - 8);
		  break;

		case 90: /* StoreNamedColor */
		  COLOR_FLAGS(color);
		  REQUEST_LENGTH();
		  COLORMAP(cmap);
		  CARD32(pixel);	
		  v16 = FIELD16(name_length);
		  UNUSED(2);
		  STRING8(name, v16);
		  PAD();
		  break;

		case 91: /* QueryColors */
		  UNUSED(1);
		  v16 = REQUEST_LENGTH();
		  COLORMAP(cmap);
		  LISTofCARD32(pixels, v16 - 8);
		  break;

		case 92: /* LookupColor */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  COLORMAP(cmap);
		  v16 = FIELD16(name_length);
		  UNUSED(2);
		  STRING8(name, v16);
		  PAD();
		  break;

		case 93: /* CreateCursor */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  CURSOR(cid);
		  PIXMAP(source_pixmap);
		  PIXMAP(mask);
		  CARD16(fore_red);
		  CARD16(fore_green);
		  CARD16(fore_blue);
		  CARD16(back_red);
		  CARD16(back_green);
		  CARD16(back_blue);
		  CARD16(x);
		  CARD16(y);
		  break;

		case 94: /* CreateGlyphCursor */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  CURSOR(cid);
		  FONT(source_font);
		  FONT(mask_font);
		  CARD16(source_char);
		  CARD16(mask_char);
		  CARD16(fore_red);
		  CARD16(fore_green);
		  CARD16(fore_blue);
		  CARD16(back_red);
		  CARD16(back_green);
		  CARD16(back_blue);
		  break;

		case 95: /* FreeCursor */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  CURSOR(cursor);
		  break;

		case 96: /* RecolorCursor */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  CURSOR(cursor);
		  CARD16(fore_red);
		  CARD16(fore_green);
		  CARD16(fore_blue);
		  CARD16(back_red);
		  CARD16(back_green);
		  CARD16(back_blue);
		  break;

		case 97: /* QueryBestSize */
		  ENUM8(class);
		  REQUEST_LENGTH();
		  DRAWABLE(drawable);
		  CARD16(width);
		  CARD16(height);
		  break;

		case 98: /* QueryExtension */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  v16 = FIELD16(name_length);
		  UNUSED(2);
		  STRING8(name, v16);
		  PAD();
		  break;

		case 99: /* ListExtensions */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  break;

		case 100: /* ChangeKeyboardMapping */
		  v8 = FIELD8(keycode_count);
		  REQUEST_LENGTH();
		  KEYCODE(first_keycode);
		  v8_2 = FIELD8(keysyms_per_keycode);
		  UNUSED(2);
		  LISTofKEYSYM(keysyms, v8, v8_2);
		  break;

		case 101: /* GetKeyboardMapping */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  KEYCODE(first_keycode);
		  FIELD8(count);
		  UNUSED(2);
		  break;

		case 102: /* ChangeKeyboardControl */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  BITMASK32(keyboard_value);
		  BITFIELD(INT8, keyboard_value_mask, key_click_percent);
		  BITFIELD(INT8, keyboard_value_mask, bell_percent);
		  BITFIELD(INT16, keyboard_value_mask, bell_pitch);
		  BITFIELD(INT16, keyboard_value_mask, bell_duration);
		  BITFIELD(INT16, keyboard_value_mask, led);
		  BITFIELD(ENUM8, keyboard_value_mask, led_mode);
		  BITFIELD(KEYCODE, keyboard_value_mask, keyboard_key);
		  BITFIELD(ENUM8, keyboard_value_mask, auto_repeat_mode);
		  break;

		case 103: /* GetKeyboardControl */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  break;

		case 104: /* Bell */
		  INT8(percent);
		  REQUEST_LENGTH();
		  break;

		case 105: /* ChangePointerControl */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  INT16(acceleration_numerator);
		  INT16(acceleration_denominator);
		  INT16(threshold);
		  BOOL(do_acceleration);
		  BOOL(do_threshold);
		  break;

		case 106: /* GetPointerControl */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  break;

		case 107: /* SetScreenSaver */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  INT16(timeout);
		  INT16(interval);
		  ENUM8(prefer_blanking);
		  ENUM8(allow_exposures);
		  UNUSED(2);
		  break;

		case 108: /* GetScreenSaver */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  break;

		case 109: /* ChangeHosts */
		  ENUM8(change_host_mode);
		  REQUEST_LENGTH();
		  ENUM8(family);
		  UNUSED(1);
		  v16 = CARD16(address_length);
		  LISTofCARD8(address, v16);
		  break;

		case 110: /* ListHosts */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  break;

		case 111: /* SetAccessControl */
		  ENUM8(access_mode);
		  REQUEST_LENGTH();
		  break;

		case 112: /* SetCloseDownMode */
		  ENUM8(close_down_mode);
		  REQUEST_LENGTH();
		  break;

		case 113: /* KillClient */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  CARD32(resource);
		  break;

		case 114: /* RotateProperties */
		  UNUSED(1);
		  v16 = REQUEST_LENGTH();
		  WINDOW(window);
		  CARD16(property_number);
		  INT16(delta);
		  LISTofATOM(properties, (v16 - 12));
		  break;

		case 115: /* ForceScreenSaver */
		  ENUM8(screen_saver_mode);
		  REQUEST_LENGTH();
		  break;

		case 116: /* SetPointerMapping */
		  v8 = FIELD8(map_length);
		  REQUEST_LENGTH();
		  LISTofCARD8(map, v8);
		  PAD();
		  break;

		case 117: /* GetPointerMapping */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  break;

		case 118: /* SetModifierMapping */
		  v8 = FIELD8(keycodes_per_modifier);
		  REQUEST_LENGTH();
		  LISTofKEYCODE(keycodes, v8);
		  break;

		case 119: /* GetModifierMapping */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  break;
		  
		case 127: /* NoOperation */
		  UNUSED(1);
		  REQUEST_LENGTH();
		  break;
	    }
	    if (cur_offset < next_offset)
		  proto_tree_add_item(t, hf_x11_undecoded, tvb, cur_offset, next_offset - cur_offset, little_endian);
	    cur_offset = next_offset;
	    left = nextLeft;
      }

      return left;
}

/************************************************************************
 ***                                                                  ***
 ***         G U E S S I N G   T H E   B Y T E   O R D E R I N G      ***
 ***                                                                  ***
 ************************************************************************/

static GTree *byte_ordering_cache = NULL;
static GMemChunk *address_chunk = NULL;
static GMemChunk *ipv4_chunk = NULL;
static GMemChunk *ipv6_chunk = NULL;

static gint compareAddresses(gconstpointer aa, gconstpointer bb)
{
      const address *a = (const address *)aa;
      const address *b = (const address *)bb;
      int c = b -> type - a -> type;
      if (c) return c;
      c = b -> len - a -> len;
      if (c) return c;
      return memcmp(b -> data, a -> data, a -> len);
}

/* If we can't guess, we return TRUE (that is little_endian), cause
   I'm developing on a Linux box :-). The (non-)guess isn't cached
   however, so we may have more luck next time. I'm quite conservative
   in my assertions, cause once it's cached, it's stay in cache, and
   we may be fooled up by a packet starting with the end of a request
   started in a previous packet...
*/

int numberOfBitSetTable[] = { 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4 };

int numberOfBitSet(tvbuff_t *tvb, int offset, int maskLength)
{
      int res = 0;
      while(maskLength--) {
	    int c = tvb_get_guint8(tvb, offset);
	    offset++;
	    res += numberOfBitSetTable[c & 0xf] + numberOfBitSetTable[c >> 4];
      }
      return res;
}

static int listOfStringLengthConsistent(tvbuff_t *tvb, int offset, int length, int listLength)
{
      if (listLength > length) return FALSE;
      while(listLength--) {
	    int l;
	    if (!tvb_bytes_exist(tvb, offset, 1)) return TRUE;
	    l = tvb_get_guint8(tvb, offset);
	    if (!l) break;
	    l++;
	    if (l > length) return FALSE;
	    if (!tvb_bytes_exist(tvb, offset, l)) return TRUE;
	    offset += l;
	    length -= l;
      }
      if (length > 3) return FALSE;
      return TRUE;
}

static int rounded4(int n)
{
      int remainder = n % 4;
      int res = n / 4;
      if (remainder) res++;
      return res;
}

/* We assume the order to be consistent, until proven wrong. */

static gboolean consistentWithOrder(int length, tvbuff_t *tvb, int offset, guint16 (*v16)(tvbuff_t *, gint))
{
      switch(tvb_get_guint8(tvb, offset)) {
	  case 1: /* CreateWindow */
	    return !tvb_bytes_exist(tvb, offset, 32) || length == 8 + numberOfBitSet(tvb, offset + 7 * 4, 4);

	  case 2: /* ChangeWindowAttributes */
	  case 56: /* ChangeGC */
	    return !tvb_bytes_exist(tvb, offset, 12) || length == 3 + numberOfBitSet(tvb, offset + 8, 4);

	  case 3: /* GetWindowAttributes */
	  case 4: /* DestroyWindow */
	  case 5: /* DestroySubwindows */
	  case 6: /* ChangeSaveSet */
	  case 8: /* MapWindow */
	  case 9: /* MapSubWindow */
	  case 10: /* UnmapWindow */
	  case 11: /* UnmapSubwindows */
	  case 13: /* CirculateWindow */
	  case 14: /* GetGeometry */
	  case 15: /* QueryTree */
	  case 17: /* GetAtomName */
	  case 21: /* ListProperties */
	  case 23: /* GetSelectionOwner */
	  case 27: /* UngrabPointer */
	  case 32: /* UngrabKeyboard */
	  case 35: /* AllowEvents */
	  case 38: /* QueryPointer */
	  case 46: /* CloseFont */
	  case 47: /* QueryFont */
	  case 54: /* FreePixmap */
	  case 60: /* FreeGC */
	  case 79: /* FreeColormap */
	  case 81: /* InstallColormap */
	  case 82: /* UninstallColormap */
	  case 83: /* ListInstalledColormaps */
	  case 95: /* FreeCursor */
	  case 101: /* GetKeyboardMapping */
	  case 113: /* KillClient */
	    return length == 2;

	  case 7: /* ReparentWindow */
	  case 22: /* SetSelectionOwner */
	  case 30: /* ChangeActivePointerGrab */
	  case 31: /* GrabKeyboard */
	  case 33: /* GrabKey */
	  case 39: /* GetMotionEvents */
	  case 40: /* TranslateCoordinates */
	  case 53: /* CreatePixmap */
	  case 57: /* CopyGC */
	  case 61: /* ClearArea */
	  case 78: /* CreateColormap */
	  case 84: /* AllocColor */
	  case 87: /* AllocColorPlanes */
	    return length == 4;

	  case 12: /* ConfigureWindow */
	    return !tvb_bytes_exist(tvb, offset, 10) || length == 3 + numberOfBitSet(tvb, offset + 8, 2);

	  case 16: /* InternAtom */
	  case 98: /* QueryExtension */
	    return !tvb_bytes_exist(tvb, offset, 6) || length == 2 + rounded4(v16(tvb, offset + 4));

	  case 18: /* ChangeProperty */
	    {
		  int multiplier, type;
		  if (!tvb_bytes_exist(tvb, offset, 17)) return TRUE;
		  type = tvb_get_guint8(tvb, 16);
		  if (type != 8 && type != 16 && type != 32) return FALSE;
		  multiplier = type == 8 ? 1 : type == 16 ? 2 : 4;
		  if (!tvb_bytes_exist(tvb, offset, 24)) return TRUE;
		  return length == 6 + rounded4((v16 == tvb_get_letohs ? tvb_get_letohl : tvb_get_ntohl)(tvb, offset + 20) * multiplier);
	    }

	  case 19: /* DeleteProperty */
	  case 29: /* UngrabButton */
	  case 34: /* UngrabKey */
	  case 42: /* SetInputFocus */
	  case 80: /* CopyColormapAndFree */
	  case 86: /* AllocColorCells */
	  case 97: /* QueryBestSize */
	  case 105: /* ChangePointerControl */
	  case 107: /* SetScreenSaver */
	    return length == 3;

	  case 20: /* GetProperty */
	  case 24: /* ConvertSelection */
	  case 26: /* GrabPointer */
	  case 28: /* GrabButton */
	  case 41: /* WarpPointer */
	    return length == 6;

	  case 25: /* SendEvent */
	    return length == 11;

	  case 36: /* GrabServer */
	  case 37: /* UngrabServer */
	  case 43: /* GetInputFocus */
	  case 44: /* QueryKeymap */
	  case 52: /* GetFontPath */
	  case 99: /* ListExtensions */
	  case 103: /* GetKeyboardControl */
	  case 104: /* Bell */
	  case 106: /* GetPointerControl */
	  case 108: /* GetScreenSaver */
	  case 110: /* ListHosts */
	  case 111: /* SetAccessControl */
	  case 112: /* SetCloseDownMode */
	  case 115: /* ForceScreenSaver */
	  case 117: /* GetPointerMapping */
	  case 119: /* GetModifierMapping */
	    return length == 1;

	  case 45: /* OpenFont */
	  case 85: /* AllocNamedColor */
	  case 92: /* LookupColor */
	    return !tvb_bytes_exist(tvb, offset, 10) || length == 3 + rounded4(v16(tvb, offset + 8));

	  case 48: /* QueryTextExtents */
	    return length >= 2;

	  case 49: /* ListFonts */
	  case 50: /* ListFontsWithInfo */
	  case 109: /* ChangeHosts */
	    return !tvb_bytes_exist(tvb, offset, 8) || length == 2 + rounded4(v16(tvb, offset + 6));

	  case 51: /* SetFontPath */
	    if (length < 2) return FALSE;
	    if (!tvb_bytes_exist(tvb, offset, 8)) return TRUE;
	    return listOfStringLengthConsistent(tvb, offset + 8, (length - 2) * 4, v16(tvb, offset + 4));

	  case 55: /* CreateGC */
	    return !tvb_bytes_exist(tvb, offset, 16) || length == 4 + numberOfBitSet(tvb, offset + 12, 4);

	  case 58: /* SetDashes */
	    return !tvb_bytes_exist(tvb, offset, 12) || length == 3 + rounded4(v16(tvb, offset + 10));

	  case 59: /* SetClipRectangles */
	  case 66: /* PolySegment */
	  case 67: /* PolyRectangle */
	  case 70: /* PolyFillRectangle */
	    return length >= 3 && (length - 3) % 2 == 0;

	  case 62: /* CopyArea */
	    return length == 7;

	  case 63: /* CopyPlane */
	  case 93: /* CreateCursor */
	  case 94: /* CreateGlyphCursor */
	    return length == 8;

	  case 64: /* PolyPoint */
	  case 65: /* PolyLine */
	  case 88: /* FreeColors */
	    return length >= 3;

	  case 68: /* PolyArc */
	  case 71: /* PolyFillArc */
	    return length >= 3 && (length - 3) % 3 == 0;

	  case 69: /* FillPoly */
	  case 76: /* ImageText8 */
	    return length >= 4;

	  case 72: /* PutImage */
	    return length >= 6;

	  case 73: /* GetImage */
	  case 96: /* RecolorCursor */
	    return length == 5;

	  case 74: /* PolyText8 */
	    if (length < 4) return FALSE;
	    return TRUE; /* We don't perform many controls on this one */

	  case 75: /* PolyText16 */
	    if (length < 4) return FALSE;
	    return TRUE; /* We don't perform many controls on this one */

	  case 77: /* ImageText16 */
	    return length >= 4;

	  case 89: /* StoreColors */
	    return length > 2 && (length - 2) % 3 == 0;

	  case 90: /* StoreNamedColor */
	    return !tvb_bytes_exist(tvb, offset, 14) || length == 4 + rounded4(v16(tvb, offset + 12));

	  case 91: /* QueryColors */
	    return length >= 2;

	  case 100: /* ChangeKeyboardMapping */
	    return !tvb_bytes_exist(tvb, offset, 6) || length == 2 + tvb_get_guint8(tvb, 1) * tvb_get_guint8(tvb, 5);

	  case 102: /* ChangeKeyboardControl */
	    return !tvb_bytes_exist(tvb, offset, 6) || length == 2 + numberOfBitSet(tvb, offset + 4, 2);

	  case 114: /* RotateProperties */
	    return !tvb_bytes_exist(tvb, offset, 10) || length == 3 + v16(tvb, offset + 8);

	  case 116: /* SetPointerMapping */
	    return length == 1 + rounded4(tvb_get_guint8(tvb, 1));

	  case 118: /* SetModifierMapping */
	    return length == 1 + tvb_get_guint8(tvb, 1) * 2;
	    
	  case 127: /* NoOperation */
	    return length >= 1;

	  default:
	    return TRUE;
      }
}

/* -1 means doesn't match, +1 means match, 0 means don't know */

static int x_endian_match(tvbuff_t *tvb, guint16 (*v16)(tvbuff_t *, gint))
{
      int offset, nextoffset;
      int atLeastOne = 0;

      for(offset = 0; tvb_bytes_exist(tvb, offset, 4); offset = nextoffset) {
	    int length;
	    length = v16(tvb, offset + 2);
	    if (!length) return -1;
	    nextoffset = offset + length * 4;
	    if (!consistentWithOrder(length, tvb, offset, v16)) return -1;
	    atLeastOne = 1;
      }
      return atLeastOne;
}

static gboolean
guess_byte_ordering(tvbuff_t *tvb)
{
      /* With X the client gives the byte ordering for the protocol,
	 and the port on the server tells us we're speaking X. */

      int le, be, decision, decisionToCache;

      address *addr = pi.srcport == pi.match_port ? &pi.net_dst : &pi.net_src;
      gint32 cache = GPOINTER_TO_INT(g_tree_lookup(byte_ordering_cache, addr));
      if (cache) return cache > 0 ? TRUE : FALSE;
      if (pi.srcport == pi.match_port) return TRUE; /* We don't try to guess on a reply / event for now */

      le = x_endian_match(tvb, tvb_get_letohs);
      be = x_endian_match(tvb, tvb_get_ntohs);

      /* remember that "decision" really means "little_endian". */
      if (le == be)
	    /* We have no reason to believe it's little- rather than
	       big-endian, so we guess the shortest length is the
	       right one.
	    */
	    if (!tvb_bytes_exist(tvb, 0, 4))
			  /* Not even a way to get the length. We're biased
			     toward little endianness here (essentially the
			     x86 world right now). Decoding won't go very far
			     anyway.
			  */
		  decision = TRUE;
	    else
		  decision = tvb_get_letohs(tvb, 2) <= tvb_get_ntohs(tvb, 2);
      else
	  decision = le >= be;

      decisionToCache = (le < 0 && be > 0) || (le > 0 && be < 0);
      if (decisionToCache) {
	    /* We encode the decision as 1 for TRUE and -1 for FALSE
	       to be able to distinguish between FALSE and no value in
	       the cache when recalling the value.
	    */
	    int address_length;
	    char *address_data;
	    address *cached;
	    if (addr -> type == AT_IPv4) {
		  address_length = 4;
		  address_data = g_mem_chunk_alloc(ipv4_chunk);
	    } else if (addr -> type == AT_IPv6) {
		  address_length = 16;
		  address_data = g_mem_chunk_alloc(ipv6_chunk);
	    } else {
		  address_length = addr -> len;
		  address_data = g_malloc(address_length);
	    }
	    cached = g_mem_chunk_alloc(address_chunk);
	    memcpy(address_data, addr -> data, address_length);
	    SET_ADDRESS(cached, addr -> type, addr -> len, address_data);
	    g_tree_insert(byte_ordering_cache, cached, GINT_TO_POINTER(decision ? 1 : -1));
      }
	    
      /*
      fprintf(stderr, "packet %d\tle %d\tbe %d\tlittle_endian %d\tcache %d\n", 
	      pi.fd -> num, le, be, decision, decisionToCache);
      */
      return decision;
}

/************************************************************************
 ***                                                                  ***
 ***         I N I T I A L I Z A T I O N   A N D   M A I N            ***
 ***                                                                  ***
 ************************************************************************/

static void
dissect_x11_request(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
/* Set up structures we will need to add the protocol subtree and manage it */
      proto_item *ti;
      proto_tree *x11_tree;
      int left;
	
/* Make entries in Protocol column and Info column on summary display */
      if (check_col(fd, COL_PROTOCOL)) 
	    col_add_str(fd, COL_PROTOCOL, "X11");
    
/* This field shows up as the "Info" column in the display; you should make
   it, if possible, summarize what's in the packet, so that a user looking
   at the list of packets can tell what type of packet it is.

   "col_add_fstr()" can be used instead of "col_add_str()"; it takes
   "printf()"-like arguments. */
      if (check_col(fd, COL_INFO)) 
	    col_add_str(fd, COL_INFO, "X11 request");

/* In the interest of speed, if "tree" is NULL, don't do any work not
   necessary to generate protocol tree items. */
      if (!tree) return;
/* NOTE: The offset and length values in the previous call to
   "proto_tree_add_item()" define what data bytes to highlight in the hex
   display window when the line in the protocol tree display
   corresponding to that item is selected.

   END_OF_FRAME is a handy way to highlight all data from the offset to
   the end of the packet. */
      ti = proto_tree_add_item(tree, proto_x11, NullTVB, offset, END_OF_FRAME, FALSE);
      x11_tree = proto_item_add_subtree(ti, ett_x11);

/* Code to process the packet goes here */

      tvb = tvb_new_subset(pi.compat_top_tvb, offset, -1, -1);
      cur_offset = 0;
      little_endian = guess_byte_ordering(tvb);
      left = dissect_x11_request_loop(x11_tree);
      if (left)
	    dissect_data(pd, offset + cur_offset, fd, x11_tree);
}

static void
dissect_x11_event(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
/* Set up structures we will need to add the protocol subtree and manage it */
      proto_item *ti;
      proto_tree *x11_tree;
	
/* Make entries in Protocol column and Info column on summary display */
      if (check_col(fd, COL_PROTOCOL)) 
	    col_add_str(fd, COL_PROTOCOL, "X11");
    
/* This field shows up as the "Info" column in the display; you should make
   it, if possible, summarize what's in the packet, so that a user looking
   at the list of packets can tell what type of packet it is.

   "col_add_fstr()" can be used instead of "col_add_str()"; it takes
   "printf()"-like arguments. */
      if (check_col(fd, COL_INFO)) 
	    col_add_str(fd, COL_INFO, "X11 event");

/* In the interest of speed, if "tree" is NULL, don't do any work not
   necessary to generate protocol tree items. */
      if (tree) {
/* NOTE: The offset and length values in the previous call to
   "proto_tree_add_item()" define what data bytes to highlight in the hex
   display window when the line in the protocol tree display
   corresponding to that item is selected.

   END_OF_FRAME is a handy way to highlight all data from the offset to
   the end of the packet. */
	    ti = proto_tree_add_item(tree, proto_x11, NullTVB, offset, END_OF_FRAME, FALSE);
	    x11_tree = proto_item_add_subtree(ti, ett_x11);

/* Code to process the packet goes here */

	    dissect_data(pd, offset, fd, tree);
      }
}

static void
dissect_x11(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
      if (pi.destport == TCP_PORT_X11 || pi.destport == TCP_PORT_X11_2 || pi.destport == TCP_PORT_X11_3)
	    dissect_x11_request(pd, offset, fd, tree);
      else
	    dissect_x11_event(pd, offset, fd, tree);
}

/* Register the protocol with Ethereal */
void proto_register_x11(void)
{                 

/* Setup list of header fields */
      static hf_register_info hf[] = {
/*
  { &hf_x11_FIELDABBREV,
  { "FIELDNAME",           "x11.FIELDABBREV",
  FIELDTYPE, FIELDBASE, FIELDCONVERT, BITMASK,          
  "FIELDDESCR" }
  },
*/
#include "packet-x11-register-info.h"
      };

/* Setup protocol subtree array */
      static gint *ett[] = {
	    &ett_x11,
	    &ett_x11_request,
      };

/* Register the protocol name and description */
      proto_x11 = proto_register_protocol("X11", "x11");

/* Required function calls to register the header fields and subtrees used */
      proto_register_field_array(proto_x11, hf, array_length(hf));
      proto_register_subtree_array(ett, array_length(ett));

      byte_ordering_cache = g_tree_new(compareAddresses);
      address_chunk = g_mem_chunk_new("x11 byte ordering address cache", sizeof(address), 
				      sizeof(address) * 128, G_ALLOC_ONLY);
      ipv4_chunk = g_mem_chunk_new("x11 byte ordering ipv4 address cache", 4, 4 * 128, G_ALLOC_ONLY);
      ipv6_chunk = g_mem_chunk_new("x11 byte ordering ipv6 address cache", 16, 16 * 128, G_ALLOC_ONLY);
};


void
proto_reg_handoff_x11(void)
{
  dissector_add("tcp.port", TCP_PORT_X11, dissect_x11);
  dissector_add("tcp.port", TCP_PORT_X11_2, dissect_x11);
  dissector_add("tcp.port", TCP_PORT_X11_3, dissect_x11);
}
