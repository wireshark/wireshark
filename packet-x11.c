/* packet-x11.c
 * Routines for X11 dissection
 * Copyright 2000, Christophe Tronche <ch.tronche@computer.org>
 *
 * $Id: packet-x11.c,v 1.45 2002/08/02 23:36:04 jmayer Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * - keep track of Atom creation by server to be able to display
 *   non-predefined atoms
 * - Idem for keysym <-> keycode ???
 * - Idem for fonts 
 * - Subtree the request ids (that is x11.create-window.window and
 *   x11.change-window.window should be  distinct), and add hidden fields
 *   (so we still have x11.window).
 * - add hidden fields so we can have x11.circulate-window in addition to
 *   x11.opcode == 13 (but you could match on x11.opcode == "CirculateWindow"
 *   now)
 * - add hidden fields so we have x11.listOfStuff.length
 * - use a faster scheme that linear list searching for the opcode.
 * - correct display of Unicode chars.
 * - Not everything is homogeneous, in particular the handling of items in
 *   list is a total mess.
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

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include "prefs.h"
#include "packet-frame.h"

#define cVALS(x) (const value_string*)(x)

/* Initialize the protocol and registered fields */
static int proto_x11 = -1;

#include "x11-declarations.h"

/* Initialize the subtree pointers */
static gint ett_x11 = -1;
static gint ett_x11_color_flags = -1;
static gint ett_x11_list_of_arc = -1;
static gint ett_x11_arc = -1;
static gint ett_x11_list_of_atom = -1;
static gint ett_x11_list_of_card32 = -1;
static gint ett_x11_list_of_color_item = -1;
static gint ett_x11_color_item = -1;
static gint ett_x11_list_of_keycode = -1;
static gint ett_x11_list_of_keysyms = -1;
static gint ett_x11_keysym = -1;
static gint ett_x11_list_of_point = -1;
static gint ett_x11_point = -1;
static gint ett_x11_list_of_rectangle = -1;
static gint ett_x11_rectangle = -1;
static gint ett_x11_list_of_segment = -1;
static gint ett_x11_segment = -1;
static gint ett_x11_list_of_string8 = -1;
static gint ett_x11_list_of_text_item = -1;
static gint ett_x11_text_item = -1;
static gint ett_x11_gc_value_mask = -1;
static gint ett_x11_event_mask = -1;
static gint ett_x11_do_not_propagate_mask = -1;
static gint ett_x11_set_of_key_mask = -1;
static gint ett_x11_pointer_event_mask = -1;
static gint ett_x11_window_value_mask = -1;
static gint ett_x11_configure_window_mask = -1;
static gint ett_x11_keyboard_value_mask = -1;

/* desegmentation of X11 messages */
static gboolean x11_desegment = TRUE;

static dissector_handle_t data_handle;

#define TCP_PORT_X11			6000
#define TCP_PORT_X11_2			6001
#define TCP_PORT_X11_3			6002

/*
 * Round a length to a multiple of 4 bytes.
 */
#define ROUND_LENGTH(n)	((((n) + 3)/4) * 4)

/************************************************************************
 ***                                                                  ***
 ***         E N U M   T A B L E S   D E F I N I T I O N S            ***
 ***                                                                  ***
 ************************************************************************/

static const value_string byte_order_vals[] = {
     { 'B', "Big-endian" },
     { 'l', "Little-endian" },
     { 0,   NULL }
};

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

#define FAMILY_INTERNET	0
#define FAMILY_DECNET	1
#define FAMILY_CHAOS	2

static const value_string family_vals[] = {
      { FAMILY_INTERNET, "Internet" },
      { FAMILY_DECNET,   "DECnet" },
      { FAMILY_CHAOS,    "Chaos" },
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
 ***           F I E L D   D E C O D I N G   M A C R O S              ***
 ***                                                                  ***
 ************************************************************************/

#define VALUE8(tvb, offset) (tvb_get_guint8(tvb, offset))
#define VALUE16(tvb, offset) (little_endian ? tvb_get_letohs(tvb, offset) : tvb_get_ntohs(tvb, offset))
#define VALUE32(tvb, offset) (little_endian ? tvb_get_letohl(tvb, offset) : tvb_get_ntohl(tvb, offset))

#define FIELD8(name)  (field8(tvb, offsetp, t, hf_x11_##name, little_endian))
#define FIELD16(name) (field16(tvb, offsetp, t, hf_x11_##name, little_endian))
#define FIELD32(name) (field32(tvb, offsetp, t, hf_x11_##name, little_endian))

#define BITFIELD(TYPE, position, name) {\
  int unused;\
  int save = *offsetp;\
  proto_tree_add_item(bitmask_tree, hf_x11_##position##_##name, tvb, bitmask_offset, \
                      bitmask_size, little_endian); \
  if (bitmask_value & proto_registrar_get_nth(hf_x11_##position##_##name) -> bitmask) {\
       TYPE(name);\
       unused = save + 4 - *offsetp;\
       if (unused)\
           proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, unused, little_endian);\
       *offsetp = save + 4;\
 }\
}

#define FLAG(position, name) {\
       proto_tree_add_boolean(bitmask_tree, hf_x11_##position##_mask##_##name, tvb, bitmask_offset, bitmask_size, bitmask_value); }

#define FLAG_IF_NONZERO(position, name) {\
  if (bitmask_value & proto_registrar_get_nth(hf_x11_##position##_mask##_##name) -> bitmask)\
       proto_tree_add_boolean(bitmask_tree, hf_x11_##position##_mask##_##name, tvb, bitmask_offset, bitmask_size, bitmask_value); }

#define ATOM(name)     { atom(tvb, offsetp, t, hf_x11_##name, little_endian); }
#define BITGRAVITY(name) { gravity(tvb, offsetp, t, hf_x11_##name, "Forget"); }
#define BITMASK(name, size) {\
      proto_item *ti; \
      guint32 bitmask_value; \
      int bitmask_offset; \
      int bitmask_size; \
      proto_tree *bitmask_tree; \
      bitmask_value = ((size == 1) ? (guint32)VALUE8(tvb, *offsetp) : \
		       ((size == 2) ? (guint32)VALUE16(tvb, *offsetp) : \
			              (guint32)VALUE32(tvb, *offsetp))); \
      bitmask_offset = *offsetp; \
      bitmask_size = size; \
      ti = proto_tree_add_uint(t, hf_x11_##name##_mask, tvb, *offsetp, size, bitmask_value); \
      bitmask_tree = proto_item_add_subtree(ti, ett_x11_##name##_mask); \
      *offsetp += size;
#define ENDBITMASK	}
#define BITMASK8(name)	BITMASK(name, 1);
#define BITMASK16(name)	BITMASK(name, 2);
#define BITMASK32(name) BITMASK(name, 4);
#define BOOL(name)     (add_boolean(tvb, offsetp, t, hf_x11_##name))
#define BUTTON(name)   { FIELD8(name); }
#define CARD8(name)    { FIELD8(name); }
#define CARD16(name)   (FIELD16(name))
#define CARD32(name)   (FIELD32(name))
#define COLOR_FLAGS(name) { colorFlags(tvb, offsetp, t); }
#define COLORMAP(name) { FIELD32(name); }
#define CURSOR(name)   { FIELD32(name); }
#define DRAWABLE(name) { FIELD32(name); }
#define ENUM8(name)    (FIELD8(name))
#define ENUM16(name)   { FIELD16(name); }
#define FONT(name)     { FIELD32(name); }
#define FONTABLE(name) { FIELD32(name); }
#define GCONTEXT(name) { FIELD32(name); }
#define INT8(name)     { FIELD8(name); }
#define INT16(name)    { FIELD16(name); }
#define KEYCODE(name)  { FIELD8(name); }
#define LISTofARC(name) { listOfArc(tvb, offsetp, t, hf_x11_##name, (next_offset - *offsetp) / 12, little_endian); }
#define LISTofATOM(name, length) { listOfAtom(tvb, offsetp, t, hf_x11_##name, (length) / 4, little_endian); }
#define LISTofBYTE(name, length) { listOfByte(tvb, offsetp, t, hf_x11_##name, (length), little_endian); }
#define LISTofCARD8(name, length) { listOfByte(tvb, offsetp, t, hf_x11_##name, (length), little_endian); }
#define LISTofCARD32(name, length) { listOfCard32(tvb, offsetp, t, hf_x11_##name, hf_x11_##name##_item, (length) / 4, little_endian); }
#define LISTofCOLORITEM(name, length) { listOfColorItem(tvb, offsetp, t, hf_x11_##name, (length) / 12, little_endian); }
#define LISTofKEYCODE(name, length) { listOfKeycode(tvb, offsetp, t, hf_x11_##name, (length), little_endian); }
#define LISTofKEYSYM(name, keycode_count, keysyms_per_keycode) { \
      listOfKeysyms(tvb, offsetp, t, hf_x11_##name, hf_x11_##name##_item, (keycode_count), (keysyms_per_keycode), little_endian); }
#define LISTofPOINT(name, length) { listOfPoint(tvb, offsetp, t, hf_x11_##name, (length) / 4, little_endian); }
#define LISTofRECTANGLE(name) { listOfRectangle(tvb, offsetp, t, hf_x11_##name, (next_offset - *offsetp) / 8, little_endian); }
#define LISTofSEGMENT(name) { listOfSegment(tvb, offsetp, t, hf_x11_##name, (next_offset - *offsetp) / 8, little_endian); }
#define LISTofSTRING8(name, length) { listOfString8(tvb, offsetp, t, hf_x11_##name, hf_x11_##name##_string, (length), little_endian); }
#define LISTofTEXTITEM8(name) { listOfTextItem(tvb, offsetp, t, hf_x11_##name, FALSE, next_offset, little_endian); }
#define LISTofTEXTITEM16(name) { listOfTextItem(tvb, offsetp, t, hf_x11_##name, TRUE, next_offset, little_endian); }
#define OPCODE()       { opcode = FIELD8(opcode); }
#define PIXMAP(name)   { FIELD32(name); }
#define REQUEST_LENGTH() (requestLength(tvb, offsetp, t, little_endian))
#define SETofEVENT(name) { setOfEvent(tvb, offsetp, t, little_endian); }
#define SETofDEVICEEVENT(name) { setOfDeviceEvent(tvb, offsetp, t, little_endian);}
#define SETofKEYMASK(name) { setOfKeyMask(tvb, offsetp, t, little_endian); }
#define SETofPOINTEREVENT(name) { setOfPointerEvent(tvb, offsetp, t, little_endian); }
#define STRING8(name, length)  { string8(tvb, offsetp, t, hf_x11_##name, length); }
#define STRING16(name, length)  { string16(tvb, offsetp, t, hf_x11_##name, hf_x11_##name##_bytes, length, little_endian); }
#define TIMESTAMP(name){ timestamp(tvb, offsetp, t, hf_x11_##name, little_endian); }
#define UNDECODED(x)   { proto_tree_add_item(t, hf_x11_undecoded, tvb, *offsetp,  x, little_endian); *offsetp += x; }
#define UNUSED(x)      { proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp,  x, little_endian); *offsetp += x; }
#define PAD()          { if (next_offset - *offsetp > 0) proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, next_offset - *offsetp, little_endian); *offsetp = next_offset; }
#define WINDOW(name)   { FIELD32(name); }
#define WINGRAVITY(name) { gravity(tvb, offsetp, t, hf_x11_##name, "Unmap"); }

#define VISUALID(name) { gint32 v = VALUE32(tvb, *offsetp); \
    proto_tree_add_uint_format(t, hf_x11_##name, tvb, *offsetp, 4, v, "Visualid: 0x%08x%s", v, \
			       v ? "" : " (CopyFromParent)"); *offsetp += 4; }

/************************************************************************
 ***                                                                  ***
 ***                  D E C O D I N G   F I E L D S                   ***
 ***                                                                  ***
 ************************************************************************/

static void atom(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
		 gboolean little_endian)
{
      const char *interpretation = NULL;

      guint32 v = VALUE32(tvb, *offsetp);
      if (v >= 1 && v < array_length(atom_predefined_interpretation))
	    interpretation = atom_predefined_interpretation[v];
      else if (v)
	    interpretation = "Not a predefined atom";
      else {
	    header_field_info *hfi = proto_registrar_get_nth(hf);
	    if (hfi -> strings)
		  interpretation = match_strval(v, cVALS(hfi -> strings));
      }
      if (!interpretation) interpretation = "error in Xlib client program ?";
      proto_tree_add_uint_format(t, hf, tvb, *offsetp, 4, v, "%s: %u (%s)", 
				 proto_registrar_get_nth(hf) -> name, v, interpretation);
      *offsetp += 4;
}

static guint32 add_boolean(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf)
{
      guint32 v = VALUE8(tvb, *offsetp);
      proto_tree_add_boolean(t, hf, tvb, *offsetp, 1, v);
      *offsetp += 1;
      return v;
}

static void colorFlags(tvbuff_t *tvb, int *offsetp, proto_tree *t)
{
      unsigned do_red_green_blue = VALUE8(tvb, *offsetp);
      proto_item *ti;
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

	    ti = proto_tree_add_uint_format(t, hf_x11_coloritem_flags, tvb, *offsetp, 1, do_red_green_blue,
					    "%s", buffer);
	    tt = proto_item_add_subtree(ti, ett_x11_color_flags);
	    if (do_red_green_blue & 0x1)
		  proto_tree_add_boolean(tt, hf_x11_coloritem_flags_do_red, tvb, *offsetp, 1, 
					 do_red_green_blue & 0x1);
	    if (do_red_green_blue & 0x2)
		  proto_tree_add_boolean(tt, hf_x11_coloritem_flags_do_green, tvb, *offsetp, 1, 
					 do_red_green_blue & 0x2);
	    if (do_red_green_blue & 0x4)
		  proto_tree_add_boolean(tt, hf_x11_coloritem_flags_do_blue, tvb, *offsetp, 1, 
					 do_red_green_blue & 0x4);
	    if (do_red_green_blue & 0xf8)
		  proto_tree_add_boolean(tt, hf_x11_coloritem_flags_unused, tvb, *offsetp, 1, 
					 do_red_green_blue & 0xf8);
      } else
	    proto_tree_add_uint_format(t, hf_x11_coloritem_flags, tvb, *offsetp, 1, do_red_green_blue,
				       "flags: none");
      *offsetp += 1;
}

static void gravity(tvbuff_t *tvb, int *offsetp, proto_tree *t,
    int hf, const char *nullInterpretation)
{
      guint8 v = VALUE8(tvb, *offsetp);

      if (!v)
	    proto_tree_add_uint_format(t, hf, tvb, *offsetp, 1, v, "%s: 0 (%s)",
	    			       proto_registrar_get_nth(hf) -> name,
				       nullInterpretation);
      else
	    proto_tree_add_uint(t, hf, tvb, *offsetp, 1, v);
      *offsetp += 1;
}

static void listOfArc(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
		      int length, gboolean little_endian)
{
      proto_item *ti = proto_tree_add_item(t, hf, tvb, *offsetp, length * 8, little_endian);
      proto_tree *tt = proto_item_add_subtree(ti, ett_x11_list_of_arc);
      while(length--) {
	    gint16 x = VALUE16(tvb, *offsetp);
	    gint16 y = VALUE16(tvb, *offsetp + 2);
	    guint16 width = VALUE16(tvb, *offsetp + 4);
	    guint16 height = VALUE16(tvb, *offsetp + 6);
	    gint16 angle1 = VALUE16(tvb, *offsetp + 8);
	    gint16 angle2 = VALUE16(tvb, *offsetp + 10);

	    proto_item *tti = proto_tree_add_none_format(tt, hf_x11_arc, tvb, *offsetp, 12, 
							     "arc: %dx%d+%d+%d, angle %d -> %d (%f degrees -> %f degrees)",
							     width, height, x, y, angle1, angle2,
							     angle1 / 64.0, angle2 / 64.0);
	    proto_tree *ttt = proto_item_add_subtree(tti, ett_x11_arc);
	    proto_tree_add_int(ttt, hf_x11_arc_x, tvb, *offsetp, 2, x);
	    *offsetp += 2;
	    proto_tree_add_int(ttt, hf_x11_arc_y, tvb, *offsetp, 2, y);
	    *offsetp += 2;
	    proto_tree_add_uint(ttt, hf_x11_arc_width, tvb, *offsetp, 2, y);
	    *offsetp += 2;
	    proto_tree_add_uint(ttt, hf_x11_arc_height, tvb, *offsetp, 2, y);
	    *offsetp += 2;
	    proto_tree_add_int(ttt, hf_x11_arc_angle1, tvb, *offsetp, 2, y);
	    *offsetp += 2;
	    proto_tree_add_int(ttt, hf_x11_arc_angle2, tvb, *offsetp, 2, y);
	    *offsetp += 2;
      }
}

static void listOfAtom(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
		       int length, gboolean little_endian)
{
      proto_item *ti = proto_tree_add_item(t, hf, tvb, *offsetp, length * 4, little_endian);
      proto_tree *tt = proto_item_add_subtree(ti, ett_x11_list_of_atom);
      while(length--)
	    atom(tvb, offsetp, tt, hf_x11_properties_item, little_endian);
}

static void listOfByte(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
		       int length, gboolean little_endian)
{
      if (length <= 0) length = 1;
      proto_tree_add_item(t, hf, tvb, *offsetp, length, little_endian);
      *offsetp += length;
}

static void listOfCard32(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
			 int hf_item, int length, gboolean little_endian)
{
      proto_item *ti = proto_tree_add_item(t, hf, tvb, *offsetp, length * 4, little_endian);
      proto_tree *tt = proto_item_add_subtree(ti, ett_x11_list_of_card32);
      while(length--) {
	    proto_tree_add_uint(tt, hf_item, tvb, *offsetp, 4, VALUE32(tvb, *offsetp));
	    *offsetp += 4;
      }
}

static void listOfColorItem(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
			    int length, gboolean little_endian)
{
      proto_item *ti = proto_tree_add_item(t, hf, tvb, *offsetp, length * 8, little_endian);
      proto_tree *tt = proto_item_add_subtree(ti, ett_x11_list_of_color_item);
      while(length--) {
	    proto_item *tti;
	    proto_tree *ttt;
	    unsigned do_red_green_blue;
	    guint16 red, green, blue;
	    char buffer[1024];
	    char *bp;
	    const char *sep;

	    red = VALUE16(tvb, *offsetp + 4);
	    green = VALUE16(tvb, *offsetp + 6);
	    blue = VALUE16(tvb, *offsetp + 8);
	    do_red_green_blue = VALUE8(tvb, *offsetp + 10);

	    bp = buffer + sprintf(buffer, "colorItem: ");
	    sep = "";
	    if (do_red_green_blue & 0x1) {
		bp += sprintf(bp, "red = %d", red);
		sep = ", ";
	    }
	    if (do_red_green_blue & 0x2) {
		bp += sprintf(bp, "%sgreen = %d", sep, green);
		sep = ", ";
	    }
	    if (do_red_green_blue & 0x4)
		bp += sprintf(bp, "%sblue = %d", sep, blue);

	    tti = proto_tree_add_none_format(tt, hf_x11_coloritem, tvb, *offsetp, 12, "%s", buffer);
	    ttt = proto_item_add_subtree(tti, ett_x11_color_item);
	    proto_tree_add_item(ttt, hf_x11_coloritem_pixel, tvb, *offsetp, 4, little_endian);
	    *offsetp += 4;
	    proto_tree_add_item(ttt, hf_x11_coloritem_red, tvb, *offsetp, 2, little_endian);
	    *offsetp += 2;
	    proto_tree_add_item(ttt, hf_x11_coloritem_green, tvb, *offsetp, 2, little_endian);
	    *offsetp += 2;
	    proto_tree_add_item(ttt, hf_x11_coloritem_blue, tvb, *offsetp, 2, little_endian);
	    *offsetp += 2;
	    colorFlags(tvb, offsetp, ttt);
	    proto_tree_add_item(ttt, hf_x11_coloritem_unused, tvb, *offsetp, 1, little_endian);
	    *offsetp += 1;
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

static void listOfKeycode(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
			  int length, gboolean little_endian)
{
      char buffer[1024];
      proto_item *ti = proto_tree_add_item(t, hf, tvb, *offsetp, length * 8, little_endian);
      proto_tree *tt = proto_item_add_subtree(ti, ett_x11_list_of_keycode);

      while(length--) {
	    char *bp = buffer;
	    const char **m;
	    int i;

	    for(i = 8, m = modifiers; i; i--, m++) {
		guchar c = tvb_get_guint8(tvb, *offsetp);
		*offsetp += 1;
		if (c)
		    bp += sprintf(bp, "  %s=%d", *m, c);
	    }

	    proto_tree_add_bytes_format(tt, hf_x11_keycodes_item, tvb, *offsetp - 8, 8, tvb_get_ptr(tvb, *offsetp - 8, 8),	"item: %s", buffer);
      }
}

static void listOfKeysyms(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
			  int hf_item, int keycode_count,
			  int keysyms_per_keycode, gboolean little_endian)
{
      proto_item *ti = proto_tree_add_item(t, hf, tvb, *offsetp, keycode_count * keysyms_per_keycode * 4, little_endian);
      proto_tree *tt = proto_item_add_subtree(ti, ett_x11_list_of_keysyms);
      proto_item *tti;
      proto_tree *ttt;
      int i;

      while(keycode_count--) {
	    tti = proto_tree_add_none_format(tt, hf_item, tvb, *offsetp, keysyms_per_keycode * 4,
						 "keysyms:");
	    ttt = proto_item_add_subtree(tti, ett_x11_keysym);
	    for(i = keysyms_per_keycode; i; i--) {
		  guint32 v = VALUE32(tvb, *offsetp);
		  proto_item_append_text(tti, " %s", keysymString(v));
		  proto_tree_add_uint_format(ttt, hf_x11_keysyms_item_keysym, tvb, *offsetp, 4, v,
					     "keysym: 0x%08x (%s)", v, keysymString(v));
		  *offsetp += 4;
	    }
      }
}

static void listOfPoint(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
			int length, gboolean little_endian)
{
      proto_item *ti = proto_tree_add_item(t, hf, tvb, *offsetp, length * 4, little_endian);
      proto_tree *tt = proto_item_add_subtree(ti, ett_x11_list_of_point);
      while(length--) {
	    gint16 x, y;
	    proto_item *tti;
	    proto_tree *ttt;

	    x = VALUE16(tvb, *offsetp);
	    y = VALUE16(tvb, *offsetp + 2);

	    tti = proto_tree_add_none_format(tt, hf_x11_point, tvb, *offsetp, 4, "point: (%d,%d)", x, y);
	    ttt = proto_item_add_subtree(tti, ett_x11_point);
	    proto_tree_add_int(ttt, hf_x11_point_x, tvb, *offsetp, 2, x);
	    *offsetp += 2;
	    proto_tree_add_int(ttt, hf_x11_point_y, tvb, *offsetp, 2, y);
	    *offsetp += 2;
      }
}

static void listOfRectangle(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
			    int length, gboolean little_endian)
{
      proto_item *ti = proto_tree_add_item(t, hf, tvb, *offsetp, length * 8, little_endian);
      proto_tree *tt = proto_item_add_subtree(ti, ett_x11_list_of_rectangle);
      while(length--) {
	    gint16 x, y;
	    unsigned width, height;
	    proto_item *tti;
	    proto_tree *ttt;

	    x = VALUE16(tvb, *offsetp);
	    y = VALUE16(tvb, *offsetp + 2);
	    width = VALUE16(tvb, *offsetp + 4);
	    height = VALUE16(tvb, *offsetp + 6);

	    tti = proto_tree_add_none_format(tt, hf_x11_rectangle, tvb, *offsetp, 8, 
						 "rectangle: %dx%d+%d+%d", width, height, x, y);
	    ttt = proto_item_add_subtree(tti, ett_x11_rectangle);
	    proto_tree_add_int(ttt, hf_x11_rectangle_x, tvb, *offsetp, 2, x);
	    *offsetp += 2;
	    proto_tree_add_int(ttt, hf_x11_rectangle_y, tvb, *offsetp, 2, y);
	    *offsetp += 2;
	    proto_tree_add_uint(ttt, hf_x11_rectangle_width, tvb, *offsetp, 2, width);
	    *offsetp += 2;
	    proto_tree_add_uint(ttt, hf_x11_rectangle_height, tvb, *offsetp, 2, height);
	    *offsetp += 2;
      }
}

static void listOfSegment(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
			  int length, gboolean little_endian)
{
      proto_item *ti = proto_tree_add_item(t, hf, tvb, *offsetp, length * 8, little_endian);
      proto_tree *tt = proto_item_add_subtree(ti, ett_x11_list_of_segment);
      while(length--) {
	    gint16 x1, y1, x2, y2;
	    proto_item *tti;
	    proto_tree *ttt;

	    x1 = VALUE16(tvb, *offsetp);
	    y1 = VALUE16(tvb, *offsetp + 2);
	    x2 = VALUE16(tvb, *offsetp + 4);
	    y2 = VALUE16(tvb, *offsetp + 6);

	    tti = proto_tree_add_none_format(tt, hf_x11_segment, tvb, *offsetp, 8, 
						 "segment: (%d,%d)-(%d,%d)", x1, y1, x2, y2);
	    ttt = proto_item_add_subtree(tti, ett_x11_segment);
	    proto_tree_add_item(ttt, hf_x11_segment_x1, tvb, *offsetp, 2, little_endian);
	    *offsetp += 2;
	    proto_tree_add_item(ttt, hf_x11_segment_y1, tvb, *offsetp, 2, little_endian);
	    *offsetp += 2;
	    proto_tree_add_item(ttt, hf_x11_segment_x2, tvb, *offsetp, 2, little_endian);
	    *offsetp += 2;
	    proto_tree_add_item(ttt, hf_x11_segment_y2, tvb, *offsetp, 2, little_endian);
	    *offsetp += 2;
      }
}

/* XXX - the protocol tree code should handle non-printable characters.
   Note that "non-printable characters" may depend on your locale.... */
static void stringCopy(char *dest, const char *source, int length)
{
      guchar c;
      while(length--) {
	    c = *source++;
	    if (!isgraph(c) && c != ' ') c = '.';
	    *dest++ = c;
      }
      *dest++ = '\0';
}

static void listOfString8(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
			  int hf_item, int length, gboolean little_endian)
{
      char *s = NULL;
      guint allocated = 0;
      proto_item *ti;
      proto_tree *tt;
      int i;

      /* Compute total length */
      
      int scanning_offset = *offsetp; /* Scanning pointer */
      int l;
      for(i = length; i; i--) {
	    l = tvb_get_guint8(tvb, scanning_offset);
	    scanning_offset += 1 + l;
      }

      ti = proto_tree_add_item(t, hf, tvb, *offsetp, scanning_offset - *offsetp, little_endian);
      tt = proto_item_add_subtree(ti, ett_x11_list_of_string8);

      /*
       * In case we throw an exception, clean up whatever stuff we've
       * allocated (if any).
       */
      CLEANUP_PUSH(g_free, s);

      while(length--) {
	    unsigned l = VALUE8(tvb, *offsetp);
	    if (allocated < (l + 1)) {
		  /* g_realloc doesn't work ??? */
		  g_free(s);
		  s = g_malloc(l + 1);
		  allocated = l + 1;
	    }
	    stringCopy(s, tvb_get_ptr(tvb, *offsetp + 1, l), l); /* Nothing better for now. We need a better string handling API. */
	    proto_tree_add_string_format(tt, hf_item, tvb, *offsetp, l + 1, s, "\"%s\"", s);
	    *offsetp += l + 1;
      }

      /*
       * Call the cleanup handler to free the string and pop the handler.
       */
      CLEANUP_CALL_AND_POP;
}

#define STRING16_MAX_DISPLAYED_LENGTH 150

static int stringIsActuallyAn8BitString(tvbuff_t *tvb, int offset, unsigned length)
{
      if (length > STRING16_MAX_DISPLAYED_LENGTH) length = STRING16_MAX_DISPLAYED_LENGTH;
      for(; length > 0; offset += 2, length--) {
	    if (tvb_get_guint8(tvb, offset))
		return FALSE;
      }
      return TRUE;
}

/* length is the length of the _byte_zone_ (that is, twice the length of the string) */

static void string16_with_buffer_preallocated(tvbuff_t *tvb, proto_tree *t,
					      int hf, int hf_bytes,
					      int offset, unsigned length,
					      char **s, int *sLength,
					      gboolean little_endian)
{
      int truncated = FALSE;
      unsigned l = length / 2;

      if (stringIsActuallyAn8BitString(tvb, offset, l)) {
	    char *dp;
	    int soffset = offset;

	    if (l > STRING16_MAX_DISPLAYED_LENGTH) {
		  truncated = TRUE;
		  l = STRING16_MAX_DISPLAYED_LENGTH;
	    }
	    if (*sLength < (int) l + 3) {
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
	    proto_tree_add_item(t, hf_bytes, tvb, offset, length, little_endian);

}

static void listOfTextItem(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
    int sizeIs16, int next_offset, gboolean little_endian)
{
      int allocated = 0;
      char *s = NULL;
      proto_item *ti;
      proto_tree *tt;
      guint32 fid;

      /* Compute total length */
      
      int scanning_offset = *offsetp; /* Scanning pointer */
      int l;                            /* Length of an individual item */
      int n = 0;                        /* Number of items */

      while(scanning_offset < next_offset) {
	    l = tvb_get_guint8(tvb, scanning_offset);
	    scanning_offset++;
	    if (!l) break;
	    n++;
	    scanning_offset += l == 255 ? 4 : l + (sizeIs16 ? l : 0) + 1;
      }

      ti = proto_tree_add_item(t, hf, tvb, *offsetp, scanning_offset - *offsetp, little_endian);
      tt = proto_item_add_subtree(ti, ett_x11_list_of_text_item);

      /*
       * In case we throw an exception, clean up whatever stuff we've
       * allocated (if any).
       */
      CLEANUP_PUSH(g_free, s);

      while(n--) {
	    unsigned l = VALUE8(tvb, *offsetp);
	    if (l == 255) { /* Item is a font */
		  fid = tvb_get_ntohl(tvb, *offsetp + 1);
		  proto_tree_add_uint(tt, hf_x11_textitem_font, tvb, *offsetp, 5, fid);
		  *offsetp += 5;
	    } else { /* Item is a string */
		  proto_item *tti;
		  proto_tree *ttt;
		  gint8 delta = VALUE8(tvb, *offsetp + 1);
		  if (sizeIs16) l += l;
		  if ((unsigned) allocated < l + 1) {
			/* g_realloc doesn't work ??? */
			g_free(s);
			s = g_malloc(l + 1);
			allocated = l + 1;
		  }
		  stringCopy(s, tvb_get_ptr(tvb, *offsetp + 2, l), l);
		  tti = proto_tree_add_none_format(tt, hf_x11_textitem_string, tvb, *offsetp, l + 2,
						       "textitem (string): delta = %d, \"%s\"",
						       delta, s);
		  ttt = proto_item_add_subtree(tti, ett_x11_text_item);
		  proto_tree_add_item(ttt, hf_x11_textitem_string_delta, tvb, *offsetp + 1, 1, little_endian);
		  if (sizeIs16)
			string16_with_buffer_preallocated(tvb, ttt, hf_x11_textitem_string_string16, 
							  hf_x11_textitem_string_string16_bytes,
							  *offsetp + 2, l,
							  &s, &allocated,
							  little_endian);
		  else
			proto_tree_add_string_format(ttt, hf_x11_textitem_string_string8, tvb, 
						     *offsetp + 2, l, s, "\"%s\"", s);
		  *offsetp += l + 2;
	    }
      }

      /*
       * Call the cleanup handler to free the string and pop the handler.
       */
      CLEANUP_CALL_AND_POP;
}

static guint32 field8(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
		      gboolean little_endian)
{
      guint32 v = VALUE8(tvb, *offsetp);
      header_field_info *hfi = proto_registrar_get_nth(hf);
      gchar *enumValue = NULL;

      if (hfi -> strings)
	    enumValue = match_strval(v, cVALS(hfi -> strings));
      if (enumValue)
	    proto_tree_add_uint_format(t, hf, tvb, *offsetp, 1, v,
				       hfi -> display == BASE_DEC ? "%s: %u (%s)" : "%s: 0x%02x (%s)",
				       hfi -> name, v, enumValue);
      else
	    proto_tree_add_item(t, hf, tvb, *offsetp, 1, little_endian);
      *offsetp += 1;
      return v;
}

static guint32 field16(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
		       gboolean little_endian)
{
      guint32 v = VALUE16(tvb, *offsetp);
      proto_tree_add_item(t, hf, tvb, *offsetp, 2, little_endian);
      *offsetp += 2;
      return v;
}

static guint32 field32(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
		       gboolean little_endian)
{
      guint32 v = VALUE32(tvb, *offsetp);
      header_field_info *hfi = proto_registrar_get_nth(hf);
      gchar *enumValue = NULL;
      gchar *nameAsChar = hfi -> name;

      if (hfi -> strings)
	    enumValue = match_strval(v, cVALS(hfi -> strings));
      if (enumValue)
	    proto_tree_add_uint_format(t, hf, tvb, *offsetp, 4, v,
				       hfi -> display == BASE_DEC ? "%s: %u (%s)" : "%s: 0x%08x (%s)",
				       nameAsChar, v, enumValue);
      else
	    proto_tree_add_uint_format(t, hf, tvb, *offsetp, 4, v, 
				       hfi -> display == BASE_DEC ? "%s: %u" : "%s: 0x%08x",
				       nameAsChar, v);
      *offsetp += 4;
      return v;
}

static void gcAttributes(tvbuff_t *tvb, int *offsetp, proto_tree *t,
			 gboolean little_endian)
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
      ENDBITMASK;
}

static void gcMask(tvbuff_t *tvb, int *offsetp, proto_tree *t,
		   gboolean little_endian)
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
      ENDBITMASK;
}

static guint32 requestLength(tvbuff_t *tvb, int *offsetp, proto_tree *t,
			     gboolean little_endian)
{
      guint32 res = VALUE16(tvb, *offsetp) * 4;
      proto_tree_add_uint(t, hf_x11_request_length, tvb, *offsetp, 2, res);
      *offsetp += 2;
      return res;
}

static void setOfEvent(tvbuff_t *tvb, int *offsetp, proto_tree *t,
		       gboolean little_endian)
{
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
      FLAG_IF_NONZERO(event, erroneous_bits);
      ENDBITMASK;
}

static void setOfDeviceEvent(tvbuff_t *tvb, int *offsetp, proto_tree *t,
			     gboolean little_endian)
{
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
      FLAG_IF_NONZERO(do_not_propagate, erroneous_bits);
      ENDBITMASK;
}

static void setOfKeyMask(tvbuff_t *tvb, int *offsetp, proto_tree *t,
			 gboolean little_endian)
{
      proto_item *ti;
      guint32 bitmask_value;
      int bitmask_offset;
      int bitmask_size;
      proto_tree *bitmask_tree;

      bitmask_value = VALUE16(tvb, *offsetp);
      bitmask_offset = *offsetp;
      bitmask_size = 2;
      if (bitmask_value == 0x8000)
	    proto_tree_add_uint_format(t, hf_x11_modifiers_mask_AnyModifier, tvb, *offsetp, 2, 0x8000,
				       "modifiers-masks: 0x8000 (AnyModifier)");
      else {
	    ti = proto_tree_add_uint(t, hf_x11_modifiers_mask, tvb, *offsetp, 2, 
						 bitmask_value);
	    bitmask_tree = proto_item_add_subtree(ti, ett_x11_set_of_key_mask);
	    FLAG(modifiers, Shift);
	    FLAG(modifiers, Lock);
	    FLAG(modifiers, Control);
	    FLAG(modifiers, Mod1);
	    FLAG(modifiers, Mod2);
	    FLAG(modifiers, Mod3);
	    FLAG(modifiers, Mod4);
	    FLAG(modifiers, Mod5);
	    FLAG_IF_NONZERO(modifiers, erroneous_bits);
      }
      *offsetp += 2; 
}

static void setOfPointerEvent(tvbuff_t *tvb, int *offsetp, proto_tree *t,
			      gboolean little_endian)
{
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
      FLAG_IF_NONZERO(pointer_event, erroneous_bits);
      ENDBITMASK;
}

static void string8(tvbuff_t *tvb, int *offsetp, proto_tree *t,
    int hf, unsigned length)
{
      char *s = g_malloc(length + 1);

      /*
       * In case we throw an exception, clean up whatever stuff we've
       * allocated (if any).
       */
      CLEANUP_PUSH(g_free, s);

      stringCopy(s, tvb_get_ptr(tvb, *offsetp, length), length);
      proto_tree_add_string(t, hf, tvb, *offsetp, length, s);

      /*
       * Call the cleanup handler to free the string and pop the handler.
       */
      CLEANUP_CALL_AND_POP;

      *offsetp += length;
}

/* The length is the length of the _byte_zone_ (twice the length of the string) */

static void string16(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
    int hf_bytes, unsigned length, gboolean little_endian)
{
      char *s = NULL;
      unsigned l = 0;

      /*
       * In case we throw an exception, clean up whatever stuff we've
       * allocated (if any).
       */
      CLEANUP_PUSH(g_free, s);

      length += length;
      string16_with_buffer_preallocated(tvb, t, hf, hf_bytes, *offsetp, length,
					&s, &l, little_endian);

      /*
       * Call the cleanup handler to free the string and pop the handler.
       */
      CLEANUP_CALL_AND_POP;

      *offsetp += length;
}

static void timestamp(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
		      gboolean little_endian)
{
      guint32 v = VALUE32(tvb, *offsetp);

      if (!v)
	    proto_tree_add_uint_format(t, hf, tvb, *offsetp, 4, 0, "%s: 0 (CurrentTime)",
		proto_registrar_get_nth(hf) -> name);
      else
	    proto_tree_add_uint(t, hf, tvb, *offsetp, 4, v);
      *offsetp += 4;
}

static void windowAttributes(tvbuff_t *tvb, int *offsetp, proto_tree *t,
			     gboolean little_endian)
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
      ENDBITMASK;
}

/*
 * Data structure associated with a conversation; keeps track of the
 * request for which we're expecting a reply, the frame number of
 * the initial connection request, and the byte order of the connection.
 *
 * An opcode of -3 means we haven't yet seen any requests yet.
 * An opcode of -2 means we're not expecting a reply.
 * An opcode of -1 means means we're waiting for a reply to the initial
 * connection request.
 * Other values are the opcode of the request for which we're expecting
 * a reply.
 *
 * XXX - assumes only one outstanding request is awaiting a reply,
 * which should always be the case.
 */
#define NOTHING_SEEN		-3
#define NOTHING_EXPECTED	-2
#define INITIAL_CONN		-1

#define BYTE_ORDER_BE		0
#define BYTE_ORDER_LE		1
#define BYTE_ORDER_UNKNOWN	-1

typedef struct {
      int	opcode;		/* opcode for which we're awaiting a reply */
      guint32	iconn_frame;	/* frame # of initial connection request */
      int	byte_order;	/* byte order of connection */
} x11_conv_data_t;

static GMemChunk *x11_state_chunk = NULL;

static void x11_init_protocol(void)
{
      if (x11_state_chunk != NULL)
	    g_mem_chunk_destroy(x11_state_chunk);

      x11_state_chunk = g_mem_chunk_new("x11_state_chunk",
					sizeof (x11_conv_data_t),
					128 * sizeof (x11_conv_data_t),
					G_ALLOC_ONLY);
}

/************************************************************************
 ***                                                                  ***
 ***         G U E S S I N G   T H E   B Y T E   O R D E R I N G      ***
 ***                                                                  ***
 ************************************************************************/

/* If we can't guess, we return TRUE (that is little_endian), cause
   I'm developing on a Linux box :-). The (non-)guess isn't cached
   however, so we may have more luck next time. I'm quite conservative
   in my assertions, cause once it's cached, it's stay in cache, and
   we may be fooled up by a packet starting with the end of a request
   started in a previous packet...
*/

static int numberOfBitSetTable[] = { 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4 };

static int numberOfBitSet(tvbuff_t *tvb, int offset, int maskLength)
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
guess_byte_ordering(tvbuff_t *tvb, packet_info *pinfo,
		    x11_conv_data_t *state_info)
{
      /* With X the client gives the byte ordering for the protocol,
	 and the port on the server tells us we're speaking X. */

      int le, be, decision, decisionToCache;

      if (state_info->byte_order == BYTE_ORDER_BE)
	    return FALSE;	/* known to be big-endian */
      else if (state_info->byte_order == BYTE_ORDER_LE)
	    return TRUE;	/* known to be little-endian */

      if (pinfo->srcport == pinfo->match_port) {
      	    /*
      	     * This is a reply or event; we don't try to guess the
      	     * byte order on it for now.
      	     */
	    return TRUE;
      }

      le = x_endian_match(tvb, tvb_get_letohs);
      be = x_endian_match(tvb, tvb_get_ntohs);

      /* remember that "decision" really means "little_endian". */
      if (le == be) {
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
      } else
	  decision = le >= be;

      decisionToCache = (le < 0 && be > 0) || (le > 0 && be < 0);
      if (decisionToCache) {
	    /*
	     * Remember the decision.
	     */
	    state_info->byte_order = decision ? BYTE_ORDER_LE : BYTE_ORDER_BE;
      }
	    
      /*
      fprintf(stderr, "packet %d\tle %d\tbe %d\tlittle_endian %d\tcache %d\n", 
	      pinfo->fd -> num, le, be, decision, decisionToCache);
      */
      return decision;
}

/************************************************************************
 ***                                                                  ***
 ***              D E C O D I N G   O N E   P A C K E T               ***
 ***                                                                  ***
 ************************************************************************/

/*
 * Decode an initial connection request.
 */
static void dissect_x11_initial_conn(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, x11_conv_data_t *state_info, gboolean little_endian)
{
      int offset = 0;
      int *offsetp = &offset;
      proto_item *ti;
      proto_tree *t;
      guint16 auth_proto_name_length, auth_proto_data_length;
      gint left;

      ti = proto_tree_add_item(tree, proto_x11, tvb, 0, -1, FALSE);
      t = proto_item_add_subtree(ti, ett_x11);

      CARD8(byte_order);
      UNUSED(1);
      CARD16(protocol_major_version);
      CARD16(protocol_minor_version);
      auth_proto_name_length = CARD16(authorization_protocol_name_length);
      auth_proto_data_length = CARD16(authorization_protocol_data_length);
      UNUSED(2);
      if (auth_proto_name_length != 0) {
	    STRING8(authorization_protocol_name, auth_proto_name_length);
	    offset = ROUND_LENGTH(offset);
      }
      if (auth_proto_data_length != 0) {
	    STRING8(authorization_protocol_data, auth_proto_data_length);
	    offset = ROUND_LENGTH(offset);
      }
      left = tvb_length_remaining(tvb, offset);
      if (left)
	    proto_tree_add_item(t, hf_x11_undecoded, tvb, offset, left, little_endian);

      /*
       * This is the initial connection request...
       */
      state_info->iconn_frame = pinfo->fd->num;

      /*
       * ...and we're expecting a reply to it.
       */
      state_info->opcode = INITIAL_CONN;
}

static void dissect_x11_request(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, const char *sep, x11_conv_data_t *state_info,
    gboolean little_endian)
{
      int offset = 0;
      int *offsetp = &offset;
      int next_offset;
      proto_item *ti;
      proto_tree *t;
      int length, opcode;
      guint8 v8, v8_2;
      guint16 v16;
      guint32 v32;
      gint left;

      length = VALUE16(tvb, 2) * 4;

      if (length < 4) {
	    /* Bogus message length? */
	    return;
      }

      next_offset = offset + length;

      ti = proto_tree_add_item(tree, proto_x11, tvb, 0, -1, FALSE);
      t = proto_item_add_subtree(ti, ett_x11);

      OPCODE();

      if (check_col(pinfo->cinfo, COL_INFO)) 
	  col_append_fstr(pinfo->cinfo, COL_INFO, "%s %s", sep,
			  val_to_str(opcode, opcode_vals, "Unknown (%u)"));

      /*
       * Does this request expect a reply?
       */
      switch(opcode) {

      case 3: /* GetWindowAttributes */
      case 14: /* GetGeometry */
      case 15: /* QueryTree */
      case 16: /* InternAtom */
      case 17: /* GetAtomName */
      case 20: /* GetProperty */
      case 21: /* ListProperties */
      case 23: /* GetSelectionOwner */
      case 26: /* GrabPointer */
      case 31: /* GrabKeyboard */
      case 38: /* QueryPointer */
      case 39: /* GetMotionEvents */
      case 40: /* TranslateCoordinates */
      case 44: /* QueryKeymap */
      case 47: /* QueryFont */
      case 48: /* QueryTextExtents */
      case 49: /* ListFonts */
      case 73: /* GetImage */
      case 83: /* ListInstalledColormaps */
      case 84: /* AllocColor */
      case 91: /* QueryColors */
      case 92: /* LookupColor */
      case 97: /* QueryBestSize */
      case 98: /* QueryExtension */
      case 99: /* ListExtensions */
      case 101: /* GetKeyboardMapping */
      case 103: /* GetKeyboardControl */
      case 106: /* GetPointerControl */
      case 108: /* GetScreenSaver */
      case 110: /* ListHosts */
      case 116: /* SetPointerMapping */
      case 117: /* GetPointerMapping */
      case 118: /* SetModifierMapping */
      case 119: /* GetModifierMapping */
	    /*
	     * Those requests expect a reply.
	     */
	    state_info->opcode = opcode;
	    break;

      default:
	    /*
	     * No reply is expected from any other request.
	     */
	    state_info->opcode = NOTHING_EXPECTED;
	    break;
      }

      if (!tree) return;

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
	    windowAttributes(tvb, offsetp, t, little_endian);
	    break;

      case 2: /* ChangeWindowAttributes */
	    UNUSED(1);
	    REQUEST_LENGTH();
	    WINDOW(window);
	    windowAttributes(tvb, offsetp, t, little_endian);
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
	    ENDBITMASK;
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
	    STRING16(string16, (next_offset - offset - (v8 ? 2 : 0)) / 2);
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
	    gcAttributes(tvb, offsetp, t, little_endian);
	    break;

      case 56: /* ChangeGC */
	    UNUSED(1);
	    REQUEST_LENGTH();
	    GCONTEXT(gc);
	    gcAttributes(tvb, offsetp, t, little_endian);
	    break;

      case 57: /* CopyGC */
	    UNUSED(1);
	    REQUEST_LENGTH();
	    GCONTEXT(src_gc);
	    GCONTEXT(dst_gc);
	    gcMask(tvb, offsetp, t, little_endian);
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
	    ENDBITMASK;
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
	    v8 = ENUM8(family);
	    UNUSED(1);
	    v16 = CARD16(address_length);
	    if (v8 == FAMILY_INTERNET && v16 == 4) {
		  /*
		   * IPv4 addresses.
		   * XXX - what about IPv6?  Is that a family of
		   * FAMILY_INTERNET (0) with a length of 16?
		   */
		  LISTofCARD8(ip_address, v16);
	    } else
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
      left = tvb_length_remaining(tvb, offset);
      if (left)
	    proto_tree_add_item(t, hf_x11_undecoded, tvb, offset, left, little_endian);
}

static void dissect_x11_requests(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree)
{
      volatile int offset = 0;
      int length_remaining;
      volatile gboolean little_endian;
      guint8 opcode;
      volatile int plen;
      proto_item *ti;
      proto_tree *t;
      volatile gboolean is_initial_creq;
      guint16 auth_proto_len, auth_data_len;
      const char *volatile sep = NULL;
      conversation_t *conversation;
      x11_conv_data_t *volatile state_info;
      int length;
      tvbuff_t *next_tvb;

      while (tvb_reported_length_remaining(tvb, offset) != 0) {
	    length_remaining = tvb_length_remaining(tvb, offset);

	    /*
	     * Can we do reassembly?
	     */
	    if (x11_desegment && pinfo->can_desegment) {
		  /*
		   * Yes - is the X11 request header split across
		   * segment boundaries?
		   */
		  if (length_remaining < 4) {
			/*
			 * Yes.  Tell the TCP dissector where the data
			 * for this message starts in the data it handed
			 * us, and how many more bytes we need, and return.
			 */
			pinfo->desegment_offset = offset;
			pinfo->desegment_len = 4 - length_remaining;
			return;
		  }
	    }

	    /*
	     * Get the state for this conversation; create the conversation
	     * if we don't have one, and create the state if we don't have
	     * any.
	     */
	    conversation = find_conversation(&pinfo->src, &pinfo->dst,
		pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
	    if (conversation == NULL) {
		  /*
		   * No - create one.
		   */
		  conversation = conversation_new(&pinfo->src,
			&pinfo->dst, pinfo->ptype, pinfo->srcport,
			pinfo->destport, 0);
	    }

	    /*
	     * Is there state attached to this conversation?
	     */
	    state_info = conversation_get_proto_data(conversation, proto_x11);
	    if (state_info == NULL) {
		  /*
		   * No - create a state structure and attach it.
		   */
		  state_info = g_mem_chunk_alloc(x11_state_chunk);
		  state_info->opcode = NOTHING_SEEN;	/* nothing seen yet */
		  state_info->iconn_frame = 0;	/* don't know it yet */
		  state_info->byte_order = BYTE_ORDER_UNKNOWN;	/* don't know it yet */
		  conversation_add_proto_data(conversation, proto_x11,
			state_info);
	    }

	    /*
	     * Guess the byte order if we don't already know it.
	     */
	    little_endian = guess_byte_ordering(tvb, pinfo, state_info);

	    /*
	     * Get the opcode and length of the putative X11 request.
	     */
	    opcode = VALUE8(tvb, 0);
	    plen = VALUE16(tvb, offset + 2);

	    if (plen == 0) {
		  /*
		   * This can't be 0, as it includes the header length.
		   * A different choice of byte order wouldn't have
		   * helped.
		   * Give up.
		   */
		  ti = proto_tree_add_item(tree, proto_x11, tvb, offset, -1, FALSE);
		  t = proto_item_add_subtree(ti, ett_x11);
		  proto_tree_add_text(t, tvb, offset, -1, "Bogus request length (0)");
		  return;
	    }

	    if (state_info->iconn_frame == pinfo->fd->num ||
		(state_info->opcode == NOTHING_SEEN &&
	         (opcode == 'B' || opcode == 'l') &&
	         (plen == 11 || plen == 2816))) {
		  /*
		   * Either
		   *
		   *	we saw this on the first pass and this is
		   *    it again
		   *
		   * or
		   *    we haven't already seen any requests, the first
		   *    byte of the message is 'B' or 'l', and the 16-bit
		   *    integer 2 bytes into the data stream is either 11
		   *    or a byte-swapped 11.
		   *
		   * This means it's probably an initial connection
		   * request, not a message.
		   *
		   * 'B' is decimal 66, which is the opcode for a
		   * PolySegment request; unfortunately, 11 is a valid
		   * length for a PolySegment request request, so we
		   * might mis-identify that request.  (Are there any
		   * other checks we can do?)
		   *
		   * 'l' is decimal 108, which is the opcode for a
		   * GetScreenSaver request; the only valid length
		   * for that request is 1.
		   */
		  is_initial_creq = TRUE;

		  /*
		   * We now know the byte order.  Override the guess.
		   */
		  if (state_info->byte_order == BYTE_ORDER_UNKNOWN) {
		  	if (opcode == 'B') {
			      /*
			       * Big-endian.
			       */
			      state_info->byte_order = BYTE_ORDER_BE;
			      little_endian = FALSE;
			} else {
			      /*
			       * Little-endian.
			       */
			      state_info->byte_order = BYTE_ORDER_LE;
			      little_endian = TRUE;
			}
		  }

		  /*
		   * Can we do reassembly?
		   */
		  if (x11_desegment && pinfo->can_desegment) {
			/*
			 * Yes - is the fixed-length portion of the
			 * initial connection header split across
			 * segment boundaries?
			 */
			if (length_remaining < 10) {
			      /*
			       * Yes.  Tell the TCP dissector where the
			       * data for this message starts in the data
			       * it handed us, and how many more bytes we
			       * need, and return.
			       */
			      pinfo->desegment_offset = offset;
			      pinfo->desegment_len = 10 - length_remaining;
			      return;
			}
		  }

		  /*
		   * Get the lengths of the authorization protocol and
		   * the authorization data.
		   */
		  auth_proto_len = VALUE16(tvb, offset + 6);
		  auth_data_len = VALUE16(tvb, offset + 8);
		  plen = 12 + ROUND_LENGTH(auth_proto_len) +
			ROUND_LENGTH(auth_data_len);
	    } else {
		  /*
		   * This is probably an ordinary request.
		   */
		  is_initial_creq = FALSE;

		  /*
		   * The length of a request is in 4-byte words.
		   */
		  plen *= 4;
	    }

	    /*
	     * Can we do reassembly?
	     */
	    if (x11_desegment && pinfo->can_desegment) {
		  /*
		   * Yes - is the X11 request split across segment
		   * boundaries?
		   */
		  if (length_remaining < plen) {
			/*
			 * Yes.  Tell the TCP dissector where the data
			 * for this message starts in the data it handed
			 * us, and how many more bytes we need, and return.
			 */
			pinfo->desegment_offset = offset;
			pinfo->desegment_len = plen - length_remaining;
			return;
		  }
	    }

	    /*
	     * Construct a tvbuff containing the amount of the payload
	     * we have available.  Make its reported length the
	     * amount of data in the X11 request.
	     *
	     * XXX - if reassembly isn't enabled. the subdissector
	     * will throw a BoundsError exception, rather than a
	     * ReportedBoundsError exception.  We really want a tvbuff
	     * where the length is "length", the reported length is "plen",
	     * and the "if the snapshot length were infinite" length is the
	     * minimum of the reported length of the tvbuff handed to us
	     * and "plen", with a new type of exception thrown if the offset
	     * is within the reported length but beyond that third length,
	     * with that exception getting the "Unreassembled Packet" error.
	     */
	    length = length_remaining;
	    if (length > plen)
		  length = plen;
	    next_tvb = tvb_new_subset(tvb, offset, length, plen);

	    /*
	     * Set the column appropriately.
	     */
	    if (is_initial_creq) {
		  if (check_col(pinfo->cinfo, COL_INFO)) 
			col_set_str(pinfo->cinfo, COL_INFO, "Initial connection request");
	    } else {
		  if (sep == NULL) {
			/*
			 * We haven't set the column yet; set it.
			 */
			if (check_col(pinfo->cinfo, COL_INFO)) 
			      col_add_str(pinfo->cinfo, COL_INFO, "Requests");

			/*
			 * Initialize the separator.
			 */
			sep = ":";
		  }
	    }

	    /*
	     * Dissect the X11 request.
	     *
	     * Catch the ReportedBoundsError exception; if this
	     * particular message happens to get a ReportedBoundsError
	     * exception, that doesn't mean that we should stop
	     * dissecting X11 requests within this frame or chunk of
	     * reassembled data.
	     *
	     * If it gets a BoundsError, we can stop, as there's nothing
	     * more to see, so we just re-throw it.
	     */
	    TRY {
		  if (is_initial_creq) {
			dissect_x11_initial_conn(next_tvb, pinfo, tree,
			    state_info, little_endian);
		  } else {
			dissect_x11_request(next_tvb, pinfo, tree, sep,
			    state_info, little_endian);
		  }
	    }
	    CATCH(BoundsError) {
		  RETHROW;
	    }
	    CATCH(ReportedBoundsError) {
		  show_reported_bounds_error(tvb, pinfo, tree);
	    }
	    ENDTRY;

	    /*
	     * Skip the X11 message.
	     */
	    offset += plen;

	    sep = ",";
      }
}

static void
dissect_x11_replies(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
/* Set up structures we will need to add the protocol subtree and manage it */
      proto_item *ti;
      proto_tree *x11_tree;
	
/* This field shows up as the "Info" column in the display; you should make
   it, if possible, summarize what's in the packet, so that a user looking
   at the list of packets can tell what type of packet it is. */
      if (check_col(pinfo->cinfo, COL_INFO)) 
	    col_set_str(pinfo->cinfo, COL_INFO, "Replies/events");

/* In the interest of speed, if "tree" is NULL, don't do any work not
   necessary to generate protocol tree items. */
      if (!tree) return;
      ti = proto_tree_add_item(tree, proto_x11, tvb, 0, -1, FALSE);
      x11_tree = proto_item_add_subtree(ti, ett_x11);

      /*
       * XXX - dissect these in a loop, like the requests.
       */
      call_dissector(data_handle,tvb, pinfo, x11_tree);
}

/************************************************************************
 ***                                                                  ***
 ***         I N I T I A L I Z A T I O N   A N D   M A I N            ***
 ***                                                                  ***
 ************************************************************************/

static void
dissect_x11(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
      if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
	    col_set_str(pinfo->cinfo, COL_PROTOCOL, "X11");
    
      if (pinfo->match_port == pinfo->destport)
	    dissect_x11_requests(tvb, pinfo, tree);
      else
	    dissect_x11_replies(tvb, pinfo, tree);
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
  "FIELDDESCR", HFILL }
  },
*/
#include "x11-register-info.h"
      };

/* Setup protocol subtree array */
      static gint *ett[] = {
	    &ett_x11,
	    &ett_x11_color_flags,
	    &ett_x11_list_of_arc,
	    &ett_x11_arc,
	    &ett_x11_list_of_atom,
	    &ett_x11_list_of_card32,
	    &ett_x11_list_of_color_item,
	    &ett_x11_color_item,
	    &ett_x11_list_of_keycode,
	    &ett_x11_list_of_keysyms,
	    &ett_x11_keysym,
	    &ett_x11_list_of_point,
	    &ett_x11_point,
	    &ett_x11_list_of_rectangle,
	    &ett_x11_rectangle,
	    &ett_x11_list_of_segment,
	    &ett_x11_segment,
	    &ett_x11_list_of_string8,
	    &ett_x11_list_of_text_item,
	    &ett_x11_text_item,
	    &ett_x11_gc_value_mask,
	    &ett_x11_event_mask,
	    &ett_x11_do_not_propagate_mask,
	    &ett_x11_set_of_key_mask,
	    &ett_x11_pointer_event_mask,
	    &ett_x11_window_value_mask,
	    &ett_x11_configure_window_mask,
	    &ett_x11_keyboard_value_mask,
      };
      module_t *x11_module;

/* Register the protocol name and description */
      proto_x11 = proto_register_protocol("X11", "X11", "x11");

/* Required function calls to register the header fields and subtrees used */
      proto_register_field_array(proto_x11, hf, array_length(hf));
      proto_register_subtree_array(ett, array_length(ett));

      register_init_routine(x11_init_protocol);

      x11_module = prefs_register_protocol(proto_x11, NULL);
      prefs_register_bool_preference(x11_module, "desegment",
	    "Desegment all X11 messages spanning multiple TCP segments",
	    "Whether the X11 dissector should desegment all messages spanning multiple TCP segments",
	    &x11_desegment);
}

void
proto_reg_handoff_x11(void)
{
  dissector_handle_t x11_handle;

  x11_handle = create_dissector_handle(dissect_x11, proto_x11);
  dissector_add("tcp.port", TCP_PORT_X11, x11_handle);
  dissector_add("tcp.port", TCP_PORT_X11_2, x11_handle);
  dissector_add("tcp.port", TCP_PORT_X11_3, x11_handle);
  data_handle = find_dissector("data");
}
