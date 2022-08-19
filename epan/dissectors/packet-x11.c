/* packet-x11.c
 * Routines for X11 dissection
 * Copyright 2000, Christophe Tronche <ch.tronche@computer.org>
 * Copyright 2003, Michael Shuldman
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

#include "config.h"


#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/show_exception.h>
#include <epan/prefs.h>

#include "packet-x11-keysymdef.h"
#include "packet-x11.h"

#include <wsutil/bits_count_ones.h>

void proto_register_x11(void);
void proto_reg_handoff_x11(void);

static dissector_handle_t x11_handle = NULL;

#define cVALS(x) (const value_string*)(x)


/*
 * Data structure associated with a conversation; keeps track of the
 * request for which we're expecting a reply, the frame number of
 * the initial connection request, and the byte order of the connection.
 *
 * An opcode of -3 means we haven't yet seen any requests yet.
 * An opcode of -2 means we're not expecting a reply (unused).
 * An opcode of -1 means we're waiting for a reply to the initial
 * connection request.
 * An opcode of 0  means the request was not seen (or unknown).
 * Other values are the opcode of the request for which we're expecting
 * a reply.
 *
 */
#define NOTHING_SEEN            -3
#define NOTHING_EXPECTED        -2
#define INITIAL_CONN            -1
#define UNKNOWN_OPCODE           0

#define MAX_OPCODES             (255 + 1) /* 255 + INITIAL_CONN */
#define LastExtensionError      255
#define LastExtensionEvent      127

#define BYTE_ORDER_UNKNOWN      0xFFFFFFFF

static const char *modifiers[] = {
      "Shift",
      "Lock",
      "Control",
      "Mod1",
      "Mod2",
      "Mod3",
      "Mod4",
      "Mod5"
};

/* Keymasks.  From <X11/X.h>. */
#define ShiftMask               (1<<0)
#define LockMask                (1<<1)
#define ControlMask             (1<<2)
#define Mod1Mask                (1<<3)
#define Mod2Mask                (1<<4)
#define Mod3Mask                (1<<5)
#define Mod4Mask                (1<<6)
#define Mod5Mask                (1<<7)

static const int modifiermask[] = { ShiftMask, LockMask, ControlMask,
Mod1Mask, Mod2Mask, Mod3Mask, Mod4Mask, Mod5Mask };

/* from <X11/X.h> */
#define NoSymbol             0L /* special KeySym */

typedef struct _x11_conv_data {
      wmem_map_t *seqtable;            /* hashtable of sequencenumber <-> opcode. */
      wmem_map_t *valtable;            /* hashtable of sequencenumber <-> &opcode_vals */
      /* major opcodes including extensions (NULL terminated) */
      value_string opcode_vals[MAX_OPCODES+1];
      /* error codes including extensions (NULL terminated) */
      value_string errorcode_vals[LastExtensionError + 2];
      /* event codes including extensions (NULL terminated) */
      value_string eventcode_vals[LastExtensionEvent + 2];
      wmem_map_t *eventcode_funcs;      /* hashtable of eventcode <-> dissect_event() */
      wmem_map_t *reply_funcs;          /* hashtable of opcode <-> dissect_reply() */

      int       sequencenumber;   /* sequencenumber of current packet.       */
      guint32   iconn_frame;      /* frame # of initial connection request   */
      guint32   iconn_reply;      /* frame # of initial connection reply     */
      guint        byte_order;       /* byte order of connection */
      gboolean  resync;           /* resynchronization of sequence number performed */

      int       *keycodemap[256]; /* keycode to keysymvalue map. */
      int       keysyms_per_keycode;
      int       first_keycode;
      int       *modifiermap[array_length(modifiers)];/* modifier to keycode.*/
      int       keycodes_per_modifier;

      union {
            struct {
                  int   first_keycode;
            } GetKeyboardMapping;
      } request;
} x11_conv_data_t;

static wmem_map_t *extension_table; /* hashtable of extension name <-> dispatch function */
static wmem_map_t *event_table;     /* hashtable of extension name <-> event info list */
static wmem_map_t *genevent_table;     /* hashtable of extension name <-> generic event info list */
static wmem_map_t *error_table;     /* hashtable of extension name <-> error list */
static wmem_map_t *reply_table;     /* hashtable of extension name <-> reply list */

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
static gint ett_x11_list_of_float = -1;
static gint ett_x11_list_of_double = -1;
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
static gint ett_x11_gc_value_mask = -1;         /* XXX - unused */
static gint ett_x11_event_mask = -1;            /* XXX - unused */
static gint ett_x11_do_not_propagate_mask = -1; /* XXX - unused */
static gint ett_x11_set_of_key_mask = -1;
static gint ett_x11_pointer_event_mask = -1;    /* XXX - unused */
static gint ett_x11_window_value_mask = -1;     /* XXX - unused */
static gint ett_x11_configure_window_mask = -1; /* XXX - unused */
static gint ett_x11_keyboard_value_mask = -1;   /* XXX - unused */
static gint ett_x11_same_screen_focus = -1;
static gint ett_x11_event = -1;
static gint ett_x11_list_of_pixmap_format = -1;
static gint ett_x11_pixmap_format = -1;
static gint ett_x11_list_of_screen = -1;
static gint ett_x11_screen = -1;
static gint ett_x11_list_of_depth_detail = -1;
static gint ett_x11_depth_detail = -1;
static gint ett_x11_list_of_visualtype= -1;
static gint ett_x11_visualtype= -1;

static expert_field ei_x11_invalid_format = EI_INIT;
static expert_field ei_x11_request_length = EI_INIT;
static expert_field ei_x11_keycode_value_out_of_range = EI_INIT;

/* desegmentation of X11 messages */
static gboolean x11_desegment = TRUE;

#define DEFAULT_X11_PORT_RANGE "6000-6063"

/*
 * Round a length to a multiple of 4 bytes.
 */
#define ROUND_LENGTH(n) ((((n) + 3)/4) * 4)

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

static const value_string image_byte_order_vals[] = {
      { 0, "LSBFirst" },
      { 1, "MSBFirst" },
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

static const value_string colormap_state_vals[] = {
      { 0, "Uninstalled" },
      { 1, "Installed" },
      { 0, NULL }
};

static const value_string coordinate_mode_vals[] = {
      { 0, "Origin" },
      { 1, "Previous" },
      { 0, NULL }
};

static const value_string destination_vals[] = {
      { 0, "PointerWindow" },
      { 1, "InputFocus" },
      { 0, NULL }
};

static const value_string direction_vals[] = {
      { 0, "RaiseLowest" },
      { 1, "LowerHighest" },
      { 0, NULL }
};

static const value_string event_detail_vals[] = {
      { 0, "Ancestor" },
      { 1, "Virtual" },
      { 2, "Inferior" },
      { 3, "Nonlinear" },
      { 4, "NonlinearVirtual" },
      { 0, NULL }
};

#define FAMILY_INTERNET 0
#define FAMILY_DECNET   1
#define FAMILY_CHAOS    2

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

static const value_string focus_detail_vals[] = {
      { 0, "Ancestor" },
      { 1, "Virtual" },
      { 2, "Inferior" },
      { 3, "Nonlinear" },
      { 4, "NonlinearVirtual" },
      { 5, "Pointer" },
      { 6, "PointerRoot" },
      { 7, "None" },
      { 0, NULL }
};

static const value_string focus_mode_vals[] = {
      {  0, "Normal" },
      {  1, "Grab" },
      {  2, "Ungrab" },
      {  3, "WhileGrabbed" },
      {  0, NULL }
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

static const value_string grab_mode_vals[] = {
      {  0, "Normal" },
      {  1, "Grab" },
      {  2, "Ungrab" },
      {  0, NULL }
};

static const value_string grab_status_vals[] = {
      {  0, "Success" },
      {  1, "AlreadyGrabbed" },
      {  2, "InvalidTime" },
      {  3, "NotViewable" },
      {  4, "Frozen" },
      {  0, NULL }
};

static const value_string bit_gravity_vals[] = {
      {  0, "Forget" },
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

static const value_string win_gravity_vals[] = {
      {  0, "Unmap" },
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

#include "x11-keysym.h"

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

static const value_string place_vals[] = {
      { 0, "Top" },
      { 1, "Bottom" },
      { 0, NULL }
};

static const value_string property_state_vals[] = {
      { 0, "NewValue" },
      { 1, "Deleted" },
      { 0, NULL }
};

static const value_string visibility_state_vals[] = {
      { 0, "Unobscured" },
      { 1, "PartiallyObscured" },
      { 2, "FullyObscured" },
      { 0, NULL }
};

static const value_string mapping_request_vals[] = {
      { 0, "MappingModifier" },
      { 1, "MappingKeyboard" },
      { 2, "MappingPointer" },
      { 0, NULL }
};

/* Requestcodes.  From <X11/Xproto.h>. */
#define X_CreateWindow                  1
#define X_ChangeWindowAttributes        2
#define X_GetWindowAttributes           3
#define X_DestroyWindow                 4
#define X_DestroySubwindows             5
#define X_ChangeSaveSet                 6
#define X_ReparentWindow                7
#define X_MapWindow                     8
#define X_MapSubwindows                 9
#define X_UnmapWindow                  10
#define X_UnmapSubwindows              11
#define X_ConfigureWindow              12
#define X_CirculateWindow              13
#define X_GetGeometry                  14
#define X_QueryTree                    15
#define X_InternAtom                   16
#define X_GetAtomName                  17
#define X_ChangeProperty               18
#define X_DeleteProperty               19
#define X_GetProperty                  20
#define X_ListProperties               21
#define X_SetSelectionOwner            22
#define X_GetSelectionOwner            23
#define X_ConvertSelection             24
#define X_SendEvent                    25
#define X_GrabPointer                  26
#define X_UngrabPointer                27
#define X_GrabButton                   28
#define X_UngrabButton                 29
#define X_ChangeActivePointerGrab      30
#define X_GrabKeyboard                 31
#define X_UngrabKeyboard               32
#define X_GrabKey                      33
#define X_UngrabKey                    34
#define X_AllowEvents                  35
#define X_GrabServer                   36
#define X_UngrabServer                 37
#define X_QueryPointer                 38
#define X_GetMotionEvents              39
#define X_TranslateCoords              40
#define X_WarpPointer                  41
#define X_SetInputFocus                42
#define X_GetInputFocus                43
#define X_QueryKeymap                  44
#define X_OpenFont                     45
#define X_CloseFont                    46
#define X_QueryFont                    47
#define X_QueryTextExtents             48
#define X_ListFonts                    49
#define X_ListFontsWithInfo            50
#define X_SetFontPath                  51
#define X_GetFontPath                  52
#define X_CreatePixmap                 53
#define X_FreePixmap                   54
#define X_CreateGC                     55
#define X_ChangeGC                     56
#define X_CopyGC                       57
#define X_SetDashes                    58
#define X_SetClipRectangles            59
#define X_FreeGC                       60
#define X_ClearArea                    61
#define X_CopyArea                     62
#define X_CopyPlane                    63
#define X_PolyPoint                    64
#define X_PolyLine                     65
#define X_PolySegment                  66
#define X_PolyRectangle                67
#define X_PolyArc                      68
#define X_FillPoly                     69
#define X_PolyFillRectangle            70
#define X_PolyFillArc                  71
#define X_PutImage                     72
#define X_GetImage                     73
#define X_PolyText8                    74
#define X_PolyText16                   75
#define X_ImageText8                   76
#define X_ImageText16                  77
#define X_CreateColormap               78
#define X_FreeColormap                 79
#define X_CopyColormapAndFree          80
#define X_InstallColormap              81
#define X_UninstallColormap            82
#define X_ListInstalledColormaps       83
#define X_AllocColor                   84
#define X_AllocNamedColor              85
#define X_AllocColorCells              86
#define X_AllocColorPlanes             87
#define X_FreeColors                   88
#define X_StoreColors                  89
#define X_StoreNamedColor              90
#define X_QueryColors                  91
#define X_LookupColor                  92
#define X_CreateCursor                 93
#define X_CreateGlyphCursor            94
#define X_FreeCursor                   95
#define X_RecolorCursor                96
#define X_QueryBestSize                97
#define X_QueryExtension               98
#define X_ListExtensions               99
#define X_ChangeKeyboardMapping        100
#define X_GetKeyboardMapping           101
#define X_ChangeKeyboardControl        102
#define X_GetKeyboardControl           103
#define X_Bell                         104
#define X_ChangePointerControl         105
#define X_GetPointerControl            106
#define X_SetScreenSaver               107
#define X_GetScreenSaver               108
#define X_ChangeHosts                  109
#define X_ListHosts                    110
#define X_SetAccessControl             111
#define X_SetCloseDownMode             112
#define X_KillClient                   113
#define X_RotateProperties             114
#define X_ForceScreenSaver             115
#define X_SetPointerMapping            116
#define X_GetPointerMapping            117
#define X_SetModifierMapping           118
#define X_GetModifierMapping           119
#define X_NoOperation                  127
#define X_FirstExtension               128
#define X_LastExtension                255

static const value_string opcode_vals[] = {
      { INITIAL_CONN,                   "Initial connection request" },
      { X_CreateWindow,                 "CreateWindow" },
      { X_ChangeWindowAttributes,       "ChangeWindowAttributes" },
      { X_GetWindowAttributes,          "GetWindowAttributes" },
      { X_DestroyWindow,                "DestroyWindow" },
      { X_DestroySubwindows,            "DestroySubwindows" },
      { X_ChangeSaveSet,                "ChangeSaveSet" },
      { X_ReparentWindow,               "ReparentWindow" },
      { X_MapWindow,                    "MapWindow" },
      { X_MapSubwindows,                "MapSubwindows" },
      { X_UnmapWindow,                  "UnmapWindow" },
      { X_UnmapSubwindows,              "UnmapSubwindows" },
      { X_ConfigureWindow,              "ConfigureWindow" },
      { X_CirculateWindow,              "CirculateWindow" },
      { X_GetGeometry,                  "GetGeometry" },
      { X_QueryTree,                    "QueryTree" },
      { X_InternAtom,                   "InternAtom" },
      { X_GetAtomName,                  "GetAtomName" },
      { X_ChangeProperty,               "ChangeProperty" },
      { X_DeleteProperty,               "DeleteProperty" },
      { X_GetProperty,                  "GetProperty" },
      { X_ListProperties,               "ListProperties" },
      { X_SetSelectionOwner,            "SetSelectionOwner" },
      { X_GetSelectionOwner,            "GetSelectionOwner" },
      { X_ConvertSelection,             "ConvertSelection" },
      { X_SendEvent,                    "SendEvent" },
      { X_GrabPointer,                  "GrabPointer" },
      { X_UngrabPointer,                "UngrabPointer" },
      { X_GrabButton,                   "GrabButton" },
      { X_UngrabButton,                 "UngrabButton" },
      { X_ChangeActivePointerGrab,      "ChangeActivePointerGrab" },
      { X_GrabKeyboard,                 "GrabKeyboard" },
      { X_UngrabKeyboard,               "UngrabKeyboard" },
      { X_GrabKey,                      "GrabKey" },
      { X_UngrabKey,                    "UngrabKey" },
      { X_AllowEvents,                  "AllowEvents" },
      { X_GrabServer,                   "GrabServer" },
      { X_UngrabServer,                 "UngrabServer" },
      { X_QueryPointer,                 "QueryPointer" },
      { X_GetMotionEvents,              "GetMotionEvents" },
      { X_TranslateCoords,              "TranslateCoordinates" },
      { X_WarpPointer,                  "WarpPointer" },
      { X_SetInputFocus,                "SetInputFocus" },
      { X_GetInputFocus,                "GetInputFocus" },
      { X_QueryKeymap,                  "QueryKeymap" },
      { X_OpenFont,                     "OpenFont" },
      { X_CloseFont,                    "CloseFont" },
      { X_QueryFont,                    "QueryFont" },
      { X_QueryTextExtents,             "QueryTextExtents" },
      { X_ListFonts,                    "ListFonts" },
      { X_ListFontsWithInfo,            "ListFontsWithInfo" },
      { X_SetFontPath,                  "SetFontPath" },
      { X_GetFontPath,                  "GetFontPath" },
      { X_CreatePixmap,                 "CreatePixmap" },
      { X_FreePixmap,                   "FreePixmap" },
      { X_CreateGC,                     "CreateGC" },
      { X_ChangeGC,                     "ChangeGC" },
      { X_CopyGC,                       "CopyGC" },
      { X_SetDashes,                    "SetDashes" },
      { X_SetClipRectangles,            "SetClipRectangles" },
      { X_FreeGC,                       "FreeGC" },
      { X_ClearArea,                    "ClearArea" },
      { X_CopyArea,                     "CopyArea" },
      { X_CopyPlane,                    "CopyPlane" },
      { X_PolyPoint,                    "PolyPoint" },
      { X_PolyLine,                     "PolyLine" },
      { X_PolySegment,                  "PolySegment" },
      { X_PolyRectangle,                "PolyRectangle" },
      { X_PolyArc,                      "PolyArc" },
      { X_FillPoly,                     "FillPoly" },
      { X_PolyFillRectangle,            "PolyFillRectangle" },
      { X_PolyFillArc,                  "PolyFillArc" },
      { X_PutImage,                     "PutImage" },
      { X_GetImage,                     "GetImage" },
      { X_PolyText8,                    "PolyText8" },
      { X_PolyText16,                   "PolyText16" },
      { X_ImageText8,                   "ImageText8" },
      { X_ImageText16,                  "ImageText16" },
      { X_CreateColormap,               "CreateColormap" },
      { X_FreeColormap,                 "FreeColormap" },
      { X_CopyColormapAndFree,          "CopyColormapAndFree" },
      { X_InstallColormap,              "InstallColormap" },
      { X_UninstallColormap,            "UninstallColormap" },
      { X_ListInstalledColormaps,       "ListInstalledColormaps" },
      { X_AllocColor,                   "AllocColor" },
      { X_AllocNamedColor,              "AllocNamedColor" },
      { X_AllocColorCells,              "AllocColorCells" },
      { X_AllocColorPlanes,             "AllocColorPlanes" },
      { X_FreeColors,                   "FreeColors" },
      { X_StoreColors,                  "StoreColors" },
      { X_StoreNamedColor,              "StoreNamedColor" },
      { X_QueryColors,                  "QueryColors" },
      { X_LookupColor,                  "LookupColor" },
      { X_CreateCursor,                 "CreateCursor" },
      { X_CreateGlyphCursor,            "CreateGlyphCursor" },
      { X_FreeCursor,                   "FreeCursor" },
      { X_RecolorCursor,                "RecolorCursor" },
      { X_QueryBestSize,                "QueryBestSize" },
      { X_QueryExtension,               "QueryExtension" },
      { X_ListExtensions,               "ListExtensions" },
      { X_ChangeKeyboardMapping,        "ChangeKeyboardMapping" },
      { X_GetKeyboardMapping,           "GetKeyboardMapping" },
      { X_ChangeKeyboardControl,        "ChangeKeyboardControl" },
      { X_GetKeyboardControl,           "GetKeyboardControl" },
      { X_Bell,                         "Bell" },
      { X_ChangePointerControl,         "ChangePointerControl" },
      { X_GetPointerControl,            "GetPointerControl" },
      { X_SetScreenSaver,               "SetScreenSaver" },
      { X_GetScreenSaver,               "GetScreenSaver" },
      { X_ChangeHosts,                  "ChangeHosts" },
      { X_ListHosts,                    "ListHosts" },
      { X_SetAccessControl,             "SetAccessControl" },
      { X_SetCloseDownMode,             "SetCloseDownMode" },
      { X_KillClient,                   "KillClient" },
      { X_RotateProperties,             "RotateProperties" },
      { X_ForceScreenSaver,             "ForceScreenSaver" },
      { X_SetPointerMapping,            "SetPointerMapping" },
      { X_GetPointerMapping,            "GetPointerMapping" },
      { X_SetModifierMapping,           "SetModifierMapping" },
      { X_GetModifierMapping,           "GetModifierMapping" },
      { X_NoOperation,                  "NoOperation" },
      { 0,                              NULL }
};

/* Eventscodes.  From <X11/X.h>. */
#define KeyPress                2
#define KeyRelease              3
#define ButtonPress             4
#define ButtonRelease           5
#define MotionNotify            6
#define EnterNotify             7
#define LeaveNotify             8
#define FocusIn                 9
#define FocusOut                10
#define KeymapNotify            11
#define Expose                  12
#define GraphicsExpose          13
#define NoExpose                14
#define VisibilityNotify        15
#define CreateNotify            16
#define DestroyNotify           17
#define UnmapNotify             18
#define MapNotify               19
#define MapRequest              20
#define ReparentNotify          21
#define ConfigureNotify         22
#define ConfigureRequest        23
#define GravityNotify           24
#define ResizeRequest           25
#define CirculateNotify         26
#define CirculateRequest        27
#define PropertyNotify          28
#define SelectionClear          29
#define SelectionRequest        30
#define SelectionNotify         31
#define ColormapNotify          32
#define ClientMessage           33
#define MappingNotify           34
#define GenericEvent            35

static const value_string eventcode_vals[] = {
      { KeyPress,          "KeyPress" },
      { KeyRelease,        "KeyRelease" },
      { ButtonPress,       "ButtonPress" },
      { ButtonRelease,     "ButtonRelease" },
      { MotionNotify,      "MotionNotify" },
      { EnterNotify,       "EnterNotify" },
      { LeaveNotify,       "LeaveNotify" },
      { FocusIn,           "FocusIn" },
      { FocusOut,          "FocusOut" },
      { KeymapNotify,      "KeymapNotify" },
      { Expose,            "Expose" },
      { GraphicsExpose,    "GraphicsExpose" },
      { NoExpose,          "NoExpose" },
      { VisibilityNotify,  "VisibilityNotify" },
      { CreateNotify,      "CreateNotify" },
      { DestroyNotify,     "DestroyNotify" },
      { UnmapNotify,       "UnmapNotify" },
      { MapNotify,         "MapNotify" },
      { MapRequest,        "MapRequest" },
      { ReparentNotify,    "ReparentNotify" },
      { ConfigureNotify,   "ConfigureNotify" },
      { ConfigureRequest,  "ConfigureRequest" },
      { GravityNotify,     "GravityNotify" },
      { ResizeRequest,     "ResizeRequest" },
      { CirculateNotify,   "CirculateNotify" },
      { CirculateRequest,  "CirculateRequest" },
      { PropertyNotify,    "PropertyNotify" },
      { SelectionClear,    "SelectionClear" },
      { SelectionRequest,  "SelectionRequest" },
      { SelectionNotify,   "SelectionNotify" },
      { ColormapNotify,    "ColormapNotify" },
      { ClientMessage,     "ClientMessage" },
      { MappingNotify,     "MappingNotify" },
      { GenericEvent,      "GenericEvent" },
      { 0,                 NULL }
};

/* Errorcodes.  From <X11/X.h> */
#define Success                 0       /* everything's okay */
#define BadRequest              1       /* bad request code */
#define BadValue                2       /* int parameter out of range */
#define BadWindow               3       /* parameter not a Window */
#define BadPixmap               4       /* parameter not a Pixmap */
#define BadAtom                 5       /* parameter not an Atom */
#define BadCursor               6       /* parameter not a Cursor */
#define BadFont                 7       /* parameter not a Font */
#define BadMatch                8       /* parameter mismatch */
#define BadDrawable             9       /* parameter not a Pixmap or Window */
#define BadAccess               10      /* depending on context:
                                         - key/button already grabbed
                                         - attempt to free an illegal
                                           cmap entry
                                        - attempt to store into a read-only
                                           color map entry.
                                        - attempt to modify the access control
                                           list from other than the local host.
                                        */
#define BadAlloc                11      /* insufficient resources */
#define BadColormap             12      /* no such colormap */
#define BadGC                   13      /* parameter not a GC */
#define BadIDChoice             14      /* choice not in range or already used */
#define BadName                 15      /* font or color name doesn't exist */
#define BadLength               16      /* Request length incorrect */
#define BadImplementation       17      /* server is defective */

static const value_string errorcode_vals[] = {
      { Success,               "Success" },
      { BadRequest,            "BadRequest" },
      { BadValue,              "BadValue" },
      { BadWindow,             "BadWindow" },
      { BadPixmap,             "BadPixmap" },
      { BadAtom,               "BadAtom" },
      { BadCursor,             "BadCursor" },
      { BadFont,               "BadFont" },
      { BadMatch,              "BadMatch" },
      { BadDrawable,           "BadDrawable" },
      { BadAccess,             "BadAccess" },
      { BadAlloc,              "BadAlloc" },
      { BadColormap,           "BadColormap" },
      { BadGC,                 "BadGC" },
      { BadIDChoice,           "BadIDChoice" },
      { BadName,               "BadName" },
      { BadLength,             "BadLength" },
      { BadImplementation,     "BadImplementation" },
      { 0,                     NULL }
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
#define FIELD8(name)  (field8(tvb, offsetp, t, hf_x11_##name, byte_order))
#define FIELD16(name) (field16(tvb, offsetp, t, hf_x11_##name, byte_order))
#define FIELD32(name) (field32(tvb, offsetp, t, hf_x11_##name, byte_order))

#define FLAG(position, name) {\
      proto_tree_add_boolean(bitmask_tree, hf_x11_##position##_mask##_##name, tvb, bitmask_offset, bitmask_size, bitmask_value); }

#define FLAG_IF_NONZERO(position, name) do {\
      if (bitmask_value & proto_registrar_get_nth(hf_x11_##position##_mask##_##name) -> bitmask) \
            proto_tree_add_boolean(bitmask_tree, hf_x11_##position##_mask##_##name, tvb, bitmask_offset, bitmask_size, bitmask_value); } while (0)

#define ATOM(name)     { atom(tvb, offsetp, t, hf_x11_##name, byte_order); }
#define BOOL(name)     (add_boolean(tvb, offsetp, t, hf_x11_##name))
#define BUTTON(name)   FIELD8(name)
#define CARD8(name)    FIELD8(name)
#define CARD16(name)   (FIELD16(name))
#define CARD32(name)   (FIELD32(name))
#define COLOR_FLAGS(name) colorFlags(tvb, offsetp, t)
#define COLORMAP(name) FIELD32(name)
#define CURSOR(name)   FIELD32(name)
#define DRAWABLE(name) FIELD32(name)
#define ENUM8(name)    (FIELD8(name))
#define ENUM16(name)   (FIELD16(name))
#define FONT(name)     FIELD32(name)
#define FONTABLE(name) FIELD32(name)
#define GCONTEXT(name) FIELD32(name)
#define INT8(name)     FIELD8(name)
#define INT16(name)    FIELD16(name)
#define INT32(name)    FIELD32(name)
#define KEYCODE(name)  FIELD8(name)
#define KEYCODE_DECODED(name, keycode, mask)  do {                    \
      proto_tree_add_uint_format(t, hf_x11_##name, tvb, offset, 1,    \
      keycode, "keycode: %d (%s)",                                    \
      keycode,  keycode2keysymString(state->keycodemap,               \
      state->first_keycode, state->keysyms_per_keycode,               \
      state->modifiermap, state->keycodes_per_modifier,               \
      keycode, mask));                                                \
      ++offset;                                                       \
} while (0)
#define EVENT() do { \
      tvbuff_t *next_tvb;                                             \
      unsigned char eventcode;                                        \
      const char *sent;                                               \
      proto_tree *event_proto_tree;                                   \
      next_tvb = tvb_new_subset_length_caplen(tvb, offset, next_offset - offset,    \
                                next_offset - offset);                \
      eventcode = tvb_get_guint8(next_tvb, 0);                        \
      sent = (eventcode & 0x80) ? "Sent-" : "";                       \
      event_proto_tree = proto_tree_add_subtree_format(t, next_tvb,   \
                               0, -1, ett_x11_event, NULL,            \
                               "event: %d (%s)",                      \
                               eventcode,                             \
                               val_to_str(eventcode & 0x7F,           \
                                          state->eventcode_vals,      \
                                          "<Unknown eventcode %u>")); \
      decode_x11_event(next_tvb, eventcode, sent, event_proto_tree,   \
                       state, byte_order);                            \
      offset = next_offset;                                           \
} while (0)

#define LISTofARC(name) { listOfArc(tvb, offsetp, t, hf_x11_##name, (next_offset - *offsetp) / 12, byte_order); }
#define LISTofATOM(name, length) { listOfAtom(tvb, offsetp, t, hf_x11_##name, (length) / 4, byte_order); }
#define LISTofBYTE(name, length) { listOfByte(tvb, offsetp, t, hf_x11_##name, (length), byte_order); }
#define LISTofCARD8(name, length) { listOfByte(tvb, offsetp, t, hf_x11_##name, (length), byte_order); }
#define LISTofIPADDRESS(name, length) { listOfByte(tvb, offsetp, t, hf_x11_##name, (length), FALSE); }
#define LISTofCARD16(name, length) { listOfCard16(tvb, offsetp, t, hf_x11_##name, hf_x11_##name##_item, (length) / 2, byte_order); }
#define LISTofCARD32(name, length) { listOfCard32(tvb, offsetp, t, hf_x11_##name, hf_x11_##name##_item, (length) / 4, byte_order); }
#define LISTofCOLORITEM(name, length) { listOfColorItem(tvb, offsetp, t, hf_x11_##name, (length) / 12, byte_order); }
#define LISTofKEYCODE(map, name, length) { listOfKeycode(tvb, offsetp, t, hf_x11_##name, map, (length), byte_order); }
#define LISTofKEYSYM(name, map, keycode_first, keycode_count, \
    keysyms_per_keycode) {\
      listOfKeysyms(tvb, pinfo, offsetp, t, hf_x11_##name, hf_x11_##name##_item, map, (keycode_first), (keycode_count), (keysyms_per_keycode), byte_order); }
#define LISTofPOINT(name, length) { listOfPoint(tvb, offsetp, t, hf_x11_##name, (length) / 4, byte_order); }
#define LISTofRECTANGLE(name) { listOfRectangle(tvb, offsetp, t, hf_x11_##name, (next_offset - *offsetp) / 8, byte_order); }
#define LISTofPIXMAPFORMAT(name, length) { listOfPixmapFormat(tvb, offsetp, t, hf_x11_##name, (length), byte_order); }
#define LISTofSCREEN(name, length) { listOfScreen(tvb, offsetp, t, hf_x11_##name, (length), byte_order); }
#define LISTofSEGMENT(name) { listOfSegment(tvb, offsetp, t, hf_x11_##name, (next_offset - *offsetp) / 8, byte_order); }
#define LISTofSTRING8(name, length) { listOfString8(tvb, offsetp, t, hf_x11_##name, hf_x11_##name##_string, (length), byte_order); }
#define LISTofTEXTITEM8(name) { listOfTextItem(tvb, offsetp, t, hf_x11_##name, FALSE, next_offset, byte_order); }
#define LISTofTEXTITEM16(name) { listOfTextItem(tvb, offsetp, t, hf_x11_##name, TRUE, next_offset, byte_order); }
#define OPCODE() {                                                \
      opcode = tvb_get_guint8(tvb, *offsetp);                             \
      proto_tree_add_uint(t, hf_x11_opcode, tvb, *offsetp,        \
            1, opcode);                                           \
      *offsetp += 1;                                              \
  }

#define PIXMAP(name)   { FIELD32(name); }
#define REQUEST_LENGTH() (requestLength(tvb, offsetp, t, byte_order))
#define SETofEVENT(name) { setOfEvent(tvb, offsetp, t, byte_order); }
#define SETofDEVICEEVENT(name) { setOfDeviceEvent(tvb, offsetp, t, byte_order);}
#define SETofKEYMASK(name) { setOfKeyButMask(tvb, offsetp, t, byte_order, 0); }
#define SETofKEYBUTMASK(name) { setOfKeyButMask(tvb, offsetp, t, byte_order, 1); }
#define SETofPOINTEREVENT(name) { setOfPointerEvent(tvb, offsetp, t, byte_order); }
#define STRING8(name, length)  { string8(tvb, offsetp, t, hf_x11_##name, length); }
#define STRING16(name, length)  { string16(tvb, offsetp, t, hf_x11_##name, hf_x11_##name##_bytes, length, byte_order); }
#define TIMESTAMP(name){ timestamp(tvb, offsetp, t, hf_x11_##name, byte_order); }
#define UNDECODED(x)   { proto_tree_add_item(t, hf_x11_undecoded, tvb, *offsetp,  x, ENC_NA); *offsetp += x; }
#define PAD()          { if (next_offset - *offsetp > 0) proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, next_offset - *offsetp, ENC_NA); *offsetp = next_offset; }
#define WINDOW(name)   { FIELD32(name); }

#define VISUALID(name) { gint32 v = tvb_get_guint32(tvb, *offsetp, byte_order); \
    proto_tree_add_uint_format(t, hf_x11_##name, tvb, *offsetp, 4, v, "Visualid: 0x%08x%s", v, \
                               v ? "" : " (CopyFromParent)"); *offsetp += 4; }
#define REPLY(name)       FIELD8(name);
#define REPLYLENGTH(name) FIELD32(name);

#define EVENTCONTENTS_COMMON() do {                          \
      TIMESTAMP(time);                                       \
      WINDOW(rootwindow);                                    \
      WINDOW(eventwindow);                                   \
      WINDOW(childwindow);                                   \
      INT16(root_x);                                         \
      INT16(root_y);                                         \
      INT16(event_x);                                        \
      INT16(event_y);                                        \
      setOfKeyButMask(tvb, offsetp, t, byte_order, 1);    \
} while (0)

#define SEQUENCENUMBER_REPLY(name) do {                                       \
      guint16 seqno;                                                          \
                                                                              \
      seqno = tvb_get_guint16(tvb, *offsetp, byte_order);                     \
      proto_tree_add_uint_format(t, hf_x11_reply_##name, tvb,                 \
      *offsetp, 2, seqno,                                                     \
      "sequencenumber: %d (%s)",                                              \
      (int)seqno,                                                             \
      val_to_str(opcode & 0xFF, state->opcode_vals, "<Unknown opcode %d>"));  \
      *offsetp += 2;                                                          \
} while (0)

#define REPLYCONTENTS_COMMON() do {                                   \
      REPLY(reply);                                                   \
      proto_tree_add_item(t, hf_x11_undecoded, tvb, *offsetp,         \
             1, ENC_NA);                                              \
      ++(*offsetp);                                                   \
      SEQUENCENUMBER_REPLY(sequencenumber);                           \
      REPLYLENGTH(replylength);                                       \
      proto_tree_add_item(t, hf_x11_undecoded, tvb, *offsetp,         \
             tvb_reported_length_remaining(tvb, *offsetp), ENC_NA);   \
      *offsetp += tvb_reported_length_remaining(tvb, *offsetp);       \
} while (0)


#define HANDLE_REPLY(plen, length_remaining, str, func) do {          \
      if (length_remaining < plen) {                                  \
            if (x11_desegment && pinfo->can_desegment) {              \
                  pinfo->desegment_offset = offset;                   \
                  pinfo->desegment_len    = plen - length_remaining;  \
                  return;                                             \
            } else {                                                  \
                  ; /* XXX yes, what then?  Need to skip/join. */     \
            }                                                         \
      }                                                               \
      if (length_remaining > plen)                                    \
            length_remaining = plen;                                  \
      next_tvb = tvb_new_subset_length_caplen(tvb, offset, length_remaining, plen); \
                                                                      \
      if (sep == NULL) {                                              \
            col_set_str(pinfo->cinfo, COL_INFO, str);                 \
            sep = ":";                                                \
      }                                                               \
                                                                      \
      TRY {                                                           \
            func(next_tvb, pinfo, tree, sep, state, byte_order);      \
      }                                                               \
                                                                      \
      CATCH_NONFATAL_ERRORS {                                         \
            show_exception(next_tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE); \
      }                                                               \
      ENDTRY;                                                         \
                                                                      \
      sep = ",";                                                      \
} while (0)

static void
dissect_x11_initial_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                  const char *sep, x11_conv_data_t *state,
                  guint byte_order);

static void
dissect_x11_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                  const char *sep, x11_conv_data_t *state,
                  guint byte_order);

static void
dissect_x11_error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                  const char *sep, x11_conv_data_t *state,
                  guint byte_order);

static void
dissect_x11_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                  const char *sep, x11_conv_data_t *state,
                  guint byte_order);

static void
decode_x11_event(tvbuff_t *tvb, unsigned char eventcode, const char *sent,
                 proto_tree *t, x11_conv_data_t *state,
                 guint byte_order);

static x11_conv_data_t *
x11_stateinit(conversation_t *conversation);

static const char *
keysymString(guint32 v);


/************************************************************************
 ***                                                                  ***
 ***                  D E C O D I N G   F I E L D S                   ***
 ***                                                                  ***
 ************************************************************************/

static void atom(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
                 guint byte_order)
{
      const char *interpretation = NULL;

      guint32 v = tvb_get_guint32(tvb, *offsetp, byte_order);
      if (v >= 1 && v < array_length(atom_predefined_interpretation))
            interpretation = atom_predefined_interpretation[v];
      else if (v)
            interpretation = "Not a predefined atom";
      else {
            header_field_info *hfi = proto_registrar_get_nth(hf);
            if (hfi -> strings)
                  interpretation = try_val_to_str(v, cVALS(hfi -> strings));
      }
      if (!interpretation) interpretation = "error in Xlib client program ?";
      proto_tree_add_uint_format(t, hf, tvb, *offsetp, 4, v, "%s: %u (%s)",
                                 proto_registrar_get_nth(hf) -> name, v, interpretation);
      *offsetp += 4;
}

static guint32 add_boolean(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf)
{
      guint32 v = tvb_get_guint8(tvb, *offsetp);
      proto_tree_add_boolean(t, hf, tvb, *offsetp, 1, v);
      *offsetp += 1;
      return v;
}

static void colorFlags(tvbuff_t *tvb, int *offsetp, proto_tree *t)
{
      guint do_red_green_blue = tvb_get_guint8(tvb, *offsetp);
      proto_item *ti;
      proto_tree *tt;

      if (do_red_green_blue) {
            int sep = FALSE;
            wmem_strbuf_t *buffer = wmem_strbuf_new_label(wmem_packet_scope());
            wmem_strbuf_append(buffer, "flags: ");

            if (do_red_green_blue & 0x1) {
                  wmem_strbuf_append(buffer, "DoRed");
                  sep = TRUE;
            }

            if (do_red_green_blue & 0x2) {
                  if (sep) wmem_strbuf_append(buffer, " | ");
                  wmem_strbuf_append(buffer, "DoGreen");
                  sep = TRUE;
            }

            if (do_red_green_blue & 0x4) {
                  if (sep) wmem_strbuf_append(buffer, " | ");
                  wmem_strbuf_append(buffer, "DoBlue");
                  sep = TRUE;
            }

            if (do_red_green_blue & 0xf8) {
                  if (sep) wmem_strbuf_append(buffer, " + trash");
            }

            ti = proto_tree_add_uint_format(t, hf_x11_coloritem_flags, tvb, *offsetp, 1, do_red_green_blue,
                                            "%s", wmem_strbuf_get_str(buffer));
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

static void listOfArc(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
                      int length, guint byte_order)
{
      proto_item *ti = proto_tree_add_item(t, hf, tvb, *offsetp, length * 8, byte_order);
      proto_tree *tt = proto_item_add_subtree(ti, ett_x11_list_of_arc);
      while(length--) {
            gint16 x = tvb_get_guint16(tvb, *offsetp, byte_order);
            gint16 y = tvb_get_guint16(tvb, *offsetp + 2, byte_order);
            guint16 width = tvb_get_guint16(tvb, *offsetp + 4, byte_order);
            guint16 height = tvb_get_guint16(tvb, *offsetp + 6, byte_order);
            gint16 angle1 = tvb_get_guint16(tvb, *offsetp + 8, byte_order);
            gint16 angle2 = tvb_get_guint16(tvb, *offsetp + 10, byte_order);

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
                       int length, guint byte_order)
{
      proto_item *ti = proto_tree_add_item(t, hf, tvb, *offsetp, length * 4, byte_order);
      proto_tree *tt = proto_item_add_subtree(ti, ett_x11_list_of_atom);
      while(length--)
            atom(tvb, offsetp, tt, hf_x11_properties_item, byte_order);
}

static void listOfByte(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
                       int length, guint byte_order)
{
      if (length <= 0) length = 1;
      proto_tree_add_item(t, hf, tvb, *offsetp, length, byte_order);
      *offsetp += length;
}

static void listOfCard16(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
                         int hf_item, int length, guint byte_order)
{
      proto_item *ti = proto_tree_add_item(t, hf, tvb, *offsetp, length * 2, byte_order);
      proto_tree *tt = proto_item_add_subtree(ti, ett_x11_list_of_card32);
      while(length--) {
            proto_tree_add_item(tt, hf_item, tvb, *offsetp, 2, byte_order);
            *offsetp += 2;
      }
}

static void listOfInt16(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
                         int hf_item, int length, guint byte_order)
{
      proto_item *ti = proto_tree_add_item(t, hf, tvb, *offsetp, length * 2, byte_order);
      proto_tree *tt = proto_item_add_subtree(ti, ett_x11_list_of_card32);
      while(length--) {
            proto_tree_add_item(tt, hf_item, tvb, *offsetp, 2, byte_order);
            *offsetp += 2;
      }
}

static void listOfCard32(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
                         int hf_item, int length, guint byte_order)
{
      proto_item *ti = proto_tree_add_item(t, hf, tvb, *offsetp, length * 4, byte_order);
      proto_tree *tt = proto_item_add_subtree(ti, ett_x11_list_of_card32);
      while(length--) {
            proto_tree_add_item(tt, hf_item, tvb, *offsetp, 4, byte_order);
            *offsetp += 4;
      }
}

static void listOfInt32(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
                         int hf_item, int length, guint byte_order)
{
      proto_item *ti = proto_tree_add_item(t, hf, tvb, *offsetp, length * 4, byte_order);
      proto_tree *tt = proto_item_add_subtree(ti, ett_x11_list_of_card32);
      while(length--) {
            proto_tree_add_item(tt, hf_item, tvb, *offsetp, 4, byte_order);
            *offsetp += 4;
      }
}

static void listOfCard64(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
                         int hf_item, int length, guint byte_order)
{
      proto_item *ti = proto_tree_add_item(t, hf, tvb, *offsetp, length * 8, byte_order);
      proto_tree *tt = proto_item_add_subtree(ti, ett_x11_list_of_card32);
      while(length--) {
            proto_tree_add_item(tt, hf_item, tvb, *offsetp, 8, byte_order);
            *offsetp += 8;
      }
}

#if 0 /* Not yet used by any extension */
static void listOfInt64(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
                         int hf_item, int length, guint byte_order)
{
      proto_item *ti = proto_tree_add_item(t, hf, tvb, *offsetp, length * 8, byte_order);
      proto_tree *tt = proto_item_add_subtree(ti, ett_x11_list_of_card32);
      while(length--) {
            proto_tree_add_item(tt, hf_item, tvb, *offsetp, 8, byte_order);
            *offsetp += 8;
      }
}
#endif

static void listOfFloat(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
                         int hf_item, int length, guint byte_order)
{
      proto_item *ti = proto_tree_add_item(t, hf, tvb, *offsetp, length * 4, byte_order);
      proto_tree *tt = proto_item_add_subtree(ti, ett_x11_list_of_float);
      while(length--) {
            proto_tree_add_item(tt, hf_item, tvb, *offsetp, 4, byte_order);
            *offsetp += 4;
      }
}

static void listOfDouble(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
                         int hf_item, int length, guint byte_order)
{
      proto_item *ti = proto_tree_add_item(t, hf, tvb, *offsetp, length * 8, byte_order);
      proto_tree *tt = proto_item_add_subtree(ti, ett_x11_list_of_double);
      while(length--) {
            proto_tree_add_item(tt, hf_item, tvb, *offsetp, 8, byte_order);
            *offsetp += 8;
      }
}

static void listOfColorItem(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
                            int length, guint byte_order)
{
      proto_item *ti = proto_tree_add_item(t, hf, tvb, *offsetp, length * 8, byte_order);
      proto_tree *tt = proto_item_add_subtree(ti, ett_x11_list_of_color_item);
      while(length--) {
            proto_item *tti;
            proto_tree *ttt;
            guint do_red_green_blue;
            guint16 red, green, blue;
            wmem_strbuf_t *buffer;
            const char *sep;

            buffer=wmem_strbuf_new_label(wmem_packet_scope());
            wmem_strbuf_append(buffer, "colorItem ");
            red = tvb_get_guint16(tvb, *offsetp + 4, byte_order);
            green = tvb_get_guint16(tvb, *offsetp + 6, byte_order);
            blue = tvb_get_guint16(tvb, *offsetp + 8, byte_order);
            do_red_green_blue = tvb_get_guint8(tvb, *offsetp + 10);

            sep = "";
            if (do_red_green_blue & 0x1) {
                wmem_strbuf_append_printf(buffer, "red = %d", red);
                sep = ", ";
            }
            if (do_red_green_blue & 0x2) {
                wmem_strbuf_append_printf(buffer, "%sgreen = %d", sep, green);
                sep = ", ";
            }
            if (do_red_green_blue & 0x4)
                wmem_strbuf_append_printf(buffer, "%sblue = %d", sep, blue);

            tti = proto_tree_add_none_format(tt, hf_x11_coloritem, tvb, *offsetp, 12, "%s", wmem_strbuf_get_str(buffer));
            ttt = proto_item_add_subtree(tti, ett_x11_color_item);
            proto_tree_add_item(ttt, hf_x11_coloritem_pixel, tvb, *offsetp, 4, byte_order);
            *offsetp += 4;
            proto_tree_add_item(ttt, hf_x11_coloritem_red, tvb, *offsetp, 2, byte_order);
            *offsetp += 2;
            proto_tree_add_item(ttt, hf_x11_coloritem_green, tvb, *offsetp, 2, byte_order);
            *offsetp += 2;
            proto_tree_add_item(ttt, hf_x11_coloritem_blue, tvb, *offsetp, 2, byte_order);
            *offsetp += 2;
            colorFlags(tvb, offsetp, ttt);
            proto_tree_add_item(ttt, hf_x11_coloritem_unused, tvb, *offsetp, 1, byte_order);
            *offsetp += 1;
      }
}

#if 0  /* XXX: Use of GTree no longer needed; use value_string_ext */
static gint compareGuint32(gconstpointer a, gconstpointer b)
{
      return GPOINTER_TO_INT(b) - GPOINTER_TO_INT(a);
}
#endif

static void
XConvertCase(register int sym, int *lower, int *upper)
{
    *lower = sym;
    *upper = sym;
    switch(sym >> 8) {
    case 0: /* Latin 1 */
        if ((sym >= XK_A) && (sym <= XK_Z))
            *lower += (XK_a - XK_A);
        else if ((sym >= XK_a) && (sym <= XK_z))
            *upper -= (XK_a - XK_A);
        else if ((sym >= XK_Agrave) && (sym <= XK_Odiaeresis))
            *lower += (XK_agrave - XK_Agrave);
        else if ((sym >= XK_agrave) && (sym <= XK_odiaeresis))
            *upper -= (XK_agrave - XK_Agrave);
        else if ((sym >= XK_Ooblique) && (sym <= XK_Thorn))
            *lower += (XK_oslash - XK_Ooblique);
        else if ((sym >= XK_oslash) && (sym <= XK_thorn))
            *upper -= (XK_oslash - XK_Ooblique);
        break;
    case 1: /* Latin 2 */
        /* Assume the KeySym is a legal value (ignore discontinuities) */
        if (sym == XK_Aogonek)
            *lower = XK_aogonek;
        else if (sym >= XK_Lstroke && sym <= XK_Sacute)
            *lower += (XK_lstroke - XK_Lstroke);
        else if (sym >= XK_Scaron && sym <= XK_Zacute)
            *lower += (XK_scaron - XK_Scaron);
        else if (sym >= XK_Zcaron && sym <= XK_Zabovedot)
            *lower += (XK_zcaron - XK_Zcaron);
        else if (sym == XK_aogonek)
            *upper = XK_Aogonek;
        else if (sym >= XK_lstroke && sym <= XK_sacute)
            *upper -= (XK_lstroke - XK_Lstroke);
        else if (sym >= XK_scaron && sym <= XK_zacute)
            *upper -= (XK_scaron - XK_Scaron);
        else if (sym >= XK_zcaron && sym <= XK_zabovedot)
            *upper -= (XK_zcaron - XK_Zcaron);
        else if (sym >= XK_Racute && sym <= XK_Tcedilla)
            *lower += (XK_racute - XK_Racute);
        else if (sym >= XK_racute && sym <= XK_tcedilla)
            *upper -= (XK_racute - XK_Racute);
        break;
    case 2: /* Latin 3 */
        /* Assume the KeySym is a legal value (ignore discontinuities) */
        if (sym >= XK_Hstroke && sym <= XK_Hcircumflex)
            *lower += (XK_hstroke - XK_Hstroke);
        else if (sym >= XK_Gbreve && sym <= XK_Jcircumflex)
            *lower += (XK_gbreve - XK_Gbreve);
        else if (sym >= XK_hstroke && sym <= XK_hcircumflex)
            *upper -= (XK_hstroke - XK_Hstroke);
        else if (sym >= XK_gbreve && sym <= XK_jcircumflex)
            *upper -= (XK_gbreve - XK_Gbreve);
        else if (sym >= XK_Cabovedot && sym <= XK_Scircumflex)
            *lower += (XK_cabovedot - XK_Cabovedot);
        else if (sym >= XK_cabovedot && sym <= XK_scircumflex)
            *upper -= (XK_cabovedot - XK_Cabovedot);
        break;
    case 3: /* Latin 4 */
        /* Assume the KeySym is a legal value (ignore discontinuities) */
        if (sym >= XK_Rcedilla && sym <= XK_Tslash)
            *lower += (XK_rcedilla - XK_Rcedilla);
        else if (sym >= XK_rcedilla && sym <= XK_tslash)
            *upper -= (XK_rcedilla - XK_Rcedilla);
        else if (sym == XK_ENG)
            *lower = XK_eng;
        else if (sym == XK_eng)
            *upper = XK_ENG;
        else if (sym >= XK_Amacron && sym <= XK_Umacron)
            *lower += (XK_amacron - XK_Amacron);
        else if (sym >= XK_amacron && sym <= XK_umacron)
            *upper -= (XK_amacron - XK_Amacron);
        break;
    case 6: /* Cyrillic */
        /* Assume the KeySym is a legal value (ignore discontinuities) */
        if (sym >= XK_Serbian_DJE && sym <= XK_Serbian_DZE)
            *lower -= (XK_Serbian_DJE - XK_Serbian_dje);
        else if (sym >= XK_Serbian_dje && sym <= XK_Serbian_dze)
            *upper += (XK_Serbian_DJE - XK_Serbian_dje);
        else if (sym >= XK_Cyrillic_YU && sym <= XK_Cyrillic_HARDSIGN)
            *lower -= (XK_Cyrillic_YU - XK_Cyrillic_yu);
        else if (sym >= XK_Cyrillic_yu && sym <= XK_Cyrillic_hardsign)
            *upper += (XK_Cyrillic_YU - XK_Cyrillic_yu);
        break;
    case 7: /* Greek */
        /* Assume the KeySym is a legal value (ignore discontinuities) */
        if (sym >= XK_Greek_ALPHAaccent && sym <= XK_Greek_OMEGAaccent)
            *lower += (XK_Greek_alphaaccent - XK_Greek_ALPHAaccent);
        else if (sym >= XK_Greek_alphaaccent && sym <= XK_Greek_omegaaccent &&
                 sym != XK_Greek_iotaaccentdieresis &&
                 sym != XK_Greek_upsilonaccentdieresis)
            *upper -= (XK_Greek_alphaaccent - XK_Greek_ALPHAaccent);
        else if (sym >= XK_Greek_ALPHA && sym <= XK_Greek_OMEGA)
            *lower += (XK_Greek_alpha - XK_Greek_ALPHA);
        else if (sym >= XK_Greek_alpha && sym <= XK_Greek_omega &&
                 sym != XK_Greek_finalsmallsigma)
            *upper -= (XK_Greek_alpha - XK_Greek_ALPHA);
        break;
    }
}

static const char *
keycode2keysymString(int *keycodemap[256], int first_keycode,
                     int keysyms_per_keycode,
                     int *modifiermap[array_length(modifiers)],
                     int keycodes_per_modifier,
                     guint32 keycode, guint32 bitmask)
{
      int *syms;
      int groupmodkc, numlockkc, numlockmod, groupmod;
      int lockmod_is_capslock = 0, lockmod_is_shiftlock = 0;
      int lockmod_is_nosymbol = 1;
      int modifier, kc, keysym;

      if ((syms = keycodemap[keycode]) == NULL)
            return "<Unknown>";

      for (kc = first_keycode, groupmodkc = numlockkc = -1; kc < 256; ++kc)
            for (keysym = 0; keysym < keysyms_per_keycode; ++keysym) {
                  if (keycodemap[kc] == NULL)
                        return "<Unknown>";
                  switch (keycodemap[kc][keysym]) {
                        case 0xff7e:
                              groupmodkc = kc;
                              break;

                        case 0xff7f:
                              numlockkc = kc;
                              break;

                        case 0xffe5:
                              lockmod_is_capslock = kc;
                              break;

                        case 0xffe6:
                              lockmod_is_shiftlock = kc;
                              break;
                  }
            }


      /*
       * If we have not seen the modifiermap we don't know what the
       * keycode translates to, but we do know it's one of the keys
       * in syms (give or take a case-conversion), so we could in
       * theory list them all.
       */
      if (modifiermap[array_length(modifiers) - 1] == NULL) /* all or none */
            return "<Unknown>";

      /* find out what the numlockmodifer and groupmodifier is. */
      for (modifier = 0, numlockmod = groupmod = -1;
           modifier < (int)array_length(modifiers) && numlockmod == -1;
           ++modifier)
            for (kc = 0; kc < keycodes_per_modifier; ++kc)
                  if (modifiermap[modifier][kc] == numlockkc)
                        numlockmod = modifier;
                  else if (modifiermap[modifier][kc] == groupmodkc)
                        groupmod = modifier;

      /*
       * ... and what the lockmodifier is interpreted as.
       * (X11v4r6 ref, keyboard and pointers section.)
       */
      for (kc = 0; kc < keycodes_per_modifier; ++kc)
            if (modifiermap[1][kc] == lockmod_is_capslock) {
                  lockmod_is_shiftlock = lockmod_is_nosymbol = 0;
                  break;
            }
            else if (modifiermap[0][kc] == lockmod_is_shiftlock) {
                  lockmod_is_capslock = lockmod_is_nosymbol = 0;
                  break;
            }

#if 0
      /*
       * This is (how I understand) the X11v4R6 protocol description given
       * in A. Nye's book.  It is quite different from the
       * code in _XTranslateKey() in the file
       * "$XConsortium: KeyBind.c /main/55 1996/02/02 14:08:55 kaleb $"
       * as shipped with XFree, and doesn't work correctly, nor do I see
       * how it could (e.g. the case of lower/uppercase-letters).
       * -- Michael Shuldman
       */

      if (numlockmod >= 0 && (bitmask & modifiermask[numlockmod])
          && ((syms[1] >= 0xff80
               && syms[1] <= 0xffbd)
              || (syms[1] >= 0x11000000
                  && syms[1] <= 0x1100ffff))) {
            if ((bitmask & ShiftMask) || lockmod_is_shiftlock)
                  return keysymString(syms[groupmod + 0]);
            else
                  if (syms[groupmod + 1] == NoSymbol)
                        return keysymString(syms[groupmod + 0]);
                  else
                        return keysymString(syms[groupmod + 1]);
      }
      else if (!(bitmask & ShiftMask) && !(bitmask & LockMask))
            return keysymString(syms[groupmod + 0]);
      else if (!(bitmask & ShiftMask)
               && ((bitmask & LockMask) && lockmod_is_capslock))
            if (islower(syms[groupmod + 0]))
/*                      return toupper(keysymString(syms[groupmod + 0])); */
                  return "Uppercase"; /* XXX */
            else
                  return keysymString(syms[groupmod + 0]);

      else if ((bitmask & ShiftMask)
               && ((bitmask & LockMask) && lockmod_is_capslock))
            if (islower(syms[groupmod + 1]))
/*                      return toupper(keysymString(syms[groupmod + 1])); */
                  return "Uppercase"; /* XXX */
            else
                  return keysymString(syms[groupmod + 1]);

      else if ((bitmask & ShiftMask)
               ||  ((bitmask & LockMask) && lockmod_is_shiftlock))
            return keysymString(syms[groupmod + 1]);
#else /* _XTranslateKey() based code. */

      while (keysyms_per_keycode > 2
             && keycodemap[keysyms_per_keycode - 1] == NoSymbol)
            --keysyms_per_keycode;
      if (keysyms_per_keycode > 2
          && (groupmod >= 0 && (modifiermask[groupmod] & bitmask))) {
            syms += 2;
            keysyms_per_keycode -= 2;
      }

      if (numlockmod >= 0 && (bitmask & modifiermask[numlockmod])
          && keysyms_per_keycode > 1
          && ((syms[1] >= 0xff80 && syms[1] <= 0xffbd)
              || (syms[1] >= 0x11000000 && syms[1] <= 0x1100ffff))) {
            if ((bitmask & ShiftMask)
                || (bitmask & LockMask && lockmod_is_shiftlock))
                  keysym = syms[0];
            else
                  keysym = syms[1];
      }
      else if (!(bitmask & ShiftMask)
               && (!(bitmask & LockMask) || lockmod_is_nosymbol)) {
            if (keysyms_per_keycode == 1
                || (keysyms_per_keycode > 1 && syms[1] == NoSymbol)) {
                  int usym;

                  XConvertCase(syms[0], &keysym, &usym);
            }
            else
                  keysym = syms[0];
      }
      else if (!(bitmask & LockMask) || !lockmod_is_capslock) {
            int lsym, usym = 0;

            if (keysyms_per_keycode == 1
                || (keysyms_per_keycode > 1 && (usym = syms[1]) == NoSymbol))
                  XConvertCase(syms[0], &lsym, &usym);
            keysym = usym;
      }
      else {
            int lsym, usym = 0;

            if (keysyms_per_keycode == 1
                || (keysyms_per_keycode > 1 && syms[1] == NoSymbol))
                  keysym = syms[0];

            XConvertCase(keysym, &lsym, &usym);

            if (!(bitmask & ShiftMask) && keysym != syms[0]
                && ((keysym != usym) || (lsym == usym)))
                  XConvertCase(syms[0], &lsym, &usym);
            keysym = usym;
      }

      if (keysym == XK_VoidSymbol)
            keysym = NoSymbol;

      return wmem_strdup_printf(wmem_packet_scope(), "%d, \"%s\"", keysym, keysymString(keysym));
#endif
}

static const char *keysymString(guint32 v)
{
#if 0  /* XXX: Use of GTree no longer needed; use value_string_ext */
      static GTree *keysymTable = NULL;

      gpointer res;
      if (!keysymTable) {

            /* This table is so big that we built it only if necessary */
            const value_string *p = x11_keysym_vals_source;
            keysymTable = g_tree_new(compareGuint32);
            for(; p -> strptr; p++)
                  g_tree_insert(keysymTable, GINT_TO_POINTER(p -> value), (gpointer) (p -> strptr) );
      }
      res = g_tree_lookup(keysymTable, GINT_TO_POINTER(v));
      return res ? res : "<Unknown>";
#endif

      return val_to_str_ext_const(v, &x11_keysym_vals_source_ext, "<Unknown>");

}

static void listOfKeycode(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
                          int *modifiermap[], int keycodes_per_modifier,
                          guint byte_order _U_)
{
      proto_item *ti = proto_tree_add_item(t, hf, tvb, *offsetp,
        (int)array_length(modifiers) * keycodes_per_modifier, ENC_NA);
      proto_tree *tt = proto_item_add_subtree(ti, ett_x11_list_of_keycode);
      size_t m;

      for (m = 0; m < array_length(modifiers);
        ++m, *offsetp += keycodes_per_modifier) {
            proto_item *tikc;
            int i;

            tikc = proto_tree_add_bytes_format(tt, hf_x11_keycodes_item, tvb,
                *offsetp, keycodes_per_modifier, NULL, "item: ");
            modifiermap[m] = (int *)
                wmem_alloc(wmem_file_scope(), sizeof(*modifiermap[m]) * keycodes_per_modifier);
            for(i = 0; i < keycodes_per_modifier; ++i) {
                guchar c = tvb_get_guint8(tvb, (*offsetp) + i);

                if (c)
                    proto_item_append_text(tikc, " %s=%d", modifiers[m], c);

                modifiermap[m][i] = c;
            }
      }
}

static void listOfKeysyms(tvbuff_t *tvb, packet_info *pinfo, int *offsetp, proto_tree *t, int hf,
                          int hf_item, int *keycodemap[256],
                          int keycode_first, int keycode_count,
                          int keysyms_per_keycode, guint byte_order)
{
      proto_item *ti = proto_tree_add_item(t, hf, tvb, *offsetp, keycode_count * keysyms_per_keycode * 4, byte_order);
      proto_tree *tt = proto_item_add_subtree(ti, ett_x11_list_of_keysyms);
      proto_item *tti;
      proto_tree *ttt;
      int i, keycode;

      DISSECTOR_ASSERT(keycode_first >= 0);
      DISSECTOR_ASSERT(keycode_count >= 0);

      for (keycode = keycode_first; keycode_count > 0;
           ++keycode, --keycode_count) {
            tti = proto_tree_add_none_format(tt, hf_item, tvb, *offsetp,
                                             4 * keysyms_per_keycode, "keysyms (keycode %d):", keycode);
            if (keycode >= 256) {
                  expert_add_info_format(pinfo, tti, &ei_x11_keycode_value_out_of_range,
                                      "keycode value %d is out of range", keycode);
                  *offsetp += 4 * keysyms_per_keycode;
                  continue;
            }

            ttt = proto_item_add_subtree(tti, ett_x11_keysym);

            tvb_ensure_bytes_exist(tvb, *offsetp, 4 * keysyms_per_keycode);
            keycodemap[keycode]
                  =  (int *)wmem_alloc(wmem_file_scope(), sizeof(*keycodemap[keycode]) * keysyms_per_keycode);

            for(i = 0; i < keysyms_per_keycode; ++i) {
                  /* keysymvalue = byte3 * 256 + byte4. */
                  guint32 v = tvb_get_guint32(tvb, *offsetp, byte_order);

                  proto_item_append_text(tti, " %s", keysymString(v));
                  proto_tree_add_uint_format(ttt, hf_x11_keysyms_item_keysym,
                                             tvb, *offsetp, 4, v,
                                             "keysym (keycode %d): 0x%08x (%s)",
                                             keycode, v, keysymString(v));

                  keycodemap[keycode][i] = v;
                  *offsetp += 4;
            }

            for (i = 1; i < keysyms_per_keycode; ++i)
                  if (keycodemap[keycode][i] != NoSymbol)
                        break;

            if (i == keysyms_per_keycode) {
                  /* all but (possibly) first were NoSymbol. */
                  if (keysyms_per_keycode == 4) {
                        keycodemap[keycode][1] = NoSymbol;
                        keycodemap[keycode][2] = keycodemap[keycode][0];
                        keycodemap[keycode][3] = NoSymbol;
                  }

                  continue;
            }

            for (i = 2; i < keysyms_per_keycode; ++i)
                  if (keycodemap[keycode][i] != NoSymbol)
                        break;
            if (i == keysyms_per_keycode) {
                  /* all but (possibly) first two were NoSymbol. */
                  if (keysyms_per_keycode == 4) {
                        keycodemap[keycode][2] = keycodemap[keycode][0];
                        keycodemap[keycode][3] =  keycodemap[keycode][1];
                  }

                  continue;
            }
      }
}

static void listOfPoint(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
                        int length, guint byte_order)
{
      proto_item *ti = proto_tree_add_item(t, hf, tvb, *offsetp, length * 4, byte_order);
      proto_tree *tt = proto_item_add_subtree(ti, ett_x11_list_of_point);
      while(length--) {
            gint16 x, y;
            proto_item *tti;
            proto_tree *ttt;

            x = tvb_get_guint16(tvb, *offsetp, byte_order);
            y = tvb_get_guint16(tvb, *offsetp + 2, byte_order);

            tti = proto_tree_add_none_format(tt, hf_x11_point, tvb, *offsetp, 4, "point: (%d,%d)", x, y);
            ttt = proto_item_add_subtree(tti, ett_x11_point);
            proto_tree_add_int(ttt, hf_x11_point_x, tvb, *offsetp, 2, x);
            *offsetp += 2;
            proto_tree_add_int(ttt, hf_x11_point_y, tvb, *offsetp, 2, y);
            *offsetp += 2;
      }
}

static void listOfRectangle(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
                            int length, guint byte_order)
{
      proto_item *ti = proto_tree_add_item(t, hf, tvb, *offsetp, length * 8, byte_order);
      proto_tree *tt = proto_item_add_subtree(ti, ett_x11_list_of_rectangle);
      while(length--) {
            gint16 x, y;
            guint width, height;
            proto_item *tti;
            proto_tree *ttt;

            x = tvb_get_guint16(tvb, *offsetp, byte_order);
            y = tvb_get_guint16(tvb, *offsetp + 2, byte_order);
            width = tvb_get_guint16(tvb, *offsetp + 4, byte_order);
            height = tvb_get_guint16(tvb, *offsetp + 6, byte_order);

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
                          int length, guint byte_order)
{
      proto_item *ti = proto_tree_add_item(t, hf, tvb, *offsetp, length * 8, byte_order);
      proto_tree *tt = proto_item_add_subtree(ti, ett_x11_list_of_segment);
      while(length--) {
            gint16 x1, y1, x2, y2;
            proto_item *tti;
            proto_tree *ttt;

            x1 = tvb_get_guint16(tvb, *offsetp, byte_order);
            y1 = tvb_get_guint16(tvb, *offsetp + 2, byte_order);
            x2 = tvb_get_guint16(tvb, *offsetp + 4, byte_order);
            y2 = tvb_get_guint16(tvb, *offsetp + 6, byte_order);

            tti = proto_tree_add_none_format(tt, hf_x11_segment, tvb, *offsetp, 8,
                                                 "segment: (%d,%d)-(%d,%d)", x1, y1, x2, y2);
            ttt = proto_item_add_subtree(tti, ett_x11_segment);
            proto_tree_add_item(ttt, hf_x11_segment_x1, tvb, *offsetp, 2, byte_order);
            *offsetp += 2;
            proto_tree_add_item(ttt, hf_x11_segment_y1, tvb, *offsetp, 2, byte_order);
            *offsetp += 2;
            proto_tree_add_item(ttt, hf_x11_segment_x2, tvb, *offsetp, 2, byte_order);
            *offsetp += 2;
            proto_tree_add_item(ttt, hf_x11_segment_y2, tvb, *offsetp, 2, byte_order);
            *offsetp += 2;
      }
}

static void listOfVisualTypes(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
                              int length, guint byte_order)
{
      proto_item *ti = proto_tree_add_item(t, hf, tvb, *offsetp, length * 24, byte_order);
      proto_tree *tt = proto_item_add_subtree(ti, ett_x11_list_of_visualtype);
      while(length--) {
            proto_item *tti;
            proto_tree *ttt;

            tti = proto_tree_add_none_format(tt, hf_x11_visualtype, tvb, *offsetp, 24,
                                             "visualtype");
            ttt = proto_item_add_subtree(tti, ett_x11_visualtype);
            proto_tree_add_item(ttt, hf_x11_visualtype_visualid, tvb, *offsetp, 4, byte_order);
            *offsetp += 4;
            proto_tree_add_item(ttt, hf_x11_visualtype_class, tvb, *offsetp, 1, byte_order);
            *offsetp += 1;
            proto_tree_add_item(ttt, hf_x11_visualtype_bits_per_rgb_value, tvb, *offsetp, 1, byte_order);
            *offsetp += 1;
            proto_tree_add_item(ttt, hf_x11_visualtype_colormap_entries, tvb, *offsetp, 2, byte_order);
            *offsetp += 2;
            proto_tree_add_item(ttt, hf_x11_visualtype_red_mask, tvb, *offsetp, 4, byte_order);
            *offsetp += 4;
            proto_tree_add_item(ttt, hf_x11_visualtype_green_mask, tvb, *offsetp, 4, byte_order);
            *offsetp += 4;
            proto_tree_add_item(ttt, hf_x11_visualtype_blue_mask, tvb, *offsetp, 4, byte_order);
            *offsetp += 4;
            proto_tree_add_item(ttt, hf_x11_unused, tvb, *offsetp, 4, byte_order);
            *offsetp += 4;
      }
}
static void listOfDepth(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
                        int length, guint byte_order)
{
      guint16 number_of_visualtypes;
      proto_item *ti;
      proto_tree *tt;

      ti = proto_tree_add_item(t, hf, tvb, *offsetp, -1, byte_order);
      tt = proto_item_add_subtree(ti, ett_x11_list_of_depth_detail);
      while(length--) {
            proto_item *tti;
            proto_tree *ttt;
            number_of_visualtypes = tvb_get_guint16(tvb, *offsetp + 2, byte_order);

            tti = proto_tree_add_none_format(tt, hf_x11_depth_detail, tvb, *offsetp, 8 + 24 * number_of_visualtypes,
                                             "depth-detail");
            ttt = proto_item_add_subtree(tti, ett_x11_screen);
            proto_tree_add_item(ttt, hf_x11_depth_detail_depth, tvb, *offsetp, 1, byte_order);
            *offsetp += 1;
            proto_tree_add_item(ttt, hf_x11_unused, tvb, *offsetp, 1, byte_order);
            *offsetp += 1;
            proto_tree_add_item(ttt, hf_x11_depth_detail_visualtypes_numbers, tvb, *offsetp, 2, byte_order);
            *offsetp += 2;
            proto_tree_add_item(ttt, hf_x11_unused, tvb, *offsetp, 4, byte_order);
            *offsetp += 4;
            if (number_of_visualtypes > 0)
                    listOfVisualTypes(tvb, offsetp, ttt, hf_x11_visualtype, number_of_visualtypes, byte_order);
      }
}

static void listOfScreen(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
                         int length, guint byte_order)
{
      proto_item *ti = proto_tree_add_item(t, hf, tvb, *offsetp, -1, byte_order);
      proto_tree *tt = proto_item_add_subtree(ti, ett_x11_list_of_screen);
      while(length--) {
            guint8 number_of_depths, root_depth;
            guint16 width_in_pixels, height_in_pixels;
            guint32 screen_root;
            proto_item *tti;
            proto_tree *ttt;

            screen_root = tvb_get_guint32(tvb, *offsetp, byte_order);
            width_in_pixels = tvb_get_guint16(tvb, *offsetp + 20, byte_order);
            height_in_pixels = tvb_get_guint16(tvb, *offsetp + 22, byte_order);
            root_depth = tvb_get_guint8(tvb, *offsetp + 38);
            tti = proto_tree_add_none_format(tt, hf_x11_screen, tvb, *offsetp, 0,
                                                 "screen (%08x: %d x %d x %d)", screen_root,
                                                 width_in_pixels, height_in_pixels, root_depth);
            ttt = proto_item_add_subtree(tti, ett_x11_screen);
            proto_tree_add_item(ttt, hf_x11_screen_root, tvb, *offsetp, 4, byte_order);
            *offsetp += 4;
            proto_tree_add_item(ttt, hf_x11_screen_default_colormap, tvb, *offsetp, 4, byte_order);
            *offsetp += 4;
            proto_tree_add_item(ttt, hf_x11_screen_white_pixel, tvb, *offsetp, 4, byte_order);
            *offsetp += 4;
            proto_tree_add_item(ttt, hf_x11_screen_black_pixel, tvb, *offsetp, 4, byte_order);
            *offsetp += 4;
            proto_tree_add_item(ttt, hf_x11_screen_current_input_masks, tvb, *offsetp, 4, byte_order);
            *offsetp += 4;
            proto_tree_add_item(ttt, hf_x11_screen_width_in_pixels, tvb, *offsetp, 2, byte_order);
            *offsetp += 2;
            proto_tree_add_item(ttt, hf_x11_screen_height_in_pixels, tvb, *offsetp, 2, byte_order);
            *offsetp += 2;
            proto_tree_add_item(ttt, hf_x11_screen_width_in_millimeters, tvb, *offsetp, 2, byte_order);
            *offsetp += 2;
            proto_tree_add_item(ttt, hf_x11_screen_height_in_millimeters, tvb, *offsetp, 2, byte_order);
            *offsetp += 2;
            proto_tree_add_item(ttt, hf_x11_screen_min_installed_maps, tvb, *offsetp, 2, byte_order);
            *offsetp += 2;
            proto_tree_add_item(ttt, hf_x11_screen_max_installed_maps, tvb, *offsetp, 2, byte_order);
            *offsetp += 2;
            proto_tree_add_item(ttt, hf_x11_screen_root_visual, tvb, *offsetp, 4, byte_order);
            *offsetp += 4;
            proto_tree_add_item(ttt, hf_x11_screen_backing_stores, tvb, *offsetp, 1, byte_order);
            *offsetp += 1;
            proto_tree_add_item(ttt, hf_x11_screen_save_unders, tvb, *offsetp, 1, byte_order);
            *offsetp += 1;
            proto_tree_add_item(ttt, hf_x11_screen_root_depth, tvb, *offsetp, 1, byte_order);
            *offsetp += 1;
            number_of_depths = tvb_get_guint8(tvb, *offsetp);
            proto_tree_add_item(ttt, hf_x11_screen_allowed_depths_len, tvb, *offsetp, 1, byte_order);
            *offsetp += 1;
            listOfDepth(tvb, offsetp, ttt, hf_x11_depth_detail, number_of_depths, byte_order);
      }
}
static void listOfPixmapFormat(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
                               int length, guint byte_order)
{
      proto_item *ti = proto_tree_add_item(t, hf, tvb, *offsetp, length * 8, byte_order);
      proto_tree *tt = proto_item_add_subtree(ti, ett_x11_list_of_pixmap_format);
      while(length--) {
            proto_item *tti;
            proto_tree *ttt;

            tti = proto_tree_add_none_format(tt, hf_x11_pixmap_format, tvb, *offsetp, 8,
                                                 "pixmap-format");
            ttt = proto_item_add_subtree(tti, ett_x11_pixmap_format);
            proto_tree_add_item(ttt, hf_x11_pixmap_format_depth, tvb, *offsetp, 1, byte_order);
            *offsetp += 1;
            proto_tree_add_item(ttt, hf_x11_pixmap_format_bits_per_pixel, tvb, *offsetp, 1, byte_order);
            *offsetp += 1;
            proto_tree_add_item(ttt, hf_x11_pixmap_format_scanline_pad, tvb, *offsetp, 1, byte_order);
            *offsetp += 1;
            proto_tree_add_item(ttt, hf_x11_unused, tvb, *offsetp, 5, byte_order);
            *offsetp += 5;
      }
}

static void listOfString8(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
                          int hf_item, int length, guint byte_order)
{
      char *s = NULL;
      proto_item *ti;
      proto_tree *tt;
      int i;

      /* Compute total length */

      int scanning_offset = *offsetp; /* Scanning pointer */
      for(i = length; i; i--) {
            int l;
            l = tvb_get_guint8(tvb, scanning_offset);
            scanning_offset += 1 + l;
      }

      ti = proto_tree_add_item(t, hf, tvb, *offsetp, scanning_offset - *offsetp, byte_order);
      tt = proto_item_add_subtree(ti, ett_x11_list_of_string8);

      while(length--) {
            guint l = tvb_get_guint8(tvb, *offsetp);
            s = tvb_get_string_enc(wmem_packet_scope(), tvb, *offsetp + 1, l, ENC_ASCII);
            proto_tree_add_string_format(tt, hf_item, tvb, *offsetp, l + 1, s, "\"%s\"", s);
            *offsetp += l + 1;
      }
}

static int stringIsActuallyAn8BitString(tvbuff_t *tvb, int offset, guint length)
{
      for(; length > 0; offset += 2, length--) {
            if (tvb_get_guint8(tvb, offset))
                  return FALSE;
      }
      return TRUE;
}

#define UNREPL 0x00FFFD

/* XXX - assumes that the string encoding is ASCII; even if 0x00 through
   0x7F are ASCII, 0x80 through 0xFF might not be, and even 0x00 through
   0x7F aren't necessarily ASCII. */
static char *tvb_get_ascii_string16(tvbuff_t *tvb, int offset, guint length)
{
      wmem_strbuf_t *str;
      guint8 ch;

      str = wmem_strbuf_sized_new(wmem_packet_scope(), length + 1, 0);

      while(length--) {
            offset++;
            ch = tvb_get_guint8(tvb, offset);
            if (ch < 0x80)
                  wmem_strbuf_append_c(str, ch);
            else
                  wmem_strbuf_append_unichar(str, UNREPL);
            offset++;
      }
      return wmem_strbuf_finalize(str);
}

static void listOfTextItem(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
    int sizeIs16, int next_offset, guint byte_order)
{
      char *s = NULL;
      proto_item *ti;
      proto_tree *tt;
      guint32 fid;

      /* Compute total length */

      int scanning_offset = *offsetp; /* Scanning pointer */
      int n = 0;                        /* Number of items */

      while(scanning_offset < next_offset) {
            int l;                            /* Length of an individual item */
            l = tvb_get_guint8(tvb, scanning_offset);
            scanning_offset++;
            if (!l) break;
            n++;
            scanning_offset += l == 255 ? 4 : l + (sizeIs16 ? l : 0) + 1;
      }

      ti = proto_tree_add_item(t, hf, tvb, *offsetp, scanning_offset - *offsetp, byte_order);
      tt = proto_item_add_subtree(ti, ett_x11_list_of_text_item);

      while(n--) {
            guint l = tvb_get_guint8(tvb, *offsetp);
            if (l == 255) { /* Item is a font */
                  fid = tvb_get_ntohl(tvb, *offsetp + 1);
                  proto_tree_add_uint(tt, hf_x11_textitem_font, tvb, *offsetp, 5, fid);
                  *offsetp += 5;
            } else { /* Item is a string */
                  proto_item *tti;
                  proto_tree *ttt;
                  gint8 delta = tvb_get_guint8(tvb, *offsetp + 1);
                  if (sizeIs16) {
                        if (stringIsActuallyAn8BitString(tvb, *offsetp + 2, l)) {
                              s = tvb_get_ascii_string16(tvb, *offsetp + 2, l);
                              tti = proto_tree_add_none_format(tt, hf_x11_textitem_string, tvb, *offsetp, l*2 + 2,
                                                               "textitem (string): delta = %d, \"%s\"",
                                                               delta, s);
                              ttt = proto_item_add_subtree(tti, ett_x11_text_item);
                              proto_tree_add_item(ttt, hf_x11_textitem_string_delta, tvb, *offsetp + 1, 1, byte_order);
                              proto_tree_add_string_format_value(ttt, hf_x11_textitem_string_string16, tvb,
                                                                 *offsetp + 2, l, s, "\"%s\"", s);
                        } else {
                              tti = proto_tree_add_none_format(tt, hf_x11_textitem_string, tvb, *offsetp, l*2 + 2,
                                                               "textitem (string): delta = %d, %s",
                                                               delta,
                                                               tvb_bytes_to_str(wmem_packet_scope(), tvb, *offsetp + 2, l*2));
                              ttt = proto_item_add_subtree(tti, ett_x11_text_item);
                              proto_tree_add_item(ttt, hf_x11_textitem_string_delta, tvb, *offsetp + 1, 1, byte_order);
                              proto_tree_add_item(ttt, hf_x11_textitem_string_string16_bytes, tvb, *offsetp + 2, l*2, byte_order);
                        }
                        *offsetp += l*2 + 2;
                  } else {
                        s = tvb_get_string_enc(wmem_packet_scope(), tvb, *offsetp + 2, l, ENC_ASCII);
                        tti = proto_tree_add_none_format(tt, hf_x11_textitem_string, tvb, *offsetp, l + 2,
                                                         "textitem (string): delta = %d, \"%s\"",
                                                         delta, s);
                        ttt = proto_item_add_subtree(tti, ett_x11_text_item);
                        proto_tree_add_item(ttt, hf_x11_textitem_string_delta, tvb, *offsetp + 1, 1, byte_order);
                        proto_tree_add_string_format(ttt, hf_x11_textitem_string_string8, tvb,
                                                     *offsetp + 2, l, s, "\"%s\"", s);
                        *offsetp += l + 2;
                  }
            }
      }
}

static guint32 field8(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
                      guint byte_order)
{
      guint32 v = tvb_get_guint8(tvb, *offsetp);
      header_field_info *hfi = proto_registrar_get_nth(hf);
      const gchar *enumValue = NULL;

      if (hfi -> strings)
            enumValue = try_val_to_str(v, cVALS(hfi -> strings));
      if (enumValue)
            proto_tree_add_uint_format(t, hf, tvb, *offsetp, 1, v,
            hfi -> display == BASE_DEC ? "%s: %u (%s)" : "%s: 0x%02x (%s)",
            hfi -> name, v, enumValue);
      else
            proto_tree_add_item(t, hf, tvb, *offsetp, 1, byte_order);
      *offsetp += 1;
      return v;
}

static guint32 field16(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
                       guint byte_order)
{
      guint32 v = tvb_get_guint16(tvb, *offsetp, byte_order);
      header_field_info *hfi = proto_registrar_get_nth(hf);
      const gchar *enumValue = NULL;

      if (hfi -> strings)
            enumValue = try_val_to_str(v, cVALS(hfi -> strings));
      if (enumValue)
            proto_tree_add_uint_format(t, hf, tvb, *offsetp, 2, v,
            hfi -> display == BASE_DEC ? "%s: %u (%s)" : "%s: 0x%02x (%s)",
            hfi -> name, v, enumValue);
      else
            proto_tree_add_item(t, hf, tvb, *offsetp, 2, byte_order);
      *offsetp += 2;
      return v;
}

static guint32 field32(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
                       guint byte_order)
{
      guint32 v = tvb_get_guint32(tvb, *offsetp, byte_order);
      header_field_info *hfi = proto_registrar_get_nth(hf);
      const gchar *enumValue = NULL;
      const gchar *nameAsChar = hfi -> name;

      if (hfi -> strings)
            enumValue = try_val_to_str(v, cVALS(hfi -> strings));
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

static int * const gc_mask_attributes[] = {
    &hf_x11_gc_value_mask_function,
    &hf_x11_gc_value_mask_plane_mask,
    &hf_x11_gc_value_mask_foreground,
    &hf_x11_gc_value_mask_background,
    &hf_x11_gc_value_mask_line_width,
    &hf_x11_gc_value_mask_line_style,
    &hf_x11_gc_value_mask_cap_style,
    &hf_x11_gc_value_mask_join_style,
    &hf_x11_gc_value_mask_fill_style,
    &hf_x11_gc_value_mask_fill_rule,
    &hf_x11_gc_value_mask_tile,
    &hf_x11_gc_value_mask_stipple,
    &hf_x11_gc_value_mask_tile_stipple_x_origin,
    &hf_x11_gc_value_mask_tile_stipple_y_origin,
    &hf_x11_gc_value_mask_font,
    &hf_x11_gc_value_mask_subwindow_mode,
    &hf_x11_gc_value_mask_graphics_exposures,
    &hf_x11_gc_value_mask_clip_x_origin,
    &hf_x11_gc_value_mask_clip_y_origin,
    &hf_x11_gc_value_mask_clip_mask,
    &hf_x11_gc_value_mask_dash_offset,
    &hf_x11_gc_value_mask_gc_dashes,
    &hf_x11_gc_value_mask_arc_mode,
    NULL
};

static void gcAttributes(tvbuff_t *tvb, int *offsetp, proto_tree *t,
                         guint byte_order)
{
      guint32 bitmask;
      bitmask = tvb_get_guint32(tvb, *offsetp, byte_order);
      proto_tree_add_bitmask(t, tvb, *offsetp, hf_x11_gc_value_mask, ett_x11_gc_value_mask, gc_mask_attributes, byte_order);
      *offsetp += 4;

      if (bitmask & 0x00000001) {
          proto_tree_add_item(t, hf_x11_function, tvb, *offsetp, 1, byte_order);
          *offsetp += 1;
          proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 3, ENC_NA);
          *offsetp += 3;
      }
      if (bitmask & 0x00000002) {
          proto_tree_add_item(t, hf_x11_plane_mask, tvb, *offsetp, 4, byte_order);
          *offsetp += 4;
      }
      if (bitmask & 0x00000004) {
          proto_tree_add_item(t, hf_x11_foreground, tvb, *offsetp, 4, byte_order);
          *offsetp += 4;
      }
      if (bitmask & 0x00000008) {
          proto_tree_add_item(t, hf_x11_background, tvb, *offsetp, 4, byte_order);
          *offsetp += 4;
      }
      if (bitmask & 0x00000010) {
          proto_tree_add_item(t, hf_x11_line_width, tvb, *offsetp, 2, byte_order);
          *offsetp += 2;
          proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
          *offsetp += 2;
      }
      if (bitmask & 0x00000020) {
          proto_tree_add_item(t, hf_x11_line_style, tvb, *offsetp, 1, byte_order);
          *offsetp += 1;
          proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 3, ENC_NA);
          *offsetp += 3;
      }
      if (bitmask & 0x00000040) {
          proto_tree_add_item(t, hf_x11_cap_style, tvb, *offsetp, 1, byte_order);
          *offsetp += 1;
          proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 3, ENC_NA);
          *offsetp += 3;
      }
      if (bitmask & 0x00000080) {
          proto_tree_add_item(t, hf_x11_join_style, tvb, *offsetp, 1, byte_order);
          *offsetp += 1;
          proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 3, ENC_NA);
          *offsetp += 3;
      }
      if (bitmask & 0x00000100) {
          proto_tree_add_item(t, hf_x11_fill_style, tvb, *offsetp, 1, byte_order);
          *offsetp += 1;
          proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 3, ENC_NA);
          *offsetp += 3;
      }
      if (bitmask & 0x00000200) {
          proto_tree_add_item(t, hf_x11_fill_rule, tvb, *offsetp, 1, byte_order);
          *offsetp += 1;
          proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 3, ENC_NA);
          *offsetp += 3;
      }
      if (bitmask & 0x00000400) {
          proto_tree_add_item(t, hf_x11_tile, tvb, *offsetp, 4, byte_order);
          *offsetp += 4;
      }
      if (bitmask & 0x00000800) {
          proto_tree_add_item(t, hf_x11_stipple, tvb, *offsetp, 4, byte_order);
          *offsetp += 4;
      }
      if (bitmask & 0x00001000) {
          proto_tree_add_item(t, hf_x11_tile_stipple_x_origin, tvb, *offsetp, 2, byte_order);
          *offsetp += 2;
          proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
          *offsetp += 2;
      }
      if (bitmask & 0x00002000) {
          proto_tree_add_item(t, hf_x11_tile_stipple_y_origin, tvb, *offsetp, 2, byte_order);
          *offsetp += 2;
          proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
          *offsetp += 2;
      }
      if (bitmask & 0x00004000) {
          proto_tree_add_item(t, hf_x11_font, tvb, *offsetp, 4, byte_order);
          *offsetp += 4;
      }
      if (bitmask & 0x00008000) {
          proto_tree_add_item(t, hf_x11_subwindow_mode, tvb, *offsetp, 1, byte_order);
          *offsetp += 1;
          proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 3, ENC_NA);
          *offsetp += 3;
      }
      if (bitmask & 0x00010000) {
          proto_tree_add_item(t, hf_x11_graphics_exposures, tvb, *offsetp, 1, byte_order);
          *offsetp += 1;
          proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 3, ENC_NA);
          *offsetp += 3;
      }
      if (bitmask & 0x00020000) {
          proto_tree_add_item(t, hf_x11_clip_x_origin, tvb, *offsetp, 2, byte_order);
          *offsetp += 2;
          proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
          *offsetp += 2;
      }
      if (bitmask & 0x00040000) {
          proto_tree_add_item(t, hf_x11_clip_y_origin, tvb, *offsetp, 2, byte_order);
          *offsetp += 2;
          proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
          *offsetp += 2;
      }
      if (bitmask & 0x00080000) {
          proto_tree_add_item(t, hf_x11_clip_mask, tvb, *offsetp, 4, byte_order);
          *offsetp += 4;
      }
      if (bitmask & 0x00100000) {
          proto_tree_add_item(t, hf_x11_dash_offset, tvb, *offsetp, 2, byte_order);
          *offsetp += 2;
          proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
          *offsetp += 2;
      }
      if (bitmask & 0x00200000) {
          proto_tree_add_item(t, hf_x11_gc_dashes, tvb, *offsetp, 1, byte_order);
          *offsetp += 1;
          proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 3, ENC_NA);
          *offsetp += 3;
      }
      if (bitmask & 0x00400000) {
          proto_tree_add_item(t, hf_x11_arc_mode, tvb, *offsetp, 1, byte_order);
          *offsetp += 1;
          proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 3, ENC_NA);
          *offsetp += 3;
      }
}

static void gcMask(tvbuff_t *tvb, int *offsetp, proto_tree *t,
                   guint byte_order)
{
      proto_tree_add_bitmask(t, tvb, *offsetp, hf_x11_gc_value_mask, ett_x11_gc_value_mask, gc_mask_attributes, byte_order);
      *offsetp += 4;
}

static guint32 requestLength(tvbuff_t *tvb, int *offsetp, proto_tree *t,
                             guint byte_order)
{
      guint32 res;
      proto_item *ti = proto_tree_add_item_ret_uint(t, hf_x11_request_length, tvb, *offsetp, 2, byte_order, &res);
      *offsetp += 2;
      if (res == 0) {
            proto_item_append_text(ti, " (extended length flag)");
            proto_tree_add_item_ret_uint(t, hf_x11_request_length, tvb, *offsetp, 4, byte_order, &res);
            *offsetp += 4;
      }
      return res * 4;
}

static void setOfEvent(tvbuff_t *tvb, int *offsetp, proto_tree *t,
                       guint byte_order)
{
      static int * const events[] = {
            &hf_x11_event_mask_KeyPress,
            &hf_x11_event_mask_KeyRelease,
            &hf_x11_event_mask_ButtonPress,
            &hf_x11_event_mask_ButtonRelease,
            &hf_x11_event_mask_EnterWindow,
            &hf_x11_event_mask_LeaveWindow,
            &hf_x11_event_mask_PointerMotion,
            &hf_x11_event_mask_PointerMotionHint,
            &hf_x11_event_mask_Button1Motion,
            &hf_x11_event_mask_Button2Motion,
            &hf_x11_event_mask_Button3Motion,
            &hf_x11_event_mask_Button4Motion,
            &hf_x11_event_mask_Button5Motion,
            &hf_x11_event_mask_ButtonMotion,
            &hf_x11_event_mask_KeymapState,
            &hf_x11_event_mask_Exposure,
            &hf_x11_event_mask_VisibilityChange,
            &hf_x11_event_mask_StructureNotify,
            &hf_x11_event_mask_ResizeRedirect,
            &hf_x11_event_mask_SubstructureNotify,
            &hf_x11_event_mask_SubstructureRedirect,
            &hf_x11_event_mask_FocusChange,
            &hf_x11_event_mask_PropertyChange,
            &hf_x11_event_mask_ColormapChange,
            &hf_x11_event_mask_OwnerGrabButton,
            NULL
      };

      proto_tree_add_bitmask(t, tvb, *offsetp, hf_x11_event_mask, ett_x11_event_mask, events, byte_order);
      *offsetp += 4;
}

static void setOfDeviceEvent(tvbuff_t *tvb, int *offsetp, proto_tree *t,
                             guint byte_order)
{
      static int * const do_not_propagate_events[] = {
            &hf_x11_do_not_propagate_mask_KeyPress,
            &hf_x11_do_not_propagate_mask_KeyRelease,
            &hf_x11_do_not_propagate_mask_ButtonPress,
            &hf_x11_do_not_propagate_mask_ButtonRelease,
            &hf_x11_do_not_propagate_mask_PointerMotion,
            &hf_x11_do_not_propagate_mask_Button1Motion,
            &hf_x11_do_not_propagate_mask_Button2Motion,
            &hf_x11_do_not_propagate_mask_Button3Motion,
            &hf_x11_do_not_propagate_mask_Button4Motion,
            &hf_x11_do_not_propagate_mask_Button5Motion,
            &hf_x11_do_not_propagate_mask_ButtonMotion,
            NULL
      };

      proto_tree_add_bitmask(t, tvb, *offsetp, hf_x11_do_not_propagate_mask, ett_x11_do_not_propagate_mask, do_not_propagate_events, byte_order);
      *offsetp += 4;
}


static void setOfKeyButMask(tvbuff_t *tvb, int *offsetp, proto_tree *t,
                            guint byte_order, gboolean butmask)
{
      proto_item *ti;
      guint32 bitmask_value;
      int bitmask_offset;
      int bitmask_size;
      proto_tree *bitmask_tree;

      bitmask_value = tvb_get_guint16(tvb, *offsetp, byte_order);
      bitmask_offset = *offsetp;
      bitmask_size = 2;

      if (!butmask && bitmask_value == 0x8000)
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

            if (butmask) {
                  FLAG(modifiers, Button1);
                  FLAG(modifiers, Button2);
                  FLAG(modifiers, Button3);
                  FLAG(modifiers, Button4);
                  FLAG(modifiers, Button5);
            }

            if (butmask)
                  FLAG_IF_NONZERO(keybut, erroneous_bits);
            else
                  FLAG_IF_NONZERO(modifiers, erroneous_bits);
      }
      *offsetp += 2;
}

static void setOfPointerEvent(tvbuff_t *tvb, int *offsetp, proto_tree *t,
                              guint byte_order)
{
      static int * const pointer_events[] = {
            &hf_x11_pointer_event_mask_ButtonRelease,
            &hf_x11_pointer_event_mask_EnterWindow,
            &hf_x11_pointer_event_mask_LeaveWindow,
            &hf_x11_pointer_event_mask_PointerMotion,
            &hf_x11_pointer_event_mask_PointerMotionHint,
            &hf_x11_pointer_event_mask_Button1Motion,
            &hf_x11_pointer_event_mask_Button2Motion,
            &hf_x11_pointer_event_mask_Button3Motion,
            &hf_x11_pointer_event_mask_Button4Motion,
            &hf_x11_pointer_event_mask_Button5Motion,
            &hf_x11_pointer_event_mask_ButtonMotion,
            &hf_x11_pointer_event_mask_KeymapState,
            NULL
      };

      proto_tree_add_bitmask(t, tvb, *offsetp, hf_x11_pointer_event_mask, ett_x11_pointer_event_mask, pointer_events, byte_order);
      *offsetp += 2;
}

static void string8(tvbuff_t *tvb, int *offsetp, proto_tree *t,
    int hf, guint length)
{
      proto_tree_add_item(t, hf, tvb, *offsetp, length, ENC_NA|ENC_ASCII);
      *offsetp += length;
}

/* The length supplied is the length of the string in CHAR2Bs (half the number of bytes) */

static void string16(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
    int hf_bytes, guint length, guint byte_order)
{
      guint l = length*2; /* byte count */
      char *s;

      if (stringIsActuallyAn8BitString(tvb, *offsetp, length)) {
            s = tvb_get_ascii_string16(tvb, *offsetp, length);
            proto_tree_add_string_format_value(t, hf, tvb, *offsetp, l, s, "\"%s\"", s);
      } else
            proto_tree_add_item(t, hf_bytes, tvb, *offsetp, l, byte_order);

      *offsetp += l;
}

static void timestamp(tvbuff_t *tvb, int *offsetp, proto_tree *t, int hf,
                      guint byte_order)
{
      guint32 v = tvb_get_guint32(tvb, *offsetp, byte_order);

      if (!v)
            proto_tree_add_uint_format(t, hf, tvb, *offsetp, 4, 0, "%s: 0 (CurrentTime)",
                                       proto_registrar_get_nth(hf) -> name);
      else
            proto_tree_add_uint(t, hf, tvb, *offsetp, 4, v);
      *offsetp += 4;
}

static void windowAttributes(tvbuff_t *tvb, int *offsetp, proto_tree *t,
                             guint byte_order)
{
      guint32 bitmask;
      static int * const window_attributes_flags[] = {
            &hf_x11_window_value_mask_background_pixmap,
            &hf_x11_window_value_mask_background_pixel,
            &hf_x11_window_value_mask_border_pixmap,
            &hf_x11_window_value_mask_border_pixel,
            &hf_x11_window_value_mask_bit_gravity,
            &hf_x11_window_value_mask_win_gravity,
            &hf_x11_window_value_mask_backing_store,
            &hf_x11_window_value_mask_backing_planes,
            &hf_x11_window_value_mask_backing_pixel,
            &hf_x11_window_value_mask_override_redirect,
            &hf_x11_window_value_mask_save_under,
            &hf_x11_window_value_mask_event_mask,
            &hf_x11_window_value_mask_do_not_propagate_mask,
            &hf_x11_window_value_mask_colormap,
            &hf_x11_window_value_mask_cursor,
            NULL
      };

      bitmask = tvb_get_guint32(tvb, *offsetp, byte_order);
      proto_tree_add_bitmask(t, tvb, *offsetp, hf_x11_window_value_mask, ett_x11_window_value_mask, window_attributes_flags, byte_order);
      *offsetp += 4;

      if (bitmask & 0x00000001) {
          proto_tree_add_item(t, hf_x11_background_pixmap, tvb, *offsetp, 4, byte_order);
          *offsetp += 4;
      }
      if (bitmask & 0x00000002) {
          proto_tree_add_item(t, hf_x11_background_pixel, tvb, *offsetp, 4, byte_order);
          *offsetp += 4;
      }
      if (bitmask & 0x00000004) {
          proto_tree_add_item(t, hf_x11_border_pixmap, tvb, *offsetp, 4, byte_order);
          *offsetp += 4;
      }
      if (bitmask & 0x00000008) {
          proto_tree_add_item(t, hf_x11_border_pixel, tvb, *offsetp, 4, byte_order);
          *offsetp += 4;
      }
      if (bitmask & 0x00000010) {
          proto_tree_add_item(t, hf_x11_bit_gravity, tvb, *offsetp, 1, byte_order);
          *offsetp += 1;
          proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 3, ENC_NA);
          *offsetp += 3;
      }
      if (bitmask & 0x00000020) {
          proto_tree_add_item(t, hf_x11_win_gravity, tvb, *offsetp, 1, byte_order);
          *offsetp += 1;
          proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 3, ENC_NA);
          *offsetp += 3;
      }
      if (bitmask & 0x00000040) {
          proto_tree_add_item(t, hf_x11_backing_store, tvb, *offsetp, 1, byte_order);
          *offsetp += 1;
          proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 3, ENC_NA);
          *offsetp += 3;
      }
      if (bitmask & 0x00000080) {
          proto_tree_add_item(t, hf_x11_backing_planes, tvb, *offsetp, 4, byte_order);
          *offsetp += 4;
      }
      if (bitmask & 0x00000100) {
          proto_tree_add_item(t, hf_x11_backing_pixel, tvb, *offsetp, 4, byte_order);
          *offsetp += 4;
      }
      if (bitmask & 0x00000200) {
          proto_tree_add_item(t, hf_x11_override_redirect, tvb, *offsetp, 1, byte_order);
          *offsetp += 1;
          proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 3, ENC_NA);
          *offsetp += 3;
      }
      if (bitmask & 0x00000400) {
          proto_tree_add_item(t, hf_x11_save_under, tvb, *offsetp, 1, byte_order);
          *offsetp += 1;
          proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 3, ENC_NA);
          *offsetp += 3;
      }
      if (bitmask & 0x00000800) {
          setOfEvent(tvb, offsetp, t, byte_order);
      }
      if (bitmask & 0x00001000) {
          setOfDeviceEvent(tvb, offsetp, t, byte_order);
      }
      if (bitmask & 0x00002000) {
          proto_tree_add_item(t, hf_x11_colormap, tvb, *offsetp, 4, byte_order);
          *offsetp += 4;
      }
      if (bitmask & 0x00004000) {
          proto_tree_add_item(t, hf_x11_cursor, tvb, *offsetp, 4, byte_order);
          *offsetp += 4;
      }
}

/************************************************************************
 ***                                                                  ***
 ***         G U E S S I N G   T H E   B Y T E   O R D E R I N G      ***
 ***                                                                  ***
 ************************************************************************/

/* If we can't guess, we return ENC_LITTLE_ENDIAN, cause
   I'm developing on a Linux box :-). The (non-)guess isn't cached
   however, so we may have more luck next time. I'm quite conservative
   in my assertions, cause once it's cached, it stays in cache, and
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

static gboolean consistentWithOrder(int length, tvbuff_t *tvb, int offset, int encoding)
{
      switch(tvb_get_guint8(tvb, offset)) {
            case X_CreateWindow:
                  return !tvb_bytes_exist(tvb, offset, 32) || length == 8 + numberOfBitSet(tvb, offset + 7 * 4, 4);

            case X_ChangeWindowAttributes:
            case X_ChangeGC:
                  return !tvb_bytes_exist(tvb, offset, 12) || length == 3 + numberOfBitSet(tvb, offset + 8, 4);

            case X_GetWindowAttributes:
            case X_DestroyWindow:
            case X_DestroySubwindows:
            case X_ChangeSaveSet:
            case X_MapWindow:
            case X_MapSubwindows:
            case X_UnmapWindow:
            case X_UnmapSubwindows:
            case X_CirculateWindow:
            case X_GetGeometry:
            case X_QueryTree:
            case X_GetAtomName:
            case X_ListProperties:
            case X_GetSelectionOwner:
            case X_UngrabPointer:
            case X_UngrabKeyboard:
            case X_AllowEvents:
            case X_QueryPointer:
            case X_CloseFont:
            case X_QueryFont:
            case X_FreePixmap:
            case X_FreeGC:
            case X_FreeColormap:
            case X_InstallColormap:
            case X_UninstallColormap:
            case X_ListInstalledColormaps:
            case X_FreeCursor:
            case X_GetKeyboardMapping:
            case X_KillClient:
                  return length == 2;

            case X_ReparentWindow:
            case X_SetSelectionOwner:
            case X_ChangeActivePointerGrab:
            case X_GrabKeyboard:
            case X_GrabKey:
            case X_GetMotionEvents:
            case X_TranslateCoords:
            case X_CreatePixmap:
            case X_CopyGC:
            case X_ClearArea:
            case X_CreateColormap:
            case X_AllocColor:
            case X_AllocColorPlanes:
                  return length == 4;

            case X_ConfigureWindow:
                  return !tvb_bytes_exist(tvb, offset, 10) || length == 3 + numberOfBitSet(tvb, offset + 8, 2);

            case X_InternAtom:
            case X_QueryExtension:
                  return !tvb_bytes_exist(tvb, offset, 6) || length == 2 + rounded4(tvb_get_guint16(tvb, offset + 4, encoding));

            case X_ChangeProperty:
            {
                  int multiplier, type;
                  if (!tvb_bytes_exist(tvb, offset, 17)) return TRUE;
                  type = tvb_get_guint8(tvb, 16);
                  if (type != 8 && type != 16 && type != 32) return FALSE;
                  multiplier = type == 8 ? 1 : type == 16 ? 2 : 4;
                  if (!tvb_bytes_exist(tvb, offset, 24)) return TRUE;
                  return length == 6 + rounded4(tvb_get_guint32(tvb, offset + 20, encoding) * multiplier);
            }

            case X_DeleteProperty:
            case X_UngrabButton:
            case X_UngrabKey:
            case X_SetInputFocus:
            case X_CopyColormapAndFree:
            case X_AllocColorCells:
            case X_QueryBestSize:
            case X_ChangePointerControl:
            case X_SetScreenSaver:
                  return length == 3;

            case X_GetProperty:
            case X_ConvertSelection:
            case X_GrabPointer:
            case X_GrabButton:
            case X_WarpPointer:
                  return length == 6;

            case X_SendEvent:
                  return length == 11;

            case X_GrabServer:
            case X_UngrabServer:
            case X_GetInputFocus:
            case X_QueryKeymap:
            case X_GetFontPath:
            case X_ListExtensions:
            case X_GetKeyboardControl:
            case X_Bell:
            case X_GetPointerControl:
            case X_GetScreenSaver:
            case X_ListHosts:
            case X_SetAccessControl:
            case X_SetCloseDownMode:
            case X_ForceScreenSaver:
            case X_GetPointerMapping:
            case X_GetModifierMapping:
                  return length == 1;

            case X_OpenFont:
            case X_AllocNamedColor:
            case X_LookupColor:
                  return !tvb_bytes_exist(tvb, offset, 10) || length == 3 + rounded4(tvb_get_guint16(tvb, offset + 8, encoding));

            case X_QueryTextExtents:
                  return length >= 2;

            case X_ListFonts:
            case X_ListFontsWithInfo:
            case X_ChangeHosts:
                  return !tvb_bytes_exist(tvb, offset, 8) || length == 2 + rounded4(tvb_get_guint16(tvb, offset + 6, encoding));

            case X_SetFontPath:
                  if (length < 2) return FALSE;
                  if (!tvb_bytes_exist(tvb, offset, 8)) return TRUE;
                  return listOfStringLengthConsistent(tvb, offset + 8, (length - 2) * 4, tvb_get_guint16(tvb, offset + 4, encoding));

            case X_CreateGC:
                  return !tvb_bytes_exist(tvb, offset, 16) || length == 4 + numberOfBitSet(tvb, offset + 12, 4);

            case X_SetDashes:
                  return !tvb_bytes_exist(tvb, offset, 12) || length == 3 + rounded4(tvb_get_guint16(tvb, offset + 10, encoding));

            case X_SetClipRectangles:
            case X_PolySegment:
            case X_PolyRectangle:
            case X_PolyFillRectangle:
                  return length >= 3 && (length - 3) % 2 == 0;

            case X_CopyArea:
                  return length == 7;

            case X_CopyPlane:
            case X_CreateCursor:
            case X_CreateGlyphCursor:
                  return length == 8;

            case X_PolyPoint:
            case X_PolyLine:
            case X_FreeColors:
                  return length >= 3;

            case X_PolyArc:
            case X_PolyFillArc:
                  return length >= 3 && (length - 3) % 3 == 0;

            case X_FillPoly:
            case X_ImageText8:
                  return length >= 4;

            case X_PutImage:
                  return length >= 6;

            case X_GetImage:
            case X_RecolorCursor:
                  return length == 5;

            case X_PolyText8:
                  if (length < 4) return FALSE;
                  return TRUE; /* We don't perform many controls on this one */

            case X_PolyText16:
                  if (length < 4) return FALSE;
                  return TRUE; /* We don't perform many controls on this one */

            case X_ImageText16:
                  return length >= 4;

            case X_StoreColors:
                  return length > 2 && (length - 2) % 3 == 0;

            case X_StoreNamedColor:
                  return !tvb_bytes_exist(tvb, offset, 14) || length == 4 + rounded4(tvb_get_guint16(tvb, offset + 12, encoding));

            case X_QueryColors:
                  return length >= 2;

            case X_ChangeKeyboardMapping:
                  return !tvb_bytes_exist(tvb, offset, 6) || length == 2 + tvb_get_guint8(tvb, 1) * tvb_get_guint8(tvb, 5);

            case X_ChangeKeyboardControl:
                  return !tvb_bytes_exist(tvb, offset, 6) || length == 2 + numberOfBitSet(tvb, offset + 4, 2);

            case X_RotateProperties:
                  return !tvb_bytes_exist(tvb, offset, 10) || length == 3 + tvb_get_guint16(tvb, offset + 8, encoding);

            case X_SetPointerMapping:
                  return length == 1 + rounded4(tvb_get_guint8(tvb, 1));

            case X_SetModifierMapping:
                  return length == 1 + tvb_get_guint8(tvb, 1) * 2;

            case X_NoOperation:
                  return length >= 1;

            default:
                  return TRUE;
      }
}

/* -1 means doesn't match, +1 means match, 0 means don't know */

static int x_endian_match(tvbuff_t *tvb, int encoding)
{
      int offset, nextoffset;
      int atLeastOne = 0;

      for(offset = 0; tvb_bytes_exist(tvb, offset, 4); offset = nextoffset) {
            int length;
            length = tvb_get_guint16(tvb, offset + 2, encoding);
            if (!length)
                return -1;
            nextoffset = offset + length * 4;
            if (!consistentWithOrder(length, tvb, offset, encoding))
                return -1;
            atLeastOne = 1;
      }
      return atLeastOne;
}

static guint
guess_byte_ordering(tvbuff_t *tvb, packet_info *pinfo,
                    x11_conv_data_t *state)
{
      /* With X the client gives the byte ordering for the protocol,
         and the port on the server tells us we're speaking X. */

      int le, be;
      guint decision;

      if (state->byte_order == ENC_BIG_ENDIAN)
            return ENC_BIG_ENDIAN;    /* known to be big-endian */
      else if (state->byte_order == ENC_LITTLE_ENDIAN)
            return ENC_LITTLE_ENDIAN; /* known to be little-endian */

      if (pinfo->srcport == pinfo->match_uint) {
            /*
             * This is a reply or event; we don't try to guess the
             * byte order on it for now.
             */
            return ENC_LITTLE_ENDIAN;
      }

      le = x_endian_match(tvb, ENC_LITTLE_ENDIAN);
      be = x_endian_match(tvb, ENC_BIG_ENDIAN);

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
                decision = ENC_LITTLE_ENDIAN;
            else {
                if (tvb_get_letohs(tvb, 2) <= tvb_get_ntohs(tvb, 2))
                      decision = ENC_LITTLE_ENDIAN;
                else
                      decision = ENC_BIG_ENDIAN;
            }
      } else {
            if (le >= be)
                  decision = ENC_LITTLE_ENDIAN;
            else
                  decision = ENC_BIG_ENDIAN;
      }

      if ((le < 0 && be > 0) || (le > 0 && be < 0)) {
            /*
             * Remember the decision.
             */
            state->byte_order = decision;
      }

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
    proto_tree *tree, x11_conv_data_t *state, guint byte_order)
{
      int offset = 0;
      int *offsetp = &offset;
      proto_item *ti;
      proto_tree *t;
      guint16 auth_proto_name_length, auth_proto_data_length;
      gint left;

      ti = proto_tree_add_item(tree, proto_x11, tvb, 0, -1, ENC_NA);
      proto_item_append_text(ti, ", Request, Initial connection request");
      t = proto_item_add_subtree(ti, ett_x11);

      CARD8(byte_order);
      proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
      *offsetp += 1;
      CARD16(protocol_major_version);
      CARD16(protocol_minor_version);
      auth_proto_name_length = CARD16(authorization_protocol_name_length);
      auth_proto_data_length = CARD16(authorization_protocol_data_length);
      proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
      *offsetp += 2;

      if (auth_proto_name_length != 0) {
            STRING8(authorization_protocol_name, auth_proto_name_length);
            offset = ROUND_LENGTH(offset);
      }

      if (auth_proto_data_length != 0) {
            STRING8(authorization_protocol_data, auth_proto_data_length);
            offset = ROUND_LENGTH(offset);
      }

      if ((left = tvb_reported_length_remaining(tvb, offset)) > 0)
            proto_tree_add_item(t, hf_x11_undecoded, tvb, offset, left,
                                ENC_NA);

      /*
       * This is the initial connection request...
       */
      state->iconn_frame = pinfo->num;

      /*
       * ...and we're expecting a reply to it.
       */
      state->sequencenumber = 0;
      wmem_map_insert(state->seqtable, GINT_TO_POINTER(state->sequencenumber),
                          (int *)INITIAL_CONN);
}

static void dissect_x11_initial_reply(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, const char _U_ *sep, x11_conv_data_t *state,
    guint byte_order)
{
      int offset = 0, *offsetp = &offset, left;
      unsigned char success;
      int length_of_vendor;
      int length_of_reason;
      int number_of_formats_in_pixmap_formats;
      int number_of_screens_in_roots;
      int unused;
      proto_item *ti;
      proto_tree *t;

      ti = proto_tree_add_item(tree, proto_x11, tvb, 0, -1, ENC_NA);
      proto_item_append_text(ti, ", Reply, Initial connection reply");
      t = proto_item_add_subtree(ti, ett_x11);

      state->iconn_reply = pinfo->num;
      success = INT8(success);
      if (success) {
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            length_of_reason = 0;
      }
      else {
            length_of_reason = INT8(length_of_reason);
      }

      INT16(protocol_major_version);
      INT16(protocol_minor_version);
      INT16(replylength);
      if (success) {
            INT32(release_number);
            INT32(resource_id_base);
            INT32(resource_id_mask);
            INT32(motion_buffer_size);
            length_of_vendor = INT16(length_of_vendor);
            INT16(maximum_request_length);
            number_of_screens_in_roots = INT8(number_of_screens_in_roots);
            number_of_formats_in_pixmap_formats = INT8(number_of_formats_in_pixmap_formats);
            INT8(image_byte_order);
            INT8(bitmap_format_bit_order);
            INT8(bitmap_format_scanline_unit);
            INT8(bitmap_format_scanline_pad);
            INT8(min_keycode);
            INT8(max_keycode);
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 4, ENC_NA);
            *offsetp += 4;
            STRING8(vendor, length_of_vendor);
            unused = (4 - (length_of_vendor % 4)) % 4;
            if (unused > 0) {
                proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, unused, ENC_NA);
                *offsetp += unused;
            }
            LISTofPIXMAPFORMAT(pixmap_format, number_of_formats_in_pixmap_formats);
            LISTofSCREEN(screen, number_of_screens_in_roots);
      } else {
            STRING8(reason, length_of_reason);
      }

      if ((left = tvb_reported_length_remaining(tvb, offset)) > 0)
            UNDECODED(left);

}

typedef struct x11_reply_info {
      const guint8 minor;
      void (*dissect)(tvbuff_t *tvb, packet_info *pinfo, int *offsetp, proto_tree *t, guint byte_order);
} x11_reply_info;

typedef struct event_info {
      const gchar *name;
      void (*dissect)(tvbuff_t *tvb, int *offsetp, proto_tree *t, guint byte_order);
} x11_event_info;

typedef struct x11_generic_event_info {
      const guint16 minor;
      void (*dissect)(tvbuff_t *tvb, int length, int *offsetp, proto_tree *t, guint byte_order);
} x11_generic_event_info;

static void set_handler(const char *name, void (*func)(tvbuff_t *tvb, packet_info *pinfo, int *offsetp, proto_tree *t, guint byte_order),
                        const char **errors,
                        const x11_event_info *event_info,
                        const x11_generic_event_info *genevent_info,
                        const x11_reply_info *reply_info)
{
      wmem_map_insert(extension_table, (gpointer)name, (gpointer)func);
      wmem_map_insert(error_table, (gpointer)name, (gpointer)errors);
      wmem_map_insert(event_table, (gpointer)name, (gpointer)event_info);
      if (genevent_info)
          wmem_map_insert(genevent_table, (gpointer)name, (gpointer)genevent_info);
      wmem_map_insert(reply_table, (gpointer)name, (gpointer)reply_info);
}

#include "x11-extension-errors.h"
#include "x11-extension-implementation.h"

static void tryExtension(int opcode, tvbuff_t *tvb, packet_info *pinfo, int *offsetp, proto_tree *t,
                         x11_conv_data_t *state, guint byte_order)
{
      const gchar *extension;
      void (*func)(tvbuff_t *tvb, packet_info *pinfo, int *offsetp, proto_tree *t, guint byte_order);

      extension = try_val_to_str(opcode, state->opcode_vals);
      if (!extension)
            return;

      func = (void (*)(tvbuff_t *, packet_info *, int *, proto_tree *, guint))wmem_map_lookup(extension_table, extension);
      if (func)
            func(tvb, pinfo, offsetp, t, byte_order);
}

static void tryExtensionReply(int opcode, tvbuff_t *tvb, packet_info *pinfo, int *offsetp, proto_tree *t,
                              x11_conv_data_t *state, guint byte_order)
{
      void (*func)(tvbuff_t *tvb, packet_info *pinfo, int *offsetp, proto_tree *t, guint byte_order);

      func = (void (*)(tvbuff_t *, packet_info *, int *, proto_tree *, guint))wmem_map_lookup(state->reply_funcs, GINT_TO_POINTER(opcode));
      if (func)
            func(tvb, pinfo, offsetp, t, byte_order);
      else
            REPLYCONTENTS_COMMON();
}

static void tryExtensionEvent(int event, tvbuff_t *tvb, int *offsetp, proto_tree *t,
                              x11_conv_data_t *state, guint byte_order)
{
      void (*func)(tvbuff_t *tvb, int *offsetp, proto_tree *t, guint byte_order);

      func = (void (*)(tvbuff_t *, int *, proto_tree *, guint))wmem_map_lookup(state->eventcode_funcs, GINT_TO_POINTER(event));
      if (func)
            func(tvb, offsetp, t, byte_order);
}

static void tryGenericExtensionEvent(tvbuff_t *tvb, int *offsetp, proto_tree *t,
                                     x11_conv_data_t *state, guint byte_order)
{
      const gchar *extname;
      int extension, length;

      extension = tvb_get_guint8(tvb, *offsetp);
      (*offsetp)++;
      extname = try_val_to_str(extension, state->opcode_vals);

      if (extname) {
          proto_tree_add_uint_format(t, hf_x11_extension, tvb, *offsetp, 1, extension, "extension: %d (%s)", extension, extname);
      } else {
          proto_tree_add_uint(t, hf_x11_extension, tvb, *offsetp, 1, extension);
      }

      CARD16(event_sequencenumber);

      length = REPLYLENGTH(eventlength);
      length = length * 4 + 32;
      *offsetp += 4;

      if (extname) {
          x11_generic_event_info *info;
          info = (x11_generic_event_info *)wmem_map_lookup(genevent_table, extname);

          if (info) {
              int i;

              int opcode = tvb_get_guint16(tvb, *offsetp, byte_order);

              for (i = 0; info[i].dissect != NULL; i++) {
                  if (info[i].minor == opcode) {
                      *offsetp += 2;
                      info[i].dissect(tvb, length, offsetp, t, byte_order);
                      return;
                  }
              }
          }
      }
      CARD16(minor_opcode);
}

static void register_extension(x11_conv_data_t *state, value_string *vals_p,
    int major_opcode, unsigned int first_event, unsigned int first_error)
{
      const char **error_string;
      x11_event_info *event_info;
      x11_reply_info *reply_info;
      int i;

      vals_p->value = major_opcode;

      error_string = (const char **)wmem_map_lookup(error_table, vals_p->strptr);
      while (error_string && *error_string && first_error <= LastExtensionError) {
            /* store string of extension error */
            for (i = 0; i <= LastExtensionError; i++) {
                  if (state->errorcode_vals[i].strptr == NULL) {
                        state->errorcode_vals[i].value = first_error;
                        state->errorcode_vals[i].strptr = *error_string;
                        break;
                  } else if (state->errorcode_vals[i].value == first_error) {
                        /* TODO: Warn about extensions stepping on each other */
                        state->errorcode_vals[i].strptr = *error_string;
                        break;
                  }
            }
            first_error++;
            error_string++;
      }

      event_info = (x11_event_info *)wmem_map_lookup(event_table, vals_p->strptr);
      while (event_info && event_info->name && first_event <= LastExtensionEvent) {
            /* store string of extension event */
            for (i = 0; i <= LastExtensionEvent; i++) {
                  if (state->eventcode_vals[i].strptr == NULL) {
                        state->eventcode_vals[i].value = first_event;
                        state->eventcode_vals[i].strptr = event_info->name;
                        break;
                  } else if (state->eventcode_vals[i].value == first_event) {
                        /* TODO: Warn about extensions stepping on each other */
                        state->eventcode_vals[i].strptr = event_info->name;
                        break;
                  }
            }

            /* store event decode function */
            wmem_map_insert(state->eventcode_funcs, GINT_TO_POINTER(first_event), (gpointer)event_info->dissect);

            first_event++;
            event_info++;
      }

      reply_info = (x11_reply_info *)wmem_map_lookup(reply_table, vals_p->strptr);
      if (reply_info)
            for (i = 0; reply_info[i].dissect; i++)
                  wmem_map_insert(state->reply_funcs,
                                      GINT_TO_POINTER(major_opcode | (reply_info[i].minor << 8)),
                                      (gpointer)reply_info[i].dissect);
}


static void dissect_x11_request(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, const char *sep, x11_conv_data_t *state,
    guint byte_order)
{
      int offset = 0;
      int *offsetp = &offset;
      int query_ext_offset;
      int next_offset;
      proto_item *ti;
      proto_tree *t;
      int length, opcode, i;
      guint8 v8, v8_2, v8_3;
      guint16 v16;
      guint32 v32;
      gint left;
      gchar *name;

      query_ext_offset = 2; /* "opcode" and "unused" */

      length = tvb_get_guint16(tvb, query_ext_offset, byte_order) * 4;
      query_ext_offset += 2;

      if (length == 0) {
            /* BIG-REQUESTS extension */
            length = tvb_get_guint32(tvb, query_ext_offset, byte_order);
            if ((gint64)length * 4 > G_MAXINT32)
                return;
            length *= 4;
            query_ext_offset += 4;
      }

      if (length < 4) {
            /* Bogus message length? */
            return;
      }

      next_offset = offset + length;

      ti = proto_tree_add_item(tree, proto_x11, tvb, 0, -1, ENC_NA);
      t = proto_item_add_subtree(ti, ett_x11);

      if (!pinfo->fd->visited)
            ++state->sequencenumber;

      OPCODE();

      col_append_fstr(pinfo->cinfo, COL_INFO, "%s %s", sep,
                    val_to_str(opcode, state->opcode_vals,
                                "<Unknown opcode %d>"));

      proto_item_append_text(ti, ", Request, opcode: %d (%s)",
                             opcode, val_to_str(opcode, state->opcode_vals,
                                                "<Unknown opcode %d>"));

      /*
       * Does this request expect a reply?
       */
      switch(opcode) {

            case X_QueryExtension:

                  /* necessary processing even if tree == NULL */

                  v16 = tvb_get_guint16(tvb, query_ext_offset, byte_order);
                  query_ext_offset += 2;
                  /* Some unused bytes */
                  query_ext_offset += 2;
                  name = tvb_get_string_enc(wmem_file_scope(), tvb, query_ext_offset, v16, ENC_ASCII);

                  /* store string of extension, opcode will be set at reply */
                  i = 0;
                  while(i < MAX_OPCODES) {
                        if (state->opcode_vals[i].strptr == NULL) {
                              state->opcode_vals[i].strptr = name;
                              state->opcode_vals[i].value = -1;
                              wmem_map_insert(state->valtable,
                                                  GINT_TO_POINTER(state->sequencenumber),
                                                  (int *)&state->opcode_vals[i]);
                              break;
                        } else if (strcmp(state->opcode_vals[i].strptr,
                                          name) == 0) {
                              wmem_map_insert(state->valtable,
                                                  GINT_TO_POINTER(state->sequencenumber),
                                                  (int *)&state->opcode_vals[i]);
                              break;
                        }
                        i++;
                  }

                  /* QueryExtension expects a reply, fall through */
      /* FALLTHROUGH */
      case X_AllocColor:
      case X_AllocColorCells:
      case X_AllocColorPlanes:
      case X_AllocNamedColor:
      case X_GetAtomName:
      case X_GetFontPath:
      case X_GetGeometry:
      case X_GetImage:
      case X_GetInputFocus:
      case X_GetKeyboardControl:
      case X_GetKeyboardMapping:
      case X_GetModifierMapping:
      case X_GetMotionEvents:
      case X_GetPointerControl:
      case X_GetPointerMapping:
      case X_GetProperty:
      case X_GetScreenSaver:
      case X_GetSelectionOwner:
      case X_GetWindowAttributes:
      case X_GrabKeyboard:
      case X_GrabPointer:
      case X_InternAtom:
      case X_ListExtensions:
      case X_ListFonts:
      case X_ListFontsWithInfo:
      case X_ListHosts:
      case X_ListInstalledColormaps:
      case X_ListProperties:
      case X_LookupColor:
      case X_QueryBestSize:
      case X_QueryColors:
      case X_QueryFont:
      case X_QueryKeymap:
      case X_QueryPointer:
      case X_QueryTextExtents:
      case X_QueryTree:
      case X_SetModifierMapping:
      case X_SetPointerMapping:
      case X_TranslateCoords:
            /*
             * Those requests expect a reply.
             */
            wmem_map_insert(state->seqtable,
                                GINT_TO_POINTER(state->sequencenumber),
                                GINT_TO_POINTER(opcode));

            break;

      default:
            /*
             * With Extension, we don't know, so assume there could be one
             */
            if (opcode >= X_FirstExtension && opcode <= X_LastExtension) {
                  guint32 minor;
                  minor = tvb_get_guint8(tvb, 1);

                  wmem_map_insert(state->seqtable,
                                      GINT_TO_POINTER(state->sequencenumber),
                                      GINT_TO_POINTER(opcode | (minor << 8)));
            }

            /*
             * No reply is expected from any other request.
             */
            break;
      }

      if (tree == NULL)
            return;

      switch(opcode) {

      case X_CreateWindow:
            CARD8(depth);
            requestLength(tvb, offsetp, t, byte_order);
            WINDOW(wid);
            WINDOW(parent);
            INT16(x);
            INT16(y);
            CARD16(width);
            CARD16(height);
            CARD16(border_width);
            ENUM16(window_class);
            VISUALID(visual);
            windowAttributes(tvb, offsetp, t, byte_order);
            break;

      case X_ChangeWindowAttributes:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            WINDOW(window);
            windowAttributes(tvb, offsetp, t, byte_order);
            break;

      case X_GetWindowAttributes:
      case X_DestroyWindow:
      case X_DestroySubwindows:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            WINDOW(window);
            break;

      case X_ChangeSaveSet:
            ENUM8(save_set_mode);
            requestLength(tvb, offsetp, t, byte_order);
            WINDOW(window);
            break;

      case X_ReparentWindow:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            WINDOW(window);
            WINDOW(parent);
            INT16(x);
            INT16(y);
            break;

      case X_MapWindow:
      case X_MapSubwindows:
      case X_UnmapWindow:
      case X_UnmapSubwindows:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            WINDOW(window);
            break;

      case X_ConfigureWindow:
            {
            guint16 bitmask16;
            static int * const window_attributes_flags[] = {
                  &hf_x11_window_value_mask_background_pixmap,
                  &hf_x11_window_value_mask_background_pixel,
                  &hf_x11_window_value_mask_border_pixmap,
                  &hf_x11_window_value_mask_border_pixel,
                  &hf_x11_window_value_mask_bit_gravity,
                  &hf_x11_window_value_mask_win_gravity,
                  &hf_x11_window_value_mask_backing_store,
                  &hf_x11_window_value_mask_backing_planes,
                  &hf_x11_window_value_mask_backing_pixel,
                  &hf_x11_window_value_mask_override_redirect,
                  &hf_x11_window_value_mask_save_under,
                  &hf_x11_window_value_mask_event_mask,
                  &hf_x11_window_value_mask_do_not_propagate_mask,
                  &hf_x11_window_value_mask_colormap,
                  &hf_x11_window_value_mask_cursor,
                  NULL
            };

            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            proto_tree_add_item(t, hf_x11_window, tvb, *offsetp, 1, byte_order);
            *offsetp += 4;
            bitmask16 = tvb_get_guint16(tvb, *offsetp, byte_order);
            proto_tree_add_bitmask(t, tvb, *offsetp, hf_x11_configure_window_mask, ett_x11_configure_window_mask, window_attributes_flags, byte_order);
            *offsetp += 2;
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
            *offsetp += 2;
            if (bitmask16 & 0x0001) {
                proto_tree_add_item(t, hf_x11_x, tvb, *offsetp, 2, byte_order);
                *offsetp += 2;
                proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
                *offsetp += 2;
            }
            if (bitmask16 & 0x0002) {
                proto_tree_add_item(t, hf_x11_y, tvb, *offsetp, 2, byte_order);
                *offsetp += 2;
                proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
                *offsetp += 2;
            }
            if (bitmask16 & 0x0004) {
                proto_tree_add_item(t, hf_x11_width, tvb, *offsetp, 2, byte_order);
                *offsetp += 2;
                proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
                *offsetp += 2;
            }
            if (bitmask16 & 0x0008) {
                proto_tree_add_item(t, hf_x11_height, tvb, *offsetp, 2, byte_order);
                *offsetp += 2;
                proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
                *offsetp += 2;
            }
            if (bitmask16 & 0x0010) {
                proto_tree_add_item(t, hf_x11_border_width, tvb, *offsetp, 2, byte_order);
                *offsetp += 2;
                proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
                *offsetp += 2;
            }
            if (bitmask16 & 0x0020) {
                proto_tree_add_item(t, hf_x11_sibling, tvb, *offsetp, 4, byte_order);
                *offsetp += 4;
            }
            if (bitmask16 & 0x0040) {
                proto_tree_add_item(t, hf_x11_stack_mode, tvb, *offsetp, 1, byte_order);
                *offsetp += 1;
                proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 3, ENC_NA);
                *offsetp += 3;
            }
            if (next_offset - *offsetp > 0) {
                proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, next_offset - *offsetp, ENC_NA);
                *offsetp = next_offset;
            }
            }
            break;

      case X_CirculateWindow:
            ENUM8(direction);
            requestLength(tvb, offsetp, t, byte_order);
            WINDOW(window);
            break;

      case X_GetGeometry:
      case X_QueryTree:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            DRAWABLE(drawable);
            break;

      case X_InternAtom:
            BOOL(only_if_exists);
            requestLength(tvb, offsetp, t, byte_order);
            v16 = FIELD16(name_length);
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
            *offsetp += 2;
            STRING8(name, v16);
            PAD();
            break;

      case X_GetAtomName:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            ATOM(atom);
            break;

      case X_ChangeProperty:
            ENUM8(mode);
            requestLength(tvb, offsetp, t, byte_order);
            WINDOW(window);
            ATOM(property);
            ATOM(type);
            v8 = CARD8(format);
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 3, ENC_NA);
            *offsetp += 3;
            v32 = CARD32(data_length);
            switch (v8) {
            case 8:
                if (v32)
                    LISTofBYTE(data, v32);
                break;
            case 16:
                if (v32)
                    LISTofCARD16(data16, v32 * 2);
                break;
            case 32:
                if (v32)
                    LISTofCARD32(data32, v32 * 4);
                break;
            default:
                expert_add_info(pinfo, ti, &ei_x11_invalid_format);
                break;
            }
            PAD();
            break;

      case X_DeleteProperty:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            WINDOW(window);
            ATOM(property);
            break;

      case X_GetProperty:
            BOOL(delete);
            requestLength(tvb, offsetp, t, byte_order);
            WINDOW(window);
            ATOM(property);
            ATOM(get_property_type);
            CARD32(long_offset);
            CARD32(long_length);
            break;

      case X_ListProperties:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            WINDOW(window);
            break;

      case X_SetSelectionOwner:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            WINDOW(owner);
            ATOM(selection);
            TIMESTAMP(time);
            break;

      case X_GetSelectionOwner:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            ATOM(selection);
            break;

      case X_ConvertSelection:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            WINDOW(requestor);
            ATOM(selection);
            ATOM(target);
            ATOM(property);
            TIMESTAMP(time);
            break;

      case X_SendEvent:
            BOOL(propagate);
            requestLength(tvb, offsetp, t, byte_order);
            WINDOW(destination);
            SETofEVENT(event_mask);
            EVENT();
            break;

      case X_GrabPointer:
            BOOL(owner_events);
            requestLength(tvb, offsetp, t, byte_order);
            WINDOW(grab_window);
            SETofPOINTEREVENT(pointer_event_mask);
            ENUM8(pointer_mode);
            ENUM8(keyboard_mode);
            WINDOW(confine_to);
            CURSOR(cursor);
            TIMESTAMP(time);
            break;

      case X_UngrabPointer:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            TIMESTAMP(time);
            break;

      case X_GrabButton:
            BOOL(owner_events);
            requestLength(tvb, offsetp, t, byte_order);
            WINDOW(grab_window);
            SETofPOINTEREVENT(event_mask);
            ENUM8(pointer_mode);
            ENUM8(keyboard_mode);
            WINDOW(confine_to);
            CURSOR(cursor);
            BUTTON(button);
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            SETofKEYMASK(modifiers);
            break;

      case X_UngrabButton:
            BUTTON(button);
            requestLength(tvb, offsetp, t, byte_order);
            WINDOW(grab_window);
            SETofKEYMASK(modifiers);
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
            *offsetp += 2;
            break;

      case X_ChangeActivePointerGrab:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            CURSOR(cursor);
            TIMESTAMP(time);
            SETofPOINTEREVENT(event_mask);
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
            *offsetp += 2;
            break;

      case X_GrabKeyboard:
            BOOL(owner_events);
            requestLength(tvb, offsetp, t, byte_order);
            WINDOW(grab_window);
            TIMESTAMP(time);
            ENUM8(pointer_mode);
            ENUM8(keyboard_mode);
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
            *offsetp += 2;
            break;

      case X_UngrabKeyboard:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            TIMESTAMP(time);
            break;

      case X_GrabKey:
            BOOL(owner_events);
            requestLength(tvb, offsetp, t, byte_order);
            WINDOW(grab_window);
            SETofKEYMASK(modifiers);
            KEYCODE(key);
            ENUM8(pointer_mode);
            ENUM8(keyboard_mode);
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 3, ENC_NA);
            *offsetp += 3;
            break;

      case X_UngrabKey:
            KEYCODE(key);
            requestLength(tvb, offsetp, t, byte_order);
            WINDOW(grab_window);
            SETofKEYMASK(modifiers);
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
            *offsetp += 2;
            break;

      case X_AllowEvents:
            ENUM8(allow_events_mode);
            requestLength(tvb, offsetp, t, byte_order);
            TIMESTAMP(time);
            break;

      case X_GrabServer:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            break;

      case X_UngrabServer:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            break;

      case X_QueryPointer:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            WINDOW(window);
            break;

      case X_GetMotionEvents:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            WINDOW(window);
            TIMESTAMP(start);
            TIMESTAMP(stop);
            break;

      case X_TranslateCoords:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            WINDOW(src_window);
            WINDOW(dst_window);
            INT16(src_x);
            INT16(src_y);
            break;

      case X_WarpPointer:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            WINDOW(warp_pointer_src_window);
            WINDOW(warp_pointer_dst_window);
            INT16(src_x);
            INT16(src_y);
            CARD16(src_width);
            CARD16(src_height);
            INT16(dst_x);
            INT16(dst_y);
            break;

      case X_SetInputFocus:
            ENUM8(revert_to);
            requestLength(tvb, offsetp, t, byte_order);
            WINDOW(focus);
            TIMESTAMP(time);
            break;

      case X_GetInputFocus:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            break;

      case X_QueryKeymap:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            break;

      case X_OpenFont:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            FONT(fid);
            v16 = FIELD16(name_length);
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
            *offsetp += 2;
            STRING8(name, v16);
            PAD();
            break;

      case X_CloseFont:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            FONT(font);
            break;

      case X_QueryFont:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            FONTABLE(font);
            break;

      case X_QueryTextExtents:
            v8 = BOOL(odd_length);
            requestLength(tvb, offsetp, t, byte_order);
            FONTABLE(font);
            STRING16(string16, (next_offset - offset - (v8 ? 2 : 0)) / 2);
            PAD();
            break;

      case X_ListFonts:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            CARD16(max_names);
            v16 = FIELD16(pattern_length);
            STRING8(pattern, v16);
            PAD();
            break;

      case X_ListFontsWithInfo:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            CARD16(max_names);
            v16 = FIELD16(pattern_length);
            STRING8(pattern, v16);
            PAD();
            break;

      case X_SetFontPath:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            v16 = CARD16(str_number_in_path);
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
            *offsetp += 2;
            LISTofSTRING8(path, v16);
            PAD();
            break;

      case X_GetFontPath:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            break;

      case X_CreatePixmap:
            CARD8(depth);
            requestLength(tvb, offsetp, t, byte_order);
            PIXMAP(pid);
            DRAWABLE(drawable);
            CARD16(width);
            CARD16(height);
            break;

      case X_FreePixmap:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            PIXMAP(pixmap);
            break;

      case X_CreateGC:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            GCONTEXT(cid);
            DRAWABLE(drawable);
            gcAttributes(tvb, offsetp, t, byte_order);
            break;

      case X_ChangeGC:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            GCONTEXT(gc);
            gcAttributes(tvb, offsetp, t, byte_order);
            break;

      case X_CopyGC:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            GCONTEXT(src_gc);
            GCONTEXT(dst_gc);
            gcMask(tvb, offsetp, t, byte_order);
            break;

      case X_SetDashes:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            GCONTEXT(gc);
            CARD16(dash_offset);
            v16 = FIELD16(dashes_length);
            LISTofCARD8(dashes, v16);
            PAD();
            break;

      case X_SetClipRectangles:
            ENUM8(ordering);
            requestLength(tvb, offsetp, t, byte_order);
            GCONTEXT(gc);
            INT16(clip_x_origin);
            INT16(clip_y_origin);
            LISTofRECTANGLE(rectangles);
            break;

      case X_FreeGC:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            GCONTEXT(gc);
            break;

      case X_ClearArea:
            BOOL(exposures);
            requestLength(tvb, offsetp, t, byte_order);
            WINDOW(window);
            INT16(x);
            INT16(y);
            CARD16(width);
            CARD16(height);
            break;

      case X_CopyArea:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
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

      case X_CopyPlane:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
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

      case X_PolyPoint:
            ENUM8(coordinate_mode);
            v16 = requestLength(tvb, offsetp, t, byte_order);
            DRAWABLE(drawable);
            GCONTEXT(gc);
            LISTofPOINT(points, v16 - 12);
            break;

      case X_PolyLine:
            ENUM8(coordinate_mode);
            v16 = requestLength(tvb, offsetp, t, byte_order);
            DRAWABLE(drawable);
            GCONTEXT(gc);
            LISTofPOINT(points, v16 - 12);
            break;

      case X_PolySegment:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            DRAWABLE(drawable);
            GCONTEXT(gc);
            LISTofSEGMENT(segments);
            break;

      case X_PolyRectangle:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            DRAWABLE(drawable);
            GCONTEXT(gc);
            LISTofRECTANGLE(rectangles);
            break;

      case X_PolyArc:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            DRAWABLE(drawable);
            GCONTEXT(gc);
            LISTofARC(arcs);
            break;

      case X_FillPoly:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            v16 = requestLength(tvb, offsetp, t, byte_order);
            DRAWABLE(drawable);
            GCONTEXT(gc);
            ENUM8(shape);
            ENUM8(coordinate_mode);
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
            *offsetp += 2;
            LISTofPOINT(points, v16 - 16);
            break;

      case X_PolyFillRectangle:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            DRAWABLE(drawable);
            GCONTEXT(gc);
            LISTofRECTANGLE(rectangles);
            break;

      case X_PolyFillArc:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            DRAWABLE(drawable);
            GCONTEXT(gc);
            LISTofARC(arcs);
            break;

      case X_PutImage:
            ENUM8(image_format);
            v16 = requestLength(tvb, offsetp, t, byte_order);
            DRAWABLE(drawable);
            GCONTEXT(gc);
            CARD16(width);
            CARD16(height);
            INT16(dst_x);
            INT16(dst_y);
            CARD8(left_pad);
            CARD8(depth);
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
            *offsetp += 2;
            LISTofBYTE(data, v16 - 24);
            PAD();
            break;

      case X_GetImage:
            ENUM8(image_pixmap_format);
            requestLength(tvb, offsetp, t, byte_order);
            DRAWABLE(drawable);
            INT16(x);
            INT16(y);
            CARD16(width);
            CARD16(height);
            CARD32(plane_mask);
            break;

      case X_PolyText8:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            DRAWABLE(drawable);
            GCONTEXT(gc);
            INT16(x);
            INT16(y);
            LISTofTEXTITEM8(items);
            PAD();
            break;

      case X_PolyText16:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            DRAWABLE(drawable);
            GCONTEXT(gc);
            INT16(x);
            INT16(y);
            LISTofTEXTITEM16(items);
            PAD();
            break;

      case X_ImageText8:
            v8 = FIELD8(string_length);
            requestLength(tvb, offsetp, t, byte_order);
            DRAWABLE(drawable);
            GCONTEXT(gc);
            INT16(x);
            INT16(y);
            STRING8(string, v8);
            PAD();
            break;

      case X_ImageText16:
            v8 = FIELD8(string_length);
            requestLength(tvb, offsetp, t, byte_order);
            DRAWABLE(drawable);
            GCONTEXT(gc);
            INT16(x);
            INT16(y);
            STRING16(string16, v8);
            PAD();
            break;

      case X_CreateColormap:
            ENUM8(alloc);
            requestLength(tvb, offsetp, t, byte_order);
            COLORMAP(mid);
            WINDOW(window);
            VISUALID(visual);
            break;

      case X_FreeColormap:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            COLORMAP(cmap);
            break;

      case X_CopyColormapAndFree:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            COLORMAP(mid);
            COLORMAP(src_cmap);
            break;

      case X_InstallColormap:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            COLORMAP(cmap);
            break;

      case X_UninstallColormap:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            COLORMAP(cmap);
            break;

      case X_ListInstalledColormaps:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            WINDOW(window);
            break;

      case X_AllocColor:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            COLORMAP(cmap);
            CARD16(red);
            CARD16(green);
            CARD16(blue);
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
            *offsetp += 2;
            break;

      case X_AllocNamedColor:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            COLORMAP(cmap);
            v16 = FIELD16(name_length);
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
            *offsetp += 2;
            STRING8(name, v16);
            PAD();
            break;

      case X_AllocColorCells:
            BOOL(contiguous);
            requestLength(tvb, offsetp, t, byte_order);
            COLORMAP(cmap);
            CARD16(colors);
            CARD16(planes);
            break;

      case X_AllocColorPlanes:
            BOOL(contiguous);
            requestLength(tvb, offsetp, t, byte_order);
            COLORMAP(cmap);
            CARD16(colors);
            CARD16(reds);
            CARD16(greens);
            CARD16(blues);
            break;

      case X_FreeColors:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            v16 = requestLength(tvb, offsetp, t, byte_order);
            COLORMAP(cmap);
            CARD32(plane_mask);
            LISTofCARD32(pixels, v16 - 12);
            break;

      case X_StoreColors:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            v16 = requestLength(tvb, offsetp, t, byte_order);
            COLORMAP(cmap);
            LISTofCOLORITEM(color_items, v16 - 8);
            break;

      case X_StoreNamedColor:
            COLOR_FLAGS(color);
            requestLength(tvb, offsetp, t, byte_order);
            COLORMAP(cmap);
            CARD32(pixel);
            v16 = FIELD16(name_length);
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
            *offsetp += 2;
            STRING8(name, v16);
            PAD();
            break;

      case X_QueryColors:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            v16 = requestLength(tvb, offsetp, t, byte_order);
            COLORMAP(cmap);
            LISTofCARD32(pixels, v16 - 8);
            break;

      case X_LookupColor:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            COLORMAP(cmap);
            v16 = FIELD16(name_length);
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
            *offsetp += 2;
            STRING8(name, v16);
            PAD();
            break;

      case X_CreateCursor:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
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

      case X_CreateGlyphCursor:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
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

      case X_FreeCursor:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            CURSOR(cursor);
            break;

      case X_RecolorCursor:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            CURSOR(cursor);
            CARD16(fore_red);
            CARD16(fore_green);
            CARD16(fore_blue);
            CARD16(back_red);
            CARD16(back_green);
            CARD16(back_blue);
            break;

      case X_QueryBestSize:
            ENUM8(class);
            requestLength(tvb, offsetp, t, byte_order);
            DRAWABLE(drawable);
            CARD16(width);
            CARD16(height);
            break;

      case X_QueryExtension:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            v16 = FIELD16(name_length);
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
            *offsetp += 2;
            STRING8(name, v16);
            PAD();
            break;

      case X_ListExtensions:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            break;

      case X_ChangeKeyboardMapping:
            v8 = FIELD8(keycode_count);
            requestLength(tvb, offsetp, t, byte_order);
            v8_2 = KEYCODE(first_keycode);
            v8_3 = FIELD8(keysyms_per_keycode);
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
            *offsetp += 2;
            LISTofKEYSYM(keysyms, state->keycodemap, v8_2, v8, v8_3);
            break;

      case X_GetKeyboardMapping:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            state->request.GetKeyboardMapping.first_keycode
            = KEYCODE(first_keycode);
            FIELD8(count);
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
            *offsetp += 2;
            break;

      case X_ChangeKeyboardControl:
            {
            guint32 bitmask32;
            static int * const keyboard_value_flags[] = {
                  &hf_x11_keyboard_value_mask_key_click_percent,
                  &hf_x11_keyboard_value_mask_bell_percent,
                  &hf_x11_keyboard_value_mask_bell_pitch,
                  &hf_x11_keyboard_value_mask_bell_duration,
                  &hf_x11_keyboard_value_mask_led,
                  &hf_x11_keyboard_value_mask_led_mode,
                  &hf_x11_keyboard_value_mask_keyboard_key,
                  &hf_x11_keyboard_value_mask_auto_repeat_mode,
                  NULL
            };

            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            bitmask32 = tvb_get_guint32(tvb, *offsetp, byte_order);
            proto_tree_add_bitmask(t, tvb, *offsetp, hf_x11_keyboard_value_mask, ett_x11_keyboard_value_mask, keyboard_value_flags, byte_order);
            *offsetp += 4;
            if (bitmask32 & 0x00000001) {
                proto_tree_add_item(t, hf_x11_key_click_percent, tvb, *offsetp, 1, byte_order);
                *offsetp += 1;
                proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 3, ENC_NA);
                *offsetp += 3;
            }
            if (bitmask32 & 0x00000002) {
                proto_tree_add_item(t, hf_x11_bell_percent, tvb, *offsetp, 1, byte_order);
                *offsetp += 1;
                proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 3, ENC_NA);
                *offsetp += 3;
            }
            if (bitmask32 & 0x00000004) {
                proto_tree_add_item(t, hf_x11_bell_pitch, tvb, *offsetp, 2, byte_order);
                *offsetp += 2;
                proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
                *offsetp += 2;
            }
            if (bitmask32 & 0x00000008) {
                proto_tree_add_item(t, hf_x11_bell_duration, tvb, *offsetp, 2, byte_order);
                *offsetp += 2;
                proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
                *offsetp += 2;
            }
            if (bitmask32 & 0x00000010) {
                proto_tree_add_item(t, hf_x11_led, tvb, *offsetp, 2, byte_order);
                *offsetp += 2;
                proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
                *offsetp += 2;
            }
            if (bitmask32 & 0x00000020) {
                proto_tree_add_item(t, hf_x11_led_mode, tvb, *offsetp, 1, byte_order);
                *offsetp += 1;
                proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 3, ENC_NA);
                *offsetp += 3;
            }
            if (bitmask32 & 0x00000040) {
                proto_tree_add_item(t, hf_x11_keyboard_key, tvb, *offsetp, 1, byte_order);
                *offsetp += 1;
                proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 3, ENC_NA);
                *offsetp += 3;
            }
            if (bitmask32 & 0x00000080) {
                proto_tree_add_item(t, hf_x11_auto_repeat_mode, tvb, *offsetp, 1, byte_order);
                *offsetp += 1;
                proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 3, ENC_NA);
                *offsetp += 3;
            }
            }
            break;

      case X_GetKeyboardControl:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            break;

      case X_Bell:
            INT8(percent);
            requestLength(tvb, offsetp, t, byte_order);
            break;

      case X_ChangePointerControl:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            INT16(acceleration_numerator);
            INT16(acceleration_denominator);
            INT16(threshold);
            BOOL(do_acceleration);
            BOOL(do_threshold);
            break;

      case X_GetPointerControl:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            break;

      case X_SetScreenSaver:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            INT16(timeout);
            INT16(interval);
            ENUM8(prefer_blanking);
            ENUM8(allow_exposures);
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
            *offsetp += 2;
            break;

      case X_GetScreenSaver:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            break;

      case X_ChangeHosts:
            ENUM8(change_host_mode);
            requestLength(tvb, offsetp, t, byte_order);
            v8 = ENUM8(family);
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            v16 = CARD16(address_length);
            if (v8 == FAMILY_INTERNET && v16 == 4) {
                  /*
                   * IPv4 addresses.
                   * XXX - what about IPv6?  Is that a family of
                   * FAMILY_INTERNET (0) with a length of 16?
                   */
                  LISTofIPADDRESS(ip_address, v16);
            } else
                  LISTofCARD8(address, v16);
            break;

      case X_ListHosts:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            break;

      case X_SetAccessControl:
            ENUM8(access_mode);
            requestLength(tvb, offsetp, t, byte_order);
            break;

      case X_SetCloseDownMode:
            ENUM8(close_down_mode);
            requestLength(tvb, offsetp, t, byte_order);
            break;

      case X_KillClient:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            CARD32(resource);
            break;

      case X_RotateProperties:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            v16 = requestLength(tvb, offsetp, t, byte_order);
            WINDOW(window);
            CARD16(property_number);
            INT16(delta);
            LISTofATOM(properties, (v16 - 12));
            break;

      case X_ForceScreenSaver:
            ENUM8(screen_saver_mode);
            requestLength(tvb, offsetp, t, byte_order);
            break;

      case X_SetPointerMapping:
            v8 = FIELD8(map_length);
            requestLength(tvb, offsetp, t, byte_order);
            LISTofCARD8(map, v8);
            PAD();
            break;

      case X_GetPointerMapping:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            break;

      case X_SetModifierMapping:
            v8 = FIELD8(keycodes_per_modifier);
            requestLength(tvb, offsetp, t, byte_order);
            LISTofKEYCODE(state->modifiermap, keycodes, v8);
            break;

      case X_GetModifierMapping:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            break;

      case X_NoOperation:
            proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
            *offsetp += 1;
            requestLength(tvb, offsetp, t, byte_order);
            break;
      default:
            tryExtension(opcode, tvb, pinfo, offsetp, t, state, byte_order);
            break;
      }

      if ((left = tvb_reported_length_remaining(tvb, offset)) > 0)
            UNDECODED(left);
}

static void dissect_x11_requests(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree)
{
      volatile int offset = 0;
      int length_remaining;
      volatile guint byte_order;
      guint8 opcode;
      volatile gint plen;
      proto_item *ti;
      volatile gboolean is_initial_creq;
      guint16 auth_proto_len, auth_data_len;
      const char *volatile sep = NULL;
      conversation_t *conversation;
      x11_conv_data_t *volatile state;
      int length;
      tvbuff_t *volatile next_tvb;

      while ((length_remaining = tvb_reported_length_remaining(tvb, offset)) > 0) {

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
                         * us and that we need "some more data."  Don't tell
                         * it exactly how many bytes we need because if/when
                         * we ask for even more (after the header) that will
                         * break reassembly.
                         */
                        pinfo->desegment_offset = offset;
                        pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                        return;
                  }
            }

            /*
             * Get the state for this conversation; create the conversation
             * if we don't have one, and create the state if we don't have
             * any.
             */
            conversation = find_or_create_conversation(pinfo);

            /*
             * Is there state attached to this conversation?
             */
            if ((state = (x11_conv_data_t *)conversation_get_proto_data(conversation, proto_x11))
            == NULL)
                state = x11_stateinit(conversation);

            /*
             * Guess the byte order if we don't already know it.
             */
            byte_order = guess_byte_ordering(tvb, pinfo, state);

            /*
             * Get the opcode and length of the putative X11 request.
             */
            opcode = tvb_get_guint8(tvb, 0);
            plen = tvb_get_guint16(tvb, offset + 2, byte_order);

            if (plen == 0) {
                  /*
                   * A length field of 0 indicates that the BIG-REQUESTS
                   * extension is used: The next four bytes are the real length.
                   */
                  plen = tvb_get_guint32(tvb, offset + 4, byte_order);
            }

            if (plen <= 0) {
                  /*
                   * This can't be less then 0, as it includes the header length.
                   * A different choice of byte order wouldn't have
                   * helped.
                   * Give up.
                   */
                  ti = proto_tree_add_item(tree, proto_x11, tvb, offset, -1, ENC_NA);
                  expert_add_info_format(pinfo, ti, &ei_x11_request_length, "Bogus request length (%d)", plen);
                  return;
            }

            if (state->iconn_frame == pinfo->num ||
                (wmem_map_lookup(state->seqtable,
                GINT_TO_POINTER(state->sequencenumber)) == (int *)NOTHING_SEEN &&
                 (opcode == 'B' || opcode == 'l') &&
                 (plen == 11 || plen == 2816))) {
                  /*
                   * Either
                   *
                   *    we saw this on the first pass and this is
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
                  if (state->byte_order == BYTE_ORDER_UNKNOWN) {
                        if (opcode == 'B') {
                              /*
                               * Big-endian.
                               */
                              byte_order = state->byte_order = ENC_BIG_ENDIAN;
                        } else {
                              /*
                               * Little-endian.
                               */
                              byte_order = state->byte_order = ENC_LITTLE_ENDIAN;
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
                               * it handed us and that we need "some more
                               * data."  Don't tell it exactly how many bytes
                               * we need because if/when we ask for even more
                               * (after the header) that will break reassembly.
                               */
                              pinfo->desegment_offset = offset;
                              pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                              return;
                        }
                  }

                  /*
                   * Get the lengths of the authorization protocol and
                   * the authorization data.
                   */
                  auth_proto_len = tvb_get_guint16(tvb, offset + 6, byte_order);
                  auth_data_len = tvb_get_guint16(tvb, offset + 8, byte_order);
                  plen = 12 + ROUND_LENGTH(auth_proto_len) +
                        ROUND_LENGTH(auth_data_len);
            } else {
                  volatile gint64 tmp = (gint64)plen * 4;
                  /*
                   * This is probably an ordinary request.
                   */
                  is_initial_creq = FALSE;

                  /*
                   * The length of a request is in 4-byte words.
                   */
                  if (tmp > G_MAXINT32) {
                        ti = proto_tree_add_item(tree, proto_x11, tvb, offset, -1, ENC_NA);
                        expert_add_info_format(pinfo, ti, &ei_x11_request_length, "Bogus request length (%"PRId64")", tmp);
                        return;
                  }
                  plen = (gint)tmp;
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
            next_tvb = tvb_new_subset_length_caplen(tvb, offset, length, plen);

            /*
             * Set the column appropriately.
             */
            if (is_initial_creq) {
                  col_set_str(pinfo->cinfo, COL_INFO, "Initial connection request");
            } else {
                  if (sep == NULL) {
                        /*
                         * We haven't set the column yet; set it.
                         */
                        col_set_str(pinfo->cinfo, COL_INFO, "Requests");

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
                            state, byte_order);
                  } else {
                        dissect_x11_request(next_tvb, pinfo, tree, sep,
                            state, byte_order);
                  }
            }
            CATCH_NONFATAL_ERRORS {
                  show_exception(tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
            }
            ENDTRY;

            /*
             * Skip the X11 message.
             */
            offset += plen;

            sep = ",";
      }
}

static x11_conv_data_t *
x11_stateinit(conversation_t *conversation)
{
      x11_conv_data_t *state;
      static x11_conv_data_t stateinit;
      int i;

      state = wmem_new(wmem_file_scope(), x11_conv_data_t);
      *state = stateinit;

      /* initialise opcodes */
      for (i = 0; opcode_vals[i].strptr != NULL; i++) {
            state->opcode_vals[i].value = opcode_vals[i].value;
            state->opcode_vals[i].strptr = opcode_vals[i].strptr;
      }
      for (; i <= MAX_OPCODES; i++) {
            state->opcode_vals[i].value = 0;
            state->opcode_vals[i].strptr = NULL;
      }

      /* initialise errorcodes */
      for (i = 0; errorcode_vals[i].strptr != NULL; i++) {
            state->errorcode_vals[i].value = errorcode_vals[i].value;
            state->errorcode_vals[i].strptr = errorcode_vals[i].strptr;
      }
      for (; i <= LastExtensionError + 1; i++) {
            state->errorcode_vals[i].value = 0;
            state->errorcode_vals[i].strptr = NULL;
      }

      /* initialise eventcodes */
      for (i = 0; eventcode_vals[i].strptr != NULL; i++) {
            state->eventcode_vals[i].value = eventcode_vals[i].value;
            state->eventcode_vals[i].strptr = eventcode_vals[i].strptr;
      }
      for (; i <= LastExtensionEvent + 1; i++) {
            state->eventcode_vals[i].value = 0;
            state->eventcode_vals[i].strptr = NULL;
      }
      state->eventcode_funcs = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
      state->reply_funcs = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);

      state->seqtable = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
      state->valtable = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
      wmem_map_insert(state->seqtable, (int *)0, (int *)NOTHING_SEEN);
      state->byte_order = BYTE_ORDER_UNKNOWN; /* don't know yet*/
      conversation_add_proto_data(conversation, proto_x11, state);
      return state;
}


static void
dissect_x11_replies(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
/* Set up structures we will need to add the protocol subtree and manage it */
      volatile int offset, plen;
      tvbuff_t *volatile next_tvb;
      conversation_t *conversation;
      x11_conv_data_t *volatile state;
      volatile guint byte_order;
      int length_remaining;
      const char *volatile sep = NULL;


      /*
       * Get the state for this conversation; create the conversation
       * if we don't have one, and create the state if we don't have
       * any.
       */
      conversation = find_or_create_conversation(pinfo);

      /*
       * Is there state attached to this conversation?
       */
      if ((state = (x11_conv_data_t *)conversation_get_proto_data(conversation, proto_x11))
          == NULL) {
            /*
             * No - create a state structure and attach it.
             */
            state = x11_stateinit(conversation);
      }

      /*
       * Guess the byte order if we don't already know it.
       */
      byte_order = guess_byte_ordering(tvb, pinfo, state);

      offset = 0;
      while ((length_remaining = tvb_reported_length_remaining(tvb, offset)) > 0) {
            /*
             * Can we do reassembly?
             */
            if (x11_desegment && pinfo->can_desegment) {
                  /*
                   * Yes - is the X11 Reply or GenericEvent header split across
                   * segment boundaries?
                   */
                  if (length_remaining < 8) {
                        /*
                         * Yes.  Tell the TCP dissector where the data
                         * for this message starts in the data it handed
                         * us and that we need "some more data."  Don't tell
                         * it exactly how many bytes we need because if/when
                         * we ask for even more (after the header) that will
                         * break reassembly.
                         */
                        pinfo->desegment_offset = offset;
                        pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                        return;
                  }
            }

            /*
             * Find out what kind of a reply it is.
             * There are four possible:
             *  - reply to initial connection
             *  - errorreply (a request generated an error)
             *  - requestreply (reply to a request)
             *  - event (some event occurred)
             */
            if (wmem_map_lookup(state->seqtable,
                                    GINT_TO_POINTER(state->sequencenumber)) == (int *)INITIAL_CONN
                || (state->iconn_reply == pinfo->num)) {
                  /*
                   * Either the connection is in the "initial
                   * connection" state, or this frame is known
                   * to have the initial connection reply.
                   * That means this is the initial connection
                   * reply.
                   */
                  plen = 8 + tvb_get_guint16(tvb, offset + 6, byte_order) * 4;

                  HANDLE_REPLY(plen, length_remaining,
                               "Initial connection reply",
                               dissect_x11_initial_reply);
            } else {
                  /*
                   * This isn't an initial connection reply
                   * (XXX - unless we missed the initial
                   * connection request).  Look at the first
                   * byte to determine what it is; errors
                   * start with a byte of 0, replies start
                   * with a byte of 1, events start with
                   * a byte with of 2 or greater.
                   */
                  switch (tvb_get_guint8(tvb, offset)) {

                        case 0:
                              plen = 32;
                              HANDLE_REPLY(plen, length_remaining,
                                           "Error", dissect_x11_error);
                              break;

                        case 1:
                        {
                              /* To avoid an "assert w/side-effect" warning,
                               * use a non-volatile temp variable instead. */
                              int tmp_plen;

                              /* replylength is in units of four. */
                              tmp_plen = plen = 32 + tvb_get_guint32(tvb, offset + 4, byte_order) * 4;
                              /* If tmp_plen < 32, we got an overflow;
                               * the reply length is too long. */
                              THROW_ON(tmp_plen < 32, ReportedBoundsError);
                              HANDLE_REPLY(plen, length_remaining,
                                           "Reply", dissect_x11_reply);
                              break;
                        }

                        case GenericEvent:
                        {
                              /* An Event, but with a length field like a Reply. */

                              /* To avoid an "assert w/side-effect" warning,
                               * use a non-volatile temp variable instead. */
                              int tmp_plen;

                              /* GenericEvent's length is also in units of four. */
                              tmp_plen = plen = 32 + tvb_get_guint32(tvb, offset + 4, byte_order) * 4;
                              /* If tmp_plen < 32, we got an overflow;
                               * the event length is too long. */
                              THROW_ON(tmp_plen < 32, ReportedBoundsError);
                              HANDLE_REPLY(plen, length_remaining,
                                           "Event", dissect_x11_event);
                              break;
                        }

                        default:
                              /* Event */
                              plen = 32;
                              HANDLE_REPLY(plen, length_remaining,
                                           "Event", dissect_x11_event);
                              break;
                  }
            }

            offset += plen;
      }

      return;
}

static void
dissect_x11_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                  const char *sep, x11_conv_data_t *state,
                  guint byte_order)
{
      int offset = 0, *offsetp = &offset, length, left, opcode;
      int major_opcode, sequence_number, first_error, first_event;
      value_string *vals_p;
      proto_item *ti;
      proto_tree *t;

      ti = proto_tree_add_item(tree, proto_x11, tvb, 0, -1, ENC_NA);
      t = proto_item_add_subtree(ti, ett_x11);


      /*
       * XXX - this doesn't work correctly if either
       *
       *        1) the request sequence number wraps in the lower 16
       *           bits;
       *
       *        2) we don't see the initial connection request and the
       *         resynchronization of sequence number fails and thus
       *           don't have the right sequence numbers
       *
       *        3) we don't have all the packets in the capture and
       *           get out of sequence.
       *
       * We might, instead, want to assume that a reply is a reply to
       * the most recent not-already-replied-to request in the same
       * connection.  That also might mismatch replies to requests if
       * packets are lost, but there's nothing you can do to fix that.
       */

      sequence_number = tvb_get_guint16(tvb, offset + 2, byte_order);
      opcode = GPOINTER_TO_INT(wmem_map_lookup(state->seqtable,
                                                   GINT_TO_POINTER(sequence_number)));

      if (state->iconn_frame == 0 &&  state->resync == FALSE) {

            /*
             * We don't see the initial connection request and no
             * resynchronization has been performed yet (first reply),
             * set the current sequence number to the one of the
             * current reply (this is only performed once).
             */
            state->sequencenumber = sequence_number;
            state->resync = TRUE;
      }

      if (opcode == UNKNOWN_OPCODE) {
            col_append_fstr(pinfo->cinfo, COL_INFO,
                            "%s to unknown request", sep);
            proto_item_append_text(ti, ", Reply to unknown request");
      } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s %s",
                            sep,
                            val_to_str(opcode & 0xFF, state->opcode_vals,
                                        "<Unknown opcode %d>"));

            if (opcode > 0xFF)
                  proto_item_append_text(ti, ", Reply, opcode: %d.%d (%s)",
                                         opcode & 0xFF, opcode >> 8, val_to_str(opcode & 0xFF,
                                                                                state->opcode_vals,
                                                                                "<Unknown opcode %d>"));
            else
                  proto_item_append_text(ti, ", Reply, opcode: %d (%s)",
                                         opcode, val_to_str(opcode,
                                                            state->opcode_vals,
                                                            "<Unknown opcode %d>"));
      }

      switch (opcode) {

            /*
             * Replies that need special processing outside tree
             */

            case X_QueryExtension:

                  /*
                   * if extension is present and request is known:
                   * store opcode of extension in value_string of
                   * opcodes
                   */
                  if (!tvb_get_guint8(tvb, offset + 8)) {
                        /* not present */
                        break;
                  }

                  vals_p = (value_string *)wmem_map_lookup(state->valtable,
                                               GINT_TO_POINTER(sequence_number));
                  if (vals_p != NULL) {
                        major_opcode = tvb_get_guint8(tvb, offset + 9);
                        first_event = tvb_get_guint8(tvb, offset + 10);
                        first_error = tvb_get_guint8(tvb, offset + 11);

                        register_extension(state, vals_p, major_opcode, first_event, first_error);
                        wmem_map_remove(state->valtable,
                                            GINT_TO_POINTER(sequence_number));
                  }
                  break;

            default:
                  break;
      }

      if (tree == NULL)
            return;

      switch (opcode) {
            /*
             * Requests that expect a reply.
             */

            case X_GetWindowAttributes:
                  REPLYCONTENTS_COMMON();
                  break;

            case X_GetGeometry:
                  REPLY(reply);
                  CARD8(depth);
                  SEQUENCENUMBER_REPLY(sequencenumber);
                  REPLYLENGTH(replylength);
                  WINDOW(rootwindow);
                  INT16(x);
                  INT16(y);
                  CARD16(width);
                  CARD16(height);
                  CARD16(border_width);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 10, ENC_NA);
                  *offsetp += 10;
                  break;

            case X_QueryTree:
                  REPLYCONTENTS_COMMON();
                  break;

            case X_InternAtom:
                  REPLY(reply);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  SEQUENCENUMBER_REPLY(sequencenumber);
                  REPLYLENGTH(replylength);
                  ATOM(atom);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 20, ENC_NA);
                  *offsetp += 20;
                  break;

            case X_GetAtomName:
                  REPLYCONTENTS_COMMON();
                  break;

            case X_GetProperty:
                  REPLY(reply);
                  CARD8(format);
                  SEQUENCENUMBER_REPLY(sequencenumber);
                  REPLYLENGTH(replylength);
                  ATOM(get_property_type);
                  CARD32(bytes_after);
                  CARD32(valuelength);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 12, ENC_NA);
                  *offsetp += 12;
                  break;

            case X_ListProperties:
                  REPLY(reply);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  SEQUENCENUMBER_REPLY(sequencenumber);
                  REPLYLENGTH(replylength);
                  length = CARD16(property_number);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 22, ENC_NA);
                  *offsetp += 22;
                  LISTofATOM(properties, length*4);
                  break;

            case X_GetSelectionOwner:
                  REPLY(reply);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  SEQUENCENUMBER_REPLY(sequencenumber);
                  REPLYLENGTH(replylength);
                  WINDOW(owner);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 20, ENC_NA);
                  *offsetp += 20;
                  break;

            case X_GrabPointer:
            case X_GrabKeyboard:
                  REPLY(reply);
                  ENUM8(grab_status);
                  SEQUENCENUMBER_REPLY(sequencenumber);
                  REPLYLENGTH(replylength);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 24, ENC_NA);
                  *offsetp += 24;
                  break;

            case X_QueryPointer:
                  REPLY(reply);
                  BOOL(same_screen);
                  SEQUENCENUMBER_REPLY(sequencenumber);
                  REPLYLENGTH(replylength);
                  WINDOW(rootwindow);
                  WINDOW(childwindow);
                  INT16(root_x);
                  INT16(root_y);
                  INT16(win_x);
                  INT16(win_y);
                  SETofKEYBUTMASK(mask);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 6, ENC_NA);
                  *offsetp += 6;
                  break;

            case X_GetMotionEvents:
                  REPLYCONTENTS_COMMON();
                  break;

            case X_TranslateCoords:
                  REPLY(reply);
                  BOOL(same_screen);
                  SEQUENCENUMBER_REPLY(sequencenumber);
                  REPLYLENGTH(replylength);
                  WINDOW(childwindow);
                  INT16(dst_x);
                  INT16(dst_y);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 16, ENC_NA);
                  *offsetp += 16;
                  break;

            case X_GetInputFocus:
                  REPLY(reply);
                  ENUM8(revert_to);
                  SEQUENCENUMBER_REPLY(sequencenumber);
                  REPLYLENGTH(replylength);
                  WINDOW(focus);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 20, ENC_NA);
                  *offsetp += 20;
                  break;

            case X_QueryKeymap:
                  REPLY(reply);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  SEQUENCENUMBER_REPLY(sequencenumber);
                  REPLYLENGTH(replylength);
                  LISTofCARD8(keys, 32);
                  break;

            case X_QueryFont:
            case X_QueryTextExtents:
            case X_ListFonts:
            case X_GetImage:
            case X_ListInstalledColormaps:
                  REPLYCONTENTS_COMMON();
                  break;

            case X_AllocColor:
                  REPLY(reply);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  SEQUENCENUMBER_REPLY(sequencenumber);
                  REPLYLENGTH(replylength);
                  CARD16(red);
                  CARD16(green);
                  CARD16(blue);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 2, ENC_NA);
                  *offsetp += 2;
                  CARD32(pixel);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 12, ENC_NA);
                  *offsetp += 12;
                  break;

            case X_QueryColors:
                  REPLYCONTENTS_COMMON();
                  break;

            case X_LookupColor:
                  REPLY(reply);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  SEQUENCENUMBER_REPLY(sequencenumber);
                  REPLYLENGTH(replylength);
                  CARD16(exact_red);
                  CARD16(exact_green);
                  CARD16(exact_blue);
                  CARD16(visual_red);
                  CARD16(visual_green);
                  CARD16(visual_blue);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 12, ENC_NA);
                  *offsetp += 12;
                  break;

            case X_QueryBestSize:
                  REPLY(reply);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  SEQUENCENUMBER_REPLY(sequencenumber);
                  REPLYLENGTH(replylength);
                  CARD16(width);
                  CARD16(height);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 20, ENC_NA);
                  *offsetp += 20;
                  break;

            case X_QueryExtension:
                  REPLY(reply);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  SEQUENCENUMBER_REPLY(sequencenumber);
                  REPLYLENGTH(replylength);
                  BOOL(present);
                  CARD8(major_opcode);
                  CARD8(first_event);
                  CARD8(first_error);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 20, ENC_NA);
                  *offsetp += 20;
                  break;

            case X_ListExtensions:
                  REPLYCONTENTS_COMMON();
                  break;

            case X_GetKeyboardMapping:
                  state->first_keycode =
                        state->request.GetKeyboardMapping.first_keycode;
                  REPLY(reply);
                  state->keysyms_per_keycode =
                        FIELD8(keysyms_per_keycode);
                  SEQUENCENUMBER_REPLY(sequencenumber);
                  length = REPLYLENGTH(replylength);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 24, ENC_NA);
                  *offsetp += 24;
                  LISTofKEYSYM(keysyms, state->keycodemap,
                               state->request.GetKeyboardMapping.first_keycode,
                               /* XXX - length / state->keysyms_per_keycode can raise a division by zero,
                                * don't know if this is the *right* way to fix it ... */
                               state->keysyms_per_keycode ? length / state->keysyms_per_keycode : 0,
                               state->keysyms_per_keycode);
                  break;

            case X_GetKeyboardControl:
                  REPLYCONTENTS_COMMON();
                  break;

            case X_GetPointerControl:
                  REPLY(reply);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  SEQUENCENUMBER_REPLY(sequencenumber);
                  REPLYLENGTH(replylength);
                  CARD16(acceleration_numerator);
                  CARD16(acceleration_denominator);
                  CARD16(threshold);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 18, ENC_NA);
                  *offsetp += 18;
                  break;

            case X_GetScreenSaver:
                  REPLY(reply);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  SEQUENCENUMBER_REPLY(sequencenumber);
                  REPLYLENGTH(replylength);
                  CARD16(timeout);
                  CARD16(interval);
                  ENUM8(prefer_blanking);
                  ENUM8(allow_exposures);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 18, ENC_NA);
                  *offsetp += 18;
                  break;

            case X_ListHosts:
            case X_SetPointerMapping:
            case X_GetPointerMapping:
            case X_SetModifierMapping:
                  REPLYCONTENTS_COMMON();
                  break;

            case X_GetModifierMapping:
                  REPLY(reply);
                  state->keycodes_per_modifier =
                        FIELD8(keycodes_per_modifier);
                  SEQUENCENUMBER_REPLY(sequencenumber);
                  REPLYLENGTH(replylength);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 24, ENC_NA);
                  *offsetp += 24;
                  LISTofKEYCODE(state->modifiermap, keycodes,
                                state->keycodes_per_modifier);
                  break;

            case UNKNOWN_OPCODE:
                  REPLYCONTENTS_COMMON();
                  break;

            default:
                  tryExtensionReply(opcode, tvb, pinfo, offsetp, t, state, byte_order);
      }

      if ((left = tvb_reported_length_remaining(tvb, offset)) > 0)
            UNDECODED(left);
}

static void
same_screen_focus(tvbuff_t *tvb, int *offsetp, proto_tree *t)
{
      proto_item *ti;
      guint32 bitmask_value;
      int bitmask_offset;
      int bitmask_size;
      proto_tree *bitmask_tree;

      bitmask_value = tvb_get_guint8(tvb, *offsetp);
      bitmask_offset = *offsetp;
      bitmask_size = 1;

      ti = proto_tree_add_uint(t, hf_x11_same_screen_focus_mask, tvb, *offsetp, 1,
                               bitmask_value);
      bitmask_tree = proto_item_add_subtree(ti, ett_x11_same_screen_focus);
      FLAG(same_screen_focus, focus);
      FLAG(same_screen_focus, same_screen);

      *offsetp += 1;
}

static void
dissect_x11_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                  const char *sep, x11_conv_data_t *state,
                  guint byte_order)
{
      unsigned char eventcode;
      const char *sent;
      proto_item *ti;
      proto_tree *t;

      ti = proto_tree_add_item(tree, proto_x11, tvb, 0, -1, ENC_NA);
      t = proto_item_add_subtree(ti, ett_x11);

      eventcode = tvb_get_guint8(tvb, 0);
      sent = (eventcode & 0x80) ? "Sent-" : "";

      col_append_fstr(pinfo->cinfo, COL_INFO, "%s %s%s",
                    sep, sent,
                    val_to_str(eventcode & 0x7F, state->eventcode_vals,
                                "<Unknown eventcode %u>"));

      proto_item_append_text(ti, ", Event, eventcode: %d (%s%s)",
                             eventcode, sent,
                             val_to_str(eventcode & 0x7F, state->eventcode_vals,
                                        "<Unknown eventcode %u>"));

      if (tree == NULL)
            return;

      decode_x11_event(tvb, eventcode, sent, t, state, byte_order);

      return;
}

static void
decode_x11_event(tvbuff_t *tvb, unsigned char eventcode, const char *sent,
                 proto_tree *t, x11_conv_data_t *state,
                 guint byte_order)
{
      int offset = 0, *offsetp = &offset, left;

      proto_tree_add_uint_format(t, hf_x11_eventcode, tvb, offset, 1,
                                 eventcode,
                                 "eventcode: %d (%s%s)",
                                 eventcode, sent,
                                 val_to_str(eventcode & 0x7F, state->eventcode_vals,
                                            "<Unknown eventcode %u>"));
      ++offset;

      switch (eventcode & 0x7F) {
            case KeyPress:
            case KeyRelease: {
                  int code, mask;

                  /* need to do some prefetching here ... */
                  code = tvb_get_guint8(tvb, offset);
                  mask = tvb_get_guint16(tvb, 28, byte_order);

                  KEYCODE_DECODED(keycode, code, mask);
                  CARD16(event_sequencenumber);
                  EVENTCONTENTS_COMMON();
                  BOOL(same_screen);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  break;
            }

            case ButtonPress:
            case ButtonRelease:
                  BUTTON(eventbutton);
                  CARD16(event_sequencenumber);
                  EVENTCONTENTS_COMMON();
                  BOOL(same_screen);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  break;

            case MotionNotify:
                  CARD8(detail);
                  CARD16(event_sequencenumber);
                  EVENTCONTENTS_COMMON();
                  BOOL(same_screen);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  break;

            case EnterNotify:
            case LeaveNotify:
                  ENUM8(event_detail);
                  CARD16(event_sequencenumber);
                  EVENTCONTENTS_COMMON();
                  ENUM8(grab_mode);
                  same_screen_focus(tvb, offsetp, t);
                  break;

            case FocusIn:
            case FocusOut:
                  ENUM8(focus_detail);
                  CARD16(event_sequencenumber);
                  WINDOW(eventwindow);
                  ENUM8(focus_mode);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 23, ENC_NA);
                  *offsetp += 23;
                  break;

            case KeymapNotify:
                  break;

            case Expose:
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  CARD16(event_sequencenumber);
                  WINDOW(eventwindow);
                  INT16(x);
                  INT16(y);
                  CARD16(width);
                  CARD16(height);
                  CARD16(count);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 14, ENC_NA);
                  *offsetp += 14;
                  break;

            case GraphicsExpose:
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  CARD16(event_sequencenumber);
                  DRAWABLE(drawable);
                  CARD16(x);
                  CARD16(y);
                  CARD16(width);
                  CARD16(height);
                  CARD16(minor_opcode);
                  CARD16(count);
                  CARD8(major_opcode);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 11, ENC_NA);
                  *offsetp += 11;
                  break;

            case NoExpose:
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  CARD16(event_sequencenumber);
                  DRAWABLE(drawable);
                  CARD16(minor_opcode);
                  CARD8(major_opcode);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 21, ENC_NA);
                  *offsetp += 21;
                  break;

            case VisibilityNotify:
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  CARD16(event_sequencenumber);
                  WINDOW(eventwindow);
                  ENUM8(visibility_state);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 23, ENC_NA);
                  *offsetp += 23;
                  break;

            case CreateNotify:
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  CARD16(event_sequencenumber);
                  WINDOW(parent);
                  WINDOW(eventwindow);
                  INT16(x);
                  INT16(y);
                  CARD16(width);
                  CARD16(height);
                  CARD16(border_width);
                  BOOL(override_redirect);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 9, ENC_NA);
                  *offsetp += 9;
                  break;

            case DestroyNotify:
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  CARD16(event_sequencenumber);
                  WINDOW(eventwindow);
                  WINDOW(window);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 20, ENC_NA);
                  *offsetp += 20;
                  break;

            case UnmapNotify:
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  CARD16(event_sequencenumber);
                  WINDOW(eventwindow);
                  WINDOW(window);
                  BOOL(from_configure);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 19, ENC_NA);
                  *offsetp += 19;
                  break;

            case MapNotify:
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  CARD16(event_sequencenumber);
                  WINDOW(eventwindow);
                  WINDOW(window);
                  BOOL(override_redirect);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 19, ENC_NA);
                  *offsetp += 19;
                  break;

            case MapRequest:
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  CARD16(event_sequencenumber);
                  WINDOW(parent);
                  WINDOW(eventwindow);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 20, ENC_NA);
                  *offsetp += 20;
                  break;

            case ReparentNotify:
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  CARD16(event_sequencenumber);
                  WINDOW(eventwindow);
                  WINDOW(window);
                  WINDOW(parent);
                  INT16(x);
                  INT16(y);
                  BOOL(override_redirect);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 11, ENC_NA);
                  *offsetp += 11;
                  break;

            case ConfigureNotify:
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  CARD16(event_sequencenumber);
                  WINDOW(eventwindow);
                  WINDOW(window);
                  WINDOW(above_sibling);
                  INT16(x);
                  INT16(y);
                  CARD16(width);
                  CARD16(height);
                  CARD16(border_width);
                  BOOL(override_redirect);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 5, ENC_NA);
                  *offsetp += 5;
                  break;

            case ConfigureRequest:
                  break;

            case GravityNotify:
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  CARD16(event_sequencenumber);
                  WINDOW(eventwindow);
                  WINDOW(window);
                  INT16(x);
                  INT16(y);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 16, ENC_NA);
                  *offsetp += 16;
                  break;

            case ResizeRequest:
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  CARD16(event_sequencenumber);
                  WINDOW(eventwindow);
                  CARD16(width);
                  CARD16(height);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 20, ENC_NA);
                  *offsetp += 20;
                  break;

            case CirculateNotify:
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  CARD16(event_sequencenumber);
                  WINDOW(eventwindow);
                  WINDOW(window);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 4, ENC_NA);
                  *offsetp += 4;
                  ENUM8(place);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 15, ENC_NA);
                  *offsetp += 15;
                  break;

            case CirculateRequest:
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  CARD16(event_sequencenumber);
                  WINDOW(parent);
                  WINDOW(eventwindow);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 4, ENC_NA);
                  *offsetp += 4;
                  ENUM8(place);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 15, ENC_NA);
                  *offsetp += 15;
                  break;

            case PropertyNotify:
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  CARD16(event_sequencenumber);
                  WINDOW(eventwindow);
                  ATOM(atom);
                  TIMESTAMP(time);
                  ENUM8(property_state);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 15, ENC_NA);
                  *offsetp += 15;
                  break;

            case SelectionClear:
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  CARD16(event_sequencenumber);
                  TIMESTAMP(time);
                  WINDOW(owner);
                  ATOM(selection);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 16, ENC_NA);
                  *offsetp += 16;
                  break;

            case SelectionRequest:
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  CARD16(event_sequencenumber);
                  TIMESTAMP(time);
                  WINDOW(owner);
                  WINDOW(requestor);
                  ATOM(selection);
                  ATOM(target);
                  ATOM(property);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 4, ENC_NA);
                  *offsetp += 4;
                  break;

            case SelectionNotify:
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  CARD16(event_sequencenumber);
                  TIMESTAMP(time);
                  WINDOW(requestor);
                  ATOM(selection);
                  ATOM(target);
                  ATOM(property);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 8, ENC_NA);
                  *offsetp += 8;
                  break;

            case ColormapNotify:
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  CARD16(event_sequencenumber);
                  WINDOW(eventwindow);
                  COLORMAP(cmap);
                  BOOL(new);
                  ENUM8(colormap_state);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 18, ENC_NA);
                  *offsetp += 18;
                  break;

            case ClientMessage:
                  CARD8(format);
                  CARD16(event_sequencenumber);
                  WINDOW(eventwindow);
                  ATOM(type);
                  LISTofBYTE(data, 20);
                  break;

            case MappingNotify:
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 1, ENC_NA);
                  *offsetp += 1;
                  CARD16(event_sequencenumber);
                  ENUM8(mapping_request);
                  CARD8(first_keycode);
                  CARD8(count);
                  proto_tree_add_item(t, hf_x11_unused, tvb, *offsetp, 25, ENC_NA);
                  *offsetp += 25;
                  break;

            case GenericEvent:
                  tryGenericExtensionEvent(tvb, offsetp, t, state, byte_order);
                  break;

            default:
                  tryExtensionEvent(eventcode & 0x7F, tvb, offsetp, t, state, byte_order);
                  break;
      }

      if ((left = tvb_reported_length_remaining(tvb, offset)) > 0)
            UNDECODED(left);
}

static void
dissect_x11_error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                  const char *sep, x11_conv_data_t *state _U_,
                  guint byte_order)
{
      int offset = 0, *offsetp = &offset, left;
      unsigned char errorcode;
      proto_item *ti;
      proto_tree *t;

      ti = proto_tree_add_item(tree, proto_x11, tvb, 0, -1, ENC_NA);
      t = proto_item_add_subtree(ti, ett_x11);

      CARD8(error);

      errorcode = tvb_get_guint8(tvb, offset);
      col_append_fstr(pinfo->cinfo, COL_INFO, "%s %s",
                    sep, val_to_str(errorcode, state->errorcode_vals, "<Unknown errorcode %u>"));

      proto_tree_add_uint_format(t, hf_x11_errorcode, tvb, offset, 1,
                                 errorcode,
                                 "errorcode: %d (%s)",
                                 errorcode,
                                 val_to_str(errorcode, state->errorcode_vals,
                                            "<Unknown errorcode %u>"));
      ++offset;

      proto_item_append_text(ti, ", Error, errorcode: %d (%s)",
                             errorcode, val_to_str(errorcode, state->errorcode_vals,
                                                   "<Unknown errorcode %u>"));

      if (tree == NULL)
            return;

      CARD16(error_sequencenumber);

      switch (errorcode) {
            case BadValue:
                  CARD32(error_badvalue);
                  break;
            case BadWindow:
            case BadPixmap:
            case BadCursor:
            case BadFont:
            case BadDrawable:
            case BadColormap:
            case BadGC:
            case BadIDChoice:
                  CARD32(error_badresourceid);
                  break;

            default:
                  UNDECODED(4);
      }

      CARD16(minor_opcode);
      CARD8(major_opcode);

      if ((left = tvb_reported_length_remaining(tvb, offset)) > 0)
            UNDECODED(left);
}



/************************************************************************
 ***                                                                  ***
 ***         I N I T I A L I Z A T I O N   A N D   M A I N            ***
 ***                                                                  ***
 ************************************************************************/

static int
dissect_x11(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "X11");

      if (pinfo->match_uint == pinfo->srcport)
            dissect_x11_replies(tvb, pinfo, tree);
      else
            dissect_x11_requests(tvb, pinfo, tree);

      return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */
void proto_register_x11(void)
{

/* Setup list of header fields */
      static hf_register_info hf[] = {
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
            &ett_x11_list_of_float,
            &ett_x11_list_of_double,
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
            &ett_x11_same_screen_focus,
            &ett_x11_event,
            &ett_x11_list_of_pixmap_format,
            &ett_x11_pixmap_format,
            &ett_x11_list_of_screen,
            &ett_x11_screen,
            &ett_x11_list_of_depth_detail,
            &ett_x11_depth_detail,
            &ett_x11_list_of_visualtype,
            &ett_x11_visualtype,
      };

      static ei_register_info ei[] = {
            { &ei_x11_invalid_format, { "x11.invalid_format", PI_PROTOCOL, PI_WARN, "Invalid Format", EXPFILL }},
            { &ei_x11_request_length, { "x11.request-length.invalid", PI_PROTOCOL, PI_WARN, "Invalid Length", EXPFILL }},
            { &ei_x11_keycode_value_out_of_range, { "x11.keycode_value_out_of_range", PI_PROTOCOL, PI_WARN, "keycode value is out of range", EXPFILL }},
      };

      module_t *x11_module;
      expert_module_t* expert_x11;

/* Register the protocol name and description */
      proto_x11 = proto_register_protocol("X11", "X11", "x11");
      x11_handle = register_dissector("x11", dissect_x11, proto_x11);

/* Required function calls to register the header fields and subtrees used */
      proto_register_field_array(proto_x11, hf, array_length(hf));
      proto_register_subtree_array(ett, array_length(ett));
      expert_x11 = expert_register_protocol(proto_x11);
      expert_register_field_array(expert_x11, ei, array_length(ei));

      extension_table = wmem_map_new(wmem_epan_scope(), wmem_str_hash, g_str_equal);
      error_table = wmem_map_new(wmem_epan_scope(), wmem_str_hash, g_str_equal);
      event_table = wmem_map_new(wmem_epan_scope(), wmem_str_hash, g_str_equal);
      genevent_table = wmem_map_new(wmem_epan_scope(), wmem_str_hash, g_str_equal);
      reply_table = wmem_map_new(wmem_epan_scope(), wmem_str_hash, g_str_equal);
      register_x11_extensions();

      x11_module = prefs_register_protocol(proto_x11, NULL);
      prefs_register_bool_preference(x11_module, "desegment",
            "Reassemble X11 messages spanning multiple TCP segments",
            "Whether the X11 dissector should reassemble messages spanning multiple TCP segments. "
            "To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
            &x11_desegment);
}

void
proto_reg_handoff_x11(void)
{
      dissector_add_uint_range_with_preference("tcp.port",  DEFAULT_X11_PORT_RANGE, x11_handle);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 6
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=6 tabstop=8 expandtab:
 * :indentSize=6:tabSize=8:noTabs=true:
 */
