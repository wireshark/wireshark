# Win32csdk.py - Genskel module for creating Win32 C SDK code
# Tabs: 8  indent: 4

# To do:
# - Come up with some sort of box packing system that will properly arrange
#   controls inside containers.
# - Link menus to commands
# - Pull in event handler from win32-main.c
# - Dump out a list of functions we need to create

from frontendutil import *
import string
import cssparser

cur_cf = None
cur_hf = None
cur_rcf = None
cur_window_id = None
cur_var_name = None
cur_width = 250
cur_height = 100
xpadding = 15
ypadding = 15
start_group = 0
callbacks = {}

# XXX - These could be folded into a single "cur_cmd_id" list, dict, or class.
cur_menu_id = 1000
cur_button_id = 2000

class CodeGenerationError:
    pass

def get_func_prefix():
    return 'win32'

def cleanup():
    cbkeys = callbacks.keys()
    cbkeys.sort()
    for cb in cbkeys:
	cur_hf.write_body('''
%(comments)svoid %(callback)s (win32_element_t *);\n''' % {
	    'comments': callbacks[cb],
	    'callback': cb
	})
    if cur_cf is not None:
	cur_cf.close()
    if cur_hf is not None:
	cur_hf.close()
    if cur_rcf is not None:
	cur_rcf.close()

#
# CSS property to element struct name conversions
#
padding_trans_tbl = {
    'padding-top'   : 'padding_top',
    'padding-left'  : 'padding_left',
    'padding-bottom': 'padding_bottom',
    'padding-right' : 'padding_right',
}

margin_trans_tbl = {
    'margin-top'   : 'margin_top',
    'margin-left'  : 'margin_left',
    'margin-bottom': 'margin_bottom',
    'margin-right' : 'margin_right',
}

#
# Generate any attribute-specific code, e.g. for "id" or "orient"
#
def get_element_attributes(node):
    default       = get_attribute(node, 'default',       'false')
    disabled      = get_attribute(node, 'disabled',      'false')
    flex          = get_attribute(node, 'flex',          None)
    flexgroup     = get_attribute(node, 'flexgroup',     None)
    el_id         = get_attribute(node, 'id',            None)
    minheight     = get_attribute(node, 'minheight',     None)
    minwidth      = get_attribute(node, 'minwidth',      None)
    orient        = get_attribute(node, 'orient',        None)
    sortdirection = get_attribute(node, 'sortdirection', 'natural')

    onchange  = get_attribute(node, 'onchange',  None)
    oncommand = get_attribute(node, 'oncommand', None)
    oninput   = get_attribute(node, 'oninput',   None)

    # XXX - Should we have a general routine for setting the default element?
    if (default.lower() == 'true'):
	cur_cf.write_body('    SetFocus(cur_el->h_wnd);\n')
    if (disabled.lower() == 'true'):
	cur_cf.write_body('    win32_element_set_disabled(cur_el, TRUE);\n')
    if (flex):
	cur_cf.write_body('    cur_el->flex = %s;\n' % (flex))
    if (flexgroup):
	cur_cf.write_body('    cur_el->flexgroup = %s;\n' % (flexgroup))
    if (el_id):
	cur_cf.write_body('    win32_element_set_id(cur_el, "' +  el_id + '");\n')
    if (minheight):
	cur_cf.write_body('    cur_el->minheight = %s;\n' % (minheight))
    if (minwidth):
	cur_cf.write_body('    cur_el->minwidth = %s;\n' % (minwidth))

    if (onchange):
	if (id is None):
	    raise CodeGenerationError
	cur_cf.write_body('    cur_el->onchange = %s;' % (onchange))
	add_callback(node.nodeName, el_id, onchange)
    if (oncommand):
	if (id is None):
	    raise CodeGenerationError
	cur_cf.write_body('    cur_el->oncommand = %s;' % (oncommand))
	add_callback(node.nodeName, el_id, oncommand)
    if (oninput):
	if (id is None):
	    raise CodeGenerationError
	cur_cf.write_body('    cur_el->oninput = %s;' % (oninput))
	add_callback(node.nodeName, el_id, oninput)

    if (orient):
	if (orient.lower() == 'horizontal'):
	    cur_cf.write_body('    cur_el->orient = BOX_ORIENT_HORIZONTAL;\n')
	elif (orient.lower() == 'vertical'):
	    cur_cf.write_body('    cur_el->orient = BOX_ORIENT_VERTICAL;\n')
	else:
	    raise CodeGenerationError

    if sortdirection.lower() == 'ascending':
	cur_cf.write_body('    cur_el->sortdirection = EL_SORT_ASCENDING;\n')
    elif sortdirection.lower() == 'descending':
	cur_cf.write_body('    cur_el->sortdirection = EL_SORT_DESCENDING;\n')

    get_element_style(node)

#
# Parse out any CSS style information, and generate code accordingly
#
def get_element_style(node):
    pvpairs = cssparser.get_css_attributes(node)

    if pvpairs is None:
	return

    for prop in pvpairs.keys():
	val = pvpairs[prop]

	if prop == 'text-align' and val.lower() in ['left', 'right', 'center', 'justify']:
	    cur_cf.write_body('    cur_el->text_align = CSS_TEXT_ALIGN_%s;\n'
		% val.upper())

	if prop in padding_trans_tbl:
	    if val[-2:] != 'px':
		raise CodeGenerationError
	    cur_cf.write_body('    cur_el->%(prop)s = %(intval)s;\n' % {
		'prop': padding_trans_tbl[prop],
		'intval': val[:-2]
	    })

	if prop in margin_trans_tbl:
	    if val[-2:] != 'px':
		raise CodeGenerationError
	    cur_cf.write_body('    cur_el->%(prop)s = %(intval)s;\n' % {
		'prop': margin_trans_tbl[prop],
		'intval': val[:-2]
	    })

#
# Add a callback function
#
def add_callback(nodename, el_id, cbname):
    comment = '/* Command sent by element type <%(nodename)s>, id "%(id)s" */\n' % {
	'nodename': nodename,
	'id': el_id,
    }

    if callbacks.has_key(cbname):
	callbacks[cbname] = callbacks[cbname] + comment
    else:
	callbacks[cbname] = comment


#
# General element generators
#
# These are called from xulender.py and MUST be named "win32_gen_<element>()"
# or "win32_gen_<element>_end()".
#

#
# <button>
#

def win32_gen_button(node):
    label = get_attribute(node, 'label', '')

    cur_cf.write_body('''
    /* Begin <button> */
    cur_el = win32_button_new(cur_box->h_wnd, "%(label)s");
    win32_box_add(cur_box, cur_el, -1);
''' % {'label': label})

    get_element_attributes(node)

    cur_cf.write_body('    /* End <button> */\n')

#
# <caption>
#
#
def win32_gen_caption(node):
    # Captions MUST be a child of <groupbox>
    # XXX - Move to xulender.py
    if node.parentNode.nodeName != 'groupbox':
	raise CodeGenerationError

    title = ""
    lines = []
    for child in node.childNodes:
	if child.nodeType == node.TEXT_NODE:
	    lines.append(child.data.strip())
	title = string.join(lines, '')
	title = title.replace('\n', '')

    # XXX - Groupboxes under Windows tend to eat various messages.  To
    # work around this, we add an insulating vbox.
    cur_cf.write_body('''
    /* Begin <caption> */
    win32_groupbox_set_title(cur_box, "%(title)s");
    /* End <caption> */
''' % {'title': title})

#
# <checkbox>
#

def win32_gen_checkbox(node):
    label = get_attribute(node, 'label', '')

    cur_cf.write_body('''
    /* Begin <checkbox> */
    cur_el = win32_checkbox_new(cur_box->h_wnd, "%(label)s");
    win32_box_add(cur_box, cur_el, -1);
''' % {'label': label})

    get_element_attributes(node)

    cur_cf.write_body('\n    /* End <checkbox> */\n')

#
# <column>
#
# XXX - We need to verify that we're inside a <grid><columns></columns></grid>
# construct.
#
def win32_gen_column(node):

    flex = float(get_attribute(node, 'flex', '0.0'))
    flexgroup = int(get_attribute(node, 'flexgroup', '0'))
    cur_cf.write_body('''
    /* Begin <column> */
    win32_grid_add_column(cur_box, %(flex)1.1f, %(flexgroup)d);
    /* End <column> */
    ''' % {
	'flex': flex,
	'flexgroup': flexgroup
	})

#
# <deck>
#

def win32_gen_deck(node):
    selectedindex = get_attribute(node, 'selectedindex', None)

    cur_cf.write_body('''
    /* Begin <deck> */
    cur_el = win32_deck_new(cur_box->h_wnd);
    win32_box_add(cur_box, cur_el, -1);
''')

    if selectedindex is not None:
	cur_cf.write_body('    win32_deck_set_selectedindex(cur_el, %s);\n' % (selectedindex))

    get_element_attributes(node)

    cur_cf.write_body('''
    box_stack = g_list_prepend(box_stack, cur_box);
    cur_box = cur_el;
''')

def win32_gen_deck_end(node):
    cur_cf.write_body('''
    box_stack = g_list_first(box_stack);
    cur_box = (win32_element_t *) box_stack->data;
    box_stack = g_list_remove(box_stack, cur_box);
    /* End <deck> */
''')

#
# <description>
#
def win32_gen_description(node):
    text = ""
    lines = []
    for child in node.childNodes:
	if child.nodeType == node.TEXT_NODE:
	    lines.append(child.data.strip())
	text = string.join(lines, '')
	text = text.replace('\n', '')

    cur_cf.write_body('''
    /* Begin <description> */
    cur_el = win32_description_new(cur_box->h_wnd, "%(text)s");
    win32_box_add(cur_box, cur_el, -1);
''' % {'text': text})

    get_element_attributes(node)

    cur_cf.write_body('''
    win32_description_apply_styles(cur_el);
    /* End <description> */
''')


#
# <dialog>
#
# Under the SDK, dialogs are created by feeding a dialog template to
# CreateDialog().  We're using XUL to lay out the controls instead of
# dialog templates.
#
# XXX - How dow we make this modal?
#
def win32_gen_dialog(node):
    global cur_cf, cur_hf, cur_rcf, cur_window_id

    try:
	cur_window_id = node.attributes['id'].value
	cur_var_name = id_to_name(cur_window_id)
    except:
	CodeGenerationError

    cur_width = int(get_attribute(node, 'width', 250))
    cur_height = int(get_attribute(node, 'height', 100))
    title = get_attribute(node, 'title', '[ Untitled - ' + cur_window_id + ' ]')
    header_file_name = cur_window_id + '.h'

    cur_cf = sect_file(cur_window_id + '.c')
    cur_cf.write_body('''
#include "config.h"

#ifdef HAVE_LIBPCAP
#include <pcap.h>
#endif

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>

#include "globals.h"

#include <epan/epan.h>

#include "color.h"

#include "win32-c-sdk.h"
#include "ethereal-win32.h"

#include "%(header_file_name)s"

/* Create dialog "%(cur_window_id)s" */
HWND
%(varname)s_dialog_create (HWND hw_parent) {
    HWND hw_dlg;
    HINSTANCE h_instance = (HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE);

    hw_dlg = CreateDialog (h_instance, "%(varname)s", hw_parent,
	%(varname)s_dlg_proc);

    if (!hw_dlg)
	return NULL;

    return hw_dlg;
}

/* Show dialog "%(cur_window_id)s" */
void
%(varname)s_dialog_show (HWND hw_dlg) {
    win32_element_t *dlg_el = (win32_element_t *) GetWindowLong(hw_dlg, GWL_USERDATA);

    win32_element_assert(dlg_el);

    ShowWindow(hw_dlg, SW_SHOW);
    win32_element_resize(dlg_el, -1, -1);
}

/* Hide dialog "%(cur_window_id)s" */
void
%(varname)s_dialog_hide (HWND hw_dlg) {
    HWND owner = GetWindow(hw_dlg, GW_OWNER);
    EnableWindow(owner, TRUE);
    SetActiveWindow(owner);
    ShowWindow(hw_dlg, SW_HIDE);
}

/* Create the contents of "%(cur_window_id)s".  Should be called from its
 * WNDPROC.
 */
void
%(varname)s_handle_wm_initdialog(HWND hw_dlg) {
    win32_element_t *cur_box;
    win32_element_t *cur_el = NULL;
    GList* box_stack = NULL;

    SendMessage(hw_dlg, WM_SETICON, (WPARAM) ICON_SMALL, (LPARAM) get_ethereal_icon_small(hw_dlg));
    SendMessage(hw_dlg, WM_SETICON, (WPARAM) ICON_BIG, (LPARAM) get_ethereal_icon_large(hw_dlg));

    cur_box = win32_hbox_new(hw_dlg, NULL);
    cur_el  = cur_box;
    win32_element_set_id(cur_box, "%(cur_window_id)s");

''' % {
    'cur_window_id': cur_window_id,
    'header_file_name': header_file_name,
    'height': cur_height,
    'title': title,
    'varname': cur_var_name,
    'width': cur_width,
    })

    get_element_style(node)

    cur_hf = sect_file(header_file_name)

    cur_hf.write_header('''
#ifndef %(define_name)s
#define %(define_name)s
''' % {
    'define_name': id_to_name(cur_window_id).upper() + '_H'
    })

    cur_hf.write_body('''
HWND %(varname)s_dialog_create (HWND hw_parent);
void %(varname)s_dialog_show (HWND);
void %(varname)s_dialog_hide (HWND);
BOOL CALLBACK %(varname)s_dlg_proc(HWND, UINT, WPARAM, LPARAM);
void %(varname)s_handle_wm_initdialog(HWND hw_dlg);

''' % {
    'varname': cur_var_name,
    })

    cur_hf.write_footer('\n\n#endif /* ' + header_file_name + ' */\n')

    cur_rcf = sect_file(cur_window_id + '.rc')

    cur_rcf.write_body('''
%(varname)s DIALOG 6, 21, %(width)d, %(height)d
STYLE DS_MODALFRAME | WS_CAPTION | WS_SYSMENU | DS_SETFOREGROUND | DS_SETFONT
CAPTION "%(title)s"
FONT 8, "MS Shell Dlg"
{

}

''' % {
    'height': cur_height,
    'title': title,
    'varname': cur_var_name,
    'width': cur_width,
    })

def win32_gen_dialog_end(node):
    cur_cf.write_body('\n}\n\n')

#
# <grid>
#

def win32_gen_grid(node):

    cur_cf.write_body('''
    /* Begin <grid> */
    cur_el = win32_grid_new(cur_box->h_wnd);
    win32_box_add(cur_box, cur_el, -1);
''')

    get_element_attributes(node)

    cur_cf.write_body('''
    box_stack = g_list_prepend(box_stack, cur_box);
    cur_box = cur_el;
''')

def win32_gen_grid_end(node):
    cur_cf.write_body('''
    box_stack = g_list_first(box_stack);
    cur_box = (win32_element_t *) box_stack->data;
    box_stack = g_list_remove(box_stack, cur_box);
    /* End <grid> */
''')

#
# <groupbox>
#

def win32_gen_groupbox(node):

    cur_cf.write_body('''
    /* Begin <groupbox> */
    cur_el = win32_groupbox_new(cur_box->h_wnd);
    win32_box_add(cur_box, cur_el, -1);
''')

    get_element_attributes(node)

    cur_cf.write_body('''
    box_stack = g_list_prepend(box_stack, cur_box);
    cur_box = cur_el;
''')

def win32_gen_groupbox_end(node):
    cur_cf.write_body('''
    box_stack = g_list_first(box_stack);
    cur_box = (win32_element_t *) box_stack->data;
    box_stack = g_list_remove(box_stack, cur_box);
    /* End <groupbox> */
''')

#
# <hbox>
#

def win32_gen_hbox(node):

    cur_cf.write_body('''
    /* Begin <hbox> */
    cur_el = win32_hbox_new(NULL, cur_box->h_wnd);
    win32_box_add(cur_box, cur_el, -1);
''')

    get_element_attributes(node)

    cur_cf.write_body('''
    box_stack = g_list_prepend(box_stack, cur_box);
    cur_box = cur_el;
''')

def win32_gen_hbox_end(node):
    cur_cf.write_body('''
    box_stack = g_list_first(box_stack);
    cur_box = (win32_element_t *) box_stack->data;
    box_stack = g_list_remove(box_stack, cur_box);
    /* End <hbox> */
''')

#
# <listbox>
#

def win32_gen_listbox(node):
    show_header   = 'FALSE'
    onselect      = get_attribute(node, 'onselect')
    ondoubleclick = get_attribute(node, 'ondoubleclick')
    el_id         = get_attribute(node, 'id')

    for child in node.childNodes:
	if child.nodeName == 'listhead':
	    show_header = 'TRUE'

    cur_cf.write_body('''
    /* Begin <listbox> */
    cur_el = win32_listbox_new(cur_box->h_wnd, %(show_header)s);
    win32_box_add(cur_box, cur_el, -1);
''' % {
    'show_header': show_header
    })

    get_element_attributes(node)

    if (onselect):
	if el_id is None:
	    raise CodeGenerationError
	cur_cf.write_body('    win32_listbox_set_onselect(cur_el, %s);' % (onselect))
	cur_hf.write_body('''
/* Command sent by <listbox> id "%(id)s" */
void %(onselect)s (win32_element_t *, LPNMLISTVIEW);
'''	% {
	    'id': el_id,
	    'onselect': onselect,
	})

    if (ondoubleclick):
	if el_id is None:
	    raise CodeGenerationError
	cur_cf.write_body('    win32_listbox_set_ondoubleclick(cur_el, %s);' % (ondoubleclick))
	cur_hf.write_body('''
/* Command sent by <listbox> id "%(id)s" */
void %(ondoubleclick)s (win32_element_t *, LPNMLISTVIEW);
'''	% {
	    'id': el_id,
	    'ondoubleclick': ondoubleclick,
	})

def win32_gen_listbox_end(node):
    cur_cf.write_body('''
    win32_listbox_minimum_size(cur_el);
    /* End <listbox> */
''')


#
# <listcell>
#

def win32_gen_listcell(node):
    # <listcell> MUST be a child of <listitem>
    # XXX - Move to xulender.py
    if node.parentNode.nodeName != 'listitem':
	raise CodeGenerationError

    label = get_attribute(node, 'label', '')
    el_id = get_attribute(node, 'id', '')

    cur_cf.write_body('''
    /* Begin <listcell> */
    win32_listbox_add_cell(cur_el, "%(id)s", "%(label)s");
''' % {
    'id': el_id,
    'label': label,
    })

#
# <listcol>
#

def win32_gen_listcol(node):
    # <listcol> MUST be a child of <listcols>
    # XXX - Move to xulender.py
    if node.parentNode.nodeName != 'listcols':
	raise CodeGenerationError

    col_id = get_attribute(node, 'id', 'NULL')
    if col_id != 'NULL':
	col_id = '"' + col_id + '"'

    cur_cf.write_body('''
    /* Begin <listcol> */
    win32_listbox_add_column(cur_el, %(id)s, NULL);
''' % {
    'id': col_id,
    })

#
# <listheader>
#

def win32_gen_listheader(node):
    # <listheader> MUST be a child of <listhead>
    # XXX - Move to xulender.py
    if node.parentNode.nodeName != 'listhead':
	raise CodeGenerationError

    col_id = get_attribute(node, 'id', 'NULL')
    if col_id != 'NULL':
	col_id = '"' + col_id + '"'
    label = get_attribute(node, 'label', '')

    cur_cf.write_body('''
    /* Begin <listheader> */
    win32_listbox_add_column(cur_el, %(id)s, "%(label)s");
''' % {
    'id': col_id,
    'label': label,
    })

#
# <menu>
#

def win32_gen_menu(node):
    label = get_attribute(node, 'label', '[ No Label ]')

    cur_rcf.write_body('  Popup "&%(label)s" {\n' % { 'label': label } )

def win32_gen_menu_end(node):
    cur_rcf.write_body('  }\n')

#
# <menubar>
#

def win32_gen_menubar(node):
    mbid = cur_window_id.upper() + '_MENU'
    for ch in [' ', '-']: mbid = mbid.replace(ch, '_')

    cur_rcf.write_body('%(mbid)s MENU {\n' % {'mbid': mbid})

def win32_gen_menubar_end(node):
    cur_rcf.write_body('}\n\n')

#
# <menuitem>
#

def win32_gen_menuitem(node):
    # Menuitems MUST be a child of <menupopup>
    # XXX - Move to xulender.py
    if node.parentNode.nodeName != 'menupopup':
	raise CodeGenerationError

    global cur_menu_id

    label = get_attribute(node, 'label', '[ No Label ]')
    command = get_attribute(node, 'command', None)
    selected = get_attribute(node, 'selected', 'false')

    if node.parentNode.parentNode.nodeName == 'menu':
	if command is None:
	    raise CodeGenerationError

	id = 'IDM_' + command.upper()
	for ch in [' ', '-', '.']: id = id.replace(ch, '_')

	cur_rcf.write_body('    MENUITEM "&%(label)s", %(id)s\n' % {
	    'id': id,
	    'label': label
	    })

	cur_hf.write_body('#define %(id)s %(cur_menu_id)d\n' % {
	    'cur_menu_id': cur_menu_id,
	    'id': id,
	    })
	cur_menu_id = cur_menu_id + 1
    elif node.parentNode.parentNode.nodeName == 'menulist':
	if selected.lower() == 'true':
	    selected = 'TRUE'
	else:
	    selected = 'FALSE'
	cur_cf.write_body('    win32_menulist_add(cur_el, "%(label)s", %(selected)s);\n' % {
	    'label': label,
	    'selected': selected,
	    })

#
# <menulist>
#

def win32_gen_menulist(node):
    editable = get_attribute(node, 'editable', 'FALSE')
    if editable.lower() == 'true':
	editable = 'TRUE'

    cur_cf.write_body('''
    /* Begin <menulist> */
    cur_el = win32_menulist_new(cur_box->h_wnd, %(editable)s);
    win32_box_add(cur_box, cur_el, -1);
''' % { 'editable': editable })

    get_element_attributes(node)

def win32_gen_menulist_end(node):
    cur_cf.write_body('    /* End <menulist> */\n')

#
# <menuseparator>
#

def win32_gen_menuseparator(node):
    # XXX - Move to xulender.py
    if node.parentNode.nodeName != 'menupopup':
	raise CodeGenerationError
    if node.parentNode.parentNode.nodeName != 'menu':
	raise CodeGenerationError

    cur_rcf.write_body('    MENUITEM SEPARATOR\n')

#
# <progressmeter>
#

def win32_gen_progressmeter(node):

    cur_cf.write_body('''
    /* Begin <progressmeter> */
    cur_el = win32_progressmeter_new(cur_box->h_wnd);
    win32_box_add(cur_box, cur_el, -1);
''')

    get_element_attributes(node)

    cur_cf.write_body('    /* End <progressmeter> */\n')

#
# <radio>
#

def win32_gen_radio(node):
    global start_group

    label = get_attribute(node, 'label', '')

    cur_cf.write_body('''
    /* Begin <radio> */
    cur_el = win32_radio_new(cur_box->h_wnd, "%(label)s", %(start_group)d);
    win32_box_add(cur_box, cur_el, -1);
''' % {
	'label': label,
	'start_group': start_group
    })

    get_element_attributes(node)
    start_group = 0

    cur_cf.write_body('    /* End <radio> */\n')

#
# <radiogroup>
#
# XXX - Should this be its own full-fledged element instead of a vbox?
#
def win32_gen_radiogroup(node):
    global start_group
    start_group = 1

    cur_cf.write_body('''
    /* Begin <radiogroup> */
    cur_el = win32_vbox_new(NULL, cur_box->h_wnd);
    win32_box_add(cur_box, cur_el, -1);
''')

    get_element_attributes(node)

    cur_cf.write_body('''
    box_stack = g_list_prepend(box_stack, cur_box);
    cur_box = cur_el;
''')

def win32_gen_radiogroup_end(node):
    cur_cf.write_body('''
    box_stack = g_list_first(box_stack);
    cur_box = (win32_element_t *) box_stack->data;
    box_stack = g_list_remove(box_stack, cur_box);
    /* End <radiogroup> */
''')


#
# <row>
#
# XXX - We need to verify that we're inside a <grid><rows></rows></grid>
# construct.
#
def win32_gen_row(node):

    flex = float(get_attribute(node, 'flex', '0.0'))
    flexgroup = int(get_attribute(node, 'flexgroup', '0'))
    cur_cf.write_body('''
    /* Begin <row> */
    win32_grid_add_row(cur_box, %(flex)1.1f, %(flexgroup)d);
    /* End <row> */
''' % {
	'flex': flex,
	'flexgroup': flexgroup
	})

#
# <spacer>
#
def win32_gen_spacer(node):

    cur_cf.write_body('''
    /* Begin <spacer> */
    cur_el = win32_spacer_new(cur_box->h_wnd);
    win32_box_add(cur_box, cur_el, -1);
''')

    get_element_attributes(node)

    cur_cf.write_body('    /* End <spacer> */\n')

#
# <splitter>
#

def win32_gen_splitter(node):
    cur_cf.write_body('''
    /* Begin <splitter> */
    cur_el = win32_box_add_splitter(cur_box, -1, cur_box->orient);
''')
    get_element_attributes(node)

    cur_cf.write_body('''
    /* End <splitter> */
''')


#
# <statusbar>
# Which is really an <hbox>.
# XXX - Do we need to force the contents to a particular set of elements,
#       e.g. <statusbarpanel>s and <splitter>s?
#

def win32_gen_statusbar(node):

    cur_cf.write_body('''
    /* Begin <statusbar> */
    cur_el = win32_hbox_new(NULL, cur_box->h_wnd);
    win32_box_add(cur_box, cur_el, -1);
''')

    get_element_attributes(node)

    cur_cf.write_body('''
    box_stack = g_list_prepend(box_stack, cur_box);
    cur_box = cur_el;
''')

def win32_gen_statusbar_end(node):
    cur_cf.write_body('''
    box_stack = g_list_first(box_stack);
    cur_box = (win32_element_t *) box_stack->data;
    box_stack = g_list_remove(box_stack, cur_box);
    /* End <statusbar> */
''')

#
# <statusbarpanel>
#
def win32_gen_statusbarpanel(node):
    text = ""
    lines = []
    for child in node.childNodes:
	if child.nodeType == node.TEXT_NODE:
	    lines.append(child.data.strip())
	text = string.join(lines, '')
	text = text.replace('\n', '')

    cur_cf.write_body('''
    /* Begin <statusbarpanel> */
    cur_el = win32_statusbarpanel_new(cur_box->h_wnd, "%(text)s");
    win32_box_add(cur_box, cur_el, -1);
''' % {'text': text})

    get_element_attributes(node)

    cur_cf.write_body('''
    win32_statusbarpanel_apply_styles(cur_el);
    /* End <statusbarpanel> */
''')


#
# <textbox>
#

def win32_gen_textbox(node):
    value = get_attribute(node, 'value', None)
    rows = get_attribute(node, 'rows', None)
    multiline = get_attribute(node, 'multiline', 'FALSE');

    if multiline.lower() == 'true':
	multiline = 'TRUE'

    cur_cf.write_body('''
    /* Begin <textbox> */
    cur_el = win32_textbox_new(cur_box->h_wnd, %s);
    win32_box_add(cur_box, cur_el, -1);
''' % (multiline))

    get_element_attributes(node)

    if value is not None:
	cur_cf.write_body('    win32_textbox_set_text(cur_el, "%s");\n' % (value))
    if rows is not None:
	cur_cf.write_body('    win32_textbox_set_row_count(cur_el, %s);\n' % (rows))
# XXX - Add multiline, onchange, oninput, other textbox-specific attributes

    cur_cf.write_body('    /* End <textbox> */\n')

#
# <toolbar>
#
def win32_gen_toolbar(node):
    # <toolbar>s MUST be a child of <toolbox>
    # XXX - Move to xulender.py
    if node.parentNode.nodeName != 'toolbox':
	raise CodeGenerationError

    cur_cf.write_body('''
    /* Begin <toolbar> */
    cur_el = win32_toolbar_new(cur_box->h_wnd);
    win32_box_add(cur_box, cur_el, -1);
''')

    get_element_attributes(node)

def win32_gen_toolbar_end(node):
    cur_cf.write_body('''
    SendMessage(cur_el->h_wnd, TB_AUTOSIZE, 0, 0);
    /* End <toolbar> */
''')

#
# <toolbarbutton>
#
def win32_gen_toolbarbutton(node):
    # <toolbarbutton>s MUST be a child of <toolbar>
    # XXX - Move to xulender.py
    if node.parentNode.nodeName != 'toolbar':
	raise CodeGenerationError

    global cur_button_id

    command = get_attribute(node, 'command', None)
    if command is None:
	raise CodeGenerationError

    label = get_attribute(node, 'label', 'NULL')
    if label != 'NULL':
	label = '"' + label + '"'

    id = 'IDB_' + command.upper()
    for ch in [' ', '-', '.']: id = id.replace(ch, '_')

    cur_hf.write_body('#define %(id)s %(cur_button_id)d\n' % {
	'cur_button_id': cur_button_id,
	'id': id,
	})
    cur_button_id = cur_button_id + 1


    cur_cf.write_body('''
    /* Begin <toolbarbutton> */
    win32_toolbar_add_button(cur_el, %(id)s, %(label)s);
    /* End <toolbarbutton> */
''' % {
	'id': id,
	'label': label
    })

#
# <toolbarseparator>
#
def win32_gen_toolbarseparator(node):
    # <toolbarbutton>s MUST be a child of <toolbar>
    # XXX - Move to xulender.py
    if node.parentNode.nodeName != 'toolbar':
	raise CodeGenerationError

    cur_cf.write_body('''
    /* Begin <toolbarseparator> */
    win32_toolbar_add_separator(cur_el);
    /* End <toolbarseparator> */
''')


#
# <toolbox>
#

def win32_gen_toolbox(node):

    cur_cf.write_body('''
    /* Begin <toolbox> */
    cur_el = win32_toolbox_new(NULL, cur_box->h_wnd);
    win32_box_add(cur_box, cur_el, -1);
''')

    get_element_attributes(node)

    cur_cf.write_body('''
    box_stack = g_list_prepend(box_stack, cur_box);
    cur_box = cur_el;
''')

def win32_gen_toolbox_end(node):
    cur_cf.write_body('''
    box_stack = g_list_first(box_stack);
    cur_box = (win32_element_t *) box_stack->data;
    box_stack = g_list_remove(box_stack, cur_box);
    /* End <toolbox> */
''')



#
# <tree>
#

def win32_gen_tree(node):
    onselect = get_attribute(node, 'onselect')
    el_id = get_attribute(node, 'id')

    cur_cf.write_body('''
    /* Begin <tree> */
    cur_el = win32_tree_new(cur_box->h_wnd);
    win32_box_add(cur_box, cur_el, -1);
''')

    get_element_attributes(node)

    if (onselect):
	if el_id is None:
	    raise CodeGenerationError
	cur_cf.write_body('    win32_tree_set_onselect(cur_el, %s);' % (onselect))
	# XXX - Add to the callback mechanism
	cur_hf.write_body('''
/* Command sent by <tree> id "%(id)s" */
void %(onselect)s (win32_element_t *, NMTREEVIEW *);
'''	% {
	    'id': el_id,
	    'onselect': onselect,
	})

def win32_gen_tree_end(node):
    cur_cf.write_body('''
    win32_tree_minimum_size(cur_el);
    /* End <tree> */
''')

#
# <treecell>
#

def win32_gen_treecell(node):
    # <treecell>s MUST be a child of <treerow>
    # XXX - Move to xulender.py
    if node.parentNode.nodeName != 'treerow':
	raise CodeGenerationError

    label = get_attribute(node, 'label', '')
    el_id = get_attribute(node, 'id', '')

    cur_cf.write_body('''
    /* Begin <treecell> */
    win32_tree_add_cell(cur_el, "%(id)s", "%(label)s");
''' % {
    'id': el_id,
    'label': label,
    })

#
# <treecol>
#

def win32_gen_treecol(node):
    # <treecol>s MUST be a child of <treecols>
    # XXX - Move to xulender.py
    if node.parentNode.nodeName != 'treecols':
	raise CodeGenerationError

    col_id = get_attribute(node, 'id', '')
    label = get_attribute(node, 'label', '')
    primary = get_attribute(node, 'primary', 'FALSE')
    if primary.lower() == 'true':
	primary = 'TRUE'
    hideheader = get_attribute(node, 'hideheader', 'FALSE')
    if hideheader.lower() == 'true':
	hideheader = 'TRUE'

    cur_cf.write_body('''
    /* Begin <treecol> */
    win32_tree_add_column(cur_el, "%(id)s", "%(label)s", %(primary)s, %(hideheader)s);
''' % {
    'id': col_id,
    'label': label,
    'primary': primary,
    'hideheader': hideheader,
    })

#
# <treeitem>
#

def win32_gen_treeitem(node):
    # <treeitem>s MUST be a child of <treechildren>
    # XXX - Move to xulender.py
    if node.parentNode.nodeName != 'treechildren':
	raise CodeGenerationError

    is_open = get_attribute(node, 'open', 'FALSE')

    cur_cf.write_body('''
    /* Begin <treeitem> */
    win32_tree_push(cur_el);
''')

    if is_open.lower() == 'true':
	cur_cf.write_body('    win32_tree_flag_open_item(cur_el);\n')

def win32_gen_treeitem_end(node):
    cur_cf.write_body('''
    win32_tree_pop(cur_el);
    /* End <treeitem> */
''')

#
# <treerow>
#

def win32_gen_treerow(node):
    # <treerow>s MUST be a child of <treeitem>
    # XXX - Move to xulender.py
    if node.parentNode.nodeName != 'treeitem':
	raise CodeGenerationError

    el_id = get_attribute(node, 'id', '')

    cur_cf.write_body('''
    /* Begin <treerow> */
    win32_tree_add_row(cur_el, "%(id)s");
''' % {
    'id': el_id
    })

#
# <vbox>
#

def win32_gen_vbox(node):

    cur_cf.write_body('''
    /* Begin <vbox> */
    cur_el = win32_vbox_new(NULL, cur_box->h_wnd);
    win32_box_add(cur_box, cur_el, -1);
''')

    get_element_attributes(node)

    cur_cf.write_body('''
    box_stack = g_list_prepend(box_stack, cur_box);
    cur_box = cur_el;
''')

def win32_gen_vbox_end(node):
    cur_cf.write_body('''
    box_stack = g_list_first(box_stack);
    cur_box = (win32_element_t *) box_stack->data;
    box_stack = g_list_remove(box_stack, cur_box);
    /* End <vbox> */
''')

#
# <window>
#

#
# Contained elements are added to the WM_CREATE notify function.
#
# XXX - We need a way to automagically pick up a list of the types of
# widgets we use, and #include them.
#
# XXX - Fix #include order to fix va_start/_end redefinition errors.
#
def win32_gen_window(node):
    global cur_cf, cur_hf, cur_rcf, cur_window_id

    try:
	cur_window_id = node.attributes['id'].value
	cur_var_name = id_to_name(cur_window_id)
    except:
	CodeGenerationError

    cur_width = int(get_attribute(node, 'width', 250))
    cur_height = int(get_attribute(node, 'height', 100))
    title = get_attribute(node, 'title', '[ Untitled - ' + cur_window_id + ' ]')
    id = get_attribute(node, 'id', None)
    header_file_name = cur_window_id + '.h'

    cur_cf = sect_file(cur_window_id + '.c')
    cur_cf.write_body('''
#include "config.h"

#ifdef HAVE_LIBPCAP
#include <pcap.h>
#endif

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>

#include "globals.h"

#include <epan/epan.h>

#include "win32-c-sdk.h"
#include "ethereal-win32.h"

#include "%(header_file_name)s"

/* Create window "%(cur_window_id)s"*/
HWND
%(varname)s_window_create (HINSTANCE h_instance) {
    HWND  h_wnd;

    /* Register main window class if this is the first instance of the app. */
    /* if (!hPrevInstance)
	if (!MenuInit (hInstance))
	    return 0; */

    h_wnd = CreateWindow ("%(varname)s", "%(title)s",
	WS_OVERLAPPEDWINDOW,
	CW_USEDEFAULT, CW_USEDEFAULT, %(width)d, %(height)d,
	(HWND) NULL, NULL, h_instance, (LPSTR) NULL);

    if (!h_wnd)
	return NULL;

    return h_wnd;
}

void
%(varname)s_window_show(HWND h_wnd, int n_cmd_show) {
    ShowWindow (h_wnd, n_cmd_show);
    UpdateWindow (h_wnd);
}

/* Resize the contents of "%(cur_window_id)s".  Should be called from its
 * WNDPROC.
 */
void
%(varname)s_handle_wm_size(HWND hwnd, int width, int height) {
    win32_element_t *hw_hbox;

    hw_hbox = (win32_element_t *) GetWindowLong(hwnd, GWL_USERDATA);
    win32_element_assert (hw_hbox);

    win32_element_resize(hw_hbox, width, height);
}

/*
 * Create the contents of "%(cur_window_id)s".  Should be called from its
 * WNDPROC.
 */
void
%(varname)s_handle_wm_create(HWND hw_win) {
    win32_element_t *win_hbox, *cur_box = NULL;
    win32_element_t *cur_el = NULL;
    GList* box_stack = NULL;

    SendMessage(hw_win, WM_SETICON, (WPARAM) ICON_SMALL, (LPARAM) get_ethereal_icon_small(hw_win));
    SendMessage(hw_win, WM_SETICON, (WPARAM) ICON_BIG, (LPARAM) get_ethereal_icon_large(hw_win));

    win_hbox = win32_hbox_new(hw_win, NULL);
    cur_box = win_hbox;
    win32_element_set_id(cur_box, "%(cur_window_id)s");

''' % {
    'cur_window_id': cur_window_id,
    'header_file_name': header_file_name,
    'height': cur_height,
    'title': title,
    'varname': cur_var_name,
    'width': cur_width,
    })

    cur_hf = sect_file(header_file_name)

    cur_hf.write_header('''
#ifndef %(define_name)s
#define %(define_name)s
''' % {
    'define_name': id_to_name(cur_window_id).upper() + '_H'
    })

    cur_hf.write_body('''
HWND %(varname)s_window_create (HINSTANCE h_instance);
void %(varname)s_handle_wm_size(HWND hw_win, int width, int height);
void %(varname)s_handle_wm_create(HWND hw_win);
void %(varname)s_window_show(HWND h_wnd, int n_cmd_show);
void %(varname)s_window_hide(HWND h_wnd, int n_cmd_show);

''' % {
    'varname': cur_var_name,
    })

    cur_hf.write_footer('\n\n#endif /* ' + header_file_name + ' */\n')

    cur_rcf = sect_file(cur_window_id + '.rc')
    cur_rcf.write_header('''
#include "%(header_file_name)s"
''' % {'header_file_name': header_file_name } )

def win32_gen_window_end(node):
    cur_cf.write_body('''
    /* Set our initial size */
    win32_element_resize(win_hbox,
    win32_element_get_width(win_hbox),
    win32_element_get_height(win_hbox));
    /* End <window> */
}

''')

#
# Ethereal-specific element generators
# XXX - These should be in their own module.
#

#
# <ethereal:byteview>
#

def win32_gen_ethereal_byteview(node):

    cur_cf.write_body('''
    /* Begin <ethereal:byteview> */
    cur_el = ethereal_byteview_new(cur_box->h_wnd);
    win32_box_add(cur_box, cur_el, -1);
''')

    get_element_attributes(node)

    cur_cf.write_body('''
    /* End <ethereal:byteview> */
    ''')

#
# <ethereal:combobox>
#
# XXX - The XUL Planet element reference at
#
#   http://www.xulplanet.com/references/elemref/
#
# doesn't define a "combobox" element.  However, the Luxor XUL project
# does in the form of a "choice" elment:
#
#   http://luxor-xul.sourceforge.net/xulref/tag-choice.html
#
# We define a combobox in the Ethereal namespace.  Should we use "choice"
# instead?
#

def win32_gen_ethereal_combobox(node):

    cur_cf.write_body('''
    /* Begin <ethereal:combobox> */
    cur_el = ethereal_combobox_new(cur_box->h_wnd);
    win32_box_add(cur_box, cur_el, -1);
''')

    get_element_attributes(node)

    cur_cf.write_body('''
    /* End <ethereal:combobox> */
    ''')

#
# <ethereal:packetlist>
#

def win32_gen_ethereal_packetlist(node):

    cur_cf.write_body('''
    /* Begin <ethereal:packetlist> */
    cur_el = ethereal_packetlist_new(cur_box->h_wnd);
    win32_box_add(cur_box, cur_el, -1);
''')

    get_element_attributes(node)

    cur_cf.write_body('''
    /* End <ethereal:packetlist> */
    ''')

#
# <ethereal:spinner>
#

def win32_gen_ethereal_spinner(node):

    cur_cf.write_body('''
    /* Begin <spinner> */
    cur_el = ethereal_spinner_new(cur_box->h_wnd);
    win32_box_add(cur_box, cur_el, -1);
''')

    get_element_attributes(node)

    cur_cf.write_body('    /* End <spinner> */\n')

#
# <ethereal:treeview>
#

def win32_gen_ethereal_treeview(node):

    cur_cf.write_body('''
    /* Begin <ethereal:treeview> */
    cur_el = ethereal_treeview_new(cur_box->h_wnd);
    win32_box_add(cur_box, cur_el, -1);
    ''')

    get_element_attributes(node)

    cur_cf.write_body('    /* End <ethereal:treeview> */\n')
