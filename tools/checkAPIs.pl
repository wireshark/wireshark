#!/usr/bin/env perl

#
# Copyright 2006, Jeff Morriss <jeff.morriss[AT]ulticom.com>
#
# A simple tool to check source code for function calls that should not
# be called by Wireshark code and to perform certain other checks.
#
# Usage:
# checkAPIs.pl [-M] [-g group1] [-g group2] [-s summary-group1] [-s summary-group2] [--nocheck-value-string-array-null-termination] file1 file2 ...
#
# $Id$
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#

use strict;
use Getopt::Long;

my %APIs = (
	# API groups.
	# Group name, e.g. 'prohibited'
	# '<name>' => {
	#   'count_errors'	=> 1,			  # 1 if these are errors, 0 if warnings
	#   'functions'		=> [ 'f1', 'f2', ...],    # Function array
	#   'function-counts'	=> {'f1',0, 'f2',0, ...}, # Function Counts hash (initialized in the code)
	# }
	#
	# APIs that MUST NOT be used in Wireshark
	'prohibited' => { 'count_errors' => 1, 'functions' => [
		# Memory-unsafe APIs
		# Use something that won't overwrite the end of your buffer instead
		# of these:
		'gets',
		'sprintf',
		'g_sprintf',
		'vsprintf',
		'g_vsprintf',
		'strcpy',
		'strncpy',
		'strcat',
		'strncat',
		'cftime',
		'ascftime',
		### non-portable APIs
		# use glib (g_*) versions instead of these:
		'ntohl',
		'ntohs',
		'htonl',
		'htons',
		'strdup',
		'strndup',
		# Windows doesn't have this; use g_ascii_strtoull() instead
		'strtoull',
		### non-ANSI C
		# use memset, memcpy, memcmp instead of these:
		'bzero',
		'bcopy',
		'bcmp',
		# use ep_*, se_*, or g_* functions instead of these:
		# (One thing to be aware of is that space allocated with malloc()
		# may not be freeable--at least on Windows--with g_free() and
		# vice-versa.)
		'malloc',
		'calloc',
		'realloc',
		'valloc',
		'free',
		'cfree',
		# Locale-unsafe APIs
		# These may have unexpected behaviors in some locales (e.g.,
		# "I" isn't always the upper-case form of "i", and "i" isn't
		# always the lower-case form of "I").  Use the g_ascii_* version
		# instead.
		'strcasecmp',
		'strncasecmp',
		'g_strcasecmp',
		'g_strncasecmp',
		'g_strup',
		'g_strdown',
		'g_string_up',
		'g_string_down',
		'strerror',	# use g_strerror
		# Use the ws_* version of these:
		# (Necessary because on Windows we use UTF8 for throughout the code
		# so we must tweak that to UTF16 before operating on the file.  Code
		# using these functions will work unless the file/path name contains
		# non-ASCII chars.)
		'open',
		'rename',
		'mkdir',
		'stat',
		'unlink',
		'remove',
		'fopen',
		'freopen',
		# Misc
		'tmpnam'	# use mkstemp
		] },

	# APIs that SHOULD NOT be used in Wireshark (any more)
	'deprecated' => { 'count_errors' => 1, 'functions' => [
		'perror',					# Use g_strerror() and report messages in whatever
								#  fashion is appropriate for the code in question.
		'ctime',					# Use abs_time_secs_to_str()
		'dissector_add',				# Use dissector_add_uint()
		'dissector_change',				# Use dissector_change_uint()
		'dissector_delete',				# Use dissector_delete_uint()
		'dissector_get_port_handle',			# Use dissector_get_uint_handle()
		'dissector_reset',				# Use dissector_reset_uint()
		'dissector_try_port',				# Use dissector_try_uint()
		'dissector_try_port_new',			# Use dissector_try_uint_new()
		'next_tvb_add_port',				# Use next_tvb_add_uint() (and a matching change
								#  of NTVB_PORT -> NTVB_UINT)

		### Deprecated GLib/GObject functions/macros
		# (The list is based upon the GLib 2.24.1 & GObject 2.24.1 documentation;
		#  Some of the entries are commented out since they are currently
		#  being used in Wireshark and since the replacement functionality
		#  is not available in all the GLib versions that Wireshark
		#  currently supports (ie: versions starting with GLib 2.4)).
		'G_ALLOC_AND_FREE',
		'G_ALLOC_ONLY',
		'g_allocator_free',				# "use slice allocator" (avail since 2.10,2.14)
		'g_allocator_new',				# "use slice allocator" (avail since 2.10,2.14)
		'g_async_queue_ref_unlocked',			# g_async_queue_ref()   (OK since 2.8)
		'g_async_queue_unref_and_unlock',		# g_async_queue_unref() (OK since 2.8)
		'g_basename',
		'g_cache_value_foreach',			# g_cache_key_foreach()
		'g_date_set_time',				# g_date_set_time_t (avail since 2.10)
		'g_dirname',
		'G_GNUC_FUNCTION',
		'G_GNUC_PRETTY_FUNCTION',
		'g_hash_table_freeze',
		'g_hash_table_thaw',
		'G_HAVE_GINT64',
		'g_io_channel_close',
		'g_io_channel_read',
		'g_io_channel_seek',
		'g_io_channel_write',
		'g_list_pop_allocator',				# "does nothing since 2.10"
		'g_list_push_allocator',			# "does nothing since 2.10"
		'g_main_destroy',
		'g_main_is_running',
		'g_main_iteration',
		'g_main_new',
		'g_main_pending',
		'g_main_quit',
		'g_main_run',
		'g_main_set_poll_func',
		'g_node_pop_allocator',				# "does nothing since 2.10"
		'g_node_push_allocator',			# "does nothing since 2.10"
		'g_scanner_add_symbol',
		'g_scanner_remove_symbol',
		'g_scanner_foreach_symbol',
		'g_scanner_freeze_symbol_table',
		'g_scanner_thaw_symbol_table',
		'g_slist_pop_allocator',			# "does nothing since 2.10"
		'g_slist_push_allocator',			# "does nothing since 2.10"
		'g_string_sprintf',				# use g_string_printf() instead
		'g_string_sprintfa',				# use g_string_append_printf instead
		'g_tree_traverse',
		'g_value_set_boxed_take_ownership',
		'g_value_set_object_take_ownership',
		'g_value_set_param_take_ownership',
		'g_value_set_string_take_ownership',
		'G_WIN32_DLLMAIN_FOR_DLL_NAME',
		'g_win32_get_package_installation_directory',
		'g_win32_get_package_installation_subdirectory',
##
## Following Deprecated as of GLib 2.10; to be replaced only when Wireshark requires GLib 2.10 or later
## Note: Only the commented out items are currently used by Wireshark
### GMemChunks should used *only* with GLib < 2.10.
###  There's an issue wherein GLib >= 2.10 g_mem_chunk_destroy doesn't actually free memory thus
###   leading to memory leaks.
###  So: either replace GMemChunk use with something else altogether
###      or use GMemChunks for GLib < 2.10 and GSlice (or whatever) for newer GLibs.
## 2.10		'g_mem_chunk_alloc',				# "use slice allocator" (avail since 2.10)
## 2.10		'g_mem_chunk_alloc0',				# "use slice allocator" (avail since 2.10)
			'g_mem_chunk_clean',				# "use slice allocator" (avail since 2.10)
## 2.10		'g_mem_chunk_create',				# "use slice allocator" (avail since 2.10)
## 2.10		'g_mem_chunk_destroy',				# "use slice allocator" (avail since 2.10)
## 2.10		'g_mem_chunk_free',					# "use slice allocator" (avail since 2.10)
			'g_mem_chunk_info',					# "use slice allocator" (avail since 2.10)
## 2.10		'g_mem_chunk_new',					# "use slice allocator" (avail since 2.10)
			'g_mem_chunk_print',				# "use slice allocator" (avail since 2.10)
			'g_mem_chunk_reset',				# "use slice allocator" (avail since 2.10)
			'g_blow_chunks',					# "use slice allocator" (avail since 2.10,2.14)
## 2.10		'g_chunk_free',						# g_slice_free (avail since 2.10)
## 2.10		'g_chunk_new',						# g_slice_new  (avail since 2.10)
			'g_chunk_new0',						# g_slice_new0 (avail since 2.10)
###
## Following Deprecated as of GLib 2.22;
## Note: Not currently used by Wireshark
		'g_mapped_file_free',				# [as of 2.22: use g_map_file_unref]
		] },

	# APIs that make the program exit. Dissectors shouldn't call these
	'abort' => { 'count_errors' => 1, 'functions' => [
		'abort',
		'assert',
		'assert_perror',
		'exit',
		'g_assert',
		'g_error',
		] },

	# APIs that print to the terminal. Dissectors shouldn't call these
	'termoutput' => { 'count_errors' => 0, 'functions' => [
		'printf',
		'g_warning',
		] },

	# Deprecated GTK APIs
	#  which SHOULD NOT be used in Wireshark (any more).
	#  (Filled in from 'E' entries in %deprecatedGtkFunctions below)
	'deprecated-gtk' => { 'count_errors' => 1, 'functions' => [
		] },

	# Deprecated GTK APIs yet to be replaced
	#  (Filled in from 'W' entries in %deprecatedGtkFunctions below)
	'deprecated-gtk-todo' => { 'count_errors' => 0, 'functions' => [
		] },

);

# Deprecated GTK+ functions/macros with (E)rror or (W)arning flag:
# (The list is based upon the GTK+ 2.20.1 documentation; Some of
#  the entries are commented out since they are currently
#  being used in Wireshark and since the replacement functionality
#  is not available in all the GTK+ versions that Wireshark
#  currently supports (ie: versions starting with GTK+ 2.4).
# E: There should be no current Wireshark use so Error if seen;
# W: Not all Wireshark use yet fixed so Warn if seen; (Change to E as fixed)
my %deprecatedGtkFunctions = (
		'gtk_about_dialog_get_name',			'E',
		'gtk_about_dialog_set_name',			'E',
		'gtk_accel_group_ref',					'E',
		'gtk_accel_group_unref',				'E',
		'gtk_action_block_activate_from',		'E', # since 2.16
		'gtk_action_connect_proxy',				'E', # since 2.16: use gtk_activatable_set_related_action() (as of 2.16)
		'gtk_action_disconnect_proxy',			'E', # since 2.16: use gtk_activatable_set_related_action() (as of 2.16)
		'gtk_action_unblock_activate_from',		'E', # since 2.16
		'gtk_binding_entry_add',				'E',
		'gtk_binding_entry_add_signall',		'E',
		'gtk_binding_entry_clear',				'E',
		'gtk_binding_parse_binding',			'E',
		'gtk_box_pack_end_defaults',			'E',
		'gtk_box_pack_start_defaults',			'E',
		'gtk_button_box_get_child_ipadding',		'E',
		'gtk_button_box_get_child_size',		'E',
		'gtk_button_box_get_spacing',			'E',
		'gtk_button_box_set_child_ipadding',		'E', # style properties child-internal-pad-x/-y
		'gtk_button_box_set_child_size',		'E', # style properties child-min-width/-height
		'gtk_button_box_set_spacing',			'E', # gtk_box_set_spacing [==]
		'gtk_button_enter',						'E', # since 2.20
		'gtk_button_leave',						'E', # since 2.20
		'gtk_button_pressed',					'E', # since 2.20
		'gtk_button_released',					'E', # since 2.20
		'gtk_calendar_display_options',			'E',
		'gtk_calendar_freeze',					'E',
		'gtk_calendar_thaw',					'E',
		'GTK_CELL_PIXMAP',						'E', # GtkTreeView (& related) ...
		'GTK_CELL_PIXTEXT',						'E',
		'gtk_cell_renderer_editing_canceled',		'E',
		'GTK_CELL_TEXT',						'W',
		'GTK_CELL_WIDGET',						'E',
		'GTK_CHECK_CAST',						'E', # G_TYPE_CHECK_INSTANCE_CAST [==]
		'GTK_CHECK_CLASS_CAST',					'E', # G_TYPE_CHECK_CLASS_CAST [==]
		'GTK_CHECK_CLASS_TYPE',					'E', # G_TYPE_CHECK_CLASS_TYPE [==]
		'GTK_CHECK_GET_CLASS',					'E', # G_TYPE_INSTANCE_GET_CLASS [==]
		'gtk_check_menu_item_set_show_toggle',		'E', # Does nothing; remove; [show_toggle is always TRUE]
		'gtk_check_menu_item_set_state',		'E',
		'GTK_CHECK_TYPE',						'E', # G_TYPE_CHECK_INSTANCE_TYPE [==]
		'GTK_CLASS_NAME',						'E',
		'GTK_CLASS_TYPE',						'E',
		'GTK_CLIST_ADD_MODE',					'E', # GtkTreeView (& related) ...
		'gtk_clist_append',						'W',
		'GTK_CLIST_AUTO_RESIZE_BLOCKED',		'E',
		'GTK_CLIST_AUTO_SORT',					'E',
		'gtk_clist_clear',						'W',
		'gtk_clist_column_title_active',		'E',
		'gtk_clist_column_title_passive',		'E',
		'gtk_clist_column_titles_active',		'E',
		'gtk_clist_column_titles_hide',			'E',
		'gtk_clist_column_titles_passive',		'E',
		'gtk_clist_column_titles_show',			'E',
		'gtk_clist_columns_autosize',			'E',
		'GTK_CLIST_DRAW_DRAG_LINE',				'E',
		'GTK_CLIST_DRAW_DRAG_RECT',				'E',
		'gtk_clist_find_row_from_data',			'E',
		'GTK_CLIST_FLAGS',						'E',
		'gtk_clist_freeze',						'E',
		'gtk_clist_get_cell_style',				'E',
		'gtk_clist_get_cell_type',				'E',
		'gtk_clist_get_column_title',			'E',
		'gtk_clist_get_column_widget',			'E',
		'gtk_clist_get_hadjustment',			'E',
		'gtk_clist_get_pixmap',					'E',
		'gtk_clist_get_pixtext',				'E',
		'gtk_clist_get_row_data',				'E',
		'gtk_clist_get_row_style',				'E',
		'gtk_clist_get_selectable',				'E',
		'gtk_clist_get_selection_info',			'E',
		'gtk_clist_get_text',					'E',
		'gtk_clist_get_vadjustment',			'E',
		'GTK_CLIST_IN_DRAG',					'E',
		'gtk_clist_insert',						'E',
		'gtk_clist_moveto',						'E',
		'gtk_clist_new',						'E',
		'gtk_clist_new_with_titles',			'E',
		'gtk_clist_optimal_column_width',		'E',
		'gtk_clist_prepend',					'E',
		'gtk_clist_remove',						'E',
		'GTK_CLIST_REORDERABLE',				'E',
		'GTK_CLIST_ROW',						'E',
		'GTK_CLIST_ROW_HEIGHT_SET',				'E',
		'gtk_clist_row_is_visible',				'E',
		'gtk_clist_row_move',					'E',
		'gtk_clist_select_all',					'E',
		'gtk_clist_select_row',					'E',
		'gtk_clist_set_auto_sort',				'E',
		'gtk_clist_set_background',				'E',
		'gtk_clist_set_button_actions',			'E',
		'gtk_clist_set_cell_style',				'E',
		'gtk_clist_set_column_auto_resize',		'E',
		'gtk_clist_set_column_justification',	'E',
		'gtk_clist_set_column_max_width',		'E',
		'gtk_clist_set_column_min_width',		'E',
		'gtk_clist_set_column_resizeable',		'E',
		'gtk_clist_set_column_title',			'E',
		'gtk_clist_set_column_visibility', 		'E',
		'gtk_clist_set_column_widget',			'E',
		'gtk_clist_set_column_width',			'E',
		'gtk_clist_set_compare_func',			'E',
		'GTK_CLIST_SET_FLAG',					'E',
		'gtk_clist_set_foreground',				'E',
		'gtk_clist_set_hadjustment',			'E',
		'gtk_clist_set_pixmap',					'E',
		'gtk_clist_set_pixtext',				'E',
		'gtk_clist_set_reorderable',			'E',
		'gtk_clist_set_row_data',				'E',
		'gtk_clist_set_row_data_full',			'E',
		'gtk_clist_set_row_height',				'E',
		'gtk_clist_set_row_style',				'E',
		'gtk_clist_set_selectable',				'E',
		'gtk_clist_set_selection_mode',			'E',
		'gtk_clist_set_shadow_type', 			'E',
		'gtk_clist_set_shift',					'E',
		'gtk_clist_set_sort_column',			'E',
		'gtk_clist_set_sort_type',				'E',
		'gtk_clist_set_text',					'E',
		'gtk_clist_set_use_drag_icons',			'E',
		'gtk_clist_set_vadjustment',			'E',
		'GTK_CLIST_SHOW_TITLES',				'E',
		'gtk_clist_sort',						'E',
		'gtk_clist_swap_rows',					'E',
		'gtk_clist_thaw',						'E',
		'gtk_clist_undo_selection',				'E',
		'gtk_clist_unselect_all',				'E',
		'gtk_clist_unselect_row',				'E',
		'GTK_CLIST_UNSET_FLAG',					'E',
		'GTK_CLIST_USE_DRAG_ICONS',				'E',
		'gtk_color_selection_get_color',		'E',
		'gtk_color_selection_set_change_palette_hook',	'E',
		'gtk_color_selection_set_color',				'E',
		'gtk_color_selection_set_update_policy',		'E',
		'gtk_combo_disable_activate',			'E', # GtkComboBoxEntry ... (avail since 2.4/2.6/2.10/2.14)
		'gtk_combo_new',						'E',
		'gtk_combo_set_case_sensitive',			'E',
		'gtk_combo_set_item_string',			'E',
		'gtk_combo_set_popdown_strings',		'E',
		'gtk_combo_set_use_arrows',				'E',
		'gtk_combo_set_use_arrows_always',		'E',
		'gtk_combo_set_value_in_list',			'E',
		'gtk_container_border_width',			'E', # gtk_container_set_border_width [==]
		'gtk_container_children',				'E', # gtk_container_get_children [==]
		'gtk_container_foreach_full',			'E',
		'gtk_ctree_collapse',					'E',
		'gtk_ctree_collapse_recursive',			'E',
		'gtk_ctree_collapse_to_depth',			'E',
		'gtk_ctree_expand',						'E',
		'gtk_ctree_expand_recursive',			'E',
		'gtk_ctree_expand_to_depth',			'E',
		'gtk_ctree_export_to_gnode',			'E',
		'gtk_ctree_find',						'E',
		'gtk_ctree_find_all_by_row_data',		'E',
		'gtk_ctree_find_all_by_row_data_custom','E',
		'gtk_ctree_find_by_row_data',			'E',
		'gtk_ctree_find_by_row_data_custom',	'E',
		'gtk_ctree_find_node_ptr',				'E',
		'GTK_CTREE_FUNC',						'E',
		'gtk_ctree_get_node_info',				'E',
		'gtk_ctree_insert_gnode',				'E',
		'gtk_ctree_insert_node',				'E',
		'gtk_ctree_is_ancestor',				'E',
		'gtk_ctree_is_hot_spot',				'E',
		'gtk_ctree_is_viewable',				'E',
		'gtk_ctree_last',						'E',
		'gtk_ctree_move',						'E',
		'gtk_ctree_new',						'E',
		'gtk_ctree_new_with_titles',			'E',
		'GTK_CTREE_NODE',						'E',
		'gtk_ctree_node_get_cell_style',		'E',
		'gtk_ctree_node_get_cell_type',			'E',
		'gtk_ctree_node_get_pixmap',			'E',
		'gtk_ctree_node_get_pixtext',			'E',
		'gtk_ctree_node_get_row_data',			'E',
		'gtk_ctree_node_get_row_style',			'E',
		'gtk_ctree_node_get_selectable',		'E',
		'gtk_ctree_node_get_text',				'E',
		'gtk_ctree_node_is_visible',			'E',
		'gtk_ctree_node_moveto',				'E',
		'GTK_CTREE_NODE_NEXT',					'E',
		'gtk_ctree_node_nth',					'E',
		'GTK_CTREE_NODE_PREV',					'E',
		'gtk_ctree_node_set_background',		'E',
		'gtk_ctree_node_set_cell_style',		'E',
		'gtk_ctree_node_set_foreground',		'E',
		'gtk_ctree_node_set_pixmap',			'E',
		'gtk_ctree_node_set_pixtext',			'E',
		'gtk_ctree_node_set_row_data',			'E',
		'gtk_ctree_node_set_row_data_full',		'E',
		'gtk_ctree_node_set_row_style',			'E',
		'gtk_ctree_node_set_selectable',		'E',
		'gtk_ctree_node_set_shift',				'E',
		'gtk_ctree_node_set_text',				'E',
		'gtk_ctree_post_recursive',				'E',
		'gtk_ctree_post_recursive_to_depth',	'E',
		'gtk_ctree_pre_recursive',				'E',
		'gtk_ctree_pre_recursive_to_depth',		'E',
		'gtk_ctree_real_select_recursive',		'E',
		'gtk_ctree_remove_node',				'E',
		'GTK_CTREE_ROW',						'E',
		'gtk_ctree_select',						'E',
		'gtk_ctree_select_recursive',			'E',
		'gtk_ctree_set_drag_compare_func',		'E',
		'gtk_ctree_set_expander_style',			'E',
		'gtk_ctree_set_indent',					'E',
		'gtk_ctree_set_line_style',				'E',
		'gtk_ctree_set_node_info',				'E',
		'gtk_ctree_set_reorderable',			'E',
		'gtk_ctree_set_show_stub',				'E',
		'gtk_ctree_set_spacing',				'E',
		'gtk_ctree_sort_node',					'E',
		'gtk_ctree_sort_recursive',				'E',
		'gtk_ctree_toggle_expansion',			'E',
		'gtk_ctree_toggle_expansion_recursive',	'E',
		'gtk_ctree_unselect',					'E',
		'gtk_ctree_unselect_recursive',			'E',
		'gtk_curve_get_vector',					'E', # since 2.20
		'gtk_curve_new',						'E', # since 2.20
		'gtk_curve_reset',						'E', # since 2.20
		'gtk_curve_set_curve_type',				'E', # since 2.20
		'gtk_curve_set_gamma',					'E', # since 2.20
		'gtk_curve_set_range',					'E', # since 2.20
		'gtk_curve_set_vector',					'E', # since 2.20
		'gtk_drag_set_default_icon',			'E',
		'gtk_draw_arrow',						'E',
		'gtk_draw_box',							'E',
		'gtk_draw_box_gap',						'E',
		'gtk_draw_check',						'E',
		'gtk_draw_diamond',						'E',
		'gtk_draw_expander',					'E',
		'gtk_draw_extension',					'E',
		'gtk_draw_flat_box',					'E',
		'gtk_draw_focus',						'E',
		'gtk_draw_handle',						'E',
		'gtk_draw_hline',						'E',
		'gtk_draw_layout',						'E',
		'gtk_draw_option',						'E',
		'gtk_draw_polygon',						'E',
		'gtk_draw_resize_grip',					'E',
		'gtk_draw_shadow',						'E',
		'gtk_draw_shadow_gap',					'E',
		'gtk_draw_slider',						'E',
		'gtk_draw_string',						'E',
		'gtk_draw_tab',							'E',
		'gtk_draw_vline',						'E',
		'gtk_drawing_area_size',				'E', # >> g_object_set() [==] ?
													 #    gtk_widget_set_size_request() [==?]
		'gtk_entry_append_text',				'E', # >> gtk_editable_insert_text() [==?]
		'gtk_entry_new_with_max_length',		'E', # gtk_entry_new(); gtk_entry_set_max_length()
		'gtk_entry_prepend_text',				'E',
		'gtk_entry_select_region',				'E',
		'gtk_entry_set_editable',				'E', # >> gtk_editable_set_editable() [==?]
		'gtk_entry_set_position',				'E',
		'gtk_exit',										'E', # exit() [==]
		'gtk_file_chooser_button_new_with_backend',		'E',
		'gtk_file_chooser_dialog_new_with_backend',		'E',
		'gtk_file_chooser_widget_new_with_backend',		'E',
		'gtk_file_selection_complete',					'E',
		'gtk_file_selection_get_filename',				'E', # GtkFileChooser ...
		'gtk_file_selection_get_select_multiple',		'E',
		'gtk_file_selection_get_selections',			'E',
		'gtk_file_selection_hide_fileop_buttons',		'E',
		'gtk_file_selection_new',						'E',
		'gtk_file_selection_set_filename',				'E',
		'gtk_file_selection_set_select_multiple',		'E',
		'gtk_file_selection_show_fileop_buttons',		'E',
		'gtk_fixed_get_has_window',						'E', # gtk_widget_get_has_window() (available since 2.18)
		'gtk_fixed_set_has_window',						'E', # gtk_widget_set_has_window() (available since 2.18)
		'gtk_font_selection_dialog_get_apply_button',	'E',
		'gtk_font_selection_dialog_get_font',			'E',
		'gtk_font_selection_get_font',					'E', # gtk_font_selection_get_font_name() [!=]
		'GTK_FUNDAMENTAL_TYPE',							'E',
		'gtk_gamma_curve_new',							'E', # since 2.20
		'gtk_hbutton_box_get_layout_default',			'E',
		'gtk_hbutton_box_get_spacing_default',			'E',
		'gtk_hbutton_box_set_layout_default',			'E',
		'gtk_hbutton_box_set_spacing_default',			'E',
		'gtk_idle_add',									'E',
		'gtk_idle_add_full',							'E',
		'gtk_idle_add_priority',						'E',
		'gtk_idle_remove',								'E',
		'gtk_idle_remove_by_data',						'E',
		'gtk_image_get',								'E',
		'gtk_image_set',								'E',
		'gtk_input_add_full',							'W', # >>> g_io_add_watch_full()
		'gtk_input_dialog_new',							'E', # since 2.20
		'gtk_input_remove',								'W', # >>> g_source_remove()
		'GTK_IS_ROOT_TREE',								'E',
		'gtk_item_factories_path_delete',				'E', # GtkUIManager (avail since 2.4) ...
		'gtk_item_factory_add_foreign',					'E',
		'gtk_item_factory_construct',					'E',
		'gtk_item_factory_create_item',					'W',
		'gtk_item_factory_create_items',				'E',
		'gtk_item_factory_create_items_ac',				'W',
		'gtk_item_factory_create_menu_entries',			'E',
		'gtk_item_factory_delete_entries',		'E',
		'gtk_item_factory_delete_entry',		'E',
		'gtk_item_factory_delete_item',			'W',
		'gtk_item_factory_from_path',			'E',
		'gtk_item_factory_from_widget',			'W',
		'gtk_item_factory_get_item',			'W',
		'gtk_item_factory_get_item_by_action',		'E',
		'gtk_item_factory_get_widget',			'W',
		'gtk_item_factory_get_widget_by_action',	'E',
		'gtk_item_factory_new',				'W',
		'gtk_item_factory_path_from_widget',		'E',
		'gtk_item_factory_popup',			'E',
		'gtk_item_factory_popup_data',			'E',
		'gtk_item_factory_popup_data_from_widget',	'E',
		'gtk_item_factory_popup_with_data',		'E',
		'gtk_item_factory_set_translate_func',		'E',
		'gtk_label_get',				'E', # gtk_label_get_text() [!=]
		'gtk_label_parse_uline',			'E',
		'gtk_label_set',				'E', # gtk_label_set_text() [==]
		'gtk_layout_freeze',				'E',
		'gtk_layout_thaw',				'E',
		'gtk_list_append_items',			'E',
		'gtk_list_child_position',			'E',
		'gtk_list_clear_items',				'E',
		'gtk_list_end_drag_selection',			'E',
		'gtk_list_end_selection',			'E',
		'gtk_list_extend_selection',			'E',
		'gtk_list_insert_items',			'E',
		'gtk_list_item_deselect',			'E',
		'gtk_list_item_new',				'E',
		'gtk_list_item_new_with_label',			'E',
		'gtk_list_item_select',				'E',
		'gtk_list_new',					'E',
		'gtk_list_prepend_items',			'E',
		'gtk_list_remove_items',			'E',
		'gtk_list_remove_items_no_unref',		'E',
		'gtk_list_scroll_horizontal',			'E',
		'gtk_list_scroll_vertical',			'E',
		'gtk_list_select_all',				'E',
		'gtk_list_select_child',			'E',
		'gtk_list_select_item',				'E',
		'gtk_list_set_selection_mode',			'E',
		'gtk_list_start_selection',			'E',
		'gtk_list_toggle_add_mode',			'E',
		'gtk_list_toggle_focus_row',			'E',
		'gtk_list_toggle_row',				'E',
		'gtk_list_undo_selection',			'E',
		'gtk_list_unselect_all',			'E',
		'gtk_list_unselect_child',			'E',
		'gtk_list_unselect_item',			'E',
		'gtk_menu_append',				'E', # gtk_menu_shell_append() [==?]
		'gtk_menu_bar_append',				'E',
		'gtk_menu_bar_insert',				'E',
		'gtk_menu_bar_prepend',				'E',
		'gtk_menu_insert',				'E',
		'gtk_menu_item_remove_submenu',			'E',
		'gtk_menu_item_right_justify',			'E',
		'gtk_menu_prepend',				'E', # gtk_menu_shell_prepend() [==?]
		'gtk_menu_tool_button_set_arrow_tooltip',	'E',
		'gtk_notebook_current_page',			'E',
		'gtk_notebook_query_tab_label_packing',		'E', # since 2.20
		'gtk_notebook_get_group_id',			'E',
		'gtk_notebook_set_group_id',			'E',
		'gtk_notebook_set_homogeneous_tabs',		'E',
		'gtk_notebook_set_page',			'E', # gtk_notebook_set_current_page() [==]
		'gtk_notebook_set_tab_border',			'E',
		'gtk_notebook_set_tab_hborder',			'E',
		'gtk_notebook_set_tab_label_packing',		'E', # since 2.20
		'gtk_notebook_set_tab_vborder',			'E',
		'gtk_object_add_arg_type',			'E',
		'gtk_object_data_force_id',			'E',
		'gtk_object_data_try_key',			'E',
		'GTK_OBJECT_FLOATING',				'E',
		'gtk_object_get',				'E',
		'gtk_object_get_data',				'E',
		'gtk_object_get_data_by_id',			'E',
		'gtk_object_get_user_data',			'E',
		'gtk_object_new',				'E',
		'gtk_object_ref',				'E',
		'gtk_object_remove_data',			'E',
		'gtk_object_remove_data_by_id',			'E',
		'gtk_object_remove_no_notify',			'E',
		'gtk_object_remove_no_notify_by_id',		'E',
		'gtk_object_set',				'E',
		'gtk_object_set_data',				'E',
		'gtk_object_set_data_by_id',			'E',
		'gtk_object_set_data_by_id_full',		'E',
		'gtk_object_set_data_full',			'E',
		'gtk_object_set_user_data',			'E',
		'gtk_object_sink',				'E',
		'GTK_OBJECT_TYPE',				'E', # G_OBJECT_TYPE
		'GTK_OBJECT_TYPE_NAME',				'E', # G_OBJECT_TYPE_NAME
		'gtk_object_unref',				'E',
		'gtk_object_weakref',				'E',
		'gtk_object_weakunref',				'E',
		'gtk_old_editable_changed',			'E',
		'gtk_old_editable_claim_selection',		'E',
		'gtk_option_menu_get_history',			'E', # GtkComboBox ... (avail since 2.4/2.6/2.10/2.14)
		'gtk_option_menu_get_menu',			'E',
		'gtk_option_menu_new',				'E',
		'gtk_option_menu_remove_menu',			'E',
		'gtk_option_menu_set_history',			'E',
		'gtk_option_menu_set_menu',			'E',
		'gtk_paint_string',				'E',
		'gtk_paned_gutter_size',			'E', # gtk_paned_set_gutter_size()
		'gtk_paned_set_gutter_size',			'E', # "does nothing"
		'gtk_pixmap_get',				'E', # GtkImage ...
		'gtk_pixmap_new',				'E',
		'gtk_pixmap_set',				'E',
		'gtk_pixmap_set_build_insensitive',		'E',
		'gtk_preview_draw_row',				'E',
		'gtk_preview_get_cmap',				'E',
		'gtk_preview_get_info',				'E',
		'gtk_preview_get_visual',			'E',
		'gtk_preview_new',				'E',
		'gtk_preview_put',				'E',
		'gtk_preview_reset',				'E',
		'gtk_preview_set_color_cube',			'E',
		'gtk_preview_set_dither',			'E',
		'gtk_preview_set_expand',			'E',
		'gtk_preview_set_gamma',			'E',
		'gtk_preview_set_install_cmap',			'E',
		'gtk_preview_set_reserved',			'E',
		'gtk_preview_size',				'E',
		'gtk_preview_uninit',				'E',
		'gtk_progress_bar_new_with_adjustment',		'E',
		'gtk_progress_bar_set_activity_blocks',		'E',
		'gtk_progress_bar_set_activity_step',		'E',
		'gtk_progress_bar_set_bar_style',		'E',
		'gtk_progress_bar_set_discrete_blocks',		'E',
		'gtk_progress_bar_update',			'E', # >>> "gtk_progress_set_value() or
									#    gtk_progress_set_percentage()"
									##  Actually: GtkProgress is deprecated so the
									##  right answer appears to be to use
									##  gtk_progress_bar_set_fraction()
		'gtk_progress_configure',			'E',
		'gtk_progress_get_current_percentage',		'E',
		'gtk_progress_get_current_text',		'E',
		'gtk_progress_get_percentage_from_value',	'E',
		'gtk_progress_get_text_from_value',		'E',
		'gtk_progress_get_value',			'E',
		'gtk_progress_set_activity_mode',		'E',
		'gtk_progress_set_adjustment',			'E',
		'gtk_progress_set_format_string',		'E',
		'gtk_progress_set_percentage',			'E',
		'gtk_progress_set_show_text',			'E',
		'gtk_progress_set_text_alignment',		'E',
		'gtk_progress_set_value',			'E',
		'gtk_radio_button_group',			'E', # gtk_radio_button_get_group() [==]
		'gtk_radio_menu_item_group',			'E',
		'gtk_rc_add_class_style',			'E',
		'gtk_rc_add_widget_class_style',		'E',
		'gtk_rc_add_widget_name_style',			'E',
		'gtk_rc_style_ref',				'E',
		'gtk_rc_style_unref',				'E',
		'gtk_recent_chooser_get_show_numbers',		'E',
		'gtk_recent_chooser_set_show_numbers',		'E',
		'gtk_recent_manager_get_for_screen',		'E',
		'gtk_recent_manager_set_screen',		'E',
		'GTK_RETLOC_BOOL',				'E',
		'GTK_RETLOC_BOXED',				'E',
		'GTK_RETLOC_CHAR',				'E',
		'GTK_RETLOC_DOUBLE',				'E',
		'GTK_RETLOC_ENUM',				'E',
		'GTK_RETLOC_FLAGS',				'E',
		'GTK_RETLOC_FLOAT',				'E',
		'GTK_RETLOC_INT',				'E',
		'GTK_RETLOC_LONG',				'E',
		'GTK_RETLOC_OBJECT',				'E',
		'GTK_RETLOC_POINTER',				'E',
		'GTK_RETLOC_STRING',				'E',
		'GTK_RETLOC_UCHAR',				'E',
		'GTK_RETLOC_UINT',				'E',
		'GTK_RETLOC_ULONG',				'E',
		'gtk_selection_clear',				'E',
		'gtk_signal_connect',				'E', # GSignal ...
		'gtk_signal_connect_after',			'E',
		'gtk_signal_connect_full',			'E',
		'gtk_signal_connect_object',			'E',
		'gtk_signal_connect_object_after',		'E',
		'gtk_signal_connect_object_while_alive',	'E',
		'gtk_signal_connect_while_alive',		'E',
		'gtk_signal_default_marshaller',		'E',
		'gtk_signal_disconnect',			'E',
		'gtk_signal_disconnect_by_data',		'E',
		'gtk_signal_disconnect_by_func',		'E',
		'gtk_signal_emit',				'E',
		'gtk_signal_emit_by_name',			'E',
		'gtk_signal_emit_stop',				'E',
		'gtk_signal_emit_stop_by_name',			'E',
		'gtk_signal_emitv',				'E',
		'gtk_signal_emitv_by_name',			'E',
		'GTK_SIGNAL_FUNC',						'E',
		'gtk_signal_handler_block',				'E',
		'gtk_signal_handler_block_by_data',		'E',
		'gtk_signal_handler_block_by_func',		'E',
		'gtk_signal_handler_pending',			'E',
		'gtk_signal_handler_pending_by_func',		'E',
		'gtk_signal_handler_unblock',				'E',
		'gtk_signal_handler_unblock_by_data',		'E',
		'gtk_signal_handler_unblock_by_func',		'E',
		'gtk_signal_lookup',						'E',
		'gtk_signal_name',							'E',
		'gtk_signal_new',							'E',
		'gtk_signal_newv',							'E',
		'GTK_SIGNAL_OFFSET',						'E',
		'gtk_socket_steal',							'E',
		'gtk_spin_button_get_value_as_float',		'E', # gtk_spin_button_get_value() [==]
		'GTK_STRUCT_OFFSET',						'E',
		'gtk_style_apply_default_pixmap',			'E',
		'gtk_style_get_font',						'E',
		'gtk_style_ref',							'E',
		'gtk_style_set_font',						'E',
		'gtk_style_unref',							'E', # g_object_unref() [==?]
		'gtk_text_backward_delete',					'E',
		'gtk_text_forward_delete',					'E',
		'gtk_text_freeze',							'E',
		'gtk_text_get_length',						'E',
		'gtk_text_get_point',						'E',
		'GTK_TEXT_INDEX',							'E',
		'gtk_text_insert',							'E', # GtkTextView (GtkText "known to be buggy" !)
		'gtk_text_new',								'E',
		'gtk_text_set_adjustments',					'E',
		'gtk_text_set_editable',					'E',
		'gtk_text_set_line_wrap',					'E',
		'gtk_text_set_point',						'E',
		'gtk_text_set_word_wrap',					'E',
		'gtk_text_thaw',							'E',
		'gtk_timeout_add',							'E', # g_timeout_add()
		'gtk_timeout_add_full',						'E',
		'gtk_timeout_remove',						'E', # g_source_remove()
		'gtk_tips_query_new',						'E',
		'gtk_tips_query_set_caller',				'E',
		'gtk_tips_query_set_labels',				'E',
		'gtk_tips_query_start_query',				'E',
		'gtk_tips_query_stop_query',				'E',
		'gtk_toggle_button_set_state',				'E', # gtk_toggle_button_set_active [==]
		'gtk_toolbar_append_element',				'E',
		'gtk_toolbar_append_item',					'E',
		'gtk_toolbar_append_space',					'E', # Use gtk_toolbar_insert() instead
		'gtk_toolbar_append_widget',				'E', # ??
		'gtk_toolbar_get_tooltips',					'E',
		'gtk_toolbar_insert_element',				'E',
		'gtk_toolbar_insert_item',					'E',
		'gtk_toolbar_insert_space',					'E',
		'gtk_toolbar_insert_stock',					'E',
		'gtk_toolbar_insert_widget',				'E',
		'gtk_toolbar_prepend_element',				'E',
		'gtk_toolbar_prepend_item',					'E',
		'gtk_toolbar_prepend_space',				'E',
		'gtk_toolbar_prepend_widget',				'E',
		'gtk_toolbar_remove_space',					'E',
		'gtk_toolbar_set_tooltips',					'E',
		'gtk_tree_append',							'E',
		'gtk_tree_child_position',					'E',
		'gtk_tree_clear_items',						'E',
		'gtk_tree_insert',							'E',
		'gtk_tree_item_collapse',					'E',
		'gtk_tree_item_deselect',					'E',
		'gtk_tree_item_expand',						'E',
		'gtk_tree_item_new',						'E',
		'gtk_tree_item_new_with_label',				'E',
		'gtk_tree_item_remove_subtree',				'E',
		'gtk_tree_item_select',						'E',
		'gtk_tree_item_set_subtree',				'E',
		'GTK_TREE_ITEM_SUBTREE',					'E',
		'gtk_tree_model_get_iter_root',				'E',
		'gtk_tree_new',								'E',
		'gtk_tree_path_new_root',					'E',
		'gtk_tree_prepend',							'E',
		'gtk_tree_remove_item',						'E',
		'gtk_tree_remove_items',					'E',
		'GTK_TREE_ROOT_TREE',						'E',
		'gtk_tree_select_child',					'E',
		'gtk_tree_select_item',						'E',
		'GTK_TREE_SELECTION_OLD',					'E',
		'gtk_tree_set_selection_mode',				'E',
		'gtk_tree_set_view_lines',					'E',
		'gtk_tree_set_view_mode',					'E',
		'gtk_tree_unselect_child',					'E',
		'gtk_tree_unselect_item',					'E',
		'gtk_tree_view_tree_to_widget_coords',		'E',
		'gtk_tree_view_widget_to_tree_coords',		'E',
		'gtk_type_class',							'E', # g_type_class_peek() or g_type_class_ref()
		'GTK_TYPE_CTREE_NODE',						'E',
		'gtk_type_enum_find_value',					'E',
		'gtk_type_enum_get_values',					'E',
		'gtk_type_flags_find_value',				'E',
		'gtk_type_flags_get_values',				'E',
		'gtk_type_from_name',						'E',
		'gtk_type_init',							'E',
		'gtk_type_is_a',							'E',
		'GTK_TYPE_IS_OBJECT',						'E',
		'gtk_type_name',							'E',
		'gtk_type_new',								'E',
		'gtk_type_parent',				'E',
		'gtk_type_unique',				'E',
		'GTK_VALUE_BOOL',				'E',
		'GTK_VALUE_BOXED',				'E',
		'GTK_VALUE_CHAR',				'E',
		'GTK_VALUE_DOUBLE',				'E',
		'GTK_VALUE_ENUM',				'E',
		'GTK_VALUE_FLAGS',				'E',
		'GTK_VALUE_FLOAT',				'E',
		'GTK_VALUE_INT',				'E',
		'GTK_VALUE_LONG',				'E',
		'GTK_VALUE_OBJECT',				'E',
		'GTK_VALUE_POINTER',				'E',
		'GTK_VALUE_SIGNAL',				'E',
		'GTK_VALUE_STRING',				'E',
		'GTK_VALUE_UCHAR',				'E',
		'GTK_VALUE_UINT',				'E',
		'GTK_VALUE_ULONG',				'E',
		'gtk_vbutton_box_get_layout_default',		'E',
		'gtk_vbutton_box_get_spacing_default',		'E',
		'gtk_vbutton_box_set_layout_default',		'E',
		'gtk_vbutton_box_set_spacing_default',		'E',
		'gtk_widget_draw',							'E',	# gtk_widget_queue_draw_area():
															#  "in general a better choice if you want
															#  to draw a region of a widget."
		'gtk_widget_pop_visual',					'E',
		'gtk_widget_push_visual',					'E',
		'gtk_widget_queue_clear',					'E',
		'gtk_widget_queue_clear_area',				'E',
		'gtk_widget_ref',							'E', # g_object_ref() [==]
		'gtk_widget_restore_default_style',			'E',
		'gtk_widget_set',							'E', # g_object_set() [==]
		'gtk_widget_set_default_visual',			'E',
		'gtk_widget_set_rc_style',					'E',
		'gtk_widget_set_uposition',					'E', # ?? (see GTK documentation)
		'gtk_widget_set_usize',						'E', # gtk_widget_set_size_request()
		'gtk_widget_set_visual',					'E',
		'gtk_widget_unref',							'E',
		'gtk_window_position',						'E',
		'gtk_window_set_policy',					'E', # >>? gtk_window_set_resizable()
##
## Deprecated for GTK+ versions greater than 2.4
## Note that entries marked with 'W' are currently being used by Wireshark
## Those marked with 'E' are not being used by Wireshark
##
## Deprecated as of GTK+ 2.12 but to be replaced only when Wireshark requires GTK+ 2.12 or later
##  (or: use conditional code based upon the GTK version).
		'gtk_tooltips_data_get',					'E', # new API: GtkToolTip (avail since 2.12) ...
		'gtk_tooltips_disable',						'E',
		'gtk_tooltips_enable',						'E',
		'gtk_tooltips_force_window',				'E',
		'gtk_tooltips_get_info_from_tip_window',	'E',
		'gtk_tooltips_new',							'W',
		'gtk_tooltips_set_delay',					'E',
		'gtk_tooltips_set_tip',						'W',
		'gtk_tool_item_set_tooltip',				'W', # gtk_tool_item_set_tooltip_text() (avail since 2.12)
##
## Deprecated as of GTK+ 2.16 but to be replaced only when Wireshark requires GTK+ 2.16 or later
##  (or: use conditional code based upon the GTK version).
		'gtk_scale_button_get_orientation',			'E', # gtk_orientable_get_orientation()		(avail since 2.16)
		'gtk_scale_button_set_orientation',			'E', # gtk_orientable_set_orientation()		(avail since 2.16)
		'gtk_toolbar_get_orientation',				'E', # gtk_orientable_get_orientation()		(avail since 2.16)
##		'gtk_toolbar_set_orientation',				'W', # gtk_orientable_set_orientation()		(avail since 2.16)
		'gtk_status_icon_set_tooltip',				'E', # gtk_status_icon_set_tooltip_text()	(avail since 2.16)
		'gtk_widget_get_action',					'E', # gtk_activatable_get_related_action()	(avail since 2.16)
##
## Deprecated as of GTK+ 2.18 but to be replaced only when Wireshark requires GTK+ 2.12 or later
##  (or: use conditional code based upon the GTK version).
		'gtk_cell_view_get_cell_renderers',			'E', # gtk_cell_layout_get_cells ()		(avail since 2.12)
##		'gtk_tree_view_column_get_cell_renderers',	'W', # gtk_cell_layout_get_cells ()		(avail since 2.12)
##
## Deprecated as of GTK+ 2.20 but to be replaced only when Wireshark requires GTK+ 2.18 or later
##  (or: use conditional code based upon the GTK version).
		'GTK_WIDGET_APP_PAINTABLE',					'E', # gtk_widget_get_app_paintable()		(avail since 2.18)
		'GTK_WIDGET_CAN_DEFAULT',					'E', # gtk_widget_getcan_default()		(avail since 2.18)
		'GTK_WIDGET_CAN_FOCUS',						'E', # gtk_widget_getcan_focus()		(avail since 2.18)
		'GTK_WIDGET_COMPOSITE_CHILD',				'E', # gtk_widget_getcomposite_child()		(avail since 2.18)
		'GTK_WIDGET_DOUBLE_BUFFERED',				'E', # gtk_widget_getdouble_buffered()		(avail since 2.18)
		'GTK_WIDGET_DRAWABLE',						'E', # gtk_widget_getdrawable()			(avail since 2.18)
		'GTK_WIDGET_FLAGS',							'E', # gtk_widget_getflags()			(avail since 2.18)
		'GTK_WIDGET_HAS_DEFAULT',					'E', # gtk_widget_gethas_default()		(avail since 2.18)
		'GTK_WIDGET_HAS_FOCUS',						'E', # gtk_widget_gethas_focus()		(avail since 2.18)
		'GTK_WIDGET_HAS_GRAB',						'E', # gtk_widget_gethas_grab()			(avail since 2.18)
		'GTK_WIDGET_IS_SENSITIVE',					'E', # gtk_widget_getis_sensitive()		(avail since 2.18)
		'GTK_WIDGET_MAPPED',						'E', # gtk_widget_getmapped()			(avail since 2.18)
		'GTK_WIDGET_NO_WINDOW',						'W', # gtk_widget_getno_window()		(avail since 2.18)
		'GTK_WIDGET_PARENT_SENSITIVE',				'E', # gtk_widget_getparent_sensitive()		(avail since 2.18)
		'GTK_WIDGET_RC_STYLE',						'E', # gtk_widget_getrc_style()			(avail since 2.18)
		'GTK_WIDGET_REALIZED',						'W', # gtk_widget_getrealized()			(avail since 2.18)
		'GTK_WIDGET_RECEIVES_DEFAULT',				'E', # gtk_widget_getreceives_default()		(avail since 2.18)
		'GTK_WIDGET_SAVED_STATE',					'E', # gtk_widget_getsaved_state()		(avail since 2.18)
		'GTK_WIDGET_SENSITIVE',						'W', # gtk_widget_getsensitive()		(avail since 2.18)
		'GTK_WIDGET_STATE',							'W', # gtk_widget_getstate()			(avail since 2.18)
		'GTK_WIDGET_TOPLEVEL',						'E', # gtk_widget_gettoplevel()			(avail since 2.18)
		'GTK_WIDGET_TYPE',							'E', # gtk_widget_gettype()			(avail since 2.18)
		'GTK_WIDGET_VISIBLE',						'W', # gtk_widget_getvisible()			(avail since 2.18)
## Deprecated as of GTK+ 2.22 but to be replaced only when Wireshark requires GTK+ 2.18 or later
##  (or: use conditional code based upon the GTK version).
		'gtk_dialog_get_has_separator',				'E', # This function will be removed in GTK+ 3
		'gtk_dialog_set_has_separator',				'E', # This function will be removed in GTK+ 3
		'gtk_icon_view_get_orientation',			'E', # gtk_icon_view_get_item_orientation()
		'gtk_icon_view_set_orientation',			'E', # gtk_icon_view_set_item_orientation()
		'gtk_item_deselect',						'E', # gtk_menu_item_deselect()
		'gtk_item_select',							'E', # gtk_menu_item_select()
		'gtk_item_toggle',							'E', #
		'gtk_recent_manager_get_limit',				'E', # Use GtkRecentChooser
		'gtk_recent_manager_set_limit',				'E', #

## Deprecated as of GTK+ 2.24 but to be replaced only when Wireshark requires GTK+ 2.24 or later
##  (or: use conditional code based upon the GTK version).
		'gtk_combo_box_new_text',					'W', # gtk_combo_box_text_new()
		'GtkComboBoxEntry',							'W', #
		'gtk_combo_box_append_text',				'W', #
		'gtk_combo_box_entry_get_text_column',		'W', #
		'gtk_combo_box_entry_new',					'W', #
		'gtk_combo_box_entry_new_text',				'W', #
		'gtk_combo_box_entry_new_with_model',		'W', #
		'gtk_combo_box_entry_set_text_column',		'W', #
		'gtk_combo_box_get_active_text',			'W', #
		'gtk_combo_box_insert_text',				'W', #
		'gtk_combo_box_new_text',					'W', #
		'gtk_combo_box_prepend_text',				'W', #
		'gtk_combo_box_remove_text',				'W', #

## GDK deprecated functions:
		'gdk_bitmap_create_from_data',				'W', # 
		'gdk_bitmap_ref',							'W', # 
		'gdk_bitmap_unref',							'W', # 
		'gdk_cairo_set_source_pixmap',				'W', # 
		'gdk_char_height',							'W', #
		'gdk_char_measure',							'W', #
		'gdk_char_width',							'W', #
		'gdk_char_width_wc',						'W', #
		'gdk_colormap_change',						'W', # 
		'gdk_colormap_get_system_size',				'W', # 
		'gdk_colormap_ref',							'W', #
		'gdk_colormap_unref',						'W', #
		'gdk_colors_alloc',							'W', #
		'gdk_colors_free',							'W', #
		'gdk_colors_store',							'W', #
		'gdk_color_alloc',							'W', #
		'gdk_color_black',							'W', #
		'gdk_color_change',							'W', #
		'gdk_color_white',							'W', #
		'gdk_cursor_destroy',						'W', # 
		'GdkDestroyNotify',							'W', # 
		'gdk_DISPLAY',								'W', # 
		'gdk_display_set_pointer_hooks',			'W', # 
		'gdk_drag_context_new',						'W', # 
		'gdk_drag_context_ref',						'W', # 
		'gdk_drag_context_unref',					'W', # 
		'gdk_drag_find_window',						'W', # 
		'gdk_drag_get_protocol',					'W', # 
		'gdk_drawable_copy_to_image',				'W', # 
		'gdk_drawable_get_data',					'W', # 
		'gdk_drawable_get_display',					'W', # 
		'gdk_drawable_get_image',					'W', # 
		'gdk_drawable_get_screen',					'W', # 
		'gdk_drawable_get_size',					'W', # 
		'gdk_drawable_get_visual',					'W', # 
		'gdk_drawable_ref',							'W', # 
		'gdk_drawable_set_data',					'W', # 
		'gdk_drawable_unref',						'W', # 
		'gdk_draw_arc',								'W', # 
		'gdk_draw_drawable',						'W', # gdk_cairo_set_source_pixmap(), 
		'gdk_draw_glyphs',							'W', # 
		'gdk_draw_glyphs_transformed',				'W', # 
		'gdk_draw_gray_image',						'W', # 
		'gdk_draw_image',							'W', # 
		'gdk_draw_indexed_image',					'W', # 
		'gdk_draw_layout',							'W', # 
		'gdk_draw_layout_line',						'W', # 
		'gdk_draw_layout_line_with_colors',			'W', # 
		'gdk_draw_layout_with_colors',				'W', # 
		'gdk_draw_line',							'W', # 
		'gdk_draw_lines',							'W', # 
		'gdk_draw_pixbuf',							'W', # gdk_cairo_set_source_pixbuf() and cairo_paint() or cairo_rectangle() and cairo_fill() instead.
		'gdk_draw_pixmap',							'W', # 
		'gdk_draw_point',							'W', # 
		'gdk_draw_points',							'W', # 
		'gdk_draw_polygon',							'W', # 
		'gdk_draw_rectangle',						'W', # 
		'gdk_draw_rgb_32_image',					'W', # 
		'gdk_draw_rgb_32_image_dithalign',			'W', # 
		'gdk_draw_rgb_image',						'W', # 
		'gdk_draw_rgb_image_dithalign',				'W', # 
		'gdk_draw_segments',						'W', # 
		'gdk_draw_string',							'W', # 
		'gdk_draw_text',							'W', # 
		'gdk_draw_text_wc',							'W', # 
		'gdk_draw_trapezoids',						'W', # 
		'gdk_event_get_graphics_expose',			'W', # 
		'gdk_exit',									'W', # 
		'GdkFillRule',								'W', # 
		'GdkFont',									'W', #
		'gdk_fontset_load',							'W', # 
		'gdk_fontset_load_for_display',				'W', # 
		'GdkFontType',								'W', # 
		'gdk_font_equal',							'W', # 
		'gdk_font_from_description',				'W', # 
		'gdk_font_from_description_for_display',	'W', # 
		'gdk_font_get_display',						'W', # 
		'gdk_font_id',								'W', # 
		'gdk_font_load',							'W', # 
		'gdk_font_load_for_display',				'W', # 
		'gdk_font_lookup',							'W', # 
		'gdk_font_lookup_for_display',				'W', # 
		'gdk_font_ref',								'W', # 
		'gdk_font_unref',							'W', # 
		'gdk_FONT_XDISPLAY',						'W', # 
		'gdk_FONT_XFONT',							'W', # 
		'gdk_free_compound_text',					'W', # 
		'gdk_free_text_list',						'W', # 
		'gdk_gc_copy',								'W', # 
		'gdk_gc_destroy',							'W', #  
		'gdk_gc_get_colormap',						'W', # 
		'gdk_gc_get_screen',						'W', # 
		'gdk_gc_get_values',						'W', # 
		'gdk_gc_new',								'W', # 
		'gdk_gc_new_with_values',					'W', # 
		'gdk_gc_offset',							'W', # 
		'gdk_gc_ref',								'W', # 
		'gdk_gc_set_background',					'W', # 
		'gdk_gc_set_clip_mask',						'W', # 
		'gdk_gc_set_clip_origin',					'W', # 
		'gdk_gc_set_clip_rectangle',				'W', # 
		'gdk_gc_set_clip_region',					'W', # 
		'gdk_gc_set_colormap',						'W', # 
		'gdk_gc_set_dashes',						'W', # 
		'gdk_gc_set_exposures',						'W', # 
		'gdk_gc_set_fill',							'W', # 
		'gdk_gc_set_font',							'W', # 
		'gdk_gc_set_foreground',					'W', # 
		'gdk_gc_set_function',						'W', # Use cairo_set_operator() with Cairo.
		'gdk_gc_set_line_attributes',				'W', # 
		'gdk_gc_set_rgb_bg_color',					'W', # 
		'gdk_gc_set_rgb_fg_color',					'W', # 
		'gdk_gc_set_stipple',						'W', # 
		'gdk_gc_set_subwindow',						'W', # 
		'gdk_gc_set_tile',							'W', # 
		'gdk_gc_set_ts_origin',						'W', # 
		'gdk_gc_set_values',						'W', # 
		'gdk_gc_unref',								'W', # 
		'gdk_get_use_xshm',							'W', # 
		'gdk_image_destroy',						'W', # 
		'gdk_image_get',							'W', # 
		'gdk_image_get_bits_per_pixel',				'W', # 
		'gdk_image_get_bytes_per_line',				'W', # 
		'gdk_image_get_bytes_per_pixel',			'W', # 
		'gdk_image_get_byte_order',					'W', # 
		'gdk_image_get_colormap',					'W', # 
		'gdk_image_get_depth',						'W', # 
		'gdk_image_get_height',						'W', # 
		'gdk_image_get_image_type',					'W', # 
		'gdk_image_get_pixel',						'W', # 
		'gdk_image_get_pixels',						'W', # 
		'gdk_image_get_visual',						'W', # 
		'gdk_image_get_width',						'W', # 
		'gdk_image_new',							'W', # 
		'gdk_image_new_bitmap',						'W', # 
		'gdk_image_put_pixel',						'W', # 
		'gdk_image_ref',							'W', # 
		'gdk_image_set_colormap',					'W', # 
		'gdk_image_unref',							'W', # 
		'gdk_input_add',							'W', # 
		'gdk_input_add_full',						'W', # 
		'gdk_input_remove',							'W', # 
		'gdk_mbstowcs',								'W', # 
		'gdk_net_wm_supports',						'W', # 
		'gdk_pango_context_set_colormap',			'W', # 
		'gdk_pixbuf_render_to_drawable',			'W', # 
		'gdk_pixbuf_render_to_drawable_alpha',		'W', # 
		'gdk_pixmap_colormap_create_from_xpm',		'W', # 
		'gdk_pixmap_colormap_create_from_xpm_d',	'W', # 
		'gdk_pixmap_create_from_data',				'W', # 
		'gdk_pixmap_create_from_xpm',				'W', # 
		'gdk_pixmap_create_from_xpm_d',				'W', # 
		'gdk_pixmap_ref',							'W', # 
		'gdk_pixmap_unref',							'W', # 
		'gdk_region_polygon',						'W', # 
		'gdk_region_rect_equal',					'W', # 
		'gdk_region_shrink',						'W', # 
		'gdk_region_spans_intersect_foreach',		'W', # 
		'GdkRgbCmap',								'W', # 
		'gdk_rgb_cmap_free',						'W', # 
		'gdk_rgb_cmap_new',							'W', # 
		'gdk_rgb_colormap_ditherable',				'W', # 
		'gdk_rgb_ditherable',						'W', # 
		'gdk_rgb_find_color',						'W', # 
		'gdk_rgb_gc_set_background',				'W', # 
		'gdk_rgb_gc_set_foreground',				'W', # 
		'gdk_rgb_get_cmap',							'W', # 
		'gdk_rgb_get_colormap',						'W', # 
		'gdk_rgb_get_visual',						'W', # 
		'gdk_rgb_init',								'W', # 
		'gdk_rgb_set_install',						'W', # 
		'gdk_rgb_set_min_colors',					'W', # 
		'gdk_rgb_set_verbose',						'W', # 
		'gdk_rgb_xpixel_from_rgb',					'W', # 
		'gdk_ROOT_PARENT',							'W', # 
		'gdk_screen_get_rgb_colormap',				'W', # 
		'gdk_screen_get_rgb_visual',				'W', # 
		'GdkSelection',								'W', # 
		'GdkSelectionType',							'W', # 
		'gdk_set_locale',							'W', # 
		'gdk_set_pointer_hooks',					'W', # 
		'gdk_set_sm_client_id',						'W', # 
		'gdk_set_use_xshm',							'W', # 
		'GdkSpanFunc',								'W', # 
		'gdk_spawn_command_line_on_screen',			'W', # 
		'gdk_spawn_on_screen',						'W', # 
		'gdk_spawn_on_screen_with_pipes',			'W', # 
		'gdk_string_extents',						'W', # 
		'gdk_string_height',						'W', # 
		'gdk_string_measure',						'W', # 
		'gdk_string_to_compound_text',				'W', # 
		'gdk_string_to_compound_text_for_display',	'W', # 
		'gdk_string_width',							'W', # 
		'GdkTarget',								'W', # 
		'gdk_text_extents',							'W', # 
		'gdk_text_extents_wc',						'W', # 
		'gdk_text_height',							'W', # 
		'gdk_text_measure',							'W', # 
		'gdk_text_property_to_text_list',				'W', # 
		'gdk_text_property_to_text_list_for_display',	'W', # 
		'gdk_text_property_to_utf8_list',				'W', # 
		'gdk_text_width',								'W', # 
		'gdk_text_width_wc',							'W', # 
		'gdk_threads_mutex',							'W', #  
		'gdk_utf8_to_compound_text',					'W', # 
		'gdk_utf8_to_compound_text_for_display',		'W', # 
		'gdk_visual_ref',								'W', # 
		'gdk_visual_unref',								'W', # 
		'gdk_wcstombs',									'W', # 
		'gdk_window_copy_area',							'W', # 
		'gdk_window_foreign_new',						'W', # 
		'gdk_window_foreign_new_for_display',			'W', # 
		'gdk_window_get_colormap',						'W', # 
		'gdk_window_get_deskrelative_origin',			'W', # 
		'gdk_window_get_size',							'W', # 
		'gdk_window_get_toplevels',						'W', # 
		'gdk_window_get_type',							'W', # 
		'gdk_window_lookup',							'W', # 
		'gdk_window_lookup_for_display',				'W', # 
		'gdk_window_ref',								'W', # 
		'gdk_window_set_colormap',						'W', # 
		'gdk_window_set_hints',							'W', # 
		'gdk_window_unref',								'W', # 
		'gdk_x11_font_get_name',						'W', # 
		'gdk_x11_font_get_xdisplay',					'W', # 
		'gdk_x11_font_get_xfont',						'W', # 
		'gdk_x11_gc_get_xdisplay',						'W', # 
		'gdk_x11_gc_get_xgc',							'W', # 
		'gdk_xid_table_lookup',							'W', # 
		'gdk_xid_table_lookup_for_display',				'W', # 
		'gdkx_colormap_get',							'W', # 
		'gdkx_visual_get',								'W', # 

);

@{$APIs{'deprecated-gtk'}->{'functions'}}      = grep {$deprecatedGtkFunctions{$_} eq 'E'} keys %deprecatedGtkFunctions;
@{$APIs{'deprecated-gtk-todo'}->{'functions'}} = grep {$deprecatedGtkFunctions{$_} eq 'W'} keys %deprecatedGtkFunctions;



# Given a ref to a hash containing "functions" and "functions_count" entries:
# Determine if the any of the list of APIs contained in the array referenced by "functions"
# exists in the file.
# For each API which appears in the file:
#     Push the API onto the provided list;
#     Add the number of times the API appears in the file to the total count
#      for the API (stored as the value of the API key in the hash referenced by "function_counts").

sub findAPIinFile($$$)
{
	my ($groupHashRef, $fileContentsRef, $foundAPIsRef) = @_;

	for my $api ( @{$groupHashRef->{functions}} )
	{
		my $cnt = 0;
		while (${$fileContentsRef} =~ m/ \W $api \W* \( /gx)
		{
			$cnt += 1;
		}
		if ($cnt > 0) {
			push @{$foundAPIsRef}, $api;
			$groupHashRef->{function_counts}->{$api} += 1;
		}
	}
}

# APIs which (generally) should not be called with an argument of tvb_get_ptr()
my @TvbPtrAPIs = (
	# Use NULL for the value_ptr instead of tvb_get_ptr() (only if the
	# given offset and length are equal) with these:
	'proto_tree_add_bytes_format',
	'proto_tree_add_bytes_format_value',
	# Use the tvb_* version of these:
	'ether_to_str',
	'ip_to_str',
	'ip6_to_str',
	'fc_to_str',
	'fcwwn_to_str',
	# Use tvb_bytes_to_str[_punct] instead of:
	'bytes_to_str',
	'bytes_to_str_punct',
);

sub checkAPIsCalledWithTvbGetPtr($$$)
{
	my ($APIs, $fileContentsRef, $foundAPIsRef) = @_;

	for my $api (@{$APIs}) {
		my @items;
		my $cnt = 0;

		@items = (${$fileContentsRef} =~ m/($api[^;]*;)/sg);
		while (@items) {
			my ($item) = @items;
			shift @items;
			if ($item =~ /tvb_get_ptr/xos) {
				$cnt += 1;
			}
		}

		if ($cnt > 0) {
			push @{$foundAPIsRef}, $api;
		}
	}
}

# Verify that all declared ett_ variables are registered.
# Don't bother trying to check usage (for now)...
sub check_ett_registration($$)
{
	my ($fileContentsRef, $filename) = @_;
	my @ett_declarations;
	my %ett_registrations;
	my @unRegisteredEtts;

	# A pattern to match ett variable names.  Obviously this assumes that
	# they start with ett_
	my $EttVarName = qr{ (?: ett_[a-z0-9_]+ (?:\[[0-9]+\])? ) }xi;

	# Remove macro lines
	my $fileContents = ${$fileContentsRef};
	$fileContents =~ s { ^\s*\#.*$} []xogm;

	# Find all the ett_ variables declared in the file
	@ett_declarations = ($fileContents =~ m{
		^\s*static		# assume declarations are on their own line
		\s+
		g?int			# could be int or gint
		\s+
		($EttVarName)		# variable name
		\s*=\s*
		-1\s*;
	}xgiom);

	if (!@ett_declarations) {
		print "Found no etts in ".$filename."\n";
		return;
	}

	#print "Found these etts in ".$filename.": ".join(',', @ett_declarations)."\n\n";

	# Find the array used for registering the etts
	# Save off the block of code containing just the variables
	my @reg_blocks;
	@reg_blocks = ($fileContents =~ m{
		static
		\s+
		g?int
		\s*\*\s*		# it's an array of pointers
		[a-z0-9_]+		# array name; usually (always?) "ett"
		\s*\[\s*\]\s*		# array brackets
		=
		\s*\{
		((?:\s*&\s*		# address of the following variable
		$EttVarName		# variable name
		\s*,?			# the comma is optional (for the last entry)
		\s*)+)			# match one or more variable names
		\}
		\s*
		;
	}xgios);
	#print "Found this ett registration block in ".$filename.": ".join(',', @reg_blocks)."\n";

	if (@reg_blocks == 0) {
		print "Hmm, found ".@reg_blocks." ett registration blocks in ".$filename."\n";
		# For now...
		return;
	}

	while (@reg_blocks) {
		my ($block) = @reg_blocks;
		shift @reg_blocks;

		# Convert the list returned by the match into a hash of the
		# form ett_variable_name -> 1.  Then combine this new hash with
		# the hash from the last registration block.
		# (Of course) using hashes makes the lookups much faster.
		%ett_registrations = map { $_ => 1 } ($block =~ m{
			\s*&\s*			# address of the following variable
			($EttVarName)		# variable name
			\s*,?			# the comma is optional (for the last entry)
		}xgios, %ett_registrations);
	}
	#print "Found these ett registrations in ".$filename.": ";
	#while( my ($k, $v) = each %ett_registrations ) {
	#          print "$k\n";
	#}

	# Find which declared etts are not registered.
	# XXX - using <@ett_declarations> and $_ instead of $ett_var makes this
	# MUCH slower...  Why?
	while (@ett_declarations) {
		my ($ett_var) = @ett_declarations;
		shift @ett_declarations;

		push(@unRegisteredEtts, $ett_var) if (!$ett_registrations{$ett_var});
	}

	if (@unRegisteredEtts) {
		print STDERR "Error: found these unregistered ett variables in ".$filename.": ".join(',', @unRegisteredEtts)."\n";
	}

}

# Given the file contents and a file name, check all of the hf entries for
# various problems (such as those checked for in proto.c).
sub check_hf_entries($$)
{
	my ($fileContentsRef, $filename) = @_;
	my $errorCount = 0;

	my @items;
	@items = (${$fileContentsRef} =~ m{
				  \{
				  \s*
				  &\s*([A-Z0-9_\[\]-]+)		# &hf
				  \s*,\s*
				  \{\s*
				  ("[A-Z0-9 '\./\(\)_:-]+")	# name
				  \s*,\s*
				  (NULL|"[A-Z0-9_\.-]*")	# abbrev
				  \s*,\s*
				  (FT_[A-Z0-9_]+)		# field type
				  \s*,\s*
				  ([A-Z0-9x\|_]+)		# display
				  \s*,\s*
				  ([A-Z0-9&_\(\)' -]+)		# convert
				  \s*,\s*
				  ([A-Z0-9_]+)			# bitmask
				  \s*,\s*
				  (NULL|"[A-Z0-9 '\./\(\)\?_:-]+")	# blurb	(NULL or a string)
				  \s*,\s*
				  HFILL				# HFILL
	}xgios);

	#print "Found @items items\n";
	while (@items) {
		my ($hf, $name, $abbrev, $ft, $display, $convert, $bitmask, $blurb) = @items;
		shift @items; shift @items; shift @items; shift @items; shift @items; shift @items; shift @items; shift @items;

		#print "name=$name, abbrev=$abbrev, ft=$ft, display=$display, convert=$convert, bitmask=$bitmask, blurb=$blurb\n";

		if ($abbrev eq '""' || $abbrev eq "NULL") {
			print STDERR "Error: field $name does not have an abbreviation in $filename\n";
			$errorCount++;
		}
		if ($abbrev =~ m/\.\.+/) {
			print STDERR "Error: the abbreviation for field $name ($abbrev) contains two or more sequential periods in $filename\n";
			$errorCount++;
		}
		if ($name eq $abbrev) {
			print STDERR "Error: the abbreviation for field $name matches the field name in $filename\n";
			$errorCount++;
		}
		if (lc($name) eq lc($blurb)) {
			print STDERR "Error: the blurb for field $name ($abbrev) matches the field name in $filename\n";
			$errorCount++;
		}
		if ($name =~ m/"\s+/) {
			print STDERR "Error: the name for field $name ($abbrev) has leading space in $filename\n";
			$errorCount++;
		}
		if ($name =~ m/\s+"/) {
			print STDERR "Error: the name for field $name ($abbrev) has trailing space in $filename\n";
			$errorCount++;
		}
		if ($blurb =~ m/"\s+/) {
			print STDERR "Error: the blurb for field $name ($abbrev) has leading space in $filename\n";
			$errorCount++;
		}
		if ($blurb =~ m/\s+"/) {
			print STDERR "Error: the blurb for field $name ($abbrev) has trailing space in $filename\n";
			$errorCount++;
		}
		if ($abbrev =~ m/\s+/) {
			print STDERR "Error: the abbreviation for field $name ($abbrev) has white space in $filename\n";
			$errorCount++;
		}
		if ("\"".$hf ."\"" eq $name) {
			print STDERR "Error: name is the hf_variable_name in field $name ($abbrev) in $filename\n";
			$errorCount++;
		}
		if ("\"".$hf ."\"" eq $abbrev) {
			print STDERR "Error: abbreviation is the hf_variable_name in field $name ($abbrev) in $filename\n";
			$errorCount++;
		}
	}

	return $errorCount;
}

# The below Regexp are based on those from:
# http://aspn.activestate.com/ASPN/Cookbook/Rx/Recipe/59811
# They are in the public domain.

# 1. A complicated regex which matches C-style comments.
my $CComment = qr{ / [*] [^*]* [*]+ (?: [^/*] [^*]* [*]+ )* / }x;

# 1.a A regex that matches C++-style comments.
#my $CppComment = qr{ // (.*?) \n }x;

# 2. A regex which matches double-quoted strings.
#    ?s added so that strings containing a 'line continuation'
#    ( \ followed by a new-line) will match.
my $DoubleQuotedStr = qr{ (?: ["] (?s: \\. | [^\"\\])* ["]) }x;

# 3. A regex which matches single-quoted strings.
my $SingleQuotedStr = qr{ (?: \' (?: \\. | [^\'\\])* [']) }x;

# 4. Now combine 1 through 3 to produce a regex which
#    matches _either_ double or single quoted strings
#    OR comments. We surround the comment-matching
#    regex in capturing parenthesis to store the contents
#    of the comment in $1.
#    my $commentAndStringRegex = qr{(?:$DoubleQuotedStr|$SingleQuotedStr)|($CComment)|($CppComment)};

# 4. Wireshark is strictly a C program so don't take out C++ style comments
#    since they shouldn't be there anyway...
#    Also: capturing the comment isn't necessary.
my $commentAndStringRegex = qr{ (?: $DoubleQuotedStr | $SingleQuotedStr | $CComment) }x;

#### Regex for use when searching for value-string definitions
my $StaticRegex		    = qr/ static \s+								/xs;
my $ConstRegex		    = qr/ const  \s+								/xs;
my $Static_andor_ConstRegex = qr/ (?: $StaticRegex $ConstRegex | $StaticRegex | $ConstRegex)		/xs;
my $ValueStringRegex	    = qr/ $Static_andor_ConstRegex value_string \ + [^;*]+ = [^;]+ [{] [^;]+ ;	/xs;

#
# MAIN
#
my $errorCount = 0;
# The default list, which can be expanded.
my @apiGroups = qw(prohibited deprecated);
my @apiSummaryGroups = ();
my $check_value_string_array_null_termination = 1;	# default: enabled
my $machine_readable_output = 0;			# default: disabled
my $check_hf = 1;					# default: enabled
my $debug_flag = 0;

my $result = GetOptions(
			'group=s' => \@apiGroups,
			'summary-group=s' => \@apiSummaryGroups,
			'check-value-string-array-null-termination!' => \$check_value_string_array_null_termination,
			'Machine-readable' => \$machine_readable_output,
			'nohf' => \$check_hf,
			'debug' => \$debug_flag
			);
if (!$result) {
	print "Usage: checkAPIs.pl [-M] [-g group1] [-g group2] ... [-s group1] [-s group2] ... [--nocheck-value-string-array-null-termination] file1 file2 ..\n";
	print "       -g <group>:  Check input files for use of APIs in <group> (in addition to the default groups)\n";
	print "       -s <group>:  Output summary (count) for each API in <group> (-g <group> also req'd)\n";
	print "       -M: Generate output for -g in 'machine-readable' format\n";
	print "\n";
	print "   Default Groups[-g]: ", join (", ", sort @apiGroups), "\n";
	print "   Available Groups:   ", join (", ", sort keys %APIs), "\n";
	exit(1);
}

# Add a 'function_count' anonymous hash to each of the 'apiGroup' entries in the %APIs hash.
for my $apiGroup (keys %APIs) {
	my @functions = @{$APIs{$apiGroup}{functions}};

	$APIs{$apiGroup}->{function_counts}   = {};
	@{$APIs{$apiGroup}->{function_counts}}{@functions} = ();  # Add fcn names as keys to the anonymous hash
}


# Read through the files; do various checks
while ($_ = $ARGV[0])
{
	shift;
	my $filename = $_;
	my $fileContents = '';
	my @foundAPIs = ();
	my $line;

	die "No such file: \"$filename\"" if (! -e $filename);

	# delete leading './'
	$filename =~ s{ ^ \. / } {}xo;

	# Read in the file (ouch, but it's easier that way)
	open(FC, $filename) || die("Couldn't open $filename");
	$line = 1;
	while (<FC>) {
		$fileContents .= $_;
		if ($_ =~ m{ [\x80-\xFF] }xo) {
			print STDERR "Error: Found non-ASCII characters on line " .$line. " of " .$filename."\n";
			$errorCount++;
		}
		$line++;
	}
	close(FC);

	if ($fileContents =~ m{ %ll }xo)
	{
		# use G_GINT64_MODIFIER instead of ll
		print STDERR "Error: Found %ll in " .$filename."\n";
		$errorCount++;
	}
	if ($fileContents =~ m{ %hh }xo)
	{
		# %hh is C99 and Windows doesn't like it:
		# http://connect.microsoft.com/VisualStudio/feedback/details/416843/sscanf-cannot-not-handle-hhd-format
		# Need to use temporary variables instead.
		print STDERR "Error: Found %hh in " .$filename."\n";
		$errorCount++;
	}

	if (! ($fileContents =~ m{ \$Id .* \$ }xo))
	{
		print STDERR "Warning: ".$filename." does not have an SVN Id tag.\n";
	}

	# optionally check the hf entries
	if ($check_hf) {
		$errorCount += check_hf_entries(\$fileContents, $filename);
	}

	# Remove all the C-comments and strings
	$fileContents =~ s {$commentAndStringRegex} []xog;

	#check_ett_registration(\$fileContents, $filename);

	if ($fileContents =~ m{ // }xo)
	{
		print STDERR "Error: Found C++ style comments in " .$filename."\n";
		$errorCount++;
	}

	#checkAPIsCalledWithTvbGetPtr(\@TvbPtrAPIs, \$fileContents, \@foundAPIs);

	#if (@foundAPIs) {
	#	print STDERR "Found APIs with embedded tvb_get_ptr() calls in ".$filename.": ".join(',', @foundAPIs)."\n"
	#}

	# Brute force check for value_string arrays which are missing {0, NULL} as the final (terminating) array entry
	if ($check_value_string_array_null_termination) {
		#  Assumption: definition is of form (pseudo-Regex):
		#    " (static const|static|const) value_string .+ = { .+ ;" (possibly over multiple lines)
		while ($fileContents =~ / ( $ValueStringRegex ) /xsog) {
			# value_string array definition found; check if NULL terminated
			my $vs = my $vsx = $1;
			if ($debug_flag) {
				$vsx =~ / ( .+ value_string [^=]+ ) = /xo;
				printf STDERR "==> %-35.35s: %s\n", $filename, $1;
				printf STDERR "%s\n", $vs;
			}
			$vs =~ s{ \s } {}xg;
			# README.developer says
			#  "Don't put a comma after the last tuple of an initializer of an array"
			# However: since this usage is present in some number of cases, we'll allow for now
			if ($vs !~ / , NULL [}] ,? [}] ; $/xo) {
				$vsx =~ /( value_string [^=]+ ) = /xo;
				printf STDERR "Error: %-35.35s: {0, NULL} is required as the last value_string array entry: %s\n", $filename, $1;
				$errorCount++;
			}
			if ($vs !~ / (static)? const value_string /xo)  {
				$vsx =~ /( value_string [^=]+ ) = /xo;
				printf STDERR "Error: %-35.35s: Missing 'const': %s\n", $filename, $1;
				$errorCount++;
			}
		}
	}

	# Check and count APIs
	for my $apiGroup (@apiGroups) {
		my $pfx = "Warning";
		@foundAPIs = ();

		findAPIinFile($APIs{$apiGroup}, \$fileContents, \@foundAPIs);

		if ($APIs{$apiGroup}->{count_errors}) {
			# the use of "prohibited" APIs is an error, increment the error count
			$errorCount += @foundAPIs;
			$pfx = "Error";
		}

		if (@foundAPIs && ! $machine_readable_output) {
			print STDERR $pfx . ": Found " . $apiGroup . " APIs in ".$filename.": ".join(',', @foundAPIs)."\n";
		}
		if (@foundAPIs && $machine_readable_output) {
			for my $api (@foundAPIs) {
				printf STDERR "%-8.8s %-20.20s %-30.30s %-45.45s\n", $pfx, $apiGroup, $filename, $api;
			}
		}
	}
}

# Summary: Print Use Counts of each API in each requested summary group

for my $apiGroup (@apiSummaryGroups) {
	printf "\n\nUse Counts\n";
	for my $api (sort {"\L$a" cmp "\L$b"} (keys %{$APIs{$apiGroup}->{function_counts}}   )) {
		printf "%-20.20s %5d  %-40.40s\n", $apiGroup . ':', $APIs{$apiGroup}{function_counts}{$api}, $api;
	}
}

exit($errorCount);

