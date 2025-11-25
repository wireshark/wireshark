/** @file
 *
 * Macros for plot graph UAT items
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PLOT_GRAPH_UAT_H__
#define __PLOT_GRAPH_UAT_H__

UAT_BOOL_CB_DEF(plot, enabled, plot_settings_t)
UAT_DEC_CB_DEF(plot, group, plot_settings_t)
UAT_CSTRING_CB_DEF(plot, name, plot_settings_t)
UAT_DISPLAY_FILTER_CB_DEF(plot, dfilter, plot_settings_t)
UAT_COLOR_CB_DEF(plot, color, plot_settings_t)
UAT_VS_DEF(plot, style, plot_settings_t, uint32_t, 0, "Line")
UAT_PROTO_FIELD_CB_DEF(plot, yfield, plot_settings_t)
UAT_DBL_CB_DEF(plot, y_axis_factor, plot_settings_t)

#endif /* __PLOT_GRAPH_UAT_H__ */
