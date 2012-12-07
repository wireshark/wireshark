/* display_filter_combo.cpp
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>

#include "qt_ui_utils.h"
#include "ui/recent.h"

#include <epan/prefs.h>

#include "display_filter_edit.h"
#include "display_filter_combo.h"
#include "wireshark_application.h"

#include <QCompleter>

// If we ever add support for multiple windows this will need to be replaced.
static DisplayFilterCombo *cur_display_filter_combo = NULL;

DisplayFilterCombo::DisplayFilterCombo(QWidget *parent) :
    QComboBox(parent)
{
    setEditable(true);
    setLineEdit(new DisplayFilterEdit());
    setSizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::Fixed);
    setAccessibleName(tr("Display filter selector"));
    cur_display_filter_combo = this;
    setStyleSheet(
            "QComboBox {"
#ifdef Q_WS_MAC
            "  border: 1px solid gray;"
#else
            "  border: 1px solid palette(shadow);"
#endif
            "  border-radius: 3px;"
            "  padding: 0px 0px 0px 0px;"
            "  margin-left: 0px;"
            "  min-width: 20em;"
            " }"

            "QComboBox::drop-down {"
            "  subcontrol-origin: padding;"
            "  subcontrol-position: top right;"
            "  width: 16px;"
            "  border-left-width: 0px;"
            " }"

            "QComboBox::down-arrow {"
            "  image: url(:/dfilter/dfilter_dropdown.png);"
            " }"

            "QComboBox::down-arrow:on { /* shift the arrow when popup is open */"
            "  top: 1px;"
            "  left: 1px;"
            "}"
            );
    completer()->setCompletionMode(QCompleter::PopupCompletion);

    connect(wsApp, SIGNAL(updatePreferences()), this, SLOT(updateMaxCount()));
}

extern "C" void dfilter_recent_combo_write_all(FILE *rf) {
    if (!cur_display_filter_combo)
        return;

    cur_display_filter_combo->writeRecent(rf);
}

void DisplayFilterCombo::writeRecent(FILE *rf) {
    int i;
    const char *filter_str;

    for (i = 0; i < count(); i++) {
        filter_str = itemText(i).toUtf8().constData();
        if(filter_str && strlen(filter_str) > 0) {
            fprintf(rf, RECENT_KEY_DISPLAY_FILTER ": %s\n", filter_str);
        }
    }
}

void DisplayFilterCombo::applyDisplayFilter()
{
    DisplayFilterEdit *df_edit = qobject_cast<DisplayFilterEdit *>(lineEdit());

    if (df_edit) df_edit->applyDisplayFilter();
}

void DisplayFilterCombo::updateMaxCount()
{
    setMaxCount(prefs.gui_recent_df_entries_max);
}

extern "C" gboolean dfilter_combo_add_recent(gchar *filter) {
    if (!cur_display_filter_combo)
        return FALSE;

    cur_display_filter_combo->addItem(filter);
    cur_display_filter_combo->clearEditText();
    return TRUE;
}


// xxx - Move to an as-yet-to-be-written capture filter module along with ::addRecentCapture and ::writeRecentCapture
QList<QString> cfilters;

extern "C" gboolean cfilter_combo_add_recent(gchar *filter) {
    cfilters.append(filter);
    return TRUE;
}

extern "C" void cfilter_combo_recent_write_all(FILE *rf) {
    QString cfilter;

    foreach (cfilter, cfilters) {
        fprintf (rf, RECENT_KEY_CAPTURE_FILTER ": %s\n", cfilter.toUtf8().constData());
    }
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
