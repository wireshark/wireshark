/* display_filter_combo.cpp
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
#include "ui/recent_utils.h"
#include "ui/recent.h"

#include <epan/prefs.h>

#include <QHelpEvent>
#include <QStyleOptionComboBox>

#include "display_filter_edit.h"
#include "display_filter_combo.h"
#include "wireshark_application.h"

// If we ever add support for multiple windows this will need to be replaced.
static DisplayFilterCombo *cur_display_filter_combo = NULL;

DisplayFilterCombo::DisplayFilterCombo(QWidget *parent) :
    QComboBox(parent)
{
    setEditable(true);
    // Enabling autocompletion here gives us two simultaneous completions:
    // Inline (highlighted text) for entire filters, handled here and popup
    // completion for fields handled by DisplayFilterEdit.
    setAutoCompletion(false);
    setLineEdit(new DisplayFilterEdit(this, DisplayFilterToApply));
    setSizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::Fixed);
    setAccessibleName(tr("Display filter selector"));
    cur_display_filter_combo = this;
    setStyleSheet(
            "QComboBox {"
#ifdef Q_OS_MAC
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
            "  width: 14px;"
            "  border-left-width: 0px;"
            " }"

            "QComboBox::down-arrow {"
            "  image: url(:/icons/toolbar/14x14/x-filter-dropdown.png);"
            " }"

            "QComboBox::down-arrow:on { /* shift the arrow when popup is open */"
            "  top: 1px;"
            "  left: 1px;"
            "}"
            );
    setToolTip(tr("Select from previously used filters."));

    connect(wsApp, SIGNAL(preferencesChanged()), this, SLOT(updateMaxCount()));
}

extern "C" void dfilter_recent_combo_write_all(FILE *rf) {
    if (!cur_display_filter_combo)
        return;

    cur_display_filter_combo->writeRecent(rf);
}

void DisplayFilterCombo::writeRecent(FILE *rf) {
    int i;

    for (i = 0; i < count(); i++) {
        const QByteArray& filter = itemText(i).toUtf8();
        if (!filter.isEmpty()) {
            fprintf(rf, RECENT_KEY_DISPLAY_FILTER ": %s\n", filter.constData());
        }
    }
}

bool DisplayFilterCombo::event(QEvent *event)
{
    switch (event->type()) {
    case QEvent::ToolTip:
    {
        // Only show a tooltip for the arrow.
        QHelpEvent *he = (QHelpEvent *) event;
        QStyleOptionComboBox opt;
        initStyleOption(&opt);
        QRect scr = style()->subControlRect(QStyle::CC_ComboBox, &opt, QStyle::SC_ComboBoxArrow, this);
        if (!scr.contains(he->pos())) {
            return false;
        }
        break;
    }
    default:
        break;
    }
    return QComboBox::event(event);
}

bool DisplayFilterCombo::checkDisplayFilter()
{
    DisplayFilterEdit *df_edit = qobject_cast<DisplayFilterEdit *>(lineEdit());
    bool state = false;

    if (df_edit) state = df_edit->checkFilter();
    return state;
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

extern "C" gboolean dfilter_combo_add_recent(const gchar *filter) {
    if (!cur_display_filter_combo)
        return FALSE;

    // Adding an item to a QComboBox also sets its lineEdit. In our case
    // that means we might trigger a temporary status message so we block
    // the lineEdit's signals.
    // Another approach would be to update QComboBox->model directly.
    bool block_state = cur_display_filter_combo->lineEdit()->blockSignals(true);
    cur_display_filter_combo->addItem(filter);
    cur_display_filter_combo->clearEditText();
    cur_display_filter_combo->lineEdit()->blockSignals(block_state);
    return TRUE;
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
