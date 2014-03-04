/* capture_filter_combo.cpp
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

#include "capture_filter_combo.h"
#include "wireshark_application.h"

#include <QCompleter>

CaptureFilterCombo::CaptureFilterCombo(QWidget *parent) :
    QComboBox(parent),
    cf_edit_(NULL)
{
    cf_edit_ = new CaptureFilterEdit();

    setEditable(true);
    setLineEdit(cf_edit_);
    setSizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::Fixed);
    setInsertPolicy(QComboBox::NoInsert);
    setAccessibleName(tr("Capture filter selector"));
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

    connect(this, SIGNAL(interfacesChanged()), cf_edit_, SLOT(checkFilter()));
    connect(cf_edit_, SIGNAL(pushFilterSyntaxStatus(QString&)),
            this, SIGNAL(pushFilterSyntaxStatus(QString&)));
    connect(cf_edit_, SIGNAL(popFilterSyntaxStatus()),
            this, SIGNAL(popFilterSyntaxStatus()));
    connect(cf_edit_, SIGNAL(captureFilterSyntaxChanged(bool)),
            this, SIGNAL(captureFilterSyntaxChanged(bool)));
    connect(cf_edit_, SIGNAL(startCapture()), this, SIGNAL(startCapture()));
    connect(cf_edit_, SIGNAL(startCapture()), this, SLOT(rebuildFilterList()));
    connect(wsApp, SIGNAL(appInitialized()), this, SLOT(rebuildFilterList()));
    connect(wsApp, SIGNAL(preferencesChanged()), this, SLOT(rebuildFilterList()));

    rebuildFilterList(false);
    clearEditText();
}

void CaptureFilterCombo::writeRecent(FILE *rf) {
    int i;
    const char *filter_str;

    for (i = 0; i < count(); i++) {
        filter_str = itemText(i).toUtf8().constData();
        if(filter_str && strlen(filter_str) > 0) {
            fprintf(rf, RECENT_KEY_DISPLAY_FILTER ": %s\n", filter_str);
        }
    }
}

void CaptureFilterCombo::rebuildFilterList(bool insert_edit_text)
{
    GList *cfilter_list = recent_get_cfilter_list(NULL);
    QString cur_filter = currentText();

    if (insert_edit_text && !currentText().isEmpty()) {
        recent_add_cfilter(NULL, currentText().toUtf8().constData());
    }

    clear();
    for (GList *li = g_list_first(cfilter_list); li != NULL; li = g_list_next(li)) {
        insertItem(0, (const gchar *) li->data);
    }
    setEditText(cur_filter);
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
