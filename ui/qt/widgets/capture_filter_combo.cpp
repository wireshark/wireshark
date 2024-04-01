/* capture_filter_combo.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>

#include <ui/qt/utils/qt_ui_utils.h>
#include "ui/recent_utils.h"
#include "ui/recent.h"

#include <epan/prefs.h>

#include <ui/qt/widgets/capture_filter_combo.h>
#include <ui/qt/utils/color_utils.h>
#include "main_application.h"

CaptureFilterCombo::CaptureFilterCombo(QWidget *parent, bool plain) :
    QComboBox(parent),
    cf_edit_(NULL)
{
    cf_edit_ = new CaptureFilterEdit(this, plain);

    setEditable(true);
    setLineEdit(cf_edit_);
    // setLineEdit will create a new QCompleter that performs inline completion,
    // be sure to disable that since our CaptureFilterEdit performs its own
    // popup completion. As QLineEdit's completer is designed for full line
    // completion, we cannot reuse it for word completion.
    setCompleter(0);
    // Default is Preferred.
    setSizePolicy(QSizePolicy::MinimumExpanding, sizePolicy().verticalPolicy());
    setInsertPolicy(QComboBox::NoInsert);
    setAccessibleName(tr("Capture filter selector"));
    updateStyleSheet();

    connect(this, &CaptureFilterCombo::interfacesChanged, cf_edit_,
            static_cast<void (CaptureFilterEdit::*)()>(&CaptureFilterEdit::checkFilter));
    connect(cf_edit_, &CaptureFilterEdit::captureFilterSyntaxChanged,
            this, &CaptureFilterCombo::captureFilterSyntaxChanged);
    connect(cf_edit_, &CaptureFilterEdit::startCapture, this, &CaptureFilterCombo::startCapture);
    connect(cf_edit_, &CaptureFilterEdit::startCapture, this, &CaptureFilterCombo::saveAndRebuildFilterList);
    connect(mainApp, &MainApplication::appInitialized, this, &CaptureFilterCombo::rebuildFilterList);
    connect(mainApp, &MainApplication::preferencesChanged, this, &CaptureFilterCombo::rebuildFilterList);

    rebuildFilterList();
    clearEditText();
}

void CaptureFilterCombo::writeRecent(FILE *rf)
{
    int i;

    for (i = 0; i < count(); i++) {
        const QByteArray& filter = itemText(i).toUtf8();
        if (!filter.isEmpty()) {
            fprintf(rf, RECENT_KEY_DISPLAY_FILTER ": %s\n", filter.constData());
        }
    }
}

bool CaptureFilterCombo::event(QEvent *event)
{
    switch (event->type()) {
    case QEvent::ApplicationPaletteChange:
        updateStyleSheet();
        break;
    default:
        break;
    }
    return QComboBox::event(event);
}

void CaptureFilterCombo::updateStyleSheet()
{
    const char *display_mode = ColorUtils::themeIsDark() ? "dark" : "light";

    QString ss = QString(
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
                "  image: url(:/stock_icons/14x14/x-filter-dropdown.%1.png);"
                " }"

                "QComboBox::down-arrow:on { /* shift the arrow when popup is open */"
                "  top: 1px;"
                "  left: 1px;"
                "}"
                ).arg(display_mode);
    setStyleSheet(ss);
}

void CaptureFilterCombo::saveAndRebuildFilterList()
{
    if (!currentText().isEmpty()) {
        recent_add_cfilter(NULL, currentText().toUtf8().constData());
    }
    rebuildFilterList();
}

void CaptureFilterCombo::rebuildFilterList()
{
    lineEdit()->blockSignals(true);
    GList *cfilter_list = recent_get_cfilter_list(NULL);
    QString cur_filter = currentText();
    clear();
    for (GList *li = g_list_first(cfilter_list); li != NULL; li = gxx_list_next(li)) {
        addItem(gxx_list_data(const char *, li));
    }
    lineEdit()->setText(cur_filter);
    lineEdit()->blockSignals(false);
}
