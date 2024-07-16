/* display_filter_combo.cpp
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

#include <QHelpEvent>
#include <QStyleOptionComboBox>
#include <QStandardItemModel>
#include <QDateTime>

#include <ui/qt/widgets/display_filter_edit.h>
#include <ui/qt/widgets/display_filter_combo.h>
#include <ui/qt/utils/color_utils.h>
#include "main_application.h"

// If we ever add support for multiple windows this will need to be replaced.
static DisplayFilterCombo *cur_display_filter_combo;

DisplayFilterCombo::DisplayFilterCombo(QWidget *parent) :
    QComboBox(parent)
{
    setEditable(true);
    setLineEdit(new DisplayFilterEdit(this, DisplayFilterToApply));
    // setLineEdit will create a new QCompleter that performs inline completion,
    // be sure to disable that since our DisplayFilterEdit performs its own
    // popup completion. As QLineEdit's completer is designed for full line
    // completion, we cannot reuse it for word completion.
    setCompleter(0);
    // When the combobox menu is not entirely populated, pressing Enter would
    // normally append entries to the end. However, before doing so it moves the
    // cursor position to the end of the field which breaks the completer.
    // Therefore disable this and rely on dfilter_combo_add_recent being called.
    setInsertPolicy(QComboBox::NoInsert);
    // Default is Preferred.
    setSizePolicy(QSizePolicy::MinimumExpanding, sizePolicy().verticalPolicy());
    setAccessibleName(tr("Display filter selector"));
    cur_display_filter_combo = this;
    updateStyleSheet();
    setToolTip(tr("Select from previously used filters."));

    QStandardItemModel *model = qobject_cast<QStandardItemModel*>(this->model());
    model->setSortRole(Qt::UserRole);

    connect(mainApp, &MainApplication::preferencesChanged, this, &DisplayFilterCombo::updateMaxCount);
    // Ugly cast required (?)
    // https://stackoverflow.com/questions/16794695/connecting-overloaded-signals-and-slots-in-qt-5
    connect(this, static_cast<void (DisplayFilterCombo::*)(int)>(&DisplayFilterCombo::activated), this, &DisplayFilterCombo::onActivated);
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

void DisplayFilterCombo::onActivated(int row)
{
    /* Update the row timestamp and resort list. */
    QStandardItemModel *m = qobject_cast<QStandardItemModel*>(this->model());
    QModelIndex idx = m->index(row, 0);
    m->setData(idx, QVariant(QDateTime::currentMSecsSinceEpoch()), Qt::UserRole);
    m->sort(0, Qt::DescendingOrder);
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
    case QEvent::ApplicationPaletteChange:
        updateStyleSheet();
        break;
    default:
        break;
    }
    return QComboBox::event(event);
}

void DisplayFilterCombo::updateStyleSheet()
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

void DisplayFilterCombo::setDisplayFilter(QString filter)
{
    lineEdit()->setText(filter);
    lineEdit()->setFocus();
}

void DisplayFilterCombo::updateMaxCount()
{
    setMaxCount(prefs.gui_recent_df_entries_max);
}

extern "C" bool dfilter_combo_add_recent(const char *filter) {
    if (!cur_display_filter_combo)
        return false;

    // Adding an item to a QComboBox also sets its lineEdit. In our case
    // that means we might trigger a temporary status message so we block
    // the lineEdit's signals.
    // Another approach would be to update QComboBox->model directly.
    bool block_state = cur_display_filter_combo->lineEdit()->blockSignals(true);
    cur_display_filter_combo->addItem(filter, QVariant(QDateTime::currentMSecsSinceEpoch()));
    cur_display_filter_combo->clearEditText();
    cur_display_filter_combo->lineEdit()->blockSignals(block_state);
    return true;
}
