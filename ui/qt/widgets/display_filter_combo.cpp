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

static QStandardItemModel *cur_model;

extern "C" void dfilter_recent_combo_write_all(FILE *rf) {
    if (cur_model == nullptr)
        return;

    for (int i = 0; i < cur_model->rowCount(); i++ ) {
        const QByteArray& filter = cur_model->item(i)->text().toUtf8();
        if (!filter.isEmpty()) {
            fprintf(rf, RECENT_KEY_DISPLAY_FILTER ": %s\n", filter.constData());
        }
    }
}

extern "C" bool dfilter_combo_add_recent(const char *filter) {
    if (cur_model == nullptr) {
        cur_model = new QStandardItemModel();
        cur_model->setSortRole(Qt::UserRole);
    }

    QStandardItem *new_item = new QStandardItem(filter);
    new_item->setData(QVariant(QDateTime::currentMSecsSinceEpoch()), Qt::UserRole);
    cur_model->appendRow(new_item);
    return true;
}

DisplayFilterCombo::DisplayFilterCombo(QWidget *parent) :
    QComboBox(parent)
{
    setEditable(true);
    DisplayFilterEdit *dfe = new DisplayFilterEdit(this, DisplayFilterToApply);
    setLineEdit(dfe);
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
    updateStyleSheet();
    setToolTip(tr("Select from previously used filters."));

#if QT_VERSION >= QT_VERSION_CHECK(5, 15, 0)
    // Setting the placeholderText keeps newly added items from being the
    // current item. It only works for the placeholderText of the QComboBox,
    // not the lineEdit (even though the lineEdit's placeholderText is shown
    // instead.) This only matters for any combobox created before the recent
    // display filter list is read (i.e., the main window one.)
    setPlaceholderText(dfe->placeholderText());
#endif

    if (cur_model == nullptr) {
        cur_model = new QStandardItemModel();
        cur_model->setSortRole(Qt::UserRole);
    }
    setModel(cur_model);

    connect(mainApp, &MainApplication::preferencesChanged, this, &DisplayFilterCombo::updateMaxCount);
    connect(dfe, &DisplayFilterEdit::filterPackets, this, &DisplayFilterCombo::filterApplied);

#if QT_VERSION < QT_VERSION_CHECK(5, 15, 0)
    connect(cur_model, &QAbstractItemModel::rowsAboutToBeInserted, this, &DisplayFilterCombo::rowsAboutToBeInserted);
#endif
    connect(cur_model, &QAbstractItemModel::rowsInserted, this, &DisplayFilterCombo::rowsInserted);
}

#if QT_VERSION < QT_VERSION_CHECK(5, 15, 0)
void DisplayFilterCombo::rowsAboutToBeInserted(const QModelIndex&, int, int)
{
    // If the current text is blank but we're inserting a row, that means
    // it is being added programmatically from the model, and we want to
    // clear it afterwards and show the placeholder text instead.
    clear_state_ = (currentText() == QString());
}
#endif

void DisplayFilterCombo::rowsInserted(const QModelIndex&, int first, int last)
{
#if QT_VERSION < QT_VERSION_CHECK(5, 15, 0)
    if (clear_state_) {
        clearEditText();
    }
#endif

    // Set the last used times of newly inserted items to the current
    // time, in order. We could subclass QStandardItemModel instead.
    QStandardItemModel *m = qobject_cast<QStandardItemModel*>(this->model());
    for (int row = first; row <= last; ++row) {
        QModelIndex idx = m->index(row, 0);
        m->setData(idx, QVariant(QDateTime::currentMSecsSinceEpoch()), Qt::UserRole);
    }
    m->sort(0, Qt::DescendingOrder);
}

void DisplayFilterCombo::filterApplied(QString filter, bool)
{
    if (filter.isEmpty()) {
        // The Clear Button was pressed. The Qt documentation suggests
        // this would set the currentIndex to -1, but that doesn't seem
        // to happen on Qt 5.15 or Qt 6
        // XXX - Note in general manually editing the associated LineEdit
        // doesn't change the currentIndex, even when the text matches.
        // We could watch for currentTextChanged and update the index
        // (it might be more natural for scrolling history.)
        setCurrentIndex(-1);
    } else {
        int row = findText(filter);
        if (row >= 0) {
            /* Update the row timestamp and resort list, if the
             * filter is already in the QComboBox. Newly inserted
             * items are handled by rowsInserted above. */
            QStandardItemModel *m = qobject_cast<QStandardItemModel*>(this->model());
            QModelIndex idx = m->index(row, 0);
            m->setData(idx, QVariant(QDateTime::currentMSecsSinceEpoch()), Qt::UserRole);
            m->sort(0, Qt::DescendingOrder);
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
