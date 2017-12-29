/* pref_delegate.cpp
 * Delegates for editing prefereneces.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <ui/qt/models/pref_delegate.h>
#include <epan/prefs-int.h>

#include <QComboBox>
#include <QFileDialog>
#include <QLineEdit>
#include <QColorDialog>

#include "uat_dialog.h"
#include "wireshark_application.h"

#include <ui/qt/widgets/editor_file_dialog.h>

RangeSyntaxLineEdit::RangeSyntaxLineEdit(QWidget *parent)
    : SyntaxLineEdit(parent),
    maxRange_(0xFFFFFFFF)
{
    connect(this, SIGNAL(textChanged(QString)), this, SLOT(checkRange(QString)));
}

void RangeSyntaxLineEdit::checkRange(QString range)
{
    if (range.isEmpty()) {
        setSyntaxState(SyntaxLineEdit::Empty);
        return;
    }

    range_t *newrange;
    convert_ret_t ret = range_convert_str(NULL, &newrange, range.toUtf8().constData(), maxRange_);

    if (ret == CVT_NO_ERROR) {
        setSyntaxState(SyntaxLineEdit::Valid);
        wmem_free(NULL, newrange);
    } else {
        setSyntaxState(SyntaxLineEdit::Invalid);
    }
}




AdvancedPrefDelegate::AdvancedPrefDelegate(QObject *parent) : QStyledItemDelegate(parent)
{
}

PrefsItem* AdvancedPrefDelegate::indexToPref(const QModelIndex &index) const
{
    const QVariant v = index.model()->data(index, Qt::UserRole);
    return VariantPointer<PrefsItem>::asPtr(v);
}

QWidget *AdvancedPrefDelegate::createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                                  const QModelIndex &index) const
{
    PrefsItem* pref;
    QString filename;

    switch(index.column())
    {
    case AdvancedPrefsModel::colName:
    case AdvancedPrefsModel::colStatus:
    case AdvancedPrefsModel::colType:
        //If user clicks on any of these columns, reset preference back to default
        //There is no need to launch an editor
        ((QAbstractItemModel*)index.model())->setData(index, QVariant(), Qt::EditRole);
        break;
    case AdvancedPrefsModel::colValue:
        pref = indexToPref(index);
        switch(pref->getPrefType())
        {
        case PREF_DECODE_AS_UINT:
        case PREF_UINT:
        {
            QLineEdit* editor = new QLineEdit(parent);
#if 0
            //XXX - Do we want some help handling formatting the number?
            editor->setInputMask("0000000009;");
#endif
            return editor;
        }
        case PREF_BOOL:
            //Setting any non-NULL value will invert boolean value
            ((QAbstractItemModel*)index.model())->setData(index, QString("BOOL"), Qt::EditRole);
            break;
        case PREF_ENUM:
        {
            QComboBox* editor = new QComboBox(parent);
            return editor;
        }
        case PREF_STRING:
        {
            //Separated from UINT in case formatting needs to be applied to UINT
            QLineEdit* editor = new QLineEdit(parent);
            return editor;
        }
        case PREF_DECODE_AS_RANGE:
        case PREF_RANGE:
        {
            RangeSyntaxLineEdit *editor = new RangeSyntaxLineEdit(parent);
            return editor;
        }
        case PREF_UAT:
        {
        if (pref->getPrefGUIType() == GUI_ALL || pref->getPrefGUIType() == GUI_QT) {
            UatDialog uat_dlg(parent, prefs_get_uat_value(pref->getPref()));
            uat_dlg.exec();
        }
        }
            break;
        case PREF_SAVE_FILENAME:
            filename = QFileDialog::getSaveFileName(parent, wsApp->windowTitleString(prefs_get_title(pref->getPref())),
                                                        index.model()->data(index, Qt::DisplayRole).toString());
            if (!filename.isEmpty()) {
                ((QAbstractItemModel*)index.model())->setData(index, QDir::toNativeSeparators(filename), Qt::EditRole);
            }
            break;
        case PREF_OPEN_FILENAME:
            filename = QFileDialog::getOpenFileName(parent, wsApp->windowTitleString(prefs_get_title(pref->getPref())),
                                                    index.model()->data(index, Qt::DisplayRole).toString());
            if (!filename.isEmpty()) {
                ((QAbstractItemModel*)index.model())->setData(index, QDir::toNativeSeparators(filename), Qt::EditRole);
            }
            break;
        case PREF_DIRNAME:
            filename = QFileDialog::getExistingDirectory(parent, wsApp->windowTitleString(prefs_get_title(pref->getPref())),
                                                        index.model()->data(index, Qt::DisplayRole).toString());
            if (!filename.isEmpty()) {
                ((QAbstractItemModel*)index.model())->setData(index, QDir::toNativeSeparators(filename), Qt::EditRole);
            }
            break;
        case PREF_COLOR:
        {
            QColorDialog color_dlg;
            color_t color = *prefs_get_color_value(pref->getPref(), pref_stashed);

            color_dlg.setCurrentColor(QColor(
                                          color.red >> 8,
                                          color.green >> 8,
                                          color.blue >> 8
                                          ));
            if (color_dlg.exec() == QDialog::Accepted) {
                ((QAbstractItemModel*)index.model())->setData(index, color_dlg.currentColor().name(), Qt::EditRole);
            }
            break;
        }

        }
        break;
    }

    return 0;
}

void AdvancedPrefDelegate::setEditorData(QWidget *editor, const QModelIndex &index) const
{
    PrefsItem* pref = indexToPref(index);

    switch(pref->getPrefType())
    {
    case PREF_DECODE_AS_UINT:
    case PREF_UINT:
        {
        QLineEdit* line = static_cast<QLineEdit*>(editor);
        line->setText(index.model()->data(index, Qt::DisplayRole).toString());
        }
        break;
    case PREF_ENUM:
        {
        QComboBox* combo = static_cast<QComboBox*>(editor);
        const enum_val_t *ev;
        PrefsItem* pref = VariantPointer<PrefsItem>::asPtr(index.model()->data(index, Qt::UserRole));
        for (ev = prefs_get_enumvals(pref->getPref()); ev && ev->description; ev++) {
            combo->addItem(ev->description, QVariant(ev->value));
            if (prefs_get_enum_value(pref->getPref(), pref_stashed) == ev->value)
                combo->setCurrentIndex(combo->count() - 1);
        }
        }
        break;
    case PREF_STRING:
        {
        QLineEdit* line = static_cast<QLineEdit*>(editor);
        line->setText(index.model()->data(index, Qt::DisplayRole).toString());
        }
        break;
    case PREF_DECODE_AS_RANGE:
    case PREF_RANGE:
        {
        RangeSyntaxLineEdit* syntax = static_cast<RangeSyntaxLineEdit*>(editor);
        syntax->setText(index.model()->data(index, Qt::DisplayRole).toString());
        }
        break;
    case PREF_UAT:
    case PREF_SAVE_FILENAME:
    case PREF_OPEN_FILENAME:
    case PREF_DIRNAME:
    case PREF_COLOR:
        //Handled by the dialogs created
        break;
    default:
        //Ensure any new preference types are handled
        Q_ASSERT(FALSE);
        break;
    }
}

void AdvancedPrefDelegate::setModelData(QWidget *editor, QAbstractItemModel *model,
                              const QModelIndex &index) const
{
    PrefsItem* pref = indexToPref(index);
    switch(pref->getPrefType())
    {
    case PREF_DECODE_AS_UINT:
    case PREF_UINT:
    case PREF_STRING:
    {
        QLineEdit* line = static_cast<QLineEdit*>(editor);
        model->setData(index, line->text(), Qt::EditRole);
        break;
    }
    case PREF_ENUM:
    {
        QComboBox* combo = static_cast<QComboBox*>(editor);
        model->setData(index, combo->itemData(combo->currentIndex()), Qt::EditRole);
    }
        break;
    case PREF_DECODE_AS_RANGE:
    case PREF_RANGE:
    {
        RangeSyntaxLineEdit* syntax = static_cast<RangeSyntaxLineEdit*>(editor);
        model->setData(index, syntax->text(), Qt::EditRole);
        break;
    }
    case PREF_UAT:
        //do nothing because UAT values aren't shown in table
        break;
    case PREF_SAVE_FILENAME:
    case PREF_OPEN_FILENAME:
    case PREF_DIRNAME:
    case PREF_COLOR:
        //do nothing, dialog signals will update table
        pref = NULL;
        break;
    default:
        //Ensure any new preference types are handled
        Q_ASSERT(FALSE);
        break;
    }
}

/* * Editor modelines
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
