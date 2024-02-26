/* wireshark_preference.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/prefs.h>
#include <epan/prefs-int.h>

#include <ui/qt/manager/wireshark_preference.h>
#include <ui/qt/manager/preference_manager.h>
#include <ui/qt/widgets/range_syntax_lineedit.h>
#include "ui/qt/widgets/wireshark_file_dialog.h"
#include <ui/qt/main_application.h>
#include <ui/qt/uat_dialog.h>

#include <QDir>
#include <QLineEdit>
#include <QComboBox>
#include <QColorDialog>

WiresharkPreference::WiresharkPreference(QObject * parent) : QObject(parent), _prefsItem(NULL)
{}

QWidget * WiresharkPreference::editor(QWidget * /*parent*/, const QStyleOptionViewItem &/*option*/, const QModelIndex &/*index*/)
{
    return Q_NULLPTR;
}

void WiresharkPreference::setData(QWidget * /*editor*/, const QModelIndex &/*index*/) {}
void WiresharkPreference::setModelData(QWidget * /*editor*/, QAbstractItemModel * /*model*/, const QModelIndex &/*index*/) {}

void WiresharkPreference::setPrefsItem(PrefsItem * item)
{
    _prefsItem = item;
}

PrefsItem * WiresharkPreference::prefsItem() const
{
    return _prefsItem;
}

class BoolPreference : public WiresharkPreference
{
public:
    BoolPreference(QObject * parent = Q_NULLPTR) : WiresharkPreference(parent) {}
    virtual QWidget * editor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &index)
    {
        const_cast<QAbstractItemModel*>(index.model())->setData(index, QString("BOOL"), Qt::EditRole);
        return WiresharkPreference::editor(parent, option, index);
    }
};
REGISTER_PREFERENCE_TYPE(PREF_BOOL, BoolPreference)

class StringPreference : public WiresharkPreference
{
public:
    StringPreference(QObject * parent = Q_NULLPTR) : WiresharkPreference(parent) {}
    virtual QWidget * editor(QWidget *parent, const QStyleOptionViewItem &/*option*/, const QModelIndex &/*index*/)
    {
        return new QLineEdit(parent);
    }

    virtual void setData(QWidget *editor, const QModelIndex &index)
    {
        QLineEdit* line = static_cast<QLineEdit*>(editor);
        line->setText(index.model()->data(index, Qt::DisplayRole).toString());
    }

    virtual void setModelData(QWidget *editor, QAbstractItemModel *model, const QModelIndex &index)
    {
        QLineEdit* line = static_cast<QLineEdit*>(editor);
        model->setData(index, line->text(), Qt::EditRole);
    }
};
REGISTER_PREFERENCE_TYPE(PREF_STRING, StringPreference)
REGISTER_PREFERENCE_TYPE(PREF_CUSTOM, StringPreference)
REGISTER_PREFERENCE_TYPE(PREF_DISSECTOR, StringPreference)

class PasswordPreference : public StringPreference
{
public:
    PasswordPreference(QObject * parent = Q_NULLPTR) : StringPreference(parent) {}
    virtual QWidget * editor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &index)
    {
        QLineEdit *le = static_cast<QLineEdit *>(StringPreference::editor(parent, option, index));

        le->setEchoMode(QLineEdit::PasswordEchoOnEdit);
        return le;
    }
};
REGISTER_PREFERENCE_TYPE(PREF_PASSWORD, PasswordPreference)

class UIntPreference : public StringPreference
{
public:
    UIntPreference(QObject * parent = Q_NULLPTR) : StringPreference(parent) {}
};
REGISTER_PREFERENCE_TYPE(PREF_UINT, UIntPreference)

class EnumPreference : public WiresharkPreference
{
public:
    EnumPreference(QObject * parent = Q_NULLPTR) : WiresharkPreference(parent) {}
    virtual QWidget * editor(QWidget *parent, const QStyleOptionViewItem &/*option*/, const QModelIndex &/*index*/)
    {
        return new QComboBox(parent);
    }

    virtual void setData(QWidget *editor, const QModelIndex &index)
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

    virtual void setModelData(QWidget *editor, QAbstractItemModel *model, const QModelIndex &index)
    {
        QComboBox* combo = static_cast<QComboBox*>(editor);
        model->setData(index, combo->itemData(combo->currentIndex()), Qt::EditRole);
    }
};
REGISTER_PREFERENCE_TYPE(PREF_ENUM, EnumPreference)

class RangePreference : public WiresharkPreference
{
public:
    RangePreference(QObject * parent = Q_NULLPTR) : WiresharkPreference(parent) {}
    virtual QWidget * editor(QWidget *parent, const QStyleOptionViewItem &/*option*/, const QModelIndex &/*index*/)
    {
        return new RangeSyntaxLineEdit(parent);
    }

    virtual void setData(QWidget *editor, const QModelIndex &index)
    {
        RangeSyntaxLineEdit* syntax = static_cast<RangeSyntaxLineEdit*>(editor);
        syntax->setText(index.model()->data(index, Qt::DisplayRole).toString());
    }

    virtual void setModelData(QWidget *editor, QAbstractItemModel *model, const QModelIndex &index)
    {
        RangeSyntaxLineEdit* syntax = static_cast<RangeSyntaxLineEdit*>(editor);
        model->setData(index, syntax->text(), Qt::EditRole);
    }
};
REGISTER_PREFERENCE_TYPE(PREF_RANGE, RangePreference)
REGISTER_PREFERENCE_TYPE(PREF_DECODE_AS_RANGE, RangePreference)

class ColorPreference : public WiresharkPreference
{
public:
    ColorPreference(QObject * parent = Q_NULLPTR) : WiresharkPreference(parent) {}
    virtual QWidget * editor(QWidget * parent, const QStyleOptionViewItem &/*option*/, const QModelIndex &/*index*/)
    {
        QColorDialog* color_dlg = new QColorDialog(parent);
        color_dlg->setWindowModality(Qt::ApplicationModal);
        color_dlg->show();
        return color_dlg;
    }

    virtual void setData(QWidget *editor, const QModelIndex &index)
    {
        QColorDialog* color_dlg = static_cast<QColorDialog*>(editor);
        QColor color = QColor("#" + index.model()->data(index, Qt::DisplayRole).toString());
        color_dlg->setCurrentColor(color);
    }

    virtual void setModelData(QWidget *editor, QAbstractItemModel *model, const QModelIndex &index)
    {
        QColorDialog* color_dlg = static_cast<QColorDialog*>(editor);
        if (color_dlg->result() == QDialog::Accepted) {
            model->setData(index, color_dlg->currentColor().name(), Qt::EditRole);
        }
    }
};
REGISTER_PREFERENCE_TYPE(PREF_COLOR, ColorPreference)

class SaveFilePreference : public WiresharkPreference
{
public:
    SaveFilePreference(QObject * parent = Q_NULLPTR) : WiresharkPreference(parent) {}
    virtual QWidget * editor(QWidget * parent, const QStyleOptionViewItem &option, const QModelIndex &index)
    {
        QString filename = WiresharkFileDialog::getSaveFileName(parent, mainApp->windowTitleString(prefs_get_title(prefsItem()->getPref())),
                                                    index.model()->data(index, Qt::DisplayRole).toString());
        if (!filename.isEmpty()) {
            const_cast<QAbstractItemModel*>(index.model())->setData(index, QDir::toNativeSeparators(filename), Qt::EditRole);
        }
        return WiresharkPreference::editor(parent, option, index);
    }
};
REGISTER_PREFERENCE_TYPE(PREF_SAVE_FILENAME, SaveFilePreference)

class OpenFilePreference : public WiresharkPreference
{
public:
    OpenFilePreference(QObject * parent = Q_NULLPTR) : WiresharkPreference(parent) {}
    virtual QWidget * editor(QWidget * parent, const QStyleOptionViewItem &option, const QModelIndex &index)
    {
        QString filename = WiresharkFileDialog::getOpenFileName(parent, mainApp->windowTitleString(prefs_get_title(prefsItem()->getPref())),
                                                        index.model()->data(index, Qt::DisplayRole).toString());
        if (!filename.isEmpty()) {
            const_cast<QAbstractItemModel*>(index.model())->setData(index, QDir::toNativeSeparators(filename), Qt::EditRole);
        }
        return WiresharkPreference::editor(parent, option, index);
    }
};
REGISTER_PREFERENCE_TYPE(PREF_OPEN_FILENAME, OpenFilePreference)

class DirNamePreference : public WiresharkPreference
{
public:
    DirNamePreference(QObject * parent = Q_NULLPTR) : WiresharkPreference(parent) {}
    virtual QWidget * editor(QWidget * parent, const QStyleOptionViewItem &option, const QModelIndex &index)
    {
        QString filename = WiresharkFileDialog::getExistingDirectory(parent, mainApp->windowTitleString(prefs_get_title(prefsItem()->getPref())),
                                                    index.model()->data(index, Qt::DisplayRole).toString());
        if (!filename.isEmpty()) {
            const_cast<QAbstractItemModel*>(index.model())->setData(index, QDir::toNativeSeparators(filename), Qt::EditRole);
        }
        return WiresharkPreference::editor(parent, option, index);
    }
};
REGISTER_PREFERENCE_TYPE(PREF_DIRNAME, DirNamePreference)

class UatPreference : public WiresharkPreference
{
public:
    UatPreference(QObject * parent = Q_NULLPTR) : WiresharkPreference(parent) {}
    virtual QWidget * editor(QWidget * parent, const QStyleOptionViewItem &option, const QModelIndex &index)
    {
        UatDialog uat_dlg(parent, prefs_get_uat_value(prefsItem()->getPref()));
        uat_dlg.exec();

        return WiresharkPreference::editor(parent, option, index);
    }
};
REGISTER_PREFERENCE_TYPE(PREF_UAT, UatPreference)
