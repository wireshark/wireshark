/* module_preferences_scroll_area.cpp
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

#include "module_preferences_scroll_area.h"
#include "ui_module_preferences_scroll_area.h"
#include "syntax_line_edit.h"
#include "qt_ui_utils.h"
#include "uat_dialog.h"

#include <epan/prefs-int.h>

#include <QAbstractButton>
#include <QButtonGroup>
#include <QCheckBox>
#include <QComboBox>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QRadioButton>
#include <QScrollBar>
#include <QSpacerItem>

#include <QDebug>

Q_DECLARE_METATYPE(pref_t *)

const char *pref_prop_ = "pref_ptr";

extern "C" {
// Callbacks prefs routines

/* show a single preference on the GtkGrid of a preference page */
static guint
pref_show(pref_t *pref, gpointer layout_ptr)
{
    QVBoxLayout *vb = static_cast<QVBoxLayout *>(layout_ptr);

    if (!pref || !vb) return 0;
    QString tooltip = QString("<span>%1</span>").arg(pref->description);

    switch (pref->type) {
    case PREF_UINT:
    {
        QHBoxLayout *hb = new QHBoxLayout();
        QLabel *label = new QLabel(pref->title);
        label->setToolTip(tooltip);
        hb->addWidget(label);
        QLineEdit *uint_le = new QLineEdit();
        uint_le->setToolTip(tooltip);
        uint_le->setProperty(pref_prop_, qVariantFromValue(pref));
        uint_le->setMinimumWidth(uint_le->fontMetrics().height() * 8);
        hb->addWidget(uint_le);
        hb->addSpacerItem(new QSpacerItem(1, 1, QSizePolicy::Expanding, QSizePolicy::Minimum));
        vb->addLayout(hb);
        break;
    }
    case PREF_BOOL:
    {
        QCheckBox *bool_cb = new QCheckBox(pref->title);
        bool_cb->setToolTip(tooltip);
        bool_cb->setProperty(pref_prop_, qVariantFromValue(pref));
        vb->addWidget(bool_cb);
        break;
    }
    case PREF_ENUM:
    {
        const enum_val_t *ev;
        if (!pref->info.enum_info.enumvals) return 0;

        if (pref->info.enum_info.radio_buttons) {
            QLabel *label = new QLabel(pref->title);
            label->setToolTip(tooltip);
            vb->addWidget(label);
            QButtonGroup *enum_bg = new QButtonGroup();
            for (ev = pref->info.enum_info.enumvals; ev && ev->description; ev++) {
                QRadioButton *enum_rb = new QRadioButton(ev->description);
                enum_rb->setToolTip(tooltip);
                QStyleOption style_opt;
                enum_rb->setProperty(pref_prop_, qVariantFromValue(pref));
                enum_rb->setStyleSheet(QString(
                                      "QRadioButton {"
                                      "  margin-left: %1px;"
                                      "}"
                                      )
                                  .arg(enum_rb->style()->subElementRect(QStyle::SE_CheckBoxContents, &style_opt).left()));
                enum_bg->addButton(enum_rb, ev->value);
                vb->addWidget(enum_rb);
            }
        } else {
            QHBoxLayout *hb = new QHBoxLayout();
            QComboBox *enum_cb = new QComboBox();
            enum_cb->setToolTip(tooltip);
            enum_cb->setProperty(pref_prop_, qVariantFromValue(pref));
            for (ev = pref->info.enum_info.enumvals; ev && ev->description; ev++) {
                enum_cb->addItem(ev->description, QVariant(ev->value));
            }
            hb->addWidget(new QLabel(pref->title));
            hb->addWidget(enum_cb);
            hb->addSpacerItem(new QSpacerItem(1, 1, QSizePolicy::Expanding, QSizePolicy::Minimum));
            vb->addLayout(hb);
        }
        break;
    }
    case PREF_STRING:
    {
        QHBoxLayout *hb = new QHBoxLayout();
        QLabel *label = new QLabel(pref->title);
        label->setToolTip(tooltip);
        hb->addWidget(label);
        QLineEdit *string_le = new QLineEdit();
        string_le->setToolTip(tooltip);
        string_le->setProperty(pref_prop_, qVariantFromValue(pref));
        string_le->setMinimumWidth(string_le->fontMetrics().height() * 20);
        hb->addWidget(string_le);
        hb->addSpacerItem(new QSpacerItem(1, 1, QSizePolicy::Expanding, QSizePolicy::Minimum));
        vb->addLayout(hb);
        break;
    }
    case PREF_RANGE:
    {
        QHBoxLayout *hb = new QHBoxLayout();
        QLabel *label = new QLabel(pref->title);
        label->setToolTip(tooltip);
        hb->addWidget(label);
        SyntaxLineEdit *range_se = new SyntaxLineEdit();
        range_se->setToolTip(tooltip);
        range_se->setProperty(pref_prop_, qVariantFromValue(pref));
        range_se->setMinimumWidth(range_se->fontMetrics().height() * 20);
        hb->addWidget(range_se);
        hb->addSpacerItem(new QSpacerItem(1, 1, QSizePolicy::Expanding, QSizePolicy::Minimum));
        vb->addLayout(hb);
        break;
    }
    case PREF_STATIC_TEXT:
    {
        QLabel *label = new QLabel(pref->title);
        label->setToolTip(tooltip);
        vb->addWidget(label);
        break;
    }
    case PREF_UAT:
    {
        QHBoxLayout *hb = new QHBoxLayout();
        QLabel *label = new QLabel(pref->title);
        label->setToolTip(tooltip);
        hb->addWidget(label);
        QPushButton *uat_pb = new QPushButton(QObject::tr("Edit..."));
        uat_pb->setToolTip(tooltip);
        uat_pb->setProperty(pref_prop_, qVariantFromValue(pref));
        hb->addWidget(uat_pb);
        hb->addSpacerItem(new QSpacerItem(1, 1, QSizePolicy::Expanding, QSizePolicy::Minimum));
        vb->addLayout(hb);
        break;
    }
    case PREF_FILENAME:
    case PREF_DIRNAME:
    {
        QLabel *label = new QLabel(pref->title);
        label->setToolTip(tooltip);
        vb->addWidget(label);
        QHBoxLayout *hb = new QHBoxLayout();
        QLineEdit *path_le = new QLineEdit();
        path_le->setToolTip(tooltip);
        QStyleOption style_opt;
        path_le->setProperty(pref_prop_, qVariantFromValue(pref));
        path_le->setMinimumWidth(path_le->fontMetrics().height() * 20);
        path_le->setStyleSheet(QString(
                              "QLineEdit {"
                              "  margin-left: %1px;"
                              "}"
                              )
                          .arg(path_le->style()->subElementRect(QStyle::SE_CheckBoxContents, &style_opt).left()));
        hb->addWidget(path_le);
        QPushButton *path_pb = new QPushButton(QObject::tr("Browse..."));
        path_pb->setProperty(pref_prop_, qVariantFromValue(pref));
        hb->addWidget(path_pb);
        hb->addSpacerItem(new QSpacerItem(1, 1, QSizePolicy::Expanding, QSizePolicy::Minimum));
        vb->addLayout(hb);
        break;
    }
    case PREF_COLOR:
    {
        // XXX - Not needed yet. When it is needed we can add a label + QFrame which pops up a
        // color picker similar to the Font and Colors prefs.
        break;
    }
    default:
        break;
    }
    return 0;
}

} // extern "C"

ModulePreferencesScrollArea::ModulePreferencesScrollArea(module_t *module, QWidget *parent) :
    QScrollArea(parent),
    ui(new Ui::ModulePreferencesScrollArea),
    module_(module)
{
    ui->setupUi(this);

    if (!module) return;

    /* Add items for each of the preferences */
    prefs_pref_foreach(module, pref_show, (gpointer) ui->verticalLayout);

    foreach (QLineEdit *le, findChildren<QLineEdit *>()) {
        pref_t *pref = le->property(pref_prop_).value<pref_t *>();
        if (!pref) continue;

        switch (pref->type) {
        case PREF_UINT:
            connect(le, SIGNAL(textEdited(QString)), this, SLOT(uintLineEditTextEdited(QString)));
            break;
        case PREF_STRING:
        case PREF_FILENAME:
        case PREF_DIRNAME:
            connect(le, SIGNAL(textEdited(QString)), this, SLOT(stringLineEditTextEdited(QString)));
            break;
        case PREF_RANGE:
            connect(le, SIGNAL(textEdited(QString)), this, SLOT(rangeSyntaxLineEditTextEdited(QString)));
            break;
        default:
            break;
        }
    }

    foreach (QCheckBox *cb, findChildren<QCheckBox *>()) {
        pref_t *pref = cb->property(pref_prop_).value<pref_t *>();
        if (!pref) continue;

        if (pref->type == PREF_BOOL) {
            connect(cb, SIGNAL(toggled(bool)), this, SLOT(boolCheckBoxToggled(bool)));
        }
    }

    foreach (QRadioButton *rb, findChildren<QRadioButton *>()) {
        pref_t *pref = rb->property(pref_prop_).value<pref_t *>();
        if (!pref) continue;

        if (pref->type == PREF_ENUM && pref->info.enum_info.radio_buttons) {
            connect(rb, SIGNAL(toggled(bool)), this, SLOT(enumRadioButtonToggled(bool)));
        }
    }

    foreach (QComboBox *combo, findChildren<QComboBox *>()) {
        pref_t *pref = combo->property(pref_prop_).value<pref_t *>();
        if (!pref) continue;

        if (pref->type == PREF_ENUM && !pref->info.enum_info.radio_buttons) {
            connect(combo, SIGNAL(currentIndexChanged(int)), this, SLOT(enumComboBoxCurrentIndexChanged(int)));
        }
    }

    foreach (QPushButton *pb, findChildren<QPushButton *>()) {
        pref_t *pref = pb->property(pref_prop_).value<pref_t *>();
        if (!pref) continue;

        if (pref->type == PREF_UAT) {
            connect(pb, SIGNAL(pressed()), this, SLOT(uatPushButtonPressed()));
        } else if (pref->type == PREF_FILENAME) {
            connect(pb, SIGNAL(pressed()), this, SLOT(filenamePushButtonPressed()));
        } else if (pref->type == PREF_DIRNAME) {
            connect(pb, SIGNAL(pressed()), this, SLOT(dirnamePushButtonPressed()));
        }
    }

    ui->verticalLayout->addSpacerItem(new QSpacerItem(10, 1, QSizePolicy::Minimum, QSizePolicy::Expanding));
}

ModulePreferencesScrollArea::~ModulePreferencesScrollArea()
{
    delete ui;
}

void ModulePreferencesScrollArea::showEvent(QShowEvent *evt)
{
    Q_UNUSED(evt)
    updateWidgets();
}

void ModulePreferencesScrollArea::resizeEvent(QResizeEvent *evt)
{
    QScrollArea::resizeEvent(evt);

    if (verticalScrollBar()->isVisible()) {
        setFrameStyle(QFrame::StyledPanel);
    } else {
        setFrameStyle(QFrame::NoFrame);
    }
}

void ModulePreferencesScrollArea::updateWidgets()
{
    foreach (QLineEdit *le, findChildren<QLineEdit *>()) {
        pref_t *pref = le->property(pref_prop_).value<pref_t *>();
        if (!pref) continue;

        le->setText(gchar_free_to_qstring(prefs_pref_to_str(pref, pref_stashed)).remove(QRegExp("\n\t")));
    }

    foreach (QCheckBox *cb, findChildren<QCheckBox *>()) {
        pref_t *pref = cb->property(pref_prop_).value<pref_t *>();
        if (!pref) continue;

        if (pref->type == PREF_BOOL) {
            cb->setChecked(pref->stashed_val.boolval);
        }
    }

    foreach (QRadioButton *enum_rb, findChildren<QRadioButton *>()) {
        pref_t *pref = enum_rb->property(pref_prop_).value<pref_t *>();
        if (!pref) continue;

        QButtonGroup *enum_bg = enum_rb->group();
        if (!enum_bg) continue;

        if (pref->type == PREF_ENUM && pref->info.enum_info.radio_buttons) {
            if (pref->stashed_val.enumval == enum_bg->id(enum_rb)) {
                enum_rb->setChecked(true);
            }
        }
    }

    foreach (QComboBox *enum_cb, findChildren<QComboBox *>()) {
        pref_t *pref = enum_cb->property(pref_prop_).value<pref_t *>();
        if (!pref) continue;

        if (pref->type == PREF_ENUM && !pref->info.enum_info.radio_buttons) {
            for (int i = 0; i < enum_cb->count(); i++) {
                if (pref->stashed_val.enumval == enum_cb->itemData(i).toInt()) {
                    enum_cb->setCurrentIndex(i);
                }
            }
        }
    }
}

void ModulePreferencesScrollArea::uintLineEditTextEdited(const QString &new_str)
{
    QLineEdit *uint_le = qobject_cast<QLineEdit*>(sender());
    if (!uint_le) return;

    pref_t *pref = uint_le->property(pref_prop_).value<pref_t *>();
    if (!pref) return;

    bool ok;
    uint new_uint = new_str.toUInt(&ok);
    if (ok) {
        pref->stashed_val.uint = new_uint;
    }
}

void ModulePreferencesScrollArea::boolCheckBoxToggled(bool checked)
{
    QCheckBox *bool_cb = qobject_cast<QCheckBox*>(sender());
    if (!bool_cb) return;

    pref_t *pref = bool_cb->property(pref_prop_).value<pref_t *>();
    if (!pref) return;

    pref->stashed_val.boolval = checked;
}

void ModulePreferencesScrollArea::enumRadioButtonToggled(bool checked)
{
    if (!checked) return;
    QRadioButton *enum_rb = qobject_cast<QRadioButton*>(sender());
    if (!enum_rb) return;

    QButtonGroup *enum_bg = enum_rb->group();
    if (!enum_bg) return;

    pref_t *pref = enum_rb->property(pref_prop_).value<pref_t *>();
    if (!pref) return;

    if (enum_bg->checkedId() >= 0) {
        pref->stashed_val.enumval = enum_bg->checkedId();
    }
}

void ModulePreferencesScrollArea::enumComboBoxCurrentIndexChanged(int index)
{
    QComboBox *enum_cb = qobject_cast<QComboBox*>(sender());
    if (!enum_cb) return;

    pref_t *pref = enum_cb->property(pref_prop_).value<pref_t *>();
    if (!pref) return;

    pref->stashed_val.enumval = enum_cb->itemData(index).toInt();
}

void ModulePreferencesScrollArea::stringLineEditTextEdited(const QString &new_str)
{
    QLineEdit *string_le = qobject_cast<QLineEdit*>(sender());
    if (!string_le) return;

    pref_t *pref = string_le->property(pref_prop_).value<pref_t *>();
    if (!pref) return;

    g_free((void *)pref->stashed_val.string);
    pref->stashed_val.string = qstring_strdup(new_str);
}

void ModulePreferencesScrollArea::rangeSyntaxLineEditTextEdited(const QString &new_str)
{
    SyntaxLineEdit *range_se = qobject_cast<SyntaxLineEdit*>(sender());
    if (!range_se) return;

    pref_t *pref = range_se->property(pref_prop_).value<pref_t *>();
    if (!pref) return;

    range_t *newrange;
    convert_ret_t ret = range_convert_str(&newrange, new_str.toUtf8().constData(), pref->info.max_value);

    if (ret == CVT_NO_ERROR) {
        g_free(pref->stashed_val.range);
        pref->stashed_val.range = newrange;

        if (new_str.isEmpty()) {
            range_se->setSyntaxState(SyntaxLineEdit::Empty);
        } else {
            range_se->setSyntaxState(SyntaxLineEdit::Valid);
        }
    } else {
        range_se->setSyntaxState(SyntaxLineEdit::Invalid);
    }
}

void ModulePreferencesScrollArea::uatPushButtonPressed()
{
    QPushButton *uat_pb = qobject_cast<QPushButton*>(sender());
    if (!uat_pb) return;

    pref_t *pref = uat_pb->property(pref_prop_).value<pref_t *>();
    if (!pref) return;

    UatDialog uat_dlg(this, pref->varp.uat);
    uat_dlg.exec();
}

void ModulePreferencesScrollArea::filenamePushButtonPressed()
{
    QPushButton *filename_pb = qobject_cast<QPushButton*>(sender());
    if (!filename_pb) return;

    pref_t *pref = filename_pb->property(pref_prop_).value<pref_t *>();
    if (!pref) return;

    QString filename = QFileDialog::getSaveFileName(this,
                                            QString(tr("Wireshark: ")) + pref->description,
                                            pref->stashed_val.string);

    if (!filename.isEmpty()) {
        g_free((void *)pref->stashed_val.string);
        pref->stashed_val.string = qstring_strdup(filename);
        updateWidgets();
    }
}

void ModulePreferencesScrollArea::dirnamePushButtonPressed()
{
    QPushButton *dirname_pb = qobject_cast<QPushButton*>(sender());
    if (!dirname_pb) return;

    pref_t *pref = dirname_pb->property(pref_prop_).value<pref_t *>();
    if (!pref) return;

    QString dirname = QFileDialog::getExistingDirectory(this,
                                                 QString(tr("Wireshark: ")) + pref->description,
                                                 pref->stashed_val.string);

    if (!dirname.isEmpty()) {
        g_free((void *)pref->stashed_val.string);
        pref->stashed_val.string = qstring_strdup(dirname);
        updateWidgets();
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
