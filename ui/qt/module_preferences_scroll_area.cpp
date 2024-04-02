/* module_preferences_scroll_area.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "module_preferences_scroll_area.h"
#include <ui_module_preferences_scroll_area.h>
#include <ui/qt/widgets/syntax_line_edit.h>
#include <ui/qt/widgets/dissector_syntax_line_edit.h>
#include "ui/qt/widgets/wireshark_file_dialog.h"
#include <ui/qt/utils/qt_ui_utils.h>
#include "uat_dialog.h"
#include "main_application.h"
#include "ui/qt/main_window.h"

#include <ui/qt/utils/variant_pointer.h>

#include <epan/prefs-int.h>

#include <wsutil/utf8_entities.h>

#include <QAbstractButton>
#include <QButtonGroup>
#include <QCheckBox>
#include <QComboBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QPushButton>
#include <QRadioButton>
#include <QScrollBar>
#include <QSpacerItem>
#include <QRegularExpression>

const char *pref_prop_ = "pref_ptr";

// Escape our ampersands so that Qt won't try to interpret them as
// mnemonics.
static const QString title_to_shortcut(const char *title) {
    QString shortcut_str(title);
    shortcut_str.replace('&', "&&");
    return shortcut_str;
}

typedef struct 
{
    QVBoxLayout *layout;
    QString moduleName;
} prefSearchData;

extern "C" {
// Callbacks prefs routines

/* Add a single preference to the QVBoxLayout of a preference page */
static unsigned
pref_show(pref_t *pref, void *user_data)
{
    prefSearchData * data = static_cast<prefSearchData *>(user_data);

    if (!pref || !data) return 0;

    QVBoxLayout *vb = data->layout;

    // Convert the pref description from plain text to rich text.
    QString description = html_escape(prefs_get_description(pref));
    QString name = QString("%1.%2").arg(data->moduleName).arg(prefs_get_name(pref));
    description.replace('\n', "<br/>");
    QString tooltip = QString("<span>%1</span><br/><br/>%2").arg(description).arg(name);

    switch (prefs_get_type(pref)) {
    case PREF_UINT:
    {
        QHBoxLayout *hb = new QHBoxLayout();
        QLabel *label = new QLabel(prefs_get_title(pref));
        label->setToolTip(tooltip);
        hb->addWidget(label);
        QLineEdit *uint_le = new QLineEdit();
        uint_le->setToolTip(tooltip);
        uint_le->setProperty(pref_prop_, VariantPointer<pref_t>::asQVariant(pref));
        uint_le->setMinimumWidth(uint_le->fontMetrics().height() * 8);
        hb->addWidget(uint_le);
        hb->addSpacerItem(new QSpacerItem(1, 1, QSizePolicy::Expanding, QSizePolicy::Minimum));
        vb->addLayout(hb);
        break;
    }
    case PREF_BOOL:
    {
        QCheckBox *bool_cb = new QCheckBox(title_to_shortcut(prefs_get_title(pref)));
        bool_cb->setToolTip(tooltip);
        bool_cb->setProperty(pref_prop_, VariantPointer<pref_t>::asQVariant(pref));
        vb->addWidget(bool_cb);
        break;
    }
    case PREF_ENUM:
    {
        const enum_val_t *ev;
        ev = prefs_get_enumvals(pref);
        if (!ev || !ev->description)
            return 0;

        if (prefs_get_enum_radiobuttons(pref)) {
            QLabel *label = new QLabel(prefs_get_title(pref));
            label->setToolTip(tooltip);
            vb->addWidget(label);
            QButtonGroup *enum_bg = new QButtonGroup(vb);
            while (ev->description) {
                QRadioButton *enum_rb = new QRadioButton(title_to_shortcut(ev->description));
                enum_rb->setToolTip(tooltip);
                QStyleOption style_opt;
                enum_rb->setProperty(pref_prop_, VariantPointer<pref_t>::asQVariant(pref));
                enum_rb->setStyleSheet(QString(
                                      "QRadioButton {"
                                      "  margin-left: %1px;"
                                      "}"
                                      )
                                  .arg(enum_rb->style()->subElementRect(QStyle::SE_CheckBoxContents, &style_opt).left()));
                enum_bg->addButton(enum_rb, ev->value);
                vb->addWidget(enum_rb);
                ev++;
            }
        } else {
            QHBoxLayout *hb = new QHBoxLayout();
            QComboBox *enum_cb = new QComboBox();
            enum_cb->setToolTip(tooltip);
            enum_cb->setProperty(pref_prop_, VariantPointer<pref_t>::asQVariant(pref));
            for (ev = prefs_get_enumvals(pref); ev && ev->description; ev++) {
                enum_cb->addItem(ev->description, QVariant(ev->value));
            }
            QLabel * lbl = new QLabel(prefs_get_title(pref));
            lbl->setToolTip(tooltip);
            hb->addWidget(lbl);
            hb->addWidget(enum_cb);
            hb->addSpacerItem(new QSpacerItem(1, 1, QSizePolicy::Expanding, QSizePolicy::Minimum));
            vb->addLayout(hb);
        }
        break;
    }
    case PREF_STRING:
    {
        QHBoxLayout *hb = new QHBoxLayout();
        QLabel *label = new QLabel(prefs_get_title(pref));
        label->setToolTip(tooltip);
        hb->addWidget(label);
        QLineEdit *string_le = new QLineEdit();
        string_le->setToolTip(tooltip);
        string_le->setProperty(pref_prop_, VariantPointer<pref_t>::asQVariant(pref));
        string_le->setMinimumWidth(string_le->fontMetrics().height() * 20);
        hb->addWidget(string_le);
        hb->addSpacerItem(new QSpacerItem(1, 1, QSizePolicy::Expanding, QSizePolicy::Minimum));
        vb->addLayout(hb);
        break;
    }
    case PREF_PASSWORD:
    {
        QHBoxLayout *hb = new QHBoxLayout();
        QLabel *label = new QLabel(prefs_get_title(pref));
        label->setToolTip(tooltip);
        hb->addWidget(label);
        QLineEdit *string_le = new QLineEdit();
        string_le->setToolTip(tooltip);
        string_le->setProperty(pref_prop_, VariantPointer<pref_t>::asQVariant(pref));
        string_le->setMinimumWidth(string_le->fontMetrics().height() * 20);
        string_le->setEchoMode(QLineEdit::PasswordEchoOnEdit);
        hb->addWidget(string_le);
        hb->addSpacerItem(new QSpacerItem(1, 1, QSizePolicy::Expanding, QSizePolicy::Minimum));
        vb->addLayout(hb);
        break;
    }
    case PREF_DISSECTOR:
    {
        QHBoxLayout *hb = new QHBoxLayout();
        QLabel *label = new QLabel(prefs_get_title(pref));
        label->setToolTip(tooltip);
        hb->addWidget(label);
        QLineEdit *string_le = new DissectorSyntaxLineEdit();
        string_le->setToolTip(tooltip);
        string_le->setProperty(pref_prop_, VariantPointer<pref_t>::asQVariant(pref));
        string_le->setMinimumWidth(string_le->fontMetrics().height() * 20);
        hb->addWidget(string_le);
        hb->addSpacerItem(new QSpacerItem(1, 1, QSizePolicy::Expanding, QSizePolicy::Minimum));
        vb->addLayout(hb);
        break;
    }
    case PREF_DECODE_AS_RANGE:
    case PREF_RANGE:
    {
        QHBoxLayout *hb = new QHBoxLayout();
        QLabel *label = new QLabel(prefs_get_title(pref));
        label->setToolTip(tooltip);
        hb->addWidget(label);
        SyntaxLineEdit *range_se = new SyntaxLineEdit();
        range_se->setToolTip(tooltip);
        range_se->setProperty(pref_prop_, VariantPointer<pref_t>::asQVariant(pref));
        range_se->setMinimumWidth(range_se->fontMetrics().height() * 20);
        hb->addWidget(range_se);
        hb->addSpacerItem(new QSpacerItem(1, 1, QSizePolicy::Expanding, QSizePolicy::Minimum));
        vb->addLayout(hb);
        break;
    }
    case PREF_STATIC_TEXT:
    {
        QLabel *label = new QLabel(prefs_get_title(pref));
        label->setToolTip(tooltip);
        label->setWordWrap(true);
        vb->addWidget(label);
        break;
    }
    case PREF_UAT:
    {
        QHBoxLayout *hb = new QHBoxLayout();
        QLabel *label = new QLabel(prefs_get_title(pref));
        label->setToolTip(tooltip);
        hb->addWidget(label);
        QPushButton *uat_pb = new QPushButton(QObject::tr("Edit…"));
        uat_pb->setToolTip(tooltip);
        uat_pb->setProperty(pref_prop_, VariantPointer<pref_t>::asQVariant(pref));
        hb->addWidget(uat_pb);
        hb->addSpacerItem(new QSpacerItem(1, 1, QSizePolicy::Expanding, QSizePolicy::Minimum));
        vb->addLayout(hb);
        break;
    }
    case PREF_SAVE_FILENAME:
    case PREF_OPEN_FILENAME:
    case PREF_DIRNAME:
    {
        QLabel *label = new QLabel(prefs_get_title(pref));
        label->setToolTip(tooltip);
        vb->addWidget(label);
        QHBoxLayout *hb = new QHBoxLayout();
        QLineEdit *path_le = new QLineEdit();
        path_le->setToolTip(tooltip);
        QStyleOption style_opt;
        path_le->setProperty(pref_prop_, VariantPointer<pref_t>::asQVariant(pref));
        path_le->setMinimumWidth(path_le->fontMetrics().height() * 20);
        path_le->setStyleSheet(QString(
                              "QLineEdit {"
                              "  margin-left: %1px;"
                              "}"
                              )
                          .arg(path_le->style()->subElementRect(QStyle::SE_CheckBoxContents, &style_opt).left()));
        hb->addWidget(path_le);
        QPushButton *path_pb = new QPushButton(QObject::tr("Browse…"));
        path_pb->setProperty(pref_prop_, VariantPointer<pref_t>::asQVariant(pref));
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
    case PREF_PROTO_TCP_SNDAMB_ENUM:
    {
        const enum_val_t *ev;
        ev = prefs_get_enumvals(pref);
        if (!ev || !ev->description)
            return 0;

        if (prefs_get_enum_radiobuttons(pref)) {
            QLabel *label = new QLabel(prefs_get_title(pref));
            label->setToolTip(tooltip);
            vb->addWidget(label);
            QButtonGroup *enum_bg = new QButtonGroup(vb);
            while (ev->description) {
                QRadioButton *enum_rb = new QRadioButton(title_to_shortcut(ev->description));
                enum_rb->setToolTip(tooltip);
                QStyleOption style_opt;
                enum_rb->setProperty(pref_prop_, VariantPointer<pref_t>::asQVariant(pref));
                enum_rb->setStyleSheet(QString(
                                      "QRadioButton {"
                                      "  margin-left: %1px;"
                                      "}"
                                      )
                                  .arg(enum_rb->style()->subElementRect(QStyle::SE_CheckBoxContents, &style_opt).left()));
                enum_bg->addButton(enum_rb, ev->value);
                vb->addWidget(enum_rb);
                ev++;
            }
        } else {
            QHBoxLayout *hb = new QHBoxLayout();
            QComboBox *enum_cb = new QComboBox();
            enum_cb->setToolTip(tooltip);
            enum_cb->setProperty(pref_prop_, VariantPointer<pref_t>::asQVariant(pref));
            for (ev = prefs_get_enumvals(pref); ev && ev->description; ev++) {
                enum_cb->addItem(ev->description, QVariant(ev->value));
            }
            QLabel * lbl = new QLabel(prefs_get_title(pref));
            lbl->setToolTip(tooltip);
            hb->addWidget(lbl);
            hb->addWidget(enum_cb);
            hb->addSpacerItem(new QSpacerItem(1, 1, QSizePolicy::Expanding, QSizePolicy::Minimum));
            vb->addLayout(hb);
        }
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

    /* Show the preference's description at the top of the page */
    QFont font;
    font.setBold(true);
    QLabel *label = new QLabel(module->description);
    label->setFont(font);
    ui->verticalLayout->addWidget(label);

    prefSearchData searchData;
    searchData.layout = ui->verticalLayout;
    searchData.moduleName = module->name;

    /* Add items for each of the preferences */
    prefs_pref_foreach(module, pref_show, &searchData);

    foreach (QLineEdit *le, findChildren<QLineEdit *>()) {
        pref_t *pref = VariantPointer<pref_t>::asPtr(le->property(pref_prop_));
        if (!pref) continue;

        switch (prefs_get_type(pref)) {
        case PREF_UINT:
            connect(le, &QLineEdit::textEdited, this, &ModulePreferencesScrollArea::uintLineEditTextEdited);
            break;
        case PREF_STRING:
        case PREF_SAVE_FILENAME:
        case PREF_OPEN_FILENAME:
        case PREF_DIRNAME:
        case PREF_PASSWORD:
        case PREF_DISSECTOR:
            connect(le, &QLineEdit::textEdited, this, &ModulePreferencesScrollArea::stringLineEditTextEdited);
            break;
        case PREF_RANGE:
        case PREF_DECODE_AS_RANGE:
            connect(le, &QLineEdit::textEdited, this, &ModulePreferencesScrollArea::rangeSyntaxLineEditTextEdited);
            break;
        default:
            break;
        }
    }

    foreach (QCheckBox *cb, findChildren<QCheckBox *>()) {
        pref_t *pref = VariantPointer<pref_t>::asPtr(cb->property(pref_prop_));
        if (!pref) continue;

        if (prefs_get_type(pref) == PREF_BOOL) {
            connect(cb, &QCheckBox::toggled, this, &ModulePreferencesScrollArea::boolCheckBoxToggled);
        }
    }

    foreach (QRadioButton *rb, findChildren<QRadioButton *>()) {
        pref_t *pref = VariantPointer<pref_t>::asPtr(rb->property(pref_prop_));
        if (!pref) continue;

        if (prefs_get_type(pref) == PREF_ENUM && prefs_get_enum_radiobuttons(pref)) {
            connect(rb, &QRadioButton::toggled, this, &ModulePreferencesScrollArea::enumRadioButtonToggled);
        }
    }

    foreach (QComboBox *combo, findChildren<QComboBox *>()) {
        pref_t *pref = VariantPointer<pref_t>::asPtr(combo->property(pref_prop_));
        if (!pref) continue;

        if (prefs_get_type(pref) == PREF_ENUM && !prefs_get_enum_radiobuttons(pref)) {
            connect(combo, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged),
                    this, &ModulePreferencesScrollArea::enumComboBoxCurrentIndexChanged);
        }
    }

    foreach (QComboBox *combo, findChildren<QComboBox *>()) {
        pref_t *pref = VariantPointer<pref_t>::asPtr(combo->property(pref_prop_));
        if (!pref) continue;

        if (prefs_get_type(pref) == PREF_PROTO_TCP_SNDAMB_ENUM && !prefs_get_enum_radiobuttons(pref)) {
            connect(combo, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged),
                    this, &ModulePreferencesScrollArea::enumComboBoxCurrentIndexChanged_PROTO_TCP);
        }
    }

    foreach (QPushButton *pb, findChildren<QPushButton *>()) {
        pref_t *pref = VariantPointer<pref_t>::asPtr(pb->property(pref_prop_));
        if (!pref) continue;

        switch (prefs_get_type(pref)) {
        case PREF_UAT:
            connect(pb, &QPushButton::clicked, this, &ModulePreferencesScrollArea::uatPushButtonClicked);
            break;
        case PREF_SAVE_FILENAME:
            connect(pb, &QPushButton::clicked, this, &ModulePreferencesScrollArea::saveFilenamePushButtonClicked);
            break;
        case PREF_OPEN_FILENAME:
            connect(pb, &QPushButton::clicked, this, &ModulePreferencesScrollArea::openFilenamePushButtonClicked);
            break;
        case PREF_DIRNAME:
            connect(pb, &QPushButton::clicked, this, &ModulePreferencesScrollArea::dirnamePushButtonClicked);
            break;
        }
    }

    ui->verticalLayout->addSpacerItem(new QSpacerItem(10, 1, QSizePolicy::Minimum, QSizePolicy::Expanding));
}

ModulePreferencesScrollArea::~ModulePreferencesScrollArea()
{
    delete ui;
}

void ModulePreferencesScrollArea::showEvent(QShowEvent *)
{
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
        pref_t *pref = VariantPointer<pref_t>::asPtr(le->property(pref_prop_));
        if (!pref) continue;

        le->setText(gchar_free_to_qstring(prefs_pref_to_str(pref, pref_stashed)).remove(QRegularExpression("\n\t")));
    }

    foreach (QCheckBox *cb, findChildren<QCheckBox *>()) {
        pref_t *pref = VariantPointer<pref_t>::asPtr(cb->property(pref_prop_));
        if (!pref) continue;

        if (prefs_get_type(pref) == PREF_BOOL) {
            cb->setChecked(prefs_get_bool_value(pref, pref_stashed));
        }
    }

    foreach (QRadioButton *enum_rb, findChildren<QRadioButton *>()) {
        pref_t *pref = VariantPointer<pref_t>::asPtr(enum_rb->property(pref_prop_));
        if (!pref) continue;

        QButtonGroup *enum_bg = enum_rb->group();
        if (!enum_bg) continue;

        if (prefs_get_type(pref) == PREF_ENUM && prefs_get_enum_radiobuttons(pref)) {
            if (prefs_get_enum_value(pref, pref_stashed) == enum_bg->id(enum_rb)) {
                enum_rb->setChecked(true);
            }
        }
    }

    foreach (QComboBox *enum_cb, findChildren<QComboBox *>()) {
        pref_t *pref = VariantPointer<pref_t>::asPtr(enum_cb->property(pref_prop_));
        if (!pref) continue;

        if (prefs_get_type(pref) == PREF_ENUM && !prefs_get_enum_radiobuttons(pref)) {
            for (int i = 0; i < enum_cb->count(); i++) {
                if (prefs_get_enum_value(pref, pref_stashed) == enum_cb->itemData(i).toInt()) {
                    enum_cb->setCurrentIndex(i);
                }
            }
        }

        if (prefs_get_type(pref) == PREF_PROTO_TCP_SNDAMB_ENUM && !prefs_get_enum_radiobuttons(pref)) {
            if (prefs_get_list_value(pref, pref_stashed) == NULL) {
                /* We haven't added a list of frames that could have their
                 * analysis changed. Set the current value to whatever the
                 * first selected frame has for its its TCP Sequence Analysis
                 * override.
                 */
                MainWindow* topWidget = qobject_cast<MainWindow*>(mainApp->mainWindow());
                /* Ensure there is one unique or multiple selections. See issue 18642 */
                if (topWidget->hasSelection() || topWidget->hasUniqueSelection()) {
                    frame_data * fdata = topWidget->frameDataForRow((topWidget->selectedRows()).at(0));
                    enum_cb->setCurrentIndex(enum_cb->findData(fdata->tcp_snd_manual_analysis));
                    QList<int> rows = topWidget->selectedRows();
                    foreach (int row, rows) {
                        frame_data * fdata = topWidget->frameDataForRow(row);
                        prefs_add_list_value(pref, fdata, pref_stashed);
                    }
                }
            } else {
                /* The initial value was already set from the selected frames,
                 * use the current value from when the CB was changed. */
                enum_cb->setCurrentIndex(enum_cb->findData(prefs_get_enum_value(pref, pref_current)));
            }
        }
    }
}

void ModulePreferencesScrollArea::uintLineEditTextEdited(const QString &new_str)
{
    QLineEdit *uint_le = qobject_cast<QLineEdit*>(sender());
    if (!uint_le) return;

    pref_t *pref = VariantPointer<pref_t>::asPtr(uint_le->property(pref_prop_));
    if (!pref) return;

    bool ok;
    uint new_uint = new_str.toUInt(&ok, 0);
    if (ok) {
        prefs_set_uint_value(pref, new_uint, pref_stashed);
    }
}

void ModulePreferencesScrollArea::boolCheckBoxToggled(bool checked)
{
    QCheckBox *bool_cb = qobject_cast<QCheckBox*>(sender());
    if (!bool_cb) return;

    pref_t *pref = VariantPointer<pref_t>::asPtr(bool_cb->property(pref_prop_));
    if (!pref) return;

    prefs_set_bool_value(pref, checked, pref_stashed);
}

void ModulePreferencesScrollArea::enumRadioButtonToggled(bool checked)
{
    if (!checked) return;
    QRadioButton *enum_rb = qobject_cast<QRadioButton*>(sender());
    if (!enum_rb) return;

    QButtonGroup *enum_bg = enum_rb->group();
    if (!enum_bg) return;

    pref_t *pref = VariantPointer<pref_t>::asPtr(enum_rb->property(pref_prop_));
    if (!pref) return;

    if (enum_bg->checkedId() >= 0) {
        prefs_set_enum_value(pref, enum_bg->checkedId(), pref_stashed);
    }
}

void ModulePreferencesScrollArea::enumComboBoxCurrentIndexChanged(int index)
{
    QComboBox *enum_cb = qobject_cast<QComboBox*>(sender());
    if (!enum_cb) return;

    pref_t *pref = VariantPointer<pref_t>::asPtr(enum_cb->property(pref_prop_));
    if (!pref) return;

    prefs_set_enum_value(pref, enum_cb->itemData(index).toInt(), pref_stashed);
}

void ModulePreferencesScrollArea::stringLineEditTextEdited(const QString &new_str)
{
    QLineEdit *string_le = qobject_cast<QLineEdit*>(sender());
    if (!string_le) return;

    pref_t *pref = VariantPointer<pref_t>::asPtr(string_le->property(pref_prop_));
    if (!pref) return;

    prefs_set_string_value(pref, new_str.toStdString().c_str(), pref_stashed);
}

void ModulePreferencesScrollArea::rangeSyntaxLineEditTextEdited(const QString &new_str)
{
    SyntaxLineEdit *range_se = qobject_cast<SyntaxLineEdit*>(sender());
    if (!range_se) return;

    pref_t *pref = VariantPointer<pref_t>::asPtr(range_se->property(pref_prop_));
    if (!pref) return;

    if (prefs_set_stashed_range_value(pref, new_str.toUtf8().constData())) {
        if (new_str.isEmpty()) {
            range_se->setSyntaxState(SyntaxLineEdit::Empty);
        } else {
            range_se->setSyntaxState(SyntaxLineEdit::Valid);
        }
    } else {
        range_se->setSyntaxState(SyntaxLineEdit::Invalid);
    }
}

void ModulePreferencesScrollArea::uatPushButtonClicked()
{
    QPushButton *uat_pb = qobject_cast<QPushButton*>(sender());
    if (!uat_pb) return;

    pref_t *pref = VariantPointer<pref_t>::asPtr(uat_pb->property(pref_prop_));
    if (!pref) return;

    UatDialog *uat_dlg = new UatDialog(this, prefs_get_uat_value(pref));
    uat_dlg->setWindowModality(Qt::ApplicationModal);
    uat_dlg->setAttribute(Qt::WA_DeleteOnClose);
    uat_dlg->show();
}

void ModulePreferencesScrollArea::saveFilenamePushButtonClicked()
{
    QPushButton *filename_pb = qobject_cast<QPushButton*>(sender());
    if (!filename_pb) return;

    pref_t *pref = VariantPointer<pref_t>::asPtr(filename_pb->property(pref_prop_));
    if (!pref) return;

    QString filename = WiresharkFileDialog::getSaveFileName(this, mainApp->windowTitleString(prefs_get_title(pref)),
                                                    prefs_get_string_value(pref, pref_stashed));

    if (!filename.isEmpty()) {
        prefs_set_string_value(pref, QDir::toNativeSeparators(filename).toStdString().c_str(), pref_stashed);
        updateWidgets();
    }
}

void ModulePreferencesScrollArea::openFilenamePushButtonClicked()
{
    QPushButton *filename_pb = qobject_cast<QPushButton*>(sender());
    if (!filename_pb) return;

    pref_t *pref = VariantPointer<pref_t>::asPtr(filename_pb->property(pref_prop_));
    if (!pref) return;

    QString filename = WiresharkFileDialog::getOpenFileName(this, mainApp->windowTitleString(prefs_get_title(pref)),
                                                    prefs_get_string_value(pref, pref_stashed));
    if (!filename.isEmpty()) {
        prefs_set_string_value(pref, QDir::toNativeSeparators(filename).toStdString().c_str(), pref_stashed);
        updateWidgets();
    }
}

void ModulePreferencesScrollArea::dirnamePushButtonClicked()
{
    QPushButton *dirname_pb = qobject_cast<QPushButton*>(sender());
    if (!dirname_pb) return;

    pref_t *pref = VariantPointer<pref_t>::asPtr(dirname_pb->property(pref_prop_));
    if (!pref) return;

    QString dirname = WiresharkFileDialog::getExistingDirectory(this, mainApp->windowTitleString(prefs_get_title(pref)),
                                                 prefs_get_string_value(pref, pref_stashed));

    if (!dirname.isEmpty()) {
        prefs_set_string_value(pref, QDir::toNativeSeparators(dirname).toStdString().c_str(), pref_stashed);
        updateWidgets();
    }
}

/*
 * Dedicated event handling for TCP SEQ Analysis overriding.
 */
void ModulePreferencesScrollArea::enumComboBoxCurrentIndexChanged_PROTO_TCP(int index)
{
    QComboBox *enum_cb = qobject_cast<QComboBox*>(sender());
    if (!enum_cb) return;

    pref_t *pref = VariantPointer<pref_t>::asPtr(enum_cb->property(pref_prop_));
    if (!pref) return;

    // Store the index value in the current value, not the stashed value.
    // We use the stashed value to store the frame data pointers.
    prefs_set_enum_value(pref, enum_cb->itemData(index).toInt(), pref_current);
    //prefs_set_enum_value(pref, enum_cb->itemData(index).toInt(), pref_stashed);
}
