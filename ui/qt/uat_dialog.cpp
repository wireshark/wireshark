/* uat_dialog.cpp
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

#include "uat_dialog.h"
#include <ui_uat_dialog.h>
#include "wireshark_application.h"

#include "epan/strutil.h"
#include "epan/to_str.h"
#include "epan/uat-int.h"
#include "epan/value_string.h"
#include "ui/help_url.h"
#include <wsutil/report_err.h>

#include "qt_ui_utils.h"

#include <QComboBox>
#include <QDesktopServices>
#include <QFileDialog>
#include <QFont>
#include <QKeyEvent>
#include <QPushButton>
#include <QTreeWidget>
#include <QTreeWidgetItemIterator>
#include <QUrl>

#include <QDebug>

UatDialog::UatDialog(QWidget *parent, epan_uat *uat) :
    GeometryStateDialog(parent),
    ui(new Ui::UatDialog),
    uat_(NULL),
    cur_line_edit_(NULL),
    cur_combo_box_(NULL)
{
    ui->setupUi(this);
    if (uat) loadGeometry(0, 0, uat->name);

    ui->deleteToolButton->setEnabled(false);
    ui->copyToolButton->setEnabled(false);
    ok_button_ = ui->buttonBox->button(QDialogButtonBox::Ok);
    help_button_ = ui->buttonBox->button(QDialogButtonBox::Help);

#ifdef Q_OS_MAC
    ui->newToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->deleteToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->copyToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->pathLabel->setAttribute(Qt::WA_MacSmallSize, true);
#endif

    setUat(uat);

#if (QT_VERSION < QT_VERSION_CHECK(5, 0, 0))
    ui->uatTreeWidget->header()->setResizeMode(QHeaderView::ResizeToContents);
#else
    ui->uatTreeWidget->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
#endif

    // Need to add uat_move or uat_insert to the UAT API.
    ui->uatTreeWidget->setDragEnabled(false);
    qDebug() << "FIX Add drag reordering to UAT dialog";
}

UatDialog::~UatDialog()
{
    delete ui;
}

void UatDialog::setUat(epan_uat *uat)
{
    QString title(tr("Unknown User Accessible Table"));

    uat_ = uat;

    ui->uatTreeWidget->clear();
    ui->uatTreeWidget->setColumnCount(0);
    ui->pathLabel->clear();
    ui->pathLabel->setEnabled(false);
    help_button_->setEnabled(false);

    if (uat_) {
        if (uat_->name) {
            title = uat_->name;
        }

        QString abs_path = gchar_free_to_qstring(uat_get_actual_filename(uat_, FALSE));
        ui->pathLabel->setText(abs_path);
        ui->pathLabel->setUrl(QUrl::fromLocalFile(abs_path).toString());
        ui->pathLabel->setToolTip(tr("Open ") + uat->filename);
        ui->pathLabel->setEnabled(true);

        ui->uatTreeWidget->setColumnCount(uat_->ncols);

        for (guint col = 0; col < uat->ncols; col++) {
            ui->uatTreeWidget->headerItem()->setText(col, uat_->fields[col].title);
        }

        updateItems();

        if (uat_->help && strlen(uat_->help) > 0) {
            help_button_->setEnabled(true);
        }
    }

    setWindowTitle(title);
}

void UatDialog::keyPressEvent(QKeyEvent *evt)
{
    if (cur_line_edit_ && cur_line_edit_->hasFocus()) {
        switch (evt->key()) {
        case Qt::Key_Escape:
            cur_line_edit_->setText(saved_string_pref_);
            stringPrefEditingFinished();
            return;
        default:
            break;
        }
    } else if (cur_combo_box_ && cur_combo_box_->hasFocus()) {
        switch (evt->key()) {
        case Qt::Key_Escape:
            cur_combo_box_->setCurrentIndex(saved_combo_idx_);
            /* Fall Through */
        case Qt::Key_Enter:
        case Qt::Key_Return:
            // XXX The combo box eats enter and return
            enumPrefCurrentIndexChanged(cur_combo_box_->currentIndex());
            delete cur_combo_box_;
            return;
        default:
            break;
        }
    }
    QDialog::keyPressEvent(evt);
}

QString UatDialog::fieldString(guint row, guint column)
{
    QString string_rep;

    if (!uat_) return string_rep;

    void *rec = UAT_INDEX_PTR(uat_, row);
    uat_field_t *field = &uat_->fields[column];
    guint length;
    char *str;

    field->cb.tostr(rec, &str, &length, field->cbdata.tostr, field->fld_data);

    switch(field->mode) {
    case PT_TXTMOD_NONE:
    case PT_TXTMOD_STRING:
    case PT_TXTMOD_ENUM:
    case PT_TXTMOD_FILENAME:
    case PT_TXTMOD_DIRECTORYNAME:
        string_rep = str;
        break;
    case PT_TXTMOD_HEXBYTES: {
        {
            char* temp_str = bytes_to_str(NULL, (const guint8 *) str, length);
            QString qstr(temp_str);
            string_rep = qstr;
            wmem_free(NULL, temp_str);
        }
        break;
    }
    default:
        g_assert_not_reached();
        break;
    }

    g_free(str);
    return string_rep;
}

void UatDialog::updateItem(QTreeWidgetItem &item)
{
    if (!uat_) return;
    guint row = item.data(0, Qt::UserRole).toUInt();
    for (guint col = 0; col < uat_->ncols; col++) {
        item.setText(col, fieldString(row, col));
    }
}

void UatDialog::updateItems()
{
    if (!uat_) return;

    // Forcibly sync ui->uaTreeWidget with uat_.
    // It would probably be more correct to create a UatModel and
    // use it in conjunction with a QTreeView.
    while (ui->uatTreeWidget->topLevelItemCount() > (int) uat_->raw_data->len) {
        delete (ui->uatTreeWidget->topLevelItem(0));
    }
    for (guint row = 0; row < uat_->raw_data->len; row++) {
        QTreeWidgetItem *item = ui->uatTreeWidget->topLevelItem(row);
        if (!item) item = new QTreeWidgetItem(ui->uatTreeWidget);
        item->setData(0, Qt::UserRole, qVariantFromValue(row));
        updateItem(*item);
    }
}

void UatDialog::activateLastItem()
{
    int last_item = ui->uatTreeWidget->topLevelItemCount() - 1;
    if (last_item < 0) return;

    QModelIndex idx = ui->uatTreeWidget->model()->index(last_item, 0);
    ui->uatTreeWidget->clearSelection();
    ui->uatTreeWidget->selectionModel()->select(idx, QItemSelectionModel::Select | QItemSelectionModel::Rows);
    on_uatTreeWidget_itemActivated(ui->uatTreeWidget->topLevelItem(last_item), 0);
    ui->uatTreeWidget->setCurrentItem(ui->uatTreeWidget->topLevelItem(last_item));
}

void UatDialog::on_uatTreeWidget_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous)
{
    for (int col = 0; col < ui->uatTreeWidget->columnCount(); col++) {
        if (previous && ui->uatTreeWidget->itemWidget(previous, col)) {
            ui->uatTreeWidget->removeItemWidget(previous, col);
            updateItem(*previous);
        }
    }
    ui->uatTreeWidget->setCurrentItem(current);
}

void UatDialog::on_uatTreeWidget_itemActivated(QTreeWidgetItem *item, int column)
{
    if (!uat_) return;

    cur_line_edit_ = NULL;
    cur_combo_box_ = NULL;

    uat_field_t *field = &uat_->fields[column];
    guint row = item->data(0, Qt::UserRole).toUInt();
    void *rec = UAT_INDEX_PTR(uat_, row);
    cur_column_ = column;
    QWidget *editor = NULL;

    // Reset any active items
    QTreeWidgetItemIterator uat_it(ui->uatTreeWidget);
    while (*uat_it) {
        for (int col = 0; col < ui->uatTreeWidget->columnCount(); col++) {
            if (ui->uatTreeWidget->itemWidget((*uat_it), col)) {
                ui->uatTreeWidget->removeItemWidget((*uat_it), col);
                updateItem(*(*uat_it));
            }
        }
        ++uat_it;
    }

    switch(field->mode) {
    case PT_TXTMOD_DIRECTORYNAME:
    {
        QString cur_path = fieldString(row, column);
        const QByteArray& new_path = QFileDialog::getExistingDirectory(this,
                field->title, cur_path).toUtf8();
        field->cb.set(rec, new_path.constData(), (unsigned) new_path.size(), field->cbdata.set, field->fld_data);
        updateItem(*item);
        break;
    }

    case PT_TXTMOD_FILENAME:
    {
        QString cur_path = fieldString(row, column);
        const QByteArray& new_path = QFileDialog::getOpenFileName(this,
                field->title, cur_path, QString(), NULL, QFileDialog::DontConfirmOverwrite).toUtf8();
        field->cb.set(rec, new_path.constData(), (unsigned) new_path.size(), field->cbdata.set, field->fld_data);
        updateItem(*item);
        break;
    }

    case PT_TXTMOD_STRING:
    case PT_TXTMOD_HEXBYTES: {
        cur_line_edit_ = new SyntaxLineEdit();
        break;
    }

    case PT_TXTMOD_ENUM: {
        cur_combo_box_ = new QComboBox();
//        const enum_val_t *ev;
        const value_string *enum_vals = (const value_string *)field->fld_data;
        for (int i = 0; enum_vals[i].strptr != NULL; i++) {
            cur_combo_box_->addItem(enum_vals[i].strptr, QVariant(enum_vals[i].value));
            if (item->text(column).compare(enum_vals[i].strptr) == 0) {
                cur_combo_box_->setCurrentIndex(cur_combo_box_->count() - 1);
            }
        }
        saved_combo_idx_ = cur_combo_box_->currentIndex();
        break;
    }
    case PT_TXTMOD_NONE: break;
    default:
        g_assert_not_reached();
        break;
    }

    if (cur_line_edit_) {
        editor = cur_line_edit_;
        cur_line_edit_->setText(fieldString(row, column));
        cur_line_edit_->selectAll();
        connect(cur_line_edit_, SIGNAL(destroyed()), this, SLOT(lineEditPrefDestroyed()));
        connect(cur_line_edit_, SIGNAL(textChanged(QString)), this, SLOT(stringPrefTextChanged(QString)));
        connect(cur_line_edit_, SIGNAL(editingFinished()), this, SLOT(stringPrefEditingFinished()));
    }
    if (cur_combo_box_) {
        editor = cur_combo_box_;
        connect(cur_combo_box_, SIGNAL(currentIndexChanged(int)), this, SLOT(enumPrefCurrentIndexChanged(int)));
        connect(cur_combo_box_, SIGNAL(destroyed()), this, SLOT(enumPrefDestroyed()));
    }
    if (editor) {
        QFrame *edit_frame = new QFrame();
        QHBoxLayout *hb = new QHBoxLayout();
        QSpacerItem *spacer = new QSpacerItem(5, 10);

        hb->addWidget(editor, 0);
        hb->addSpacerItem(spacer);
        hb->setStretch(1, 1);
        hb->setContentsMargins(0, 0, 0, 0);

        edit_frame->setLineWidth(0);
        edit_frame->setFrameStyle(QFrame::NoFrame);
        // The documentation suggests setting autoFillbackground. That looks silly
        // so we clear the item text instead.
        saved_string_pref_ = item->text(column);
        item->setText(column, "");
        edit_frame->setLayout(hb);
        ui->uatTreeWidget->setItemWidget(item, column, edit_frame);
        if (cur_line_edit_) {
            ui->uatTreeWidget->setCurrentItem(item);
        }
        editor->setFocus();
    }
}

void UatDialog::on_uatTreeWidget_itemSelectionChanged()
{
    if (ui->uatTreeWidget->selectedItems().length() > 0) {
        ui->deleteToolButton->setEnabled(true);
        ui->copyToolButton->setEnabled(true);
    } else {
        ui->deleteToolButton->setEnabled(false);
        ui->copyToolButton->setEnabled(false);
    }
}

void UatDialog::lineEditPrefDestroyed()
{
    cur_line_edit_ = NULL;
}

void UatDialog::enumPrefDestroyed()
{
    cur_combo_box_ = NULL;
}

void UatDialog::enumPrefCurrentIndexChanged(int index)
{
    QTreeWidgetItem *item = ui->uatTreeWidget->currentItem();
    if (!cur_combo_box_ || !item || index < 0) return;
    guint row = item->data(0, Qt::UserRole).toUInt();
    void *rec = UAT_INDEX_PTR(uat_, row);
    uat_field_t *field = &uat_->fields[cur_column_];
    const QByteArray& enum_txt = cur_combo_box_->itemText(index).toUtf8();
    char *err = NULL;

    if (field->cb.chk && !field->cb.chk(rec, enum_txt.constData(), (unsigned) enum_txt.size(), field->cbdata.chk, field->fld_data, &err)) {
        QString err_string = "<font color='red'>%1</font>";
        ui->hintLabel->setText(err_string.arg(err));
        g_free(err);
        ok_button_->setEnabled(false);
        uat_update_record(uat_, rec, FALSE);
    } else if (uat_->update_cb) {
        field->cb.set(rec, enum_txt.constData(), (unsigned) enum_txt.size(), field->cbdata.set, field->fld_data);

        if (!uat_->update_cb(rec, &err)) {
            QString err_string = "<font color='red'>%1</font>";
            ui->hintLabel->setText(err_string.arg(err));
            g_free(err);
            ok_button_->setEnabled(false);
        } else {
            ui->hintLabel->clear();
            ok_button_->setEnabled(true);
        }
    } else {
        ui->hintLabel->clear();
        field->cb.set(rec, enum_txt.constData(), (unsigned) enum_txt.size(), field->cbdata.set, field->fld_data);
        ok_button_->setEnabled(true);
        uat_update_record(uat_, rec, TRUE);
    }

    this->update();
    uat_->changed = TRUE;
}

const QByteArray UatDialog::unhexbytes(const QString input, QString &qt_err) {
    if (input.size() % 2) {
        qt_err = tr("Uneven number of chars hex string (%1)").arg(input.size());
        return NULL;
    }

    QByteArray output = QByteArray::fromHex(input.toUtf8());

    if (output.size() != (input.size()/2)) {
        qt_err = tr("Error parsing hex string");
    }
    return output;
}


void UatDialog::stringPrefTextChanged(const QString &text)
{
    QTreeWidgetItem *item = ui->uatTreeWidget->currentItem();
    if (!cur_line_edit_) {
        cur_line_edit_ = new SyntaxLineEdit();
    }
    if (!cur_line_edit_ || !item) return;
    guint row = item->data(0, Qt::UserRole).toUInt();
    void *rec = UAT_INDEX_PTR(uat_, row);
    uat_field_t *field = &uat_->fields[cur_column_];
    SyntaxLineEdit::SyntaxState ss = SyntaxLineEdit::Empty;
    bool enable_ok = true;
    QString qt_err;
    const QByteArray &txt = (field->mode == PT_TXTMOD_HEXBYTES) ? unhexbytes(text, qt_err) : text.toUtf8();
    QString err_string = "<font color='red'>%1</font>";
    if (!qt_err.isEmpty()) {
        ui->hintLabel->setText(err_string.arg(qt_err));
        enable_ok = false;
        ss = SyntaxLineEdit::Invalid;
    } else {
        char *err = NULL;
        if (field->cb.chk && !field->cb.chk(rec, txt.constData(), (unsigned) txt.size(), field->cbdata.chk, field->fld_data, &err)) {
            ui->hintLabel->setText(err_string.arg(err));
            g_free(err);
            enable_ok = false;
            ss = SyntaxLineEdit::Invalid;
            uat_update_record(uat_, rec, FALSE);
        } else {
            ui->hintLabel->clear();
            field->cb.set(rec, txt.constData(), (unsigned) txt.size(), field->cbdata.set, field->fld_data);
            saved_string_pref_ = text;
            ss = SyntaxLineEdit::Valid;
            uat_update_record(uat_, rec, TRUE);
        }
    }
    this->update();

    ok_button_->setEnabled(enable_ok);
    cur_line_edit_->setSyntaxState(ss);
    uat_->changed = TRUE;
}

void UatDialog::stringPrefEditingFinished()
{
    QTreeWidgetItem *item = ui->uatTreeWidget->currentItem();
    if (!cur_line_edit_ || !item) return;

    item->setText(cur_column_, saved_string_pref_);
    ok_button_->setEnabled(true);

    if (uat_ && uat_->update_cb) {
        gchar *err;
        void *rec = UAT_INDEX_PTR(uat_, item->data(0, Qt::UserRole).toUInt());
        if (!uat_->update_cb(rec, &err)) {
            QString err_string = "<font color='red'>%1</font>";
            ui->hintLabel->setText(err_string.arg(err));
            g_free(err);
            ok_button_->setEnabled(false);
        } else {
            ui->hintLabel->clear();
        }
        this->update();
    }

    cur_line_edit_ = NULL;
    updateItem(*item);
}

void UatDialog::addRecord(bool copy_from_current)
{
    if (!uat_) return;

    void *rec = g_malloc0(uat_->record_size);

    if (copy_from_current && uat_->copy_cb) {
        QTreeWidgetItem *item = ui->uatTreeWidget->currentItem();
        if (!item) return;
        guint row = item->data(0, Qt::UserRole).toUInt();
        uat_->copy_cb(rec, UAT_INDEX_PTR(uat_, row), uat_->record_size);
    } else {
        for (guint col = 0; col < uat_->ncols; col++) {
            uat_field_t *field = &uat_->fields[col];
            switch (field->mode) {
            case PT_TXTMOD_ENUM:
                guint length;
                char *str;
                field->cb.tostr(rec, &str, &length, field->cbdata.tostr, field->fld_data);
                field->cb.set(rec, str, length, field->cbdata.set, field->fld_data);
                g_free(str);
                break;
            case PT_TXTMOD_NONE:
                break;
            default:
                field->cb.set(rec, "", 0, field->cbdata.set, field->fld_data);
                break;
            }
        }
    }

    uat_add_record(uat_, rec, TRUE);
    if (uat_->free_cb) {
        uat_->free_cb(rec);
    }
    g_free(rec);
    uat_->changed = TRUE;
    updateItems();
    activateLastItem();
}

void UatDialog::on_newToolButton_clicked()
{
    addRecord();
}

void UatDialog::on_deleteToolButton_clicked()
{
    QTreeWidgetItem *item = ui->uatTreeWidget->currentItem();
    if (!uat_ || !item) return;

    guint row = item->data(0, Qt::UserRole).toUInt();

    uat_remove_record_idx(uat_, row);
    updateItems();

    on_uatTreeWidget_itemSelectionChanged();
    uat_->changed = TRUE;
}

void UatDialog::on_copyToolButton_clicked()
{
    addRecord(true);
}

void UatDialog::applyChanges()
{
    if (!uat_) return;

    if (uat_->flags & UAT_AFFECTS_FIELDS) {
        /* Recreate list with new fields and redissect packets */
        wsApp->queueAppSignal(WiresharkApplication::FieldsChanged);
    }
    if (uat_->flags & UAT_AFFECTS_DISSECTION) {
        /* Just redissect packets if we have any */
        wsApp->queueAppSignal(WiresharkApplication::PacketDissectionChanged);
    }
}


void UatDialog::on_buttonBox_accepted()
{
    if (!uat_) return;

    if (uat_->changed) {
        gchar *err = NULL;

        if (!uat_save(uat_, &err)) {
            report_failure("Error while saving %s: %s", uat_->name, err);
            g_free(err);
        }

        if (uat_->post_update_cb) {
            uat_->post_update_cb();
        }
        applyChanges();
    }
}

void UatDialog::on_buttonBox_rejected()
{
    if (!uat_) return;

    if (uat_->changed) {
        gchar *err = NULL;
        uat_clear(uat_);
        if (!uat_load(uat_, &err)) {
            report_failure("Error while loading %s: %s", uat_->name, err);
            g_free(err);
        }
        applyChanges();
    }
}

void UatDialog::on_buttonBox_helpRequested()
{
    if (!uat_) return;

    QString help_page = uat_->help, url;

    help_page.append(".html");
    url = gchar_free_to_qstring(user_guide_url(help_page.toUtf8().constData()));
    if (!url.isNull()) {
        QDesktopServices::openUrl(QUrl(url));
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
