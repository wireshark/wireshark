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
#include "ui_uat_dialog.h"
#include "wireshark_application.h"

#include "epan/strutil.h"
#include "epan/to_str.h"
#include "epan/value_string.h"
#include "ui/help_url.h"
#include <wsutil/report_err.h>

#include "qt_ui_utils.h"

#include <QDesktopServices>
#include <QFileDialog>
#include <QFont>
#include <QKeyEvent>
#include <QTreeWidget>
#include <QTreeWidgetItemIterator>
#include <QUrl>

#include <QDebug>

UatDialog::UatDialog(QWidget *parent, uat_t *uat) :
    QDialog(parent),
    ui(new Ui::UatDialog),
    uat_(NULL),
    cur_line_edit_(NULL),
    cur_combo_box_(NULL)
{
    ui->setupUi(this);

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

void UatDialog::setUat(uat_t *uat)
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
        case Qt::Key_Enter:
        case Qt::Key_Return:
            stringPrefEditingFinished();
            return;
        default:
            break;
        }
    } else if (cur_combo_box_ && cur_combo_box_->hasFocus()) {
        switch (evt->key()) {
        case Qt::Key_Escape:
            cur_combo_box_->setCurrentIndex(saved_combo_idx_);
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
    guint    length;
    const char *str;

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
        string_rep = bytes_to_ep_str((const guint8 *) str, length);
        break;
    }
    default:
        g_assert_not_reached();
        break;
    }

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
    Q_UNUSED(current)

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
    QFileDialog::Options fd_opt = QFileDialog::DontConfirmOverwrite;
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
        fd_opt |= QFileDialog::ShowDirsOnly;
    case PT_TXTMOD_FILENAME:
    {
        QString cur_path = fieldString(row, column);
        QString new_path = QFileDialog::getSaveFileName(this, field->title, cur_path, QString(), NULL, fd_opt);
        field->cb.set(rec, new_path.toUtf8().constData(), (unsigned) strlen(new_path.toUtf8().constData()), field->cbdata.set, field->fld_data);
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
    const char *enum_txt = cur_combo_box_->itemText(index).toUtf8().constData();
    const char *err = NULL;

    if (field->cb.chk && field->cb.chk(rec, enum_txt, (unsigned) strlen(enum_txt), field->cbdata.chk, field->fld_data, &err)) {
        field->cb.set(rec, enum_txt, (unsigned) strlen(enum_txt), field->cbdata.set, field->fld_data);
        ok_button_->setEnabled(true);
    } else {
        ok_button_->setEnabled(false);
    }
    uat_->changed = TRUE;
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
    const char *txt = text.toUtf8().constData();
    const char *err = NULL;
    bool enable_ok = true;
    SyntaxLineEdit::SyntaxState ss = SyntaxLineEdit::Empty;

    if (field->cb.chk) {
        if (field->cb.chk(rec, txt, (unsigned) strlen(txt), field->cbdata.chk, field->fld_data, &err)) {
            field->cb.set(rec, txt, (unsigned) strlen(txt), field->cbdata.set, field->fld_data);
            saved_string_pref_ = text;
            ss = SyntaxLineEdit::Valid;
        } else {
            enable_ok = false;
            ss = SyntaxLineEdit::Invalid;
        }
    }

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

    updateItem(*item);
}

void UatDialog::addRecord(bool copy_from_current)
{
    if (!uat_) return;

    void *rec = g_malloc0(uat_->record_size);

    if (copy_from_current) {
        QTreeWidgetItem *item = ui->uatTreeWidget->currentItem();
        if (!item) return;
        guint row = item->data(0, Qt::UserRole).toUInt();
        if (uat_->copy_cb) {
            uat_->copy_cb(rec, UAT_INDEX_PTR(uat_, row), uat_->record_size);
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
        wsApp->emitAppSignal(WiresharkApplication::ColumnsChanged);
    }
    if (uat_->flags & UAT_AFFECTS_DISSECTION) {
        /* Just redissect packets if we have any */
        wsApp->emitAppSignal(WiresharkApplication::PacketDissectionChanged);
    }
}


void UatDialog::on_buttonBox_accepted()
{
    if (!uat_) return;

    if (uat_->changed) {
        const gchar *err = NULL;
        uat_save(uat_, &err);

        if (err) {
            report_failure("Error while saving %s: %s", uat_->name, err);
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
        const gchar *err = NULL;
        uat_clear(uat_);
        uat_load(uat_, &err);

        if (err) {
            report_failure("Error while loading %s: %s", uat_->name, err);
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
