/* address_editor_frame.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "file.h"
#include "frame_tvbuff.h"

#include "epan/addr_resolv.h"
#include "epan/epan_dissect.h"
#include "epan/frame_data.h"

#include "main_application.h"

#include "address_editor_frame.h"
#include <ui_address_editor_frame.h>

#include <QPushButton>
#include <QKeyEvent>

#include <ui/qt/utils/qt_ui_utils.h>

// To do:
// - Fill in currently resolved address.
// - Allow editing other kinds of addresses.

AddressEditorFrame::AddressEditorFrame(QWidget *parent) :
    AccordionFrame(parent),
    ui(new Ui::AddressEditorFrame),
    cap_file_(NULL)
{
    ui->setupUi(this);
    ui->addressComboBox->setSizeAdjustPolicy(QComboBox::AdjustToContents);

#ifdef Q_OS_MAC
    foreach (QWidget *w, findChildren<QWidget *>()) {
        w->setAttribute(Qt::WA_MacSmallSize, true);
    }
#endif
}

AddressEditorFrame::~AddressEditorFrame()
{
    delete ui;
}

QString AddressEditorFrame::addressToString(const FieldInformation& finfo)
{
    address addr;
    QString addr_str;
    const ipv4_addr_and_mask *ipv4;
    const ipv6_addr_and_prefix *ipv6;

    if (!finfo.isValid()) {
        return QString();
    }

    switch (finfo.headerInfo().type) {

    case FT_IPv4:
        // FieldInformation.toString gives us the result of
        // proto_item_fill_display_label, but that gives us
        // the currently resolved version, if resolution is
        // available and enabled. We want the unresolved string.
        ipv4 = fvalue_get_ipv4(finfo.fieldInfo()->value);
        set_address_ipv4(&addr, ipv4);
        addr_str = gchar_free_to_qstring(address_to_str(NULL, &addr));
        free_address(&addr);
        break;
    case FT_IPv6:
        ipv6 = fvalue_get_ipv6(finfo.fieldInfo()->value);
        set_address_ipv6(&addr, ipv6);
        addr_str = gchar_free_to_qstring(address_to_str(NULL, &addr));
        free_address(&addr);
        break;
    default:
        addr_str = QString();
    }
    return addr_str;
}

// NOLINTNEXTLINE(misc-no-recursion)
void AddressEditorFrame::addAddresses(const ProtoNode& node, QStringList& addresses)
{
    QString addrString = addressToString(FieldInformation(&node));
    if (!addrString.isEmpty()) {
        addresses << addrString;
    }
    ProtoNode::ChildIterator kids = node.children();
    while (kids.element().isValid()) {
        // We recurse here, but we're limited by tree depth checks in epan
        addAddresses(kids.element(), addresses);
        kids.next();
    }
}

void AddressEditorFrame::editAddresses(CaptureFile &cf, int column)
{
    cap_file_ = cf.capFile();

    if (!cap_file_->current_frame) {
        on_buttonBox_rejected();
        return;
    }

    if (!cf_read_current_record(cap_file_)) {
        on_buttonBox_rejected();
        return; // error reading the frame
    }

    epan_dissect_t edt;
    QStringList addresses;
    QString selectedString;

    ui->addressComboBox->clear();

    // Dissect the record with a visible tree and fill in the custom
    // columns. We don't really need to have a visible tree (we should
    // have one in cap_file_->edt->tree as we have a current frame), but
    // this is only a single frame that's previously been dissected so
    // the performance hit is slight anyway.
    epan_dissect_init(&edt, cap_file_->epan, true, true);
    col_custom_prime_edt(&edt, &cap_file_->cinfo);

    epan_dissect_run(&edt, cap_file_->cd_t, &cap_file_->rec,
        frame_tvbuff_new_buffer(&cap_file_->provider, cap_file_->current_frame, &cap_file_->buf),
        cap_file_->current_frame, &cap_file_->cinfo);
    epan_dissect_fill_in_columns(&edt, true, true);

    addAddresses(ProtoNode(edt.tree), addresses);

    if (column >= 0) {
        // Check selected column
        if (isAddressColumn(&cap_file_->cinfo, column)) {
            // This always gets the unresolved value.
            // XXX: For multifield custom columns, we don't have a good
            // function to return each string separately before joining
            // them. Since we know that IP addresses don't include commas,
            // we could split on commas here, and check each field value
            // to find the first one that is an IP address in our list.
            selectedString = cap_file_->cinfo.col_expr.col_expr_val[column];
        }
    } else if (cap_file_->finfo_selected) {
        selectedString = addressToString(FieldInformation(cap_file_->finfo_selected));
    }

    epan_dissect_cleanup(&edt);

    displayPreviousUserDefinedHostname();

    addresses.removeDuplicates();
    ui->addressComboBox->addItems(addresses);
    int index = ui->addressComboBox->findText(selectedString);
    if (index != -1) {
        ui->addressComboBox->setCurrentIndex(index);
    }
    ui->nameLineEdit->setFocus();
    updateWidgets();
}

void AddressEditorFrame::showEvent(QShowEvent *event)
{
    ui->nameLineEdit->setFocus();
    ui->nameLineEdit->selectAll();

    AccordionFrame::showEvent(event);
}

void AddressEditorFrame::keyPressEvent(QKeyEvent *event)
{
    if (event->modifiers() == Qt::NoModifier) {
        if (event->key() == Qt::Key_Escape) {
            on_buttonBox_rejected();
        } else if (event->key() == Qt::Key_Enter || event->key() == Qt::Key_Return) {
            if (ui->buttonBox->button(QDialogButtonBox::Ok)->isEnabled()) {
                on_buttonBox_accepted();
            }
        }
    }

    AccordionFrame::keyPressEvent(event);
}

void AddressEditorFrame::displayPreviousUserDefinedHostname()
{
    QString addr = ui->addressComboBox->currentText();
    // XXX: If there's a resolved name that wasn't manually entered,
    // we should probably display that too. Possibly even if network
    // name resolution is off globally, as get_edited_resolved_name() does.
    // It's possible to have such names from DNS lookups if the global is
    // turned on then turned back off, from NRBs, or from DNS packets.
    // There's no clean API call to always get the resolved name, but
    // we could access the hash tables directly the way that
    // models/resolved_addresses_models.cpp does.
    resolved_name_t* previous_entry = get_edited_resolved_name(addr.toUtf8().constData());
    if (previous_entry)
    {
        ui->nameLineEdit->setText(previous_entry->name);
    }
    else
    {
        ui->nameLineEdit->setText("");
    }
}

void AddressEditorFrame::updateWidgets()
{
    bool ok_enable = false;
    if (ui->addressComboBox->count() > 0) {
        ok_enable = true;
    }

    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(ok_enable);
}

void AddressEditorFrame::on_nameResolutionPreferencesToolButton_clicked()
{
    on_buttonBox_rejected();
    emit showNameResolutionPreferences("nameres");
}

void AddressEditorFrame::on_addressComboBox_currentIndexChanged(int)
{
    displayPreviousUserDefinedHostname();
    updateWidgets();
}

void AddressEditorFrame::on_nameLineEdit_textEdited(const QString &)
{
    updateWidgets();
}

void AddressEditorFrame::on_buttonBox_accepted()
{
    if (ui->addressComboBox->count() < 1) {
        return;
    }
    QString addr = ui->addressComboBox->currentText();
    QString name = ui->nameLineEdit->text();
    if (!cf_add_ip_name_from_string(cap_file_, addr.toUtf8().constData(), name.toUtf8().constData())) {
        QString error_msg = tr("Can't assign %1 to %2.").arg(name).arg(addr);
        mainApp->pushStatus(MainApplication::TemporaryStatus, error_msg);
        ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
        return;
    }
    on_buttonBox_rejected();
    // There's no point in redissecting packets if the network resolution
    // global is off. There is a use case for editing several names before
    // turning on the preference to avoid a lot of expensive redissects.
    // (Statistics->Resolved Addresses still displays them even when
    // resolution is disabled, so the user can check what has been input.)
    //
    // XXX: Can entering a new name but having nothing happen because
    // network name resolution is off be confusing to the user? The GTK
    // dialog had a simple checkbox, the "Name Resolution Preferences..."
    // is a little more complicated but hopefully obvious enough.
    if (gbl_resolv_flags.network_name) {
        emit redissectPackets();
    }
}

void AddressEditorFrame::on_buttonBox_rejected()
{
    ui->addressComboBox->clear();
    ui->nameLineEdit->clear();
    animatedHide();
}

bool AddressEditorFrame::isAddressColumn(epan_column_info *cinfo, int column)
{
    if (!cinfo || column < 0 || column >= cinfo->num_cols) return false;

    if (((cinfo->columns[column].col_fmt == COL_DEF_SRC) ||
         (cinfo->columns[column].col_fmt == COL_RES_SRC) ||
         (cinfo->columns[column].col_fmt == COL_UNRES_SRC) ||
         (cinfo->columns[column].col_fmt == COL_DEF_DST) ||
         (cinfo->columns[column].col_fmt == COL_RES_DST) ||
         (cinfo->columns[column].col_fmt == COL_UNRES_DST) ||
         (cinfo->columns[column].col_fmt == COL_DEF_NET_SRC) ||
         (cinfo->columns[column].col_fmt == COL_RES_NET_SRC) ||
         (cinfo->columns[column].col_fmt == COL_UNRES_NET_SRC) ||
         (cinfo->columns[column].col_fmt == COL_DEF_NET_DST) ||
         (cinfo->columns[column].col_fmt == COL_RES_NET_DST) ||
         (cinfo->columns[column].col_fmt == COL_UNRES_NET_DST)) &&
        strlen(cinfo->col_expr.col_expr_val[column]))
    {
        return true;
    }

    if ((cinfo->columns[column].col_fmt == COL_CUSTOM) &&
         cinfo->columns[column].col_custom_fields) {
        // We could cycle through all the col_custom_fields_ids and
        // see if proto_registrar_get_ftype() says that any of them
        // are FT_IPv4 or FT_IPv6, but let's just check the string
        // against all the addresses we found from the tree.
        return true;
    }

    return false;
}
