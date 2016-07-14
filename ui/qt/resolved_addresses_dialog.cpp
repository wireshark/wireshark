/* resolved_addresses_dialog.cpp
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

#include "resolved_addresses_dialog.h"
#include <ui_resolved_addresses_dialog.h>

#include "config.h"

#include <glib.h>

#include "file.h"

#include "epan/addr_resolv.h"
#include <wiretap/wtap.h>

#include <QMenu>
#include <QPushButton>
#include <QTextCursor>

#include "capture_file.h"
#include "wireshark_application.h"

// To do:
// - We do a *lot* of string copying.
// - We end up with a lot of numeric entries here.

extern "C" {

static void
ipv4_hash_table_resolved_to_qstringlist(gpointer, gpointer value, gpointer sl_ptr)
{
    QStringList *string_list = (QStringList *) sl_ptr;
    hashipv4_t *ipv4_hash_table_entry = (hashipv4_t *) value;

    if((ipv4_hash_table_entry->flags & DUMMY_ADDRESS_ENTRY) == 0) {
        QString entry = QString("%1\t%2")
                .arg(ipv4_hash_table_entry->ip)
                .arg(ipv4_hash_table_entry->name);
        *string_list << entry;
    }
}

static void
ipv6_hash_table_resolved_to_qstringlist(gpointer, gpointer value, gpointer sl_ptr)
{
    QStringList *string_list = (QStringList *) sl_ptr;
    hashipv6_t *ipv6_hash_table_entry = (hashipv6_t *) value;

    if((ipv6_hash_table_entry->flags & DUMMY_ADDRESS_ENTRY) == 0) {
        QString entry = QString("%1\t%2")
                .arg(ipv6_hash_table_entry->ip6)
                .arg(ipv6_hash_table_entry->name);
        *string_list << entry;
    }
}

static void
ipv4_hash_table_to_qstringlist(gpointer key, gpointer value, gpointer sl_ptr)
{
    QStringList *string_list = (QStringList *) sl_ptr;
    hashipv4_t *ipv4_hash_table_entry = (hashipv4_t *)value;
    int addr = GPOINTER_TO_UINT(key);

    QString entry = QString("Key: 0x%1 IPv4: %2, Name: %3")
            .arg(QString::number(addr, 16))
            .arg(ipv4_hash_table_entry->ip)
            .arg(ipv4_hash_table_entry->name);

    *string_list << entry;
}

static void
ipv6_hash_table_to_qstringlist(gpointer key, gpointer value, gpointer sl_ptr)
{
    QStringList *string_list = (QStringList *) sl_ptr;
    hashipv6_t *ipv6_hash_table_entry = (hashipv6_t *)value;
    int addr = GPOINTER_TO_UINT(key);

    QString entry = QString("Key: 0x%1 IPv4: %2, Name: %3")
            .arg(QString::number(addr, 16))
            .arg(ipv6_hash_table_entry->ip6)
            .arg(ipv6_hash_table_entry->name);

    *string_list << entry;
}

static void
serv_port_hash_to_qstringlist(gpointer key, gpointer value, gpointer sl_ptr)
{
    QStringList *string_list = (QStringList *) sl_ptr;
    serv_port_t *serv_port = (serv_port_t *)value;
    int port = *(int*)key;

    QStringList entries;

    if (serv_port->tcp_name) entries << QString("%1\t%2/tcp").arg(serv_port->tcp_name).arg(port);
    if (serv_port->udp_name) entries << QString("%1\t%2/udp").arg(serv_port->udp_name).arg(port);
    if (serv_port->sctp_name) entries << QString("%1\t%2/sctp").arg(serv_port->sctp_name).arg(port);
    if (serv_port->dccp_name) entries << QString("%1\t%2/dccp").arg(serv_port->dccp_name).arg(port);

    if (!entries.isEmpty()) *string_list << entries.join("\n");
}

static void
eth_hash_to_qstringlist(gpointer, gpointer value, gpointer sl_ptr)
{
    QStringList *string_list = (QStringList *) sl_ptr;
    hashether_t* tp = (hashether_t*)value;

    QString entry = QString("%1 %2")
            .arg(get_hash_ether_hexaddr(tp))
            .arg(get_hash_ether_resolved_name(tp));

   *string_list << entry;
}

static void
manuf_hash_to_qstringlist(gpointer key, gpointer value, gpointer sl_ptr)
{
    QStringList *string_list = (QStringList *) sl_ptr;
    hashmanuf_t *manuf = (hashmanuf_t*)value;
    int eth_as_gint = *(int*)key;

    QString entry = QString("%1:%2:%3 %4")
            .arg((eth_as_gint >> 16 & 0xff), 2, 16, QChar('0'))
            .arg((eth_as_gint >>  8 & 0xff), 2, 16, QChar('0'))
            .arg((eth_as_gint & 0xff), 2, 16, QChar('0'))
            .arg(get_hash_manuf_resolved_name(manuf));

   *string_list << entry;
}

static void
wka_hash_to_qstringlist(gpointer key, gpointer value, gpointer sl_ptr)
{
    QStringList *string_list = (QStringList *) sl_ptr;
    gchar *name = (gchar *)value;
    guint8 *eth_addr = (guint8*)key;

    QString entry = QString("%1:%2:%3:%4:%5:%6 %7")
            .arg(eth_addr[0], 2, 16, QChar('0'))
            .arg(eth_addr[1], 2, 16, QChar('0'))
            .arg(eth_addr[2], 2, 16, QChar('0'))
            .arg(eth_addr[3], 2, 16, QChar('0'))
            .arg(eth_addr[4], 2, 16, QChar('0'))
            .arg(eth_addr[5], 2, 16, QChar('0'))
            .arg(name);

    *string_list << entry;
}

}
const QString no_entries_ = QObject::tr("No entries.");
const QString entry_count_ = QObject::tr("%1 entries.");

ResolvedAddressesDialog::ResolvedAddressesDialog(QWidget *parent, CaptureFile *capture_file) :
    GeometryStateDialog(NULL),
    ui(new Ui::ResolvedAddressesDialog),
    file_name_(tr("[no file]"))
{
    ui->setupUi(this);
    if (parent) loadGeometry(parent->width() * 2 / 3, parent->height());
    setAttribute(Qt::WA_DeleteOnClose, true);

    QStringList title_parts = QStringList() << tr("Resolved Addresses");

    if (capture_file->isValid()) {
        file_name_ = capture_file->capFile()->filename;
        title_parts << file_name_;
    }
    setWindowTitle(wsApp->windowTitleString(title_parts));

    ui->plainTextEdit->setFont(wsApp->monospaceFont());
    ui->plainTextEdit->setReadOnly(true);
    ui->plainTextEdit->setWordWrapMode(QTextOption::NoWrap);
    ui->plainTextEdit->setTabStopWidth(ui->plainTextEdit->fontMetrics().averageCharWidth() * 8);

    if (capture_file->isValid()) {
        wtap* wth = capture_file->capFile()->wth;
        if (wth) {
            // might return null
            wtap_block_t nrb_hdr;

            /*
             * XXX - support multiple NRBs.
             */
            nrb_hdr = wtap_file_get_nrb(wth);
            if (nrb_hdr != NULL) {
                char *str;

                /*
                 * XXX - support multiple comments.
                 */
                if (wtap_block_get_nth_string_option_value(nrb_hdr, OPT_COMMENT, 0, &str) == WTAP_OPTTYPE_SUCCESS) {
                    comment_ = str;
                }
            }
        }
    }

    wmem_map_t *ipv4_hash_table = get_ipv4_hash_table();
    if (ipv4_hash_table) {
        wmem_map_foreach(ipv4_hash_table, ipv4_hash_table_resolved_to_qstringlist, &host_addresses_);
        wmem_map_foreach(ipv4_hash_table, ipv4_hash_table_to_qstringlist, &v4_hash_addrs_);
    }

    wmem_map_t *ipv6_hash_table = get_ipv6_hash_table();
    if (ipv6_hash_table) {
        wmem_map_foreach(ipv6_hash_table, ipv6_hash_table_resolved_to_qstringlist, &host_addresses_);
        wmem_map_foreach(ipv6_hash_table, ipv6_hash_table_to_qstringlist, &v6_hash_addrs_);
    }

    wmem_map_t *serv_port_hashtable = get_serv_port_hashtable();
    if(serv_port_hashtable){
        wmem_map_foreach(serv_port_hashtable, serv_port_hash_to_qstringlist, &service_ports_);
    }

    wmem_map_t *eth_hashtable = get_eth_hashtable();
    if (eth_hashtable){
        wmem_map_foreach(eth_hashtable, eth_hash_to_qstringlist, &ethernet_addresses_);
    }

    wmem_map_t *manuf_hashtable = get_manuf_hashtable();
    if (manuf_hashtable){
        wmem_map_foreach(manuf_hashtable, manuf_hash_to_qstringlist, &ethernet_manufacturers_);
    }

    wmem_map_t *wka_hashtable = get_wka_hashtable();
    if(wka_hashtable){
        wmem_map_foreach(wka_hashtable, wka_hash_to_qstringlist, &ethernet_well_known_);
    }

    fillShowMenu();
    fillBlocks();
}

ResolvedAddressesDialog::~ResolvedAddressesDialog()
{
    delete ui;
}

void ResolvedAddressesDialog::changeEvent(QEvent *event)
{
    if (0 != event)
    {
        switch (event->type())
        {
        case QEvent::LanguageChange:
            ui->retranslateUi(this);
            fillShowMenu();
            fillBlocks();
            break;
        default:
            break;
        }
    }
    QDialog::changeEvent(event);
}

void ResolvedAddressesDialog::fillShowMenu()
{
    QPushButton *show_bt = ui->buttonBox->button(QDialogButtonBox::Apply);
    show_bt->setText(tr("Show"));

    if (!show_bt->menu()) {
        show_bt->setMenu(new QMenu());
    }

    QMenu *show_menu = show_bt->menu();
    show_menu->clear();

    show_menu->addAction(ui->actionAddressesHosts);
    show_menu->addAction(ui->actionComment);
    show_menu->addAction(ui->actionIPv4HashTable);
    show_menu->addAction(ui->actionIPv6HashTable);
    show_menu->addAction(ui->actionPortNames);
    show_menu->addAction(ui->actionEthernetAddresses);
    show_menu->addAction(ui->actionEthernetManufacturers);
    show_menu->addAction(ui->actionEthernetWKA);

    show_menu->addSeparator();
    show_menu->addAction(ui->actionShowAll);
    show_menu->addAction(ui->actionHideAll);
}

void ResolvedAddressesDialog::fillBlocks()
{
    setUpdatesEnabled(false);
    ui->plainTextEdit->clear();

    QString lines;
    ui->plainTextEdit->appendPlainText(tr("# Resolved addresses found in %1").arg(file_name_));

    if (ui->actionComment->isChecked()) {
        lines = "\n";
        lines.append(tr("# Comments\n#\n# "));
        if (!comment_.isEmpty()) {
            lines.append("\n\n");
            lines.append(comment_);
            lines.append("\n");
        } else {
            lines.append(no_entries_);
        }
        ui->plainTextEdit->appendPlainText(lines);
    }

    if (ui->actionAddressesHosts->isChecked()) {
        lines = "\n";
        lines.append(tr("# Hosts\n#\n# "));
        if (!host_addresses_.isEmpty()) {
            lines.append(entry_count_.arg(host_addresses_.length()));
            lines.append("\n\n");
            lines.append(host_addresses_.join("\n"));
        } else {
            lines.append(no_entries_);
        }
        ui->plainTextEdit->appendPlainText(lines);
    }

    if (ui->actionIPv4HashTable->isChecked()) {
        lines = "\n";
        lines.append(tr("# IPv4 Hash Table\n#\n# "));
        if (!v4_hash_addrs_.isEmpty()) {
            lines.append(entry_count_.arg(v4_hash_addrs_.length()));
            lines.append(tr("\n\n"));
            lines.append(v4_hash_addrs_.join("\n"));
        } else {
            lines.append(no_entries_);
        }
        ui->plainTextEdit->appendPlainText(lines);
    }

    if (ui->actionIPv6HashTable->isChecked()) {
        lines = "\n";
        lines.append(tr("# IPv6 Hash Table\n#\n# "));
        if (!v6_hash_addrs_.isEmpty()) {
            lines.append(entry_count_.arg(v6_hash_addrs_.length()));
            lines.append(tr("\n\n"));
            lines.append(v6_hash_addrs_.join("\n"));
        } else {
            lines.append(no_entries_);
        }
        ui->plainTextEdit->appendPlainText(lines);
    }

    if (ui->actionPortNames->isChecked()) {
        lines = "\n";
        lines.append(tr("# Services\n#\n# "));
        if (!service_ports_.isEmpty()) {
            lines.append(entry_count_.arg(service_ports_.length()));
            lines.append(tr("\n\n"));
            lines.append(service_ports_.join("\n"));
        } else {
            lines.append(no_entries_);
        }
        ui->plainTextEdit->appendPlainText(lines);
    }

    if (ui->actionEthernetAddresses->isChecked()) {
        lines = "\n";
        lines.append(tr("# Ethernet addresses\n#\n# "));
        if (!ethernet_addresses_.isEmpty()) {
            lines.append(entry_count_.arg(ethernet_addresses_.length()));
            lines.append(tr("\n\n"));
            lines.append(ethernet_addresses_.join("\n"));
        } else {
            lines.append(no_entries_);
        }
        ui->plainTextEdit->appendPlainText(lines);
    }

    if (ui->actionEthernetManufacturers->isChecked()) {
        lines = "\n";
        lines.append(tr("# Ethernet manufacturers\n#\n# "));
        if (!ethernet_manufacturers_.isEmpty()) {
            lines.append(entry_count_.arg(ethernet_manufacturers_.length()));
            lines.append(tr("\n\n"));
            lines.append(ethernet_manufacturers_.join("\n"));
        } else {
            lines.append(no_entries_);
        }
        ui->plainTextEdit->appendPlainText(lines);
    }

    if (ui->actionEthernetWKA->isChecked()) {
        lines = "\n";
        lines.append(tr("# Well known Ethernet addresses\n#\n# "));
        if (!ethernet_well_known_.isEmpty()) {
            lines.append(entry_count_.arg(ethernet_well_known_.length()));
            lines.append(tr("\n\n"));
            lines.append(ethernet_well_known_.join("\n"));
        } else {
            lines.append(no_entries_);
        }
        ui->plainTextEdit->appendPlainText(lines);
    }

    ui->plainTextEdit->moveCursor(QTextCursor::Start);
    setUpdatesEnabled(true);
}

void ResolvedAddressesDialog::on_actionAddressesHosts_triggered()
{
    fillBlocks();
}

void ResolvedAddressesDialog::on_actionComment_triggered()
{
    fillBlocks();
}

void ResolvedAddressesDialog::on_actionIPv4HashTable_triggered()
{
    fillBlocks();
}

void ResolvedAddressesDialog::on_actionIPv6HashTable_triggered()
{
    fillBlocks();
}

void ResolvedAddressesDialog::on_actionPortNames_triggered()
{
    fillBlocks();
}

void ResolvedAddressesDialog::on_actionEthernetAddresses_triggered()
{
    fillBlocks();
}

void ResolvedAddressesDialog::on_actionEthernetManufacturers_triggered()
{
    fillBlocks();
}

void ResolvedAddressesDialog::on_actionEthernetWKA_triggered()
{
    fillBlocks();
}

void ResolvedAddressesDialog::on_actionShowAll_triggered()
{
    ui->actionAddressesHosts->setChecked(true);
    ui->actionComment->setChecked(true);
    ui->actionIPv4HashTable->setChecked(true);
    ui->actionIPv6HashTable->setChecked(true);
    ui->actionPortNames->setChecked(true);
    ui->actionEthernetAddresses->setChecked(true);
    ui->actionEthernetManufacturers->setChecked(true);
    ui->actionEthernetWKA->setChecked(true);

    fillBlocks();
}

void ResolvedAddressesDialog::on_actionHideAll_triggered()
{
    ui->actionAddressesHosts->setChecked(false);
    ui->actionComment->setChecked(false);
    ui->actionIPv4HashTable->setChecked(false);
    ui->actionIPv6HashTable->setChecked(false);
    ui->actionPortNames->setChecked(false);
    ui->actionEthernetAddresses->setChecked(false);
    ui->actionEthernetManufacturers->setChecked(false);
    ui->actionEthernetWKA->setChecked(false);

    fillBlocks();
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
