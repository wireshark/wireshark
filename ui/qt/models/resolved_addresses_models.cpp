/* resolved_addresses_models.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/models/resolved_addresses_models.h>

#include "file.h"

#include "epan/addr_resolv.h"
#include <wiretap/wtap.h>

extern "C"
{

static void
serv_port_hash_to_qstringlist(void *key, void *value, void *member_ptr)
{
    PortsModel *model = static_cast<PortsModel *>(member_ptr);
    serv_port_t *serv_port = (serv_port_t *)value;
    unsigned port = GPOINTER_TO_UINT(key);

    if (serv_port->tcp_name) {
        QStringList entries;

        entries << serv_port->tcp_name;
        entries << QString::number(port);
        entries << "tcp";
        model->appendRow(entries);
    }
    if (serv_port->udp_name) {
        QStringList entries;

        entries << serv_port->udp_name;
        entries << QString::number(port);
        entries << "udp";
        model->appendRow(entries);
    }
    if (serv_port->sctp_name) {
        QStringList entries;

        entries << serv_port->sctp_name;
        entries << QString::number(port);
        entries << "sctp";
        model->appendRow(entries);
    }
    if (serv_port->dccp_name) {
        QStringList entries;

        entries << serv_port->dccp_name;
        entries << QString::number(port);
        entries << "dccp";
        model->appendRow(entries);
    }
}

static void
ipv4_hash_table_resolved_to_list(void *, void *value, void *sl_ptr)
{
    QList<QStringList> *hosts = (QList<QStringList> *) sl_ptr;
    hashipv4_t *ipv4_hash_table_entry = (hashipv4_t *) value;

    if ((ipv4_hash_table_entry->flags & (USED_AND_RESOLVED_MASK)) == USED_AND_RESOLVED_MASK) {
        *hosts << (QStringList() << QString(ipv4_hash_table_entry->ip) << QString(ipv4_hash_table_entry->name));
    }
}

static void
ipv6_hash_table_resolved_to_list(void *, void *value, void *sl_ptr)
{
    QList<QStringList> *hosts = (QList<QStringList> *) sl_ptr;
    hashipv6_t *ipv6_hash_table_entry = (hashipv6_t *) value;

    if ((ipv6_hash_table_entry->flags & USED_AND_RESOLVED_MASK) == USED_AND_RESOLVED_MASK) {
        *hosts << (QStringList() << QString(ipv6_hash_table_entry->ip6) << QString(ipv6_hash_table_entry->name));
    }
}

static void
eth_hash_to_qstringlist(void *, void *value, void *sl_ptr)
{
    QList<QStringList> *values = (QList<QStringList> *) sl_ptr;
    hashether_t* tp = (hashether_t*)value;

    if (get_hash_ether_used(tp)) {
        *values << (QStringList() << QString(get_hash_ether_hexaddr(tp)) << QString(get_hash_ether_resolved_name(tp)));
    }
}

static void
manuf_hash_to_qstringlist(void *key, void *value, void *sl_ptr)
{
    QList<QStringList> *values = (QList<QStringList> *) sl_ptr;
    hashmanuf_t *manuf = (hashmanuf_t*)value;
    unsigned eth_as_guint = GPOINTER_TO_UINT(key);

    if (get_hash_manuf_used(manuf)) {
        QString entry = QString("%1:%2:%3")
                .arg((eth_as_guint >> 16 & 0xff), 2, 16, QChar('0'))
                .arg((eth_as_guint >>  8 & 0xff), 2, 16, QChar('0'))
                .arg((eth_as_guint & 0xff), 2, 16, QChar('0'));

        *values << (QStringList() << entry << QString(get_hash_manuf_resolved_name(manuf)));
    }
}

static void
wka_hash_to_qstringlist(void *key, void *value, void *sl_ptr)
{
    QList<QStringList> *values = (QList<QStringList> *) sl_ptr;
    hashwka_t *wkahash = (hashwka_t *)value;
    uint8_t *eth_addr = (uint8_t*)key;

    if (get_hash_wka_used(wkahash)) {
        QString entry = QString("%1:%2:%3:%4:%5:%6")
                .arg(eth_addr[0], 2, 16, QChar('0'))
                .arg(eth_addr[1], 2, 16, QChar('0'))
                .arg(eth_addr[2], 2, 16, QChar('0'))
                .arg(eth_addr[3], 2, 16, QChar('0'))
                .arg(eth_addr[4], 2, 16, QChar('0'))
                .arg(eth_addr[5], 2, 16, QChar('0'));

        *values << (QStringList() << entry << QString(get_hash_wka_resolved_name(wkahash)));
    }
}

}

EthernetAddressModel::EthernetAddressModel(QObject * parent):
    AStringListListModel(parent)
{
    populate();
}

QStringList EthernetAddressModel::headerColumns() const
{
    return QStringList() << tr("Type") << tr("Address") << tr("Name");
}

QStringList EthernetAddressModel::filterValues() const
{
    return QStringList()
        << tr("All entries")
        << tr("Hosts")
        << tr("Ethernet Addresses") << tr("Ethernet Manufacturers")
        << tr("Ethernet Well-Known Addresses");
}

void EthernetAddressModel::populate()
{
    QList<QStringList> hosts;   // List of (address, names)
    if (wmem_map_t *ipv4_hash_table = get_ipv4_hash_table()) {
        wmem_map_foreach(ipv4_hash_table, ipv4_hash_table_resolved_to_list, &hosts);
    }
    if (wmem_map_t *ipv6_hash_table = get_ipv6_hash_table()) {
        wmem_map_foreach(ipv6_hash_table, ipv6_hash_table_resolved_to_list, &hosts);
    }
    const QString &hosts_label = tr("Hosts");
    foreach (const QStringList &addr_name, hosts)
        appendRow(QStringList() << hosts_label << addr_name);

    QList<QStringList> values;
    if (wmem_map_t *eth_hashtable = get_eth_hashtable()) {
        wmem_map_foreach(eth_hashtable, eth_hash_to_qstringlist, &values);
    }
    const QString &eth_label = tr("Ethernet Addresses");
    foreach (const QStringList &line, values)
        appendRow(QStringList() << eth_label << line);
    values.clear();
    if (wmem_map_t *eth_hashtable = get_manuf_hashtable()) {
        wmem_map_foreach(eth_hashtable, manuf_hash_to_qstringlist, &values);
    }
    const QString &manuf_label = tr("Ethernet Manufacturers");
    foreach (const QStringList &line, values)
        appendRow(QStringList() << manuf_label << line);
    values.clear();
    if (wmem_map_t *eth_hashtable = get_wka_hashtable()) {
        wmem_map_foreach(eth_hashtable, wka_hash_to_qstringlist, &values);
    }
    const QString &wka_label = tr("Ethernet Well-Known Addresses");
    foreach (const QStringList &line, values)
        appendRow(QStringList() << wka_label << line);
}

PortsModel::PortsModel(QObject * parent):
    AStringListListModel(parent)
{
    populate();
}

QStringList PortsModel::filterValues() const
{
    return QStringList()
        << tr("All entries") << tr("tcp") << tr("udp") << tr("sctp") << tr("dccp");
}

QStringList PortsModel::headerColumns() const
{
    return QStringList() << tr("Name") << tr("Port") << tr("Type");
}

void PortsModel::populate()
{
    wmem_map_t *serv_port_hashtable = get_serv_port_hashtable();
    if (serv_port_hashtable) {
        wmem_map_foreach(serv_port_hashtable, serv_port_hash_to_qstringlist, this);
    }
}
