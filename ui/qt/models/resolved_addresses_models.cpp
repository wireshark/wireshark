/* resolved_addresses_models.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/models/resolved_addresses_models.h>

#include <glib.h>

#include "file.h"

#include "epan/addr_resolv.h"
#include <wiretap/wtap.h>

extern "C"
{

static void
serv_port_hash_to_qstringlist(gpointer key, gpointer value, gpointer sl_ptr)
{
    QStringList *string_list = (QStringList *) sl_ptr;
    serv_port_t *serv_port = (serv_port_t *)value;
    guint port = GPOINTER_TO_UINT(key);

    QStringList entries;

    if (serv_port->tcp_name) entries << QString("%1 %2 tcp").arg(serv_port->tcp_name).arg(port);
    if (serv_port->udp_name) entries << QString("%1 %2 udp").arg(serv_port->udp_name).arg(port);
    if (serv_port->sctp_name) entries << QString("%1 %2 sctp").arg(serv_port->sctp_name).arg(port);
    if (serv_port->dccp_name) entries << QString("%1 %2 dccp").arg(serv_port->dccp_name).arg(port);

    if (!entries.isEmpty()) *string_list << entries.join("\n");
}

static void
ipv4_hash_table_resolved_to_qstringlist(gpointer, gpointer value, gpointer sl_ptr)
{
    QStringList *string_list = (QStringList *) sl_ptr;
    hashipv4_t *ipv4_hash_table_entry = (hashipv4_t *) value;

    if ((ipv4_hash_table_entry->flags & NAME_RESOLVED)) {
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

    if ((ipv6_hash_table_entry->flags & NAME_RESOLVED)) {
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
    guint addr = GPOINTER_TO_UINT(key);

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
    guint addr = GPOINTER_TO_UINT(key);

    QString entry = QString("Key: 0x%1 IPv4: %2, Name: %3")
            .arg(QString::number(addr, 16))
            .arg(ipv6_hash_table_entry->ip6)
            .arg(ipv6_hash_table_entry->name);

    *string_list << entry;
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
    guint eth_as_guint = GPOINTER_TO_UINT(key);

    QString entry = QString("%1:%2:%3 %4")
            .arg((eth_as_guint >> 16 & 0xff), 2, 16, QChar('0'))
            .arg((eth_as_guint >>  8 & 0xff), 2, 16, QChar('0'))
            .arg((eth_as_guint & 0xff), 2, 16, QChar('0'))
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

EthernetAddressModel::EthernetAddressModel(QObject * parent):
    AStringListListModel(parent)
{
    populate();
}

QStringList EthernetAddressModel::headerColumns() const
{
    return QStringList() << tr("Type") << tr("Mac Address") << tr("Name");
}

QStringList EthernetAddressModel::filterValues() const
{
    return QStringList()
        << tr("All entries")
        << tr("IPv4 Hosts") << tr("IPv4 Hash Table")
        << tr("IPv6 Hosts") << tr("IPv6 Hash Table")
        << tr("Ethernet Addresses") << tr("Ethernet Manufacturers")
        << tr("Ethernet Well-Known Addresses");
}

void EthernetAddressModel::populate()
{
    QStringList values;
    wmem_map_t *ipv4_hash_table = get_ipv4_hash_table();
    if (ipv4_hash_table) {
        wmem_map_foreach(ipv4_hash_table, ipv4_hash_table_resolved_to_qstringlist, &values);
        foreach(QString line, values)
            appendRow(QStringList() << tr("IPv4 Hosts") << line.split(" "));
        wmem_map_foreach(ipv4_hash_table, ipv4_hash_table_to_qstringlist, &values);
        foreach(QString line, values)
            appendRow(QStringList() << tr("IPv4 Hash Table") << line.split(" "));
    }

    wmem_map_t *ipv6_hash_table = get_ipv6_hash_table();
    if (ipv6_hash_table) {
        wmem_map_foreach(ipv6_hash_table, ipv6_hash_table_resolved_to_qstringlist, &values);
        foreach(QString line, values)
            appendRow(QStringList() << tr("IPv6 Hosts") << line.split(" "));
        wmem_map_foreach(ipv6_hash_table, ipv6_hash_table_to_qstringlist, &values);
        foreach(QString line, values)
            appendRow(QStringList() << tr("IPv6 Hash Table") << line.split(" "));
    }

    wmem_map_t *eth_hashtable = get_eth_hashtable();
    if (eth_hashtable)
        wmem_map_foreach(eth_hashtable, eth_hash_to_qstringlist, &values);
    foreach(QString line, values)
        appendRow(QStringList() << tr("Ethernet Addresses") << line.split(" "));

    eth_hashtable = get_manuf_hashtable();
    if (eth_hashtable)
        wmem_map_foreach(eth_hashtable, manuf_hash_to_qstringlist, &values);

    foreach(QString line, values)
        appendRow(QStringList() << tr("Ethernet Manufacturers") << line.split(" "));

    eth_hashtable = get_wka_hashtable();
    if (eth_hashtable)
        wmem_map_foreach(eth_hashtable, wka_hash_to_qstringlist, &values);

    foreach(QString line, values)
        appendRow(QStringList() << tr("Ethernet Well-Known Addresses") << line.split(" "));
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
    QStringList values;

    wmem_map_t *serv_port_hashtable = get_serv_port_hashtable();
    if (serv_port_hashtable) {
        wmem_map_foreach(serv_port_hashtable, serv_port_hash_to_qstringlist, &values);
    }

    foreach(QString line, values)
        appendRow(QStringList() << line.split(" "));
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
