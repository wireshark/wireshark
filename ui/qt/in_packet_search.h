/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef IN_PACKET_SEARCH_H
#define IN_PACKET_SEARCH_H

#include <QModelIndex>
#include <QObject>
#include <QString>

class ProtoTree;

/**
 * @brief Search-within-current-packet logic shared by Find Packet (main window)
 *        and InPacketFindBar (single-packet dialog).
 */
class InPacketSearch : public QObject
{
    Q_OBJECT

public:
    explicit InPacketSearch(ProtoTree *tree, QObject *parent = nullptr);

    void installDelegate();

    bool isMatch(const QModelIndex &index) const;
    bool isCurrentMatch(const QModelIndex &index) const;
    bool highlightsVisible() const;

    void setHighlightEnabled(bool enabled);
    void clearMatches();

    void search(const QString &pattern, bool case_sensitive, bool use_regex);
    void findNext();
    void findPrevious();

    qsizetype matchCount() const { return matches_.size(); }
    qsizetype currentMatchIndex() const { return current_match_; }
    bool isRegexInvalid() const { return regex_invalid_; }

signals:
    void matchesChanged();

private:
    void collectIndices(const QModelIndex &parent, QList<QModelIndex> &out);
    void navigateTo(qsizetype index);
    void expandParents(const QModelIndex &index);

    ProtoTree *proto_tree_;
    QList<QModelIndex> matches_;
    qsizetype current_match_;
    bool highlight_enabled_;
    bool regex_invalid_;
};

#endif // IN_PACKET_SEARCH_H
