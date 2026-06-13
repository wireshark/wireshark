/* in_packet_search.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "in_packet_search.h"

#include "proto_tree.h"
#include "models/in_packet_find_delegate.h"
#include "main_application.h"

#include <QAbstractItemModel>
#include <QRegularExpression>

InPacketSearch::InPacketSearch(ProtoTree *tree, QObject *parent) :
    QObject(parent),
    proto_tree_(tree),
    current_match_(-1),
    highlight_enabled_(false),
    regex_invalid_(false)
{
}

void InPacketSearch::installDelegate()
{
    if (!proto_tree_ || proto_tree_->itemDelegate()) {
        return;
    }
    InPacketFindDelegate *delegate = new InPacketFindDelegate(this, proto_tree_);
    proto_tree_->setItemDelegate(delegate);
}

bool InPacketSearch::isMatch(const QModelIndex &index) const
{
    return matches_.contains(index);
}

bool InPacketSearch::isCurrentMatch(const QModelIndex &index) const
{
    if (current_match_ < 0 || current_match_ >= matches_.size()) {
        return false;
    }
    return matches_.at(current_match_) == index;
}

bool InPacketSearch::highlightsVisible() const
{
    return highlight_enabled_ && !matches_.isEmpty();
}

void InPacketSearch::setHighlightEnabled(bool enabled)
{
    if (highlight_enabled_ == enabled) {
        return;
    }
    highlight_enabled_ = enabled;
    if (proto_tree_) {
        proto_tree_->viewport()->update();
    }
}

void InPacketSearch::clearMatches()
{
    matches_.clear();
    current_match_ = -1;
    regex_invalid_ = false;
    emit matchesChanged();
    if (proto_tree_) {
        proto_tree_->viewport()->update();
    }
}

void InPacketSearch::search(const QString &pattern, bool case_sensitive, bool use_regex)
{
    matches_.clear();
    current_match_ = -1;
    regex_invalid_ = false;

    mainApp->popStatus(MainApplication::FilterSyntax);

    if (pattern.isEmpty() || !proto_tree_) {
        emit matchesChanged();
        proto_tree_->viewport()->update();
        return;
    }

    QList<QModelIndex> all_indices;
    collectIndices(QModelIndex(), all_indices);

    QString regex_pattern = use_regex ? pattern : QRegularExpression::escape(pattern);

    QRegularExpression::PatternOptions opts = QRegularExpression::NoPatternOption;
    if (!case_sensitive) {
        opts |= QRegularExpression::CaseInsensitiveOption;
    }

    QRegularExpression re(regex_pattern, opts);
    if (!re.isValid()) {
        regex_invalid_ = true;
        emit matchesChanged();
        proto_tree_->viewport()->update();
        return;
    }

    for (const QModelIndex &idx : all_indices) {
        QString text = idx.data(Qt::DisplayRole).toString();
        if (re.match(text).hasMatch()) {
            matches_.append(idx);
        }
    }

    if (!matches_.isEmpty()) {
        current_match_ = 0;
        navigateTo(current_match_);
    }

    emit matchesChanged();
    proto_tree_->viewport()->update();
}

void InPacketSearch::findNext()
{
    if (matches_.isEmpty()) {
        return;
    }
    current_match_ = static_cast<qsizetype>((current_match_ + 1) % matches_.size());
    navigateTo(current_match_);
    emit matchesChanged();
    proto_tree_->viewport()->update();
}

void InPacketSearch::findPrevious()
{
    if (matches_.isEmpty()) {
        return;
    }
    current_match_ = static_cast<qsizetype>((current_match_ - 1 + matches_.size()) % matches_.size());
    navigateTo(current_match_);
    emit matchesChanged();
    proto_tree_->viewport()->update();
}

void InPacketSearch::collectIndices(const QModelIndex &parent, QList<QModelIndex> &out)
{
    QAbstractItemModel *model = proto_tree_->model();
    if (!model) {
        return;
    }

    QList<QModelIndex> stack;
    int rows = model->rowCount(parent);
    for (int r = rows - 1; r >= 0; --r) {
        QModelIndex idx = model->index(r, 0, parent);
        if (idx.isValid()) {
            stack.append(idx);
        }
    }

    while (!stack.isEmpty()) {
        QModelIndex current = stack.takeLast();
        out.append(current);

        int child_rows = model->rowCount(current);
        for (int r = child_rows - 1; r >= 0; --r) {
            QModelIndex child = model->index(r, 0, current);
            if (child.isValid()) {
                stack.append(child);
            }
        }
    }
}

void InPacketSearch::navigateTo(qsizetype index)
{
    if (index < 0 || index >= matches_.size()) {
        return;
    }

    QModelIndex match = matches_.at(index);
    expandParents(match);
    proto_tree_->autoScrollTo(match);
}

void InPacketSearch::expandParents(const QModelIndex &index)
{
    QList<QModelIndex> parents;
    QModelIndex parent = index.parent();
    while (parent.isValid()) {
        parents.prepend(parent);
        parent = parent.parent();
    }
    for (const QModelIndex &p : parents) {
        proto_tree_->expand(p);
    }
}
