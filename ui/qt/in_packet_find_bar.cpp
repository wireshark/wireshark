/* in_packet_find_bar.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "in_packet_find_bar.h"
#include "proto_tree.h"
#include "models/in_packet_find_delegate.h"

#include <QAbstractItemModel>
#include <QApplication>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QPalette>
#include <QRegularExpression>
#include <QStyle>
#include "main_application.h"

int InPacketFindBar::open_instances_ = 0;

InPacketFindBar::~InPacketFindBar()
{
    if (is_open_) {
        --open_instances_;
        is_open_ = false;
    }
}

InPacketFindBar::InPacketFindBar(ProtoTree *tree, QWidget *parent) :
    QWidget(parent),
    proto_tree_(tree),
    is_open_(false),
    current_match_(-1),
    regex_invalid_(false),
    natural_height_(0)
{
    // Build UI
    QHBoxLayout *layout = new QHBoxLayout(this);
    layout->setContentsMargins(4, 2, 4, 2);
    layout->setSpacing(4);

    // Search field
    search_edit_ = new SyntaxLineEdit(this);
    search_edit_->setPlaceholderText(tr("Find in packet%1").arg(UTF8_HORIZONTAL_ELLIPSIS));
    search_edit_->setFont(mainApp->monospaceFont());
    search_edit_->setMinimumWidth(180);
    layout->addWidget(search_edit_);

    // Toggle buttons helper lambda
    auto makePill = [this](const QString &text) -> QToolButton* {
        QToolButton *btn = new QToolButton(this);
        btn->setText(text);
        btn->setCheckable(true);
        return btn;
    };

    case_button_ = makePill(tr("Case"));
    regex_button_ = makePill(tr("Regex"));
    word_button_ = makePill(tr("Word"));
    layout->addWidget(case_button_);
    layout->addWidget(regex_button_);
    layout->addWidget(word_button_);

    // Counter label
    counter_label_ = new QLabel(this);
    counter_label_->setMinimumWidth(70);
    layout->addWidget(counter_label_);

    // Prev / Next
    prev_button_ = new QToolButton(this);
    prev_button_->setText(QStringLiteral("\u25B2"));
    prev_button_->setToolTip(tr("Previous match (Shift+Enter)"));
    prev_button_->setAutoRaise(true);
    layout->addWidget(prev_button_);

    next_button_ = new QToolButton(this);
    next_button_->setText(QStringLiteral("\u25BC"));
    next_button_->setToolTip(tr("Next match (Enter)"));
    next_button_->setAutoRaise(true);
    layout->addWidget(next_button_);

    // Spacer
    layout->addStretch();

    // Close
    close_button_ = new QToolButton(this);
    close_button_->setText(tr("Cancel"));
    layout->addWidget(close_button_);

    setLayout(layout);

    // Match bar background to proto tree
    QPalette pal = palette();
    pal.setColor(QPalette::Window, pal.color(QPalette::Base));
    setPalette(pal);
    setAutoFillBackground(true);

    // Animation setup
    animation_ = new QPropertyAnimation(this, "barHeight", this);
    animation_->setDuration(120);
    animation_->setEasingCurve(QEasingCurve::OutCubic);

    // Debounce timer
    debounce_timer_ = new QTimer(this);
    debounce_timer_->setSingleShot(true);
    debounce_timer_->setInterval(50);
    connect(debounce_timer_, &QTimer::timeout, this, &InPacketFindBar::performSearch);

    // Connections
    connect(search_edit_, &QLineEdit::textChanged, this, &InPacketFindBar::onTextChanged);
    connect(next_button_, &QToolButton::clicked, this, &InPacketFindBar::findNext);
    connect(prev_button_, &QToolButton::clicked, this, &InPacketFindBar::findPrevious);
    connect(close_button_, &QToolButton::clicked, this, &InPacketFindBar::closeBar);
    connect(case_button_, &QToolButton::toggled, this, &InPacketFindBar::onToggleChanged);
    connect(regex_button_, &QToolButton::toggled, this, &InPacketFindBar::onToggleChanged);
    connect(word_button_, &QToolButton::toggled, this, &InPacketFindBar::onToggleChanged);

    // Install event filter on search_edit_ for Enter / Shift+Enter / Escape
    search_edit_->installEventFilter(this);

    // Install delegate on tree
    InPacketFindDelegate *delegate = new InPacketFindDelegate(this, proto_tree_);
    proto_tree_->setItemDelegate(delegate);

    // Start hidden
    setVisible(false);
    setMaximumHeight(0);
}

int InPacketFindBar::barHeight() const 
{
    return maximumHeight();
}

void InPacketFindBar::setBarHeight(int h)
{
    setMaximumHeight(h);
}

void InPacketFindBar::showAnimated()
{
    if (isVisible() && maximumHeight() > 0) {
        // Already open (just refocus)
        search_edit_->setFocus();
        search_edit_->selectAll();
        return;
    }

    // Calculate natural height on first show
    if (natural_height_ == 0) {
        setMaximumHeight(QWIDGETSIZE_MAX);
        adjustSize();
        natural_height_ = sizeHint().height();
        setMaximumHeight(0);
    }

    setVisible(true);
    animation_->stop();
    animation_->setStartValue(0);
    animation_->setEndValue(natural_height_);
    animation_->start();

    if (!is_open_) { 
        ++open_instances_;
        is_open_ = true;
    }

    search_edit_->setFocus();
    search_edit_->selectAll();
}

void InPacketFindBar::hideAnimated()
{
    animation_->stop();
    animation_->setStartValue(maximumHeight());
    animation_->setEndValue(0);

    QMetaObject::Connection *conn = new QMetaObject::Connection();
    *conn = connect(animation_, &QPropertyAnimation::finished, this, [this, conn]() {
        setVisible(false);
        // Clear highlights
        matches_.clear();
        current_match_ = -1;
        regex_invalid_ = false;
        counter_label_->clear();
        search_edit_->setSyntaxState(SyntaxLineEdit::Empty);
        if (is_open_) {
            --open_instances_;
            is_open_ = false;
        }
        emit matchesChanged();
        disconnect(*conn);
        delete conn;
    });
    animation_->start();
}

void InPacketFindBar::focusSearchField()
{
    if (isVisible()) {
        search_edit_->setFocus();
        search_edit_->selectAll();
    }
}

bool InPacketFindBar::isMatch(const QModelIndex &index) const
{
    return matches_.contains(index);
}

bool InPacketFindBar::isCurrentMatch(const QModelIndex &index) const
{
    if (current_match_ < 0 || current_match_ >= matches_.size())
        return false;
    return matches_.at(current_match_) == index;
}

bool InPacketFindBar::isDarkMode() const
{
    return palette().color(QPalette::Window).lightness() < 128;
}

bool InPacketFindBar::eventFilter(QObject *obj, QEvent *event)
{
    if (obj == search_edit_ && event->type() == QEvent::KeyPress) {
        QKeyEvent *ke = static_cast<QKeyEvent *>(event);
        if (ke->key() == Qt::Key_Escape) {
            closeBar();
            return true;
        }
        if (ke->key() == Qt::Key_Return || ke->key() == Qt::Key_Enter) {
            if (ke->modifiers() & Qt::ShiftModifier) {
                findPrevious();
            } else {
                findNext();
            }
            return true;
        }
    }
    return QWidget::eventFilter(obj, event);
}

void InPacketFindBar::onTextChanged(const QString &)
{
    debounce_timer_->start();
}

void InPacketFindBar::performSearch()
{
    updateMatches();
}

void InPacketFindBar::onToggleChanged()
{
    if (!search_edit_->text().isEmpty()) {
        updateMatches();
    }
}

void InPacketFindBar::collectIndices(const QModelIndex &parent, QList<QModelIndex> &out)
{
    QAbstractItemModel *model = proto_tree_->model();
    if (!model) return;

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

void InPacketFindBar::updateMatches()
{
    matches_.clear();
    current_match_ = -1;
    regex_invalid_ = false;

    QString pattern = search_edit_->text();

    if (pattern.isEmpty()) {
        search_edit_->setSyntaxState(SyntaxLineEdit::Empty);
        updateCounterLabel();
        emit matchesChanged();
        proto_tree_->viewport()->update();
        return;
    }

    // Build all indices
    QList<QModelIndex> all_indices;
    collectIndices(QModelIndex(), all_indices);

    bool case_sensitive = case_button_->isChecked();
    bool use_regex = regex_button_->isChecked();
    bool whole_word = word_button_->isChecked();

    // Build pattern string
    QString regex_pattern;
    if (use_regex) {
        regex_pattern = pattern;
    } else {
        regex_pattern = QRegularExpression::escape(pattern);
    }

    if (whole_word) {
        regex_pattern = QStringLiteral("\\b") + regex_pattern + QStringLiteral("\\b");
    }

    QRegularExpression::PatternOptions opts = QRegularExpression::NoPatternOption;
    if (!case_sensitive) {
        opts |= QRegularExpression::CaseInsensitiveOption;
    }

    QRegularExpression re(regex_pattern, opts);
    if (!re.isValid()) {
        regex_invalid_ = true;
        search_edit_->setSyntaxState(SyntaxLineEdit::Invalid);
        updateCounterLabel();
        emit matchesChanged();
        proto_tree_->viewport()->update();
        return;
    }

    search_edit_->setSyntaxState(SyntaxLineEdit::Valid);

    // Search all items
    for (const QModelIndex &idx : all_indices) {
        QString text = idx.data(Qt::DisplayRole).toString();
        if (re.match(text).hasMatch()) {
            matches_.append(idx);
        }
    }

    if (!matches_.isEmpty()) {
        current_match_ = 0;
        navigateTo(current_match_);
        search_edit_->setSyntaxState(SyntaxLineEdit::Valid);
    } else {
        search_edit_->setSyntaxState(SyntaxLineEdit::Invalid);
    }

    updateCounterLabel();
    emit matchesChanged();
    proto_tree_->viewport()->update();
}

void InPacketFindBar::updateCounterLabel()
{
    if (search_edit_->text().isEmpty()) {
        counter_label_->clear();
        return;
    }
    if (regex_invalid_) {
        counter_label_->setText(tr("invalid pattern"));
        return;
    }
    if (matches_.isEmpty()) {
        counter_label_->setText(tr("no matches"));
        return;
    }
    counter_label_->setText(tr("%1 of %2").arg(current_match_ + 1).arg(matches_.size()));
}

void InPacketFindBar::navigateTo(qsizetype index)
{
    if (index < 0 || index >= matches_.size())
        return;

    QModelIndex match = matches_.at(index);

    // Expand parents so the item is visible
    expandParents(match);

    proto_tree_->autoScrollTo(match);

    proto_tree_->viewport()->update();
}

void InPacketFindBar::expandParents(const QModelIndex &index)
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

void InPacketFindBar::findNext()
{
    if (matches_.isEmpty()) return;
    current_match_ = static_cast<qsizetype>((current_match_ + 1) % matches_.size());
    navigateTo(current_match_);
    updateCounterLabel();
    proto_tree_->viewport()->update();
}

void InPacketFindBar::findPrevious()
{
    if (matches_.isEmpty()) return;
    current_match_ = static_cast<qsizetype>((current_match_ - 1 + matches_.size()) % matches_.size());
    navigateTo(current_match_);
    updateCounterLabel();
    proto_tree_->viewport()->update();
}

void InPacketFindBar::closeBar()
{
    hideAnimated();
}
