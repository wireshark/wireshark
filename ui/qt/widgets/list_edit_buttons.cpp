/* list_edit_buttons.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/list_edit_buttons.h>

#include <ui/qt/utils/themes/themed_icon.h>
#include <ui/qt/widgets/profile_inherit_combo_box.h>

#include <QHBoxLayout>

ListEditButtons::ListEditButtons(QWidget *parent) :
    QWidget(parent),
    move_visible_(true),
    copy_single_(false)
{
    QHBoxLayout *layout = new QHBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);

    new_button_ = makeButton("list-add");
    delete_button_ = makeButton("list-remove");
    copy_button_ = makeButton("list-copy");
    move_up_button_ = makeButton("list-move-up");
    move_down_button_ = makeButton("list-move-down");
    clear_button_ = makeButton("list-clear");

    for (QToolButton *button : { new_button_, delete_button_, copy_button_,
                                 move_up_button_, move_down_button_, clear_button_ }) {
        layout->addWidget(button);
    }

    connect(new_button_, &QToolButton::clicked, this, &ListEditButtons::newClicked);
    connect(delete_button_, &QToolButton::clicked, this, &ListEditButtons::deleteClicked);
    connect(copy_button_, &QToolButton::clicked, this, &ListEditButtons::copyClicked);
    connect(move_up_button_, &QToolButton::clicked, this, &ListEditButtons::moveUpClicked);
    connect(move_down_button_, &QToolButton::clicked, this, &ListEditButtons::moveDownClicked);
    connect(clear_button_, &QToolButton::clicked, this, &ListEditButtons::clearClicked);

    // Nothing is selected, and nothing is there to clear, to begin with
    delete_button_->setEnabled(false);
    copy_button_->setEnabled(false);
    move_up_button_->setEnabled(false);
    move_down_button_->setEnabled(false);
    clear_button_->setEnabled(false);

    tool_tips_.add = tr("Add a new entry.");
    tool_tips_.remove = tr("Remove the selected entries.");
    tool_tips_.copy = tr("Duplicate the selected entries.");
    tool_tips_.moveUp = tr("Move the selected entries up.");
    tool_tips_.moveDown = tr("Move the selected entries down.");
    tool_tips_.clear = tr("Clear all entries.");
    setToolTips(tool_tips_);
}

QToolButton *ListEditButtons::makeButton(const char *icon)
{
    QToolButton *button = new QToolButton(this);
    button->setIcon(ThemedIcon(icon));
#ifdef Q_OS_MACOS
    button->setAttribute(Qt::WA_MacSmallSize, true);
#endif
    return button;
}

void ListEditButtons::setMoveButtonsVisible(bool visible)
{
    move_visible_ = visible;
    move_up_button_->setVisible(visible);
    move_down_button_->setVisible(visible);
}

void ListEditButtons::setToolTips(const ToolTips &tool_tips)
{
    tool_tips_ = tool_tips;
    new_button_->setToolTip(tool_tips_.add);
    delete_button_->setToolTip(tool_tips_.remove);
    copy_button_->setToolTip(tool_tips_.copy);
    move_up_button_->setToolTip(tool_tips_.moveUp);
    move_down_button_->setToolTip(tool_tips_.moveDown);
    clear_button_->setToolTip(tool_tips_.clear);
}

void ListEditButtons::updateToolTip(QToolButton *button, const QString &base, const QString &reason)
{
    button->setToolTip(reason.isEmpty() ? base : QStringLiteral("%1\n%2").arg(base, reason));
}

void ListEditButtons::setSelection(const InheritSelection &sel)
{
    const QString parent_only = ProfileInheritComboBox::ownEntriesNotUsedText();
    const QString nothing_selected = tr("Select an entry first.");
    const QString inherited_read_only = tr("Inherited entries are read-only. Change them in the parent profile, "
                                           "or copy them to this profile first.");
    const QString unavailable = tr("Not available for this selection.");

    // New
    new_button_->setEnabled(sel.own_used);
    updateToolTip(new_button_, tool_tips_.add, sel.own_used ? QString() : parent_only);

    // Delete
    QString reason;
    if (!sel.selected())
        reason = nothing_selected;
    else if (sel.inherited_selected)
        reason = inherited_read_only;
    delete_button_->setEnabled(sel.selected() && !sel.inherited_selected);
    updateToolTip(delete_button_, tool_tips_.remove, reason);

    // Copy; an inherited entry is copied into the entries of this profile
    reason.clear();
    bool copy_selection = sel.selected() && (!copy_single_ || sel.selected_count == 1);
    if (!sel.own_used)
        reason = parent_only;
    else if (!sel.selected())
        reason = nothing_selected;
    else if (!copy_selection)
        reason = unavailable;
    copy_button_->setEnabled(sel.own_used && copy_selection);
    updateToolTip(copy_button_, tool_tips_.copy, reason);

    // Move
    bool can_move = sel.selected() && !sel.inherited_selected && sel.contiguous();
    reason = !sel.selected() ? nothing_selected : sel.inherited_selected ? inherited_read_only
           : !sel.contiguous() ? unavailable : QString();
    move_up_button_->setEnabled(can_move && sel.first_row > 0);
    updateToolTip(move_up_button_, tool_tips_.moveUp, reason);
    move_down_button_->setEnabled(can_move && sel.last_row < sel.own_count - 1);
    updateToolTip(move_down_button_, tool_tips_.moveDown, reason);

    // Clear removes the entries of this profile only
    reason.clear();
    if (sel.own_visible == 0)
        reason = unavailable;
    clear_button_->setEnabled(sel.own_visible != 0);
    updateToolTip(clear_button_, tool_tips_.clear, reason);
}
