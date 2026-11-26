/** @file
 *
 * Base of the models of rules that can be inherited from parent profiles
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef INHERITED_RULES_MODEL_H
#define INHERITED_RULES_MODEL_H

#include <config.h>

#include <wsutil/profile_inherit.h>

#include <app/application_flavor.h>

#include <ui/qt/models/tree_model_helpers.h>
#include <ui/qt/utils/color_utils.h>
#include <ui/qt/widgets/profile_inherit_combo_box.h>

#include <QAbstractItemModel>
#include <QFont>
#include <QList>
#include <QSet>
#include <QTimer>

/**
 * @brief A flat list of rules, the profile's own rules first, then the rules inherited from parent profiles.
 *
 * Shared by the coloring rules, the tagging rules and the filter lists. A
 * rule is identified by its name and its filter, unless keyedByFilter() says
 * otherwise: an inherited rule with the name or the filter of an own rule is
 * overridden. Inherited rules are read-only, and the own
 * rules are kept, but not shown, when only the parent's rules are used.
 *
 * New rules go at the top of the own rules, as the first matching rule is
 * used. The UAT, Decode As and filter list models, whose entries have no
 * order of precedence, add new entries after the own entries instead.
 *
 * Item is a ModelHelperTreeItem with the members name_, filter_ and
 * source_profile_, isInherited(), and a copy constructor. The rules are children of
 * root_, which the derived model creates.
 */
template <typename Item>
class InheritedRulesModel : public QAbstractItemModel
{
public:
    /**
     * @brief Constructs the model.
     * @param filename The configuration file name, naming the inherit setting.
     * @param parent The parent object.
     */
    InheritedRulesModel(const char *filename, QObject *parent) :
        QAbstractItemModel(parent),
        root_(nullptr),
        inherit_mode_(profile_get_inherit(application_configuration_environment_prefix(), NULL, filename)),
        refreshing_inherited_(false),
        refresh_pending_(false),
        own_edited_(false)
    {
    }

    ~InheritedRulesModel() override
    {
        delete root_;
        qDeleteAll(inherited_rules_);
        qDeleteAll(hidden_own_rules_);
    }

    /**
     * @brief The selected inherit mode.
     * @return The mode.
     */
    profile_inherit_e inheritMode() const { return inherit_mode_; }

    /**
     * @brief The number of the profile's own rules shown, which come first.
     * @return The number of own rules.
     */
    int ownRowCount() const
    {
        int count = 0;
        for (int row = 0; row < root_->childCount(); row++) {
            if (!root_->child(row)->isInherited())
                count++;
        }
        return count;
    }

    /**
     * @brief Whether a row is a rule inherited from a parent profile.
     * @param row The row.
     * @return true if inherited.
     */
    bool isInherited(int row) const
    {
        Item *rule = root_->child(row);
        return rule != nullptr && rule->isInherited();
    }

    /**
     * @brief The parent profile a rule is inherited from.
     * @param row The row.
     * @return The profile name, empty for an own rule.
     */
    QString sourceProfile(int row) const
    {
        Item *rule = root_->child(row);
        return rule != nullptr ? rule->source_profile_ : QString();
    }

    /**
     * @brief Whether a row is an inherited rule overridden by an own rule, which is not used.
     * @param row The row.
     * @return true if the rule is inherited and overridden.
     */
    bool isOverridden(int row) const
    {
        const Item *rule = root_->child(row);
        return rule != nullptr && rule->isInherited() && overriddenByOwn(rule);
    }

    /**
     * @brief Selects where the rules come from, reloading the inherited rules.
     *
     * The own rules are kept while hidden in PROFILE_INHERIT_PARENT_ONLY mode.
     * @param mode The inherit mode.
     */
    void setInheritMode(profile_inherit_e mode)
    {
        if (mode == inherit_mode_)
            return;

        refreshing_inherited_ = true;

        // Drop the inherited rows; they are read again for the new mode
        removeInheritedRows();
        leavingInheritMode(inherit_mode_);

        if (mode == PROFILE_INHERIT_PARENT_ONLY) {
            // Keep the own rules, so another mode can show them again
            hidden_own_rules_ << takeOwnRows();
        } else if (inherit_mode_ == PROFILE_INHERIT_PARENT_ONLY) {
            insertOwnRows(hidden_own_rules_);
        }

        inherit_mode_ = mode;
        enteredInheritMode(mode);
        refreshing_inherited_ = false;

        loadInherited();
        refreshInherited();
    }

    // A flat list: the rules are the children of the root
    QModelIndex index(int row, int column, const QModelIndex &parent = QModelIndex()) const override
    {
        if (!hasIndex(row, column, parent))
            return QModelIndex();

        Item *parent_item = parent.isValid() ? static_cast<Item *>(parent.internalPointer()) : root_;
        Item *child_item = parent_item ? parent_item->child(row) : nullptr;
        return child_item ? createIndex(row, column, child_item) : QModelIndex();
    }

    QModelIndex parent(const QModelIndex &indexItem) const override
    {
        if (!indexItem.isValid())
            return QModelIndex();

        Item *item = static_cast<Item *>(indexItem.internalPointer());
        Item *parent_item = item ? item->parentItem() : nullptr;
        if (parent_item == nullptr || parent_item == root_)
            return QModelIndex();
        return createIndex(parent_item->row(), 0, parent_item);
    }

    int rowCount(const QModelIndex &parent = QModelIndex()) const override
    {
        if (parent.column() > 0)
            return 0;

        Item *parent_item = parent.isValid() ? static_cast<Item *>(parent.internalPointer()) : root_;
        return parent_item ? parent_item->childCount() : 0;
    }

    /**
     * @brief Moves own rules, as RowMoveTreeView and the UAT model do.
     *
     * Rules move within the own rules only.
     * @param sourceParent Unused, the rules are a flat list.
     * @param sourceRow The first rule to move.
     * @param count The number of rules to move.
     * @param destinationParent Unused, the rules are a flat list.
     * @param destinationChild The row where the first rule moved up, or the
     * last rule moved down, ends up.
     * @return true if the rules were moved.
     */
    bool moveRows(const QModelIndex &sourceParent, int sourceRow, int count,
                  const QModelIndex &destinationParent, int destinationChild) override
    {
        Q_UNUSED(sourceParent)
        Q_UNUSED(destinationParent)

        int own_count = ownRowCount();
        if (count <= 0 || sourceRow < 0 || sourceRow + count > own_count ||
            destinationChild < 0 || destinationChild >= own_count ||
            (destinationChild >= sourceRow && destinationChild < sourceRow + count))
            return false;

        bool up = destinationChild < sourceRow;
        if (!beginMoveRows(QModelIndex(), sourceRow, sourceRow + count - 1, QModelIndex(),
                           up ? destinationChild : destinationChild + 1))
            return false;

        // Move the items themselves, which the persistent indexes point to
        QList<Item *> rules;
        for (int i = 0; i < count; i++)
            rules << root_->takeChild(sourceRow);
        int insert_at = up ? destinationChild : destinationChild - count + 1;
        for (int i = 0; i < count; i++)
            root_->insertChild(insert_at + i, rules[i]);
        own_edited_ = true;
        endMoveRows();
        return true;
    }

protected:
    /**
     * @brief Reads the rules inherited from the parent profiles.
     * @param mode The inherit mode, not PROFILE_INHERIT_PROFILE_ONLY.
     * @return New rules with source_profile_ set, nearest parent first.
     */
    virtual QList<Item *> readInherited(profile_inherit_e mode) = 0;

    /**
     * @brief Called when switching mode, after the inherited rows are dropped.
     * @param mode The mode in use until now.
     */
    virtual void leavingInheritMode(profile_inherit_e mode) { Q_UNUSED(mode) }

    /**
     * @brief The color of the lock or the icon of a rule not used.
     * @param rule The rule.
     * @return An invalid color, for the theme's, by default.
     */
    virtual QColor iconColor(const Item *rule) const { Q_UNUSED(rule) return QColor(); }

    /**
     * @brief Called when switching mode, once the own rows for the new mode are shown.
     * @param mode The new mode.
     */
    virtual void enteredInheritMode(profile_inherit_e mode) { Q_UNUSED(mode) }

    /**
     * @brief Whether a rule is also identified by its filter, besides its name.
     *
     * An inherited rule with the filter of an own rule is then overridden.
     * @return true by default.
     */
    virtual bool keyedByFilter() const { return true; }

    /**
     * @brief Reads the inherited rules and shows them; call once root_ holds the own rules.
     *
     * An own rule overrides an inherited rule with the same name or filter,
     * which is then shown struck out, also after editing, adding or removing rules.
     */
    void initInherited()
    {
        loadInherited();
        refreshInherited();

        QObject::connect(this, &QAbstractItemModel::dataChanged, this, [this]() { scheduleRefreshInherited(); });
        QObject::connect(this, &QAbstractItemModel::rowsInserted, this, [this]() { scheduleRefreshInherited(); });
        QObject::connect(this, &QAbstractItemModel::rowsRemoved, this, [this]() { scheduleRefreshInherited(); });
        QObject::connect(this, &QAbstractItemModel::modelReset, this, [this]() { scheduleRefreshInherited(); });
    }

    /**
     * @brief Shows the inherited rules again once the change being signalled is delivered.
     *
     * Inserting or removing rows from the handler of another signal of this
     * model reaches the views before that signal does, with stale indexes.
     */
    void scheduleRefreshInherited()
    {
        if (refreshing_inherited_ || refresh_pending_)
            return;
        refresh_pending_ = true;
        QTimer::singleShot(0, this, [this]() {
            refresh_pending_ = false;
            refreshInherited();
        });
    }

    /** @brief Reads the inherited rules for the selected mode. */
    void loadInherited()
    {
        qDeleteAll(inherited_rules_);
        inherited_rules_.clear();

        if (inherit_mode_ != PROFILE_INHERIT_PROFILE_ONLY)
            inherited_rules_ = readInherited(inherit_mode_);
    }

    /**
     * @brief Whether an own rule has the name or the filter of a rule.
     *
     * An inherited rule overridden by an own rule is not used.
     * @param rule The rule.
     * @return true if an own rule overrides the rule.
     */
    bool overriddenByOwn(const Item *rule) const
    {
        int own_count = ownRowCount();
        for (int row = 0; row < own_count; row++) {
            const Item *own = root_->child(row);
            if (own->name_ == rule->name_ || (keyedByFilter() && own->filter_ == rule->filter_))
                return true;
        }
        return false;
    }

    /** @brief Shows the inherited rules after the own rules, those overridden by an own rule marked. */
    void refreshInherited()
    {
        if (refreshing_inherited_)
            return;

        // The rules to show: all inherited rules
        int own_count = ownRowCount();
        QList<Item *> visible = inherited_rules_;

        // Nothing to do if the same rules are shown already
        int shown = root_->childCount() - own_count;
        bool same = (shown == visible.count());
        for (int i = 0; same && i < shown; i++) {
            Item *rule = root_->child(own_count + i);
            same = rule->name_ == visible[i]->name_ && rule->filter_ == visible[i]->filter_ &&
                   rule->source_profile_ == visible[i]->source_profile_;
        }
        if (same) {
            // Own rules may have changed which inherited rules they override
            if (shown > 0) {
                refreshing_inherited_ = true;
                emit this->dataChanged(index(own_count, 0), index(own_count + shown - 1, columnCount() - 1));
                refreshing_inherited_ = false;
            }
            return;
        }

        refreshing_inherited_ = true;
        removeInheritedRows();
        if (!visible.isEmpty()) {
            beginInsertRows(QModelIndex(), own_count, own_count + static_cast<int>(visible.count()) - 1);
            for (Item *rule : visible) {
                Item *item = new Item(*rule);
                item->setParentItem(root_);
                root_->appendChild(item);
            }
            endInsertRows();
        }
        refreshing_inherited_ = false;
    }

    /** @brief Removes the inherited rows. */
    void removeInheritedRows()
    {
        int own_count = ownRowCount();
        int shown = root_->childCount() - own_count;
        if (shown <= 0)
            return;

        beginRemoveRows(QModelIndex(), own_count, own_count + shown - 1);
        for (int i = 0; i < shown; i++)
            root_->removeChild(own_count);
        endRemoveRows();
    }

    /** @brief Removes the own rows, returning copies of them. */
    QList<Item *> takeOwnRows()
    {
        QList<Item *> rules;
        int own_count = ownRowCount();
        if (own_count == 0)
            return rules;

        beginRemoveRows(QModelIndex(), 0, own_count - 1);
        for (int i = 0; i < own_count; i++) {
            rules << new Item(*root_->child(0));
            root_->removeChild(0);
        }
        endRemoveRows();
        return rules;
    }

    /** @brief Inserts rules as the own rows, taking them from the list. */
    void insertOwnRows(QList<Item *> &rules)
    {
        if (rules.isEmpty())
            return;

        beginInsertRows(QModelIndex(), 0, static_cast<int>(rules.count()) - 1);
        for (int i = 0; i < rules.count(); i++) {
            rules[i]->setParentItem(root_);
            root_->insertChild(i, rules[i]);
        }
        rules.clear();
        endInsertRows();
    }

    /**
     * @brief Flags of a row: an inherited rule is read-only.
     * @param idx The index.
     * @param flags The flags of an own rule.
     * @return The flags.
     */
    Qt::ItemFlags inheritedFlags(const QModelIndex &idx, Qt::ItemFlags flags) const
    {
        if (idx.isValid() && isInherited(idx.row()))
            return flags & ~(Qt::ItemIsEditable | Qt::ItemIsUserCheckable | Qt::ItemIsDragEnabled | Qt::ItemIsDropEnabled);
        return flags;
    }

    /**
     * @brief Data of an inherited rule that differs from an own rule.
     *
     * The lock replaces the check box in the name column, the text is in
     * italics, and the tool tip names the parent profile.
     * @param rule The rule.
     * @param idx The index.
     * @param role The role.
     * @param handled Set to true if the returned value is the data for the role.
     * @return The data.
     */
    QVariant inheritedData(const Item *rule, const QModelIndex &idx, int role, bool *handled) const
    {
        *handled = rule->isInherited();
        if (!rule->isInherited())
            return QVariant();

        if (overriddenByOwn(rule)) {
            // Not used: looks as an inherited rule, also struck out, with the reason
            switch (role) {
            case Qt::FontRole:
            {
                QFont font;
                font.setItalic(true);
                font.setStrikeOut(true);
                return font;
            }
            case Qt::ToolTipRole:
            case Qt::AccessibleDescriptionRole:
                return ProfileInheritComboBox::notUsedText(rule->source_profile_);
            default:
                break;
            }
        }

        switch (role) {
        case Qt::CheckStateRole:
            return QVariant();
        case Qt::DecorationRole:
            if (idx.column() != 0)
                return QVariant();
            return overriddenByOwn(rule) ? ProfileInheritComboBox::overriddenIcon(iconColor(rule))
                                         : ProfileInheritComboBox::inheritedIcon(iconColor(rule));
        case Qt::FontRole:
        case Qt::ToolTipRole:
        case Qt::AccessibleDescriptionRole:
            return ProfileInheritComboBox::inheritedData(role, rule->source_profile_);
        default:
            *handled = false;
            return QVariant();
        }
    }

    /** @brief The root item; its children are the rules shown. */
    Item *root_;

    /** @brief The inherited rules, including the ones hidden by own rules. */
    QList<Item *> inherited_rules_;

    /** @brief The profile's own rules, while hidden in PROFILE_INHERIT_PARENT_ONLY mode. */
    QList<Item *> hidden_own_rules_;

    /** @brief Where the rules come from. */
    profile_inherit_e inherit_mode_;

    /** @brief Set while the rows are being replaced. */
    bool refreshing_inherited_;

    /** @brief Set while a refresh waits for the change signalled to be delivered. */
    bool refresh_pending_;

    /** @brief Set if the user changed the own rules. */
    bool own_edited_;
};

#endif // INHERITED_RULES_MODEL_H
