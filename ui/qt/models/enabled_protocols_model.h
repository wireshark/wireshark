/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ENABLED_PROTOCOLS_MODEL_H
#define ENABLED_PROTOCOLS_MODEL_H

#include <config.h>

#include <ui/qt/models/tree_model_helpers.h>

#include <epan/proto.h>

#include <QAbstractItemModel>
#include <QSortFilterProxyModel>

/**
 * @brief Represents a protocol item that can be enabled or disabled in a tree model.
 */
class EnabledProtocolItem : public ModelHelperTreeItem<EnabledProtocolItem>
{
    Q_GADGET
public:
    /**
     * @brief Defines the type of enabled protocol.
     */
    enum EnableProtocolType{
        Any,       /**< Any protocol type. */
        Standard,  /**< A standard protocol. */
        Heuristic  /**< A heuristic protocol. */
    };
    Q_ENUM(EnableProtocolType)

    /**
     * @brief Constructs a new EnabledProtocolItem.
     * @param name The name of the protocol.
     * @param description The description of the protocol.
     * @param enabled True if the protocol is enabled.
     * @param parent The parent item in the tree.
     */
    EnabledProtocolItem(QString name, QString description, bool enabled, EnabledProtocolItem* parent);

    /**
     * @brief Destroys the EnabledProtocolItem.
     */
    virtual ~EnabledProtocolItem();

    /**
     * @brief Retrieves the name of the protocol.
     * @return The protocol name.
     */
    QString name() const {return name_;}

    /**
     * @brief Retrieves the description of the protocol.
     * @return The protocol description.
     */
    QString description() const {return description_;}

    /**
     * @brief Checks if the protocol is currently marked as enabled.
     * @return True if enabled, false otherwise.
     */
    bool enabled() const {return enabled_;}

    /**
     * @brief Sets the enabled state of the protocol.
     * @param enable True to enable, false to disable.
     */
    void setEnabled(bool enable) {enabled_ = enable;}

    /**
     * @brief Retrieves the type of the protocol item.
     * @return The protocol type enum value.
     */
    EnableProtocolType type() const;

    /**
     * @brief Applies the current enabled value to the underlying core structures.
     * @return True if the value was successfully applied and resulted in a change.
     */
    bool applyValue();

protected:
    /**
     * @brief Implements the specific logic to apply the value change to the core.
     * @param value The value to apply.
     */
    virtual void applyValuePrivate(bool value) = 0;

    /** The protocol name. */
    QString name_;

    /** The protocol description. */
    QString description_;

    /** The current enabled state. */
    bool enabled_;

    /** The initial enabled state, used to determine if a change occurred. */
    bool enabledInit_;      //value that model starts with to determine change

    /** The protocol classification type. */
    EnableProtocolType type_;
};

/**
 * @brief A tree model managing the list of all standard and heuristic protocols.
 */
class EnabledProtocolsModel : public QAbstractItemModel
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new EnabledProtocolsModel.
     * @param parent The parent QObject, defaults to Q_NULLPTR.
     */
    explicit EnabledProtocolsModel(QObject * parent = Q_NULLPTR);

    /**
     * @brief Destroys the EnabledProtocolsModel.
     */
    virtual ~EnabledProtocolsModel();

    /**
     * @brief Enumerates the columns for the enabled protocols model.
     */
    enum EnabledProtocolsColumn {
        colProtocol = 0,    /**< Protocol name column. */
        colDescription,     /**< Protocol description column. */
        colLast            /**< End of columns marker. */
    };

    /**
     * @brief Enumerates the custom data roles for the enabled protocols model.
     */
    enum EnableProtocolData {
        DATA_ENABLE = Qt::UserRole, /**< Role to access the enable state. */
        DATA_PROTOCOL_TYPE          /**< Role to access the protocol type. */
    };

    /**
     * @brief Generates an index for the given row and column.
     * @param row The row index.
     * @param column The column index.
     * @param parent The parent index (defaults to an invalid QModelIndex).
     * @return The corresponding model index.
     */
    QModelIndex index(int row, int column,
                      const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Retrieves the parent of a given index.
     * @param index The child model index.
     * @return The parent model index.
     */
    QModelIndex parent(const QModelIndex &index) const;

    /**
     * @brief Retrieves the item flags for a given index.
     * @param index The model index.
     * @return The item flags.
     */
    Qt::ItemFlags flags(const QModelIndex &index) const;

    /**
     * @brief Retrieves data from the model for a given index and role.
     * @param index The model index.
     * @param role The data role requested.
     * @return The data associated with the index and role.
     */
    QVariant data(const QModelIndex &index, int role) const;

    /**
     * @brief Sets data in the model for a given index and role.
     * @param index The model index to update.
     * @param value The value to set.
     * @param role The role being edited (defaults to Qt::EditRole).
     * @return True if successful, false otherwise.
     */
    bool setData(const QModelIndex &index, const QVariant &value, int role = Qt::EditRole);

    /**
     * @brief Retrieves the header data for a specific section and role.
     * @param section The column or row section.
     * @param orientation The orientation of the header.
     * @param role The data role requested (defaults to Qt::DisplayRole).
     * @return The header data.
     */
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const;

    /**
     * @brief Returns the number of rows under a given parent.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return The number of rows.
     */
    int rowCount(const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Returns the number of columns under a given parent.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return The number of columns.
     */
    int columnCount(const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Populates the model with protocols from the core engine.
     */
    void populate();

    /**
     * @brief Applies pending changes to the core protocol definitions.
     * @param writeChanges True to write changes out to the configuration file (defaults to true).
     */
    void applyChanges(bool writeChanges = true);

    /**
     * @brief Disables a specific protocol directly in the core.
     * @param protocol Pointer to the core protocol structure.
     */
    static void disableProtocol(struct _protocol *protocol);

protected:
    /**
     * @brief Triggers the core mechanism to save protocol changes.
     * @param writeChanges True to save to disk (defaults to true).
     */
    static void saveChanges(bool writeChanges = true);

private:
    /** Pointer to the root item of the model tree. */
    EnabledProtocolItem* root_;
};

/**
 * @brief A proxy model used for filtering and sorting the enabled protocols model.
 */
class EnabledProtocolsProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    /**
     * @brief Defines the search filtering scope.
     */
    enum SearchType
    {
        EveryWhere = 0x0,       /**< Search all text fields. */
        OnlyProtocol = 0x1,     /**< Search only protocol names. */
        OnlyDescription = 0x2,  /**< Search only protocol descriptions. */
        EnabledItems = 0x4,     /**< Show only enabled items. */
        DisabledItems = 0x8,    /**< Show only disabled items. */
    };
    Q_ENUM(SearchType)
    Q_DECLARE_FLAGS(SearchTypes, SearchType)

    /**
     * @brief Defines the action type when batch enabling/disabling items.
     */
    enum EnableType
    {
        Enable,   /**< Enable items. */
        Disable,  /**< Disable items. */
        Invert    /**< Invert the enable state. */
    };

    /**
     * @brief Constructs a new EnabledProtocolsProxyModel.
     * @param parent The parent QObject, defaults to Q_NULLPTR.
     */
    explicit EnabledProtocolsProxyModel(QObject * parent = Q_NULLPTR);

    /**
     * @brief Determines whether a row from the source model should be displayed.
     * @param sourceRow The row in the source model.
     * @param sourceParent The parent index in the source model.
     * @return True if the row is accepted, false otherwise.
     */
    virtual bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const override;

    /**
     * @brief Retrieves item flags, taking into account any proxy state modifications.
     * @param index The proxy model index.
     * @return The item flags.
     */
    virtual Qt::ItemFlags flags(const QModelIndex &index) const override;

    /**
     * @brief Sets the active filter criteria.
     * @param filter The text/pattern to filter by.
     * @param type The search scope for the text.
     * @param protocolType The specific protocol type (e.g., Any, Standard) to filter by.
     */
    void setFilter(const QString& filter, EnabledProtocolsProxyModel::SearchTypes type,
        EnabledProtocolItem::EnableProtocolType protocolType);

    /**
     * @brief Applies an enable/disable action to a parent item and all its children.
     * @param enable The action to apply (Enable, Disable, Invert).
     * @param parent The parent model index to act upon (defaults to root).
     */
    void setItemsEnable(EnabledProtocolsProxyModel::EnableType enable, QModelIndex parent = QModelIndex());

protected:
    /**
     * @brief Compares two source indices to determine their sort order.
     * @param source_left The first source index.
     * @param source_right The second source index.
     * @return True if the left item should appear before the right item.
     */
    bool lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const override;

private:
    /** The active search filtering scope. */
    EnabledProtocolsProxyModel::SearchTypes type_;

    /** The active protocol type filter. */
    EnabledProtocolItem::EnableProtocolType protocolType_;

    /** The active search filter text/pattern. */
    QString filter_;

    /**
     * @brief Checks if a specific row explicitly matches the filter criteria.
     * @param sourceRow The row in the source model.
     * @param sourceParent The parent index in the source model.
     * @return True if the item matches directly.
     */
    bool filterAcceptsSelf(int sourceRow, const QModelIndex &sourceParent) const;

    /**
     * @brief Checks if any child of a specific row matches the filter criteria.
     * @param sourceRow The row in the source model.
     * @param sourceParent The parent index in the source model.
     * @return True if a child matches.
     */
    bool filterAcceptsChild(int sourceRow, const QModelIndex &sourceParent) const;
};

Q_DECLARE_OPERATORS_FOR_FLAGS(EnabledProtocolsProxyModel::SearchTypes)

#endif // ENABLED_PROTOCOLS_MODEL_H
