/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PREF_MODELS_H
#define PREF_MODELS_H

#include <config.h>

#include <ui/qt/models/tree_model_helpers.h>

#include <epan/prefs.h>

#include <QSortFilterProxyModel>
#include <QTreeView>

class PrefsItem;

/**
 * @brief Tree model backing the Preferences dialog.
 */
class PrefsModel : public QAbstractItemModel
{
    Q_OBJECT

public:
    /**
     * @brief Construct a PrefsModel and populate it from the preference registry.
     * @param parent The parent QObject.
     */
    explicit PrefsModel(QObject *parent = Q_NULLPTR);

    /** @brief Destroy the model and its PrefsItem tree. */
    virtual ~PrefsModel();

    /**
     * @brief Top-level preference page type identifiers.
     */
    enum PrefsModelType {
        Advanced = Qt::UserRole, /**< Flat list of all individual preference values. */
        Appearance,              /**< Appearance settings page. */
        Layout,                  /**< Layout settings page. */
        Columns,                 /**< Packet list column settings page. */
        FontAndColors,           /**< Font and color settings page. */
        WelcomePage,             /**< Welcome / start page settings. */
        Capture,                 /**< Capture settings page. */
        Expert,                  /**< Expert information settings page. */
        FilterButtons,           /**< Filter toolbar button settings page. */
        RSAKeys,                 /**< RSA key decryption settings page. */
        Aggregation              /**< Aggregation settings page. */
    };

    /**
     * @brief Column indices for the raw PrefsModel tree.
     */
    enum PrefsModelColumn {
        colName   = 0, /**< Module or preference name. */
        colStatus,     /**< Default / changed status indicator. */
        colType,       /**< Preference type string. */
        colValue,      /**< Current preference value. */
        colLast        /**< Sentinel — total column count. */
    };

    /**
     * @brief Return the model index for the item at (@p row, @p column) under @p parent.
     * @param row    Row within the parent item.
     * @param column Column index.
     * @param parent Parent model index; invalid index denotes the root.
     * @return The model index for the requested item.
     */
    QModelIndex index(int row, int column,
                      const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Return the parent model index of @p index.
     * @param index A valid model index.
     * @return The model index of @p index's parent, or an invalid index for
     *         top-level items.
     */
    QModelIndex parent(const QModelIndex &index) const;

    /**
     * @brief Return data for @p index under @p role.
     * @param index The model index to query.
     * @param role  The data role (Qt::DisplayRole, Qt::UserRole, etc.).
     * @return The requested data, or an invalid QVariant if unavailable.
     */
    QVariant data(const QModelIndex &index, int role) const;

    /**
     * @brief Return the number of child rows under @p parent.
     * @param parent The parent model index; invalid index = root.
     * @return The number of direct children.
     */
    int rowCount(const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Return the number of columns.
     * @param parent Unused; present for API compatibility.
     * @return Always @c colLast.
     */
    int columnCount(const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Return the display name for a built-in preference page type.
     * @param type The PrefsModelType to look up.
     * @return A translated, human-readable page name string.
     */
    static QString typeToString(PrefsModelType type);

    /**
     * @brief Return the help text for a built-in preference page type.
     * @param type The PrefsModelType to look up.
     * @return A translated help string, or an empty string if none is defined.
     */
    static QString typeToHelp(PrefsModelType type);

private:
    /**
     * @brief Build the PrefsItem tree from the Wireshark preference registry.
     */
    void populate();

    PrefsItem *root_; /**< Invisible root item that owns all top-level items. */
};

/**
 * @brief A single node in the PrefsModel tree.
 */
class PrefsItem : public ModelHelperTreeItem<PrefsItem>
{
public:
    /**
     * @brief Construct a PrefsItem for an individual preference.
     * @param module The preference module that owns @p pref.
     * @param pref   The individual preference value this item represents.
     * @param parent The parent PrefsItem in the tree.
     */
    PrefsItem(module_t *module, pref_t *pref, PrefsItem *parent);

    /**
     * @brief Construct a PrefsItem for a named grouping node.
     * @param name   The display name for this grouping node.
     * @param parent The parent PrefsItem in the tree.
     */
    PrefsItem(const QString name, PrefsItem *parent);

    /**
     * @brief Construct a PrefsItem for a built-in preference page.
     * @param type   The PrefsModelType this item represents.
     * @param parent The parent PrefsItem in the tree.
     */
    PrefsItem(PrefsModel::PrefsModelType type, PrefsItem *parent);

    /** @brief Destroy this PrefsItem and all of its children. */
    virtual ~PrefsItem();

    /**
     * @brief Return the display name of this item.
     * @return The name string set at construction time.
     */
    QString getName() const { return name_; }

    /**
     * @brief Return the pref_t this item represents.
     * @return The @c pref_t pointer, or nullptr for module/page nodes.
     */
    pref_t *getPref() const { return pref_; }

    /**
     * @brief Return the numeric type of the underlying preference.
     * @return The @c pref_t type constant, or 0 if this is not a pref node.
     */
    int getPrefType() const;

    /**
     * @brief Return whether the preference currently holds its default value.
     * @return true if the preference value equals its compiled-in default.
     */
    bool isPrefDefault() const;

    /**
     * @brief Return a human-readable string for the preference type.
     * @return A type name such as @c "uint", @c "string", @c "enum", etc.
     */
    QString getPrefTypeName() const;

    /**
     * @brief Return the preference module associated with this item.
     * @return The @c module_t pointer, or nullptr for page nodes.
     */
    module_t *getModule() const { return module_; }

    /**
     * @brief Return the internal (short) name of the associated module.
     * @return The module's @c name field, or an empty string if unavailable.
     */
    QString getModuleName() const;

    /**
     * @brief Return the display title of the associated module.
     * @return The module's @c title field, or an empty string if unavailable.
     */
    QString getModuleTitle() const;

    /**
     * @brief Return the help text for the associated module.
     * @return The module's help string, or an empty string if unavailable.
     */
    QString getModuleHelp() const;

    /**
     * @brief Mark this preference as having been changed during this session.
     * @param changed true to mark as changed; false to clear the flag.
     */
    void setChanged(bool changed = true);

private:
    pref_t   *pref_;    /**< The individual preference, or nullptr for module nodes. */
    module_t *module_;  /**< The preference module, or nullptr for page nodes. */
    QString   name_;    /**< Display name of this item. */
    QString   help_;    /**< Help text for this item. */
    /** True if this preference was modified during the current dialog session;
     *  used to choose the correct default value for comparison in isPrefDefault(). */
    bool changed_;
};

/**
 * @brief Sort/filter proxy model for the Advanced Preferences pane.
 */
class AdvancedPrefsModel : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    /**
     * @brief Construct an AdvancedPrefsModel.
     * @param parent The parent QObject.
     */
    explicit AdvancedPrefsModel(QObject *parent = Q_NULLPTR);

    /**
     * @brief Column indices for the Advanced preferences view.
     */
    enum AdvancedPrefsModelColumn {
        colName   = 0, /**< Preference name. */
        colStatus,     /**< Default / changed status indicator. */
        colType,       /**< Preference type string. */
        colValue,      /**< Current preference value. */
        colLast        /**< Sentinel — total column count. */
    };

    /**
     * @brief Determine whether a source row should be included in the view.
     *
     * A row is accepted if it belongs to the Advanced subtree of the source
     * model and passes the current text filter and changed-values filter.
     *
     * @param sourceRow    The row index in the source model.
     * @param sourceParent The parent index in the source model.
     * @return true if the row should be shown; false to hide it.
     */
    virtual bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const;

    /**
     * @brief Set the text filter applied to preference names and values.
     *
     * Rows whose name or value do not contain @p filter (case-insensitive)
     * are hidden. An empty string shows all rows.
     *
     * @param filter The filter string to apply.
     */
    void setFilter(const QString &filter);

    /**
     * @brief Restrict the view to preferences that differ from their defaults.
     * @param show_changed_values true to show only changed preferences;
     *                            false to show all preferences.
     */
    void setShowChangedValues(bool show_changed_values);

    /**
     * @brief Return the column header label.
     * @param section     Column index.
     * @param orientation Must be Qt::Horizontal.
     * @param role        The data role; typically Qt::DisplayRole.
     * @return The header label for @p section, or an invalid QVariant.
     */
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const;

    /**
     * @brief Return data for @p index under @p role.
     *
     * @param index The proxy model index to query.
     * @param role  The data role.
     * @return The requested data, or an invalid QVariant if unavailable.
     */
    QVariant data(const QModelIndex &index, int role) const;

    /**
     * @brief Return the item flags for @p index.
     *
     * Marks editable preference items with Qt::ItemIsEditable.
     *
     * @param index The proxy model index to query.
     * @return The item flags for the preference at @p index.
     */
    Qt::ItemFlags flags(const QModelIndex &index) const;

    /**
     * @brief Write @p value to the preference at @p index.
     *
     * @param index The proxy model index of the preference to update.
     * @param value The new value to apply.
     * @param role  The data role; only Qt::EditRole is handled.
     * @return true if the value was successfully applied; false otherwise.
     */
    bool setData(const QModelIndex &index, const QVariant &value,
                 int role = Qt::EditRole);

    /**
     * @brief Return the number of columns in this model.
     * @param parent Unused; present for API compatibility.
     * @return Always @c colLast.
     */
    int columnCount(const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Mark module-level rows as spanning all columns in @p tree.
     *
     * Keep the internals of model hidden from tree.
     *
     * @param tree  The QTreeView to update.
     * @param index The root index from which to start; defaults to the
     *              model root.
     */
    void setFirstColumnSpanned(QTreeView *tree, const QModelIndex &index = QModelIndex());

protected:
    /**
     * @brief Test whether a single PrefsItem passes the current filters.
     * @param item The PrefsItem to evaluate.
     * @return true if @p item should be included in the filtered view.
     */
    bool filterAcceptItem(PrefsItem &item) const;

private:
    QString filter_;             /**< Current text filter string. */
    bool show_changed_values_;   /**< When true, only show non-default preferences. */
    const QChar passwordChar_;   /**< Masking character used to obscure password values. */
};

/**
 * @brief Sort/filter proxy model for the module (left-hand) pane of the
 * Preferences dialog.
 */
class ModulePrefsModel : public QSortFilterProxyModel
{
public:
    /**
     * @brief Construct a ModulePrefsModel.
     * @param parent The parent QObject.
     */
    explicit ModulePrefsModel(QObject *parent = Q_NULLPTR);

    /**
     * @brief Column indices for the module pane.
     */
    enum ModulePrefsModelColumn {
        colName = 0, /**< Module display name. */
        colLast      /**< Sentinel — total column count. */
    };

    /**
     * @brief Custom data roles for module items.
     */
    enum ModulePrefsRoles {
        ModuleName = Qt::UserRole + 1, /**< Internal (short) module name string. */
        ModuleHelp = Qt::UserRole + 2  /**< Module help text string. */
    };

    /**
     * @brief Return data for @p index under @p role.
     *
     * @param index The proxy model index to query.
     * @param role  The data role.
     * @return The requested data, or an invalid QVariant if unavailable.
     */
    QVariant data(const QModelIndex &index, int role) const;

    /**
     * @brief Return the item flags for @p index.
     *
     * @param index The proxy model index to query.
     * @return The item flags for the module at @p index.
     */
    Qt::ItemFlags flags(const QModelIndex &index) const;

    /**
     * @brief Return the number of columns in this model.
     * @param parent Unused; present for API compatibility.
     * @return Always @c colLast.
     */
    int columnCount(const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Determine whether a source row should appear in the module pane.
     *
     * @param sourceRow    The row index in the source model.
     * @param sourceParent The parent index in the source model.
     * @return true if the row is a module-level item; false otherwise.
     */
    virtual bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const;

protected:
    /**
     * @brief Define the sort order for module rows.
     *
     * @param source_left  Source index of the left-hand item to compare.
     * @param source_right Source index of the right-hand item to compare.
     * @return true if the left item should appear before the right item.
     */
    bool lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const;

private:
    /** Cached translated display name of the "Advanced" preferences entry,
     *  used by lessThan() to guarantee it sorts first. */
    QString advancedPrefName_;
};

/**
 * @brief Retrieves the preference structure associated with a given preference pointer.
 *
 * @param pref_ptr The pointer to the preference.
 * @return A pointer to the preference structure, or NULL if not found.
 */
extern pref_t *prefFromPrefPtr(void *pref_ptr);

#endif // PREF_MODELS_H
