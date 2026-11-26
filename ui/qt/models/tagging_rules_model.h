/* tagging_rules_model.h
 *
 * Model for the Tagging Rules dialog
 * Copyright 2026, Mark Stout <mark.stout@markstout.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TAGGING_RULES_MODEL_H
#define TAGGING_RULES_MODEL_H

#include <config.h>

#include <epan/tag_rules.h>

#include <ui/qt/models/inherited_rules_model.h>

#include <QList>
#include <QAbstractItemModel>

/**
 * @brief Represents a single tagging rule item in a tree model.
 */
class TaggingRuleItem : public ModelHelperTreeItem<TaggingRuleItem>
{
public:
    /**
     * @brief Constructs a new TaggingRuleItem with explicit fields.
     * @param disabled True if the rule is disabled.
     * @param name The name of the rule (also used as frame.tag value).
     * @param filter The display filter expression for the rule.
     * @param tag_content The visual content shown in the COL_TAG column.
     * @param comment Optional reference comment.
     * @param parent The parent rule item.
     */
    TaggingRuleItem(bool disabled, QString name, QString filter,
                    QString tag_content, QString tag_url, QString comment,
                    TaggingRuleItem *parent);

    /**
     * @brief Constructs a new TaggingRuleItem from a core tag rule structure.
     * @param rule Pointer to the core tag rule.
     * @param parent The parent rule item.
     */
    TaggingRuleItem(tag_rule_t *rule, TaggingRuleItem *parent);

    /**
     * @brief Copy constructor for TaggingRuleItem.
     * @param item The item to copy.
     */
    TaggingRuleItem(const TaggingRuleItem &item);

    /**
     * @brief Destroys the TaggingRuleItem.
     */
    virtual ~TaggingRuleItem();

    /**
     * @brief Assignment operator for TaggingRuleItem.
     * @param rhs The item to assign from.
     * @return A reference to this item.
     */
    TaggingRuleItem &operator=(TaggingRuleItem &rhs);

    /** @brief Indicates if the rule is currently disabled. */
    bool disabled_;

    /** @brief The display name of the rule (also used as frame.tag value). */
    QString name_;

    /** @brief The display filter expression associated with the rule. */
    QString filter_;

    /** @brief The visual content shown in the COL_TAG column (emoji / text). */
    QString tag_content_;

    /** @brief Optional URL opened when the COL_TAG cell is clicked. */
    QString tag_url_;

    /** @brief Optional reference comment. */
    QString comment_;

    /** @brief The parent profile the rule is inherited from, empty for an own rule. */
    QString source_profile_;

    /** @brief Whether the rule comes from a parent profile; such a rule is read-only. @return true if inherited. */
    bool isInherited() const { return !source_profile_.isEmpty(); }
};

/**
 * @brief A model managing the tagging rules for packet display.
 */
class TaggingRulesModel : public InheritedRulesModel<TaggingRuleItem>
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new TaggingRulesModel, cloning the current active rule list.
     * @param parent The parent QObject.
     */
    explicit TaggingRulesModel(QObject *parent);

    /**
     * @brief Destroys the TaggingRulesModel.
     */
    virtual ~TaggingRulesModel();

    /**
     * @brief Defines the columns used in the tagging rules model.
     */
    enum TaggingRulesColumn {
        colName    = 0, /**< The rule name column (with enabled checkbox). */
        colFilter  = 1, /**< The filter expression column. */
        colTag     = 2, /**< The visual tag content column (emoji / text). */
        colLink    = 3, /**< The URL column (right-click → Follow Link). */
        colComment = 4, /**< The comment column. */
        colCount        /**< Sentinel: total number of columns. */
    };

    /**
     * @brief Custom data roles for TaggingRulesModel.
     */
    enum TaggingRulesRole {
        TagContentRole  = Qt::UserRole + 1, /**< Role for accessing the tag_content_ field. */
        TagUrlRole      = Qt::UserRole + 2  /**< Role for accessing the tag_url_ field. */
    };

    /**
     * @brief Adds a new rule with specified properties.
     */
    void addRule(bool disabled, const QString &name, const QString &filter,
                 const QString &tag_content, const QString &tag_url,
                 const QString &comment);

    /**
     * @brief Adds a rule from a core tag_rule_t structure (used during cloning).
     *
     * Copies the rule data and frees the original rule.
     *
     * @param rule Pointer to the core tag rule structure; freed after copying.
     */
    void addRule(tag_rule_t *rule);

    /**
     * @brief Load rules from an arbitrary path into the model (replaces current contents).
     * @param path     Full path to a tagrules.jsonc file.
     * @param err      Set to error message on failure.
     * @return True on success.
     */
    bool loadFromPath(const QString &path, QString &err);

    /**
     * @brief Write the own rules to the profile's file.
     *
     * A file without rules is written only if the file had rules, or the
     * preferences changed; a profile without a file keeps using the
     * inherited rules.
     * @param path     Full path to write.
     * @param prefs    Prefs to embed in the file header (may be NULL).
     * @param prefs_changed Set if the preferences differ from the file's.
     * @param err      Set to error message on failure.
     * @return True on success.
     */
    bool writeToPath(const QString &path, const tag_prefs_t *prefs, bool prefs_changed, QString &err);

    /**
     * @brief Imports tagging rules from a file, appending to the current model.
     * @param path Path of the file to import.
     * @param err Output string set to an error message on failure.
     * @return True if the import succeeded, false otherwise.
     */
    bool importRules(const QString &path, QString &err);

    /**
     * @brief Exports the current tagging rules to a file.
     * @param path Path of the file to write.
     * @param err Output string set to an error message on failure.
     * @return True if the export succeeded, false otherwise.
     */
    bool exportRules(const QString &path, QString &err);

    /**
     * @brief Retrieves the item flags for a given index.
     * @param index The model index to query.
     * @return The item flags for the specified index.
     */
    Qt::ItemFlags flags(const QModelIndex &index) const override;

    /**
     * @brief Retrieves data from the model for the given index and role.
     * @param index The model index to retrieve data for.
     * @param role The role for which data is requested.
     * @return The data associated with the index and role.
     */
    QVariant data(const QModelIndex &index, int role) const override;

    /**
     * @brief Sets data in the model for the given index and role.
     * @param index The model index to update.
     * @param value The value to set.
     * @param role The role for which data is being set (defaults to Qt::EditRole).
     * @return True if the data was successfully set, false otherwise.
     */
    bool setData(const QModelIndex &index, const QVariant &value, int role = Qt::EditRole) override;

    /**
     * @brief Retrieves header data for the given section, orientation, and role.
     * @param section The column or row section.
     * @param orientation The orientation of the header.
     * @param role The role for which data is requested (defaults to Qt::DisplayRole).
     * @return The header data for the specified parameters.
     */
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const override;

    /**
     * @brief Returns the number of columns under the given parent.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return The number of columns in the model.
     */
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;

    /**
     * @brief Inserts rows into the model.
     * @param row The starting row index for insertion.
     * @param count The number of rows to insert.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return True if the insertion was successful, false otherwise.
     */
    bool insertRows(int row, int count, const QModelIndex &parent = QModelIndex()) override;

    /**
     * @brief Removes rows from the model.
     * @param row The starting row index for removal.
     * @param count The number of rows to remove.
     * @param parent The parent model index (defaults to an invalid QModelIndex).
     * @return True if the removal was successful, false otherwise.
     */
    bool removeRows(int row, int count, const QModelIndex &parent = QModelIndex()) override;

    // Drag-and-drop functionality

    /**
     * @brief Specifies the supported drag and drop actions.
     * @return The supported drop actions.
     */
    Qt::DropActions supportedDropActions() const override;

    /**
     * @brief Retrieves the list of supported MIME types for drag and drop operations.
     * @return A list of supported MIME type strings.
     */
    QStringList mimeTypes() const override;

    /**
     * @brief Generates MIME data for the specified list of indexes.
     * @param indexes The list of indexes to generate data for.
     * @return A pointer to the generated QMimeData.
     */
    QMimeData *mimeData(const QModelIndexList &indexes) const override;

    /**
     * @brief Handles dropped MIME data.
     * @param data The MIME data being dropped.
     * @param action The drop action being performed.
     * @param row The target row for the drop.
     * @param column The target column for the drop.
     * @param parent The target parent index.
     * @return True if the drop was successful, false otherwise.
     */
    bool dropMimeData(const QMimeData *data, Qt::DropAction action, int row, int column,
                      const QModelIndex &parent) override;

protected:
    QList<TaggingRuleItem*> readInherited(profile_inherit_e mode) override;

private:
    /**
     * @brief Whether a tagging rules file has rules, which an empty file may replace.
     * @param path The file.
     * @return true if so.
     */
    static bool fileHasRules(const QString &path);

    /**
     * @brief Builds a GSList of tag_rule_t pointers from the current model items.
     *
     * Caller is responsible for freeing the list (e.g. by passing it to tag_rules_apply()).
     *
     * @return Newly allocated GSList of tag_rule_t*; caller takes ownership.
     */
    GSList *createTagRuleList();

    /**
     * @brief Creates a GSList of tag rules from rule items.
     * @param rules The rule items.
     * @return Newly allocated GSList of tag_rule_t*; caller takes ownership.
     */
    GSList *createTagRuleList(const QList<TaggingRuleItem *> &rules);

    /** @brief List of rows currently involved in a drag-and-drop operation. */
};

#endif // TAGGING_RULES_MODEL_H
