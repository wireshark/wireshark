/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PROFILE_MODEL_H
#define PROFILE_MODEL_H

#include "config.h"

#include <ui/profile.h>

#include <QAbstractTableModel>
#include <QSortFilterProxyModel>
#include <QLoggingCategory>
#include <QFileInfoList>

Q_DECLARE_LOGGING_CATEGORY(profileLogger)

/**
 * @brief Represents a single configuration profile entry in the profile manager,
 *        tracking its name, origin, lifecycle status, and auto-switch filter.
 */
class ProfileItem
{
public:
    /**
     * @brief Lifecycle status of a profile item within the model.
     */
    enum StatusType {
        New      = 0, /**< Newly created profile, not yet persisted. */
        Existing,     /**< Profile loaded from an existing on-disk profile directory. */
        Changed,      /**< Existing profile whose name or settings have been modified. */
        Copy          /**< Profile created as a duplicate of another profile. */
    };

    /**
     * @brief Constructs a ProfileItem from a raw libwireshark profile definition.
     * @param profile Pointer to the profile_def to wrap.
     */
    ProfileItem(profile_def *profile);

    /**
     * @brief Constructs a ProfileItem from individual field values.
     * @param name       Display name of the profile.
     * @param reference  Original name of the profile at creation time (used to locate the on-disk directory).
     * @param status     Initial lifecycle status.
     * @param isGlobal   @c true if this is a read-only global (system) profile.
     * @param fromGlobal @c true if this profile was copied from a global profile.
     * @param isImport   @c true if this profile was imported from an external archive or directory.
     */
    ProfileItem(QString name, QString reference, StatusType status, bool isGlobal, bool fromGlobal, bool isImport);

    /**
     * @brief Returns the current display name of the profile.
     * @return Const reference to the profile name string.
     */
    const QString &getName() const { return name_; }

    /**
     * @brief Returns a localised string describing the profile type (e.g. "Personal", "Global").
     * @return Profile type string.
     */
    const QString getType() const;

    /**
     * @brief Returns the display-filter expression used for automatic profile switching.
     * @return Const reference to the auto-switch filter string, or an empty string if none is set.
     */
    const QString &getAutoSwitchFilter() const { return autoSwitchFilter_; }

    /**
     * @brief Returns the current lifecycle status of this profile item.
     * @return Current StatusType value.
     */
    StatusType getStatus() const { return status_; }

    /**
     * @brief Returns whether this is a read-only global (system-wide) profile.
     * @return @c true for global profiles.
     */
    bool isGlobal() const { return isGlobal_; }

    /**
     * @brief Returns whether this profile was originally copied from a global profile.
     * @return @c true if the profile originated from a global profile.
     */
    bool isFromGlobal() const { return fromGlobal_; }

    /**
     * @brief Returns whether the profile has unsaved changes relative to its on-disk state.
     * @return @c true if the profile has been modified.
     */
    bool isChanged() const { return isChanged_; }

    /**
     * @brief Returns whether this is the built-in default profile.
     * @return @c true for the default profile.
     */
    bool isDefault() const;

    /**
     * @brief Returns whether this profile was imported from an external source.
     * @return @c true if the profile was imported.
     */
    bool isImport() const { return isImport_; }

    /**
     * @brief Returns whether this profile is marked for deletion on the next apply.
     * @return @c true if the profile is pending deletion.
     */
    bool isDeleted() const { return setForDeletion_; }

    /**
     * @brief Returns the original name of the profile at creation time.
     *
     * Used to locate the corresponding on-disk directory when the display name
     * has been changed.
     *
     * @return Const reference to the reference name string.
     */
    const QString &getReference() const { return reference_; }

    /**
     * @brief Returns the filesystem path for this profile.
     * @param profileName Name to append to the base profile directory path.
     *                    If empty, the current profile name (@c name_) is used.
     * @return Absolute path string for the profile directory.
     */
    QString getProfilePath(QString profileName = "") const;

    /**
     * @brief Sets a new display name for the profile and marks it as changed if applicable.
     * @param value New profile name.
     */
    void setName(QString value);

    /**
     * @brief Updates the lifecycle status of the profile.
     * @param status New StatusType value to assign.
     */
    void setStatus(StatusType status) { status_ = status; }

    /**
     * @brief Sets the display-filter expression used for automatic profile switching.
     * @param value Display-filter string; an empty string disables auto-switching.
     */
    void setAutoSwitchFilter(QString value);

    /** @brief Marks this profile for deletion on the next call to ProfileModel::applyChanges(). */
    void setForDeletion() { setForDeletion_ = true; }

private:
    QString    name_;             /**< Current display name of the profile. */
    StatusType status_;           /**< Current lifecycle status. */

    QString autoSwitchFilter_;    /**< Display-filter expression that triggers an automatic switch to this profile. */
    bool    isGlobal_;            /**< @c true for read-only global (system-wide) profiles. */
    bool    fromGlobal_ = false;  /**< @c true if this profile was copied from a global profile. */
    bool    isImport_   = false;  /**< @c true if this profile was imported from an external source. */
    bool    setForDeletion_ = false; /**< @c true if this profile is pending deletion. */

    QString reference_;           /**< Original profile name at creation time; used to resolve the on-disk directory. */

    bool isChanged_ = false;      /**< @c true if the profile has unsaved changes. */
};


/**
 * @brief Sort/filter proxy model for ProfileModel, supporting filtering by
 *        profile visibility (all, personal, or global) and a text search string.
 */
class ProfileSortModel : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a ProfileSortModel with no active text filter and AllProfiles visibility.
     * @param parent Optional parent QObject.
     */
    ProfileSortModel(QObject *parent = Q_NULLPTR);

    /**
     * @brief Controls which profiles are visible based on their scope.
     */
    enum FilterType {
        AllProfiles      = 0, /**< Show both personal and global profiles. */
        PersonalProfiles,     /**< Show only user-owned personal profiles. */
        GlobalProfiles        /**< Show only read-only global profiles. */
    };

    /**
     * @brief Sets the profile-scope filter.
     * @param ft The FilterType to apply.
     */
    void setFilterType(FilterType ft);

    /**
     * @brief Sets a case-insensitive substring filter applied to profile names.
     * @param txt Filter string; pass an empty string to clear the filter.
     */
    void setFilterString(QString txt = QString());

    /**
     * @brief Returns a localised list of filter type display names, ordered by FilterType value.
     * @return QStringList of filter type labels suitable for a combo box.
     */
    static QStringList filterTypes();

protected:
    /**
     * @brief Compares two rows for sort ordering, placing personal profiles before global ones
     *        and sorting alphabetically within each group.
     * @param source_left  Index of the left-hand item in the source model.
     * @param source_right Index of the right-hand item in the source model.
     * @return @c true if the left item should sort before the right item.
     */
    virtual bool lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const;

    /**
     * @brief Determines whether a source row passes the active scope and text filters.
     * @param source_row    Row index in the source model.
     * @param source_parent Parent index in the source model (unused for table models).
     * @return @c true if the row should be included in the filtered view.
     */
    virtual bool filterAcceptsRow(int source_row, const QModelIndex &source_parent) const;

private:
    FilterType ft_;    /**< Active profile-scope filter. */
    QString    ftext_; /**< Active case-insensitive substring filter text. */
};


/**
 * @brief Table model that manages the full set of configuration profiles,
 *        supporting creation, duplication, deletion, import, and export.
 */
class ProfileModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a ProfileModel and populates it from the current profile directories.
     * @param parent Optional parent QObject.
     */
    explicit ProfileModel(QObject *parent = Q_NULLPTR);

    /**
     * @brief Destroys the model and frees all ProfileItem instances.
     */
    virtual ~ProfileModel();

    /**
     * @brief Column index constants for the profile table.
     */
    enum {
        COL_NAME              = 0, /**< Profile name column. */
        COL_TYPE,                  /**< Profile type (Personal / Global) column. */
        COL_AUTO_SWITCH_FILTER,    /**< Auto-switch display-filter expression column. */
        _LAST_ENTRY                /**< Sentinel: total number of columns. */
    } columns_;

    /**
     * @brief Custom Qt::UserRole data keys returned by data().
     */
    enum {
        DATA_IS_DEFAULT = Qt::UserRole, /**< bool — @c true if the item represents the default profile. */
        DATA_IS_GLOBAL,                 /**< bool — @c true if the item represents a global profile. */
    } data_values_;

    /**
     * @brief (Re-)populates the model from the on-disk profile directories.
     *
     * Clears all existing items, then walks both the personal and global profile
     * directories and adds a ProfileItem for each discovered profile.
     */
    void fillTable();

    // ── QAbstractItemModel interface ──────────────────────────────────────

    /**
     * @brief Returns the number of profile rows.
     * @param parent Unused; pass a default QModelIndex for table models.
     * @return Number of ProfileItem entries in the model.
     */
    virtual int rowCount(const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Returns the number of columns (always @c _LAST_ENTRY).
     * @param parent Unused.
     * @return Number of columns defined by the @c columns_ enum.
     */
    virtual int columnCount(const QModelIndex &parent = QModelIndex()) const;

    /**
     * @brief Returns data for the given index and role.
     * @param idx  Model index of the requested cell.
     * @param role Qt item data role.
     * @return QVariant with the requested data, or an invalid QVariant if unavailable.
     */
    virtual QVariant data(const QModelIndex &idx, int role = Qt::DisplayRole) const;

    /**
     * @brief Sets data for an editable cell (profile name or auto-switch filter).
     * @param index Model index of the cell to modify.
     * @param value New value to assign.
     * @param role  Must be Qt::EditRole.
     * @return @c true if the value was successfully applied.
     */
    virtual bool setData(const QModelIndex &index, const QVariant &value, int role);

    /**
     * @brief Returns the header label for the given section.
     * @param section     Column (horizontal) or row (vertical) index.
     * @param orientation Header orientation.
     * @param role        Qt item data role.
     * @return QVariant with the header text, or an invalid QVariant for unsupported roles.
     */
    virtual QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const;

    /**
     * @brief Returns the item flags for the given index.
     *
     * Global and default profiles are not editable; personal profiles support
     * Qt::ItemIsEditable in the name and auto-switch-filter columns.
     *
     * @param index Model index to query.
     * @return Combination of Qt::ItemFlag values.
     */
    virtual Qt::ItemFlags flags(const QModelIndex &index) const;

    // ── Mutation helpers ──────────────────────────────────────────────────

    /**
     * @brief Marks the profiles at the given indices for deletion.
     * @param idcs List of model indices to delete.
     */
    void deleteEntries(QModelIndexList idcs);

    /**
     * @brief Clears the deletion flag on the profiles at the given indices.
     * @param idcs List of model indices to restore.
     * @return @c true if at least one entry was successfully restored.
     */
    bool restoreEntries(QModelIndexList idcs);

    // ── Lookup ────────────────────────────────────────────────────────────

    /**
     * @brief Returns the row index of the first profile whose name matches exactly.
     * @param name Profile name to search for.
     * @return Row index, or @c -1 if not found.
     */
    int findByName(const QString &name);

    /**
     * @brief Adds a new empty personal profile with the given name.
     * @param name Display name for the new profile.
     * @return Model index of the newly inserted row.
     */
    QModelIndex addNewProfile(QString name);

    /**
     * @brief Creates a duplicate of the profile at @p idx.
     * @param idx    Index of the profile to copy.
     * @param status StatusType to assign to the duplicate (default: Copy).
     * @return Model index of the newly inserted duplicate row.
     */
    QModelIndex duplicateEntry(QModelIndex idx, ProfileItem::StatusType status = ProfileItem::StatusType::Copy);

    /**
     * @brief Returns the model index of the currently active (in-use) profile row.
     * @return Valid model index, or an invalid index if the active profile is not found.
     */
    QModelIndex activeProfile() const;

    /**
     * @brief Returns whether any editable (non-global, non-default) profiles exist.
     * @return @c true if at least one personal profile is present.
     */
    bool userProfilesExist() const;

    /**
     * @brief Validates all pending profile changes for conflicts and illegal names.
     * @param err Populated with a human-readable error message on failure.
     * @return @c true if all data is valid and changes can be applied.
     */
    bool isDataValid(QString &err);

#if defined(HAVE_MINIZIP) || defined(HAVE_MINIZIPNG)
    /**
     * @brief Exports the profiles at the given indices to a ZIP archive.
     * @param filename Path to the destination ZIP file.
     * @param items    List of model indices identifying the profiles to export.
     * @param err      Populated with an error message on failure.
     * @return @c true on success.
     */
    bool exportProfiles(QString filename, QModelIndexList items, QString &err);

    /**
     * @brief Imports profiles from a ZIP archive into the model.
     * @param filename    Path to the source ZIP archive.
     * @param skippedCnt  Set to the number of profiles skipped due to conflicts.
     * @param importList  Populated with the names of successfully imported profiles.
     */
    void importProfilesFromZip(QString filename, int &skippedCnt, QStringList &importList);
#endif

    /**
     * @brief Imports profiles from a directory (or an extracted ZIP staging area).
     * @param filename    Path to the source directory.
     * @param skippedCnt  Set to the number of profiles skipped due to conflicts.
     * @param importList  Populated with the names of successfully imported profiles.
     * @param fromZip     @c true when the directory is a temporary ZIP extraction; affects name sanitisation.
     */
    void importProfilesFromDir(QString filename, int &skippedCnt, QStringList &importList, bool fromZip = false);

    /**
     * @brief Validates a candidate profile name for illegal characters and reserved names.
     * @param name Display name to validate.
     * @param msg  Populated with a human-readable reason if the name is invalid.
     * @return @c true if the name is acceptable.
     */
    static bool checkNameValidity(QString name, QString &msg);

    /**
     * @brief Finds all profiles matching the given name and global-scope flag.
     * @param name            Name to match.
     * @param isGlobal        If @c true, restrict the search to global profiles.
     * @param searchReference If @c true, also match against the reference (original) name.
     * @return List of row indices for all matching profiles.
     */
    QList<int> findAllByNameAndVisibility(const QString &name, bool isGlobal = false, bool searchReference = false) const;

    /**
     * @brief Checks whether the profile at @p index has a name collision with another entry.
     * @param index                Model index of the profile to check.
     * @param isOriginalToDuplicate @c true when checking whether the source of a pending
     *                              duplication would cause a conflict.
     * @return @c true if a duplicate name exists.
     */
    bool checkDuplicate(const QModelIndex &index, bool isOriginalToDuplicate = false) const;

    /**
     * @brief Applies all pending changes (additions, renames, copies, deletions)
     *        to the on-disk profile directories and updates libwireshark's profile list.
     */
    void applyChanges();

    /**
     * @brief Returns the ProfileItem representing the profile that was active when
     *        the model was constructed.
     * @return Pointer to the current profile item, or @c nullptr if unknown.
     */
    const ProfileItem *getCurrentProfile() const { return current_profile_; }

    /**
     * @brief Returns the ProfileItem at the given flat list index.
     * @param index Zero-based index into the internal profile list.
     * @return Pointer to the corresponding ProfileItem.
     */
    const ProfileItem *getProfile(int index) const { return profile_items_[index]; }

    /**
     * @brief Finds a personal (non-global) profile by name.
     * @param name Display name to search for.
     * @return Pointer to the matching ProfileItem, or @c nullptr if not found.
     */
    const ProfileItem *getPersonalProfile(const QString &name);

    /**
     * @brief Returns display data for a cell together with the profile's filesystem path.
     * @param idx         Model index of the cell to query.
     * @param profilePath Set to the filesystem path of the profile at @p idx.
     * @return QVariant with the display value for the cell.
     */
    QVariant dataPath(const QModelIndex &idx, QString &profilePath) const;

protected:
    /**
     * @brief Returns the set of characters that are not permitted in profile names.
     * @return String of illegal characters.
     */
    static QString illegalCharacters();

    /**
     * @brief Internal helper that inserts a new ProfileItem with explicit field values.
     * @param name       Display name.
     * @param reference  Original/reference name for on-disk directory resolution.
     * @param isGlobal   @c true for global profiles.
     * @param fromGlobal @c true if copied from a global profile.
     * @param isImport   @c true if imported from an external source.
     * @return Model index of the newly inserted row.
     */
    QModelIndex addNewProfile(QString name, QString reference, bool isGlobal = false, bool fromGlobal = false, bool isImport = false);

private:
    QList<ProfileItem *> profile_items_; /**< Ordered list of all profile items managed by the model. */
    QStringList          profile_files_; /**< List of profile-related filenames used during import/export. */
    ProfileItem         *current_profile_ = Q_NULLPTR; /**< Profile that was active when the model was constructed. */

    /**
     * @brief Finds the first profile matching the given name and global-scope flag.
     * @param name            Name to match.
     * @param isGlobal        If @c true, restrict to global profiles.
     * @param searchReference If @c true, also match against the reference (original) name.
     * @return Row index of the first match, or @c -1 if not found.
     */
    int findByNameAndVisibility(const QString &name, bool isGlobal = false, bool searchReference = false) const;

#if defined(HAVE_MINIZIP) || defined(HAVE_MINIZIPNG)
    /**
     * @brief Decides whether a file from a ZIP archive should be included in the import.
     * @param fileName Name of the file entry within the archive.
     * @param fileSize Uncompressed size of the file in bytes.
     * @return @c true if the file should be extracted and imported.
     */
    static bool acceptFile(QString fileName, int fileSize);

    /**
     * @brief Sanitises a filename extracted from a ZIP archive for use as a profile name.
     * @param fileName Raw filename from the archive.
     * @return Sanitised name safe for use as a profile directory name.
     */
    static QString cleanName(QString fileName);
#endif

    /**
     * @brief Returns display-role data for the cell at @p idx.
     * @param idx Model index to query.
     * @return QVariant with the cell's display string.
     */
    QVariant dataDisplay(const QModelIndex &idx) const;

    /**
     * @brief Returns font-role data for the cell at @p idx.
     * @param idx Model index to query.
     * @return QVariant containing a QFont, or an invalid QVariant.
     */
    QVariant dataFontRole(const QModelIndex &idx) const;

    /**
     * @brief Returns background-colour-role data for the cell at @p idx.
     * @param idx Model index to query.
     * @return QVariant containing a QBrush, or an invalid QVariant.
     */
    QVariant dataBackgroundRole(const QModelIndex &idx) const;

    /**
     * @brief Returns foreground-colour-role data for the cell at @p idx.
     * @param idx Model index to query.
     * @return QVariant containing a QBrush, or an invalid QVariant.
     */
    QVariant dataForegroundRole(const QModelIndex &idx) const;

    /**
     * @brief Returns tooltip-role data for the cell at @p idx.
     * @param idx Model index to query.
     * @return QVariant containing a tooltip string, or an invalid QVariant.
     */
    QVariant dataToolTipRole(const QModelIndex &idx) const;

#if defined(HAVE_MINIZIP) || defined(HAVE_MINIZIPNG)
    /**
     * @brief Builds the list of profile files to include in a ZIP export.
     * @param items List of model indices identifying the profiles to export.
     * @return List of absolute file paths to add to the archive.
     */
    QStringList exportFileList(QModelIndexList items);
#endif

    /**
     * @brief Copies a temporary staging directory into the final profile directory.
     * @param tempPath    Path to the temporary source directory.
     * @param profilePath Path to the destination profile directory.
     * @param wasEmpty    Set to @c true if the destination directory did not exist prior to the copy.
     * @return @c true if the copy completed without errors.
     */
    bool copyTempToProfile(QString tempPath, QString profilePath, bool &wasEmpty);

    /**
     * @brief Recursively filters a directory listing to include only valid profile entries.
     * @param path    Base path being scanned.
     * @param ent     Input file info list to filter.
     * @param fromZip @c true if the entries originate from a ZIP extraction.
     * @return Filtered list of QFileInfo entries representing valid profiles.
     */
    QFileInfoList filterProfilePath(QString path, QFileInfoList ent, bool fromZip);

    /**
     * @brief Removes duplicate paths from a file info list.
     * @param lst Input list potentially containing duplicate entries.
     * @return De-duplicated list of QFileInfo entries.
     */
    QFileInfoList uniquePaths(QFileInfoList lst);
};

#endif
