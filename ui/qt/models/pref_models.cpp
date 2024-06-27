/* pref_models.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/models/pref_models.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include <epan/prefs-int.h>

#ifdef HAVE_LIBPCAP
#ifdef _WIN32
#include "capture/capture-wpcap.h"
#endif /* _WIN32 */
#endif /* HAVE_LIBPCAP */

#include <QFont>
#include <QColor>
#include <QRegularExpression>
#include <QApplication>

// XXX Should we move this to ui/preference_utils?
static GHashTable * pref_ptr_to_pref_;
pref_t *prefFromPrefPtr(void *pref_ptr)
{
    return (pref_t *)g_hash_table_lookup(pref_ptr_to_pref_, (void *) pref_ptr);
}

static void prefInsertPrefPtr(void * pref_ptr, pref_t * pref)
{
    if (! pref_ptr_to_pref_)
        pref_ptr_to_pref_ = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    void *key = (void *) pref_ptr;
    void *val = (void *) pref;

    /* Already existing entries will be ignored */
    if ((void *)g_hash_table_lookup(pref_ptr_to_pref_, key) == NULL)
        g_hash_table_insert(pref_ptr_to_pref_, key, val);
}

PrefsItem::PrefsItem(module_t *module, pref_t *pref, PrefsItem* parent)
    : ModelHelperTreeItem<PrefsItem>(parent),
    pref_(pref),
    module_(module),
    name_(module->name ? module->name : module->parent->name),
    help_(QString()),
    changed_(false)
{
    if (pref_ != NULL) {
        name_ += QString(".%1").arg(prefs_get_name(pref_));
    }
}

PrefsItem::PrefsItem(const QString name, PrefsItem* parent)
    : ModelHelperTreeItem<PrefsItem>(parent),
    pref_(NULL),
    module_(NULL),
    name_(name),
    help_(QString()),
    changed_(false)
{
}

PrefsItem::PrefsItem(PrefsModel::PrefsModelType type, PrefsItem* parent)
    : ModelHelperTreeItem<PrefsItem>(parent),
    pref_(NULL),
    module_(NULL),
    name_(PrefsModel::typeToString(type)),
    help_(PrefsModel::typeToHelp(type)),
    changed_(false)
{
}

PrefsItem::~PrefsItem()
{
}

int PrefsItem::getPrefType() const
{
    if (pref_ == NULL)
        return 0;

    return prefs_get_type(pref_);
}

bool PrefsItem::isPrefDefault() const
{
    if (pref_ == NULL)
        return true;

    if (changed_ == false)
        return prefs_pref_is_default(pref_) ? true : false;

    return false;
}

QString PrefsItem::getPrefTypeName() const
{
    if (pref_ == NULL)
        return "";

    return QString(prefs_pref_type_name(pref_));
}

QString PrefsItem::getModuleName() const
{
    if (module_ == NULL)
        return name_;

    return QString(module_->name);
}

QString PrefsItem::getModuleTitle() const
{
    if ((module_ == NULL) && (pref_ == NULL))
        return name_;

    Q_ASSERT(module_);

    return QString(module_->title);
}

QString PrefsItem::getModuleHelp() const
{
    if (module_ == nullptr)
        return help_;

    module_t *pref_module = module_;

    while (pref_module->help == nullptr && pref_module->parent) {
        pref_module = pref_module->parent;
    }

    return pref_module->help;
}

void PrefsItem::setChanged(bool changed)
{
    changed_ = changed;
}

PrefsModel::PrefsModel(QObject *parent) :
    QAbstractItemModel(parent),
    root_(new PrefsItem(QString("ROOT"), NULL))
{
    populate();
}

PrefsModel::~PrefsModel()
{
    delete root_;
}

int PrefsModel::rowCount(const QModelIndex &parent) const
{
    PrefsItem *parent_item;
    if (parent.column() > 0)
        return 0;

    if (!parent.isValid())
        parent_item = root_;
    else
        parent_item = static_cast<PrefsItem*>(parent.internalPointer());

    if (parent_item == NULL)
        return 0;

    return static_cast<int>(parent_item->childCount());
}

int PrefsModel::columnCount(const QModelIndex&) const
{
    return colLast;
}


QModelIndex PrefsModel::parent(const QModelIndex& index) const
{
    if (!index.isValid())
        return QModelIndex();

    PrefsItem* item = static_cast<PrefsItem*>(index.internalPointer());
    if (item != NULL) {
        PrefsItem* parent_item = item->parentItem();
        if (parent_item != NULL) {
            if (parent_item == root_)
                return QModelIndex();

            return createIndex(parent_item->row(), 0, parent_item);
        }
    }

    return QModelIndex();
}

QModelIndex PrefsModel::index(int row, int column, const QModelIndex& parent) const
{
    if (!hasIndex(row, column, parent))
        return QModelIndex();

    PrefsItem *parent_item, *child_item;

    if (!parent.isValid())
        parent_item = root_;
    else
        parent_item = static_cast<PrefsItem*>(parent.internalPointer());

    Q_ASSERT(parent_item);

    child_item = parent_item->child(row);
    if (child_item) {
        return createIndex(row, column, child_item);
    }

    return QModelIndex();
}

QVariant PrefsModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || (role != Qt::DisplayRole && role != Qt::UserRole))
        return QVariant();

    PrefsItem* item = static_cast<PrefsItem*>(index.internalPointer());
    if (item == NULL)
        return QVariant();

    if (role == Qt::UserRole)
        return VariantPointer<PrefsItem>::asQVariant(item);

    switch ((enum PrefsModelColumn)index.column()) {
    case colName:
        return item->getName();

    case colStatus:
        if (item->getPrefType() == PREF_UAT || item->getPrefType() == PREF_CUSTOM)
            return QObject::tr("Unknown");

        if (item->isPrefDefault())
            return QObject::tr("Default");

        return QObject::tr("Changed");
    case colType:
        return item->getPrefTypeName();
    case colValue:
        if (item->getPref() == NULL)
            return QVariant();

        return QString(gchar_free_to_qstring(prefs_pref_to_str(item->getPref(), pref_stashed)).remove(QRegularExpression("\n\t")));
    default:
        break;
    }

    return QVariant();
}

static unsigned
fill_prefs(module_t *module, void *root_ptr)
{
    PrefsItem* root_item = static_cast<PrefsItem*>(root_ptr);

    if ((module == NULL) || (root_item == NULL))
        return 1;

    if (module->numprefs < 1 && !prefs_module_has_submodules(module))
        return 0;

    PrefsItem* module_item = new PrefsItem(module, NULL, root_item);
    root_item->prependChild(module_item);

    for (GList *pref_l = module->prefs; pref_l && pref_l->data; pref_l = gxx_list_next(pref_l)) {
        pref_t *pref = gxx_list_data(pref_t *, pref_l);

        if (prefs_get_type(pref) == PREF_OBSOLETE || prefs_get_type(pref) == PREF_STATIC_TEXT)
            continue;

        const char *type_name = prefs_pref_type_name(pref);
        if (!type_name)
            continue;

        pref_stash(pref, NULL);

        PrefsItem* item = new PrefsItem(module, pref, module_item);
        module_item->prependChild(item);

        // .uat is a void * so it wins the "useful key value" prize.
        if (prefs_get_uat_value(pref)) {
            prefInsertPrefPtr(prefs_get_uat_value(pref), pref);
        }
    }

    if (prefs_module_has_submodules(module))
        return prefs_modules_foreach_submodules(module, fill_prefs, module_item);

    return 0;
}

void PrefsModel::populate()
{
    prefs_modules_foreach_submodules(NULL, fill_prefs, (void *)root_);

    //Add the "specially handled" preferences
    PrefsItem *appearance_item, *appearance_subitem, *special_item;

    appearance_item = new PrefsItem(PrefsModel::Appearance, root_);
    root_->prependChild(appearance_item);

    appearance_subitem = new PrefsItem(PrefsModel::Layout, appearance_item);
    appearance_item->prependChild(appearance_subitem);
    appearance_subitem = new PrefsItem(PrefsModel::Columns, appearance_item);
    appearance_item->prependChild(appearance_subitem);
    appearance_subitem = new PrefsItem(PrefsModel::FontAndColors, appearance_item);
    appearance_item->prependChild(appearance_subitem);

    special_item = new PrefsItem(PrefsModel::Capture, root_);
    root_->prependChild(special_item);
    special_item = new PrefsItem(PrefsModel::Expert, root_);
    root_->prependChild(special_item);
    special_item = new PrefsItem(PrefsModel::FilterButtons, root_);
    root_->prependChild(special_item);
#ifdef HAVE_LIBGNUTLS
    special_item = new PrefsItem(PrefsModel::RSAKeys, root_);
    root_->prependChild(special_item);
#endif
    special_item = new PrefsItem(PrefsModel::Advanced, root_);
    root_->prependChild(special_item);
}

QString PrefsModel::typeToString(int type)
{
    QString typeStr;

    switch(type)
    {
        case Advanced: typeStr = tr("Advanced"); break;
        case Appearance: typeStr = tr("Appearance"); break;
        case Layout: typeStr = tr("Layout"); break;
        case Columns: typeStr = tr("Columns"); break;
        case FontAndColors: typeStr = tr("Font and Colors"); break;
        case Capture: typeStr = tr("Capture"); break;
        case Expert: typeStr = tr("Expert"); break;
        case FilterButtons: typeStr = tr("Filter Buttons"); break;
        case RSAKeys: typeStr = tr("RSA Keys"); break;
    }

    return typeStr;
}

QString PrefsModel::typeToHelp(int type)
{
    QString helpStr;

    switch(type)
    {
        case Appearance:
            helpStr = QString("ChCustPreferencesSection.html#_appearance");
            break;
        case Columns:
            helpStr = QString("ChCustPreferencesSection.html#_columns");
            break;
        case FontAndColors:
            helpStr = QString("ChCustPreferencesSection.html#_font_and_colors");
            break;
        case Layout:
            helpStr = QString("ChCustPreferencesSection.html#_layout");
            break;
        case Capture:
            helpStr = QString("ChCustPreferencesSection.html#_capture");
            break;
        case Expert:
            helpStr = QString("ChCustPreferencesSection.html#ChCustPrefsExpertSection");
            break;
        case FilterButtons:
            helpStr = QString("ChCustPreferencesSection.html#ChCustFilterButtons");
            break;
        case RSAKeys:
            helpStr = QString("ChCustPreferencesSection.html#ChCustPrefsRSASection");
            break;
        case Advanced:
            helpStr = QString("ChCustPreferencesSection.html#_advanced");
            break;
    }

    return helpStr;
}

AdvancedPrefsModel::AdvancedPrefsModel(QObject * parent)
: QSortFilterProxyModel(parent),
filter_(),
show_changed_values_(false),
passwordChar_(QApplication::style()->styleHint(QStyle::SH_LineEdit_PasswordCharacter))
{
}

QVariant AdvancedPrefsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole) {

        switch (section) {
        case colName:
            return tr("Name");
        case colStatus:
            return tr("Status");
        case colType:
            return tr("Type");
        case colValue:
            return tr("Value");
        default:
            break;
        }
    }
    return QVariant();
}

QVariant AdvancedPrefsModel::data(const QModelIndex &dataindex, int role) const
{
    if (!dataindex.isValid())
        return QVariant();

    QModelIndex modelIndex = mapToSource(dataindex);

    PrefsItem* item = static_cast<PrefsItem*>(modelIndex.internalPointer());
    if (item == NULL)
        return QVariant();

    switch (role)
    {
    case Qt::DisplayRole:
        switch ((AdvancedPrefsModelColumn)dataindex.column())
        {
        case colName:
            if (item->getPref() == NULL)
                return item->getModule()->title;

            return sourceModel()->data(sourceModel()->index(modelIndex.row(), PrefsModel::colName, modelIndex.parent()), role);
        case colStatus:
            if (item->getPref() == NULL)
                return QVariant();

            return sourceModel()->data(sourceModel()->index(modelIndex.row(), PrefsModel::colStatus, modelIndex.parent()), role);
        case colType:
            if (item->getPref() == NULL)
                return QVariant();

            return sourceModel()->data(sourceModel()->index(modelIndex.row(), PrefsModel::colType, modelIndex.parent()), role);
        case colValue:
            if (item->getPref() == NULL)
                return QVariant();

            if (PREF_PASSWORD == item->getPrefType())
            {
                return QString(sourceModel()->data(sourceModel()->index(modelIndex.row(), PrefsModel::colValue, modelIndex.parent()), role).toString().size(), passwordChar_);
            } else {
                return sourceModel()->data(sourceModel()->index(modelIndex.row(), PrefsModel::colValue, modelIndex.parent()), role);
            }
        default:
            break;
        }
        break;
    case Qt::ToolTipRole:
        switch ((AdvancedPrefsModelColumn)dataindex.column())
        {
        case colName:
            if (item->getPref() == NULL)
                return QString("<span>%1</span>").arg(item->getModule()->description);

            return QString("<span>%1</span>").arg(prefs_get_description(item->getPref()));
        case colStatus:
            if (item->getPref() == NULL)
                return QVariant();

            return QObject::tr("Has this preference been changed?");
        case colType:
            if (item->getPref() == NULL) {
                return QVariant();
            } else {
                QString type_desc = gchar_free_to_qstring(prefs_pref_type_description(item->getPref()));
                return QString("<span>%1</span>").arg(type_desc);
            }
            break;
        case colValue:
            if (item->getPref() == NULL) {
                return QVariant();
            } else {
                QString default_value = gchar_free_to_qstring(prefs_pref_to_str(item->getPref(), pref_stashed));
                return QString("<span>%1</span>").arg(
                            default_value.isEmpty() ? default_value : QObject::tr("Default value is empty"));
            }
        default:
            break;
        }
        break;
    case Qt::FontRole:
        if (item->getPref() == NULL)
            return QVariant();

        if (!item->isPrefDefault() &&
            /* UATs and custom preferences are "unknown", that shouldn't mean that they are always bolded */
            item->getPrefType() != PREF_UAT && item->getPrefType() != PREF_CUSTOM) {
            QFont font;
            font.setBold(true);
            return font;
        }
        break;
    case Qt::UserRole:
        return sourceModel()->data(modelIndex, role);
    default:
        break;
    }

    return QVariant();
}

bool AdvancedPrefsModel::setData(const QModelIndex &dataindex, const QVariant &value, int role)
{
    if ((!dataindex.isValid()) || (role != Qt::EditRole))
        return false;

    QModelIndex modelIndex = mapToSource(dataindex);

    PrefsItem* item = static_cast<PrefsItem*>(modelIndex.internalPointer());
    if (item == NULL)
        return false;

    if (value.isNull()) {
        //reset preference to default
        reset_stashed_pref(item->getPref());
        item->setChanged(false);
    } else {
        item->setChanged(true);
        switch (item->getPrefType())
        {
        case PREF_UINT:
            {
            bool ok;
            unsigned new_val = value.toString().toUInt(&ok, prefs_get_uint_base(item->getPref()));

            if (ok)
                prefs_set_uint_value(item->getPref(), new_val, pref_stashed);
            }
            break;
        case PREF_BOOL:
            prefs_invert_bool_value(item->getPref(), pref_stashed);
            break;
        case PREF_ENUM:
            prefs_set_enum_value(item->getPref(), value.toInt(), pref_stashed);
            break;
        case PREF_STRING:
        case PREF_DISSECTOR:
            prefs_set_string_value(item->getPref(), value.toString().toStdString().c_str(), pref_stashed);
            break;
        case PREF_PASSWORD:
            prefs_set_password_value(item->getPref(), value.toString().toStdString().c_str(), pref_stashed);
            break;
        case PREF_DECODE_AS_RANGE:
        case PREF_RANGE:
            prefs_set_stashed_range_value(item->getPref(), value.toString().toUtf8().constData());
            break;
        case PREF_SAVE_FILENAME:
        case PREF_OPEN_FILENAME:
        case PREF_DIRNAME:
            prefs_set_string_value(item->getPref(), value.toString().toStdString().c_str(), pref_stashed);
            break;
        case PREF_COLOR:
        {
            QColor qc(value.toString());
            color_t color;

            color.red = qc.red() << 8 | qc.red();
            color.green = qc.green() << 8 | qc.green();
            color.blue = qc.blue() << 8 | qc.blue();

            prefs_set_color_value(item->getPref(), color, pref_stashed);
            break;
        }
        case PREF_CUSTOM:
            prefs_set_custom_value(item->getPref(), value.toString().toStdString().c_str(), pref_stashed);
            break;
        }
    }

    QVector<int> roles;
    roles << role;

    // The status field may change as well as the value, so mark them for update
    emit dataChanged(index(dataindex.row(), 0, dataindex.parent()),
                     index(dataindex.row(), columnCount() - 1, dataindex.parent()),
                     roles);

    return true;
}

Qt::ItemFlags AdvancedPrefsModel::flags(const QModelIndex &index) const
{
    if (!index.isValid())
        return Qt::ItemFlags();

    QModelIndex modelIndex = mapToSource(index);

    PrefsItem* item = static_cast<PrefsItem*>(modelIndex.internalPointer());
    if (item == NULL)
        return Qt::ItemFlags();

    Qt::ItemFlags flags = QAbstractItemModel::flags(index);
    if (item->getPref() == NULL) {
        /* Base modules aren't changeable */
        flags &= ~(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
    } else {
        flags |= Qt::ItemIsEditable;
    }

    return flags;
}


int AdvancedPrefsModel::columnCount(const QModelIndex&) const
{
    return colLast;
}

void AdvancedPrefsModel::setFirstColumnSpanned(QTreeView* tree, const QModelIndex& mIndex)
{
    int childCount, row;
    PrefsItem* item;
    if (mIndex.isValid()) {
        item = VariantPointer<PrefsItem>::asPtr(data(mIndex, Qt::UserRole));
        if (item != NULL) {
            childCount = item->childCount();
            if (childCount > 0) {
                tree->setFirstColumnSpanned(mIndex.row(), mIndex.parent(), true);
                for (row = 0; row < childCount; row++) {
                    setFirstColumnSpanned(tree, index(row, 0, mIndex));
                }
            }
        }
    } else {
        for (row = 0; row < rowCount(); row++) {
            setFirstColumnSpanned(tree, index(row, 0));
        }
    }
}

bool AdvancedPrefsModel::filterAcceptItem(PrefsItem& item) const
{
    if (filter_.isEmpty() && !show_changed_values_)
        return true;

    QString name, tooltip;
    if (item.getPref() == NULL) {
        name = item.getModule()->title;
        tooltip = item.getModule()->description;
    } else {
        name = QString(item.getModule()->name ? item.getModule()->name : item.getModule()->parent->name);
        name += QString(".%1").arg(prefs_get_name(item.getPref()));
        tooltip = prefs_get_description(item.getPref());
    }

    if (show_changed_values_ && item.getPref()) {
        // UATs and custom preferences are "unknown", do not show when show_changed_only.
        if (item.isPrefDefault() || item.getPrefType() == PREF_UAT || item.getPrefType() == PREF_CUSTOM) {
            return false;
        } else if (filter_.isEmpty()) {
            return true;
        }
    }

    // Do not match module title or description when having show_changed_only.
    if (!(filter_.isEmpty() || (show_changed_values_ && !item.getPref())) &&
        (name.contains(filter_, Qt::CaseInsensitive) || tooltip.contains(filter_, Qt::CaseInsensitive)))
        return true;

    PrefsItem *child_item;
    for (int child_row = 0; child_row < item.childCount(); child_row++)
    {
        child_item = item.child(child_row);
        if ((child_item != NULL) && (filterAcceptItem(*child_item)))
            return true;
    }

    return false;
}

bool AdvancedPrefsModel::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    QModelIndex nameIdx = sourceModel()->index(sourceRow, PrefsModel::colName, sourceParent);
    PrefsItem* item = static_cast<PrefsItem*>(nameIdx.internalPointer());
    if (item == NULL)
        return true;

    //filter out the "special" preferences
    if ((item->getModule() == NULL) && (item->getPref() == NULL))
        return false;

    if (filterAcceptItem(*item))
        return true;

    return false;
}

void AdvancedPrefsModel::setFilter(const QString& filter)
{
    filter_ = filter;
    invalidateFilter();
}

void AdvancedPrefsModel::setShowChangedValues(bool show_changed_values)
{
    show_changed_values_ = show_changed_values;
    invalidateFilter();
}



ModulePrefsModel::ModulePrefsModel(QObject* parent)
    : QSortFilterProxyModel(parent)
    , advancedPrefName_(PrefsModel::typeToString(PrefsModel::Advanced))
{
}

QVariant ModulePrefsModel::data(const QModelIndex &dataindex, int role) const
{
    if (!dataindex.isValid())
        return QVariant();

    QModelIndex modelIndex = mapToSource(dataindex);

    PrefsItem* item = static_cast<PrefsItem*>(modelIndex.internalPointer());
    if (item == NULL)
        return QVariant();

    switch (role)
    {
    case Qt::DisplayRole:
        switch ((ModulePrefsModelColumn)dataindex.column())
        {
        case colName:
            return item->getModuleTitle();
        default:
            break;
        }
        break;
    case Qt::UserRole:
        return sourceModel()->data(modelIndex, role);
    case ModuleName:
        return item->getModuleName();
    case ModuleHelp:
        return item->getModuleHelp();
    default:
        break;
    }

    return QVariant();
}
Qt::ItemFlags ModulePrefsModel::flags(const QModelIndex &index) const
{
    if (!index.isValid())
        return Qt::ItemFlags();

    bool disable_capture = true;
#ifdef HAVE_LIBPCAP
#ifdef _WIN32
    /* Is WPcap loaded? */
    if (has_wpcap) {
#endif /* _WIN32 */
        disable_capture = false;
#ifdef _WIN32
    }
#endif /* _WIN32 */
#endif /* HAVE_LIBPCAP */

    Qt::ItemFlags flags = QAbstractItemModel::flags(index);
    if (disable_capture) {
        QModelIndex modelIndex = mapToSource(index);

        PrefsItem* item = static_cast<PrefsItem*>(modelIndex.internalPointer());
        if (item == NULL)
            return flags;

        if (item->getName().compare(PrefsModel::typeToString(PrefsModel::Capture)) == 0) {
            flags &= (~Qt::ItemIsEnabled);
        }
    }

    return flags;
}

int ModulePrefsModel::columnCount(const QModelIndex&) const
{
    return colLast;
}

bool ModulePrefsModel::lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const
{
    PrefsItem* left_item = static_cast<PrefsItem*>(source_left.internalPointer());
    PrefsItem* right_item = static_cast<PrefsItem*>(source_right.internalPointer());

    if ((left_item != NULL) && (right_item != NULL)) {
        QString left_name = left_item->getModuleTitle(),
                right_name = right_item->getModuleTitle();

        //Force "Advanced" preferences to be at bottom of model
        if (source_left.isValid() && !source_left.parent().isValid() &&
            source_right.isValid() && !source_right.parent().isValid()) {
            if (left_name.compare(advancedPrefName_) == 0) {
                return false;
            }
            if (right_name.compare(advancedPrefName_) == 0) {
                return true;
            }
        }

        if (left_name.compare(right_name, Qt::CaseInsensitive) < 0)
            return true;
    }

    return false;
}

bool ModulePrefsModel::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    QModelIndex nameIdx = sourceModel()->index(sourceRow, PrefsModel::colName, sourceParent);
    PrefsItem* item = static_cast<PrefsItem*>(nameIdx.internalPointer());
    if (item == NULL)
        return true;

    if (item->getPref() != NULL)
        return false;

    if (item->getModule() != NULL) {
        if (!item->getModule()->use_gui) {
            return false;
        }
    }

    return true;
}
