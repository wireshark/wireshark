/* font_selection_widget.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/font_selection_widget.h>
#include <ui_font_selection_widget.h>

#include <ui/qt/utils/font_manager.h>
#include <ui/qt/utils/zoom_scaling.h>
#include "wsutil/array.h"

#include <glib.h>

#include <algorithm>

#include <QApplication>
#include <QFontDatabase>
#include <QFontInfo>
#include <QGuiApplication>
#include <QListWidgetItem>
#include <QRegularExpression>
#include <QSignalBlocker>

//: These are pangrams. Feel free to replace with nonsense text that spans your alphabet.
//: https://en.wikipedia.org/wiki/Pangram
static const char *font_pangrams_[] = {
    QT_TRANSLATE_NOOP("FontSelectionWidget", "Example GIF query packets have jumbo window sizes"),
    QT_TRANSLATE_NOOP("FontSelectionWidget", "Lazy badgers move unique waxy jellyfish packets")
};
const int num_font_pangrams_ = array_length(font_pangrams_);

namespace {

struct FamilyEntry {
    QString family;
    bool fixedPitch;
    bool symbol;
};

struct FamilyCache {
    QList<FamilyEntry> entries;
    int generation = 0;
    bool filled = false;
    bool connected = false;
};

FamilyCache &familyCache()
{
    static FamilyCache cache;
    return cache;
}

// QFontDatabase::families() lists a family once per foundry as
// "Name [foundry]"; strip the suffix so each family appears once.
QString normalizedFamily(const QString &name)
{
    static const QRegularExpression foundry_suffix(QStringLiteral("\\s*\\[[^\\]]*\\]$"));
    QString normalized = name;
    normalized.remove(foundry_suffix);
    return normalized;
}

void ensureFamilyCache()
{
    FamilyCache &cache = familyCache();

    if (!cache.connected) {
        cache.connected = true;
        QObject::connect(qApp, &QGuiApplication::fontDatabaseChanged, qApp, [] {
            FamilyCache &c = familyCache();
            c.entries.clear();
            c.filled = false;
            c.generation++;
        });
    }
    if (cache.filled) {
        return;
    }

    QApplication::setOverrideCursor(Qt::WaitCursor);
    for (const QString &raw : QFontDatabase::families()) {
        const QString name = normalizedFamily(raw);
        const bool fixed = QFontDatabase::isFixedPitch(raw);
        const bool symbol = QFontDatabase::writingSystems(raw).contains(QFontDatabase::Symbol);
        bool found = false;
        for (FamilyEntry &entry : cache.entries) {
            if (entry.family == name) {
                entry.fixedPitch = entry.fixedPitch || fixed;
                entry.symbol = entry.symbol || symbol;
                found = true;
                break;
            }
        }
        if (!found) {
            cache.entries.append({name, fixed, symbol});
        }
    }
    cache.filled = true;
    QApplication::restoreOverrideCursor();
}

const FamilyEntry *findCached(const QString &normalized)
{
    for (const FamilyEntry &entry : familyCache().entries) {
        if (entry.family.compare(normalized, Qt::CaseInsensitive) == 0) {
            return &entry;
        }
    }
    return nullptr;
}

// QFontDatabase::font() needs a point size, but only the face attributes
// (weight, style, style name) of its result are used, so any size works.
QFont faceFont(const QString &family, const QString &style)
{
    return QFontDatabase::font(family, style, 12);
}

// The item the user picked. A list that gets keyboard focus without a
// current row makes its first row current but does not select it.
QListWidgetItem *selectedListItem(const QListWidget *list)
{
    const QList<QListWidgetItem *> items = list->selectedItems();
    return items.isEmpty() ? nullptr : items.first();
}

} // namespace

bool FontSelectionWidget::Selection::operator==(const Selection &other) const
{
    return family == other.family && qFuzzyCompare(1.0 + pointSize, 1.0 + other.pointSize);
}

FontSelectionWidget::FontSelectionWidget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::FontSelectionWidget)
{
    ui->setupUi(this);
    ZoomScaling::scaleSizeLimits(ui->styleListWidget);
    ZoomScaling::scaleSizeLimits(ui->sizeSpinBox);
    ZoomScaling::scaleSizeLimits(ui->sizeListWidget);
    ZoomScaling::scaleSizeLimits(ui->effectsGroupBox);
    setFocusProxy(ui->familyListWidget);

    // The pangram spans the alphabet; the hex dump line shows how the packet
    // bytes pane looks. The dump is data, not prose, so it is not translated.
    GRand *rand_state = g_rand_new();
    const char *pangram = font_pangrams_[g_rand_int_range(rand_state, 0, num_font_pangrams_)];
    g_rand_free(rand_state);
    sampleText_ = QStringLiteral("%1 0123456789\n%2")
        .arg(tr(pangram),
             QStringLiteral("0010  00 40 12 34 40 00 40 06  ab cd 01 01 01 01  .@.4@.@....."));
    ui->sampleLabel->setText(sampleText_);

    connect(ui->familyLineEdit, &QLineEdit::textChanged,
            this, &FontSelectionWidget::applyFamilyTextFilter);
    // Edits follow the selection, not the current row: focus alone moves the
    // current row (see selectedListItem()).
    connect(ui->familyListWidget, &QListWidget::itemSelectionChanged,
            this, &FontSelectionWidget::familySelectionChanged);
    connect(ui->monospaceCheckBox, &QCheckBox::toggled,
            this, &FontSelectionWidget::monospaceToggled);
    connect(ui->styleListWidget, &QListWidget::itemSelectionChanged,
            this, &FontSelectionWidget::styleSelectionChanged);
    connect(ui->sizeListWidget, &QListWidget::itemSelectionChanged,
            this, &FontSelectionWidget::sizeSelectionChanged);
    connect(ui->sizeSpinBox, &QDoubleSpinBox::valueChanged,
            this, &FontSelectionWidget::sizeValueChanged);
    connect(ui->strikeoutCheckBox, &QCheckBox::toggled,
            this, &FontSelectionWidget::strikeOutToggled);
    connect(ui->underlineCheckBox, &QCheckBox::toggled,
            this, &FontSelectionWidget::underlineToggled);

    FontManager *fm = FontManager::instance();
    connect(fm, &FontManager::applicationFontChanged, this, &FontSelectionWidget::refreshSample);
    connect(fm, &FontManager::monospaceFontChanged, this, &FontSelectionWidget::refreshSample);

    refreshAll();
}

FontSelectionWidget::~FontSelectionWidget()
{
    delete ui;
}

void FontSelectionWidget::setFamilyFilter(FamilyFilter filter)
{
    filter_ = filter;
    {
        QSignalBlocker blocker(ui->monospaceCheckBox);
        ui->monospaceCheckBox->setChecked(filter_ == FamilyFilter::FixedPitchOnly);
    }
    fillFamilyList();
}

FontSelectionWidget::FamilyFilter FontSelectionWidget::familyFilter() const
{
    return filter_;
}

void FontSelectionWidget::setFontClass(FontClass fontClass)
{
    fontClass_ = fontClass;
    refreshAll();
}

FontSelectionWidget::FontClass FontSelectionWidget::fontClass() const
{
    return fontClass_;
}

void FontSelectionWidget::setFeatures(Features features)
{
    features_ = features;
    ui->styleLabel->setVisible(features_.testFlag(StyleFeature));
    ui->styleListWidget->setVisible(features_.testFlag(StyleFeature));
    ui->effectsGroupBox->setVisible(features_.testFlag(EffectsFeature));
    ui->monospaceCheckBox->setVisible(features_.testFlag(FamilyFilterFeature));
}

FontSelectionWidget::Features FontSelectionWidget::features() const
{
    return features_;
}

void FontSelectionWidget::setDefaultAllowed(bool allowed)
{
    defaultAllowed_ = allowed;
    refreshAll();
}

bool FontSelectionWidget::defaultAllowed() const
{
    return defaultAllowed_;
}

void FontSelectionWidget::resetTo(const QFont &font, const Selection &sel)
{
    base_ = font;
    sel_ = sel;
    style_ = QFontDatabase::styleString(font);
    strikeOut_ = font.strikeOut();
    underline_ = font.underline();
    familyEdited_ = false;
    styleEdited_ = false;
    sizeEdited_ = false;
    strikeOutEdited_ = false;
    underlineEdited_ = false;
    refreshAll();
}

void FontSelectionWidget::setSelection(const Selection &sel)
{
    QFont font;
    if (!sel.family.isEmpty()) {
        font.setFamily(sel.family);
    }
    if (sel.pointSize > 0) {
        font.setPointSizeF(sel.pointSize);
    }
    resetTo(font, sel);
}

FontSelectionWidget::Selection FontSelectionWidget::selection() const
{
    return sel_;
}

void FontSelectionWidget::setSelectedFont(const QFont &font)
{
    resetTo(font, {font.family(), font.pointSizeF()});
}

QFont FontSelectionWidget::selectedFont() const
{
    QFont font = base_;
    if (familyEdited_ && !sel_.family.isEmpty()) {
        font.setFamily(sel_.family);
        // A style name the new family lacks would match nothing; without it
        // Qt picks the face by weight and italic.
        if (!styleEdited_ && !base_.styleName().isEmpty()
                && !QFontDatabase::styles(sel_.family).contains(base_.styleName(), Qt::CaseInsensitive)) {
            font.setStyleName(QString());
        }
    }
    if (styleEdited_ && !style_.isEmpty()) {
        const QFont styled = faceFont(lookupFamily(), style_);
        font.setWeight(styled.weight());
        font.setStyle(styled.style());
        font.setStyleName(styled.styleName());
    }
    if (sizeEdited_ && sel_.pointSize > 0) {
        font.setPointSizeF(sel_.pointSize);
    }
    if (strikeOutEdited_) {
        font.setStrikeOut(strikeOut_);
    }
    if (underlineEdited_) {
        font.setUnderline(underline_);
    }
    return font;
}

QFont FontSelectionWidget::resolvedFont() const
{
    const bool monospace = fontClass_ == FontClass::Monospace;
    if (sel_.family.isEmpty()) {
        QFont font = FontManager::themeFont(QString(), monospace);
        if (sel_.pointSize > 0) {
            font.setPointSizeF(sel_.pointSize);
        }
        return font;
    }
    return monospace ? FontManager::preferenceMonospaceFont(selectedFont()) : selectedFont();
}

void FontSelectionWidget::setSampleText(const QString &text)
{
    sampleText_ = text;
    ui->sampleLabel->setText(sampleText_);
}

void FontSelectionWidget::showEvent(QShowEvent *event)
{
    ensureFamilyCache();
    if (filledGeneration_ != familyCache().generation) {
        fillFamilyList();
    }
    fillStyleList();
    fillSizeList();
    // Also undoes a parent that reset the font of every child.
    refreshSample();
    QWidget::showEvent(event);
}

QString FontSelectionWidget::lookupFamily() const
{
    return sel_.family.isEmpty() ? base_.family() : sel_.family;
}

void FontSelectionWidget::fillFamilyList()
{
    const FamilyCache &cache = familyCache();
    QListWidget *list = ui->familyListWidget;
    QSignalBlocker blocker(list);

    auto ownFont = [list](const QString &family) {
        QFont font(family);
        if (list->font().pointSizeF() > 0) {
            font.setPointSizeF(list->font().pointSizeF());
        }
        return font;
    };
    auto addFamily = [list, &ownFont](int row, const QString &text, const QString &family, bool ownTypeface) {
        QListWidgetItem *item = new QListWidgetItem(text);
        item->setData(Qt::UserRole, family);
        if (ownTypeface) {
            item->setData(Qt::FontRole, ownFont(family));
        }
        list->insertItem(row, item);
    };

    list->clear();
    if (defaultAllowed_) {
        addFamily(0, tr("(Platform default)"), QString(), false);
    }

    // Without a default entry an empty family shows what it resolves to.
    const QString current = (sel_.family.isEmpty() && !defaultAllowed_)
        ? resolvedFont().family() : sel_.family;
    int currentRow = -1;

    if (!cache.filled) {
        // Fonts are enumerated on first show; until then only the current one.
        if (!current.isEmpty()) {
            currentRow = list->count();
            addFamily(currentRow, current, current, false);
        } else if (defaultAllowed_) {
            currentRow = 0;
        }
        filledGeneration_ = -1;
    } else {
        for (const FamilyEntry &entry : cache.entries) {
            if (filter_ == FamilyFilter::FixedPitchOnly && !entry.fixedPitch) {
                continue;
            }
            // Symbol fonts would draw their own name as symbols.
            addFamily(list->count(), entry.family, entry.family, !entry.symbol);
        }
        filledGeneration_ = cache.generation;

        if (current.isEmpty()) {
            currentRow = defaultAllowed_ ? 0 : -1;
        } else {
            const QString normalized = normalizedFamily(current);
            for (int row = 0; row < list->count(); row++) {
                if (list->item(row)->data(Qt::UserRole).toString().compare(normalized, Qt::CaseInsensitive) == 0) {
                    currentRow = row;
                    break;
                }
            }
            if (currentRow < 0) {
                currentRow = defaultAllowed_ ? 1 : 0;
                if (const FamilyEntry *entry = findCached(normalized)) {
                    // Installed, but not offered by the filter.
                    addFamily(currentRow, current, current, !entry->symbol);
                } else {
                    addFamily(currentRow, tr("%1 (not installed)").arg(current), current, false);
                }
            }
        }
    }

    // Shown by the text filter when it hides every family.
    QListWidgetItem *placeholder = new QListWidgetItem(tr("No matching font families"));
    placeholder->setFlags(Qt::NoItemFlags);
    list->addItem(placeholder);

    list->setCurrentRow(currentRow);
    if (QListWidgetItem *item = list->item(currentRow)) {
        list->scrollToItem(item);
    }
    applyFamilyTextFilter();
}

void FontSelectionWidget::applyFamilyTextFilter()
{
    QListWidget *list = ui->familyListWidget;
    const QString text = ui->familyLineEdit->text();
    const int placeholderRow = list->count() - 1;
    bool anyShown = false;

    for (int row = 0; row < placeholderRow; row++) {
        const bool hide = !text.isEmpty()
            && !list->item(row)->text().contains(text, Qt::CaseInsensitive);
        list->setRowHidden(row, hide);
        anyShown = anyShown || !hide;
    }
    if (placeholderRow >= 0) {
        list->setRowHidden(placeholderRow, anyShown);
    }
}

void FontSelectionWidget::fillStyleList()
{
    QListWidget *list = ui->styleListWidget;
    QSignalBlocker blocker(list);
    list->clear();
    if (!familyCache().filled) {
        return;
    }

    const QString family = lookupFamily();
    QStringList styles;
    if (QFontDatabase::hasFamily(family)) {
        struct StyleKey {
            QString name;
            int weight;
            bool upright;
        };
        QList<StyleKey> keys;
        for (const QString &style : QFontDatabase::styles(family)) {
            // QFontDatabase::italic() is false for oblique faces; the face's
            // style() tells upright from both italic and oblique.
            const QFont face = faceFont(family, style);
            keys.append({style, face.weight(), face.style() == QFont::StyleNormal});
        }
        // Lightest first, upright before slanted within one weight.
        std::stable_sort(keys.begin(), keys.end(), [](const StyleKey &a, const StyleKey &b) {
            if (a.weight != b.weight) {
                return a.weight < b.weight;
            }
            return a.upright && !b.upright;
        });
        for (const StyleKey &key : keys) {
            styles.append(key.name);
        }
    } else if (!style_.isEmpty()) {
        // A missing family has no style list; show the stored style only.
        styles.append(style_);
    }
    list->addItems(styles);

    // The stored style, else the face Qt matched: a family change can keep a
    // style name such as "Normal" that the new family does not list.
    QList<QListWidgetItem *> matches =
        list->findItems(QFontDatabase::styleString(selectedFont()), Qt::MatchFixedString);
    if (matches.isEmpty()) {
        const QString matched = QFontInfo(resolvedFont()).styleName();
        if (!matched.isEmpty()) {
            matches = list->findItems(matched, Qt::MatchFixedString);
        }
    }
    if (!matches.isEmpty()) {
        list->setCurrentItem(matches.first());
        list->scrollToItem(matches.first());
    }
}

void FontSelectionWidget::fillSizeList()
{
    updateSizeSpin();

    QListWidget *list = ui->sizeListWidget;
    QSignalBlocker blocker(list);
    list->clear();
    if (!familyCache().filled) {
        return;
    }

    QList<int> sizes = QFontDatabase::pointSizes(lookupFamily(), style_);
    if (sizes.isEmpty()) {
        sizes = QFontDatabase::standardSizes();
    }
    for (int size : sizes) {
        QListWidgetItem *item = new QListWidgetItem(QString::number(size));
        item->setData(Qt::UserRole, size);
        list->addItem(item);
    }
    selectSizeRow();
}

void FontSelectionWidget::updateSizeSpin()
{
    QSignalBlocker blocker(ui->sizeSpinBox);
    QDoubleSpinBox *spin = ui->sizeSpinBox;

    spin->setMinimum(defaultAllowed_ ? 0.0 : 1.0);
    spin->setSpecialValueText(defaultAllowed_ ? tr("Default") : QString());
    if (sel_.pointSize > 0) {
        spin->setValue(sel_.pointSize);
    } else if (defaultAllowed_) {
        spin->setValue(0.0);
    } else {
        spin->setValue(QFontInfo(resolvedFont()).pointSizeF());
    }
}

void FontSelectionWidget::selectSizeRow()
{
    QListWidget *list = ui->sizeListWidget;
    QSignalBlocker blocker(list);
    const double value = ui->sizeSpinBox->value();

    // An off-list size such as 12.5 leaves the list without a selection.
    for (int row = 0; row < list->count(); row++) {
        if (qFuzzyCompare(list->item(row)->data(Qt::UserRole).toDouble(), value)) {
            list->setCurrentRow(row);
            list->scrollToItem(list->item(row));
            return;
        }
    }
    list->setCurrentItem(nullptr);
}

void FontSelectionWidget::updateEffects()
{
    QSignalBlocker strikeout_blocker(ui->strikeoutCheckBox);
    QSignalBlocker underline_blocker(ui->underlineCheckBox);
    ui->strikeoutCheckBox->setChecked(strikeOut_);
    ui->underlineCheckBox->setChecked(underline_);
}

void FontSelectionWidget::refreshAll()
{
    fillFamilyList();
    fillStyleList();
    fillSizeList();
    updateEffects();
    refreshSample();
}

void FontSelectionWidget::refreshSample()
{
    ui->sampleLabel->setFont(resolvedFont());
}

void FontSelectionWidget::familySelectionChanged()
{
    const QListWidgetItem *item = selectedListItem(ui->familyListWidget);
    if (!item || !(item->flags() & Qt::ItemIsSelectable)) {
        return;
    }
    sel_.family = item->data(Qt::UserRole).toString();
    familyEdited_ = true;
    fillStyleList();
    fillSizeList();
    refreshSample();
    emit changed();
}

void FontSelectionWidget::monospaceToggled(bool checked)
{
    filter_ = checked ? FamilyFilter::FixedPitchOnly : FamilyFilter::AllFamilies;
    fillFamilyList();
}

void FontSelectionWidget::styleSelectionChanged()
{
    const QListWidgetItem *item = selectedListItem(ui->styleListWidget);
    if (!item) {
        return;
    }
    style_ = item->text();
    styleEdited_ = true;
    fillSizeList();
    refreshSample();
    emit changed();
}

void FontSelectionWidget::sizeSelectionChanged()
{
    const QListWidgetItem *item = selectedListItem(ui->sizeListWidget);
    if (!item) {
        return;
    }
    // The spin box signal records the edit.
    ui->sizeSpinBox->setValue(item->data(Qt::UserRole).toInt());
}

void FontSelectionWidget::sizeValueChanged(double value)
{
    sel_.pointSize = value;
    sizeEdited_ = true;
    selectSizeRow();
    refreshSample();
    emit changed();
}

void FontSelectionWidget::strikeOutToggled(bool checked)
{
    strikeOut_ = checked;
    strikeOutEdited_ = true;
    refreshSample();
    emit changed();
}

void FontSelectionWidget::underlineToggled(bool checked)
{
    underline_ = checked;
    underlineEdited_ = true;
    refreshSample();
    emit changed();
}
