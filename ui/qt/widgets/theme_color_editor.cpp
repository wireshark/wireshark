/* theme_color_editor.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <config.h>

#include "theme_color_editor.h"
#include <ui_theme_color_editor.h>

#include <ui/qt/utils/font_manager.h>
#include <ui/qt/utils/themes/theme_format.h>
#include <ui/qt/utils/themes/theme_writer.h>
#include <ui/qt/widgets/syntax_line_edit.h>

#include <QAbstractItemView>
#include <QCheckBox>
#include <QCoreApplication>
#include <QColorDialog>
#include <QFontMetrics>
#include <QHeaderView>
#include <QLineEdit>
#include <QMenu>
#include <QMetaEnum>
#include <QPainter>
#include <QPixmap>
#include <QPushButton>
#include <QRegularExpression>
#include <QSet>
#include <QTreeWidget>

#include <algorithm>

namespace {

// Row ids: color and derived rows use the token value, graph slots start
// far above the last token so the ranges never meet.
const int kGraphRowBase = 0x10000;
const int kNoGraphsRowId = kGraphRowBase - 1;
const int kSwatchSize = 12;

QColor themeColor(ThemeManager::ThemeToken token)
{
    return ThemeManager::instance()->color(token);
}

QPixmap swatchPixmap(const QColor &color, const QColor &border, qreal dpr)
{
    QPixmap pm(QSize(kSwatchSize, kSwatchSize) * dpr);
    pm.setDevicePixelRatio(dpr);
    pm.fill(Qt::transparent);
    QPainter painter(&pm);
    const QRect rect(0, 0, kSwatchSize - 1, kSwatchSize - 1);
    if (color.isValid())
        painter.fillRect(rect, color);
    painter.setPen(border);
    painter.drawRect(rect);
    return pm;
}

// Group title of a file key: the key with its first letter upper-cased.
QString groupTitle(const QString &key)
{
    return key.isEmpty() ? key : key.left(1).toUpper() + key.mid(1);
}

} // namespace

ThemeColorEditor::ThemeColorEditor(QWidget *parent) :
    QWidget(parent),
    dark_(ThemeManager::instance()->isDarkMode()),
    ui_(new Ui::ThemeColorEditor)
{
    ui_->setupUi(this);

    side_widget_[0] = ui_->lightRow;
    side_widget_[1] = ui_->darkRow;
    swatch_label_[0] = ui_->lightSwatchLabel;
    swatch_label_[1] = ui_->darkSwatchLabel;
    hex_edit_[0] = ui_->lightHexEdit;
    hex_edit_[1] = ui_->darkHexEdit;
    choose_button_[0] = ui_->lightChooseButton;
    choose_button_[1] = ui_->darkChooseButton;
    revert_button_[0] = ui_->lightRevertButton;
    revert_button_[1] = ui_->darkRevertButton;

    ui_->colorTree->setIconSize(QSize(kSwatchSize, kSwatchSize));
    ui_->colorTree->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    ui_->colorTree->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    ui_->colorTree->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);

    // Line up the hex fields of both sides.
    const int side_label_width = qMax(ui_->lightLabel->sizeHint().width(),
                                      ui_->darkLabel->sizeHint().width());
    ui_->lightLabel->setMinimumWidth(side_label_width);
    ui_->darkLabel->setMinimumWidth(side_label_width);

    const QFont mono = FontManager::monospaceFont();
    for (int side = 0; side < 2; ++side) {
        hex_edit_[side]->setFont(mono);
        hex_edit_[side]->setMinimumWidth(QFontMetrics(mono).horizontalAdvance(QStringLiteral("auto #aarrggbb")) + 16);
        connect(hex_edit_[side], &QLineEdit::textEdited, this,
                [this, side](const QString &text) { hexEdited(side, text); });
        connect(hex_edit_[side], &QLineEdit::editingFinished, this,
                [this, side]() { hexEditingFinished(side); });
        connect(choose_button_[side], &QPushButton::clicked, this,
                [this, side]() { chooseColor(side); });
        connect(revert_button_[side], &QPushButton::clicked, this,
                [this, side]() { revertSide(side); });
    }

    connect(ui_->filterEdit, &QLineEdit::textChanged, this, &ThemeColorEditor::applyFilter);
    connect(ui_->changedOnlyCheckBox, &QCheckBox::toggled, this, &ThemeColorEditor::applyFilter);
    connect(ui_->colorTree, &QTreeWidget::currentItemChanged, this, &ThemeColorEditor::currentItemChanged);
    connect(ui_->colorTree, &QTreeWidget::customContextMenuRequested, this, &ThemeColorEditor::showContextMenu);
    connect(ui_->useAutoButton, &QPushButton::clicked, this, &ThemeColorEditor::useAuto);
    connect(ui_->addColorButton, &QPushButton::clicked, this, &ThemeColorEditor::addGraphColor);
    connect(ui_->removeColorButton, &QPushButton::clicked, this, &ThemeColorEditor::removeGraphColor);
    connect(ThemeManager::instance(), &ThemeManager::themeChanged, this, &ThemeColorEditor::themeChanged);

    ThemeManager::setValidationState(ui_->errorLabel, QStringLiteral("invalid"));
    resolveBoth(base_, base_resolved_);
    rebuildTree();
    recompute();
    refreshRows();
    updateDetail(true);
}

ThemeColorEditor::~ThemeColorEditor()
{
    delete ui_;
}

void ThemeColorEditor::setDrafts(const ThemeDraft &base, const ThemeDraft &draft)
{
    // Pending text belongs to the fields of the theme being edited; it is
    // kept only when the caller hands back the same theme with the same
    // colors (for example after a meta data or font edit).
    const bool same_theme = base_.info.internalName == base.info.internalName
                            && base_ == base && draft_.sameColors(draft);
    if (!same_theme)
        pending_.clear();

    base_ = base;
    draft_ = draft;
    resolveBoth(base_, base_resolved_);
    rebuildTree();
    recompute();
    refreshRows();
    updateDetail(true);
}

void ThemeColorEditor::setDarkSide(bool dark)
{
    if (dark_ == dark)
        return;
    dark_ = dark;
    refreshRows();
    updateDetail(false);
}

int ThemeColorEditor::editedCount() const
{
    int count = 0;
    for (const Row &row : rows_) {
        if (row.state == RowState::Edited)
            ++count;
    }
    // Slots removed from the end of the graph list have no row of their own.
    count += static_cast<int>(qMax<qsizetype>(0, base_.graphColors.size() - draft_.graphColors.size()));
    return count;
}

int ThemeColorEditor::changedCount() const
{
    int count = 0;
    for (const Row &row : rows_) {
        if (row.state == RowState::Changed)
            ++count;
    }
    return count;
}

QString ThemeColorEditor::firstInvalidPath() const
{
    for (const Row &row : rows_) {
        for (int side = 0; side < 2; ++side) {
            if (pending_.contains(qMakePair(row.id(), side)))
                return row.path + (side ? QStringLiteral(".dark") : QStringLiteral(".light"));
        }
    }
    return QString();
}

int ThemeColorEditor::rowIdFor(RowKind kind, ThemeManager::ThemeToken token, int graph)
{
    switch (kind) {
    case RowKind::Graph:
        return kGraphRowBase + graph;
    case RowKind::NoGraphs:
        return kNoGraphsRowId;
    default:
        return static_cast<int>(token);
    }
}

QString ThemeColorEditor::graphDescription()
{
    return tr("Graph color cycle. No backfill from the default theme.");
}

QString ThemeColorEditor::tokenName(ThemeManager::ThemeToken token)
{
    return QString::fromLatin1(QMetaEnum::fromType<ThemeManager::ThemeToken>().valueToKey(token));
}

void ThemeColorEditor::resolveBoth(const ThemeDraft &draft, ResolvedMap out[2],
                                   ThemeTokenHandler::SourceMap *sources)
{
    // resolveDraftTokens() only guarantees the requested side, so each side
    // is resolved on its own.
    const ThemeManager *tm = ThemeManager::instance();
    out[0] = ThemeManager::flattenTokens(tm->resolveDraftTokens(draft, false, nullptr, sources), false);
    out[1] = ThemeManager::flattenTokens(tm->resolveDraftTokens(draft, true), true);
}

void ThemeColorEditor::rebuildTree()
{
    const QSignalBlocker blocker(ui_->colorTree);
    ui_->colorTree->clear();
    rows_.clear();
    row_index_.clear();
    group_items_.clear();

    QFont group_font = ui_->colorTree->font();
    group_font.setBold(true);
    QTreeWidgetItem *group = nullptr;
    auto addGroup = [&](const QString &title) {
        group = new QTreeWidgetItem(ui_->colorTree);
        group->setText(0, title);
        group->setFont(0, group_font);
        group->setFlags(Qt::ItemIsEnabled);
        group->setFirstColumnSpanned(true);
        group_items_ << group;
    };
    auto addRow = [&](Row row) {
        row.item = new QTreeWidgetItem(group);
        row.item->setData(0, Qt::UserRole, row.id());
        row_index_.insert(row.id(), static_cast<int>(rows_.size()));
        rows_ << row;
    };

    QSet<int> settable;
    QString last_section;
    for (const ThemeWriter::KeyInfo &info : ThemeWriter::keyTable()) {
        const QString &section = info.section;
        if (section != last_section) {
            addGroup(groupTitle(section));
            last_section = section;
        }
        Row row;
        row.kind = RowKind::Color;
        row.token = info.token;
        row.label = info.key;
        row.section = section;
        row.path = ThemeWriter::keyPath(info);
        row.required = ThemeDraft::requiredTokens().contains(info.token);
        row.description = QCoreApplication::translate("ThemeWriter", info.description);
        addRow(row);
        settable.insert(info.token);
    }

    const QString separator_key = QString(ThemeFormat::Separator);
    addGroup(groupTitle(separator_key));
    {
        Row row;
        row.kind = RowKind::Color;
        row.token = ThemeManager::Separator;
        row.label = separator_key;
        row.section = separator_key;
        row.path = row.label;
        row.description = tr("Hairline dividers between cards and panes.");
        addRow(row);
    }

    const QString graphs_key = QString(ThemeFormat::Graphs);
    addGroup(groupTitle(graphs_key));
    for (int i = 0; i < draft_.graphColors.size(); ++i) {
        Row row;
        row.kind = RowKind::Graph;
        row.graph = i;
        row.label = tr("color %1").arg(i + 1);
        row.section = graphs_key;
        row.path = ThemeFormat::graphPath(i);
        addRow(row);
    }
    if (draft_.graphColors.isEmpty()) {
        Row row;
        row.kind = RowKind::NoGraphs;
        row.label = tr("No graph colors");
        row.section = graphs_key;
        row.path = graphs_key;
        addRow(row);
    }

    addGroup(tr("Derived (read-only)"));
    const QMetaEnum meta = QMetaEnum::fromType<ThemeManager::ThemeToken>();
    for (int i = 0; i < meta.keyCount(); ++i) {
        const ThemeManager::ThemeToken token = static_cast<ThemeManager::ThemeToken>(meta.value(i));
        if (token == ThemeManager::NoRole || token == ThemeManager::Separator || settable.contains(token))
            continue;
        Row row;
        row.kind = RowKind::Derived;
        row.token = token;
        row.label = QString::fromLatin1(meta.key(i));
        row.section = QStringLiteral("derived");
        row.path = row.label;
        addRow(row);
    }

    ui_->colorTree->expandAll();

    if (!row_index_.contains(current_row_id_) && !rows_.isEmpty())
        current_row_id_ = rows_.first().id();
    if (row_index_.contains(current_row_id_))
        ui_->colorTree->setCurrentItem(rows_.at(row_index_.value(current_row_id_)).item);
}

void ThemeColorEditor::recompute()
{
    // deriveAll() and build() only insert, so a rule text from an earlier
    // draft would survive a revert or unset without this.
    sources_.clear();
    resolveBoth(draft_, draft_resolved_, &sources_);

    auto resolvedDiffers = [this](ThemeManager::ThemeToken token) {
        for (int side = 0; side < 2; ++side) {
            if (!ThemeColorPair::sameColor(draft_resolved_[side].value(token), base_resolved_[side].value(token)))
                return true;
        }
        return false;
    };

    for (Row &row : rows_) {
        row.state = RowState::None;
        switch (row.kind) {
        case RowKind::Color:
        {
            const bool in_draft = draft_.colors.contains(row.token);
            const bool in_base = base_.colors.contains(row.token);
            const bool edited = in_draft != in_base
                                || (in_draft && draft_.colors.value(row.token) != base_.colors.value(row.token));
            if (edited)
                row.state = RowState::Edited;
            else if (!in_draft && resolvedDiffers(row.token))
                row.state = RowState::Changed;
            else if (row.required)
                row.state = RowState::Required;
            break;
        }
        case RowKind::Graph:
            if (row.graph >= base_.graphColors.size()
                    || draft_.graphColors.at(row.graph) != base_.graphColors.at(row.graph))
                row.state = RowState::Edited;
            break;
        case RowKind::Derived:
            if (resolvedDiffers(row.token))
                row.state = RowState::Changed;
            break;
        case RowKind::NoGraphs:
            break;
        }
    }
}

void ThemeColorEditor::refreshRows()
{
    ui_->colorTree->setHeaderLabels({ tr("Color"),
                                      dark_ ? tr("Value (Dark)") : tr("Value (Light)"),
                                      tr("State") });

    const QFont plain = ui_->colorTree->font();
    QFont italic = plain;
    italic.setItalic(true);
    QFont bold = plain;
    bold.setBold(true);
    const qreal dpr = devicePixelRatioF();
    const int side = dark_ ? 1 : 0;

    for (const Row &row : rows_) {
        QTreeWidgetItem *item = row.item;
        for (int col = 0; col < 3; ++col) {
            item->setFont(col, plain);
            item->setData(col, Qt::ForegroundRole, QVariant());
        }
        item->setText(0, row.label);

        if (row.kind == RowKind::NoGraphs) {
            item->setIcon(0, QIcon());
            item->setText(1, QString());
            item->setText(2, QString());
            for (int col = 0; col < 3; ++col)
                item->setForeground(col, themeColor(ThemeManager::MutedText));
            continue;
        }

        const QColor shown = shownColor(row, side);
        item->setIcon(0, QIcon(swatchPixmap(shown, themeColor(ThemeManager::FieldBorder), dpr)));

        bool is_set = true;
        if (row.kind == RowKind::Color)
            inputColor(row, side, &is_set);
        if (!is_set) {
            item->setText(1, autoValueText(shown));
            item->setFont(1, italic);
            item->setForeground(1, themeColor(ThemeManager::MutedText));
        } else {
            item->setText(1, ThemeWriter::colorText(shown));
        }

        if (row.kind == RowKind::Derived) {
            for (int col = 0; col < 3; ++col)
                item->setForeground(col, themeColor(ThemeManager::MutedText));
        }

        switch (row.state) {
        case RowState::Edited:
            item->setText(2, tr("edited"));
            item->setForeground(2, themeColor(ThemeManager::AccentInfo));
            item->setFont(2, bold);
            break;
        case RowState::Changed:
            item->setText(2, tr("changed"));
            item->setForeground(2, themeColor(ThemeManager::AccentWarning));
            break;
        case RowState::Required:
            item->setText(2, tr("required"));
            item->setForeground(2, themeColor(ThemeManager::MutedText));
            break;
        case RowState::None:
            item->setText(2, QString());
            break;
        }
    }

    applyFilter();
}

void ThemeColorEditor::applyFilter()
{
    const QString text = ui_->filterEdit->text().trimmed();
    const bool changed_only = ui_->changedOnlyCheckBox->isChecked();

    for (const Row &row : rows_) {
        bool visible = text.isEmpty()
                       || row.label.contains(text, Qt::CaseInsensitive)
                       || row.section.contains(text, Qt::CaseInsensitive)
                       || rowDescription(row).contains(text, Qt::CaseInsensitive);
        if (changed_only && row.state != RowState::Edited && row.state != RowState::Changed)
            visible = false;
        row.item->setHidden(!visible);
    }

    for (QTreeWidgetItem *group : group_items_) {
        bool any = false;
        for (int i = 0; i < group->childCount() && !any; ++i)
            any = !group->child(i)->isHidden();
        group->setHidden(!any);
    }
}

void ThemeColorEditor::updateDetail(bool force_fields)
{
    const Row *row = currentRow();
    ui_->detailWidget->setVisible(row != nullptr);
    if (!row)
        return;

    const int active = dark_ ? 1 : 0;

    if (row->kind == RowKind::Derived) {
        const QFont mono = FontManager::monospaceFont();
        ui_->titleLabel->setText(QStringLiteral("<b>%1</b> <span style=\"font-family: '%2'; color: %3;\">%4</span>")
                                  .arg(row->label.toHtmlEscaped(), mono.family().toHtmlEscaped(),
                                       themeColor(ThemeManager::MutedText).name(),
                                       ThemeWriter::colorText(shownColor(*row, active)).toHtmlEscaped()));
        QString derived = tr("Derived, read-only. Source: %1. Not stored in theme files.")
                              .arg(derivedText(row->token));
        if (!sourceTokens(*row).isEmpty())
            derived += tr(" Right-click the row to go to a source color.");
        ui_->descriptionLabel->setText(derived);
        side_widget_[0]->hide();
        side_widget_[1]->hide();
        ui_->buttonRow->hide();
        ui_->errorLabel->hide();
        return;
    }

    QString title = QStringLiteral("<b>%1</b>").arg(row->path.toHtmlEscaped());
    if (row->state == RowState::Edited) {
        title += editedMarkHtml();
    } else if (row->state == RowState::Changed) {
        title += QStringLiteral(" <span style=\"color: %1;\">%2</span>")
                     .arg(themeColor(ThemeManager::AccentWarning).name(), tr("changed by another color").toHtmlEscaped());
    }
    ui_->titleLabel->setText(title);

    QString description = rowDescription(*row);
    if (row->kind == RowKind::Color) {
        const QStringList affected = affectedTokens(row->token);
        if (!affected.isEmpty())
            description += QLatin1Char(' ') + tr("Affects: %1.").arg(affected.join(QStringLiteral(", ")));
    }
    ui_->descriptionLabel->setText(description);

    const bool is_editable = row->editable();
    const int id = row->id();
    QStringList errors;
    for (int side = 0; side < 2; ++side) {
        side_widget_[side]->setVisible(is_editable);
        if (!is_editable)
            continue;
        if (force_fields || !hex_edit_[side]->hasFocus())
            updateField(side);

        const auto pending = pending_.constFind(qMakePair(id, side));
        if (pending != pending_.constEnd()) {
            hex_edit_[side]->setSyntaxState(SyntaxLineEdit::Invalid);
            swatch_label_[side]->setPixmap(swatchPixmap(QColor(), themeColor(ThemeManager::FieldBorder), devicePixelRatioF()));
            errors << tr("\"%1\" is not a color. Use #rrggbb.").arg(pending.value());
        } else {
            hex_edit_[side]->setSyntaxState(SyntaxLineEdit::Empty);
            swatch_label_[side]->setPixmap(swatchPixmap(shownColor(*row, side), themeColor(ThemeManager::FieldBorder),
                                                        devicePixelRatioF()));
        }

        bool is_set = true;
        const QColor shown = shownColor(*row, side);
        if (row->kind == RowKind::Color)
            inputColor(*row, side, &is_set);
        hex_edit_[side]->setPlaceholderText(is_set ? QString() : autoValueText(shown));
        choose_button_[side]->setToolTip(chooseTitle(*row, side));

        revert_button_[side]->setVisible(sideEdited(*row, side));
        const bool in_base = row->kind == RowKind::Color ? base_.colors.contains(row->token)
                                                         : row->graph < base_.graphColors.size();
        // Without a saved value the click removes the entry, unless only
        // pending text is dropped.
        revert_button_[side]->setToolTip(in_base || !sideValueEdited(*row, side)
                                         ? tr("Revert to the saved value")
                                         : tr("Remove this color; the saved theme does not set it"));
    }

    bool key_set = false;
    if (row->kind == RowKind::Color)
        inputColor(*row, 0, &key_set);
    ui_->useAutoButton->setVisible(row->kind == RowKind::Color && key_set && !row->required);
    ui_->addColorButton->setVisible(row->kind == RowKind::Graph || row->kind == RowKind::NoGraphs);
    ui_->removeColorButton->setVisible(row->kind == RowKind::Graph);
    ui_->removeColorButton->setEnabled(draft_.graphColors.size() > 1);
    ui_->buttonRow->setVisible(ui_->useAutoButton->isVisibleTo(ui_->buttonRow)
                            || ui_->addColorButton->isVisibleTo(ui_->buttonRow));

    ui_->errorLabel->setText(errors.join(QLatin1Char('\n')));
    ui_->errorLabel->setVisible(!errors.isEmpty());
}

void ThemeColorEditor::updateField(int side)
{
    const Row *row = currentRow();
    if (!row)
        return;
    const auto pending = pending_.constFind(qMakePair(row->id(), side));
    if (pending != pending_.constEnd()) {
        hex_edit_[side]->setText(pending.value());
        return;
    }
    hex_edit_[side]->setText(ThemeWriter::colorText(inputColor(*row, side)));
}

const ThemeColorEditor::Row *ThemeColorEditor::currentRow() const
{
    auto it = row_index_.constFind(current_row_id_);
    if (it == row_index_.constEnd())
        return nullptr;
    return &rows_.at(it.value());
}

QColor ThemeColorEditor::inputColor(const Row &row, int side, bool *is_set) const
{
    if (is_set)
        *is_set = false;
    switch (row.kind) {
    case RowKind::Color:
    {
        auto it = draft_.colors.constFind(row.token);
        if (it == draft_.colors.constEnd())
            return QColor();
        if (is_set)
            *is_set = true;
        return it.value().forMode(side != 0);
    }
    case RowKind::Graph:
        if (row.graph < 0 || row.graph >= draft_.graphColors.size())
            return QColor();
        if (is_set)
            *is_set = true;
        return draft_.graphColors.at(row.graph).forMode(side != 0);
    default:
        return QColor();
    }
}

QColor ThemeColorEditor::shownColor(const Row &row, int side) const
{
    switch (row.kind) {
    case RowKind::Color:
    {
        bool is_set = false;
        const QColor input = inputColor(row, side, &is_set);
        return is_set ? input : draft_resolved_[side].value(row.token);
    }
    case RowKind::Graph:
        return inputColor(row, side);
    case RowKind::Derived:
        return draft_resolved_[side].value(row.token);
    case RowKind::NoGraphs:
        break;
    }
    return QColor();
}

QString ThemeColorEditor::rowDescription(const Row &row) const
{
    switch (row.kind) {
    case RowKind::Color:
        return row.description;
    case RowKind::Derived:
        return derivedText(row.token);
    case RowKind::Graph:
    case RowKind::NoGraphs:
        break;
    }
    return graphDescription();
}

// Which tokens follow this one: set it to black and to white on both sides
// and list every other token whose resolved value moves.  Computed instead
// of tabled so it stays exact when the derivations change.
QStringList ThemeColorEditor::affectedTokens(ThemeManager::ThemeToken token) const
{
    QSet<int> hit;
    for (const QColor &probe : { QColor(Qt::black), QColor(Qt::white) }) {
        ThemeDraft probe_draft = draft_;
        probe_draft.colors.insert(token, ThemeColorPair { probe, probe });
        ResolvedMap resolved[2];
        resolveBoth(probe_draft, resolved);
        for (int side = 0; side < 2; ++side) {
            QSet<ThemeManager::ThemeToken> keys;
            for (auto it = resolved[side].constBegin(); it != resolved[side].constEnd(); ++it)
                keys.insert(it.key());
            for (auto it = draft_resolved_[side].constBegin(); it != draft_resolved_[side].constEnd(); ++it)
                keys.insert(it.key());
            for (ThemeManager::ThemeToken key : keys) {
                if (key != token && !ThemeColorPair::sameColor(resolved[side].value(key), draft_resolved_[side].value(key)))
                    hit.insert(key);
            }
        }
    }

    QList<int> ordered(hit.cbegin(), hit.cend());
    std::sort(ordered.begin(), ordered.end());
    QStringList names;
    for (int value : ordered)
        names << tokenName(static_cast<ThemeManager::ThemeToken>(value));
    return names;
}

void ThemeColorEditor::setColor(const Row &row, int side, const QColor &color)
{
    if (row.kind == RowKind::Color) {
        ThemeColorPair pair;
        auto it = draft_.colors.constFind(row.token);
        if (it != draft_.colors.constEnd()) {
            pair = it.value();
        } else {
            // The other side starts from what the user saw as its auto value.
            pair = ThemeColorPair { draft_resolved_[0].value(row.token), draft_resolved_[1].value(row.token) };
        }
        pair.setForMode(side != 0, color);
        if (!pair.forMode(side == 0).isValid())
            pair.setForMode(side == 0, color);
        draft_.colors.insert(row.token, pair);
    } else if (row.kind == RowKind::Graph && row.graph >= 0 && row.graph < draft_.graphColors.size()) {
        draft_.graphColors[row.graph].setForMode(side != 0, color);
    }
}

void ThemeColorEditor::dropPending(int row_id)
{
    pending_.remove(qMakePair(row_id, 0));
    pending_.remove(qMakePair(row_id, 1));
}

// Moves the pending text of graph slots at index >= from by delta slots.
void ThemeColorEditor::shiftGraphPending(int from, int delta)
{
    QMap<QPair<int, int>, QString> shifted;
    for (auto it = pending_.constBegin(); it != pending_.constEnd(); ++it) {
        QPair<int, int> key = it.key();
        if (key.first >= kGraphRowBase && key.first - kGraphRowBase >= from)
            key.first += delta;
        shifted.insert(key, it.value());
    }
    pending_ = shifted;
}

void ThemeColorEditor::finishChange(bool force_fields)
{
    recompute();
    refreshRows();
    updateDetail(force_fields);
    emit draftChanged();
}

bool ThemeColorEditor::sideValueEdited(const Row &row, int side) const
{
    const bool dark = side != 0;
    switch (row.kind) {
    case RowKind::Color:
    {
        auto draft_it = draft_.colors.constFind(row.token);
        auto base_it = base_.colors.constFind(row.token);
        const bool in_draft = draft_it != draft_.colors.constEnd();
        const bool in_base = base_it != base_.colors.constEnd();
        if (in_draft != in_base)
            return true;
        return in_draft && !ThemeColorPair::sameColor(draft_it.value().forMode(dark), base_it.value().forMode(dark));
    }
    case RowKind::Graph:
        if (row.graph >= base_.graphColors.size())
            return true;
        return !ThemeColorPair::sameColor(draft_.graphColors.at(row.graph).forMode(dark),
                                          base_.graphColors.at(row.graph).forMode(dark));
    default:
        return false;
    }
}

bool ThemeColorEditor::sideEdited(const Row &row, int side) const
{
    return pending_.contains(qMakePair(row.id(), side)) || sideValueEdited(row, side);
}

void ThemeColorEditor::currentItemChanged(QTreeWidgetItem *current)
{
    if (!current)
        return;
    const QVariant id = current->data(0, Qt::UserRole);
    if (!id.isValid() || !row_index_.contains(id.toInt()))
        return;
    current_row_id_ = id.toInt();
    updateDetail(true);
}

void ThemeColorEditor::hexEdited(int side, const QString &text)
{
    const Row *current = currentRow();
    if (!current || !current->editable())
        return;
    const Row row = *current;
    const QPair<int, int> key(row.id(), side);

    // The field takes opaque colors only: the stylesheet path drops alpha,
    // so a translucent value would preview differently than it saves.
    static const QRegularExpression hex_re(QStringLiteral("^#?([0-9a-fA-F]{6})$"));
    const QString trimmed = text.trimmed();
    if (trimmed.isEmpty()) {
        pending_.remove(key);
    } else {
        const QRegularExpressionMatch match = hex_re.match(trimmed);
        if (match.hasMatch()) {
            pending_.remove(key);
            setColor(row, side, QColor(QLatin1Char('#') + match.captured(1)));
        } else {
            pending_.insert(key, text);
        }
    }
    finishChange();
}

void ThemeColorEditor::hexEditingFinished(int side)
{
    const Row *row = currentRow();
    if (!row || !row->editable())
        return;
    // Show the normalized value; pending text stays as typed.
    if (!pending_.contains(qMakePair(row->id(), side)))
        updateField(side);
}

void ThemeColorEditor::chooseColor(int side)
{
    const Row *current = currentRow();
    if (!current || !current->editable())
        return;
    const Row row = *current;
    QColor initial = shownColor(row, side);
    if (!initial.isValid())
        initial = Qt::white;
    initial.setAlpha(255);

    const QColor color = QColorDialog::getColor(initial, this,
                                                chooseTitle(row, side));
    emit childDialogClosed();
    if (!color.isValid())
        return;
    pending_.remove(qMakePair(row.id(), side));
    setColor(row, side, color);
    finishChange(true);
}

void ThemeColorEditor::useAuto()
{
    const Row *row = currentRow();
    if (!row || row->kind != RowKind::Color || row->required)
        return;
    draft_.colors.remove(row->token);
    dropPending(row->id());
    finishChange(true);
}

void ThemeColorEditor::revertColor()
{
    const Row *current = currentRow();
    if (!current)
        return;
    const Row row = *current;
    const int id = row.id();

    if (row.kind == RowKind::Color) {
        auto it = base_.colors.constFind(row.token);
        if (it != base_.colors.constEnd())
            draft_.colors.insert(row.token, it.value());
        else
            draft_.colors.remove(row.token);
        dropPending(id);
    } else if (row.kind == RowKind::Graph) {
        dropPending(id);
        if (row.graph < base_.graphColors.size()) {
            draft_.graphColors[row.graph] = base_.graphColors.at(row.graph);
        } else {
            // The base has no such slot: reverting means removing it.
            removeGraphSlot(row.graph);
        }
    } else {
        return;
    }
    finishChange(true);
}

// Reverts one side.  Only what made that side edited is undone: pending
// text alone is dropped without touching the draft, an edited value goes
// back to the base side, or the entry goes when the base does not have it.
void ThemeColorEditor::revertSide(int side)
{
    const Row *current = currentRow();
    if (!current || !current->editable())
        return;
    const Row row = *current;
    const bool value_edited = sideValueEdited(row, side);
    pending_.remove(qMakePair(row.id(), side));
    if (!value_edited) {
        finishChange(true);
        return;
    }

    if (row.kind == RowKind::Color) {
        auto it = base_.colors.constFind(row.token);
        if (it != base_.colors.constEnd())
            setColor(row, side, it.value().forMode(side != 0));
        else
            draft_.colors.remove(row.token);
        finishChange(true);
    } else if (row.graph < base_.graphColors.size()) {
        setColor(row, side, base_.graphColors.at(row.graph).forMode(side != 0));
        finishChange(true);
    } else {
        // A slot the base does not have: removing it takes both sides.
        revertColor();
    }
}

void ThemeColorEditor::showContextMenu(const QPoint &pos)
{
    QTreeWidgetItem *item = ui_->colorTree->itemAt(pos);
    if (!item)
        return;
    const QVariant id = item->data(0, Qt::UserRole);
    if (!id.isValid())
        return;
    auto it = row_index_.constFind(id.toInt());
    if (it == row_index_.constEnd())
        return;
    const Row &row = rows_.at(it.value());
    // Only edited entries offer a revert; there is nothing to undo otherwise.
    const bool can_revert = row.editable()
                            && (row.state == RowState::Edited
                                || pending_.contains(qMakePair(row.id(), 0))
                                || pending_.contains(qMakePair(row.id(), 1)));
    const bool has_sources = offersSources(row);
    if (!can_revert && !has_sources)
        return;

    ui_->colorTree->setCurrentItem(item);
    QMenu menu(this);
    if (has_sources) {
        const QList<ThemeManager::ThemeToken> sources = sourceTokens(row);
        if (sources.isEmpty()) {
            menu.addAction(tr("No source color"))->setEnabled(false);
        }
        for (int i = 0; i < sources.size(); ++i) {
            const ThemeManager::ThemeToken source = sources.at(i);
            QString label = tokenLabel(source);
            auto src_it = row_index_.constFind(rowIdFor(RowKind::Derived, source, -1));
            if (src_it != row_index_.constEnd() && rows_.at(src_it.value()).kind == RowKind::Derived)
                label = tr("%1 (derived)").arg(label);
            QAction *action = menu.addAction(tokenSwatch(source),
                                             i == 0 ? tr("Go to %1").arg(label) : tr("Also uses %1").arg(label));
            connect(action, &QAction::triggered, this, [this, source]() { selectToken(source); });
        }
    }
    if (can_revert) {
        if (has_sources)
            menu.addSeparator();
        QAction *revert_action = menu.addAction(tr("Revert Color"));
        connect(revert_action, &QAction::triggered, this, &ThemeColorEditor::revertColor);
    }
    menu.exec(ui_->colorTree->viewport()->mapToGlobal(pos));
}

bool ThemeColorEditor::selectToken(ThemeManager::ThemeToken token, bool *filter_cleared)
{
    if (filter_cleared)
        *filter_cleared = false;
    if (token == ThemeManager::NoRole)
        return false;
    // Color and derived rows share the token-valued id.
    auto it = row_index_.constFind(rowIdFor(RowKind::Derived, token, -1));
    if (it == row_index_.constEnd())
        return false;
    QTreeWidgetItem *item = rows_.at(it.value()).item;
    if (item->isHidden()) {
        // The signals run applyFilter(), which shows the row again.
        ui_->filterEdit->clear();
        ui_->changedOnlyCheckBox->setChecked(false);
        if (filter_cleared)
            *filter_cleared = true;
    }
    if (item->parent())
        item->parent()->setExpanded(true);
    ui_->colorTree->setCurrentItem(item);
    ui_->colorTree->scrollToItem(item, QAbstractItemView::PositionAtCenter);
    return true;
}

QString ThemeColorEditor::tokenLabel(ThemeManager::ThemeToken token) const
{
    auto it = row_index_.constFind(rowIdFor(RowKind::Derived, token, -1));
    if (it == row_index_.constEnd())
        return tokenName(token);
    return rows_.at(it.value()).label;
}

QIcon ThemeColorEditor::tokenSwatch(ThemeManager::ThemeToken token) const
{
    return QIcon(swatchPixmap(draft_resolved_[dark_ ? 1 : 0].value(token),
                              themeColor(ThemeManager::FieldBorder), devicePixelRatioF()));
}

bool ThemeColorEditor::offersSources(const Row &row) const
{
    if (row.kind == RowKind::Derived)
        return true;
    if (row.kind != RowKind::Color)
        return false;
    bool is_set = false;
    inputColor(row, dark_ ? 1 : 0, &is_set);
    return !is_set;
}

QList<ThemeManager::ThemeToken> ThemeColorEditor::sourceTokens(const Row &row) const
{
    if (!offersSources(row))
        return QList<ThemeManager::ThemeToken>();
    QList<ThemeManager::ThemeToken> tokens = ThemeTokenHandler::sourceTokens(sources_.value(row.token, nullptr));
    tokens.removeAll(row.token);
    return tokens;
}

void ThemeColorEditor::addGraphColor()
{
    const Row *current = currentRow();
    if (!current)
        return;
    if (current->kind == RowKind::NoGraphs) {
        draft_.graphColors.append(ThemeColorPair { draft_resolved_[0].value(ThemeManager::AccentInfo),
                                                   draft_resolved_[1].value(ThemeManager::AccentInfo) });
        current_row_id_ = kGraphRowBase;
    } else if (current->kind == RowKind::Graph) {
        const int slot = current->graph;
        shiftGraphPending(slot + 1, 1);
        draft_.graphColors.insert(slot + 1, draft_.graphColors.at(slot));
        current_row_id_ = kGraphRowBase + slot + 1;
    } else {
        return;
    }
    rebuildTree();
    finishChange(true);
}

void ThemeColorEditor::removeGraphColor()
{
    const Row *current = currentRow();
    // The last slot stays: without any graph color ThemeManager::graphColor()
    // has nothing to return.
    if (!current || current->kind != RowKind::Graph || draft_.graphColors.size() <= 1)
        return;
    const int slot = current->graph;
    dropPending(kGraphRowBase + slot);
    removeGraphSlot(slot);
    finishChange(true);
}

void ThemeColorEditor::removeGraphSlot(int slot)
{
    shiftGraphPending(slot + 1, -1);
    draft_.graphColors.removeAt(slot);
    if (draft_.graphColors.isEmpty())
        current_row_id_ = kNoGraphsRowId;
    else
        current_row_id_ = kGraphRowBase + static_cast<int>(qMin<qsizetype>(slot, draft_.graphColors.size() - 1));
    rebuildTree();
}

void ThemeColorEditor::themeChanged()
{
    resolveBoth(base_, base_resolved_);
    recompute();
    refreshRows();
    updateDetail(false);
}

QString ThemeColorEditor::editedMarkHtml()
{
    return QStringLiteral(" <b style=\"color: %1;\">%2</b>")
            .arg(themeColor(ThemeManager::AccentInfo).name(), tr("edited").toHtmlEscaped());
}

QString ThemeColorEditor::derivedText(ThemeManager::ThemeToken token) const
{
    const char *source = sources_.value(token, nullptr);
    return source ? QCoreApplication::translate("ThemeTokenHandler", source) : QString();
}

QString ThemeColorEditor::autoValueText(const QColor &shown) const
{
    return shown.isValid() ? tr("auto %1").arg(ThemeWriter::colorText(shown)) : tr("auto row background");
}

QString ThemeColorEditor::chooseTitle(const Row &row, int side)
{
    return tr("Choose %1 (%2)").arg(row.path, side ? tr("Dark") : tr("Light"));
}
