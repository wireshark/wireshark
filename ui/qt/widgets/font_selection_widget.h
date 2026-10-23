/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FONT_SELECTION_WIDGET_H
#define FONT_SELECTION_WIDGET_H

#include <QFont>
#include <QString>
#include <QWidget>

namespace Ui {
class FontSelectionWidget;
}

/**
 * @brief Font selector with family, style and size lists, effects and a sample.
 *
 * The family list is built lazily, once per process, on the first show of any
 * selector; until then it holds only the current family and the style and size
 * lists stay empty. Setters never emit changed(); only user edits do. Every
 * field (family, style, size, strikeout, underline) the user did not edit is
 * kept exactly as set, so opening and closing a dialog does not rewrite a
 * stored font.
 */
class FontSelectionWidget : public QWidget
{
    Q_OBJECT

public:
    /** @brief Which families the family list offers. */
    enum class FamilyFilter {
        AllFamilies,    ///< every installed family
        FixedPitchOnly  ///< fixed-pitch families only
    };

    /** @brief What an empty family resolves to. */
    enum class FontClass {
        Regular,    ///< the system general font
        Monospace   ///< the system fixed font, guaranteed fixed-pitch
    };

    /** @brief Optional parts of the selector. */
    enum Feature {
        StyleFeature = 0x1,         ///< the style label and list
        EffectsFeature = 0x2,       ///< the Effects group (strikeout, underline)
        FamilyFilterFeature = 0x4   ///< the "Show only monospaced fonts" checkbox
    };
    Q_DECLARE_FLAGS(Features, Feature)

    /** @brief The edited value: family and point size. */
    struct Selection {
        QString family;       ///< empty: platform default (only meaningful with defaultAllowed)
        qreal pointSize = 0;  ///< <= 0: default size (only meaningful with defaultAllowed)

        /** @brief Compare family and point size. */
        bool operator==(const Selection &other) const;
        /** @brief Negation of operator==. */
        bool operator!=(const Selection &other) const { return !(*this == other); }
    };

    /**
     * @brief Construct a FontSelectionWidget.
     * @param parent The parent widget; may be nullptr.
     */
    explicit FontSelectionWidget(QWidget *parent = nullptr);

    /** @brief Destroy the widget and its UI form. */
    ~FontSelectionWidget();

    /**
     * @brief Choose which families are offered. The default is AllFamilies.
     *
     * Also sets the "Show only monospaced fonts" checkbox. Only the list
     * changes; the selected family stays listed and changed() is not emitted.
     *
     * @param filter The family filter.
     */
    void setFamilyFilter(FamilyFilter filter);

    /** @brief Return the active family filter. */
    FamilyFilter familyFilter() const;

    /**
     * @brief Choose what an empty family resolves to. The default is Regular.
     * @param fontClass The font class.
     */
    void setFontClass(FontClass fontClass);

    /** @brief Return the font class. */
    FontClass fontClass() const;

    /**
     * @brief Show or hide the optional parts. The default is all features.
     * @param features The parts to show.
     */
    void setFeatures(Features features);

    /** @brief Return the shown optional parts. */
    Features features() const;

    /**
     * @brief Allow the "no explicit font" state.
     *
     * When allowed, the family list gets a "(Platform default)" entry and the
     * size spin box shows "Default" at its minimum. Off by default.
     *
     * @param allowed true to allow the default state.
     */
    void setDefaultAllowed(bool allowed);

    /** @brief Return whether the default state is allowed. */
    bool defaultAllowed() const;

    /**
     * @brief Set the value from a Selection without emitting changed().
     * @param sel The family and point size to show.
     */
    void setSelection(const Selection &sel);

    /** @brief Return the current Selection. */
    Selection selection() const;

    /**
     * @brief Set the value from a QFont without emitting changed().
     *
     * All attributes of @p font are kept by selectedFont() until the user
     * edits the field they belong to.
     *
     * @param font The font to show.
     */
    void setSelectedFont(const QFont &font);

    /**
     * @brief Return the edited font.
     *
     * This is the font given to setSelectedFont() (or built by setSelection()),
     * with family, style, size, strikeout and underline replaced only once the
     * user edited them.
     */
    QFont selectedFont() const;

    /**
     * @brief Return the font the sample is drawn with.
     *
     * For FontClass::Monospace this is the font FontManager applies for the
     * monospace font preference, so it may differ from selectedFont() when the
     * family is not installed.
     */
    QFont resolvedFont() const;

    /**
     * @brief Replace the sample text.
     * @param text The sample text.
     */
    void setSampleText(const QString &text);

signals:
    /** @brief Emitted when the user changes family, style, size or an effect. */
    void changed();

protected:
    /** @brief Fill the lists on first show and refresh the sample. */
    void showEvent(QShowEvent *event) override;

private:
    QString lookupFamily() const;
    void fillFamilyList();
    void applyFamilyTextFilter();
    void fillStyleList();
    void fillSizeList();
    void updateSizeSpin();
    void selectSizeRow();
    void updateEffects();
    void resetTo(const QFont &font, const Selection &sel);
    void refreshAll();
    void refreshSample();
    void familySelectionChanged();
    void monospaceToggled(bool checked);
    void styleSelectionChanged();
    void sizeSelectionChanged();
    void sizeValueChanged(double value);
    void strikeOutToggled(bool checked);
    void underlineToggled(bool checked);

    Ui::FontSelectionWidget *ui;
    QFont base_;
    Selection sel_;
    QString style_;
    bool strikeOut_ = false;
    bool underline_ = false;
    bool familyEdited_ = false;
    bool styleEdited_ = false;
    bool sizeEdited_ = false;
    bool strikeOutEdited_ = false;
    bool underlineEdited_ = false;
    FamilyFilter filter_ = FamilyFilter::AllFamilies;
    FontClass fontClass_ = FontClass::Regular;
    Features features_ = Features(StyleFeature | EffectsFeature | FamilyFilterFeature);
    bool defaultAllowed_ = false;
    int filledGeneration_ = -1;
    QString sampleText_;
};

Q_DECLARE_OPERATORS_FOR_FLAGS(FontSelectionWidget::Features)

#endif // FONT_SELECTION_WIDGET_H
