/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef UI_QT_ADDITIONAL_TOOLBAR_H_
#define UI_QT_ADDITIONAL_TOOLBAR_H_

#include <ui/plugins/include/plugin_if.h>

#include <QToolBar>
#include <QWidgetAction>

/**
 * @brief Class for all display widgets.
 *
 * Inherits QWidgetAction, otherwise the extension popup might not work for the toolbar
 */
class AdditionalToolbarWidgetAction : public QWidgetAction
{
    Q_OBJECT

public:
    /**
     * @brief Construct an empty AdditionalToolbarWidgetAction.
     * @param parent The parent QObject.
     */
    AdditionalToolbarWidgetAction(QObject *parent = 0);

    /**
     * @brief Construct an AdditionalToolbarWidgetAction for a toolbar item.
     * @param item   The external toolbar item descriptor whose type and
     *               metadata determine the widget that will be created.
     * @param parent The parent QObject.
     */
    AdditionalToolbarWidgetAction(ext_toolbar_t *item, QObject *parent = 0);

    /**
     * @brief Copy constructor.
     * @param copy_object The object to copy.
     */
    AdditionalToolbarWidgetAction(const AdditionalToolbarWidgetAction &copy_object);

    /**
     * @brief Destructor.
     */
    ~AdditionalToolbarWidgetAction();

protected:
    /**
     * @brief Create the appropriate widget for this action's toolbar item.
     * @param parent The parent widget supplied by the toolbar.
     * @return The newly created widget, or nullptr if the item type is
     *         unknown.
     */
    virtual QWidget *createWidget(QWidget *parent) override;

    /** @brief QObject property name used to attach the ext_toolbar_t pointer to widgets. */
    static const char *propertyName;

private:
    ext_toolbar_t *toolbar_item; /**< The external toolbar item descriptor for this action. */

    /**
     * @brief Create a push-button widget for @p item.
     * @param item   The toolbar item descriptor.
     * @param parent The parent widget.
     * @return The created QPushButton wrapped in a label frame.
     */
    QWidget *createButton(ext_toolbar_t *item, QWidget *parent);

    /**
     * @brief Create a checkbox widget for @p item.
     * @param item   The toolbar item descriptor.
     * @param parent The parent widget.
     * @return The created QCheckBox wrapped in a label frame.
     */
    QWidget *createBoolean(ext_toolbar_t *item, QWidget *parent);

    /**
     * @brief Create a text-entry widget for @p item.
     * @param item   The toolbar item descriptor.
     * @param parent The parent widget.
     * @return The created QLineEdit wrapped in a label frame.
     */
    QWidget *createTextEditor(ext_toolbar_t *item, QWidget *parent);

    /**
     * @brief Create a drop-down selector widget for @p item.
     * @param item   The toolbar item descriptor.
     * @param parent The parent widget.
     * @return The created QComboBox wrapped in a label frame.
     */
    QWidget *createSelector(ext_toolbar_t *item, QWidget *parent);

    /**
     * @brief Wrap a widget in a labelled frame with the item's display name.
     * @param item   The toolbar item whose label text is used.
     * @param parent The parent widget for the frame.
     * @return A QFrame containing a label and a placeholder for the child widget.
     */
    QWidget *createLabelFrame(ext_toolbar_t *item, QWidget *parent);

    /**
     * @brief Retrieve the ext_toolbar_t pointer attached to a QObject.
     *
     * @param object The QObject whose property should be read.
     * @return The attached @c ext_toolbar_t pointer, or nullptr if absent.
     */
    ext_toolbar_t *extractToolbarItemFromObject(QObject *object);

private slots:
    /** @brief Forward a button click to the ext_toolbar_t callback. */
    void onButtonClicked();

#if QT_VERSION >= QT_VERSION_CHECK(6, 7, 0)
    /**
     * @brief Forward a checkbox state change to the ext_toolbar_t callback (Qt 6.7+).
     * @param state The new check state.
     */
    void onCheckBoxChecked(Qt::CheckState state);
#else
    /**
     * @brief Forward a checkbox state change to the ext_toolbar_t callback (pre-Qt 6.7).
     * @param checkState The new check state as an integer (Qt::CheckState value).
     */
    void onCheckBoxChecked(int checkState);
#endif

    /** @brief Forward the current text-editor contents to the ext_toolbar_t callback. */
    void sendTextToCallback();

    /**
     * @brief Forward a selector index change to the ext_toolbar_t callback.
     * @param idx The index of the newly selected item in the combo box.
     */
    void onSelectionInWidgetChanged(int idx);

    /**
     * @brief Enable or disable this action's widget based on capture state.
     * @param activeCaptures Non-zero when a capture is active; zero when idle.
     */
    void captureActive(int activeCaptures);
};


/**
 * @brief A QToolBar populated from an ext_toolbar_t plugin toolbar descriptor.
 */
class AdditionalToolBar : public QToolBar
{
    Q_OBJECT

public:
    /**
     * @brief Construct an AdditionalToolBar from an ext_toolbar_t descriptor.
     * @param toolbar The external toolbar descriptor whose items are added.
     * @param parent  The parent widget.
     */
    AdditionalToolBar(ext_toolbar_t *toolbar, QWidget *parent = 0);

    /**
     * @brief Destroy the AdditionalToolBar.
     */
    virtual ~AdditionalToolBar();

    /**
     * @brief Factory method: create an AdditionalToolBar if @p toolbar is valid.
     *
     * @param parent  The parent widget.
     * @param toolbar The external toolbar descriptor to use.
     * @return A new AdditionalToolBar, or nullptr if @p toolbar is invalid
     *         or has no items.
     */
    static AdditionalToolBar *create(QWidget *parent, ext_toolbar_t *toolbar);

    /**
     * @brief Return the display name of this toolbar.
     * @return The toolbar's name string from the ext_toolbar_t descriptor,
     *         for use in the View → Toolbars menu.
     */
    QString menuName();

private:
    ext_toolbar_t *toolbar; /**< The external toolbar descriptor this bar was created from. */
};

#endif /* UI_QT_ADDITIONAL_TOOLBAR_H_ */
