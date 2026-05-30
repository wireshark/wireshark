/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CAPTURE_CARD_WIDGET_H
#define CAPTURE_CARD_WIDGET_H

#include <QFrame>

class InterfaceFrame;

namespace Ui {
class CaptureCardWidget;
}

/**
 * @brief A widget representing a capture card in the UI, providing interface selection and filtering capabilities.
 */
class CaptureCardWidget : public QFrame {
    Q_OBJECT
public:
    /**
     * @brief Constructs a new CaptureCardWidget.
     * @param parent The parent widget, defaults to nullptr.
     */
    explicit CaptureCardWidget(QWidget *parent = nullptr);

    /**
     * @brief Destroys the CaptureCardWidget.
     */
    ~CaptureCardWidget();

    /**
     * @brief Retrieves the interface frame associated with this capture card.
     * @return A pointer to the InterfaceFrame.
     */
    InterfaceFrame *interfaceFrame();

    /**
     * @brief Gets the current capture filter.
     * @return The capture filter string.
     */
    const QString captureFilter();

    /**
     * @brief Sets the current capture filter.
     * @param filter The filter string to apply.
     */
    void setCaptureFilter(const QString &filter);

    /**
     * @brief Sets the text of the capture filter input without necessarily applying it.
     * @param filter The filter string to set in the UI.
     */
    void setCaptureFilterText(const QString &filter);

public slots:
    /**
     * @brief Slot triggered when an interface is selected.
     */
    void interfaceSelected();

signals:
    /**
     * @brief Signal emitted to start a capture.
     * @param ifaces The list of interfaces to capture on.
     */
    void startCapture(QStringList ifaces);

    /**
     * @brief Signal emitted when the syntax validity of the capture filter changes.
     * @param valid True if the syntax is valid, false otherwise.
     */
    void captureFilterSyntaxChanged(bool valid);

    /**
     * @brief Signal emitted to show extcap options for a specific device.
     * @param device_name The name of the extcap device.
     * @param startCaptureOnClose Whether to start the capture automatically when the options dialog closes.
     */
    void showExtcapOptions(QString device_name, bool startCaptureOnClose);

    /**
     * @brief Signal emitted when the list or state of available interfaces changes.
     */
    void interfacesChanged();

protected:
    /**
     * @brief Handles general events for the widget.
     * @param event The event to handle.
     * @return True if the event was handled, false otherwise.
     */
    bool event(QEvent *event) override;

    /**
     * @brief Handles resize events for the widget.
     * @param event The resize event.
     */
    void resizeEvent(QResizeEvent *event) override;

private:
    /** Pointer to the generated UI elements. */
    Ui::CaptureCardWidget *ui_;

    /**
     * @brief Updates the visibility of the capture filter row based on current state.
     */
    void updateFilterRowVisibility();

    /**
     * @brief Picks the most verbose interface-type button label that fits the
     *        available width, falling back to terser variants (and finally
     *        eliding) on narrow windows so it can never overrun the capture
     *        filter combo. The full text is kept as the button's tooltip.
     */
    void updateInterfaceTypeButton();

    /** Interface-type button labels, ordered most verbose to most terse. */
    QStringList interfaceTypeButtonTexts_;

private slots:
    /**
     * @brief Slot triggered when the application has been fully initialized.
     */
    void appInitialized();

    /**
     * @brief Slot triggered when the global interface list changes.
     */
    void interfaceListChanged();

    /**
     * @brief Slot triggered when the user edits the capture filter text.
     * @param filter The newly edited filter text.
     */
    void captureFilterTextEdited(const QString &filter);

    /**
     * @brief Slot triggered when a capture process is starting.
     */
    void captureStarting();
};

#endif // CAPTURE_CARD_WIDGET_H
