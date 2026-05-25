/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef UI_QT_EXTCAP_ARGUMENT_H_
#define UI_QT_EXTCAP_ARGUMENT_H_

#include <QObject>
#include <QWidget>
#include <QLabel>
#include <QVariant>
#include <QList>
#include <QLineEdit>
#include <QComboBox>
#include <QButtonGroup>
#include <QCheckBox>
#include <QDateTime>

#include <extcap_parser.h>

#define EXTCAP_GUI_BLANK_LABEL "QLabel { color : ; }"
#define EXTCAP_GUI_ERROR_LABEL "QLabel { color : red; }"

class ExtcapValue;

typedef QList<ExtcapValue> ExtcapValueList;

/**
 * @brief Represents a single value option for an extcap argument.
 */
class ExtcapValue
{
public:
    /**
     * @brief Constructs a new ExtcapValue.
     * @param value The display value.
     * @param call The string used to call this value.
     * @param enabled True if this value is enabled.
     * @param isDefault True if this value is the default.
     */
    ExtcapValue(QString value, QString call, bool enabled, bool isDefault) :
        _value(value), _call(call), _enabled(enabled),
        _isDefault(isDefault), _depth(0) {}

    /**
     * @brief Destroys the ExtcapValue.
     */
    virtual ~ExtcapValue();

    /**
     * @brief Sets the child values for this value.
     * @param children The list of child values to set.
     */
    void setChildren(ExtcapValueList children);

    /**
     * @brief Retrieves the child values.
     * @return The list of child values, or an empty list if none.
     */
    ExtcapValueList children()
    {
        if (_children.length() == 0)
            return ExtcapValueList();
        return _children;
    }

    /**
     * @brief Retrieves the display value.
     * @return The display value string.
     */
    QString value() const { return _value; }

    /**
     * @brief Retrieves the call string.
     * @return The call string.
     */
    const QString call() const { return _call; }

    /**
     * @brief Checks if the value is enabled.
     * @return True if enabled, false otherwise.
     */
    bool enabled() const { return _enabled; }

    /**
     * @brief Checks if the value is the default.
     * @return True if it is the default value, false otherwise.
     */
    bool isDefault() const { return _isDefault; }

    /**
     * @brief Retrieves the hierarchical depth of this value.
     * @return The depth integer.
     */
    int depth() { return _depth; }

private:
    /** The display value string. */
    QString _value;

    /** The string used to invoke this value. */
    QString _call;

    /** Flag indicating whether the value is enabled. */
    bool _enabled;

    /** Flag indicating whether this is the default value. */
    bool _isDefault;

    /** The hierarchical depth of the value. */
    int _depth;

    /** The list of child values. */
    ExtcapValueList _children;
};


/**
 * @brief Base class representing a command line argument for an extcap utility.
 */
class ExtcapArgument: public QObject
{
    Q_OBJECT

public:
    /**
     * @brief Constructs an empty ExtcapArgument.
     * @param parent The parent QObject, defaults to Q_NULLPTR.
     */
    ExtcapArgument(QObject *parent = Q_NULLPTR);

    /**
     * @brief Constructs an ExtcapArgument from a core extcap_arg structure.
     * @param argument Pointer to the core extcap_arg.
     * @param parent The parent QObject, defaults to Q_NULLPTR.
     */
    ExtcapArgument(extcap_arg * argument, QObject *parent = Q_NULLPTR);

    /**
     * @brief Copy constructor for ExtcapArgument.
     * @param obj The ExtcapArgument to copy from.
     */
    ExtcapArgument(const ExtcapArgument &obj);

    /**
     * @brief Destroys the ExtcapArgument.
     */
    virtual ~ExtcapArgument();

    /**
     * @brief Creates a label widget for this argument.
     * @param parent The parent widget for the label.
     * @return A pointer to the created label widget.
     */
    virtual QWidget * createLabel(QWidget * parent = 0);

    /**
     * @brief Creates an editor widget for this argument.
     * @param parent The parent widget for the editor.
     * @return A pointer to the created editor widget.
     */
    virtual QWidget * createEditor(QWidget * parent = 0);

    /**
     * @brief Retrieves the underlying extcap_arg structure.
     * @return Pointer to the extcap_arg.
     */
    virtual extcap_arg * argument() { return _argument; }

    /**
     * @brief Retrieves the call string for this argument.
     * @return The call string.
     */
    virtual QString call();

    /**
     * @brief Retrieves the current value of the argument.
     * @return The value string.
     */
    virtual QString value();

    /**
     * @brief Retrieves the default value of the argument.
     * @return The default value string.
     */
    virtual QString defaultValue();

    /**
     * @brief Checks if the argument currently holds its default value.
     * @return True if it holds the default value, false otherwise.
     */
    bool isDefault();

    /**
     * @brief Checks if the current state of the argument is valid.
     * @return True if valid, false otherwise.
     */
    virtual bool isValid();

    /**
     * @brief Checks if the argument is required.
     * @return True if required, false otherwise.
     */
    bool isRequired();

    /**
     * @brief Checks if the argument provides sufficient information on its own.
     * @return True if sufficient, false otherwise.
     */
    bool isSufficient();

    /**
     * @brief Reloads the argument data.
     * @return True if successful, false otherwise.
     */
    bool reload();

    /**
     * @brief Generates a preference key for this argument.
     * @param device_name The extcap device name.
     * @param option_name The extcap option name.
     * @param option_value The extcap option value.
     * @return The preference key string.
     */
    QString prefKey(const QString & device_name,
        const QString & option_name, const QString & option_value);

    /**
     * @brief Retrieves the preference value for this argument.
     * @return The preference value string.
     */
    virtual QString prefValue();

    /**
     * @brief Resets the argument to its initial value.
     */
    void resetValue();

    /**
     * @brief Retrieves the group name this argument belongs to.
     * @return The group name string.
     */
    virtual QString group() const;

    /**
     * @brief Retrieves the argument number.
     * @return The argument number.
     */
    virtual int argNr() const;

    /**
     * @brief Factory method to create an appropriate ExtcapArgument subclass.
     * @param argument Pointer to the core extcap_arg.
     * @param parent The parent QObject.
     * @return A pointer to the newly created ExtcapArgument.
     */
    static ExtcapArgument * create(extcap_arg * argument = Q_NULLPTR, QObject * parent = Q_NULLPTR);

    /**
     * @brief Checks if setting a default value is supported by this argument type.
     * @return True if supported, false otherwise.
     */
    virtual bool isSetDefaultValueSupported();

public Q_SLOTS:
    /**
     * @brief Slot to set the argument to its default value.
     */
    virtual void setDefaultValue();

    /**
     * @brief Slot to handle boolean value changes.
     * @param val The new boolean value.
     */
    void onBoolChanged(bool val);

    /**
     * @brief Slot to handle integer value changes.
     * @param val The new integer value.
     */
    void onIntChanged(int val);

    /**
     * @brief Slot to handle string value changes.
     * @param val The new string value.
     */
    void onStringChanged(QString val);

Q_SIGNALS:
    /**
     * @brief Signal emitted when the argument's value changes.
     */
    void valueChanged();

protected:

    /**
     * @brief Checks if a file path specified by the argument exists.
     * @return True if the file exists, false otherwise.
     */
    bool fileExists();

    /**
     * @brief Loads the available values for this argument.
     * @param parent The parent hierarchy string.
     * @return A list of loaded ExtcapValue objects.
     */
    ExtcapValueList loadValues(QString parent);

    /**
     * @brief Reloads the values list.
     * @return True if successful, false otherwise.
     */
    bool reloadValues();

    /** The list of available values for this argument. */
    ExtcapValueList values;

    /** Pointer to the core extcap_arg structure. */
    extcap_arg * _argument;

    /** Pointer to the associated label widget. */
    QLabel * _label;

    /** The argument number identifier. */
    int _number;
};


/**
 * @brief Extcap argument representing a text input field.
 */
class ExtArgText : public ExtcapArgument
{
    Q_OBJECT

public:
    /**
     * @brief Constructs an ExtArgText.
     * @param argument Pointer to the core extcap_arg.
     * @param parent The parent QObject.
     */
    ExtArgText(extcap_arg * argument, QObject *parent = Q_NULLPTR);

    /**
     * @brief Creates the text editor widget.
     * @param parent The parent widget for the editor.
     * @return A pointer to the created line edit widget.
     */
    virtual QWidget * createEditor(QWidget * parent) override;

    /**
     * @brief Retrieves the current text value.
     * @return The text string.
     */
    virtual QString value() override;

    /**
     * @brief Checks if the current text value is valid.
     * @return True if valid, false otherwise.
     */
    virtual bool isValid() override;

    /**
     * @brief Checks if setting a default text value is supported.
     * @return True if supported, false otherwise.
     */
    virtual bool isSetDefaultValueSupported() override;

public Q_SLOTS:
    /**
     * @brief Sets the text field to its default value.
     */
    virtual void setDefaultValue() override;

protected:

    /** The line edit widget used for text input. */
    QLineEdit * textBox;
};


/**
 * @brief Extcap argument representing a numeric input field.
 */
class ExtArgNumber : public ExtArgText
{
    Q_OBJECT

public:
    /**
     * @brief Constructs an ExtArgNumber.
     * @param argument Pointer to the core extcap_arg.
     * @param parent The parent QObject.
     */
    ExtArgNumber(extcap_arg * argument, QObject *parent = Q_NULLPTR);

    /**
     * @brief Creates the numeric editor widget.
     * @param parent The parent widget for the editor.
     * @return A pointer to the created widget.
     */
    virtual QWidget * createEditor(QWidget * parent) override;

    /**
     * @brief Retrieves the default numeric value.
     * @return The default value string.
     */
    virtual QString defaultValue() override;
};


/**
 * @brief Extcap argument representing a selection dropdown.
 */
class ExtArgSelector : public ExtcapArgument
{
    Q_OBJECT

public:
    /**
     * @brief Constructs an ExtArgSelector.
     * @param argument Pointer to the core extcap_arg.
     * @param parent The parent QObject.
     */
    ExtArgSelector(extcap_arg * argument, QObject *parent = Q_NULLPTR);

    /**
     * @brief Creates the combobox editor widget.
     * @param parent The parent widget for the editor.
     * @return A pointer to the created combobox widget.
     */
    virtual QWidget * createEditor(QWidget * parent) override;

    /**
     * @brief Retrieves the currently selected value.
     * @return The selected value string.
     */
    virtual QString value() override;

    /**
     * @brief Checks if the current selection is valid.
     * @return True if valid, false otherwise.
     */
    virtual bool isValid() override;

    /**
     * @brief Checks if setting a default selection is supported.
     * @return True if supported, false otherwise.
     */
    virtual bool isSetDefaultValueSupported() override;

public Q_SLOTS:
    /**
     * @brief Sets the dropdown to its default selection.
     */
    virtual void setDefaultValue() override;

protected:
    /** The combobox widget used for selection. */
    QComboBox * boxSelection;

private Q_SLOTS:
    /**
     * @brief Slot triggered to reload the selector items.
     */
    void onReloadTriggered();

};

/**
 * @brief Extcap argument representing an editable selection dropdown.
 */
class ExtArgEditSelector : public ExtArgSelector
{
    Q_OBJECT

public:
    /**
     * @brief Constructs an ExtArgEditSelector.
     * @param argument Pointer to the core extcap_arg.
     * @param parent The parent QObject.
     */
    ExtArgEditSelector(extcap_arg * argument, QObject *parent = Q_NULLPTR);

    /**
     * @brief Creates the editable combobox editor widget.
     * @param parent The parent widget for the editor.
     * @return A pointer to the created editable combobox widget.
     */
    virtual QWidget * createEditor(QWidget * parent) override;

    /**
     * @brief Retrieves the current text or selection value.
     * @return The value string.
     */
    virtual QString value() override;

public Q_SLOTS:
    /**
     * @brief Sets the editable selector to its default value.
     */
    virtual void setDefaultValue() override;
};

/**
 * @brief Extcap argument representing a set of radio buttons.
 */
class ExtArgRadio : public ExtcapArgument
{
    Q_OBJECT

public:
    /**
     * @brief Constructs an ExtArgRadio.
     * @param argument Pointer to the core extcap_arg.
     * @param parent The parent QObject.
     */
    ExtArgRadio(extcap_arg * argument, QObject *parent = Q_NULLPTR);

    /**
     * @brief Destroys the ExtArgRadio.
     */
    virtual ~ExtArgRadio();

    /**
     * @brief Creates the radio button group editor widget.
     * @param parent The parent widget for the editor.
     * @return A pointer to the created widget containing radio buttons.
     */
    virtual QWidget * createEditor(QWidget * parent) override;

    /**
     * @brief Retrieves the value of the currently selected radio button.
     * @return The selected value string.
     */
    virtual QString value() override;

    /**
     * @brief Checks if a valid radio button is selected.
     * @return True if valid, false otherwise.
     */
    virtual bool isValid() override;

    /**
     * @brief Checks if setting a default radio button is supported.
     * @return True if supported, false otherwise.
     */
    virtual bool isSetDefaultValueSupported() override;

public Q_SLOTS:
    /**
     * @brief Selects the default radio button.
     */
    virtual void setDefaultValue() override;

private:

    /** The button group managing the radio buttons. */
    QButtonGroup * selectorGroup;

    /** The list of call strings corresponding to each radio button. */
    QList<QString> * callStrings;
};


/**
 * @brief Extcap argument representing a boolean toggle (checkbox).
 */
class ExtArgBool : public ExtcapArgument
{
    Q_OBJECT

public:
    /**
     * @brief Constructs an ExtArgBool.
     * @param argument Pointer to the core extcap_arg.
     * @param parent The parent QObject.
     */
    ExtArgBool(extcap_arg * argument, QObject *parent = Q_NULLPTR);

    /**
     * @brief Creates the label widget for the boolean argument.
     * @param parent The parent widget.
     * @return A pointer to the created label widget.
     */
    virtual QWidget * createLabel(QWidget * parent) override;

    /**
     * @brief Creates the checkbox editor widget.
     * @param parent The parent widget for the editor.
     * @return A pointer to the created checkbox widget.
     */
    virtual QWidget * createEditor(QWidget * parent) override;

    /**
     * @brief Retrieves the call string based on the boolean state.
     * @return The call string.
     */
    virtual QString call() override;

    /**
     * @brief Retrieves the boolean state as a string.
     * @return "true" or "false" string representation.
     */
    virtual QString value() override;

    /**
     * @brief Checks if the boolean state is valid.
     * @return True if valid, false otherwise.
     */
    virtual bool isValid() override;

    /**
     * @brief Retrieves the default boolean value as a string.
     * @return The default boolean string representation.
     */
    virtual QString defaultValue() override;

    /**
     * @brief Retrieves the preference value for the boolean argument.
     * @return The preference value string.
     */
    virtual QString prefValue() override;

    /**
     * @brief Checks if setting a default boolean value is supported.
     * @return True if supported, false otherwise.
     */
    virtual bool isSetDefaultValueSupported() override;

public Q_SLOTS:
    /**
     * @brief Sets the checkbox to its default state.
     */
    virtual void setDefaultValue() override;

private:

    /** The checkbox widget representing the boolean toggle. */
    QCheckBox * boolBox;

    /**
     * @brief Retrieves the default boolean state.
     * @return The default boolean value.
     */
    bool defaultBool();
};


/**
 * @brief Extcap argument representing a timestamp input.
 */
class ExtArgTimestamp : public ExtcapArgument
{
    Q_OBJECT

public:
    /**
     * @brief Constructs an ExtArgTimestamp.
     * @param argument Pointer to the core extcap_arg.
     * @param parent The parent QObject.
     */
    ExtArgTimestamp(extcap_arg * argument, QObject *parent = Q_NULLPTR);

    /**
     * @brief Creates the datetime editor widget.
     * @param parent The parent widget for the editor.
     * @return A pointer to the created datetime widget.
     */
    virtual QWidget * createEditor(QWidget * parent) override;

    /**
     * @brief Checks if the timestamp input is valid.
     * @return True if valid, false otherwise.
     */
    virtual bool isValid() override;

    /**
     * @brief Retrieves the default timestamp value.
     * @return The default timestamp string.
     */
    virtual QString defaultValue() override;

    /**
     * @brief Retrieves the current timestamp value.
     * @return The current timestamp string.
     */
    virtual QString value() override;

    /**
     * @brief Retrieves the preference value for the timestamp.
     * @return The preference value string.
     */
    virtual QString prefValue() override;

    /**
     * @brief Checks if setting a default timestamp is supported.
     * @return True if supported, false otherwise.
     */
    virtual bool isSetDefaultValueSupported() override;

public Q_SLOTS:
    /**
     * @brief Sets the timestamp to its default value.
     */
    virtual void setDefaultValue() override;

private Q_SLOTS:
    /**
     * @brief Slot triggered when the datetime in the editor changes.
     * @param datetime The new datetime value.
     */
    void onDateTimeChanged(QDateTime datetime);

private:
    /** The active datetime value. */
    QDateTime ts;

    /** The datetime edit widget. */
    QDateTimeEdit *tsBox;
};
#endif /* UI_QT_EXTCAP_ARGUMENT_H_ */
