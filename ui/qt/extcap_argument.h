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

class ExtcapValue
{
public:
    ExtcapValue(QString value, QString call, bool enabled, bool isDefault) :
        _value(value), _call(call), _enabled(enabled),
        _isDefault(isDefault), _depth(0) {}
    virtual ~ExtcapValue();

    void setChildren(ExtcapValueList children);
    ExtcapValueList children()
    {
        if (_children.length() == 0)
            return ExtcapValueList();
        return _children;
    }

    QString value() const { return _value; }
    const QString call() const { return _call; }
    bool enabled() const { return _enabled; }
    bool isDefault() const { return _isDefault; }

    int depth() { return _depth; }

private:
    QString _value;
    QString _call;

    bool _enabled;
    bool _isDefault;

    int _depth;

    ExtcapValueList _children;
};



class ExtcapArgument: public QObject
{
    Q_OBJECT

public:
    ExtcapArgument(QObject *parent = Q_NULLPTR);
    ExtcapArgument(extcap_arg * argument, QObject *parent = Q_NULLPTR);
    ExtcapArgument(const ExtcapArgument &obj);
    virtual ~ExtcapArgument();

    virtual QWidget * createLabel(QWidget * parent = 0);
    virtual QWidget * createEditor(QWidget * parent = 0);

    virtual extcap_arg * argument() { return _argument; }
    virtual QString call();
    virtual QString value();
    virtual QString defaultValue();

    bool isDefault();
    virtual bool isValid();
    bool isRequired();
    bool reload();

    QString prefKey(const QString & device_name);
    virtual QString prefValue();

    void resetValue();

    virtual QString group() const;
    virtual int argNr() const;

    static ExtcapArgument * create(extcap_arg * argument = Q_NULLPTR, QObject * parent = Q_NULLPTR);
    virtual bool isSetDefaultValueSupported();

public Q_SLOTS:
    virtual void setDefaultValue();

Q_SIGNALS:
    void valueChanged();

protected:

    bool fileExists();

    ExtcapValueList loadValues(QString parent);
    bool reloadValues();

    ExtcapValueList values;

    extcap_arg * _argument;
    QLabel * _label;
    int _number;

    const QString label_style;

private Q_SLOTS:

    void onStringChanged(QString);
    void onIntChanged(int);
    void onBoolChanged(bool);

};



class ExtArgText : public ExtcapArgument
{
    Q_OBJECT

public:
    ExtArgText(extcap_arg * argument, QObject *parent = Q_NULLPTR);

    virtual QWidget * createEditor(QWidget * parent);
    virtual QString value();
    virtual bool isValid();
    virtual bool isSetDefaultValueSupported();

public Q_SLOTS:
    virtual void setDefaultValue();

protected:

    QLineEdit * textBox;
};



class ExtArgNumber : public ExtArgText
{
    Q_OBJECT

public:
    ExtArgNumber(extcap_arg * argument, QObject *parent = Q_NULLPTR);

    virtual QWidget * createEditor(QWidget * parent);
    virtual QString defaultValue();
};



class ExtArgSelector : public ExtcapArgument
{
    Q_OBJECT

public:
    ExtArgSelector(extcap_arg * argument, QObject *parent = Q_NULLPTR);

    virtual QWidget * createEditor(QWidget * parent);
    virtual QString value();
    virtual bool isValid();
    virtual bool isSetDefaultValueSupported();

public Q_SLOTS:
    virtual void setDefaultValue();

protected:
    QComboBox * boxSelection;

private Q_SLOTS:
    void onReloadTriggered();

};


class ExtArgEditSelector : public ExtArgSelector
{
    Q_OBJECT

public:
    ExtArgEditSelector(extcap_arg * argument, QObject *parent = Q_NULLPTR);
    virtual QWidget * createEditor(QWidget * parent);
    virtual QString value();

public Q_SLOTS:
    virtual void setDefaultValue();
};


class ExtArgRadio : public ExtcapArgument
{
    Q_OBJECT

public:
    ExtArgRadio(extcap_arg * argument, QObject *parent = Q_NULLPTR);
    virtual ~ExtArgRadio();

    virtual QWidget * createEditor(QWidget * parent);
    virtual QString value();
    virtual bool isValid();
    virtual bool isSetDefaultValueSupported();

public Q_SLOTS:
    virtual void setDefaultValue();

private:

    QButtonGroup * selectorGroup;
    QList<QString> * callStrings;
};



class ExtArgBool : public ExtcapArgument
{
    Q_OBJECT

public:
    ExtArgBool(extcap_arg * argument, QObject *parent = Q_NULLPTR);

    virtual QWidget * createLabel(QWidget * parent);
    virtual QWidget * createEditor(QWidget * parent);

    virtual QString call();
    virtual QString value();
    virtual bool isValid();
    virtual QString defaultValue();
    virtual QString prefValue();
    virtual bool isSetDefaultValueSupported();

public Q_SLOTS:
    virtual void setDefaultValue();

private:

    QCheckBox * boolBox;

    bool defaultBool();
};



class ExtArgTimestamp : public ExtcapArgument
{
    Q_OBJECT

public:
    ExtArgTimestamp(extcap_arg * argument, QObject *parent = Q_NULLPTR);
    virtual QWidget * createEditor(QWidget * parent);

    virtual bool isValid();
    virtual QString defaultValue();
    virtual QString value();
    virtual QString prefValue();
    virtual bool isSetDefaultValueSupported();

public Q_SLOTS:
    virtual void setDefaultValue();

private Q_SLOTS:
    void onDateTimeChanged(QDateTime);

private:
    QDateTime ts;
    QDateTimeEdit *tsBox;
};

#endif /* UI_QT_EXTCAP_ARGUMENT_H_ */
