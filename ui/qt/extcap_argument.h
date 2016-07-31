/* extcap_argument.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
        _isDefault(isDefault), _depth(0) {};
    virtual ~ExtcapValue();

    void setChildren(ExtcapValueList children);
    ExtcapValueList children()
    {
        if ( _children.length() == 0 )
            return ExtcapValueList();
        return _children;
    };

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
	ExtcapArgument(QObject *parent=0);
    ExtcapArgument(extcap_arg * argument, QObject *parent=0);
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

    QString prefKey(const QString & device_name);
    virtual QString prefValue();

    void resetValue();

    static ExtcapArgument * create(extcap_arg * argument = 0);

Q_SIGNALS:
    void valueChanged();

protected:

    bool fileExists();

    ExtcapValueList loadValues(QString parent);

    ExtcapValueList values;

    extcap_arg * _argument;
    QLabel * _label;

    const QString label_style;

private Q_SLOTS:

    void onStringChanged(QString);
    void onIntChanged(int);
    void onBoolChanged(bool);

};

Q_DECLARE_METATYPE(ExtcapArgument)
Q_DECLARE_METATYPE(ExtcapArgument *)

class ExtArgText : public ExtcapArgument
{

public:
    ExtArgText(extcap_arg * argument);

    virtual QWidget * createEditor(QWidget * parent);
    virtual QString value();
    virtual bool isValid();

protected:

    QLineEdit * textBox;
};

class ExtArgNumber : public ExtArgText
{
public:
    ExtArgNumber(extcap_arg * argument);

    virtual QWidget * createEditor(QWidget * parent);
    virtual QString defaultValue();
};

class ExtArgSelector : public ExtcapArgument
{
public:
    ExtArgSelector(extcap_arg * argument);

    virtual QWidget * createEditor(QWidget * parent);
    virtual QString value();
    virtual bool isValid();

private:

    QComboBox * boxSelection;
};

class ExtArgRadio : public ExtcapArgument
{
public:
    ExtArgRadio(extcap_arg * argument);

    virtual QWidget * createEditor(QWidget * parent);
    virtual QString value();
    virtual bool isValid();

private:

    QButtonGroup * selectorGroup;
    QList<QString> * callStrings;
};

class ExtArgBool : public ExtcapArgument
{
public:
    ExtArgBool(extcap_arg * argument);

    virtual QWidget * createLabel(QWidget * parent);
    virtual QWidget * createEditor(QWidget * parent);

    virtual QString call();
    virtual QString value();
    virtual bool isValid();
    virtual QString defaultValue();
    virtual QString prefValue();

private:

    QCheckBox * boolBox;

    bool defaultBool();
};

#endif /* UI_QT_EXTCAP_ARGUMENT_H_ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
