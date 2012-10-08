#ifndef SYNTAX_LINE_EDIT_H
#define SYNTAX_LINE_EDIT_H

#include <QLineEdit>

class SyntaxLineEdit : public QLineEdit
{
    Q_OBJECT
    Q_PROPERTY(SyntaxState syntaxState READ syntaxState)
    Q_ENUMS(SyntaxState)
public:
    explicit SyntaxLineEdit(QWidget *parent = 0);
    enum SyntaxState { Empty, Invalid, Deprecated, Valid };

    SyntaxState syntaxState() const { return syntax_state_; }
    void setSyntaxState(SyntaxState state = Empty);
    QString styleSheet() const;

private:
    SyntaxState syntax_state_;
    QString style_sheet_;
    QString state_style_sheet_;

signals:
    
public slots:
    void setStyleSheet(const QString &style_sheet);
};

#endif // SYNTAX_LINE_EDIT_H
