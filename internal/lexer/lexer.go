package lexer

import (
	"github.com/nsecho/gxpc/internal/token"
	"unicode"
)

func New(input string) *Lexer {
	l := &Lexer{input: input}
	l.readChar()
	return l
}

type Lexer struct {
	input        string
	position     int
	readPosition int
	ch           byte
}

func (l *Lexer) NextToken() token.Token {
	var tok token.Token
	l.skipWhitespace()

	switch l.ch {
	case '=':
		if l.peekChar() == '>' {
			l.readChar()
			tok.Literal = "=>"
			tok.TokenType = token.DEF
		} else {
			tok = newToken(token.EQ, l.ch)
		}
	case '>':
		tok = newToken(token.GT, l.ch)
	case '{':
		tok = newToken(token.LBRACE, l.ch)
	case '}':
		tok = newToken(token.RBRACE, l.ch)
	case ':':
		tok = newToken(token.COLON, l.ch)
	case ',':
		tok = newToken(token.COMMA, l.ch)
	case '"':
		tok.TokenType = token.STRING
		tok.Literal = l.readString()
	case 0:
		tok = newToken(token.EOF, 0)
	default:
		if unicode.IsLetter(rune(l.ch)) {
			tok.Literal = l.readIdentifier()
			tok.TokenType = token.LookupIdent(tok.Literal)
			return tok
		} else if unicode.IsNumber(rune(l.ch)) {
			tok.Literal = l.readNumber()
			tok.TokenType = token.INT
			return tok
		} else {
			tok = newToken(token.ILLEGAL, l.ch)
		}
	}

	l.readChar()
	return tok
}

func (l *Lexer) readNumber() string {
	pos := l.position
	for unicode.IsNumber(rune(l.ch)) {
		l.readChar()
	}
	return l.input[pos:l.position]
}

func (l *Lexer) readString() string {
	pos := l.position + 1
	for {
		l.readChar()
		if l.ch == '"' || l.ch == 0 {
			break
		}
	}
	return l.input[pos:l.position]
}

func (l *Lexer) readIdentifier() string {
	pos := l.position
	for unicode.IsLetter(rune(l.ch)) || l.ch == '_' {
		l.readChar()
	}
	return l.input[pos:l.position]
}

func (l *Lexer) readChar() {
	if l.readPosition >= len(l.input) {
		l.ch = 0
	} else {
		l.ch = l.input[l.readPosition]
	}
	l.position = l.readPosition
	l.readPosition += 1
}

func (l *Lexer) skipWhitespace() {
	for unicode.IsSpace(rune(l.ch)) {
		l.readChar()
	}
}

func (l *Lexer) atEOF() bool {
	return l.readPosition >= len(l.input)
}

func (l *Lexer) peekChar() byte {
	if l.atEOF() {
		return 0
	}

	return l.input[l.readPosition]
}

func newToken(t token.Type, literal byte) token.Token {
	return token.Token{
		TokenType: t,
		Literal:   string(literal),
	}
}
