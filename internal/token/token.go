package token

type Type string

const (
	ILLEGAL Type = "ILLEGAL"
	EOF          = "EOF"

	IDENT = "IDENT"

	EQ = "="
	GT = ">"

	DEF = "=>"

	FN = "FN"
)

var keywords = map[string]Type{
	"fn": FN,
}

func LookupIdent(ident string) Type {
	if tok, ok := keywords[ident]; ok {
		return tok
	}
	return IDENT
}

type Token struct {
	TokenType Type
	Literal   string
}
