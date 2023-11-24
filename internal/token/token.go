package token

type Type string

const (
	ILLEGAL Type = "ILLEGAL"
	EOF          = "EOF"

	STRING = "STRING"
	INT    = "INT"
	DOUBLE = "DOUBLE"
	IDENT  = "IDENT"

	LBRACE   = "{"
	RBRACE   = "}"
	LBRACKET = "["
	RBRACKET = "]"

	SEMI = ";"
	EQ   = "="
	GT   = ">"

	COLON = ":"
	COMMA = ","

	DEF = "=>"

	FN     = "FN"
	FIRST  = "FIRST"
	SECOND = "SECOND"
	THIRD  = "THIRD"
	WITH   = "WITH"
	NULL   = "NULL"
)

var keywords = map[string]Type{
	"fn":     FN,
	"first":  FIRST,
	"second": SECOND,
	"third":  THIRD,
	"with":   WITH,
	"null":   NULL,
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
