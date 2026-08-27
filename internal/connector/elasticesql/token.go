package elasticesql

type tokenKind uint8

const (
	tokenEOF tokenKind = iota
	tokenWord
	tokenString
	tokenInteger
	tokenPipe
	tokenComma
	tokenLeftParen
	tokenRightParen
	tokenEqual
	tokenNotEqual
	tokenLess
	tokenLessEqual
	tokenGreater
	tokenGreaterEqual
)

type token struct {
	kind   tokenKind
	text   string
	value  any
	offset int
}
