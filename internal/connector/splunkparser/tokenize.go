package splunkparser

import (
	"context"
	"unicode/utf8"
)

type tokenKind uint8

const (
	tokenWord tokenKind = iota + 1
	tokenString
	tokenInteger
	tokenEqual
	tokenNotEqual
	tokenLess
	tokenLessEqual
	tokenGreater
	tokenGreaterEqual
	tokenPipe
	tokenComma
	tokenLeftParen
	tokenRightParen
	tokenLeftBracket
	tokenRightBracket
	tokenPlus
	tokenMinus
	tokenEOF
)

type token struct {
	kind tokenKind
	text string
}

func tokenize(ctx context.Context, input string) ([]token, error) {
	if len(input) == 0 || len(input) > MaximumInputBytes {
		return nil, syntaxDenied("input_size_invalid")
	}
	if !utf8.ValidString(input) {
		return nil, syntaxDenied("input_encoding_invalid")
	}
	tokens := make([]token, 0, min(len(input)/3, MaximumTokens))
	for offset := 0; offset < len(input); {
		if offset&63 == 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
		}
		current := input[offset]
		if current == ' ' || current == '\t' {
			offset++
			continue
		}
		if current < 0x20 || current == 0x7f {
			return nil, syntaxDenied("control_character_not_allowed")
		}
		if current == '`' {
			return nil, syntaxDenied("backtick_not_allowed")
		}
		if current == '\'' {
			return nil, syntaxDenied("single_quote_not_allowed")
		}
		if current == ';' {
			return nil, syntaxDenied("semicolon_not_allowed")
		}
		if current == '$' {
			return nil, syntaxDenied("dollar_substitution_not_allowed")
		}
		if current == '*' {
			return nil, syntaxDenied("wildcard_not_allowed")
		}
		if current == '"' {
			value, next, err := scanString(ctx, input, offset+1)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, token{kind: tokenString, text: value})
			offset = next
		} else if isWordStart(current) {
			start := offset
			for offset < len(input) && isWordContinue(input[offset]) {
				offset++
			}
			tokens = append(tokens, token{kind: tokenWord, text: input[start:offset]})
		} else if current >= '0' && current <= '9' {
			start := offset
			for offset < len(input) && input[offset] >= '0' && input[offset] <= '9' {
				offset++
			}
			tokens = append(tokens, token{kind: tokenInteger, text: input[start:offset]})
		} else {
			kind, width, ok := punctuation(input[offset:])
			if !ok {
				return nil, syntaxDenied("character_not_allowed")
			}
			tokens = append(tokens, token{kind: kind, text: input[offset : offset+width]})
			offset += width
		}
		if len(tokens) > MaximumTokens {
			return nil, syntaxDenied("token_limit_exceeded")
		}
	}
	tokens = append(tokens, token{kind: tokenEOF})
	return tokens, nil
}

func scanString(ctx context.Context, input string, offset int) (string, int, error) {
	value := make([]byte, 0, 32)
	for offset < len(input) {
		if offset&63 == 0 {
			select {
			case <-ctx.Done():
				return "", 0, ctx.Err()
			default:
			}
		}
		current := input[offset]
		if current == '"' {
			return string(value), offset + 1, nil
		}
		if current < 0x20 || current == 0x7f {
			return "", 0, syntaxDenied("string_control_character_not_allowed")
		}
		if current == '`' {
			return "", 0, syntaxDenied("backtick_not_allowed")
		}
		if current == '$' {
			return "", 0, syntaxDenied("dollar_substitution_not_allowed")
		}
		if current == '*' {
			return "", 0, syntaxDenied("wildcard_not_allowed")
		}
		if current == ';' {
			return "", 0, syntaxDenied("semicolon_not_allowed")
		}
		if current == '\\' {
			offset++
			if offset >= len(input) || (input[offset] != '\\' && input[offset] != '"') {
				return "", 0, syntaxDenied("string_escape_invalid")
			}
			current = input[offset]
		}
		value = append(value, current)
		offset++
	}
	return "", 0, syntaxDenied("string_unterminated")
}

func punctuation(input string) (tokenKind, int, bool) {
	if len(input) >= 2 {
		switch input[:2] {
		case "!=":
			return tokenNotEqual, 2, true
		case "<=":
			return tokenLessEqual, 2, true
		case ">=":
			return tokenGreaterEqual, 2, true
		}
	}
	switch input[0] {
	case '=':
		return tokenEqual, 1, true
	case '<':
		return tokenLess, 1, true
	case '>':
		return tokenGreater, 1, true
	case '|':
		return tokenPipe, 1, true
	case ',':
		return tokenComma, 1, true
	case '(':
		return tokenLeftParen, 1, true
	case ')':
		return tokenRightParen, 1, true
	case '[':
		return tokenLeftBracket, 1, true
	case ']':
		return tokenRightBracket, 1, true
	case '+':
		return tokenPlus, 1, true
	case '-':
		return tokenMinus, 1, true
	default:
		return 0, 0, false
	}
}

func isWordStart(value byte) bool {
	return value == '_' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func isWordContinue(value byte) bool {
	return isWordStart(value) || value >= '0' && value <= '9' || value == '.' || value == '-'
}
