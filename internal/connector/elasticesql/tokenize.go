package elasticesql

import (
	"context"
	"strconv"
	"strings"
	"unicode/utf8"
)

func tokenize(ctx context.Context, input string) ([]token, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if input == "" || len(input) > maximumInputBytes || !utf8.ValidString(input) {
		return nil, deny("esql_input_invalid")
	}
	tokens := make([]token, 0, min(len(input)/3, maximumTokens))
	for offset := 0; offset < len(input); {
		if len(tokens) >= maximumTokens {
			return nil, deny("esql_token_limit")
		}
		if len(tokens)%64 == 0 {
			if err := contextError(ctx); err != nil {
				return nil, err
			}
		}
		value := input[offset]
		if isSpace(value) {
			offset++
			continue
		}
		start := offset
		switch value {
		case '|':
			tokens, offset = append(tokens, token{kind: tokenPipe, text: "|", offset: start}), offset+1
		case ',':
			tokens, offset = append(tokens, token{kind: tokenComma, text: ",", offset: start}), offset+1
		case '(':
			tokens, offset = append(tokens, token{kind: tokenLeftParen, text: "(", offset: start}), offset+1
		case ')':
			tokens, offset = append(tokens, token{kind: tokenRightParen, text: ")", offset: start}), offset+1
		case '=':
			if offset+1 >= len(input) || input[offset+1] != '=' {
				return nil, deny("esql_operator_unsupported")
			}
			tokens, offset = append(tokens, token{kind: tokenEqual, text: "==", offset: start}), offset+2
		case '!':
			if offset+1 >= len(input) || input[offset+1] != '=' {
				return nil, deny("esql_operator_unsupported")
			}
			tokens, offset = append(tokens, token{kind: tokenNotEqual, text: "!=", offset: start}), offset+2
		case '<', '>':
			offset++
			kind := tokenLess
			if value == '>' {
				kind = tokenGreater
			}
			if offset < len(input) && input[offset] == '=' {
				offset++
				if value == '<' {
					kind = tokenLessEqual
				} else {
					kind = tokenGreaterEqual
				}
			}
			tokens = append(tokens, token{kind: kind, text: input[start:offset], offset: start})
		case '"':
			raw, next, err := scanString(input, offset)
			if err != nil {
				return nil, err
			}
			decoded, err := strconv.Unquote(raw)
			if err != nil || decoded == "" || strings.ContainsAny(decoded, "\x00\r\n\t") || len(decoded) > 4096 {
				return nil, deny("esql_string_invalid")
			}
			tokens, offset = append(tokens, token{kind: tokenString, text: raw, value: decoded, offset: start}), next
		default:
			if value == '-' || isDigit(value) {
				next := offset
				if input[next] == '-' {
					next++
					if next >= len(input) || !isDigit(input[next]) {
						return nil, deny("esql_integer_invalid")
					}
				}
				for next < len(input) && isDigit(input[next]) {
					next++
				}
				integer, err := strconv.ParseInt(input[offset:next], 10, 64)
				if err != nil {
					return nil, deny("esql_integer_invalid")
				}
				tokens, offset = append(tokens, token{kind: tokenInteger, text: input[offset:next], value: integer, offset: start}), next
				continue
			}
			if !isWordStart(value) {
				return nil, deny("esql_character_unsupported")
			}
			next := offset + 1
			for next < len(input) && isWordContinue(input[next]) {
				next++
			}
			tokens, offset = append(tokens, token{kind: tokenWord, text: input[offset:next], offset: start}), next
		}
	}
	tokens = append(tokens, token{kind: tokenEOF, offset: len(input)})
	return tokens, nil
}

func scanString(input string, offset int) (string, int, error) {
	start := offset
	offset++
	for offset < len(input) {
		switch input[offset] {
		case '"':
			return input[start : offset+1], offset + 1, nil
		case '\\':
			offset += 2
			if offset > len(input) {
				return "", 0, deny("esql_string_invalid")
			}
		default:
			if input[offset] < 0x20 {
				return "", 0, deny("esql_string_invalid")
			}
			offset++
		}
	}
	return "", 0, deny("esql_string_invalid")
}

func isSpace(value byte) bool { return value == ' ' || value == '\n' || value == '\r' || value == '\t' }
func isDigit(value byte) bool { return value >= '0' && value <= '9' }
func isWordStart(value byte) bool {
	return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || value == '@' || value == '_'
}
func isWordContinue(value byte) bool {
	return isWordStart(value) || isDigit(value) || value == '.' || value == '-'
}
