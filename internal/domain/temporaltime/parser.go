package temporaltime

import (
	"context"
	"time"
)

// StrictParserRegistry contains only immutable built-in parser specifications.
// It has no dynamic layout, plugin, callback, or fallback parsing surface.
type StrictParserRegistry struct {
	identities map[ParserIdentity]ParserKind
	parser     strictParser
}

func NewStrictParserRegistry(specifications []ParserSpec) (*StrictParserRegistry, error) {
	identities := make(map[ParserIdentity]ParserKind, len(specifications))
	for _, specification := range specifications {
		if !validParser(specification.Identity) || specification.Kind != BuiltinStrictParser {
			return nil, newError(InvalidInput, ParserNotRegistered, nil)
		}
		if _, exists := identities[specification.Identity]; exists {
			return nil, newError(ConflictError, ParserNotRegistered, nil)
		}
		identities[specification.Identity] = specification.Kind
	}
	return &StrictParserRegistry{identities: identities}, nil
}

func (registry *StrictParserRegistry) ResolveParser(ctx context.Context, identity ParserIdentity) (Parser, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if registry == nil {
		return nil, newError(InvalidInput, ParserNotRegistered, nil)
	}
	if kind, exists := registry.identities[identity]; !exists || kind != BuiltinStrictParser {
		return nil, newError(DeniedError, ParserNotRegistered, nil)
	}
	return registry.parser, nil
}

type strictParser struct{}

func (strictParser) Parse(ctx context.Context, source, format string, precision Precision) (CivilTime, error) {
	if err := checkContext(ctx); err != nil {
		return CivilTime{}, err
	}
	if len(source) == 0 || len(source) > 4096 || !validPrecision(precision) || precision == UnknownPrecision {
		return CivilTime{}, newError(DeniedError, InvalidSourceText, nil)
	}
	var layout string
	requiresOffset := false
	switch format {
	case "rfc3339":
		layout, requiresOffset = time.RFC3339Nano, true
	case "civil_date":
		layout = "2006-01-02"
		if precision != Day {
			return CivilTime{}, newError(DeniedError, FormatNotSupported, nil)
		}
	case "civil_hour":
		layout = "2006-01-02T15"
		if precision != Hour {
			return CivilTime{}, newError(DeniedError, FormatNotSupported, nil)
		}
	case "civil_minute":
		layout = "2006-01-02T15:04"
		if precision != Minute {
			return CivilTime{}, newError(DeniedError, FormatNotSupported, nil)
		}
	case "civil_second":
		layout = "2006-01-02T15:04:05"
		if precision != Second {
			return CivilTime{}, newError(DeniedError, FormatNotSupported, nil)
		}
	case "civil_fraction":
		layout = "2006-01-02T15:04:05.999999999"
		if precision != Millisecond && precision != Microsecond && precision != Nanosecond {
			return CivilTime{}, newError(DeniedError, FormatNotSupported, nil)
		}
	default:
		return CivilTime{}, newError(DeniedError, FormatNotSupported, nil)
	}
	parsed, err := time.Parse(layout, source)
	if err != nil {
		return CivilTime{}, newError(DeniedError, InvalidSourceText, err)
	}
	value := CivilTime{Year: parsed.Year(), Month: parsed.Month(), Day: parsed.Day(), Hour: parsed.Hour(), Minute: parsed.Minute(), Second: parsed.Second(), Nanosecond: parsed.Nanosecond(), Precision: precision}
	if requiresOffset {
		_, offsetSeconds := parsed.Zone()
		if offsetSeconds%60 != 0 || offsetSeconds/60 < -840 || offsetSeconds/60 > 840 {
			return CivilTime{}, newError(DeniedError, InvalidSourceText, nil)
		}
		offset := int16(offsetSeconds / 60)
		value.SourceOffsetMinutes = &offset
	}
	if !validCivil(value) || !civilAligned(value) {
		return CivilTime{}, newError(DeniedError, InvalidSourceText, nil)
	}
	return value, nil
}

func civilAligned(value CivilTime) bool {
	switch value.Precision {
	case Day:
		return value.Hour == 0 && value.Minute == 0 && value.Second == 0 && value.Nanosecond == 0
	case Hour:
		return value.Minute == 0 && value.Second == 0 && value.Nanosecond == 0
	case Minute:
		return value.Second == 0 && value.Nanosecond == 0
	case Second:
		return value.Nanosecond == 0
	case Millisecond:
		return value.Nanosecond%int(time.Millisecond) == 0
	case Microsecond:
		return value.Nanosecond%int(time.Microsecond) == 0
	case Nanosecond:
		return true
	default:
		return false
	}
}
