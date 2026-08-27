package evidencelifecycle

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

func DecodeExportManifest(input []byte) (ExportManifest, error) {
	var value ExportManifest
	if err := decodeCanonical(input, &value); err != nil || ValidateExportManifest(value) != nil {
		return ExportManifest{}, newError(Denied, "manifest_decode_invalid", false, err)
	}
	return value, nil
}

func DecodeDetachedSignature(input []byte) (DetachedSignature, error) {
	var value DetachedSignature
	if err := decodeCanonical(input, &value); err != nil || ValidateDetachedSignature(value) != nil {
		return DetachedSignature{}, newError(Denied, "signature_decode_invalid", false, err)
	}
	return value, nil
}

func decodeCanonical(input []byte, destination any) error {
	canonical, err := domaincontract.Canonicalize(input)
	if err != nil || !bytes.Equal(canonical, input) {
		return errors.New("input is not unique canonical JSON")
	}
	wire, err := domaincontract.DecodeUnique(input)
	if err != nil {
		return err
	}
	value := reflect.ValueOf(destination)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return errors.New("decode destination is invalid")
	}
	return fromWireValue(wire, value.Elem())
}

func fromWireValue(input any, destination reflect.Value) error {
	if destination.Kind() == reflect.Pointer {
		if input == nil {
			destination.SetZero()
			return nil
		}
		value := reflect.New(destination.Type().Elem())
		if err := fromWireValue(input, value.Elem()); err != nil {
			return err
		}
		destination.Set(value)
		return nil
	}
	if destination.Type() == reflect.TypeOf(time.Time{}) {
		text, ok := input.(string)
		if !ok {
			return errors.New("timestamp is invalid")
		}
		value, err := time.Parse("2006-01-02T15:04:05.000000000Z", text)
		if err != nil || value.Location() != time.UTC {
			return errors.New("timestamp is invalid")
		}
		destination.Set(reflect.ValueOf(value))
		return nil
	}
	switch destination.Kind() {
	case reflect.Struct:
		object, ok := input.(map[string]any)
		if !ok || len(object) != destination.NumField() {
			return errors.New("object shape is invalid")
		}
		for index := 0; index < destination.NumField(); index++ {
			name := snakeName(destination.Type().Field(index).Name)
			wire, found := object[name]
			if !found {
				return errors.New("required field is missing")
			}
			if err := fromWireValue(wire, destination.Field(index)); err != nil {
				return err
			}
		}
		return nil
	case reflect.Slice:
		array, ok := input.([]any)
		if !ok {
			return errors.New("array is invalid")
		}
		value := reflect.MakeSlice(destination.Type(), len(array), len(array))
		for index := range array {
			if err := fromWireValue(array[index], value.Index(index)); err != nil {
				return err
			}
		}
		destination.Set(value)
		return nil
	case reflect.String:
		value, ok := input.(string)
		if !ok {
			return errors.New("string is invalid")
		}
		destination.SetString(value)
		return nil
	case reflect.Bool:
		value, ok := input.(bool)
		if !ok {
			return errors.New("boolean is invalid")
		}
		destination.SetBool(value)
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		value, ok := input.(json.Number)
		if !ok {
			return errors.New("integer is invalid")
		}
		parsed, err := value.Int64()
		if err != nil || destination.OverflowInt(parsed) {
			return errors.New("integer is invalid")
		}
		destination.SetInt(parsed)
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		value, ok := input.(json.Number)
		if !ok {
			return errors.New("unsigned integer is invalid")
		}
		parsed, err := value.Int64()
		if err != nil || parsed < 0 || destination.OverflowUint(uint64(parsed)) {
			return errors.New("unsigned integer is invalid")
		}
		destination.SetUint(uint64(parsed))
		return nil
	default:
		return errors.New("wire type is unsupported")
	}
}
