// Package rere redacts sensitive fields through an allow or deny list of field and key names
package rere

import (
	"reflect"
	"slices"
	"strings"
	"unsafe"

	"github.com/qdm12/reprint"
)

type redactMode string

const (
	redactedMessage = "REDACTED"

	allow redactMode = "allow"
	deny  redactMode = "deny"
)

// RedactWithAllowList by default redacts all string and []byte field and key values found in the provided value.
// If a field or key name is in the allow list then it will not be redacted.
//
// String fields are redacted with "REDACTED". Byte slice fields are redacted with []byte("REDACTED").
// Empty string and byte slice fields are not redacted to make it easier to troubleshoot empty values.
//
// RedactWithAllowList will create a deep copy of the provided value, so the original value is not modified.
//
// RedactWithAllowList will loop through elements in slices and arrays to redact using above approach.
//
// If RedactWithAllowList is provided a string or []byte value then it will redact the value with "REDACTED",
// regardless of the allow list. The same is true when looping through types like []string when the field
// name is not in the allow list.
func RedactWithAllowList[T any](value T, allowList []string) T {
	// create a deep copy of the provided value, so original value is not modified
	//nolint:forcetypeassert // the type is correct and if not then reprint is broken and will be caught by unit tests
	deepCopy := reprint.This(value).(T)

	reflectedValue := reflect.ValueOf(&deepCopy)

	// redact all redacted field types
	redact(reflectedValue, allow, allowList)

	return deepCopy
}

// RedactWithDenyList by default leaves all string and []byte field and key values found in the provided value as-is.
// If a field or key name is in the deny list then it will be redacted.
//
// String fields are redacted with "REDACTED". Byte slice fields are redacted with []byte("REDACTED").
// Empty string and byte slice fields are not redacted to make it easier to troubleshoot empty values.
//
// RedactWithDenyList will create a deep copy of the provided value, so the original value is not modified.
//
// RedactWithDenyList will loop through elements in slices and arrays to redact using above approach.
//
// If RedactWithDenyList is provided a string or []byte value then it will redact the value with "REDACTED",
// regardless of the deny list. The same is true when looping through types like []string when the field
// name is in the deny list.
//
// NOTE: It is *STRONGLY* discouraged to use RedactWithDenyList in production code, as it is easy to accidentally
// miss redacting sensitive information.
// Example: a struct in v1 has a field name of "Password". In v2, a new field name of "PrivateKey" is added and
// code is migrated from using "Password" to "PrivateKey". If the deny list is not updated, then the new field,
// "PrivateKey", will not be redacted.
//
// RedactWithAllowList is recommended for production code, as it is more explicit about what fields are not redacted.
// In the above example, the "PrivateKey" field would be redacted if it is not in the allow list. If a new field like
// "Organization" is added in v2, but forgotten in the allow list, then the worse case is that the "Organization"
// field is not redacted, which is less severe than leaking a "PrivateKey" field.
func RedactWithDenyList[T any](value T, denyList []string) T {
	// create a deep copy of the provided value, so original value is not modified
	//nolint:forcetypeassert // the type is correct and if not then reprint is broken and will be caught by unit tests
	deepCopy := reprint.This(value).(T)

	reflectedValue := reflect.ValueOf(&deepCopy)

	// redact all redacted field types
	redact(reflectedValue, deny, denyList)

	return deepCopy
}

// If mode is allow then fieldKeyNameList is an allow list.
// If mode is deny then fieldKeyNameList is a deny list.
//
//nolint:cyclop,funlen,gocognit // I think the long switch statement is easier to read than breaking it up
func redact(value reflect.Value, mode redactMode, fieldKeyNameList []string) {
	reflectedValueElem := value

	// recurse through pointers to find actual value
	for reflectedValueElem.Kind() == reflect.Pointer {
		reflectedValueElem = reflectedValueElem.Elem()
	}

	switch reflectedValueElem.Kind() {
	case reflect.Array, reflect.Slice:
		// handle byte slice/array
		if reflectedValueElem.Type().Elem().Kind() == reflect.Uint8 {
			// only redact non-empty byte slice values
			if reflectedValueElem.Len() != 0 {
				reflectedValueElem.Set(reflect.ValueOf([]byte(redactedMessage)))
			}

			break
		}

		// otherwise loop through elements
		for i := 0; i < reflectedValueElem.Len(); i++ {
			redact(reflectedValueElem.Index(i), mode, fieldKeyNameList)
		}
	case reflect.Interface:
		element := reflectedValueElem.Elem()

		redactedValue := reflect.New(element.Type())
		redactedValue.Elem().Set(element)

		redact(redactedValue, mode, fieldKeyNameList)

		reflectedValueElem.Set(redactedValue.Elem())
	case reflect.Map:
		for _, key := range reflectedValueElem.MapKeys() {
			keyName := key.String()

			// skip redacting keys in the allow list when in allow mode
			inAllowList := mode == allow && slices.ContainsFunc(fieldKeyNameList, func(allowedKey string) bool {
				return strings.EqualFold(allowedKey, keyName)
			})
			// skip redacting keys not in the deny list when in deny mode
			notInDenyList := mode == deny && !slices.ContainsFunc(fieldKeyNameList, func(deniedKey string) bool {
				return strings.EqualFold(deniedKey, keyName)
			})
			if inAllowList || notInDenyList {
				continue
			}

			element := reflectedValueElem.MapIndex(key)

			redactedValue := reflect.New(element.Type())
			redactedValue.Elem().Set(element)

			redact(redactedValue, mode, fieldKeyNameList)

			reflectedValueElem.SetMapIndex(key, redactedValue.Elem())
		}
	case reflect.String:
		// only redact non-empty string values
		if !reflectedValueElem.IsZero() {
			reflectedValueElem.SetString(redactedMessage)
		}
	case reflect.Struct:
		for fieldIndex := 0; fieldIndex < reflectedValueElem.NumField(); fieldIndex++ {
			fieldName := reflectedValueElem.Type().Field(fieldIndex).Name

			field := reflectedValueElem.Field(fieldIndex)

			var (
				isStringType    = field.Kind() == reflect.String
				isByteSliceType = field.Kind() == reflect.Slice && field.Type().Elem().Kind() == reflect.Uint8
			)

			if isStringType || isByteSliceType {
				// skip redacting fields in the allow list when in allow mode
				inAllowList := mode == allow && slices.ContainsFunc(fieldKeyNameList, func(allowedField string) bool {
					return strings.EqualFold(allowedField, fieldName)
				})
				// skip redacting fields not in the deny list when in deny mode
				notInDenyList := mode == deny && !slices.ContainsFunc(fieldKeyNameList, func(deniedField string) bool {
					return strings.EqualFold(deniedField, fieldName)
				})
				if inAllowList || notInDenyList {
					continue
				}
			}

			// use reflect.NewAt to handle redacted unexported fields
			redactedValue := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()

			redact(redactedValue, mode, fieldKeyNameList)
		}
	case reflect.Bool,
		reflect.Chan,
		reflect.Complex64,
		reflect.Complex128,
		reflect.Float32,
		reflect.Float64,
		reflect.Func,
		reflect.Int,
		reflect.Int8,
		reflect.Int16,
		reflect.Int32,
		reflect.Int64,
		reflect.Invalid,
		reflect.Pointer,
		reflect.Uint,
		reflect.Uint8,
		reflect.Uint16,
		reflect.Uint32,
		reflect.Uint64,
		reflect.Uintptr,
		reflect.UnsafePointer:
		// do nothing
		break
	}
}
