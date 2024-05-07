package rere

import (
	"reflect"
	"slices"
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
// If RedactWithAllowList is provided a string or []byte value then it will redact the value with "REDACTED", regardless of the allow list. The same is true when looping through types like []string when when the field name is not in the allow list.
func RedactWithAllowList[T any](value T, allowList []string) T {
	// create a deep copy of the provided value, so original value is not modified
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
// If RedactWithDenyList is provided a string or []byte value then it will redact the value with "REDACTED", regardless of the deny list. The same is true when looping through types like []string when when the field name is in the deny list.
//
// NOTE: It is *STRONGLY* discouraged to use RedactWithDenyList in production code, as it is easy to accidentally miss redacting sensitive information.
// Example: a struct in v1 has a field name of "Password". In v2, a new field name of "PrivateKey" is added and code is migrated from
// using "Password" to "PrivateKey". If the deny list is not updated, then the new field, "PrivateKey", will not be redacted.
//
// RedactWithAllowList is recommended for production code, as it is more explicit about what fields are not redacted. In the above example,
// the "PrivateKey" field would be redacted if it is not in the allow list. If a new field like "Organization" is added in v2, but
// forgotten in the allow list, then the worse case is that the "Organization" field is not redacted, which is less severe than
// leaking a "PrivateKey" field.
func RedactWithDenyList[T any](value T, denyList []string) T {
	// create a deep copy of the provided value, so original value is not modified
	deepCopy := reprint.This(value).(T)

	reflectedValue := reflect.ValueOf(&deepCopy)

	// redact all redacted field types
	redact(reflectedValue, deny, denyList)

	return deepCopy
}

// If mode is allow then fieldKeyNameList is an allow list.
// If mode is deny then fieldKeyNameList is a deny list.
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
			inAllowList := mode == allow && slices.Contains(fieldKeyNameList, keyName)
			// skip redacting fields not in the deny list when in deny mode
			notInDenyList := mode == deny && !slices.Contains(fieldKeyNameList, keyName)
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
		for i := 0; i < reflectedValueElem.NumField(); i++ {
			fieldName := reflectedValueElem.Type().Field(i).Name

			// skip redacting fields in the allow list when in allow mode
			inAllowList := mode == allow && slices.Contains(fieldKeyNameList, fieldName)
			// skip redacting fields not in the deny list when in deny mode
			notInDenyList := mode == deny && !slices.Contains(fieldKeyNameList, fieldName)
			if inAllowList || notInDenyList {
				continue
			}

			field := reflectedValueElem.Field(i)

			// use reflect.NewAt to handle redacted unexported fields
			redactedValue := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()

			redact(redactedValue, mode, fieldKeyNameList)
		}
		// ignore other types
	}
}
