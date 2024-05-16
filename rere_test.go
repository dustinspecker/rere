//nolint:goconst // I think constants make test data harder to glance
package rere_test

import (
	"testing"

	"github.com/dustinspecker/rere"
	"github.com/onsi/gomega"
	"github.com/qdm12/reprint"
)

const (
	redacted  = "REDACTED"
	rawString = "raw string"
)

type structWithoutRedactedFields struct {
	Number int
}

type structWithRedactedFields struct {
	Username string
	Password string
	// validate Redacts handles unexported fields
	password  string
	username  string
	byteSlice []byte
	stringPtr *string
}

type structWithByteField struct {
	Value byte
}

type structWithByteSlice struct {
	Password []byte
	password []byte
}

type structWithNestedStruct struct {
	Nested structWithRedactedFields
}

type complicatedStruct struct {
	NestedStructs []structWithNestedStruct
}

type structWithNestedPointer struct {
	Password **string
}

type structWithInterface struct {
	Password any
	password any
}

type structWithEverything struct {
	RawString   string
	rawString   string
	StringPtr   *string
	stringPtr   *string
	StringSlice []string
	stringSlice []string
	ByteSlice   []byte
	byteSlice   []byte
	Number      int
	number      int
	NumberPtr   *int
	numberPtr   *int
	StructSlice []structWithRedactedFields
	structSlice []structWithRedactedFields
}

type complexStructHolder struct {
	NestedStruct *structWithEverything
}

//nolint:funlen,maintidx // I'm okay with test functions with several statements of test data
func TestRedactWithAllowList(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		input     any
		allowList []string
		output    any
	}{
		{
			name: "does nothing for struct without redacted fields",
			input: structWithoutRedactedFields{
				Number: 1,
			},
			allowList: nil,
			output: structWithoutRedactedFields{
				Number: 1,
			},
		},
		{
			name: "redacts string fields on structs",
			input: structWithRedactedFields{
				Username:  "alice",
				username:  "bob",
				Password:  "hunter2",
				password:  "*****",
				byteSlice: nil,
				stringPtr: nil,
			},
			allowList: nil,
			output: structWithRedactedFields{
				Username:  redacted,
				username:  redacted,
				Password:  redacted,
				password:  redacted,
				byteSlice: nil,
				stringPtr: nil,
			},
		},
		{
			name: "does not modify provided input",
			input: &structWithRedactedFields{
				Username:  "username",
				username:  "username",
				Password:  "password",
				password:  "password",
				byteSlice: nil,
				stringPtr: nil,
			},
			allowList: nil,
			output: &structWithRedactedFields{
				Username:  redacted,
				username:  redacted,
				Password:  redacted,
				password:  redacted,
				byteSlice: nil,
				stringPtr: nil,
			},
		},
		{
			name: "does not redact empty strings",
			input: structWithRedactedFields{
				Username:  "",
				username:  "",
				Password:  "",
				password:  "",
				byteSlice: nil,
				stringPtr: nil,
			},
			allowList: nil,
			output: structWithRedactedFields{
				Username:  "",
				username:  "",
				Password:  "",
				password:  "",
				byteSlice: nil,
				stringPtr: nil,
			},
		},
		{
			name: "does not redact byte value",
			input: structWithByteField{
				Value: 1,
			},
			allowList: nil,
			output: structWithByteField{
				Value: 1,
			},
		},
		{
			name: "redact byte slices",
			input: structWithByteSlice{
				Password: []byte("password"),
				password: []byte("password"),
			},
			allowList: nil,
			output: structWithByteSlice{
				Password: []byte(redacted),
				password: []byte(redacted),
			},
		},
		{
			name: "does not redact empty byte slices",
			input: structWithByteSlice{
				Password: []byte(""),
				password: nil,
			},
			allowList: nil,
			output: structWithByteSlice{
				Password: []byte(""),
				password: nil,
			},
		},
		{
			name: "handles nested structs",
			input: structWithNestedStruct{
				Nested: structWithRedactedFields{
					Username:  "username",
					username:  "username",
					Password:  "password",
					password:  redacted,
					byteSlice: nil,
					stringPtr: nil,
				},
			},
			allowList: nil,
			output: structWithNestedStruct{
				Nested: structWithRedactedFields{
					Username:  redacted,
					username:  redacted,
					Password:  redacted,
					password:  redacted,
					byteSlice: nil,
					stringPtr: nil,
				},
			},
		},
		{
			name:      "handles maps",
			input:     map[string]string{"password": "password"},
			allowList: nil,
			output:    map[string]string{"password": redacted},
		},
		{
			name:      "handles strings",
			input:     "password",
			allowList: nil,
			output:    redacted,
		},
		{
			name:      "handles arrays",
			input:     [1]string{"some_value"},
			allowList: nil,
			output:    [1]string{redacted},
		},
		{
			name:      "handles slices",
			input:     []string{"password"},
			allowList: nil,
			output:    []string{redacted},
		},
		{
			name: "handles complex struct",
			input: complicatedStruct{
				NestedStructs: []structWithNestedStruct{
					{
						Nested: structWithRedactedFields{
							Username:  "username",
							username:  "username",
							Password:  "password",
							password:  "password",
							byteSlice: nil,
							stringPtr: nil,
						},
					},
				},
			},
			allowList: nil,
			output: complicatedStruct{
				NestedStructs: []structWithNestedStruct{
					{
						Nested: structWithRedactedFields{
							Username:  redacted,
							username:  redacted,
							Password:  redacted,
							password:  redacted,
							byteSlice: nil,
							stringPtr: nil,
						},
					},
				},
			},
		},
		{
			name: "handles nested pointers",
			input: structWithNestedPointer{
				Password: func() **string {
					redacted := redacted
					redactedPointer := &redacted

					return &redactedPointer
				}(),
			},
			allowList: nil,
			output: structWithNestedPointer{
				Password: func() **string {
					redacted := redacted
					redactedPointer := &redacted

					return &redactedPointer
				}(),
			},
		},
		{
			name: "handles interfaces",
			input: structWithInterface{
				Password: "password",
				password: "password",
			},
			allowList: nil,
			output: structWithInterface{
				Password: redacted,
				password: redacted,
			},
		},
		{
			name: "skips redacting fields in allow list regardless of case",
			input: structWithRedactedFields{
				Username:  "dustin",
				Password:  "",
				password:  "",
				username:  "dustin",
				byteSlice: nil,
				stringPtr: nil,
			},
			allowList: []string{"Username"},
			output: structWithRedactedFields{
				Username:  "dustin",
				Password:  "",
				password:  "",
				username:  "dustin",
				byteSlice: nil,
				stringPtr: nil,
			},
		},
		{
			name: "skips redacting keys in allow list regardless of case",
			input: map[string]string{
				"Username": "dustin",
				"username": "dustin",
				"Password": "password",
			},
			allowList: []string{"Username"},
			output: map[string]string{
				"Username": "dustin",
				"username": "dustin",
				"Password": redacted,
			},
		},
		{
			name: "redacts nested structs",
			input: structWithNestedStruct{
				Nested: structWithRedactedFields{
					Username:  "username",
					username:  "username",
					Password:  "password",
					password:  "password",
					byteSlice: []byte("password"),
					stringPtr: nil,
				},
			},
			allowList: []string{"username", "byteslice"},
			output: structWithNestedStruct{
				Nested: structWithRedactedFields{
					Username:  "username",
					username:  "username",
					Password:  redacted,
					password:  redacted,
					byteSlice: []byte("password"),
					stringPtr: nil,
				},
			},
		},
		{
			name:      "redacts everything by default",
			input:     getComplexStruct(),
			allowList: nil,
			output:    getRedactedComplexStruct(),
		},
		{
			name:  "can avoid redacting everything included in allow list",
			input: getComplexStruct(),
			allowList: []string{
				"RawString",
				"StringPtr",
				"StringSlice",
				"ByteSlice",
				"Number",
				"NumberPtr",
				"username",
				"password",
			},
			output: getComplexStruct(),
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			g := gomega.NewWithT(t)

			originalInput := reprint.This(testCase.input)

			redacted := rere.RedactWithAllowList(testCase.input, testCase.allowList)

			g.Expect(redacted).To(gomega.Equal(testCase.output), "RedactWithAllowList should redact the provided input")
			g.Expect(&redacted).ToNot(gomega.BeIdenticalTo(&testCase.input), "RedactWithAllowList should create a deep copy")
			g.Expect(testCase.input).To(gomega.Equal(originalInput), "RedactWithAllowList should not modify the provided input")
		})
	}
}

//nolint:funlen // I'm okay with test functions with several statements of test data
func TestRedactWithDenyList(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		input    any
		denyList []string
		output   any
	}{
		{
			name:     "does not redact simple []byte value",
			input:    []byte("hello"),
			denyList: nil,
			output:   []byte("hello"),
		},
		{
			name:     "does not redact simple string value",
			input:    "hello",
			denyList: nil,
			output:   "hello",
		},
		{
			name: "redacts only field names in deny list regardless of case",
			input: structWithRedactedFields{
				Username:  "username",
				username:  "username",
				Password:  "password",
				password:  "password",
				byteSlice: nil,
				stringPtr: nil,
			},
			denyList: []string{"Password"},
			output: structWithRedactedFields{
				Username:  "username",
				username:  "username",
				Password:  redacted,
				password:  redacted,
				byteSlice: nil,
				stringPtr: nil,
			},
		},
		{
			name: "redacts only key names in deny list regardless of case",
			input: map[string]string{
				"Username": "username",
				"Password": "password",
				"password": "password",
			},
			denyList: []string{"password"},
			output: map[string]string{
				"Username": "username",
				"Password": redacted,
				"password": redacted,
			},
		},
		{
			name: "redacts nested structs",
			input: structWithNestedStruct{
				Nested: structWithRedactedFields{
					Username:  "username",
					username:  "username",
					Password:  "password",
					password:  "password",
					byteSlice: []byte("password"),
					stringPtr: func() *string {
						password := "password"

						return &password
					}(),
				},
			},
			denyList: []string{"password"},
			output: structWithNestedStruct{
				Nested: structWithRedactedFields{
					Username:  "username",
					username:  "username",
					Password:  redacted,
					password:  redacted,
					byteSlice: []byte("password"),
					stringPtr: func() *string {
						password := "password"

						return &password
					}(),
				},
			},
		},
		{
			name:     "redacts nothing by default",
			input:    getComplexStruct(),
			denyList: nil,
			output:   getComplexStruct(),
		},
		{
			name:  "can redact every string and []byte included in deny list",
			input: getComplexStruct(),
			denyList: []string{
				"RawString",
				"StringPtr",
				"StringSlice",
				"ByteSlice",
				"Number",
				"NumberPtr",
				"username",
				"password",
			},
			output: getRedactedComplexStruct(),
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			g := gomega.NewWithT(t)

			originalInput := reprint.This(testCase.input)

			redacted := rere.RedactWithDenyList(testCase.input, testCase.denyList)

			g.Expect(redacted).To(gomega.Equal(testCase.output), "RedactWithDenyList should redact the provided input")
			g.Expect(&redacted).ToNot(gomega.BeIdenticalTo(&testCase.input), "RedactWithDenyList should create a deep copy")
			g.Expect(testCase.input).To(gomega.Equal(originalInput), "RedactWithDenyList should not modify the provided input")
		})
	}
}

func getComplexStruct() complexStructHolder {
	return complexStructHolder{
		NestedStruct: &structWithEverything{
			RawString: rawString,
			rawString: rawString,
			StringPtr: func() *string {
				rawString := rawString

				return &rawString
			}(),
			stringPtr: func() *string {
				rawString := rawString

				return &rawString
			}(),
			StringSlice: []string{"string slice", "string slice"},
			stringSlice: []string{"string slice", "string slice"},
			ByteSlice:   []byte("byte slice"),
			byteSlice:   []byte("byte slice"),
			Number:      42,
			number:      42,
			NumberPtr: func() *int {
				number := 42

				return &number
			}(),
			numberPtr: func() *int {
				number := 42

				return &number
			}(),
			StructSlice: []structWithRedactedFields{
				{
					Username:  "username",
					username:  "username",
					Password:  "password",
					password:  "password",
					byteSlice: []byte("password"),
					stringPtr: func() *string {
						password := "password"

						return &password
					}(),
				},
			},
			structSlice: []structWithRedactedFields{
				{
					Username:  "username",
					username:  "username",
					Password:  "password",
					password:  "password",
					byteSlice: []byte("password"),
					stringPtr: func() *string {
						password := "password"

						return &password
					}(),
				},
			},
		},
	}
}

func getRedactedComplexStruct() complexStructHolder {
	return complexStructHolder{
		NestedStruct: &structWithEverything{
			RawString: redacted,
			rawString: redacted,
			StringPtr: func() *string {
				rawString := redacted

				return &rawString
			}(),
			stringPtr: func() *string {
				rawString := redacted

				return &rawString
			}(),
			StringSlice: []string{redacted, redacted},
			stringSlice: []string{redacted, redacted},
			ByteSlice:   []byte(redacted),
			byteSlice:   []byte(redacted),
			Number:      42,
			number:      42,
			NumberPtr: func() *int {
				number := 42

				return &number
			}(),
			numberPtr: func() *int {
				number := 42

				return &number
			}(),
			StructSlice: []structWithRedactedFields{
				{
					Username:  redacted,
					username:  redacted,
					Password:  redacted,
					password:  redacted,
					byteSlice: []byte(redacted),
					stringPtr: func() *string {
						password := redacted

						return &password
					}(),
				},
			},
			structSlice: []structWithRedactedFields{
				{
					Username:  redacted,
					username:  redacted,
					Password:  redacted,
					password:  redacted,
					byteSlice: []byte(redacted),
					stringPtr: func() *string {
						password := redacted

						return &password
					}(),
				},
			},
		},
	}
}
