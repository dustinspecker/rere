package rere_test

import (
	"testing"

	"github.com/dustinspecker/rere"
	"github.com/onsi/gomega"
	"github.com/qdm12/reprint"
)

type structWithoutRedactedFields struct {
	Number int
	// validate that Redact doesn't panic when unexported fields are present
	number int
}

type structWithRedactedFields struct {
	Username string
	Password string
	// validate Redacts handles unexported fields
	password string
}

type structWithByteField struct {
	Value byte
	value byte
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
			output: structWithoutRedactedFields{
				Number: 1,
			},
		},
		{
			name: "redacts string fields on structs",
			input: structWithRedactedFields{
				Password: "hunter2",
				password: "*****",
			},
			output: structWithRedactedFields{
				Password: "REDACTED",
				password: "REDACTED",
			},
		},
		{
			name: "does not modify provided input",
			input: &structWithRedactedFields{
				Password: "password",
				password: "password",
			},
			output: &structWithRedactedFields{
				Password: "REDACTED",
				password: "REDACTED",
			},
		},
		{
			name:   "does not redact empty strings",
			input:  structWithRedactedFields{},
			output: structWithRedactedFields{},
		},
		{
			name: "does not redact byte value",
			input: structWithByteField{
				Value: 1,
			},
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
			output: structWithByteSlice{
				Password: []byte("REDACTED"),
				password: []byte("REDACTED"),
			},
		},
		{
			name: "does not redact empty byte slices",
			input: structWithByteSlice{
				Password: []byte(""),
				password: nil,
			},
			output: structWithByteSlice{
				Password: []byte(""),
				password: nil,
			},
		},
		{
			name: "handles nested structs",
			input: structWithNestedStruct{
				Nested: structWithRedactedFields{
					Password: "password",
					password: "REDACTED",
				},
			},
			output: structWithNestedStruct{
				Nested: structWithRedactedFields{
					Password: "REDACTED",
					password: "REDACTED",
				},
			},
		},
		{
			name:   "handles maps",
			input:  map[string]string{"password": "password"},
			output: map[string]string{"password": "REDACTED"},
		},
		{
			name:   "handles strings",
			input:  "password",
			output: "REDACTED",
		},
		{
			name:   "handles arrays",
			input:  [1]string{"some_value"},
			output: [1]string{"REDACTED"},
		},
		{
			name:   "handles slices",
			input:  []string{"password"},
			output: []string{"REDACTED"},
		},
		{
			name: "handles complex struct",
			input: complicatedStruct{
				NestedStructs: []structWithNestedStruct{
					{
						Nested: structWithRedactedFields{
							Password: "password",
							password: "password",
						},
					},
				},
			},
			output: complicatedStruct{
				NestedStructs: []structWithNestedStruct{
					{
						Nested: structWithRedactedFields{
							Password: "REDACTED",
							password: "REDACTED",
						},
					},
				},
			},
		},
		{
			name: "handles nested pointers",
			input: structWithNestedPointer{
				Password: func() **string {
					redacted := "REDACTED"
					redactedPointer := &redacted
					return &redactedPointer
				}(),
			},
			output: structWithNestedPointer{
				Password: func() **string {
					redacted := "REDACTED"
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
			output: structWithInterface{
				Password: "REDACTED",
				password: "REDACTED",
			},
		},
		{
			name: "skips redacting fields in allow list",
			input: structWithRedactedFields{
				Username: "dustin",
			},
			allowList: []string{"Username"},
			output: structWithRedactedFields{
				Username: "dustin",
			},
		},
		{
			name: "skips redacting keys in allow list",
			input: map[string]string{
				"Username": "dustin",
				"Password": "password",
			},
			allowList: []string{"Username"},
			output: map[string]string{
				"Username": "dustin",
				"Password": "REDACTED",
			},
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

func TestRedactWithDenyList(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		input    any
		denyList []string
		output   any
	}{
		{
			name:   "redacts simple []byte value",
			input:  []byte("hello"),
			output: []byte("REDACTED"),
		},
		{
			name:   "redacts simple string value",
			input:  "hello",
			output: "REDACTED",
		},
		{
			name: "redacts only field names in deny list",
			input: structWithRedactedFields{
				Username: "username",
				Password: "password",
				password: "password",
			},
			denyList: []string{"Password", "password"},
			output: structWithRedactedFields{
				Username: "username",
				Password: "REDACTED",
				password: "REDACTED",
			},
		},
		{
			name: "redacts only key names in deny list",
			input: map[string]string{
				"Username": "username",
				"Password": "password",
				"password": "password",
			},
			denyList: []string{"Password", "password"},
			output: map[string]string{
				"Username": "username",
				"Password": "REDACTED",
				"password": "REDACTED",
			},
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
