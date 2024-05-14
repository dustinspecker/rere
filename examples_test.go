package rere_test

import (
	"fmt"

	"github.com/dustinspecker/rere"
)

func ExampleRedactWithAllowList() {
	// RedactWithAllowList will redact string and byte slice/array field values for field names not found in allow list
	type user struct {
		Username string
		Password string
		Key      []byte
		IsAdmin  bool
	}

	testUser := user{
		Username: "dustin",
		Password: "super secret",
		Key:      []byte("another secret"),
		IsAdmin:  true,
	}
	allowList := []string{"Username"}
	redactedUser := rere.RedactWithAllowList(testUser, allowList)
	fmt.Printf("redacted string field value: %+v\n", redactedUser)

	// RedactWithAllowList will not modify the original value - perfect for logging
	// RedactWithAllowList does not require a pointer. This is just to help further exemplify the point
	// that the original value is left unchanged.
	redactedUserPointer := rere.RedactWithAllowList(&testUser, allowList)
	fmt.Printf("redacted string field value on pointer to struct: %+v\n", *redactedUserPointer)
	fmt.Printf("original value left unchanged: %+v\n", testUser)

	//nolint:lll // ignore long line length for example output
	// Output: redacted string field value: {Username:dustin Password:REDACTED Key:[82 69 68 65 67 84 69 68] IsAdmin:true}
	// redacted string field value on pointer to struct: {Username:dustin Password:REDACTED Key:[82 69 68 65 67 84 69 68] IsAdmin:true}
	// original value left unchanged: {Username:dustin Password:super secret Key:[97 110 111 116 104 101 114 32 115 101 99 114 101 116] IsAdmin:true}
}

func ExampleRedactWithDenyList() {
	// RedactWithDenyList will redact string and byte slice/array field values for field names found in deny list
	type user struct {
		Username string
		Password string
		Key      []byte
		IsAdmin  bool
	}

	testUser := user{
		Username: "dustin",
		Password: "super secret",
		Key:      []byte("another secret"),
		IsAdmin:  true,
	}
	denyList := []string{"Password", "Key"}
	redactedUser := rere.RedactWithDenyList(testUser, denyList)
	fmt.Printf("redacted string field value: %+v\n", redactedUser)

	// RedactWithDenyList will not modify the original value - perfect for logging
	// RedactWithDenyList does not require a pointer. This is just to help further exemplify the point
	// that the original value is left unchanged.
	redactedUserPointer := rere.RedactWithDenyList(&testUser, denyList)
	fmt.Printf("redacted string field value on pointer to struct: %+v\n", *redactedUserPointer)
	fmt.Printf("original value left unchanged: %+v\n", testUser)

	//nolint:lll // ignore long line length for example output
	// Output: redacted string field value: {Username:dustin Password:REDACTED Key:[82 69 68 65 67 84 69 68] IsAdmin:true}
	// redacted string field value on pointer to struct: {Username:dustin Password:REDACTED Key:[82 69 68 65 67 84 69 68] IsAdmin:true}
	// original value left unchanged: {Username:dustin Password:super secret Key:[97 110 111 116 104 101 114 32 115 101 99 114 101 116] IsAdmin:true}
}
