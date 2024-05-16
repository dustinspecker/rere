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
		Groups   []string
	}

	testUser := user{
		Username: "dustin",
		Password: "super secret",
		Key:      []byte("another secret"),
		IsAdmin:  true,
		Groups:   []string{"users"},
	}
	// RedactWithAllowList redacts all strings and []byte by default
	defaultRedactedUser := rere.RedactWithAllowList(testUser, nil)
	fmt.Printf("default redacted value: %+v\n", defaultRedactedUser)

	// allowList is matched against case insensitively
	allowList := []string{"username", "groups"}
	redactedUser := rere.RedactWithAllowList(testUser, allowList)
	fmt.Printf("redacted value with allow list: %+v\n", redactedUser)

	// RedactWithAllowList will not modify the original value - perfect for logging
	// RedactWithAllowList does not require a pointer. This is just to help further exemplify the point
	// that the original value is left unchanged.
	redactedUserPointer := rere.RedactWithAllowList(&testUser, allowList)
	fmt.Printf("redacted pointer value: %+v\n", *redactedUserPointer)
	fmt.Printf("original value left unchanged: %+v\n", testUser)

	//nolint:lll // ignore long line length for example output
	// Output: default redacted value: {Username:REDACTED Password:REDACTED Key:[82 69 68 65 67 84 69 68] IsAdmin:true Groups:[REDACTED]}
	// redacted value with allow list: {Username:dustin Password:REDACTED Key:[82 69 68 65 67 84 69 68] IsAdmin:true Groups:[users]}
	// redacted pointer value: {Username:dustin Password:REDACTED Key:[82 69 68 65 67 84 69 68] IsAdmin:true Groups:[users]}
	// original value left unchanged: {Username:dustin Password:super secret Key:[97 110 111 116 104 101 114 32 115 101 99 114 101 116] IsAdmin:true Groups:[users]}
}

func ExampleRedactWithDenyList() {
	// RedactWithDenyList will redact string and byte slice/array field values for field names found in deny list
	type user struct {
		Username string
		Password string
		Key      []byte
		IsAdmin  bool
		Groups   []string
	}

	testUser := user{
		Username: "dustin",
		Password: "super secret",
		Key:      []byte("another secret"),
		IsAdmin:  true,
		Groups:   []string{"users"},
	}
	// RedactWithDenyList redacts nothing by default
	defaultRedactedUser := rere.RedactWithDenyList(testUser, nil)
	fmt.Printf("default denied value: %+v\n", defaultRedactedUser)

	// denyList is matched against case insensitively
	denyList := []string{"password", "Key"}
	redactedUser := rere.RedactWithDenyList(testUser, denyList)
	fmt.Printf("redacted value with deny list: %+v\n", redactedUser)

	// RedactWithDenyList will not modify the original value - perfect for logging
	// RedactWithDenyList does not require a pointer. This is just to help further exemplify the point
	// that the original value is left unchanged.
	redactedUserPointer := rere.RedactWithDenyList(&testUser, denyList)
	fmt.Printf("redacted pointer value: %+v\n", *redactedUserPointer)
	fmt.Printf("original value left unchanged: %+v\n", testUser)

	//nolint:lll // ignore long line length for example output
	// Output: default denied value: {Username:dustin Password:super secret Key:[97 110 111 116 104 101 114 32 115 101 99 114 101 116] IsAdmin:true Groups:[users]}
	// redacted value with deny list: {Username:dustin Password:REDACTED Key:[82 69 68 65 67 84 69 68] IsAdmin:true Groups:[users]}
	// redacted pointer value: {Username:dustin Password:REDACTED Key:[82 69 68 65 67 84 69 68] IsAdmin:true Groups:[users]}
	// original value left unchanged: {Username:dustin Password:super secret Key:[97 110 111 116 104 101 114 32 115 101 99 114 101 116] IsAdmin:true Groups:[users]}
}
