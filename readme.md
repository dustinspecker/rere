# rere

> Redact sensitive fields through an allow or deny list of field and key names

## What problem does rere solve?

rere allows you to redact sensitive fields. This is useful when you want to log a data structure but need to redact sensitive fields like passwords, keys, or other sensitive information and do not have control over the struct definition.

rere can be used for structs you've defined yourself, but there are better approaches to tagging fields as secret in those cases. rere is best used when you need to redact data from structs you don't control.

rere does not try to be intelligent about which fields or values to redact. It takes an opinionated stance to redact only `string` and `[]byte` field and key values based on a provided allow or deny list of field and key names.

## Install

Install rere by running:

```sh
go get github.com/dustinspecker/rere
```

## Usage

rere has two functions it supports, `RedactWithAllowList` and `RedactWithDenyList`.

`RedactWithAllowList` will redact every `string` and `[]byte` it finds in a provided array, map, slice, or struct. It will not
redact any field or key names that are provided in an allow list.

`RedactWithDenyList` will skip redacting every `string` and `[]byte` it finds in a provided array, map, slice, or struct. It will
redact any field or key names are are provided in a deny list.

Both of these functions create a deep copy to avoid modifying the original value.

It is strongly recommended to only use `RedactWithAllowList` since it will prevent accidental leaks of sensitive information. Please
read the warning in [Example using a deny list](#example-using-a-deny-list) for more information.

### Example using an allow list


An example of typical usage of `rere.RedactWithAllowList` is:

```go
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
```

### Example using a deny list

An example of typical usage of `rere.RedactWithDenyList` is:

```go
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
```

**NOTE**: It is **STRONGLY** discouraged to use `RedactWithDenyList` in production code, as it is easy to accidentally miss redacting sensitive information.

Example: a struct in v1 has a field name of "Password". In v2, a new field name of "PrivateKey" is added and code is migrated from
using "Password" to "PrivateKey". If the deny list is not updated, then the new field, "PrivateKey", will not be redacted.

`RedactWithAllowList` is recommended for production code, as it is more explicit about what fields are not redacted. In the previous example,
the "PrivateKey" field would be redacted if it is not in the allow list. If a new field like "Organization" is added in v2, but
forgotten in the allow list, then the worse case is that the "Organization" field is redacted by accident, which is less severe than
leaking a "PrivateKey" field.

### More examples

More examples can be found in [examples_test.go](examples_test.go).

## How does rere work?

rere redacts values by the following process:

1. Create a deep copy of the input value
1. Traverse through any pointers to retrieve actual element value
1. Iterate and recurse through the element's struct fields, map keys, and slice/array elements
1. Use reflection to redact any field or key values that are `string` or `[]byte`
   1. For `RedactWithAllowList`, if a field or key name is found in the allow list (case insensitive), then the value is left unchanged
   1. For `RedactWithDenyList`, if a field or key name is not found in the deny list (case insensitive), then the value is left unchanged

## Why the name rere?

rere is a play on [Git's rerere](https://git-scm.com/book/en/v2/Git-Tools-Rerere). The original name for this project was rerere where it stood for "recurse, reflect, redact" (the process of how rere works). This package's exported functions, `RedactWithAllowList` and `RedactWithDenyList`, would result in a stutter, so the package name
was shortened to rere.

Also, I have a speech impediment, struggle to pronounce "re", and am my own worst enemy.

## License

MIT
