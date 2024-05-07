serve-docs:
	godoc -http=:6060

test:
	go test -test.v ./...
