lint:
	ENABLE_LINTERS=$(ENABLE_LINTERS) ./scripts/lint.sh

serve-docs:
	godoc -http=:6060

test:
	go test -test.v ./...
