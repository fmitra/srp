lint:
	gofmt -w -s ./
	golangci-lint run -v

test:
	go test -v -cover ./...

test_and_lint:
	go test -v -race -count=1 -coverprofile=coverage.txt -covermode=atomic ./...
	gofmt -w -s ./
	golangci-lint run -v
