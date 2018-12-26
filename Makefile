ci_dependencies:
	go get -v -u honnef.co/go/tools/cmd/megacheck
	go get -v -u golang.org/x/lint/golint
	go get -v -u github.com/golang/dep/cmd/dep && dep ensure -vendor-only -v

lint:
	go fmt ./...
	go vet ./...
	megacheck $$(go list ./...)
	golint $$(go list ./...)

test:
	go test -count=1 -cover ./...

test_dev:
	go test -cover ./...

test_and_lint:
	go fmt ./...
	go vet ./...
	megacheck $$(go list ./...)
	golint $$(go list ./...)
	go test -v -race -count=1 -coverprofile=coverage.txt -covermode=atomic ./...
