ci_dependencies:
	go get -v -u honnef.co/go/tools/cmd/megacheck
	go get -v -u golang.org/x/lint/golint
	go get -v -u github.com/golang/dep/cmd/dep && dep ensure -vendor-only -v

docker_dependencies:
	go get -v -u github.com/golang/dep/cmd/dep && dep ensure -vendor-only -v

lint:
	go fmt ./...
	go vet ./...
	megacheck $$(go list ./...)
	golint $$(go list ./...)

test_dev:
	# Run entire test suite with caching enabled for repeat tests
	go test -p=1 -cover ./...

test_and_lint:
	go fmt ./...
	go vet ./...
	megacheck $$(go list ./...)
	golint $$(go list ./...)
	# Verbose test with coverage, race condition checks and cache disabled
	go test -p=1 -count=1 -v -race -coverprofile=coverage.txt -covermode=atomic ./...

build:
	CGO_ENABLED=0 GOOS=linux go build -v -a -installsuffix cgo -ldflags '-s' -o auth-gate ./cmd/auth-gate
