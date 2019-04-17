all: dep build

build:
	go build -o snyk-filter

install:
	go build -o ${GOPATH}/bin/snyk-filter

dep:
	GO111MODULE=on GOFLAGS=-mod=vendor go mod vendor -v

release:
	GOOS=linux go build -o snyk-filter_linux
	GOOS=darwin go build -o snyk-filter_mac

.PHONY: install test build
