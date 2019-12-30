GOFMT=gofmt
GC=go build
VERSION := $(shell git describe --always --tags --long)
BUILD_NODE_PAR = -ldflags "-X github.com/ontio/ontology/common/config.Version=$(VERSION)" #-race

ARCH=$(shell uname -m)
DBUILD=docker build
DRUN=docker run
DOCKER_NS ?= ontio
DOCKER_TAG=$(ARCH)-$(VERSION)

SRC_FILES = $(shell git ls-files | grep -e .go$ | grep -v _test.go)
TOOLS=./tools
ABI=$(TOOLS)/abi
NATIVE_ABI_SCRIPT=./cmd/abi/native_abi_script

tesrame: $(SRC_FILES)
	$(GC)  $(BUILD_NODE_PAR) -o tesrame main.go
 
all: tesrame

tesrame-cross: tesrame-windows tesrame-linux tesrame-darwin

tesrame-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GC) $(BUILD_NODE_PAR) -o tesrame-windows-amd64.exe main.go

tesrame-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GC) $(BUILD_NODE_PAR) -o tesrame-linux-amd64 main.go

tesrame-darwin:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GC) $(BUILD_NODE_PAR) -o tesrame-darwin-amd64 main.go

all-cross: tesrame-cross

format:
	$(GOFMT) -w main.go

clean:
	rm -rf *.8 *.o *.out *.6 *exe coverage
	rm -rf tesrame tesrame-*
