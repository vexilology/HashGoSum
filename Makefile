default_build := go build .

all: install tests linux

list:
	@grep '^[^#[:space:]].*:' Makefile

linux:
	GOOS=linux GOARCH=amd64 $(default_build)
	sudo ln -sf hashgosum /usr/bin/hashgosum

win:
	GOOS=windows GOARCH=amd64 $(default_build)

macos:
	GOOS=darwin GOARCH=amd64 $(default_build)

install:
	go get github.com/cxmcc/tiger
	go get github.com/htruong/go-md2
	go get github.com/ebfe/keccak
	go get -u golang.org/x/crypto

fix:
	go get -u golang.org/x/sys/cpu

tests:
	go test -v
	cd output && go test -v
	cd algorithm && go test -bench=.
	cd algorithm && go test -v
