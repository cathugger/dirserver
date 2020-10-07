#!/bin/sh
export GOPATH=`go env GOPATH`:`pwd`
exec go get "$@"
