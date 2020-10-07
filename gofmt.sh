#!/bin/sh
export GOPATH=`go env GOPATH`:`pwd`
exec goimports -local 'dirserver/' -w src/dirserver
