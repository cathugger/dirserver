#!/bin/sh
GOPATH="$PWD" exec goimports -local 'dirserver/' -w src/dirserver
