package main

import (
	"net/http"
	"strings"
)

func tarHandler(
	w http.ResponseWriter, entry string,
	node *fsnode, prev, next string) bool {

	const sfx = ".zip"

	if next == "" {
		return false
	}
	// skip leading '/'
	next = next[1:]

	if strings.IndexByte(next, '/') >= 0 ||
		!strings.HasSuffix(next, sfx) {

		return false
	}

	next = next[:len(sfx)]

	if !strings.HasSuffix(prev, next) ||
		(len(prev[:len(next)]) != 0 && prev[len(next)-1] != '/') {

		return false
	}

	return false
}
