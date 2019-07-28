package main

import (
	"reflect"
	"unsafe"
)

func unsafeStrToBytes(s string) []byte {
	sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
	bh := reflect.SliceHeader{
		Data: sh.Data,
		Len:  sh.Len,
		Cap:  sh.Len,
	}
	return *(*[]byte)(unsafe.Pointer(&bh))
}

func unsafeBytesToStr(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}
