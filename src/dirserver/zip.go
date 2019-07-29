package main

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

func zipCompress(twx *zip.Writer, nx *fsnode, dirpfxx string) {

	var prevnodes []*fsnode

	var packDirContents func(tw *zip.Writer, n *fsnode, dirpfx string)

	packDirContents = func(tw *zip.Writer, n *fsnode, dirpfx string) {
		if n.fh < 0 {
			panic("not directory")
		}

		prevnodes = append(prevnodes, n)

		n.lock.RLock()
		fh := n.fh
		// copy 1 lvl of contents
		chlist := make([]fsnamed, len(n.chlist))
		copy(chlist, n.chlist)
		updt := n.upd
		n.lock.RUnlock()

		if dirpfx != "" {
			hdr := &zip.FileHeader{
				Name:     dirpfx,
				Modified: updt,
			}
			tw.CreateHeader(hdr)
		}

		for i := range chlist {
			nn := chlist[i].node
			name := chlist[i].name
			fullname := dirpfx + name

			// directory
			if nn.fh >= 0 {
				// check for loop
				for _, pn := range prevnodes {
					if pn == nn {
						goto loopdetected
					}
				}

				packDirContents(tw, nn, fullname)

			loopdetected:
				continue
			}

			hdr := &zip.FileHeader{Name: fullname}

			const oflags = int(unix.O_RDONLY)
			oh, errno := unix.Openat(int(fh), name, oflags, 0)
			if oh < 0 || errno != nil {
				// failed to open - skip
				fmt.Fprintf(
					os.Stderr,
					"got error on openat %q: %v\n",
					name, os.NewSyscallError("openat", errno))
				continue
			}

			st := &unix.Stat_t{}
			errno = unix.Fstat(oh, st)
			if errno != nil {
				unix.Close(oh)
				fmt.Fprintf(
					os.Stderr,
					"failed to stat %q: %v\n",
					name, os.NewSyscallError("fstatat", errno))
				continue
			}
			hdr.Modified = extractTime(st)

			pw, err := tw.CreateHeader(hdr)
			if err != nil {
				unix.Close(oh)
				panic("CreateHeader err: " + err.Error())
			}

			f := os.NewFile(uintptr(oh), "")
			_, err = io.Copy(pw, f)
			if err != nil {
				f.Close()
				panic("file copying failed: " + err.Error())
			}
			_ = f.Close()
		}

		prevnodes = prevnodes[:len(prevnodes)-1] // un-append
	}

	packDirContents(twx, nx, dirpfxx)
}

func zipHandler(
	w http.ResponseWriter, entry string,
	node *fsnode, prev, next string) bool {

	const sfx = ".zip"

	if next == "" {
		fmt.Fprintf(os.Stderr, "zip: next is empty\n")
		return false
	}

	if strings.IndexByte(next[1:], '/') >= 0 || !strings.HasSuffix(next, sfx) {
		fmt.Fprintf(os.Stderr, "zip: next %q not suitable\n", next)
		return false
	}

	next = next[:len(next)-len(sfx)]

	if !strings.HasSuffix(prev, next) {
		fmt.Fprintf(os.Stderr, "zip: prev %q not matching next %q\n", prev, next)
		return false
	}

	tw := zip.NewWriter(w)

	next = next[1:] // skip leading '/'
	if next != "" {
		next += "/" // need trailing / to indicate dir
	}
	zipCompress(tw, node, next)

	tw.Close()

	return true
}
