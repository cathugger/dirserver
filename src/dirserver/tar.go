package main

import (
	"archive/tar"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

func compressDirContents(tw *tar.Writer, n *fsnode, dirpfx string) {
	if n.fh < 0 {
		panic("not directory")
	}
	for i := range n.chlist {
		nn := n.chlist[i].node
		isdir := nn.fh >= 0
		hdr := tar.Header{Name: dirpfx + n.chlist[i].name}
		if !isdir {
			hdr.Mode = 0644

			const oflags = int(unix.O_RDONLY)
			oh, errno := unix.Openat(int(n.fh), hdr.Name, oflags, 0)
			if oh < 0 || errno != nil {
				// failed to open - skip
				fmt.Fprintf(
					os.Stderr,
					"got error on openat %q: %v\n",
					hdr.Name, os.NewSyscallError("openat", errno))
				continue
			}

			st := &unix.Stat_t{}
			errno = unix.Fstat(oh, st)
			if errno != nil {
				unix.Close(oh)
				fmt.Fprintf(
					os.Stderr,
					"failed to stat %q: %v\n",
					hdr.Name, os.NewSyscallError("fstatat", errno))
				continue
			}
			hdr.ModTime = extractTime(st)
			hdr.Size = st.Size

			tw.WriteHeader(&hdr)

			f := os.NewFile(uintptr(oh), "")
			_, err := io.CopyN(tw, f, st.Size)
			if err != nil {
				f.Close()
				panic("file copying failed: " + err.Error())
			}
			_ = f.Close()

		} else {
			hdr.Mode = 0755
			hdr.ModTime = nn.upd

			tw.WriteHeader(&hdr)

			compressDirContents(tw, nn, hdr.Name)
		}
	}
}

func tarHandler(
	w http.ResponseWriter, entry string,
	node *fsnode, prev, next string) bool {

	const sfx = ".tar"

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
