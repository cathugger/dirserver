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

func doCompress(twx *tar.Writer, nx *fsnode, dirpfxx string) {

	var prevnodes []*fsnode

	var compressDirContents func(tw *tar.Writer, n *fsnode, dirpfx string)

	compressDirContents = func(tw *tar.Writer, n *fsnode, dirpfx string) {
		if n.fh < 0 {
			panic("not directory")
		}

		prevnodes = append(prevnodes, n)

		var hdr tar.Header

		n.lock.RLock()
		fh := n.fh
		chlist := n.chlist
		updt := n.upd
		n.lock.RUnlock()

		if dirpfx != "" {
			hdr = tar.Header{
				Name:    dirpfx,
				Mode:    0755,
				ModTime: updt,
			}
			tw.WriteHeader(&hdr)
		}

		for i := range chlist {
			nn := chlist[i].node

			hdr = tar.Header{Name: dirpfx + chlist[i].name}

			// directory
			if nn.fh >= 0 {
				// check for loop
				for _, pn := range prevnodes {
					if pn == n {
						goto loopdetected
					}
				}

				compressDirContents(tw, nn, hdr.Name)

			loopdetected:
				continue
			}

			hdr.Mode = 0644

			const oflags = int(unix.O_RDONLY)
			oh, errno := unix.Openat(int(fh), hdr.Name, oflags, 0)
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
		}

		prevnodes = prevnodes[:len(prevnodes)-1] // un-append
	}

	compressDirContents(twx, nx, dirpfxx)
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

	tw := tar.NewWriter(w)

	if next != "" {
		next += "/"
	}
	doCompress(tw, node, next)

	tw.Close()

	return true
}
