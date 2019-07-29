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

func tarPack(twx *tar.Writer, nx *fsnode, dirpfxx string) {

	var prevnodes []*fsnode
	var hdr tar.Header

	var packDirContents func(tw *tar.Writer, n *fsnode, dirpfx string)

	packDirContents = func(tw *tar.Writer, n *fsnode, dirpfx string) {
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
			hdr = tar.Header{
				Name:    dirpfx,
				Mode:    0755,
				ModTime: updt,
			}
			tw.WriteHeader(&hdr)
		}

		for i := range chlist {
			nn := chlist[i].node
			name := chlist[i].name
			fullname := dirpfx + name

			// directory
			if nn.fh >= 0 {
				// check for loop
				for _, pn := range prevnodes {
					if pn == n {
						goto loopdetected
					}
				}

				packDirContents(tw, nn, fullname)

			loopdetected:
				continue
			}

			hdr = tar.Header{Name: fullname, Mode: 0644}

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
			hdr.ModTime = extractTime(st)
			hdr.Size = st.Size

			err := tw.WriteHeader(&hdr)
			if err != nil {
				unix.Close(oh)
				panic("WriteHeader err: " + err.Error())
			}

			f := os.NewFile(uintptr(oh), "")
			_, err = io.CopyN(tw, f, st.Size)
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

func tarHandler(
	w http.ResponseWriter, entry string,
	node *fsnode, prev, next string) bool {

	const sfx = ".tar"

	if next == "" {
		fmt.Fprintf(os.Stderr, "tar: next is empty\n")
		return false
	}

	if strings.IndexByte(next[1:], '/') >= 0 || !strings.HasSuffix(next, sfx) {
		fmt.Fprintf(os.Stderr, "tar: next %q not suitable\n", next)
		return false
	}

	next = next[:len(next)-len(sfx)]

	if !strings.HasSuffix(prev, next) {
		fmt.Fprintf(os.Stderr, "tar: prev %q not matching next %q\n", prev, next)
		return false
	}

	tw := tar.NewWriter(w)

	next = next[1:] // skip leading '/'
	if next != "" {
		next += "/" // need trailing / to indicate dir
	}
	tarPack(tw, node, next)

	tw.Close()

	return true
}
