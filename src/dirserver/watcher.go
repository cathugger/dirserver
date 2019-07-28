// +build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

type Event struct {
	name string // this needs to be copied either way so mem alloc needs to happen
	raw  unix.InotifyEvent
}

type watcher struct {
	ifd int32
	plr *fdPoller
}

func newWatcher() (*watcher, error) {
	// initialise inotify watcher. nonblocking, as we will use epoll to watch it
	fd, errno := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if fd == -1 {
		return nil, os.NewSyscallError("inotify_init1", errno)
	}

	plr, err := newFDPoller(int32(fd))
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("newFDPoller failed: %v", err)
	}

	w := &watcher{
		ifd: int32(fd),
		plr: plr,
	}
	return w, nil
}

// channel write should not block
func (w *watcher) watch(ch chan<- Event) {
	var (
		buf   [unix.SizeofInotifyEvent * 4096]byte // Buffer for a maximum of 4096 raw events
		ok    bool
		errno error
		n     int
	)

	// recursively
	// 1. lock current node (or all tree)
	// 2. start listening on current node
	// 3. list directory under current node
	// 4. add directory list to current node's children
	// 5. sort current node's children
	// 6. unlock current node (or all tree)
	// 7. if not async, process inotify events

	// there can be race when renaming directories
	// 1. add big directory xxx/yyy/zzz
	// 2. add directory xxx/yyy/eee
	// 3. move xxx/yyy to xxx/hhh
	// now after we finish parsing 1st on 2nd we will fail because our knowledge about FS is out of sync
	// for that, lets keep folder handles
	// also only use openat to open folders
	// if we fail to open, we will succeed by interpreting undefined->defined move operation
	// therefore if we fail to find move source, act as if we got new folder and try to open it
	// if things keep moving, we will settle eventually anyway
	// keeping folder handle may be a bit costy
	// but it's the only sane way I can think of to keep things in sync
	// as it allows very comfortable openat logic

	for {
		ok, errno = w.plr.wait()
		if errno != nil {
			fmt.Fprintf(os.Stderr, "poller fail: %v\n", errno)
			return // XXX
		}
		if !ok {
			continue
		}
	readin:
		n, errno = unix.Read(int(w.ifd), buf[:])
		if n == -1 {
			if errno == unix.EINTR {
				goto readin
			}
			if errno == unix.EAGAIN || errno == unix.EWOULDBLOCK {
				continue
			}
			fmt.Fprintf(os.Stderr, "failed readinf from inotify fd: %v\n", os.NewSyscallError("read", errno))
			return // XXX
		}
		if n < unix.SizeofInotifyEvent {
			if n == 0 {
				// whu
				fmt.Fprintf(os.Stderr, "EOF read on inotify fd\n")
			} else {
				fmt.Fprintf(os.Stderr, "too short (got %d, want %d) read on inotify fd\n", n, unix.SizeofInotifyEvent)
			}
			continue
		}
		offset := uint32(0)
		for offset <= uint32(n-unix.SizeofInotifyEvent) {
			ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
			nameLen := ev.Len
			var xname []byte
			if nameLen > 0 {
				bname := (*[unix.PathMax]byte)(unsafe.Pointer(&buf[offset+unix.SizeofInotifyEvent]))
				if i := bytes.IndexByte(bname[:nameLen], 0); i >= 0 {
					xname = bname[:i]
				} else {
					xname = bname[:nameLen]
				}
			}
			ch <- Event{name: string(xname), raw: *ev}
			offset += unix.SizeofInotifyEvent + nameLen
		}
	}
}

func (w *watcher) addWatch(h int32) (int32, error) {
	if h == -1 {
		panic("handle cannot be negative")
	}

	dirlock.Lock()
	defer dirlock.Unlock()

	errno := unix.Fchdir(int(h))
	if errno != nil {
		return -1, fmt.Errorf("failed to chdir: %v\n", os.NewSyscallError("fchdir", errno))
	}
	inflags := uint32(unix.IN_ATTRIB | unix.IN_CLOSE_WRITE |
		unix.IN_CREATE | unix.IN_DELETE | unix.IN_MOVE |
		unix.IN_EXCL_UNLINK)
	wd, errno := unix.InotifyAddWatch(int(w.ifd), ".", inflags)
	if wd == -1 {
		return -1, fmt.Errorf("error adding watch: %v\n", os.NewSyscallError("inotify_add_watch", errno))
	}
	return int32(wd), nil
}
