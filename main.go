// +build linux

package main

import (
	"net/http"
	//"github.com/fsnotify/fsnotify"
	"golang.org/x/sys/unix"
	//"github.com/rjeczalik/notify"
	//fe "github.com/tywkeene/go-fsevents"
	"flag"
	"fmt"
	ft "github.com/valyala/fasttemplate"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"text/template"
	//"path/filepath"
	"sort"
	"unsafe"
	"time"
	"bytes"
)

type fsnode struct {
	lock   sync.RWMutex
	chmap  map[string]*fsnode
	chlist []fsnamed
	papas  []*fsnode
	upd    time.Time
	fh     int32
	wd     int32
}

type fsnamed struct {
	name  []byte  // filename. includes / for dirs.
	lname []byte  // path-escaped, for use with links
	node  *fsnode // nod nod nod
}

func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	np := path.Clean(p)
	// path.Clean removes trailing slash except for root;
	// put the trailing slash back if necessary.
	if p[len(p)-1] == '/' && np != "/" {
		np += "/"
	}
	return np
}

var (
	prefix   string
	rootnode *fsnode
	//lock   sync.RWMutex
	tbegin *ft.Template
	tlist  *ft.Template
	tend   *ft.Template
)

func servefolder(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "HEAD" {
		http.Error(w, "405 method not allowed", 405)
		return
	}
	np := cleanPath(r.URL.Path)
	if np != r.URL.Path {
		url := *r.URL
		url.Path = np
		http.Redirect(w, r, url.String(), http.StatusTemporaryRedirect)
		return
	}
	pf := r.URL.Path
	if len(pf) < len(prefix) || pf[:len(prefix)] != prefix || pf[len(pf)-1] != '/' {
		http.Error(w, "500 we're not supposed to serve this", 500)
		return
	}
	pp := pf[len(prefix):]
	pc := pp
	cn := rootnode

	cn.lock.RLock()
	// walk to node we want
	for {
		is := strings.IndexByte(pc, '/')
		if is < 0 {
			break
		}
		ch := cn.chmap[pc[:is]]
		if ch == nil || ch.fh == -1 {
			cn.lock.RUnlock()
			http.NotFound(w, r)
			return
		}
		pc = pc[is+1:]
		cn.lock.RUnlock()
		cn = ch
		cn.lock.RLock()
	}
	defer cn.lock.RUnlock()
	// XXX check not modified headers?
	// print stuff
	/*
	 * XXX could be one template embeding another
	 * but that'd be useless without ability to specify multiple
	 * child templates. and im too lazy for that
	 */
	fg := func(w io.Writer, tag string) (int, error) {
		switch tag {
		case "uf":
			return w.Write([]byte(pf))
		case "lf":
			return w.Write([]byte((&url.URL{Path: pf}).EscapedPath()))
		case "hf":
			template.HTMLEscape(w, []byte(pf))
		case "jf":
			template.JSEscape(w, []byte(pf))
		}
		return 0, nil
	}
	tbegin.ExecuteFunc(w, fg)
	for i := range cn.chlist {
		chname := cn.chlist[i].name
		chlname := cn.chlist[i].lname
		fc := func(w io.Writer, tag string) (int, error) {
			switch tag {
			case "un":
				return w.Write(chname)
			case "ln":
				return w.Write(chlname)
			case "hn":
				template.HTMLEscape(w, chname)
			case "jn":
				template.JSEscape(w, chname)
			}
			return 0, nil
		}
		tlist.ExecuteFunc(w, fc)
	}
	tend.ExecuteFunc(w, fg)
}

var servedir string

func loadAllToStrs(dir string, files ...string) (res []string, err error) {
	for _, f := range files {
		var buf []byte
		buf, err = ioutil.ReadFile(path.Join(dir, f))
		if err != nil {
			return res, fmt.Errorf("error reading %s: %v", f, err)
		}
		res = append(res, string(buf))
	}
	return
}

type bindst []string

func (b *bindst) Set(v string) error {
	*b = strings.Split(v, ",")
	return nil
}

func (b bindst) String() string {
	return strings.Join(b, ",")
}

var listendir string

var (
	notifyMap     = make(map[int32]*fsnode)
	notyfyMapLock sync.RWMutex
)


type Event struct {
	name []byte
	raw unix.InotifyEvent
}

var watchToNode = make(map[int32]*fsnode)

func sortNode(n *fsnode) {
	cl := n.chlist
	sort.Slice(cl, func(i, j int) bool {
		d1 := cl[i].node.fh != -1
		d2 := cl[j].node.fh != -1
		if d1 && !d2 {
			return true
		}
		if !d1 && d2 {
			return false
		}
		return string(cl[i].name) < string(cl[j].name)
	})
}

// process inotify events
func eventProcessor(ch <-chan Event) {
	var err error
	var wd int32
	var n *fsnode
	var oknode bool
	var movenode *fsnode
	var moveCookie uint32
	for {
		if n != nil {
			n.lock.Unlock()
		}
		ev := <-ch
		killmovenode := func() {
			if movenode != nil {
				fmt.Fprintf(os.Stderr, "dbg: killing move node\n")
				killNode(movenode)
				movenode = nil
				moveCookie = 0
			}
		}
		if ev.raw.Mask & unix.IN_Q_OVERFLOW != 0 {
			killmovenode()
			// event queue overflowed. warn. assume we're in inconsistent state
			fmt.Fprintf(os.Stderr, "inotify queue overflowed\n")
			continue
		}
		dir := ev.raw.Mask & unix.IN_ISDIR != 0
		n, oknode = watchToNode[ev.raw.Wd]
		if !oknode {
			killmovenode()
			fmt.Fprintf(os.Stderr, "received event on unknown watch descriptor %d, name(%q), dir(%t), mask(0x%08X)\n",
				ev.raw.Wd, ev.name, dir, ev.raw.Mask)
			
			// we wouldn't know what to do with it
			continue
		}
		n.lock.Lock()
		
		if n.wd != ev.raw.Wd {
			panic("wrong wd mapping")
		}
		
		if ev.raw.Mask & unix.IN_IGNORED != 0 {
			killmovenode()
			fmt.Fprintf(os.Stderr, "dbg: ignore event, name(%s), wd(%d)\n", ev.name, ev.raw.Wd)
			// watch was removed
			n.wd = -1
			delete(watchToNode, ev.raw.Wd)
			continue // XXX?
		}
		if n.fh == -1 {
			killmovenode()
			fmt.Fprintf(os.Stderr, "dbg: event on dead or non-dir node, name(%s)\n", ev.name)
			continue
		}
		
		handlecreate := func() {
			namesl := append(ev.name, '/')
			old := n.chmap[string(ev.name)]
			delold := func() {
				fmt.Fprintf(os.Stderr, "dbg: deleting old node\n")
				delete(n.chmap, string(ev.name))
				for i := range old.papas {
					if old.papas[i] == n {
						old.papas = append(old.papas[:i], old.papas[i+1:]...)
						break // remove only one of them
					}
				}
				var dnam []byte
				if old.fh == -1 {
					// what we search for was file
					dnam = ev.name
				} else {
					// what we search for was dir
					dnam = namesl
				}
				for i := range n.chlist {
					if string(n.chlist[i].name) == string(dnam) {
						n.chlist = append(n.chlist[:i], n.chlist[i+1:]...)
						break
					}
				}
				killNode(old)
			}
			// open handle which can persist
			var oflags = int(unix.O_RDONLY | unix.O_PATH) // intentionally follow symlinks
			oh, errno := unix.Openat(int(n.fh), string(ev.name), oflags, 0)
			if oh == -1 {
				fmt.Fprintf(os.Stderr, "ignoring, got error on openat: %v\n", os.NewSyscallError("openat", errno))
				if old != nil {
					delold()
				}
				return
			}
			// we should get more info about it. dir flag can lie incase of symlinks
			st := &unix.Stat_t{}
			errno = unix.Fstatat(oh, "", st, unix.AT_EMPTY_PATH) // intentionally follow symlinks
			if errno != nil {
				unix.Close(oh)
				fmt.Fprintf(os.Stderr, "failed to stat %q: %v\n", ev.name, os.NewSyscallError("fstatat", errno))
				if old != nil {
					delold()
				}
				return
			}
			ft := st.Mode & unix.S_IFMT
			if ft == unix.S_IFDIR {
				// dir is kinda ready, just attach watch and scan it
				wd, err = addWatch(int32(oh))
				if wd == -1 {
					fmt.Fprintf(os.Stderr, "bogus, error trying to add watch for %q: %v\n", ev.name, err)
				}
				
				if old != nil {
					if old.fh == -1 {
						// old was file. rid of it
						delold()
						// continue adding
					} else {
						// old was some dir. check if it's same
						if wd != -1 && wd == old.wd {
							// it's same. we already have it
							unix.Close(oh)
							return
						} else {
							// oh? it apparently is different dir now
							// get rid of old one, taking up its name
							delold()
							// continue adding
						}
					}
				}
				
				var nn *fsnode
				if wd != -1 {
					nn = watchToNode[wd]
					if nn != nil {
						unix.Close(oh) // no longer needed. we already have different handle to this
						nn.papas = append(nn.papas, n)
						// XXX update other stuff in file
					}
				}
				if nn == nil {
					nn = &fsnode{
						upd: time.Time{}, // XXX
						fh: int32(oh),
						wd: wd,
						chmap: make(map[string]*fsnode),
						papas: []*fsnode{n},
					}
					if wd != -1 {
						watchToNode[wd] = nn
						scanDir(nn)
					}
				}
				n.chlist = append(n.chlist, fsnamed{
					name: namesl,
					lname: []byte((&url.URL{Path: string(namesl)}).EscapedPath()),
					node: nn,
				})
				n.chmap[string(ev.name)] = nn
				
				sortNode(n)
			} else {
				unix.Close(oh) // non-dirs dont need it
				if ft == unix.S_IFREG {
					fmt.Fprintf(os.Stderr, "dbg: %q is regular, adding\n", ev.name)
					// normal file
					if old != nil {
						// old exists
						if old.fh != -1 {
							// old was dir. delet
							delold()
							// continue adding
						} else {
							// old and new are files. just update
							// XXX
							return
						}
					}
					nn := &fsnode{
						upd: time.Time{}, // XXX
						fh: -1,
						wd: -1,
						papas: []*fsnode{n},
					}
					n.chlist = append(n.chlist, fsnamed{
						name: ev.name,
						lname: []byte((&url.URL{Path: string(ev.name)}).EscapedPath()),
						node: nn,
					})
					n.chmap[string(ev.name)] = nn
					sortNode(n)
				} else {
					fmt.Fprintf(os.Stderr, "dbg: %q is irregular(0x%04X), expunge\n", ev.name, ft)
					// oddity. delet old if exists, dont add
					if old != nil {
						delold()
					}
				}
			}
			return
		}
		if ev.raw.Mask & unix.IN_MOVED_TO != 0 {
			// file/dir was moved to
			fmt.Fprintf(os.Stderr, "dbg: moved to, name(%s), dir(%t), cookie(%d)\n", ev.name, dir, ev.raw.Cookie)
			if movenode != nil {
				fmt.Fprintf(os.Stderr, "dbg: found old move node\n")
				if moveCookie != ev.raw.Cookie {
					fmt.Fprintf(os.Stderr, "dbg: old move cookie(%d) does not match new. dropping\n", moveCookie)
					killmovenode()
				} else {
					// all checks out, just put it in
					movenode.papas = append(movenode.papas, n)
					var nam []byte
					if movenode.fh == -1 {
						nam = ev.name
					} else {
						nam = append(ev.name, '/')
					}
					n.chlist = append(n.chlist, fsnamed{
						name: nam,
						lname: []byte((&url.URL{Path: string(nam)}).EscapedPath()),
						node: movenode,
					})
					n.chmap[string(ev.name)] = movenode
					movenode = nil
					sortNode(n)
					continue
				}
			}
			fmt.Fprintf(os.Stderr, "dbg: handling move as creation\n")
			handlecreate()
			continue
		}
		killmovenode()
		if ev.raw.Mask & unix.IN_CREATE != 0 {
			// file/dir was made
			fmt.Fprintf(os.Stderr, "dbg: create event, name(%s), dir(%t)\n", ev.name, dir)
			handlecreate()
			continue
		}
		handledelete := func() {
			old, ok := n.chmap[string(ev.name)]
			if ok {
				delete(n.chmap, string(ev.name))
			}
			if old != nil {
				for i := range old.papas {
					if old.papas[i] == n {
						old.papas = append(old.papas[:i], old.papas[i+1:]...)
						break // remove only one of them
					}
				}
				var dnam []byte
				if old.fh == -1 {
					// what we search for was file
					dnam = ev.name
				} else {
					// what we search for was dir
					dnam = append(ev.name, '/')
				}
				for i := range n.chlist {
					if string(n.chlist[i].name) == string(dnam) {
						n.chlist = append(n.chlist[:i], n.chlist[i+1:]...)
						break
					}
				}
				killNode(old)
			}
		}
		if ev.raw.Mask & unix.IN_DELETE != 0 {
			// file/dir was deleted
			fmt.Fprintf(os.Stderr, "dbg: delete event, name(%s), dir(%t)\n", ev.name, dir)
			handledelete()
			continue
		}
		if ev.raw.Mask & unix.IN_MOVED_FROM != 0 {
			// file/dir was moved from
			fmt.Fprintf(os.Stderr, "dbg: moved from, name(%s), dir(%t), cookie(%d)\n", ev.name, dir, ev.raw.Cookie)
			old, ok := n.chmap[string(ev.name)]
			if ok {
				delete(n.chmap, string(ev.name))
			}
			if old != nil {
				for i := range old.papas {
					if old.papas[i] == n {
						old.papas = append(old.papas[:i], old.papas[i+1:]...)
						break // remove only one of them
					}
				}
				var dnam []byte
				if old.fh == -1 {
					// what we search for was file
					dnam = ev.name
				} else {
					// what we search for was dir
					dnam = append(ev.name, '/')
				}
				for i := range n.chlist {
					if string(n.chlist[i].name) == string(dnam) {
						n.chlist = append(n.chlist[:i], n.chlist[i+1:]...)
						break
					}
				}
				movenode = old
				moveCookie = ev.raw.Cookie
			}
			continue
		}
	}
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
		buf [unix.SizeofInotifyEvent * 4096]byte // Buffer for a maximum of 4096 raw events
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
			var name []byte
			if nameLen > 0 {
				bname := (*[unix.PathMax]byte)(unsafe.Pointer(&buf[offset+unix.SizeofInotifyEvent]))
				if i := bytes.IndexByte(bname[:nameLen], '\000'); i >= 0 {
					name = bname[:i]
				} else {
					name = bname[:nameLen]
				}
			}
			ch <- Event{name: append([]byte(nil), name...), raw: *ev}
			offset += unix.SizeofInotifyEvent + nameLen
		}
	}
}

var gwatcher *watcher

func addWatch(h int32) (int32, error) {
	if h == -1 {
		panic("handle cannot be negative")
	}
	errno := unix.Fchdir(int(h))
	if errno != nil {
		return -1, fmt.Errorf("failed to chdir: %v\n", os.NewSyscallError("fchdir", errno))
	}
	inflags := uint32(unix.IN_ATTRIB | unix.IN_CLOSE_WRITE |
		unix.IN_CREATE | unix.IN_DELETE | unix.IN_MOVE |
		unix.IN_EXCL_UNLINK)
	wd, errno := unix.InotifyAddWatch(int(gwatcher.ifd), ".", inflags)
	if wd == -1 {
		return -1, fmt.Errorf("error adding watch: %v\n", os.NewSyscallError("inotify_add_watch", errno))
	}
	return int32(wd), nil
}

func killNode(n *fsnode) {
	if len(n.papas) != 0 {
		fmt.Fprintf(os.Stderr, "not killing killing node wd(%d), fh(%d) because it has papas\n", n.wd, n.fh)
		return
	}
	fmt.Fprintf(os.Stderr, "killing node wd(%d), fh(%d)\n", n.wd, n.fh)
	if n.wd != -1 {
		unix.InotifyRmWatch(int(gwatcher.ifd), uint32(n.wd))
	}
	if n.fh != -1 {
		unix.Close(int(n.fh))
		n.fh = -1
	}
	for _, cln := range n.chlist {
		nn := cln.node
		for i, p := range nn.papas {
			if p == n {
				nn.papas = append(nn.papas[:i], nn.papas[i+1:]...)
				break // delet only one
			}
		}
		killNode(nn)
	}
	n.chlist = nil
}

func scanDir(n *fsnode) {
	n.lock.Lock()
	defer n.lock.Unlock()
	
	var err error

	if n.fh == -1 {
		fmt.Fprintf(os.Stderr, "directory file handle is -1, cannot scan\n")
		return
	}
	// reuse its handle to open dir reading handle
	dh, errno := unix.Openat(int(n.fh), ".", unix.O_RDONLY | unix.O_DIRECTORY, 0)
	if dh == -1 {
		fmt.Fprintf(os.Stderr, "failed to open dir for listing, err: %v\n", os.NewSyscallError("openat", errno))
		return
	}
	f := os.NewFile(uintptr(dh), "")
	names, err := f.Readdirnames(-1)
	f.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to scan dir filenames, err: %v\n", err)
		return
	}
	st := &unix.Stat_t{}
	for _, fn := range names {
		if fn == "." || fn == ".." {
			continue
		}
		namesl := fn + "/"
		old := n.chmap[fn]
		delold := func() {
			fmt.Fprintf(os.Stderr, "dbg: deleting old")
			delete(n.chmap, fn)
			for i := range old.papas {
				if old.papas[i] == n {
					old.papas = append(old.papas[:i], old.papas[i+1:]...)
					break // remove only one of them
				}
			}
			var dnam string
			if old.fh == -1 {
				// what we search for was file
				dnam = fn
			} else {
				// what we search for was dir
				dnam = namesl
			}
			for i := range n.chlist {
				if string(n.chlist[i].name) == dnam {
					n.chlist = append(n.chlist[:i], n.chlist[i+1:]...)
					break
				}
			}
			killNode(old)
		}
		fmt.Fprintf(os.Stderr, "dbg: discovered file %q\n", fn)
		fh, errno := unix.Openat(int(n.fh), fn, unix.O_RDONLY | unix.O_PATH, 0) // follow symlinks
		if fh == -1 {
			fmt.Fprintf(os.Stderr, "failed to open child dir %q, err: %v\n", fn, os.NewSyscallError("openat", errno))
			if old != nil {
				delold()
			}
			continue
		}
		*st = unix.Stat_t{}
		errno = unix.Fstatat(fh, "", st, unix.AT_EMPTY_PATH) // follow symlinks
		if errno != nil {
			unix.Close(fh)
			fmt.Fprintf(os.Stderr, "failed to stat %q: %v\n", fn, os.NewSyscallError("fstatat", errno))
			if old != nil {
				delold()
			}
			continue
		}
		ft := st.Mode & unix.S_IFMT
		if ft == unix.S_IFREG {
			fmt.Fprintf(os.Stderr, "%q is regular\n", fn)
			unix.Close(fh)
			if old != nil {
				if old.fh != -1 {
					// old was directory. fugged
					fmt.Fprintf(os.Stderr, "%q: removing old node which was directory\n", fn)
					delold()
					// now continue adding
				} else {
					// old was file aswell. dont add new, update old
					fmt.Fprintf(os.Stderr, "%q: old node is same file, leaving\n", fn)
					continue
				}
			}
			nn := &fsnode{
				upd: time.Time{}, // XXX
				fh: -1,
				wd: -1,
				papas: []*fsnode{n},
			}
			n.chlist = append(n.chlist, fsnamed{
				name: []byte(fn),
				lname: []byte((&url.URL{Path: fn}).EscapedPath()),
				node: nn,
			})
			n.chmap[fn] = nn
			
			continue
		} else if ft == unix.S_IFDIR {
			fmt.Fprintf(os.Stderr, "%q is directory\n", fn)
			var wd int32
			wd, err = addWatch(int32(fh))
			if wd == -1 {
				fmt.Fprintf(os.Stderr, "failed to watch new %q: %v\n", fn, err)
			}
			if old != nil {
				if old.fh == -1 {
					// old was file. fugged
					fmt.Fprintf(os.Stderr, "%q: removing old node which was file\n", fn)
					delold()
					// now continue adding
				} else {
					// old was dir aswell.. we should check if it's same dir tho by adding watch
					if wd != -1 && old.wd == wd {
						fmt.Fprintf(os.Stderr, "%q: old node is same dir, leaving\n", fn)
						// ok it's same dir. update it. dont add new.
						unix.Close(fh)
						continue
					} else {
						// oh?
						fmt.Fprintf(os.Stderr, "%q: old node was different dir, removing it\n", fn)
						// stuff is out of sync at this point. remove old dir
						delold()
						// continue adding
					}
				}
			}
			
			
			
			var nn *fsnode
			if wd != -1 {
				nn = watchToNode[wd]
				if nn != nil {
					unix.Close(fh) // no longer needed. we already have different handle to this
					nn.papas = append(nn.papas, n)
					// XXX update other stuff in file
				}
			}
			if nn == nil {
				nn = &fsnode{
					upd: time.Time{}, // XXX
					fh: int32(fh),
					wd: wd,
					chmap: make(map[string]*fsnode),
					papas: []*fsnode{n},
				}
				if wd != -1 {
					watchToNode[wd] = nn
					scanDir(nn)
				}
			}
			n.chlist = append(n.chlist, fsnamed{
				name: []byte(namesl),
				lname: []byte((&url.URL{Path: namesl}).EscapedPath()),
				node: nn,
			})
			n.chmap[fn] = nn
			
			continue
		} else if ft == unix.S_IFLNK {
			fmt.Fprintf(os.Stderr, "%q is link(0x%04X)\n", fn, ft)
			unix.Close(fh)
		} else {
			fmt.Fprintf(os.Stderr, "%q is unknown 0x%04X\n", fn, ft)
			unix.Close(fh)
		}
		if old != nil {
			fmt.Fprintf(os.Stderr, "%q: removing old node\n", fn)
			delold()
		}
	}

	sortNode(n)
}

func main() {
	binds := bindst{}
	flag.Var(&binds, "http", "http bind")
	flag.StringVar(&prefix, "prefix", "/", "where root starts")
	flag.StringVar(&servedir, "root", "./data", "root directory")
	tmpldir := flag.String("tmpldir", "./tmpl", "template directory")
	flag.Parse()
	if len(prefix) == 0 || prefix[len(prefix)-1] != '/' {
		prefix += "/"
	}
	if len(binds) == 0 {
		fmt.Fprintln(os.Stderr, "please specify atleast one bind")
		return
	}

	fs, e := loadAllToStrs(*tmpldir, "head.tmpl", "list.tmpl", "tail.tmpl")
	if e != nil {
		fmt.Fprintf(os.Stderr, "error reading tamplates: %v\n", e)
		return
	}
	tbegin = ft.New(fs[0], "{{", "}}")
	tlist = ft.New(fs[1], "{{", "}}")
	tend = ft.New(fs[2], "{{", "}}")

	//go indexer()
	w, e := newWatcher()
	if e != nil {
		fmt.Fprintf(os.Stderr, "error creating watcher: %v\n", e)
		return
	}
	gwatcher = w
	ch := make(chan Event, 1024)
	
	dh, errno := unix.Open(servedir, unix.O_RDONLY | unix.O_DIRECTORY | unix.O_PATH, 0)
	if dh == -1 {
		fmt.Fprintf(os.Stderr, "error opening watch dir: %v\n", errno)
		return
	}
	wd, e := addWatch(int32(dh))
	if e != nil {
		fmt.Fprintf(os.Stderr, "error adding watch: %v\n", e)
		return
	}
	rootnode = &fsnode{
		fh: int32(dh),
		wd: wd,
		chmap: make(map[string]*fsnode),
	}
	watchToNode[wd] = rootnode
	
	scanDir(rootnode)
	
	go eventProcessor(ch)
	go w.watch(ch)

	var wg sync.WaitGroup
	wg.Add(len(binds))
	for _, b := range binds {
		go func(bind string) {
			_ = http.ListenAndServe(bind, http.HandlerFunc(servefolder))
			wg.Done()
		}(b)
	}
	wg.Wait()
}
