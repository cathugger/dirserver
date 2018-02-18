package main

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
)

type fdPoller struct {
	efd  int32    // epoll fd
	wfd  int32    // watch fd
	pfds [2]int32 // pipe fds. for wakeup
}

func newFDPoller(fd int32) (*fdPoller, error) {
	var errno error
	poller := &fdPoller{
		wfd:  fd,
		efd:  -1,
		pfds: [2]int32{-1, -1},
	}

	// create epoll object
	epfd, errno := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	poller.efd = int32(epfd)
	if epfd == -1 {
		return nil, os.NewSyscallError("epoll_create1", errno)
	}

	defer func() {
		if errno != nil {
			poller.close()
		}
	}()

	// create wakeup pipe
	var pfds [2]int
	errno = unix.Pipe2(pfds[:], unix.O_NONBLOCK|unix.O_CLOEXEC)
	poller.pfds = [2]int32{int32(pfds[0]), int32(pfds[1])}
	if errno != nil {
		return nil, os.NewSyscallError("pipe2", errno)
	}

	// register fd
	event := unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     poller.wfd,
	}
	errno = unix.EpollCtl(int(poller.efd), unix.EPOLL_CTL_ADD, int(poller.wfd), &event)
	if errno != nil {
		return nil, os.NewSyscallError("epoll_ctl", errno)
	}

	// register wakeup pipe
	event = unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     poller.pfds[0],
	}
	errno = unix.EpollCtl(int(poller.efd), unix.EPOLL_CTL_ADD, int(poller.pfds[0]), &event)
	if errno != nil {
		return nil, os.NewSyscallError("epoll_ctl", errno)
	}

	return poller, nil
}

func (p *fdPoller) wait() (bool, error) {
	// 3 theorically possible events per fd, 2 fds, 1 additional just cuz
	events := make([]unix.EpollEvent, 7)
	for {
		n, errno := unix.EpollWait(int(p.efd), events, -1)
		if n == -1 {
			if errno == unix.EINTR {
				continue
			}
			return false, os.NewSyscallError("epoll_wait", errno)
		}
		if n == 0 {
			// If there are no events, try again.
			continue
		}
		if n > 6 {
			// This should never happen. More events were returned than should be possible.
			return false, errors.New("epoll_wait returned more events than I know what to do with")
		}
		ready := events[:n]
		epollhup := false
		epollerr := false
		epollin := false
		for _, event := range ready {
			if event.Fd == int32(p.wfd) {
				if event.Events&unix.EPOLLHUP != 0 {
					// This should not happen, but if it does, treat it as a wakeup.
					epollhup = true
				}
				if event.Events&unix.EPOLLERR != 0 {
					// If an error is waiting on the file descriptor, we should pretend
					// something is ready to read, and let unix.Read pick up the error.
					epollerr = true
				}
				if event.Events&unix.EPOLLIN != 0 {
					// There is data to read.
					epollin = true
				}
			}
			if event.Fd == int32(p.pfds[0]) {
				if event.Events&unix.EPOLLHUP != 0 {
					// Write pipe descriptor was closed, by us. This means we're closing down the
					// watcher, and we should wake up.
				}
				if event.Events&unix.EPOLLERR != 0 {
					// If an error is waiting on the pipe file descriptor.
					// This is an absolute mystery, and should never ever happen.
					return false, errors.New("Error on the pipe descriptor.")
				}
				if event.Events&unix.EPOLLIN != 0 {
					// This is a regular wakeup, so we have to clear the buffer.
					err := p.clearWake()
					if err != nil {
						return false, err
					}
				}
			}
		}

		if epollhup || epollerr || epollin {
			return true, nil
		}
		return false, nil
	}
}

func (p *fdPoller) wake() error {
	buf := make([]byte, 1)
doit:
	n, errno := unix.Write(int(p.pfds[1]), buf)
	if n == -1 {
		if errno == unix.EAGAIN || errno == unix.EWOULDBLOCK {
			// buffer is full, poller will wake
			return nil
		}
		if errno == unix.EINTR {
			// retry
			goto doit
		}
		return os.NewSyscallError("write", errno)
	}
	return nil
}

func (p *fdPoller) clearWake() error {
	buf := make([]byte, 16)
	for {
		n, errno := unix.Read(int(p.pfds[0]), buf)
		if n == -1 {
			if errno == unix.EAGAIN || errno == unix.EWOULDBLOCK {
				// buffer is already cleared
				return nil
			}
			if errno == unix.EINTR {
				// retry
				continue
			}
			return os.NewSyscallError("read", errno)
		}
	}
}

func (p *fdPoller) close() {
	if p.pfds[1] != -1 {
		unix.Close(int(p.pfds[1]))
	}
	if p.pfds[0] != -1 {
		unix.Close(int(p.pfds[0]))
	}
	if p.efd != -1 {
		unix.Close(int(p.efd))
	}
}
