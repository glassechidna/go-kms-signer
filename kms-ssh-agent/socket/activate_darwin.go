package socket

/*
#include <stdlib.h>
int launch_activate_socket(const char *name, int **fds, size_t *cnt);
*/
import "C"

import (
	"C"
	"errors"
	"net"
	"os"
	"unsafe"
)

// almost entirely from https://github.com/sstephenson/launch_socket_server/blob/master/src/launch/socket.go

func activateSocket(name string) ([]int, error) {
	cName := C.CString(name)
	var cFds *C.int
	cCnt := C.size_t(0)

	err := C.launch_activate_socket(cName, &cFds, &cCnt)
	if err != 0 {
		return nil, errors.New("couldn't activate launchd socket " + name)
	}

	length := int(cCnt)
	pointer := unsafe.Pointer(cFds)
	fds := (*[1 << 30]C.int)(pointer)
	result := make([]int, length)

	for i := 0; i < length; i++ {
		result[i] = int(fds[i])
	}

	C.free(pointer)
	return result, nil
}

func Files(name string) ([]*os.File, error) {
	fds, err := activateSocket(name)
	if err != nil {
		return nil, err
	}

	files := make([]*os.File, 0)
	for _, fd := range fds {
		file := os.NewFile(uintptr(fd), "")
		files = append(files, file)
	}

	return files, nil
}

func Listeners(name string) ([]net.Listener, error) {
	files, err := Files(name)
	if err != nil {
		return nil, err
	}

	listeners := make([]net.Listener, 0)
	for _, file := range files {
		listener, err := net.FileListener(file)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, listener)
	}

	return listeners, nil
}

func Listener(name string) (net.Listener, error) {
	slice, err := Listeners(name)
	if err != nil {
		return nil, err
	}

	return slice[0], nil
}
