//go:build android

package main

/*
#include "bridge.h"
*/
import "C"

import (
	"core"
	"time"
	"unsafe"
)

type vpnCallbacks struct{}

func (vpnCallbacks) Protect(fd int) bool {
	return C.protectSocket(C.int(fd)) != 0
}

func (vpnCallbacks) ResolveUid(_ int, _, _ string) int { return -1 }
func (vpnCallbacks) ResolvePackage(_ int) string       { return "" }

//export lunarisInvoke
func lunarisInvoke(data *C.char, size C.int, responseSize *C.int) unsafe.Pointer {
	reply := make(chan []byte, 1)
	core.InvokeMethod(C.GoStringN(data, size), func(response []byte) {
		reply <- response
	})
	select {
	case response := <-reply:
		*responseSize = C.int(len(response))
		return C.CBytes(response)
	case <-time.After(15 * time.Second):
		return nil
	}
}

//export lunarisStartTun
func lunarisStartTun(fd C.int, addresses *C.char, dns *C.char) C.int {
	if core.StartTun(vpnCallbacks{}, int(fd), "gvisor", C.GoString(addresses), C.GoString(dns), `{"mtu":1500}`) {
		return 1
	}
	return 0
}

//export lunarisStopTun
func lunarisStopTun() { core.StopTun() }

//export lunarisResetNetwork
func lunarisResetNetwork() { core.ResetNetwork() }

func main() {}
