/*
 * Copyright (c) 2014, Yawning Angel <yawning at schwanenlied dot me>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

// Package transports provides a interface to query supported pluggable
// transports.
package transports // import "gitlab.com/yawning/obfs4.git/transports"

import (
	"errors"
	"fmt"
	"sync"

	"gitlab.com/yawning/obfs4.git/transports/base"
	"gitlab.com/yawning/obfs4.git/transports/meeklite"
	"gitlab.com/yawning/obfs4.git/transports/obfs2"
	"gitlab.com/yawning/obfs4.git/transports/obfs3"
	"gitlab.com/yawning/obfs4.git/transports/obfs4"
	"gitlab.com/yawning/obfs4.git/transports/scramblesuit"
)

var transportMapLock sync.Mutex
var transportMap map[string]base.Transport = make(map[string]base.Transport)

// Register registers a transport protocol.
func Register(transport base.Transport) error {
	transportMapLock.Lock()
	defer transportMapLock.Unlock()

	name := transport.Name()
	_, registered := transportMap[name]
	if registered {
		return fmt.Errorf("transport %q already registered", name)
	}
	transportMap[name] = transport

	return nil
}

// Transports returns the list of registered transport protocols.
func Transports() []string {
	transportMapLock.Lock()
	defer transportMapLock.Unlock()

	var ret []string
	for name := range transportMap {
		ret = append(ret, name)
	}

	return ret
}

// Get returns a transport protocol implementation by name.
func Get(name string) (base.Transport, error) {
	transportMapLock.Lock()
	defer transportMapLock.Unlock()

	t := transportMap[name]
	if t == nil {
		return nil, errors.New("no such transport is supported")
	}
	return t, nil
}

// Init initializes all of the integrated transports.
func Init() error {
	for _, v := range []base.Transport{
		new(meeklite.Transport),
		new(obfs2.Transport),
		new(obfs3.Transport),
		new(obfs4.Transport),
		new(scramblesuit.Transport),
	} {
		if err := Register(v); err != nil {
			return err
		}
	}

	return nil
}
