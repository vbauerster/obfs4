/*
 * Copyright (c) 2015, Yawning Angel <yawning at schwanenlied dot me>
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

package socks5

import (
	"errors"
)

const (
	authRFC1929Ver     = 0x01
	authRFC1929Success = 0x00
	authRFC1929Fail    = 0x01
)

func (req *Request) authRFC1929() (err error) {
	status := byte(authRFC1929Fail)
	defer func() {
		resp := []byte{authRFC1929Ver, status}
		if _, ew := req.rw.Write(resp); err == nil {
			if ew != nil {
				err = ew
			} else {
				err = req.flushBuffers()
			}
		} else if ew == nil {
			// Swallow write/flush errors, the auth failure is the relevant error
			_ = req.flushBuffers()
		}
	}()

	// The client sends a Username/Password request.
	//  uint8_t ver (0x01)
	//  uint8_t ulen (>= 1)
	//  uint8_t uname[ulen]
	//  uint8_t plen (>= 1)
	//  uint8_t passwd[plen]

	err = req.readByteVerify("auth version", authRFC1929Ver)
	if err != nil {
		return err
	}

	// Read the username.
	ulen, err := req.readByte()
	if err != nil {
		return err
	} else if ulen < 1 {
		return errors.New("username with 0 length")
	}
	uname := make([]byte, ulen)
	if _, err = req.readFull(uname); err != nil {
		return err
	}

	// Read the password.
	plen, err := req.readByte()
	if err != nil {
		return err
	} else if plen < 1 {
		return errors.New("password with 0 length")
	}
	passwd := make([]byte, plen)
	if _, err = req.readFull(passwd); err != nil {
		return err
	}

	// Pluggable transports use the username/password field to pass
	// per-connection arguments.  The fields contain ASCII strings that
	// are combined and then parsed into key/value pairs.
	if !(plen == 1 && passwd[0] == 0x00) {
		// tor will set the password to 'NUL', if the field doesn't contain any
		// actual argument data.
		uname = append(uname, passwd...)
	}
	if req.Args, err = parseClientParameters(string(uname)); err != nil {
		return err
	}

	status = authRFC1929Success
	return nil
}
