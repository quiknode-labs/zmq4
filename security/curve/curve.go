// Copyright 2024 The go-zeromq Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package curve provides the ZeroMQ CURVE security mechanism as specified by:
// https://rfc.zeromq.org/spec:25/ZMTP-CURVE/
package curve

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/quiknode-labs/zmq4"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	keySize   = 32 // Size of public and private keys
	nonceSize = 24 // Size of a NaCl nonce

	messageCmdLen   = 8
	messageNonceLen = 8
	messageMacLen   = 16
	messageFlagsLen = 1
	// MESSAGE command prefix + short nonce + box(MAC + flags [+ payload]).
	messageMinSize = messageCmdLen + messageNonceLen + messageMacLen + messageFlagsLen

	encryptStackSize = 512

	noncePrefixHello    = "CurveZMQHELLO---"
	noncePrefixWelcome  = "WELCOME-"
	noncePrefixInitiate = "CurveZMQINITIATE"
	noncePrefixReady    = "CurveZMQREADY---"
	noncePrefixVouch    = "VOUCH---"
	noncePrefixCookie   = "COOKIE--"
	noncePrefixMsgC     = "CurveZMQMESSAGEC"
	noncePrefixMsgS     = "CurveZMQMESSAGES"
)

// ZMTP-CURVE MESSAGE command prefix: 0x07 "MESSAGE"
var messageCmd = []byte{7, 'M', 'E', 'S', 'S', 'A', 'G', 'E'}

// KeyPair represents a CurveZMQ key pair.
type KeyPair struct {
	Public  [keySize]byte
	Private [keySize]byte
}

// NewKeyPair generates a new random keypair for curve security.
func NewKeyPair() (*KeyPair, error) {
	var kp KeyPair
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	copy(kp.Public[:], pub[:])
	copy(kp.Private[:], priv[:])
	return &kp, nil
}

// security implements the CURVE security mechanism.
type security struct {
	serverPubKey  [keySize]byte                               // Long-term server public key
	clientKeyPair *KeyPair                                    // client KeyPair
	keyFunc       func(clientKey *[32]byte) (*KeyPair, error) // Func for retrieving server's KeyPair
	asServer      bool                                        // True if this is a server
}

// SecurityForClient returns a CURVE security mechanism for a client.
// The client must know the server's public key.
func SecurityForClient(serverKey [keySize]byte, clientKeys *KeyPair) zmq4.Security {
	sec := &security{
		serverPubKey:  serverKey,
		clientKeyPair: clientKeys,
		asServer:      false,
	}
	return sec
}

// SecurityForServer returns a CURVE security mechanism for a server.
// The server must have its own key pair.
func SecurityForServer(serverKeys *KeyPair) zmq4.Security {
	sec := &security{
		keyFunc: func(_ *[32]byte) (*KeyPair, error) {
			return serverKeys, nil
		},
		asServer: true,
	}
	return sec
}

// SecurityForServerFunc returns a CURVE security mechanism for a server.
//
// keyFunc is called with the client's short-term public key (C') during HELLO
// to obtain the server's long-term key pair. It is called again with the
// client's permanent public key (C) during INITIATE; a non-nil error rejects
// the client with an ERROR command.
func SecurityForServerFunc(keyFunc func(*[32]byte) (*KeyPair, error)) zmq4.Security {
	sec := &security{
		keyFunc:  keyFunc,
		asServer: true,
	}
	return sec
}

// Type returns the security mechanism type.
func (security) Type() zmq4.SecurityType {
	return zmq4.CurveSecurity
}

// Handshake implements the ZMTP security handshake according to
// the CURVE security mechanism.
// see: https://rfc.zeromq.org/spec:25/ZMTP-CURVE/
func (sec *security) Handshake(conn *zmq4.Conn, server bool) error {
	if server != sec.asServer {
		return fmt.Errorf("security/curve: invalid server flag, got=%v, want=%v", server, sec.asServer)
	}

	if server {
		return sec.serverHandshake(conn)
	}

	ephemeral, err := NewKeyPair()
	if err != nil {
		return fmt.Errorf("security/curve: could not generate session keypair: %w", err)
	}
	return sec.clientHandshake(conn, ephemeral)
}

func (sec *security) clientHandshake(conn *zmq4.Conn, ephemeral *KeyPair) error {
	var nonce Nonce
	err := sec.doHello(conn, &nonce, ephemeral)
	if err != nil {
		return fmt.Errorf("security/curve: could not send HELLO to server: %w", err)
	}

	servCookie, secretKey, err := sec.doWelcome(&nonce, conn, ephemeral)
	if err != nil {
		return fmt.Errorf("security/curve: failed WELCOME: %w", err)
	}

	err = sec.doInitiate(conn, servCookie, &nonce, sec.clientKeyPair, secretKey, ephemeral)
	if err != nil {
		return fmt.Errorf("security/curve: failed INITIATE: %w", err)
	}

	servMeta, err := sec.doReady(conn, &nonce, secretKey, ephemeral)
	if err != nil {
		return fmt.Errorf("security/curve: failed READY: %w", err)
	}

	conn.NonceIdx = 3
	conn.Peer.NonceIdx = 1
	var sharedKey [32]byte
	box.Precompute(&sharedKey, secretKey, &ephemeral.Private)
	conn.SharedKey = &sharedKey

	// Unmarshal the server metadata
	err = conn.Peer.Meta.UnmarshalZMTP(servMeta)
	if err != nil {
		return fmt.Errorf("security/curve: could not unmarshal server metadata: %w", err)
	}

	return nil
}

func (sec *security) serverHandshake(conn *zmq4.Conn) error {
	var nonce Nonce
	var cookieKey [32]byte
	defer zeroKey(&cookieKey)

	clientTransPubKey, keys, err := sec.doServerHello(&nonce, conn)
	if err != nil {
		return fmt.Errorf("security/curve: Client hello failed: %w", err)
	}

	err = sec.doServerWelcome(&nonce, conn, &clientTransPubKey, &cookieKey, keys)
	if err != nil {
		return fmt.Errorf("security/curve: Failed sending welcome: %w", err)
	}

	clientMeta, serverTransSecKey, err := sec.doServerInitiate(&nonce, conn, &cookieKey, &clientTransPubKey, &keys.Public)
	if err != nil {
		return fmt.Errorf("security/curve: Client initiate failed: %w", err)
	}
	defer zeroKey(&serverTransSecKey)

	err = conn.Peer.Meta.UnmarshalZMTP(clientMeta)
	if err != nil {
		return fmt.Errorf("security/curve: Could not unmarshal client metadata: %w", err)
	}

	err = sec.doServerReady(conn, &clientTransPubKey, &serverTransSecKey)
	if err != nil {
		return fmt.Errorf("security/curve: Server ready failed: %w", err)
	}

	conn.NonceIdx = 2
	conn.Peer.NonceIdx = 2
	var sharedKey [32]byte
	box.Precompute(&sharedKey, &clientTransPubKey, &serverTransSecKey)
	conn.SharedKey = &sharedKey
	return nil
}

// Encrypt returns a ZMTP-CURVE MESSAGE command body for data.
func (sec *security) Encrypt(conn *zmq4.Conn, data []byte, more bool) ([]byte, error) {
	if conn.SharedKey == nil {
		return nil, fmt.Errorf("security/curve: missing shared key")
	}

	n := conn.NonceIdx
	conn.NonceIdx = n + 1

	// Header is 16 bytes (command + short nonce); the box is appended in place.
	out := make([]byte, messageCmdLen+messageNonceLen, messageMinSize+len(data))
	copy(out, messageCmd)
	binary.BigEndian.PutUint64(out[8:16], n)

	var nonce Nonce
	if sec.asServer {
		nonce.Short(noncePrefixMsgS, n) // From server
	} else {
		nonce.Short(noncePrefixMsgC, n) // From client
	}

	need := messageFlagsLen + len(data)
	var stack [encryptStackSize]byte
	var plain []byte
	if need <= encryptStackSize {
		plain = stack[:need]
	} else {
		plain = make([]byte, need)
	}
	if more {
		plain[0] = 0x1
	}
	copy(plain[1:], data)

	return box.SealAfterPrecomputation(out, plain, nonce.N(), conn.SharedKey), nil
}

// Decrypt opens a ZMTP-CURVE MESSAGE command body.
func (sec *security) Decrypt(conn *zmq4.Conn, body []byte) ([]byte, bool, error) {
	if conn.SharedKey == nil {
		return nil, false, fmt.Errorf("security/curve: missing shared key")
	}
	if len(body) < messageMinSize {
		return nil, false, fmt.Errorf("security/curve: invalid message: too short")
	}
	if !bytes.Equal(body[:messageCmdLen], messageCmd) {
		return nil, false, fmt.Errorf("security/curve: expected MESSAGE command")
	}

	shortNonce := binary.BigEndian.Uint64(body[8:16])
	if shortNonce != conn.Peer.NonceIdx+1 {
		return nil, false, fmt.Errorf("security/curve: peer used invalid nonce (expected %d, got %d)", conn.Peer.NonceIdx+1, shortNonce)
	}

	var nonce Nonce
	if sec.asServer {
		nonce.Short(noncePrefixMsgC, shortNonce) // From client
	} else {
		nonce.Short(noncePrefixMsgS, shortNonce) // From server
	}

	plain, ok := box.OpenAfterPrecomputation(make([]byte, 0, len(body)-32), body[16:], nonce.N(), conn.SharedKey)
	if !ok {
		return nil, false, fmt.Errorf("security/curve: failed opening message box")
	}
	if len(plain) < messageFlagsLen {
		return nil, false, fmt.Errorf("security/curve: invalid message: missing flags")
	}
	// RFC 26: bits 7-1 are reserved and MUST be zero.
	if plain[0]&^0x01 != 0 {
		return nil, false, fmt.Errorf("security/curve: reserved MESSAGE flags set: %#x", plain[0])
	}
	conn.Peer.NonceIdx = shortNonce
	more := plain[0]&0x1 == 1
	return plain[1:], more, nil
}

func (sec *security) doHello(conn *zmq4.Conn, nonce *Nonce, ephemeral *KeyPair) error {
	body := make([]byte, 194)
	body[0] = 1 // version
	copy(body[74:106], ephemeral.Public[:])
	binary.BigEndian.PutUint64(body[106:114], 1)
	nonce.Short(noncePrefixHello, 1)
	var sigBox [64]byte
	box.Seal(body[114:114], sigBox[:], nonce.N(), &sec.serverPubKey, &ephemeral.Private)
	return conn.SendCmd(zmq4.CmdHello, body)
}

func (sec *security) doWelcome(nonce *Nonce, conn *zmq4.Conn, ephemeral *KeyPair) ([]byte, *[32]byte, error) {
	cmd, err := conn.RecvCmd()
	if err != nil {
		return nil, nil, fmt.Errorf("security/curve: could not receive WELCOME from server: %w", err)
	}
	if err := errFromPeerError(cmd); err != nil {
		return nil, nil, err
	}
	if cmd.Name != zmq4.CmdWelcome {
		return nil, nil, fmt.Errorf("security/curve: expected WELCOME command, got %s", cmd.Name)
	}
	if len(cmd.Body) != 160 {
		return nil, nil, fmt.Errorf("security/curve: expected WELCOME body to be 160 bytes long")
	}

	nonce.FromLong(noncePrefixWelcome, cmd.Body[:16])
	welcomeBox := make([]byte, 128)
	_, ok := box.Open(welcomeBox[0:0], cmd.Body[16:], nonce.N(), &sec.serverPubKey, &ephemeral.Private)
	if !ok {
		return nil, nil, fmt.Errorf("Failed opening welcome box")
	}

	var secretKey [32]byte
	copy(secretKey[:], welcomeBox[:32])
	return welcomeBox[32:], &secretKey, nil
}

func (sec *security) doInitiate(conn *zmq4.Conn, servCookie []byte, nonce *Nonce, keys *KeyPair, secretKey *[32]byte, ephemeral *KeyPair) error {
	meta, err := conn.Meta.MarshalZMTP()
	if err != nil {
		return fmt.Errorf("security/curve: could not marshal metadata: %w", err)
	}
	initiateBody := make([]byte, 96+8+32+96+len(meta)+16)
	copy(initiateBody[:96], servCookie)
	binary.BigEndian.PutUint64(initiateBody[96:104], 2)

	// initiate::vouch
	nonce.Long(noncePrefixVouch)
	vouch := make([]byte, 64)
	copy(vouch, ephemeral.Public[:])
	copy(vouch[32:], sec.serverPubKey[:])
	vouchBox := make([]byte, 80)
	box.Seal(vouchBox[0:0], vouch, nonce.N(), secretKey, &keys.Private)

	initBox := make([]byte, 128+len(meta))
	copy(initBox, keys.Public[:])
	copy(initBox[32:48], nonce[8:])
	copy(initBox[48:128], vouchBox)
	copy(initBox[128:], meta)
	nonce.Short(noncePrefixInitiate, 2)
	box.Seal(initiateBody[104:104], initBox, nonce.N(), secretKey, &ephemeral.Private)
	return conn.SendCmd(zmq4.CmdInitiate, initiateBody)
}

func (sec *security) doReady(conn *zmq4.Conn, nonce *Nonce, secretKey *[32]byte, ephemeral *KeyPair) ([]byte, error) {
	cmd, err := conn.RecvCmd()
	if err != nil {
		return nil, fmt.Errorf("security/curve: could not receive READY from server: %w", err)
	}
	if err := errFromPeerError(cmd); err != nil {
		return nil, err
	}
	if cmd.Name != zmq4.CmdReady {
		return nil, fmt.Errorf("security/curve: expected READY command, got %s", cmd.Name)
	}
	if len(cmd.Body) < 24 {
		return nil, fmt.Errorf("security/curve: expected READY body to be at least 24 bytes long")
	}

	servNonce := binary.BigEndian.Uint64(cmd.Body[:8])
	if servNonce != 1 {
		return nil, fmt.Errorf("security/curve: expected server nonce to be 1, got %d", servNonce)
	}
	nonce.Short(noncePrefixReady, 1)
	servMeta := make([]byte, len(cmd.Body)-24)
	if _, ok := box.Open(servMeta[0:0], cmd.Body[8:], nonce.N(), secretKey, &ephemeral.Private); !ok {
		return nil, fmt.Errorf("security/curve: failed opening metadata")
	}
	return servMeta, nil
}

func (sec *security) doServerHello(nonce *Nonce, conn *zmq4.Conn) (clientTransPubKey [32]byte, keys *KeyPair, err error) {
	cmd, err := conn.RecvCmd()
	if err != nil {
		return clientTransPubKey, nil, err
	}
	if cmd.Name != zmq4.CmdHello {
		err = fmt.Errorf("security/curve: invalid handshake: expected hello, got %s", cmd.Name)
		return
	}
	if len(cmd.Body) != 194 {
		err = fmt.Errorf("security/curve: invalid hello: expected length to be 194 bytes, got %d", len(cmd.Body))
		return
	}
	if cmd.Body[0] != 1 || cmd.Body[1] != 0 {
		err = fmt.Errorf("security/curve: Expected CURVEZMQ version 1.0, got %d.%d", cmd.Body[0], cmd.Body[1])
		return
	}

	copy(clientTransPubKey[:], cmd.Body[74:106])
	cliNonceIdx := binary.BigEndian.Uint64(cmd.Body[106:114])
	nonce.Short(noncePrefixHello, cliNonceIdx)
	if cliNonceIdx != 1 {
		err = fmt.Errorf("security/curve: Expected client nonce to be 1, got %d", cliNonceIdx)
		return
	}
	var out [64]byte

	keys, err = sec.keyFunc(&clientTransPubKey)
	if err != nil {
		return clientTransPubKey, nil, fmt.Errorf("security/curve: hello could not retrieve keypair: %w", err)
	}
	if keys == nil {
		return clientTransPubKey, nil, fmt.Errorf("security/curve: hello keyFunc returned nil keypair")
	}

	_, ok := box.Open(out[0:0], cmd.Body[114:], nonce.N(), &clientTransPubKey, &keys.Private)
	if !ok {
		err = fmt.Errorf("security/curve: Invalid signature in hello command")
		return
	}

	for idx, b := range out {
		if b != 0 {
			err = fmt.Errorf("security/curve: Expected signature to contain only 0's, byte %d has value %x", idx, b)
			return
		}
	}
	return clientTransPubKey, keys, nil
}

func (sec *security) doServerWelcome(nonce *Nonce, conn *zmq4.Conn, clientTransPubKey, cookieKey *[32]byte, keys *KeyPair) error {
	kp, err := NewKeyPair()
	if err != nil {
		return fmt.Errorf("security/curve: could not generate session keypair: %w", err)
	}
	welcomeBody := make([]byte, 160)
	var cookie [64]byte
	copy(cookie[:], clientTransPubKey[:])
	copy(cookie[32:], kp.Private[:])
	PopulateSecKey(cookieKey)

	nonce.Long(noncePrefixCookie)
	cookieData := make([]byte, 96)
	secretbox.Seal(cookieData[16:16], cookie[:], nonce.N(), cookieKey)
	copy(cookieData[:16], nonce[8:])
	zeroKey(&kp.Private)
	for i := range cookie {
		cookie[i] = 0
	}

	welcomeBox := make([]byte, 128)
	copy(welcomeBox, kp.Public[:])
	copy(welcomeBox[32:], cookieData)
	nonce.Long(noncePrefixWelcome)
	copy(welcomeBody, nonce[8:])
	box.Seal(welcomeBody[16:16], welcomeBox, nonce.N(), clientTransPubKey, &keys.Private)
	return conn.SendCmd(zmq4.CmdWelcome, welcomeBody)
}

func PopulateSecKey(sec *[32]byte) {
	_, err := io.ReadFull(rand.Reader, sec[:])
	if err != nil {
		panic(err)
	}
}

func (sec *security) doServerInitiate(nonce *Nonce, conn *zmq4.Conn, cookieKey, clientTransPubKey, serverPub *[32]byte) ([]byte, [32]byte, error) {
	var serverTransSecKey [32]byte
	cmd, err := conn.RecvCmd()
	if err != nil {
		return nil, serverTransSecKey, fmt.Errorf("security/curve: could not receive INITIATE from client: %w", err)
	}
	if cmd.Name != zmq4.CmdInitiate {
		return nil, serverTransSecKey, fmt.Errorf("security/curve: invalid handshake: expected initiate, got %s", cmd.Name)
	}
	if len(cmd.Body) < 248 {
		return nil, serverTransSecKey, fmt.Errorf("security/curve: invalid initiate: expected length to be at least 248 bytes, got %d", len(cmd.Body))
	}

	nonce.FromLong(noncePrefixCookie, cmd.Body[:16])
	clientCookieBox := cmd.Body[16:96]
	clientCookieData := make([]byte, 0, 64)
	clientCookieData, ok := secretbox.Open(clientCookieData, clientCookieBox, nonce.N(), cookieKey)
	if !ok {
		return nil, serverTransSecKey, fmt.Errorf("security/curve: client sent invalid cookie")
	}

	serverTransSecKey, err = checkCookie(clientCookieData, clientTransPubKey)
	if err != nil {
		return nil, [32]byte{}, err
	}

	cliNonceIdx := binary.BigEndian.Uint64(cmd.Body[96:104])
	if cliNonceIdx != 2 {
		return nil, serverTransSecKey, fmt.Errorf("security/curve: expected client nonce to be 2, got %d", cliNonceIdx)
	}
	nonce.Short(noncePrefixInitiate, cliNonceIdx)
	initBox := make([]byte, 0, len(cmd.Body)-120)
	initBox, ok = box.Open(initBox, cmd.Body[104:], nonce.N(), clientTransPubKey, &serverTransSecKey)
	if !ok {
		return nil, serverTransSecKey, fmt.Errorf("security/curve: failed opening initiate box")
	}

	var clientPermPublicKey [32]byte
	copy(clientPermPublicKey[:], initBox[:32])
	vouch := initBox[32:128]
	clientMeta := initBox[128:]
	nonce.FromLong(noncePrefixVouch, vouch[:16])
	vouchData := make([]byte, 0, 64)
	vouchData, ok = box.Open(vouchData, vouch[16:], nonce.N(), &clientPermPublicKey, &serverTransSecKey)
	if !ok {
		return nil, serverTransSecKey, fmt.Errorf("security/curve: failed opening vouch box")
	}
	if err := checkVouch(vouchData, clientTransPubKey, serverPub); err != nil {
		return nil, serverTransSecKey, err
	}

	if _, err := sec.keyFunc(&clientPermPublicKey); err != nil {
		_ = sendCurveError(conn, "authentication failed")
		return nil, serverTransSecKey, fmt.Errorf("security/curve: client authentication failed: %w", err)
	}
	return clientMeta, serverTransSecKey, nil
}

func checkCookie(cookie []byte, clientTransPubKey *[32]byte) ([32]byte, error) {
	var sPrime [32]byte
	if len(cookie) != 64 {
		return sPrime, fmt.Errorf("security/curve: invalid cookie plaintext length %d", len(cookie))
	}
	if subtle.ConstantTimeCompare(cookie[:32], clientTransPubKey[:]) != 1 {
		return sPrime, fmt.Errorf("security/curve: cookie client key mismatch")
	}
	copy(sPrime[:], cookie[32:])
	return sPrime, nil
}

func checkVouch(vouch []byte, clientTransPubKey, serverPub *[32]byte) error {
	if len(vouch) != 64 {
		return fmt.Errorf("security/curve: invalid vouch plaintext length %d", len(vouch))
	}
	if subtle.ConstantTimeCompare(vouch[:32], clientTransPubKey[:]) != 1 {
		return fmt.Errorf("security/curve: vouch transient key mismatch")
	}
	if subtle.ConstantTimeCompare(vouch[32:], serverPub[:]) != 1 {
		return fmt.Errorf("security/curve: vouch server key mismatch")
	}
	return nil
}

func sendCurveError(conn *zmq4.Conn, reason string) error {
	if len(reason) > 255 {
		reason = reason[:255]
	}
	body := make([]byte, 1+len(reason))
	body[0] = byte(len(reason))
	copy(body[1:], reason)
	return conn.SendCmd(zmq4.CmdError, body)
}

func errFromPeerError(cmd zmq4.Cmd) error {
	if cmd.Name != zmq4.CmdError {
		return nil
	}
	reason := parseErrorReason(cmd.Body)
	if reason == "" {
		return fmt.Errorf("security/curve: server sent ERROR")
	}
	return fmt.Errorf("security/curve: server sent ERROR: %s", reason)
}

func parseErrorReason(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	n := int(body[0])
	if n > 255 || 1+n > len(body) {
		return string(body)
	}
	return string(body[1 : 1+n])
}

func zeroKey(k *[32]byte) {
	for i := range k {
		k[i] = 0
	}
}

func (sec *security) doServerReady(conn *zmq4.Conn, clientTransPubKey *[32]byte,
	serverTransSecKey *[32]byte) error {
	var nonce Nonce
	nonce.Short(noncePrefixReady, 1)

	meta, err := conn.Meta.MarshalZMTP()
	if err != nil {
		return fmt.Errorf("security/curve: could not marshal metadata: %w", err)
	}

	readyBody := make([]byte, len(meta)+16+8)
	binary.BigEndian.PutUint64(readyBody[0:8], 1)
	box.Seal(readyBody[8:8], meta, nonce.N(), clientTransPubKey, serverTransSecKey)

	return conn.SendCmd(zmq4.CmdReady, readyBody)
}

var (
	_ zmq4.SecurityEncryption = (*security)(nil)
)
