// Copyright 2026 The go-zeromq Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package curve

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/quiknode-labs/zmq4"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/sync/errgroup"
)

func TestEncryptWritesNonce(t *testing.T) {
	cli, srv, cconn, sconn := pairedConns(t)

	const start = uint64(3)
	cconn.NonceIdx = start

	out, err := cli.Encrypt(cconn, []byte("hello"), false)
	if err != nil {
		t.Fatalf("encrypt: %+v", err)
	}
	if len(out) < messageMinSize {
		t.Fatalf("MESSAGE too short: %d", len(out))
	}
	if !bytes.Equal(out[:8], messageCmd) {
		t.Fatalf("missing MESSAGE prefix: %q", out[:8])
	}
	got := binary.BigEndian.Uint64(out[8:16])
	if got != start {
		t.Fatalf("short nonce on wire: got %d, want %d", got, start)
	}
	if cconn.NonceIdx != start+1 {
		t.Fatalf("NonceIdx: got %d, want %d", cconn.NonceIdx, start+1)
	}

	plain, more, err := srv.Decrypt(sconn, out)
	if err != nil {
		t.Fatalf("decrypt: %+v", err)
	}
	if more {
		t.Fatal("unexpected more flag")
	}
	if string(plain) != "hello" {
		t.Fatalf("payload: got %q", plain)
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	cli, srv, cconn, sconn := pairedConns(t)

	payloads := [][]byte{
		nil,
		[]byte("a"),
		bytes.Repeat([]byte("x"), 64),
		bytes.Repeat([]byte("y"), encryptStackSize+16),
	}

	for i, payload := range payloads {
		more := i%2 == 0
		out, err := cli.Encrypt(cconn, payload, more)
		if err != nil {
			t.Fatalf("encrypt %d: %+v", i, err)
		}
		got, gotMore, err := srv.Decrypt(sconn, out)
		if err != nil {
			t.Fatalf("decrypt %d: %+v", i, err)
		}
		if gotMore != more {
			t.Fatalf("more %d: got %v want %v", i, gotMore, more)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("payload %d: got %q want %q", i, got, payload)
		}
	}

	// Server -> client
	out, err := srv.Encrypt(sconn, []byte("from-server"), true)
	if err != nil {
		t.Fatalf("server encrypt: %+v", err)
	}
	got, more, err := cli.Decrypt(cconn, out)
	if err != nil {
		t.Fatalf("client decrypt: %+v", err)
	}
	if !more || string(got) != "from-server" {
		t.Fatalf("server payload: more=%v data=%q", more, got)
	}
}

func TestDecryptRejectsBadNonce(t *testing.T) {
	cli, srv, cconn, sconn := pairedConns(t)
	out, err := cli.Encrypt(cconn, []byte("x"), false)
	if err != nil {
		t.Fatalf("encrypt: %+v", err)
	}
	sconn.Peer.NonceIdx = 99
	if _, _, err := srv.Decrypt(sconn, out); err == nil {
		t.Fatal("expected nonce error")
	}
}

func TestDecryptRejectsReservedFlags(t *testing.T) {
	_, srv, _, sconn := pairedConns(t)
	n := sconn.Peer.NonceIdx + 1
	var nonce Nonce
	nonce.Short(noncePrefixMsgC, n)

	out := make([]byte, messageCmdLen+messageNonceLen)
	copy(out, messageCmd)
	binary.BigEndian.PutUint64(out[8:16], n)
	out = box.SealAfterPrecomputation(out, []byte{0x02, 'x'}, nonce.N(), sconn.SharedKey)

	before := sconn.Peer.NonceIdx
	if _, _, err := srv.Decrypt(sconn, out); err == nil {
		t.Fatal("expected reserved flags error")
	}
	if sconn.Peer.NonceIdx != before {
		t.Fatalf("nonce advanced on reserved flags: %d -> %d", before, sconn.Peer.NonceIdx)
	}
}

func TestDecryptDoesNotAdvanceNonceOnOpenFailure(t *testing.T) {
	cli, srv, cconn, sconn := pairedConns(t)
	out, err := cli.Encrypt(cconn, []byte("x"), false)
	if err != nil {
		t.Fatalf("encrypt: %+v", err)
	}
	out[len(out)-1] ^= 0xff
	before := sconn.Peer.NonceIdx
	if _, _, err := srv.Decrypt(sconn, out); err == nil {
		t.Fatal("expected open failure")
	}
	if sconn.Peer.NonceIdx != before {
		t.Fatalf("nonce advanced on failure: %d -> %d", before, sconn.Peer.NonceIdx)
	}
}

func TestHandshakePair(t *testing.T) {
	serverKeys, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	clientKeys, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ep := mustEndpoint()
	srv := zmq4.NewPair(ctx, zmq4.WithSecurity(SecurityForServer(serverKeys)))
	cli := zmq4.NewPair(ctx, zmq4.WithSecurity(SecurityForClient(serverKeys.Public, clientKeys)))
	defer srv.Close()
	defer cli.Close()

	grp, _ := errgroup.WithContext(ctx)
	grp.Go(func() error {
		if err := srv.Listen(ep); err != nil {
			return fmt.Errorf("listen: %w", err)
		}
		msg, err := srv.Recv()
		if err != nil {
			return fmt.Errorf("recv: %w", err)
		}
		if string(msg.Bytes()) != "hello-curve" {
			return fmt.Errorf("got %q", msg.Bytes())
		}
		return srv.Send(zmq4.NewMsgString("ack"))
	})
	grp.Go(func() error {
		if err := cli.Dial(ep); err != nil {
			return fmt.Errorf("dial: %w", err)
		}
		if err := cli.Send(zmq4.NewMsgString("hello-curve")); err != nil {
			return fmt.Errorf("send: %w", err)
		}
		msg, err := cli.Recv()
		if err != nil {
			return fmt.Errorf("recv ack: %w", err)
		}
		if string(msg.Bytes()) != "ack" {
			return fmt.Errorf("ack %q", msg.Bytes())
		}
		return nil
	})
	if err := grp.Wait(); err != nil {
		t.Fatalf("%+v", err)
	}
}

func TestHandshakeMultipart(t *testing.T) {
	serverKeys, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	clientKeys, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ep := mustEndpoint()
	srv := zmq4.NewPair(ctx, zmq4.WithSecurity(SecurityForServer(serverKeys)))
	cli := zmq4.NewPair(ctx, zmq4.WithSecurity(SecurityForClient(serverKeys.Public, clientKeys)))
	defer srv.Close()
	defer cli.Close()

	want := zmq4.NewMsgFrom([]byte("one"), []byte("two"), bytes.Repeat([]byte("z"), 300))

	grp, _ := errgroup.WithContext(ctx)
	grp.Go(func() error {
		if err := srv.Listen(ep); err != nil {
			return err
		}
		got, err := srv.Recv()
		if err != nil {
			return err
		}
		if len(got.Frames) != len(want.Frames) {
			return fmt.Errorf("frames %d", len(got.Frames))
		}
		for i := range want.Frames {
			if !bytes.Equal(got.Frames[i], want.Frames[i]) {
				return fmt.Errorf("frame %d", i)
			}
		}
		return nil
	})
	grp.Go(func() error {
		if err := cli.Dial(ep); err != nil {
			return err
		}
		return cli.SendMulti(want)
	})
	if err := grp.Wait(); err != nil {
		t.Fatalf("%+v", err)
	}
}

func TestHandshakeUnauthorizedClient(t *testing.T) {
	serverKeys, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	clientKeys, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	calls := 0
	srvSec := SecurityForServerFunc(func(k *[32]byte) (*KeyPair, error) {
		calls++
		if calls == 1 {
			return serverKeys, nil
		}
		if *k != clientKeys.Public {
			return serverKeys, fmt.Errorf("expected permanent client key")
		}
		return nil, fmt.Errorf("unauthorized")
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ep := mustEndpoint()
	srv := zmq4.NewPair(ctx, zmq4.WithSecurity(srvSec))
	cli := zmq4.NewPair(ctx, zmq4.WithSecurity(SecurityForClient(serverKeys.Public, clientKeys)))
	defer srv.Close()
	defer cli.Close()

	if err := srv.Listen(ep); err != nil {
		t.Fatalf("listen: %+v", err)
	}
	err = cli.Dial(ep)
	if err == nil {
		t.Fatal("expected dial to fail")
	}
	if !strings.Contains(err.Error(), "ERROR") {
		t.Fatalf("expected ERROR command, got: %+v", err)
	}
}

func TestCheckCookie(t *testing.T) {
	var cPrime, sPrime [32]byte
	if _, err := rand.Read(cPrime[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(sPrime[:]); err != nil {
		t.Fatal(err)
	}
	cookie := make([]byte, 64)
	copy(cookie[:32], cPrime[:])
	copy(cookie[32:], sPrime[:])

	got, err := checkCookie(cookie, &cPrime)
	if err != nil {
		t.Fatalf("valid cookie: %v", err)
	}
	if got != sPrime {
		t.Fatalf("s' mismatch")
	}

	var other [32]byte
	if _, err := rand.Read(other[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := checkCookie(cookie, &other); err == nil {
		t.Fatal("expected client key mismatch")
	}
	if _, err := checkCookie(cookie[:63], &cPrime); err == nil {
		t.Fatal("expected short cookie error")
	}
}

func TestCheckVouch(t *testing.T) {
	var cPrime, serverPub [32]byte
	if _, err := rand.Read(cPrime[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(serverPub[:]); err != nil {
		t.Fatal(err)
	}
	vouch := make([]byte, 64)
	copy(vouch[:32], cPrime[:])
	copy(vouch[32:], serverPub[:])
	if err := checkVouch(vouch, &cPrime, &serverPub); err != nil {
		t.Fatalf("valid vouch: %v", err)
	}

	var other [32]byte
	if _, err := rand.Read(other[:]); err != nil {
		t.Fatal(err)
	}
	if err := checkVouch(vouch, &other, &serverPub); err == nil {
		t.Fatal("expected C' mismatch")
	}
	if err := checkVouch(vouch, &cPrime, &other); err == nil {
		t.Fatal("expected S mismatch")
	}
	if err := checkVouch(vouch[:63], &cPrime, &serverPub); err == nil {
		t.Fatal("expected short vouch error")
	}
}

func TestParseErrorReason(t *testing.T) {
	if got := parseErrorReason([]byte{4, 'f', 'a', 'i', 'l'}); got != "fail" {
		t.Fatalf("got %q", got)
	}
	if got := parseErrorReason(nil); got != "" {
		t.Fatalf("empty: %q", got)
	}
}

func pairedConns(t *testing.T) (cli, srv *security, cconn, sconn *zmq4.Conn) {
	t.Helper()
	ck, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sk, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	var clientShared, serverShared [32]byte
	box.Precompute(&clientShared, &sk.Public, &ck.Private)
	box.Precompute(&serverShared, &ck.Public, &sk.Private)
	if clientShared != serverShared {
		t.Fatal("shared keys do not match")
	}

	cli = SecurityForClient(sk.Public, ck).(*security)
	srv = SecurityForServer(sk).(*security)
	cconn = &zmq4.Conn{NonceIdx: 3, SharedKey: &clientShared}
	cconn.Peer.NonceIdx = 1
	sconn = &zmq4.Conn{NonceIdx: 2, SharedKey: &serverShared}
	sconn.Peer.NonceIdx = 2
	return cli, srv, cconn, sconn
}

func mustEndpoint() string {
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return fmt.Sprintf("tcp://%s", l.Addr())
}
