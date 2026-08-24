// Copyright 2026 The go-zeromq Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package zmq4

import (
	"bytes"
	"math/rand"
	"sort"
	"testing"
)

func TestPrefixTrieMatch(t *testing.T) {
	tests := []struct {
		name  string
		subs  []string
		unsub []string
		topic string
		want  bool
	}{
		{name: "empty trie", topic: "msg", want: false},
		{name: "empty prefix matches all", subs: []string{""}, topic: "anything", want: true},
		{name: "empty prefix matches empty topic", subs: []string{""}, topic: "", want: true},
		{name: "empty topic without empty prefix", subs: []string{"a"}, topic: "", want: false},
		{name: "exact match", subs: []string{"msg"}, topic: "msg", want: true},
		{name: "prefix match", subs: []string{"msg"}, topic: "msg 1", want: true},
		{name: "non prefix", subs: []string{"MSG"}, topic: "msg 1", want: false},
		{name: "shorter topic", subs: []string{"msg"}, topic: "ms", want: false},
		{name: "unrelated", subs: []string{"foo"}, topic: "bar", want: false},
		{name: "overlapping prefixes", subs: []string{"f", "fo", "foo"}, topic: "foobar", want: true},
		{name: "overlapping prefixes miss", subs: []string{"foo", "bar"}, topic: "fo", want: false},
		{name: "unsubscribe exact", subs: []string{"msg"}, unsub: []string{"msg"}, topic: "msg", want: false},
		{name: "unsubscribe keeps longer", subs: []string{"foo", "foobar"}, unsub: []string{"foo"}, topic: "foobar", want: true},
		{name: "unsubscribe longer keeps shorter", subs: []string{"foo", "foobar"}, unsub: []string{"foobar"}, topic: "foo", want: true},
		{name: "unsubscribe longer no longer matches extra", subs: []string{"foo", "foobar"}, unsub: []string{"foobar"}, topic: "foobaz", want: true},
		{name: "unsubscribe missing is noop", subs: []string{"foo"}, unsub: []string{"bar"}, topic: "foo", want: true},
		{name: "duplicate insert", subs: []string{"foo", "foo"}, topic: "foobar", want: true},
		{name: "binary bytes", subs: []string{"\x00\xff"}, topic: "\x00\xff\x01", want: true},
		{name: "binary miss", subs: []string{"\x00\xff"}, topic: "\x00\xfe", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var trie prefixTrie
			for _, s := range tt.subs {
				trie.insert([]byte(s))
			}
			for _, s := range tt.unsub {
				trie.remove([]byte(s))
			}
			if got := trie.match([]byte(tt.topic)); got != tt.want {
				t.Fatalf("match(%q) = %v, want %v", tt.topic, got, tt.want)
			}
		})
	}
}

func TestPrefixTrieKeys(t *testing.T) {
	var trie prefixTrie
	if keys := trie.keys(); len(keys) != 0 {
		t.Fatalf("empty trie keys = %q, want empty", keys)
	}

	for _, s := range []string{"", "a", "ab", "b", "msg"} {
		trie.insert([]byte(s))
	}
	trie.insert([]byte("a")) // duplicate
	trie.remove([]byte("ab"))
	trie.remove([]byte("missing"))

	got := trie.keys()
	sort.Strings(got)
	want := []string{"", "a", "b", "msg"}
	if len(got) != len(want) {
		t.Fatalf("keys = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("keys = %q, want %q", got, want)
		}
	}

	if !trie.match([]byte("a")) {
		t.Fatal("expected match for \"a\" after removing \"ab\"")
	}
	if trie.match([]byte("abx")) && !trie.match([]byte("a")) {
		t.Fatal("removing \"ab\" should not remove prefix \"a\"")
	}
	if !trie.match([]byte("abx")) {
		t.Fatal("topic \"abx\" should still match remaining prefix \"a\"")
	}
}

func TestPrefixTrieMatchesHasPrefix(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for trial := 0; trial < 200; trial++ {
		var trie prefixTrie
		var subs [][]byte
		nsub := rng.Intn(16)
		for i := 0; i < nsub; i++ {
			k := randTopic(rng)
			trie.insert(k)
			subs = append(subs, append([]byte(nil), k...))
		}
		nrem := rng.Intn(8)
		for i := 0; i < nrem; i++ {
			var k []byte
			if len(subs) > 0 && rng.Intn(2) == 0 {
				k = subs[rng.Intn(len(subs))]
			} else {
				k = randTopic(rng)
			}
			trie.remove(k)
			subs = removeAllEqual(subs, k)
		}

		for i := 0; i < 8; i++ {
			var topic []byte
			if len(subs) > 0 && rng.Intn(3) == 0 {
				s := subs[rng.Intn(len(subs))]
				topic = append(append([]byte(nil), s...), randTopic(rng)...)
			} else {
				topic = randTopic(rng)
			}
			got := trie.match(topic)
			want := naivePrefixMatch(subs, topic)
			if got != want {
				t.Fatalf("trial %d: match(%q) = %v, want %v (subs=%q)", trial, topic, got, want, subs)
			}
		}

		gotKeys := trie.keys()
		sort.Strings(gotKeys)
		wantKeys := uniqueSortedStrings(subs)
		if len(gotKeys) != len(wantKeys) {
			t.Fatalf("trial %d: keys = %q, want %q", trial, gotKeys, wantKeys)
		}
		for i := range wantKeys {
			if gotKeys[i] != wantKeys[i] {
				t.Fatalf("trial %d: keys = %q, want %q", trial, gotKeys, wantKeys)
			}
		}
	}
}

func naivePrefixMatch(subs [][]byte, topic []byte) bool {
	for _, k := range subs {
		if bytes.HasPrefix(topic, k) {
			return true
		}
	}
	return false
}

func randTopic(rng *rand.Rand) []byte {
	n := rng.Intn(8)
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.Intn(16))
	}
	return b
}

func removeAllEqual(subs [][]byte, key []byte) [][]byte {
	out := subs[:0]
	for _, s := range subs {
		if !bytes.Equal(s, key) {
			out = append(out, s)
		}
	}
	return out
}

func uniqueSortedStrings(subs [][]byte) []string {
	seen := make(map[string]struct{}, len(subs))
	var keys []string
	for _, s := range subs {
		k := string(s)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
