// Copyright 2026 The go-zeromq Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package zmq4

// prefixTrie is a byte-alphabet trie of subscription prefixes.
// A topic matches if any inserted key is a prefix of the topic,
// including the empty key which matches every topic.
type prefixTrie struct {
	end      bool
	children map[byte]*prefixTrie
}

func (t *prefixTrie) insert(key []byte) {
	n := t
	for _, b := range key {
		child, ok := n.children[b]
		if !ok {
			if n.children == nil {
				n.children = make(map[byte]*prefixTrie)
			}
			child = &prefixTrie{}
			n.children[b] = child
		}
		n = child
	}
	n.end = true
}

func (t *prefixTrie) remove(key []byte) {
	t.removeAt(key)
}

// removeAt reports whether this node has no subscription and no children,
// so its parent may drop it.
func (t *prefixTrie) removeAt(key []byte) bool {
	if len(key) == 0 {
		t.end = false
		return len(t.children) == 0
	}
	child, ok := t.children[key[0]]
	if !ok {
		return !t.end && len(t.children) == 0
	}
	if child.removeAt(key[1:]) {
		delete(t.children, key[0])
		if len(t.children) == 0 {
			t.children = nil
		}
	}
	return !t.end && len(t.children) == 0
}

// match reports whether any inserted key is a prefix of topic.
func (t *prefixTrie) match(topic []byte) bool {
	n := t
	if n.end {
		return true
	}
	for _, b := range topic {
		n = n.children[b]
		if n == nil {
			return false
		}
		if n.end {
			return true
		}
	}
	return false
}

func (t *prefixTrie) keys() []string {
	var keys []string
	t.collect(nil, &keys)
	return keys
}

func (t *prefixTrie) collect(prefix []byte, keys *[]string) {
	if t.end {
		*keys = append(*keys, string(prefix))
	}
	for b, child := range t.children {
		child.collect(append(prefix, b), keys)
	}
}
