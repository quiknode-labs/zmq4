// Copyright 2019 The go-zeromq Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package zmq4

import (
	"container/list"
)

const innerCap = 512

type Queue struct {
	rep *list.List
	len int
}

func NewQueue() *Queue {
	q := &Queue{list.New(), 0}
	return q
}

func (q *Queue) Len() int {
	return q.len
}

func (q *Queue) Init() {
	q.rep.Init()
	q.len = 0
}

func (q *Queue) Push(val Msg) {
	q.len++

	var chunk []Msg
	elem := q.rep.Back()
	if elem != nil {
		chunk = elem.Value.([]Msg)
	}
	if chunk == nil || len(chunk) == innerCap {
		elem = q.rep.PushBack(make([]Msg, 0, innerCap))
		chunk = elem.Value.([]Msg)
	}

	elem.Value = append(chunk, val)
}

func (q *Queue) Peek() (Msg, bool) {
	chunk := q.front()
	if chunk == nil {
		return Msg{}, false
	}
	return chunk[0], true
}

func (q *Queue) Pop() {
	elem := q.rep.Front()
	if elem == nil {
		panic("attempting to Pop on an empty Queue")
	}

	q.len--
	chunk := elem.Value.([]Msg)
	chunk[0] = Msg{} // drop ref to popped element
	chunk = chunk[1:]
	if len(chunk) == 0 {
		q.rep.Remove(elem)
	} else {
		elem.Value = chunk
	}
}

func (q *Queue) front() []Msg {
	elem := q.rep.Front()
	if elem == nil {
		return nil
	}
	return elem.Value.([]Msg)
}
