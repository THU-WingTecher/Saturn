// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"

	"github.com/google/syzkaller/pkg/log"
)

// Generate generates a random program with ncalls calls.
// ct contains a set of allowed syscalls, if nil all syscalls are used.
func (target *Target) Generate(rs rand.Source, ncalls int, ct *ChoiceTable) *Prog {
	p := &Prog{
		Target: target,
	}
	r := newRand(target, rs)
	s := newState(target, ct, nil)
	for len(p.Calls) < ncalls {
		calls := r.generateCall(s, p, len(p.Calls))
		for _, c := range calls {
			s.analyze(c)
			p.Calls = append(p.Calls, c)
		}
	}
	// For the last generated call we could get additional calls that create
	// resources and overflow ncalls. Remove some of these calls.
	// The resources in the last call will be replaced with the default values,
	// which is exactly what we want.
	for len(p.Calls) > ncalls {
		p.RemoveCall(ncalls - 1)
	}
	p.sanitizeFix()
	p.debugValidate()
	return p
}

func (target *Target) GenerateFileProg(rs rand.Source, ncalls int, ct *ChoiceTable, nameFdMap map[string]string) *Prog {
	p := &Prog{
		Target: target,
	}
	r := newRand(target, rs)
	s := newState(target, ct, nil)

	// generate file open syscall by nameFdMap
	for name, fd := range nameFdMap {
		meta := target.resourceCret[fd]
		log.Logf(0, "file prog: name: %v, fd: %v", name, fd)
		if meta == nil {
			meta = target.resourceCtors[fd]
			if meta == nil {
				panic("no resource ctor for fd " + fd)
			}
			// continue
		}

		// randomly choose item from list
		var call *Call
		for {
			// log.Logf(0, "file prog loop")
			idx := r.rand(len(meta))
			log.Logf(0, "file prog loop meta, name: %v, Ret: %v", meta[idx].Name, meta[idx].Ret)

			if meta[idx].Ret == nil || meta[idx].Ret.Name() != fd {
				continue
			}

			call = r.generateParticularCall(s, meta[idx])[0]
			if call.Meta.CallName == "openat" && call.Args[1].(*PointerArg).Res != nil {
				call.Args[1].(*PointerArg).Res.(*DataArg).data = []byte(name)
				break
			} else if (call.Meta.CallName == "syz_open_dev" && call.Meta.Args[1].Name == "id" && call.Args[0].(*PointerArg).Res != nil) || (call.Meta.CallName == "open") {
				if call.Args[0].(*PointerArg).Res != nil {
					call.Args[0].(*PointerArg).Res.(*DataArg).data = []byte(name)
				}
				break
			}
		}

		s.analyze(call)
		p.Calls = append(p.Calls, call)
	}

	for len(p.Calls) < ncalls {
		calls := r.generateCall(s, p, len(p.Calls))
		for _, c := range calls {
			s.analyze(c)
			p.Calls = append(p.Calls, c)
		}
	}
	// For the last generated call we could get additional calls that create
	// resources and overflow ncalls. Remove some of these calls.
	// The resources in the last call will be replaced with the default values,
	// which is exactly what we want.
	for len(p.Calls) > ncalls {
		p.RemoveCall(ncalls - 1)
	}
	p.sanitizeFix()
	p.debugValidate()
	return p
}

// Generate usb init system call
func (target *Target) GenerateByName(rs rand.Source, funcNames []string) *Prog {
	p := &Prog{
		Target: target,
	}
	r := newRand(target, rs)
	s := newState(target, nil, nil)

	for _, funcName := range funcNames {
		meta := target.SyscallMap[funcName]
		calls := r.generateParticularCall(s, meta)

		// no need to update state
		p.Calls = append(p.Calls, calls[0])
	}

	p.sanitizeFix()
	p.debugValidate()
	return p
}
