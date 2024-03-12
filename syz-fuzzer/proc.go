// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

// Proc represents a single fuzzing process (executor).
type Proc struct {
	fuzzer          *Fuzzer
	pid             int
	env             *ipc.Env
	rnd             *rand.Rand
	execOpts        *ipc.ExecOpts
	execOptsCollide *ipc.ExecOpts
	execOptsCover   *ipc.ExecOpts
	execOptsComps   *ipc.ExecOpts
}

func newProc(fuzzer *Fuzzer, pid int) (*Proc, error) {
	env, err := ipc.MakeEnv(fuzzer.config, pid)
	if err != nil {
		return nil, err
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(pid)*1e12))
	execOptsCollide := *fuzzer.execOpts
	execOptsCollide.Flags &= ^ipc.FlagCollectSignal
	execOptsCover := *fuzzer.execOpts
	execOptsCover.Flags |= ipc.FlagCollectCover
	execOptsComps := *fuzzer.execOpts
	execOptsComps.Flags |= ipc.FlagCollectComps
	proc := &Proc{
		fuzzer:          fuzzer,
		pid:             pid,
		env:             env,
		rnd:             rnd,
		execOpts:        fuzzer.execOpts,
		execOptsCollide: &execOptsCollide,
		execOptsCover:   &execOptsCover,
		execOptsComps:   &execOptsComps,
	}
	return proc, nil
}

func (proc *Proc) loop() {
	// generatePeriod := 100
	// if proc.fuzzer.config.Flags&ipc.FlagSignal == 0 {
	// 	// If we don't have real coverage signal, generate programs more frequently
	// 	// because fallback signal is weak.
	// 	generatePeriod = 2
	// }

	for i := 0; ; i++ {
		log.Logf(0, "###proc loop idx: %v", i)

		_ = proc.fuzzer.workQueue.dequeue()
		// if item != nil {
		// 	switch item := item.(type) {
		// 	// TODO: put triage queue and smash queue after execution instead of receiving from other vm
		// 	case *WorkTriage:
		// 		proc.triageInput(item)
		// 		panic("!!!triaging input")
		// 	case *WorkCandidate:
		// 		if item.flags&ProgAttach != 0 {
		// 			proc.execute(proc.execOpts, item.p, item.flags, StatCandidate)
		// 		}
		// 	case *WorkSmash:
		// 		proc.smashInput(item)
		// 		panic("!!!smash input")
		// 	default:
		// 		log.Fatalf("unknown work type: %#v", item)
		// 	}
		// 	continue
		// }
		log.Logf(0, "###begin to attach usb device")

		// attach gadget, if failed, attach again
		var attach_map map[string]string
		var attach_err error
		for {
			attach_map, attach_err = proc.attachUsbDevice()
			if attach_err == nil {
				break
			}
		}
		log.Logf(0, "###attach usb device success: %v", attach_map)

		// proc.gen_dev_spec(); // open("...") resourcefd

		// persistently fuzz: coverage no promote or timeout
		maxPeriod := 10
		for j := 0; j < maxPeriod; j++ {
			log.Logf(0, "###begin to generate program")

			ct := proc.fuzzer.choiceTable
			// fuzzerSnapshot := proc.fuzzer.snapshot()

			p := proc.fuzzer.target.GenerateFileProg(proc.rnd, prog.RecommendedCalls, ct, attach_map)
			log.Logf(1, "###%v: generated file prog", proc.pid)
			proc.executeAndCollide(proc.execOpts, p, ProgNormal, StatGenerate)

			// if len(fuzzerSnapshot.corpus) == 0 || i%generatePeriod == 0 {
			// 	// Generate a new prog.
			// 	// open device and store the fd status
			// 	// proc.gen_dev_call() // open("f1")=> hidfd  opne("f2") => gfd
			// 	// proc.Generate(calls, state, rng, ct)
			// 	p := proc.fuzzer.target.Generate(proc.rnd, prog.RecommendedCalls, ct)
			// 	log.Logf(1, "#%v: generated", proc.pid)
			// 	proc.executeAndCollide(proc.execOpts, p, ProgNormal, StatGenerate)
			// } else {
			// 	// Mutate an existing prog.
			// 	// select corpus for current gadget
			// 	// c0 = proc.fuzzer.corpus[proc.gadget_ty]

			// 	p := fuzzerSnapshot.chooseProgram(proc.rnd).Clone()
			// 	// proc.fixup_dev_path(p)
			// 	p.Mutate(proc.rnd, prog.RecommendedCalls, ct, fuzzerSnapshot.corpus)
			// 	log.Logf(1, "#%v: mutated", proc.pid)
			// 	proc.executeAndCollide(proc.execOpts, p, ProgNormal, StatFuzz)
			// }
		}

		// proc.detachUsbDevice()
	}
}

// try to attach usb device and get the device file
func (proc *Proc) attachUsbDevice() (map[string]string, error) {
	log.Logf(0, "###begin to attach usb device")
	devFilePath := "/dev"
	dev_map := make(map[string]string)

	// random generate number 0-10
	rand_num := proc.rnd.Intn(10)
	attachFuncs := make([]string, 0)
	if rand_num > 7 {
		attachFuncs = append(attachFuncs, "syz_attach_gadget$hid")

	} else {
		attachFuncs = append(attachFuncs, "syz_attach_gadget")
	}
	p := proc.fuzzer.target.GenerateByName(proc.rnd, attachFuncs)
	p.FixUidArg(proc.pid)

	// usb mutex lock
	proc.fuzzer.usbMu.Lock()
	rawDevs, _ := prog.ReadFileNamesRe(devFilePath)

	// first attach, to check if the execute is vaild
	info := proc.executeRaw(proc.execOpts, p, StatCandidate)
	if info == nil {
		log.Logf(0, "###attach usb device failed")
		proc.fuzzer.usbMu.Unlock()
		return nil, errors.New("attach usb device failed")
	}
	// if execute vaild, check if there is new signal info
	calls, extra := proc.fuzzer.checkNewSignal(p, info)

	// if there is new signal info, trigate the prog, and add to corpus
	for _, callIndex := range calls {
		log.Logf(0, "###callIndex: %v", callIndex)
		infoo := info.Calls[callIndex]
		infoo.Signal = append([]uint32{}, infoo.Signal...)
		infoo.Cover = nil
		proc.triageInput(&WorkTriage{
			p:     p.Clone(),
			call:  callIndex,
			info:  infoo,
			flags: ProgAttach})
	}
	if extra {
		log.Logf(0, "###execute extra")

		infoo := info.Extra
		infoo.Signal = append([]uint32{}, infoo.Signal...)
		infoo.Cover = nil
		proc.triageInput(&WorkTriage{
			p:     p.Clone(),
			call:  -1,
			info:  infoo,
			flags: ProgAttach})
	}

	// last attach to get the device file
	info = proc.executeRaw(proc.execOpts, p, StatCandidate)
	if info == nil {
		log.Logf(0, "###attach usb device failed")
		proc.fuzzer.usbMu.Unlock()
		return nil, errors.New("attach usb device failed")
	}

	files, err := prog.GetDevInfo(rawDevs, time.Second*10)
	if len(files) > 20 {
		log.Logf(0, "###attach usb device failed")
		proc.fuzzer.usbMu.Unlock()
		return nil, errors.New("attach usb device failed: too many devices")
	}
	if err != nil {
		log.Logf(0, "###attach usb device error: %v", err)
		proc.fuzzer.usbMu.Unlock()
		return dev_map, err
	}

	file_map := make(map[string]string)
	for _, file := range files {
		proc.fuzzer.devMap[prog.ConvertPath(file)] = ""
		file_map[file] = prog.ConvertPath(file)
	}

	// open the device files
	prog.OpenFiles(files)

	proc.fuzzer.usbMu.Unlock()
	proc.fuzzer.procUsage[proc.pid] = true

	time.Sleep(time.Second)
	for _, file := range files {
		conv_file := prog.ConvertPath(file)
		fd, ok := prog.FopsResMap[proc.fuzzer.devMap[conv_file]]
		if !ok {
			prog.FopsResMap[proc.fuzzer.devMap[conv_file]] = "fd_general"
			dev_map[conv_file] = "fd_general"
			log.Logf(0, "loss fops fd map: %v(%v) -> %v", file, conv_file, proc.fuzzer.devMap[conv_file])
			// panic("loss fops fd map: " + file + " -> " + proc.fuzzer.devMap[conv_file])
			// logLossFops(proc.fuzzer.devMap[file], file)
		} else {
			// process block fd
			if fd == "fd_block" {
				if strings.Contains(file, "fd") {
					fd = "fd_floppy"
				} else if strings.Contains(file, "nbd") {
					fd = "fd_nbd"
				}
			}
			dev_map[conv_file] = fd
		}
		log.Logf(0, "fops fd map: %v(%v) -> %v, fd: %v", file, conv_file, proc.fuzzer.devMap[conv_file], dev_map[conv_file])

		delete(proc.fuzzer.devMap, conv_file)
	}

	for k, v := range file_map {
		file_map[k] = dev_map[v]
	}

	return file_map, err
}

func (proc *Proc) triageInput(item *WorkTriage) {
	// debug.PrintStack()
	log.Logf(1, "###%v: triaging type=%x", proc.pid, item.flags)

	prio := signalPrio(item.p, &item.info, item.call)
	inputSignal := signal.FromRaw(item.info.Signal, prio)
	newSignal := proc.fuzzer.corpusSignalDiff(inputSignal)
	if newSignal.Empty() {
		return
	}
	callName := ".extra"
	logCallName := "extra"
	if item.call != -1 {
		callName = item.p.Calls[item.call].Meta.Name
		logCallName = fmt.Sprintf("call #%v %v", item.call, callName)
	}
	log.Logf(0, "###triaging input for %v (new signal=%v)", logCallName, newSignal.Len())
	var inputCover cover.Cover
	var (
		signalRuns       = 3
		minimizeAttempts = 3
	)
	if item.flags&ProgAttach != 0 {
		signalRuns = 1
		minimizeAttempts = 1
	}

	// Compute input coverage and non-flaky signal for minimization.
	notexecuted := 0
	rawCover := []uint32{}
	for i := 0; i < signalRuns; i++ {
		log.Logf(0, "###trigate input luns %v", i)
		info := proc.executeRaw(proc.execOptsCover, item.p, StatTriage)
		if !reexecutionSuccess(info, &item.info, item.call) {
			// The call was not executed or failed.
			notexecuted++
			if notexecuted > signalRuns/2+1 {
				return // if happens too often, give up
			}
			continue
		}
		thisSignal, thisCover := getSignalAndCover(item.p, info, item.call)
		if len(rawCover) == 0 && proc.fuzzer.fetchRawCover {
			rawCover = append([]uint32{}, thisCover...)
		}
		newSignal = newSignal.Intersection(thisSignal)
		// Without !minimized check manager starts losing some considerable amount
		// of coverage after each restart. Mechanics of this are not completely clear.
		if newSignal.Empty() && item.flags&ProgMinimized == 0 {
			return
		}
		inputCover.Merge(thisCover)
	}
	if (item.flags&ProgMinimized == 0) && (item.flags&ProgAttach == 0) {
		log.Logf(0, "###triage input: minimizing")
		item.p, item.call = prog.Minimize(item.p, item.call, false,
			func(p1 *prog.Prog, call1 int) bool {
				for i := 0; i < minimizeAttempts; i++ {
					info := proc.execute(proc.execOpts, p1, ProgNormal, StatMinimize)
					if !reexecutionSuccess(info, &item.info, call1) {
						// The call was not executed or failed.
						continue
					}
					thisSignal, _ := getSignalAndCover(p1, info, call1)
					if newSignal.Intersection(thisSignal).Len() == newSignal.Len() {
						return true
					}
				}
				return false
			})
	}

	data := item.p.Serialize()
	sig := hash.Hash(data)

	log.Logf(0, "added new input for %v to corpus:\n%s", logCallName, data)
	proc.fuzzer.sendInputToManager(rpctype.Input{
		Call:     callName,
		CallID:   item.call,
		Prog:     data,
		Signal:   inputSignal.Serialize(),
		Cover:    inputCover.Serialize(),
		RawCover: rawCover,
	})

	proc.fuzzer.addInputToCorpus(item.p, inputSignal, sig)

	if item.flags&ProgAttach != 0 {
		return
	}

	if item.flags&ProgSmashed == 0 {
		// proc.fuzzer.workQueue.enqueue(&WorkSmash{item.p, item.call})
		proc.smashInput(&WorkSmash{item.p, item.call})
	}
}

func reexecutionSuccess(info *ipc.ProgInfo, oldInfo *ipc.CallInfo, call int) bool {
	if info == nil || len(info.Calls) == 0 {
		return false
	}
	if call != -1 {
		// Don't minimize calls from successful to unsuccessful.
		// Successful calls are much more valuable.
		if oldInfo.Errno == 0 && info.Calls[call].Errno != 0 {
			return false
		}
		return len(info.Calls[call].Signal) != 0
	}
	return len(info.Extra.Signal) != 0
}

func getSignalAndCover(p *prog.Prog, info *ipc.ProgInfo, call int) (signal.Signal, []uint32) {
	inf := &info.Extra
	if call != -1 {
		inf = &info.Calls[call]
	}
	return signal.FromRaw(inf.Signal, signalPrio(p, inf, call)), inf.Cover
}

func (proc *Proc) smashInput(item *WorkSmash) {
	if proc.fuzzer.faultInjectionEnabled && item.call != -1 {
		proc.failCall(item.p, item.call)
	}
	if proc.fuzzer.comparisonTracingEnabled && item.call != -1 {
		proc.executeHintSeed(item.p, item.call)
	}
	fuzzerSnapshot := proc.fuzzer.snapshot()
	for i := 0; i < 100; i++ {
		p := item.p.Clone()
		p.Mutate(proc.rnd, prog.RecommendedCalls, proc.fuzzer.choiceTable, fuzzerSnapshot.corpus)
		log.Logf(1, "#%v: smash mutated", proc.pid)
		proc.executeAndCollide(proc.execOpts, p, ProgNormal, StatSmash)
	}
}

func (proc *Proc) failCall(p *prog.Prog, call int) {
	for nth := 1; nth <= 100; nth++ {
		log.Logf(1, "#%v: injecting fault into call %v/%v", proc.pid, call, nth)
		newProg := p.Clone()
		newProg.Calls[call].Props.FailNth = nth
		info := proc.executeRaw(proc.execOpts, newProg, StatSmash)
		if info != nil && len(info.Calls) > call && info.Calls[call].Flags&ipc.CallFaultInjected == 0 {
			break
		}
	}
}

func (proc *Proc) executeHintSeed(p *prog.Prog, call int) {
	log.Logf(1, "#%v: collecting comparisons", proc.pid)
	// First execute the original program to dump comparisons from KCOV.
	info := proc.execute(proc.execOptsComps, p, ProgNormal, StatSeed)
	if info == nil {
		return
	}

	// Then mutate the initial program for every match between
	// a syscall argument and a comparison operand.
	// Execute each of such mutants to check if it gives new coverage.
	p.MutateWithHints(call, info.Calls[call].Comps, func(p *prog.Prog) {
		log.Logf(1, "#%v: executing comparison hint", proc.pid)
		proc.execute(proc.execOpts, p, ProgNormal, StatHint)
	})
}

func (proc *Proc) execute(execOpts *ipc.ExecOpts, p *prog.Prog, flags ProgTypes, stat Stat) *ipc.ProgInfo {
	info := proc.executeRaw(execOpts, p, stat)
	if info == nil {
		return nil
	}

	// after executing, begin to triage the new input
	calls, extra := proc.fuzzer.checkNewSignal(p, info)
	for _, callIndex := range calls {
		log.Logf(0, "###callIndex: %v", callIndex)
		// proc.enqueueCallTriage(p, flags, callIndex, info.Calls[callIndex])
		infoo := info.Calls[callIndex]
		infoo.Signal = append([]uint32{}, infoo.Signal...)
		infoo.Cover = nil
		proc.triageInput(&WorkTriage{
			p:     p.Clone(),
			call:  callIndex,
			info:  infoo,
			flags: flags})
	}
	if extra {
		// proc.enqueueCallTriage(p, flags, -1, info.Extra)
		log.Logf(0, "###execute extra")

		infoo := info.Extra
		infoo.Signal = append([]uint32{}, infoo.Signal...)
		infoo.Cover = nil
		proc.triageInput(&WorkTriage{
			p:     p.Clone(),
			call:  -1,
			info:  infoo,
			flags: flags})
	}

	return info
}

func (proc *Proc) enqueueCallTriage(p *prog.Prog, flags ProgTypes, callIndex int, info ipc.CallInfo) {
	// info.Signal points to the output shmem region, detach it before queueing.
	info.Signal = append([]uint32{}, info.Signal...)
	// None of the caller use Cover, so just nil it instead of detaching.
	// Note: triage input uses executeRaw to get coverage.
	info.Cover = nil
	proc.fuzzer.workQueue.enqueue(&WorkTriage{
		p:     p.Clone(),
		call:  callIndex,
		info:  info,
		flags: flags,
	})
}

func (proc *Proc) executeAndCollide(execOpts *ipc.ExecOpts, p *prog.Prog, flags ProgTypes, stat Stat) {
	proc.execute(execOpts, p, flags, stat)

	if proc.execOptsCollide.Flags&ipc.FlagThreaded == 0 {
		// We cannot collide syscalls without being in the threaded mode.
		return
	}
	const collideIterations = 2
	for i := 0; i < collideIterations; i++ {
		proc.executeRaw(proc.execOptsCollide, proc.randomCollide(p), StatCollide)
	}
}

func (proc *Proc) randomCollide(origP *prog.Prog) *prog.Prog {
	// Old-styl collide with a 33% probability.
	if proc.rnd.Intn(3) == 0 {
		p, err := prog.DoubleExecCollide(origP, proc.rnd)
		if err == nil {
			return p
		}
	}
	p := prog.AssignRandomAsync(origP, proc.rnd)
	if proc.rnd.Intn(2) != 0 {
		prog.AssignRandomRerun(p, proc.rnd)
	}
	return p
}

func (proc *Proc) executeRaw(opts *ipc.ExecOpts, p *prog.Prog, stat Stat) *ipc.ProgInfo {
	proc.fuzzer.checkDisabledCalls(p)

	// Limit concurrency window and do leak checking once in a while.
	ticket := proc.fuzzer.gate.Enter()
	defer proc.fuzzer.gate.Leave(ticket)

	proc.logProgram(opts, p)
	for try := 0; ; try++ {
		atomic.AddUint64(&proc.fuzzer.stats[stat], 1)
		output, info, hanged, err := proc.env.Exec(opts, p)
		if err != nil {
			if err == prog.ErrExecBufferTooSmall {
				// It's bad if we systematically fail to serialize programs,
				// but so far we don't have a better handling than ignoring this.
				// This error is observed a lot on the seeded syz_mount_image calls.
				return nil
			}
			if try > 10 {
				log.Fatalf("executor %v failed %v times: %v", proc.pid, try, err)
			}
			log.Logf(4, "fuzzer detected executor failure='%v', retrying #%d", err, try+1)
			debug.FreeOSMemory()
			time.Sleep(time.Second)
			continue
		}
		log.Logf(2, "result hanged=%v: %s", hanged, output)
		return info
	}
}

func (proc *Proc) logOpenSyscall(p *prog.Prog) {
	for _, call := range p.Calls {
		if call.Meta.CallName == "openat" && call.Args[1].(*prog.PointerArg).Res != nil {
			log.Logf(2, "#####callname: %v:, filename: %v, resource: %v", call.Meta.Name, string(call.Args[1].(*prog.PointerArg).Res.(*prog.DataArg).Data()), call.Meta.Ret.(*prog.ResourceType).String())
		} else if call.Meta.CallName == "syz_open_dev" && call.Meta.Args[1].Name == "id" && call.Args[0].(*prog.PointerArg).Res != nil {
			log.Logf(2, "#####callname: %v:, filename: %v, resource: %v", call.Meta.Name, string(call.Args[0].(*prog.PointerArg).Res.(*prog.DataArg).Data()), call.Meta.Ret.(*prog.ResourceType).String())
		}
	}
}

func (proc *Proc) logProgram(opts *ipc.ExecOpts, p *prog.Prog) {
	if proc.fuzzer.outputType == OutputNone {
		return
	}

	data := p.Serialize()

	// The following output helps to understand what program crashed kernel.
	// It must not be intermixed.
	switch proc.fuzzer.outputType {
	case OutputStdout:
		now := time.Now()
		proc.fuzzer.logMu.Lock()
		fmt.Printf("%02v:%02v:%02v executing program %v:\n%s\n",
			now.Hour(), now.Minute(), now.Second(),
			proc.pid, data)
		proc.fuzzer.logMu.Unlock()
	case OutputDmesg:
		fd, err := syscall.Open("/dev/kmsg", syscall.O_WRONLY, 0)
		if err == nil {
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, "syzkaller: executing program %v:\n%s\n",
				proc.pid, data)
			syscall.Write(fd, buf.Bytes())
			syscall.Close(fd)
		}
	case OutputFile:
		f, err := os.Create(fmt.Sprintf("%v-%v.prog", proc.fuzzer.name, proc.pid))
		if err == nil {
			f.Write(data)
			f.Close()
		}
	default:
		log.Fatalf("unknown output type: %v", proc.fuzzer.outputType)
	}
}
