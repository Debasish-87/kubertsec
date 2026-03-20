// pkg/ebpf/loader.go
package ebpf

import (
	"context"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// probeLinks holds all active eBPF program attachments.
// Each entry is closed on shutdown.
var probeLinks []link.Link
var rd *ringbuf.Reader
var coll *ebpf.Collection

// LoadProgram loads all eBPF programs, attaches probes, and starts the event reader.
func LoadProgram(ctx context.Context) error {
	spec, err := ebpf.LoadCollectionSpec("bpf/execve.bpf.o")
	if err != nil {
		return err
	}

	coll, err = ebpf.NewCollection(spec)
	if err != nil {
		return err
	}

	// Attach all probes with graceful fallback on naming differences between kernels.
	attachments := []struct {
		progName   string
		kprobeName string // kprobe target
		tpGroup    string // tracepoint group (if kprobeName is empty)
		tpName     string // tracepoint name
		fallback   string // alternative kprobe name
	}{
		{progName: "trace_execve", kprobeName: "__x64_sys_execve", fallback: "sys_execve"},
		{progName: "trace_execveat", kprobeName: "__x64_sys_execveat", fallback: "sys_execveat"},
		{progName: "trace_connect", kprobeName: "tcp_v4_connect", fallback: ""},
		{progName: "trace_connect6", kprobeName: "tcp_v6_connect", fallback: ""},
		{progName: "trace_exec_common", kprobeName: "do_execveat_common", fallback: ""},
		{progName: "trace_sched_exec", tpGroup: "sched", tpName: "sched_process_exec"},
		{progName: "trace_openat", tpGroup: "syscalls", tpName: "sys_enter_openat"},
		{progName: "trace_fork", tpGroup: "sched", tpName: "sched_process_fork"},
	}

	for _, a := range attachments {
		prog := coll.Programs[a.progName]
		if prog == nil {
			log.Printf("[ebpf] program %q not found in object — skipping", a.progName)
			continue
		}

		// Tracepoint
		if a.tpGroup != "" {
			lnk, err := link.Tracepoint(a.tpGroup, a.tpName, prog, nil)
			if err != nil {
				log.Printf("[ebpf] tracepoint %s/%s failed: %v — skipping", a.tpGroup, a.tpName, err)
				continue
			}
			probeLinks = append(probeLinks, lnk)
			log.Printf("[ebpf] attached tracepoint %s/%s", a.tpGroup, a.tpName)
			continue
		}

		// Kprobe (with optional fallback)
		lnk, err := link.Kprobe(a.kprobeName, prog, nil)
		if err != nil {
			if a.fallback != "" {
				log.Printf("[ebpf] kprobe %s failed, trying fallback %s", a.kprobeName, a.fallback)
				lnk, err = link.Kprobe(a.fallback, prog, nil)
			}
			if err != nil {
				log.Printf("[ebpf] kprobe %s failed: %v — skipping", a.kprobeName, err)
				continue
			}
		}
		probeLinks = append(probeLinks, lnk)
		log.Printf("[ebpf] attached kprobe %s", a.kprobeName)
	}

	// Ring buffer reader
	eventsMap := coll.Maps["events"]
	if eventsMap == nil {
		cleanup()
		return ErrMissingMap
	}

	rd, err = ringbuf.NewReader(eventsMap)
	if err != nil {
		cleanup()
		return err
	}

	log.Printf("[ebpf] %d probes attached, ring buffer ready", len(probeLinks))

	go ReadEvents(ctx, rd)

	// Graceful shutdown
	go func() {
		<-ctx.Done()
		log.Println("[ebpf] stopping...")
		cleanup()
		log.Println("[ebpf] stopped")
	}()

	return nil
}

// ErrMissingMap is returned when the 'events' BPF map is not found.
var ErrMissingMap = ebpfError("bpf map 'events' not found in object")

type ebpfError string

func (e ebpfError) Error() string { return string(e) }

// cleanup releases all eBPF resources in order.
func cleanup() {
	if rd != nil {
		rd.Close()
		rd = nil
	}
	for _, lnk := range probeLinks {
		lnk.Close()
	}
	probeLinks = nil
	if coll != nil {
		coll.Close()
		coll = nil
	}
}
