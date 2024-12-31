package run

import (
	"github.com/cen-ngc5139/bpfnfs/internal/config"
	"github.com/cilium/ebpf"
)

func upateBpfSpecWithFlags(bpfSpec *ebpf.CollectionSpec, cfg config.Configuration) {
	if !cfg.Features.NFSMetrics {
		delete(bpfSpec.Programs, "kb_nfs_write_d")
		delete(bpfSpec.Programs, "kb_nfs_read_d")
		delete(bpfSpec.Programs, "rpc_exit_task")
		delete(bpfSpec.Programs, "rpc_execute")
		delete(bpfSpec.Programs, "nfs_init_read")
		delete(bpfSpec.Programs, "nfs_init_write")
		delete(bpfSpec.Programs, "rpc_task_begin")
		delete(bpfSpec.Programs, "rpc_task_done")

		delete(bpfSpec.Maps, "waiting_RPC")
		delete(bpfSpec.Maps, "link_begin")
		delete(bpfSpec.Maps, "link_end")
		delete(bpfSpec.Maps, "io_metrics")
	}
}

func getKprobeAttachMap(cfg config.Configuration) (kprobeFuncs, kretprobeFuncs map[string]string) {
	kprobeFuncs = make(map[string]string)
	kretprobeFuncs = make(map[string]string)

	if cfg.Features.NFSMetrics {
		kprobeFuncs["kb_nfs_write_d"] = "nfs_writeback_done"
		kprobeFuncs["kb_nfs_read_d"] = "nfs_readpage_done"
		kprobeFuncs["rpc_exit_task"] = "rpc_exit_task"
		kprobeFuncs["rpc_execute"] = "rpc_make_runnable"
	}

	return kprobeFuncs, kretprobeFuncs
}
