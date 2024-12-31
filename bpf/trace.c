// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Martynas Pumputis */
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "vmlinux-x86.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_endian.h"
#include "bpf/bpf_ipv6.h"
#include "bpf_utils.h"

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 127
#endif
// 用于传递 nfs span 信息
BPF_PERF_EVENT_ARRAY(nfs_span_map)

// 程序数组
struct
{
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} dns_prog_array SEC(".maps");

#define MAX_PKT_SIZE 512
#define DNS_PORT 53
#define MAX_DOMAIN_LEN 512
#define __user
#ifndef RPC_TASK_VAR
#define RPC_TASK_VAR nfs_pgio_header
#endif
#define MAX_PATH_DEPTH 10

struct raw_metrics
{
    u64 read_count;
    u64 read_size;
    u64 read_lat;
    u64 write_count;
    u64 write_size;
    u64 write_lat;
    char pod[100];
    char container[100];
};

struct rpc_task_info
{
    u64 timestamp;
    u32 pid;
    u32 tid;
};

struct rpc_task_state
{
    /* The first 8 bytes is not allowed to read */
    unsigned long pad;

    u64 task_id;
    u64 client_id;
    const void *action;
    unsigned long runstate;
    int status;
    unsigned short flags;
} __attribute__((packed));

struct nfs_file_fields
{
    /* The first 8 bytes is not allowed to read */
    unsigned long pad;

    dev_t dev;
    u32 fhandle;
    u64 fileid;
    loff_t offset;
    u32 arg_count;
    u32 res_count;
};

struct nfs_init_fields
{
    /* The first 8 bytes is not allowed to read */
    unsigned long pad;

    dev_t dev;
    u32 fhandle;
    u64 fileid;
    loff_t offset;
    u32 count;
};

// 1. 定义传递 span 上下文的结构体
struct span_info
{
    __u64 timestamp;      // 操作时间
    __u64 start_time;     // 操作开始时间
    __u64 end_time;       // 操作结束时间
    __u64 trace_id;       // trace id 高 64 位
    __u64 span_id;        // span id
    __u64 parent_span_id; // 父 span id
    __u32 pid;            // 进程 ID
    __u32 tid;            // 线程 ID
    char name[32];        // span 名称
    char pod[100];        // pod 名称
    char container[100];  // 容器名称
    __u64 dev_file_id;    // 设备文件 ID
} __attribute__((packed));

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct span_info);
    __uint(max_entries, 1024);
} link_begin SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct span_info);
    __uint(max_entries, 1024);
} waiting_RPC SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct span_info);
    __uint(max_entries, 1024);
} link_end SEC(".maps");

struct raw_metrics *unused_raw_metrics __attribute__((unused));
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, struct raw_metrics);
    __uint(max_entries, 4096);
} io_metrics SEC(".maps");
struct rpc_task_fields
{
    int pid;
    int mount_id;
    char pod[100];
    char container[100];
    u64 caller_addr;
    u32 dev_id;
    u32 file_id;
    u64 key;
};

struct rpc_task_fields *unused_event __attribute__((unused));

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} nfs_trace_map SEC(".maps");

struct metadata
{
    char pod[100];
    char container[100];
    u64 pid;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct metadata);
    __uint(max_entries, 2048);
} pid_cgroup_map SEC(".maps");

struct path_segment
{
    u64 file_id;
    u64 dev_id;
    u32 len;
    u8 is_complete;
    u8 depth;
    u8 name[100];
};

struct path_segment *unused_segment __attribute__((unused));

struct dns_event
{
    __u32 pid;
    u32 len;
    char common[100];
    char domain[200];
};

struct dns_event *unused_dns_event __attribute__((unused));

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} dns_events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} path_ringbuf SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);   // pid
    __type(value, u64); // request_id
    __uint(max_entries, 10000);
} active_requests SEC(".maps"); // 跟踪活跃的 NFS 请求

static __always_inline int process_dentry(struct pt_regs *ctx, struct dentry **dentry, struct dentry *root, u64 file_id, u64 dev_id, u8 depth)
{
    struct dentry *parent;
    struct qstr dname;
    struct path_segment segment = {};

    if (bpf_probe_read_kernel(&dname, sizeof(dname), &(*dentry)->d_name) < 0)
        return -1;

    segment.file_id = file_id;
    segment.dev_id = dev_id;
    segment.len = dname.len;
    segment.depth = depth;
    segment.is_complete = (*dentry == root || depth >= MAX_PATH_DEPTH - 1) ? 1 : 0;

    if (bpf_probe_read_kernel_str(segment.name, sizeof(segment.name), dname.name) < 0)
    {
        return -1;
    }

    if (cfg->debug_log)
    {
        bpf_printk("segment->name: %s\n", segment.name);
    }

    bpf_perf_event_output(ctx, &path_ringbuf, BPF_F_CURRENT_CPU, &segment, sizeof(segment));

    if (bpf_probe_read_kernel(&parent, sizeof(parent), &(*dentry)->d_parent) < 0)
        return -1;

    if (*dentry == parent || *dentry == root)
        return -1;

    *dentry = parent;
    return 0;
}

static __always_inline int get_full_path(struct pt_regs *ctx, struct dentry *dentry, struct dentry *root, u64 file_id, u64 dev_id)
{
    u8 depth = 0;

#pragma unroll
    for (int i = 0; i < MAX_PATH_DEPTH; i++)
    {
        if (process_dentry(ctx, &dentry, root, file_id, dev_id, depth) < 0)
            break;
        depth++;
    }

    return 0;
}

static __always_inline int
kprobe_nfs_kiocb(struct kiocb *iocb, struct pt_regs *ctx)
{
    struct rpc_task_fields event = {};

    // 获取 PID
    event.pid = bpf_get_current_pid_tgid() >> 32;

    // 使用 pid 到 pid_cgroup_map 中搜索
    struct metadata *metadata = bpf_map_lookup_elem(&pid_cgroup_map, &event.pid);
    if (metadata)
    {
        bpf_probe_read_kernel(&event.pod, sizeof(event.pod), metadata->pod);
        bpf_probe_read_kernel(&event.container, sizeof(event.container), metadata->container);
    }

    // 从 kiocb 结构体中获取文件路径
    struct file *file = BPF_CORE_READ(iocb, ki_filp);
    if (!file)
        return 0;

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;

    event.dev_id = BPF_CORE_READ(inode, i_sb, s_dev);
    event.file_id = BPF_CORE_READ(inode, i_ino);

    if (cfg->debug_log)
    {
        bpf_printk("Details - dev: %llu, file: %llu\n", event.dev_id, event.file_id);
    }

    event.key = (((u64)event.dev_id) << 32) | (event.file_id & 0xFFFFFFFF);

    struct path fp = BPF_CORE_READ(file, f_path);
    if (!fp.mnt)
        return 0;

    struct dentry *de = BPF_CORE_READ(&fp, dentry);
    if (!de)
        return 0;

    // 获取 stack point
    if (bpf_probe_read_kernel(&event.caller_addr, sizeof(event.caller_addr), (void *)PT_REGS_SP(ctx)))
    {
        return 0;
    }

    // 获取 mount id
    struct vfsmount *vfsmnt = BPF_CORE_READ(&fp, mnt);
    if (!vfsmnt)
        return 0;

    struct dentry *rootDentry = BPF_CORE_READ(vfsmnt, mnt_root);
    if (!rootDentry)
        return 0;

    // 获取文件的完整路径
    get_full_path(ctx, de, rootDentry, event.file_id, event.dev_id);

    struct mount *mnt = container_of(vfsmnt, struct mount, mnt);
    if (!mnt)
        return 0;

    event.mount_id = BPF_CORE_READ(mnt, mnt_id);

    // 输出件到 perf 事件数组
    bpf_perf_event_output(ctx, &nfs_trace_map, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return BPF_OK;
}

#define CONCAT(a, b) a##b
#define EXPAND_AND_CONCAT(a, b) CONCAT(a, b)

#ifdef HAS_KPROBE_MULTI
#define NFSTRACE_KPROBE_TYPE "kprobe.multi"
#define NFSTRACE_HAS_GET_FUNC_IP true
#else
#define NFSTRACE_KPROBE_TYPE "kprobe"
#define NFSTRACE_HAS_GET_FUNC_IP false
#endif /* HAS_KPROBE_MULTI */

#define NFSTRACE_ADD_KPROBE(X)                                                  \
    SEC(NFSTRACE_KPROBE_TYPE "/skb-" #X)                                        \
    int kprobe_skb_##X(struct pt_regs *ctx)                                     \
    {                                                                           \
        struct RPC_TASK_VAR *hdr = (struct RPC_TASK_VAR *)PT_REGS_PARM##X(ctx); \
        return EXPAND_AND_CONCAT(kprobe_nfs_, RPC_TASK_VAR)(hdr, ctx);          \
    }

NFSTRACE_ADD_KPROBE(1)
NFSTRACE_ADD_KPROBE(2)
NFSTRACE_ADD_KPROBE(3)
NFSTRACE_ADD_KPROBE(4)
NFSTRACE_ADD_KPROBE(5)

// tracepoint 增加 nfs_readpage_done/nfs_writeback_done 挂载函数用于统计 IOPS
SEC("tracepoint/nfs/nfs_initiate_read")
int nfs_init_read(struct nfs_init_fields *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 timestamp = bpf_ktime_get_ns();

    __u64 random = (timestamp << 32) | (pid & 0xFFFFFFFF);

    if (cfg->debug_log)
    {
        bpf_printk("request_id: %llu, pid: %u\n", random, pid);
    }

    // 记录活跃请求
    bpf_map_update_elem(&active_requests, &pid, &random, BPF_ANY);

    if (cfg->debug_log)
    {
        bpf_printk("nfs_init_read: %llu, pid: %u, tid: %u\n", timestamp, pid, tid);
    }

    struct span_info span = {
        .timestamp = timestamp,
        .start_time = timestamp,
        .pid = pid,
        .tid = tid,
        .trace_id = random,
        .span_id = random,
        .parent_span_id = random,
        .name = "nfs_initiate_read",
    };

    bpf_map_update_elem(&link_begin, &pid, &span, BPF_ANY);

    return 0;
}

SEC("tracepoint/nfs/nfs_initiate_write")
int nfs_init_write(struct nfs_init_fields *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 timestamp = bpf_ktime_get_ns();

    __u64 random = (timestamp << 32) | (pid & 0xFFFFFFFF);

    if (cfg->debug_log)
    {
        bpf_printk("request_id: %llu, pid: %u\n", random, pid);
    }

    // 记录活跃请求
    bpf_map_update_elem(&active_requests, &pid, &random, BPF_ANY);

    if (cfg->debug_log)
    {
        bpf_printk("nfs_init_write: %llu, pid: %u, tid: %u\n", timestamp, pid, tid);
    }

    struct span_info span = {
        .timestamp = timestamp,
        .start_time = timestamp,
        .pid = pid,
        .tid = tid,
        .trace_id = random,
        .span_id = random,
        .parent_span_id = random,
        .name = "nfs_initiate_write",
    };

    bpf_map_update_elem(&link_begin, &pid, &span, BPF_ANY);

    return 0;
}

SEC("tracepoint/sunrpc/rpc_task_begin")
int rpc_task_begin(struct rpc_task_state *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 rpc_task_id = (u64)ctx->task_id;
    u64 timestamp = bpf_ktime_get_ns();

    if (cfg->debug_log)
    {
        bpf_printk("rpc_task_begin: %llu, pid: %u, tid: %u\n", rpc_task_id, pid, tid);
    }

    struct span_info *span = bpf_map_lookup_elem(&link_begin, &pid);
    if (span)
    {
        span->end_time = timestamp;
        nfs_span_map__perf_event_output(ctx, (u64 *)span, sizeof(*span));

        __u64 random = (timestamp << 32) | (pid & 0xFFFFFFFF);
        span->span_id = random;
        span->start_time = span->end_time;
        __builtin_memcpy(span->name, "rpc_task_execute", sizeof("rpc_task_execute"));
        bpf_map_update_elem(&waiting_RPC, &rpc_task_id, span, BPF_ANY);
    }

    return 0;
}

SEC("tracepoint/sunrpc/rpc_task_end")
int rpc_task_done(struct rpc_task_state *ctx)
{
    u64 rpc_task_id = (u64)ctx->task_id;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 timestamp = bpf_ktime_get_ns();

    if (cfg->debug_log)
    {
        bpf_printk("rpc_task_done: %llu\n", rpc_task_id);
    }

    struct span_info *span = bpf_map_lookup_elem(&waiting_RPC, &rpc_task_id);
    if (span)
    {
        span->end_time = timestamp;
        nfs_span_map__perf_event_output(ctx, (u64 *)span, sizeof(*span));

        __u64 random = (timestamp << 32) | (pid & 0xFFFFFFFF);
        span->span_id = random;
        span->start_time = timestamp;
        __builtin_memcpy(span->name, "rpc_task_done", sizeof("rpc_task_done"));

        // 更新 link_end map
        int update_result = bpf_map_update_elem(&link_end, &span->pid, span, BPF_ANY);
        if (update_result != 0)
        {
            return 0;
        }

        // 从 waiting_RPC map 中删除元素
        int delete_result = bpf_map_delete_elem(&waiting_RPC, &rpc_task_id);
        if (delete_result != 0)
        {
            return 0;
        }
    }

    return 0;
}

SEC("kprobe/rpc_make_runnable")
int rpc_execute(struct pt_regs *regs)
{
    struct rpc_task *task;
    task = (struct rpc_task *)PT_REGS_PARM2(regs);

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 rpc_task_id = BPF_CORE_READ(task, tk_pid);
    u64 timestamp = bpf_ktime_get_ns();

    if (cfg->debug_log)
    {
        bpf_printk("rpc_execute: %llu, pid: %u, tid: %u\n", rpc_task_id, pid, tid);
    }

    struct span_info *span = bpf_map_lookup_elem(&link_begin, &pid);
    if (span)
    {
        span->end_time = timestamp;
        nfs_span_map__perf_event_output(regs, (u64 *)span, sizeof(*span));

        __u64 random = (timestamp << 32) | (pid & 0xFFFFFFFF);
        span->span_id = random;
        span->start_time = timestamp;
        __builtin_memcpy(span->name, "rpc_task_execute", sizeof("rpc_task_execute"));
        bpf_map_update_elem(&waiting_RPC, &rpc_task_id, span, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/rpc_exit_task")
int rpc_exit_task(struct pt_regs *regs)
{
    struct rpc_task *task;
    task = (struct rpc_task *)PT_REGS_PARM1(regs);
    u64 timestamp = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u64 rpc_task_id = BPF_CORE_READ(task, tk_pid);

    if (cfg->debug_log)
    {
        bpf_printk("rpc_exit_task: %llu\n", rpc_task_id);
    }

    struct span_info *span = bpf_map_lookup_elem(&waiting_RPC, &rpc_task_id);
    if (span)
    {
        span->end_time = timestamp;
        nfs_span_map__perf_event_output(regs, (u64 *)span, sizeof(*span));

        __u64 random = (timestamp << 32) | (pid & 0xFFFFFFFF);
        span->span_id = random;
        span->start_time = timestamp;
        __builtin_memcpy(span->name, "rpc_task_done", sizeof("rpc_task_done"));

        // 更新 link_end map
        int update_result = bpf_map_update_elem(&link_end, &span->pid, span, BPF_ANY);
        if (update_result != 0)
        {
            return 0;
        }

        // 从 waiting_RPC map 中删除元素
        int delete_result = bpf_map_delete_elem(&waiting_RPC, &rpc_task_id);
        if (delete_result != 0)
        {
            return 0;
        }
    }

    return 0;
}

SEC("kprobe/nfs_readpage_done")
int kb_nfs_read_d(struct pt_regs *regs)
{
    struct rpc_task *task;
    struct inode *inode;
    struct nfs_pgio_header *hdr;
    u64 current_time = bpf_ktime_get_ns();
    int pid;

    task = (struct rpc_task *)PT_REGS_PARM1(regs);

    // 获取 rpc owner pid
    if (bpf_probe_read_kernel(&pid, sizeof(pid), &task->tk_owner) < 0)
    {
        return 0;
    }

    inode = (struct inode *)PT_REGS_PARM3(regs);
    hdr = (struct nfs_pgio_header *)PT_REGS_PARM2(regs);

    // 获取 dev 和 fileid
    u64 dev = BPF_CORE_READ(inode, i_sb, s_dev);
    u64 fileid = BPF_CORE_READ(inode, i_ino);
    u64 key = (((u64)dev) << 32) | (fileid & 0xFFFFFFFF);

    // 获取读取字节数
    u32 res_count = BPF_CORE_READ(hdr, res.count);

    struct raw_metrics *metrics = bpf_map_lookup_elem(&io_metrics, &key);
    if (!metrics)
    {
        struct raw_metrics new_metrics = {0};
        bpf_map_update_elem(&io_metrics, &key, &new_metrics, BPF_ANY);
        metrics = bpf_map_lookup_elem(&io_metrics, &key);
        if (!metrics)
            return 0;
    }

    // 使用 pid 到 pid_cgroup_map 中搜索
    u64 pid_ptr = (u64)pid;
    struct metadata *metadata = bpf_map_lookup_elem(&pid_cgroup_map, &pid_ptr);
    if (metadata)
    {
        bpf_probe_read_kernel(&metrics->pod, sizeof(metrics->pod), metadata->pod);
        bpf_probe_read_kernel(&metrics->container, sizeof(metrics->container), metadata->container);
    }

    // 计算读操作延迟
    struct span_info *span = bpf_map_lookup_elem(&link_end, &pid);
    if (span)
    {
        span->end_time = current_time;
        bpf_probe_read_kernel(&span->pod, sizeof(span->pod), metadata->pod);
        bpf_probe_read_kernel(&span->container, sizeof(span->container), metadata->container);
        span->dev_file_id = key;
        nfs_span_map__perf_event_output(regs, (u64 *)span, sizeof(*span));

        metrics->read_lat += current_time - span->timestamp;
        bpf_map_delete_elem(&link_begin, &pid);
    }

    // 更新读操作计数和字节数
    __sync_fetch_and_add(&metrics->read_count, 1);
    __sync_fetch_and_add(&metrics->read_size, res_count);

    // 更新 io_metrics map
    bpf_map_update_elem(&io_metrics, &key, metrics, BPF_ANY);

    // 删除活跃请求
    bpf_map_delete_elem(&active_requests, &pid);

    if (cfg->debug_log)
    {
        bpf_printk("Read - dev: %llu, file: %llu\n", dev, fileid);
        // bpf_printk("Read - dev: %llu, file: %llu, bytes: %u, count: %d, total_bytes: %d, latency: %d\n",
        //            dev, fileid, res_count, metrics->read_count, metrics->read_size, metrics->read_lat);
    }

    return 0;
}

SEC("kprobe/nfs_writeback_done")
int kb_nfs_write_d(struct pt_regs *regs)
{
    int pid;
    struct rpc_task *task;
    struct inode *inode;
    struct nfs_pgio_header *hdr;
    u64 current_time = bpf_ktime_get_ns();

    task = (struct rpc_task *)PT_REGS_PARM1(regs);

    // 获取 rpc owner pid
    if (bpf_probe_read_kernel(&pid, sizeof(pid), &task->tk_owner) < 0)
    {
        return 0;
    }

    inode = (struct inode *)PT_REGS_PARM3(regs);
    hdr = (struct nfs_pgio_header *)PT_REGS_PARM2(regs);

    // 获取 dev 和 fileid
    u64 dev = BPF_CORE_READ(inode, i_sb, s_dev);
    u64 fileid = BPF_CORE_READ(inode, i_ino);
    u64 key = (((u64)dev) << 32) | (fileid & 0xFFFFFFFF);
    // 获取写入字节数
    u32 res_count = BPF_CORE_READ(hdr, res.count);

    struct raw_metrics *metrics = bpf_map_lookup_elem(&io_metrics, &key);
    if (!metrics)
    {
        struct raw_metrics new_metrics = {0};
        bpf_map_update_elem(&io_metrics, &key, &new_metrics, BPF_ANY);
        metrics = bpf_map_lookup_elem(&io_metrics, &key);
        if (!metrics)
            return 0;
    }

    // 使用 pid 到 pid_cgroup_map 中搜索
    u64 pid_ptr = (u64)pid;
    struct metadata *metadata = bpf_map_lookup_elem(&pid_cgroup_map, &pid_ptr);
    if (metadata)
    {
        bpf_probe_read_kernel(&metrics->pod, sizeof(metrics->pod), metadata->pod);
        bpf_probe_read_kernel(&metrics->container, sizeof(metrics->container), metadata->container);
    }

    // 计算写操作延迟
    struct span_info *span = bpf_map_lookup_elem(&link_end, &pid);
    if (span)
    {
        span->end_time = current_time;
        bpf_probe_read_kernel(&span->pod, sizeof(span->pod), metadata->pod);
        bpf_probe_read_kernel(&span->container, sizeof(span->container), metadata->container);
        span->dev_file_id = key;
        nfs_span_map__perf_event_output(regs, (u64 *)span, sizeof(*span));
        metrics->write_lat += current_time - span->timestamp;
        bpf_map_delete_elem(&link_begin, &pid);
    }

    // 更新写操作计数和字节数
    __sync_fetch_and_add(&metrics->write_count, 1);
    __sync_fetch_and_add(&metrics->write_size, res_count);

    // 更新 io_metrics map
    bpf_map_update_elem(&io_metrics, &key, metrics, BPF_ANY);

    // 删除活跃请求
    bpf_map_delete_elem(&active_requests, &pid);

    if (cfg->debug_log)
    {
        bpf_printk("Write - dev: %llu, file: %llu\n", dev, fileid);
        // bpf_printk("Write - dev: %llu, file: %llu, bytes: %u, count: %d, total_bytes: %d, latency: %d\n",
        //            dev, fileid, res_count, metrics->write_count, metrics->write_size, metrics->write_lat);
    }

    return 0;
}

char __license[] SEC("license") = "Dual BSD/GPL";
