# bpfnfs
bpfnfs 使用 eBPF 技术监控和分析 NFS（网络文件系统）操作。它提供了 NFS 性能指标的实时洞察，并帮助诊断分布式文件系统中的问题。

## 功能

- 实时监控 NFS 读写操作
- 性能指标收集（IOPS、延迟、吞吐量）
- Kubernetes 集成，用于 Pod 级别的 NFS 使用跟踪
- Prometheus 指标导出，便于与监控系统集成
- 可定制的函数探测和过滤

## 前提条件

- 支持 BTF 的 Linux 内核 4.19+
- Go 1.22+
- Kubernetes 集群（用于 K8s 集成）

已测试的操作系统和内核版本：
- KylinOS 10 SP3 (ARM64) - kernel 4.19.90
- Ubuntu 24.04 (AMD64) - kernel 6.8.0
- Ubuntu 22.04 (AMD64) - kernel 5.15.0
- Alibaba Cloud Linux OS 3 (AMD64) - kernel 5.10.134-16.3.al8 

## 安装

1. 克隆仓库：
   ```bash
   git clone https://github.com/cen-ngc5139/bpfnfs.git
   cd bpfnfs
   ```

2. 构建项目：
   ```bash
   make build
   ```

## 使用

使用默认设置运行 NFS Trace：

```
./bpfnfs
```

获取更多高级用法和配置选项：

```
./bpfnfs --help
```

### 阿里云 OS 专门启动方式

在阿里云 OS 上启动监控时，需要指定 BTF 文件，因为阿里云 Linux 的 BTF 文件可能不在默认位置。此外，由于 NFS 相关的 `rpc_task` 结构定义在内核模块中而不是主内核 vmlinux 中，我们还需要指定内核模块 BTF 文件的目录。

以下是具体的启动命令示例：

```bash
# 使用配置文件指定 BTF 文件
./bpfnfs --config-path=/path/to/config.yaml
```

配置文件示例 (config.yaml):
```yaml
btf:
  kernel: "/path/to/btf/linux-5.10.134-16.3.al8-vmlinux.btf"
  model_dir: "/path/to/btf"  # 可选，默认为 /sys/kernel/btf

# 其他配置项...
```

## 配置

NFS Trace 支持通过配置文件进行配置，配置文件路径可以通过 `--config-path` 指定。

配置文件示例：

```yaml
filter:
  func: "^(vfs_|nfs_).*"
  struct: "kiocb"

probing:
  all_kmods: true
  skip_attach: false
  add_funcs: "nfs_file_direct_read:1,nfs_file_direct_write:1,nfs_swap_rw:1,nfs_file_read:1,nfs_file_write:1"

features:
  debug: false
  dns: true
  nfs_metrics: true

output:
  type: otlp  # 支持输出到 OpenTelemetry Collector
  otlp:
    endpoint: "localhost:4317"  # OTLP gRPC 端点
    insecure: true             # 是否使用非安全连接
    timeout: "30s"             # 连接超时时间
    headers:                   # 自定义请求头
      Authorization: "Bearer <token>"
```

## 指标与追踪

NFS Trace 收集并导出以下数据：

### 指标
- NFS 读/写次数
- NFS 读/写大小
- NFS 读/写延迟

这些指标可以通过 `/metrics` 的 Prometheus 端点获取。

### 追踪
支持将 NFS 操作追踪数据以 OpenTelemetry 格式输出到 OpenTelemetry Collector，包括：
- NFS 操作的完整调用链
- 操作类型、文件路径等属性
- 操作耗时
- 错误信息

## Kubernetes 集成

NFS Trace 可以作为 DaemonSet / Deployment 部署在您的 Kubernetes 集群中，以监控所有节点上的 NFS 操作。它提供了 Pod 级别的 NFS 使用可见性。

## 贡献

欢迎贡献！请随时提交 Pull Request。

## 许可证

本项目采用 Dual BSD/GPL 许可证 - 详见 [LICENSE](LICENSE) 文件。

## 特别致谢

开发过程中参考了以下项目，在此表示感谢：

1. NFS 性能指标的实现参考了以下论文：
- [T Dubuc](http://perso.ens-lyon.fr/theophile.dubuc/files/CHEOPS24-TrackIOps.pdf)

2. eBPF 程序的管理以及 CO-RE 工具借鉴以下项目：
- [PWRU](https://github.com/cilium/pwru)

3. eBPF 脚手架使用以下项目：
- [Cilium eBPF](https://github.com/cilium/ebpf) 