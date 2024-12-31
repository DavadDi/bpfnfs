package output

import (
	"context"
	"fmt"
	"os"
	"time"

	"encoding/binary"

	"golang.org/x/sys/unix"

	ebpfbinary "github.com/cen-ngc5139/bpfnfs/internal/binary"
	"github.com/cen-ngc5139/bpfnfs/internal/cache"
	"github.com/cen-ngc5139/bpfnfs/internal/config"
	"github.com/cen-ngc5139/bpfnfs/internal/log"
	"github.com/cen-ngc5139/bpfnfs/internal/metadata"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"go.opentelemetry.io/otel/trace"
)

func InitTracerProvider(ctx context.Context, url string) (*sdktrace.TracerProvider, error) {
	// 创建 OTLP exporter
	client := otlptracegrpc.NewClient(
		otlptracegrpc.WithEndpoint(url),
		otlptracegrpc.WithInsecure(),
	)
	exporter, err := otlptrace.New(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("创建 OTLP exporter 失败: %w", err)
	}

	// 创建资源信息
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String("bpfnfs"),
			semconv.ServiceVersionKey.String("1.0.0"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("创建资源失败: %w", err)
	}

	// 创建 TracerProvider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	return tp, nil
}

func ProcessSpan(coll *ebpf.Collection, ctx context.Context, cfg config.Configuration, nodeName string) {
	events := coll.Maps["__nfs_span_map"]
	// Set up a perf reader to read events from the eBPF program
	rd, err := perf.NewReader(events, os.Getpagesize())
	if err != nil {
		log.Fatalf("Creating perf reader failed: %v\n", err)
	}
	defer rd.Close()

	var event ebpfbinary.NFSTraceSpanInfo
	for {
		for {
			if err := parseEvent(rd, &event); err == nil {
				break
			}

			select {
			case <-ctx.Done():
				log.Infof("退出事件处理")
				return
			case <-time.After(time.Microsecond):
				continue
			}
		}

		log.StdoutOrFile(cfg.Output.Type, event, map[string]interface{}{"type": "span", "name": convertInt8ToString(event.Name[:])})
		if cfg.Output.OTel.Enable {
			tracer := otel.Tracer("bpfnfs")

			var file metadata.NFSFile
			fileInfo, ok := cache.NFSDevIDFileIDFileInfoMap.Load(event.DevFileId)
			if ok {
				file = fileInfo.(metadata.NFSFile)
			}

			// 创建 SpanContext
			spanCtx := trace.NewSpanContext(trace.SpanContextConfig{
				TraceID:    generateTraceID(event.TraceId),
				SpanID:     generateSpanID(event.SpanId),
				TraceFlags: trace.FlagsSampled,
			})

			// 创建带有 parent context 的新 context
			ctxWithSpan := trace.ContextWithSpanContext(ctx, spanCtx)

			// 使用带有 parent context 的 context 创建新的 span
			_, span := tracer.Start(ctxWithSpan, convertInt8ToString(event.Name[:]),
				trace.WithTimestamp(kernelTimeToTime(event.StartTime)))
			span.SetAttributes(
				attribute.String("name", convertInt8ToString(event.Name[:])),
				attribute.String("parent_span_id", generateSpanID(event.ParentSpanId).String()),
				attribute.Int64("duration_ns", int64(event.EndTime-event.StartTime)),
				attribute.Int64("pid", int64(event.Pid)),
				attribute.Int64("tid", int64(event.Tid)),
				attribute.String("node", nodeName),
				attribute.String("pod", sanitizeString(convertInt8ToString(event.Pod[:]))),
				attribute.String("container", sanitizeString(convertInt8ToString(event.Container[:]))),
				attribute.Int64("dev_file_id", int64(event.DevFileId)),
				attribute.String("file_path", file.FilePath),
				attribute.String("mount_path", file.MountPath),
				attribute.String("remote_nfs_addr", file.RemoteNFSAddr),
				attribute.String("local_mount_dir", file.LocalMountDir),
				attribute.String("pyroscope.profile.id", generateSpanID(event.ParentSpanId).String()),
			)
			span.End(trace.WithTimestamp(kernelTimeToTime(event.EndTime)))
		}

		select {
		case <-ctx.Done():
			log.Infof("退出事件处理")
			return
		default:
		}
	}
}

func generateTraceID(high uint64) trace.TraceID {
	var tid [16]byte
	binary.BigEndian.PutUint64(tid[0:8], high)
	return tid
}

func generateSpanID(id uint64) trace.SpanID {
	var sid [8]byte
	binary.BigEndian.PutUint64(sid[:], id)
	return sid
}

func calculateMonotonicOffset() time.Duration {
	mono := &unix.Timespec{}
	now := time.Now()
	_ = unix.ClockGettime(unix.CLOCK_BOOTTIME, mono)
	return time.Duration(now.UnixNano() - unix.TimespecToNsec(*mono))
}

func kernelTimeToTime(monotonic uint64) time.Time {
	// 获取单调时钟的偏移量
	offset := calculateMonotonicOffset()

	// 将 BPF 时间转换为 time.Duration
	monotonicDuration := time.Duration(monotonic)

	// 返回实际时间 = 偏移量 + BPF时间
	return time.Unix(0, int64(offset+monotonicDuration))
}
