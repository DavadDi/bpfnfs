package output

import (
	"fmt"
	"os"
	"sync"

	"github.com/cen-ngc5139/bpfnfs/internal/metadata"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	NFSReadCount      = "nfs_read_count"
	NFSWriteCount     = "nfs_write_count"
	NFSReadSize       = "nfs_read_size"
	NFSWriteSize      = "nfs_write_size"
	NFSReadLatencies  = "nfs_read_latencies"
	NFSWriteLatencies = "nfs_write_latencies"
	// NFSFileDetail     = "nfs_file_detail"
)

type TraceMetrics struct {
	NFSMetrics *NFSMetrics
}

func NewTraceMetrics(nfsMetrics *NFSMetrics) *TraceMetrics {
	return &TraceMetrics{
		NFSMetrics: nfsMetrics,
	}
}

// NFSMetrics holds all the NFS related metrics
type NFSMetrics struct {
	ReadCount      *prometheus.GaugeVec
	WriteCount     *prometheus.GaugeVec
	ReadSize       *prometheus.GaugeVec
	WriteSize      *prometheus.GaugeVec
	ReadLatencies  *prometheus.GaugeVec
	WriteLatencies *prometheus.GaugeVec
	NFSFileDetail  *prometheus.GaugeVec
	performanceMap *sync.Map
	fileInfoMap    *sync.Map
}

// createNFSMetricsGaugeVec 创建并注册一个 prometheus.GaugeVec
func createNFSMetricsGaugeVec(name, help string) *prometheus.GaugeVec {
	return promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: name,
			Help: help,
		},
		[]string{"dev_id", "file_id", "node_name", "nfs_server", "file_path", "mount_path", "nfs_pod", "nfs_container"},
	)
}

func createGaugeVec(name, help string, labels []string) *prometheus.GaugeVec {
	return promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: name,
			Help: help,
		},
		labels,
	)
}

// NewNFSMetrics 创建并注册 NFS 指标
func NewNFSMetrics(performanceMap *sync.Map, fileInfoMap *sync.Map) *NFSMetrics {
	return &NFSMetrics{
		ReadCount:      createNFSMetricsGaugeVec(NFSReadCount, "NFS read count"),
		WriteCount:     createNFSMetricsGaugeVec(NFSWriteCount, "NFS write count"),
		ReadSize:       createNFSMetricsGaugeVec(NFSReadSize, "NFS read size"),
		WriteSize:      createNFSMetricsGaugeVec(NFSWriteSize, "NFS write size"),
		ReadLatencies:  createNFSMetricsGaugeVec(NFSReadLatencies, "NFS read latencies"),
		WriteLatencies: createNFSMetricsGaugeVec(NFSWriteLatencies, "NFS write latencies"),
		// NFSFileDetail:  createCounterVec(NFSFileDetail, "NFS file detail"),
		performanceMap: performanceMap,
		fileInfoMap:    fileInfoMap,
	}
}

func GetDevIDFileID(keyStr uint64) (string, string) {
	// 假设 keyStr 的格式是 "devID:fileID"
	devID, fileID := parseKey(keyStr)

	// devID fileID 转换成字符串
	devIDStr := fmt.Sprintf("%d", devID)
	fileIDStr := fmt.Sprintf("%d", fileID)

	return devIDStr, fileIDStr
}

// UpdateMetricsFromCache updates the Prometheus metrics from the NFSPerformanceMap
func (m *NFSMetrics) UpdateMetricsFromCache(nodeName string) {
	// m.fileInfoMap.Range(func(key, value interface{}) bool {
	// 	devIDStr, fileIDStr := GetDevIDFileID(key.(uint64))
	// 	m.NFSFileDetail.WithLabelValues(devIDStr, fileIDStr, nodeName, "", value.(string), "", "", "").Set(1)
	// 	return true
	// })

	m.performanceMap.Range(func(key, value interface{}) bool {
		keyStr := key.(uint64)
		info := value.(metadata.NFSTraceInfo)
		metrics := info.Traffic
		file := info.File
		nfsServer := file.RemoteNFSAddr
		filePath := file.FilePath
		mountPath := file.MountPath

		// 假设 keyStr 的格式是 "devID:fileID"
		devID, fileID := parseKey(keyStr)

		// devID fileID 转换成字符串
		devIDStr := fmt.Sprintf("%d", devID)
		fileIDStr := fmt.Sprintf("%d", fileID)
		pod := file.Pod
		container := file.Container

		// 更新所有指标
		if metrics.ReadCount > 0 {
			m.ReadCount.WithLabelValues(devIDStr, fileIDStr, nodeName, nfsServer, filePath, mountPath, pod, container).Set(float64(metrics.ReadCount))
		}
		if metrics.WriteCount > 0 {
			m.WriteCount.WithLabelValues(devIDStr, fileIDStr, nodeName, nfsServer, filePath, mountPath, pod, container).Set(float64(metrics.WriteCount))
		}
		if metrics.ReadSize > 0 {
			m.ReadSize.WithLabelValues(devIDStr, fileIDStr, nodeName, nfsServer, filePath, mountPath, pod, container).Set(float64(metrics.ReadSize))
		}
		if metrics.WriteSize > 0 {
			m.WriteSize.WithLabelValues(devIDStr, fileIDStr, nodeName, nfsServer, filePath, mountPath, pod, container).Set(float64(metrics.WriteSize))
		}
		if metrics.ReadLat > 0 {
			m.ReadLatencies.WithLabelValues(devIDStr, fileIDStr, nodeName, nfsServer, filePath, mountPath, pod, container).Set(float64(metrics.ReadLat))
		}
		if metrics.WriteLat > 0 {
			m.WriteLatencies.WithLabelValues(devIDStr, fileIDStr, nodeName, nfsServer, filePath, mountPath, pod, container).Set(float64(metrics.WriteLat))
		}

		return true
	})
}

func (m *TraceMetrics) MetricsHandler() gin.HandlerFunc {
	h := promhttp.Handler()

	nodeName, err := os.Hostname()
	if err != nil {
		nodeName = "default_node"
	}

	return func(c *gin.Context) {
		m.NFSMetrics.UpdateMetricsFromCache(nodeName)
		h.ServeHTTP(c.Writer, c.Request)
	}
}
