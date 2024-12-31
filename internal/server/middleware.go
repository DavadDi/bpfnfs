package server

import (
	"github.com/cen-ngc5139/bpfnfs/internal/cache"
	"github.com/cen-ngc5139/bpfnfs/internal/output"
	"github.com/gin-gonic/gin"
)

func InitPrometheusMetrics(r *gin.Engine) {
	nfsMetrics := output.NewNFSMetrics(cache.NFSPerformanceMap, cache.NFSFileDetailMap)
	traceMetrics := output.NewTraceMetrics(nfsMetrics)
	r.GET("/metrics", traceMetrics.MetricsHandler())
}
