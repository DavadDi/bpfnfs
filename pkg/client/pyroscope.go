package client

import (
	"context"
	"strconv"
	"time"
)

// PyroscopeClient 专门处理与 Pyroscope 服务器的交互
type PyroscopeClient struct {
	*BaseClient
}

// PyroscopeParams 定义所有可能的查询参数
type PyroscopeParams struct {
	Name            string `json:"name"`                      // required
	From            int64  `json:"from"`                      // required
	Until           int64  `json:"until"`                     // required
	Format          string `json:"format,omitempty"`          // optional, default: folded
	SampleRate      int    `json:"sampleRate,omitempty"`      // optional, default: 100
	SpyName         string `json:"spyName,omitempty"`         // optional
	Units           string `json:"units,omitempty"`           // optional, default: samples
	AggregationType string `json:"aggregationType,omitempty"` // optional, default: sum
}

// NewPyroscopeClient 创建新的 Pyroscope 客户端
func NewPyroscopeClient(url string, timeout time.Duration) *PyroscopeClient {
	return &PyroscopeClient{
		BaseClient: NewBaseClient(url, timeout),
	}
}

// IngestProfile 上传性能分析数据到 Pyroscope
func (c *PyroscopeClient) IngestProfile(ctx context.Context, params PyroscopeParams, data string) error {
	queryParams := map[string]string{
		"name":  params.Name,
		"from":  strconv.FormatInt(params.From, 10),
		"until": strconv.FormatInt(params.Until, 10),
	}

	// 添加可选参数
	if params.Format != "" {
		queryParams["format"] = params.Format
	}
	if params.SampleRate > 0 {
		queryParams["sampleRate"] = strconv.Itoa(params.SampleRate)
	}
	if params.SpyName != "" {
		queryParams["spyName"] = params.SpyName
	}
	if params.Units != "" {
		queryParams["units"] = params.Units
	}
	if params.AggregationType != "" {
		queryParams["aggregationType"] = params.AggregationType
	}

	return c.PostRawData(ctx, "/ingest", data, queryParams)
}
