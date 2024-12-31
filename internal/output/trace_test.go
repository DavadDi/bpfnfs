package output

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestKernelTimeToTime(t *testing.T) {
	// 获取当前单调时钟时间作为基准
	mono := &unix.Timespec{}
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, mono); err != nil {
		t.Fatalf("获取单调时钟时间失败: %v", err)
	}
	monoNs := unix.TimespecToNsec(*mono)

	// 测试用例
	tests := []struct {
		name      string
		monotonic uint64
		want      time.Duration // 期望的误差范围
	}{
		{
			name:      "当前时间",
			monotonic: uint64(monoNs),
			want:      time.Millisecond * 100, // 允许100ms误差
		},
		{
			name:      "过去时间",
			monotonic: uint64(monoNs) - uint64(time.Second),
			want:      time.Millisecond * 100,
		},
		{
			name:      "1分钟时间戳",
			monotonic: uint64(time.Minute),
			want:      time.Second, // 允许1秒误差
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 获取转换后的时间
			got := kernelTimeToTime(tt.monotonic)

			// 计算预期时间
			offset := calculateMonotonicOffset()
			want := time.Unix(0, int64(offset+time.Duration(tt.monotonic)))

			// 比较结果
			diff := got.Sub(want).Abs()
			if diff > tt.want {
				t.Errorf("kernelTimeToTime() = %v, want %v ± %v, diff = %v",
					got, want, tt.want, diff)
			}
		})
	}
}
