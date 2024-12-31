package config

type Configuration struct {
	Pprof      PprofConfig    `yaml:"pprof"`
	Filter     FilterConfig   `yaml:"filter"`
	BTF        BTFConfig      `yaml:"btf"`
	Probing    ProbingConfig  `yaml:"probing"`
	Features   FeaturesConfig `yaml:"features"`
	Output     OutputConfig   `yaml:"output"`
	ConfigPath string         `yaml:"-"`
}

type PprofConfig struct {
	Enable bool `yaml:"enable"`
}

type FilterConfig struct {
	Func   string `yaml:"func"`
	Struct string `yaml:"struct"`
}

type BTFConfig struct {
	Kernel   string `yaml:"kernel"`
	ModelDir string `yaml:"model_dir"`
}

type ProbingConfig struct {
	AllKMods   bool   `yaml:"all_kmods"`
	SkipAttach bool   `yaml:"skip_attach"`
	AddFuncs   string `yaml:"add_funcs"`
}

type FeaturesConfig struct {
	Debug      bool `yaml:"debug"`
	NFSMetrics bool `yaml:"nfs_metrics"`
	NFSTracer  bool `yaml:"nfs_tracer"`
}

type OutputConfig struct {
	Type   string            `yaml:"type"` // enum: file, stdout, kafka
	File   FileOutputConfig  `yaml:"file"`
	Stdout struct{}          `yaml:"stdout"`
	Kafka  KafkaOutputConfig `yaml:"kafka"`
	OTel   OTelOutputConfig  `yaml:"otel"`
}

type OTelOutputConfig struct {
	Enable   bool   `yaml:"enable"`
	Endpoint string `yaml:"endpoint"`
}

type FileOutputConfig struct {
	Path string `yaml:"path"`
}

type KafkaOutputConfig struct {
	Brokers []string `yaml:"brokers"`
	Topic   string   `yaml:"topic"`
}
