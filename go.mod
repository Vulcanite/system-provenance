module system-monitor

go 1.25.4

require (
	github.com/cilium/ebpf v0.20.0
	github.com/elastic/go-elasticsearch/v8 v8.19.0
	github.com/google/gopacket v1.1.19
)

require gopkg.in/yaml.v3 v3.0.1 // indirect

require (
	github.com/elastic/elastic-transport-go/v8 v8.8.0 // indirect
	github.com/elastic/go-libaudit/v2 v2.6.2
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.38.0 // indirect
	go.opentelemetry.io/otel/metric v1.38.0 // indirect
	go.opentelemetry.io/otel/trace v1.38.0 // indirect
	golang.org/x/sys v0.38.0
)
