## ADR-0006: Local-First, Cloud-Second Observability Stack

**Status:** Accepted  
**Date:** 2025-07-17  
**Tags:** infrastructure, learning, cost, docker, cloud

### Context

Cloud observability services provide production-grade capabilities but introduce learning friction during development and experimentation phases. The primary goal is observability mastery, not immediate production deployment.

### Problem Statement

Cloud observability services create barriers to learning:

- **Authentication complexity**: Service accounts, IAM policies, API key management
- **Network dependencies**: Outbound connectivity, firewall rules, quota limits
- **Cost concerns**: Ingestion charges during experimentation and high-frequency testing
- **Debugging overhead**: Cannot inspect pipeline internals or troubleshoot configurations
- **Rate limiting**: API limits prevent rapid iteration during learning phases

### Forces & Considerations

| Approach | Learning Velocity | Production Fidelity | Cost | Debugging Capability |
|----------|------------------|-------------------|------|---------------------|
| **Local-only** | High | Low | Free | High |
| **Cloud-first** | Low | High | Variable | Low |
| **Hybrid** | Medium | High | Controlled | Medium |
| **Local→Cloud** | High→Medium | Low→High | Free→Controlled | High→Medium |

### Options Considered

#### Option 1: Cloud-First Development (Rejected)

Start with production cloud services from day one.

**Pros:**

- Production-realistic environment
- Real-world integration patterns
- Immediate scalability testing

**Cons:**

- Authentication setup complexity
- Ingestion costs during learning
- Network configuration overhead
- Difficult to debug pipeline issues

#### Option 2: Local-Only Development (Rejected)

Never integrate with cloud services.

**Pros:**

- No external dependencies
- Free experimentation
- Fast iteration cycles

**Cons:**

- No cloud integration patterns
- May miss production-specific issues
- Cannot test cloud-specific features

#### Option 3: Local-First, Cloud-Second (Chosen)

Start local, add cloud exporters after patterns are mastered.

**Pros:**

- Fast learning velocity
- Controlled costs
- Gradual complexity introduction
- Easy debugging

**Cons:**

- Two configuration paths
- Delayed cloud pattern learning

#### Option 4: Hybrid from Start (Rejected)

Run both local and cloud simultaneously.

**Pros:**

- Best of both worlds
- Immediate comparison

**Cons:**

- Configuration complexity
- Cost from day one
- Overwhelming for learning

### Decision

**Learn with local stack first, add cloud exporters after patterns are mastered.**

### Implementation Strategy

#### Phase 1-5: Local Development Stack

```yaml
# docker-compose.yml - Complete observability pipeline
version: '3.8'

networks:
  observability-net:
    driver: bridge

volumes:
  tempo-data:
  prometheus-data:
  grafana-data:

services:
  # Application (containerized for robust networking)
  api:
    build: .
    environment:
      - OTLP_ENDPOINT=http://otel-collector:4318  # HTTP endpoint for consistency
      - SERVICE_NAME=go-observability-mastery
      - ENVIRONMENT=local
    ports:
      - "8080:8080"
    depends_on:
      - otel-collector
    networks:
      - observability-net

  # OpenTelemetry Collector - Central telemetry processor
  otel-collector:
    image: otel/opentelemetry-collector-contrib:0.116.0
    command: ["--config=/etc/otel-collector-config.yml"]
    volumes:
      - ./deployments/otel-collector/config.yml:/etc/otel-collector-config.yml
    ports:
      - "4318:4318"   # OTLP HTTP receiver
      - "8888:8888"   # Self-metrics endpoint
      - "13133:13133" # Health check extension
    networks:
      - observability-net

  # Tempo: Trace storage and query
  tempo:
    image: grafana/tempo:2.8.1
    command: ["-config.file=/etc/tempo.yml"]
    volumes:
      - ./deployments/tempo/tempo.yml:/etc/tempo.yml
      - tempo-data:/var/tempo
    ports:
      - "3200:3200"   # Tempo HTTP API
    networks:
      - observability-net

  # Prometheus: Metrics collection and storage
  prometheus:
    image: prom/prometheus:v2.54.1
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=15d'
      - '--web.enable-lifecycle'
    volumes:
      - ./deployments/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    ports:
      - "9090:9090"
    networks:
      - observability-net

  # Grafana: Dashboards and visualization
  grafana:
    image: grafana/grafana:11.4.0
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_FEATURE_TOGGLES_ENABLE=traceqlEditor
      - GF_INSTALL_PLUGINS=grafana-piechart-panel
    volumes:
      - grafana-data:/var/lib/grafana
      - ./deployments/grafana/provisioning:/etc/grafana/provisioning
    ports:
      - "3000:3000"
    networks:
      - observability-net
```

#### OpenTelemetry Collector Configuration

```yaml
# deployments/otel-collector/config.yml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318  # HTTP receiver for consistency
      grpc:
        endpoint: 0.0.0.0:4317  # gRPC receiver for compatibility

processors:
  batch:
    timeout: 1s
    send_batch_size: 1024
    send_batch_max_size: 2048

  memory_limiter:
    limit_mib: 512

  resource:
    attributes:
      - key: environment
        value: local
        action: insert

exporters:
  # Local exporters
  otlp/tempo:
    endpoint: tempo:4317
    tls:
      insecure: true

  logging:
    loglevel: debug
    sampling_initial: 5
    sampling_thereafter: 200

service:
  telemetry:
    metrics:
      address: 0.0.0.0:8888  # Self-metrics for Prometheus scraping

  extensions: [health_check]

  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, resource, batch]
      exporters: [otlp/tempo, logging]

    metrics:
      receivers: [otlp]
      processors: [memory_limiter, resource, batch]
      exporters: [logging]

extensions:
  health_check:
    endpoint: 0.0.0.0:13133
```

#### Prometheus Configuration

```yaml
# deployments/prometheus/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "rules/*.yml"

scrape_configs:
  - job_name: 'go-api'
    static_configs:
      - targets: ['api:8080']
    metrics_path: '/metrics'
    scrape_interval: 10s

  - job_name: 'otel-collector'
    static_configs:
      - targets: ['otel-collector:8888']  # Self-metrics port
    metrics_path: '/metrics'
    scrape_interval: 10s

alerting:
  alertmanagers:
    - static_configs:
        - targets: []  # No alertmanager in local development

# Optional: Include recording rules for development
recording_rules:
  - name: development_rules
    rules:
      - record: api:request_rate_5m
        expr: rate(http_requests_total[5m])
      - record: api:error_rate_5m  
        expr: rate(http_requests_total{status_class="4xx"}[5m]) + rate(http_requests_total{status_class="5xx"}[5m])
```

#### Tempo Configuration

```yaml
# deployments/tempo/tempo.yml
server:
  http_listen_port: 3200

distributor:
  receivers:
    otlp:
      protocols:
        grpc:
          endpoint: 0.0.0.0:4317
        http:
          endpoint: 0.0.0.0:4318

ingester:
  trace_idle_period: 10s
  max_block_bytes: 1_000_000
  max_block_duration: 5m

storage:
  trace:
    backend: local
    wal:
      path: /var/tempo/wal
    local:
      path: /var/tempo/blocks

compactor:
  compaction:
    block_retention: 1h  # Short retention for development

overrides:
  ingestion_rate_strategy: local
  ingestion_rate_limit_bytes: 20000000
  ingestion_burst_size_bytes: 30000000
```

#### Phase 6: Cloud Integration (Optional)

```yaml
# Optional cloud exporters (same interfaces)
exporters:
  # Google Cloud Logging
  googlecloud:
    project: ${GCP_PROJECT_ID}
    
  # Sentry for error tracking
  sentry:
    dsn: ${SENTRY_DSN}
    environment: ${ENVIRONMENT}
    
  # Google Cloud Trace
  googlecloud/trace:
    project: ${GCP_PROJECT_ID}

# Update pipelines to include cloud exporters
pipelines:
  traces:
    receivers: [otlp]
    processors: [memory_limiter, resource, batch]
    exporters: [otlp/tempo, googlecloud/trace]  # Both local and cloud
    
  logs:
    receivers: [otlp]
    processors: [memory_limiter, resource, batch]
    exporters: [logging, googlecloud]  # Both local and cloud
```

### Health Check Automation

#### Comprehensive Health Monitoring

```bash
#!/bin/bash
# scripts/health-check.sh

set -e

echo "🔍 Checking observability stack health..."

declare -A services=(
    ["prometheus"]="http://localhost:9090/-/ready"
    ["grafana"]="http://localhost:3000/api/health"
    ["tempo"]="http://localhost:3200/api/status"  # Updated endpoint
    ["otel-collector"]="http://localhost:13133/"
    ["api"]="http://localhost:8080/health"
)

all_healthy=true
failed_services=()

for service in "${!services[@]}"; do
    url="${services[$service]}"
    echo -n "Checking $service... "

    if curl -sf "$url" > /dev/null 2>&1; then
        echo "✅ healthy"
    else
        echo "❌ unhealthy"
        failed_services+=("$service")
        all_healthy=false
    fi
done

if $all_healthy; then
    echo "🎉 All services are healthy!"
    echo ""
    echo "📊 Access URLs:"
    echo "  Grafana:    http://localhost:3000 (admin/admin)"
    echo "  Prometheus: http://localhost:9090"
    echo "  Tempo:      http://localhost:3200"
    echo "  API:        http://localhost:8080"
    exit 0
else
    echo ""
    echo "💥 Failed services: ${failed_services[*]}"
    echo "📋 Troubleshooting steps:"
    echo "  1. Check Docker containers: docker-compose -f deployments/docker-compose.yml ps"
    echo "  2. Check service logs: docker-compose -f deployments/docker-compose.yml logs [service]"
    echo "  3. Restart stack: make stack-restart"
    exit 1
fi
```

#### Pipeline Verification

```bash
#!/bin/bash
# scripts/verify-pipeline.sh

echo "🔧 Verifying observability pipeline end-to-end..."

# Step 1: Generate test signals
echo "📡 Generating test signals..."
curl -s http://localhost:8080/health > /dev/null
sleep 2

# Step 2: Verify metrics collection
echo "📊 Verifying metrics pipeline..."
if curl -s "http://localhost:9090/api/v1/query?query=up" | jq -e '.data.result | length > 0' > /dev/null; then
    echo "✅ Metrics pipeline working"
else
    echo "❌ Metrics pipeline failed"
    exit 1
fi

# Step 3: Verify traces collection
echo "🔍 Verifying traces pipeline..."
if curl -s "http://localhost:3200/api/search" | jq -e '. != null' > /dev/null; then
    echo "✅ Traces pipeline working"
else
    echo "❌ Traces pipeline failed"
    exit 1
fi

# Step 4: Verify Grafana data sources
echo "📈 Verifying Grafana data sources..."
if curl -s -u admin:admin "http://localhost:3000/api/datasources" | jq -e 'length > 0' > /dev/null; then
    echo "✅ Grafana data sources configured"
else
    echo "❌ Grafana data sources failed"
    exit 1
fi

echo "🎉 End-to-end pipeline verification complete!"
```

### Unified Configuration Management

#### Environment-Based Exporter Selection

```go
type ObservabilityConfig struct {
    Mode        string `env:"OBS_MODE" envDefault:"local"`        // local, cloud, hybrid
    ServiceName string `env:"SERVICE_NAME" envDefault:"api"`
    
    // Local exporters
    OTLPEndpoint     string `env:"OTLP_ENDPOINT" envDefault:"http://otel-collector:4318"`
    PrometheusAddr   string `env:"PROMETHEUS_ADDR" envDefault:":9090"`
    
    // Cloud exporters (used when Mode=cloud or Mode=hybrid)
    SentryDSN        string `env:"SENTRY_DSN"`
    GCPProjectID     string `env:"GCP_PROJECT_ID"`
    GCPLogName       string `env:"GCP_LOG_NAME" envDefault:"application"`
    
    // Sampling configuration
    TraceSampleRate  float64 `env:"TRACE_SAMPLE_RATE" envDefault:"1.0"`  // 100% for local
    MetricsScrapeInterval time.Duration `env:"METRICS_SCRAPE_INTERVAL" envDefault:"10s"`
}

func NewObservability(cfg ObservabilityConfig) (*Observability, error) {
    switch cfg.Mode {
    case "local":
        return newLocalExporters(cfg)
    case "cloud": 
        return newCloudExporters(cfg)
    case "hybrid":
        return newHybridExporters(cfg)
    default:
        return nil, fmt.Errorf("unknown observability mode: %s", cfg.Mode)
    }
}

func newLocalExporters(cfg ObservabilityConfig) (*Observability, error) {
    // OTLP HTTP exporter to local collector
    traceExporter, err := otlptracehttp.New(context.Background(),
        otlptracehttp.WithEndpoint(cfg.OTLPEndpoint),
        otlptracehttp.WithInsecure(),
    )
    if err != nil {
        return nil, fmt.Errorf("failed to create trace exporter: %w", err)
    }

    // Prometheus registry for local scraping
    promRegistry := prometheus.NewRegistry()

    // Structured logger with local output
    logger := log.NewLogger(log.Config{
        Format: log.FormatJSON,
        Level:  slog.LevelDebug,  // Verbose for development
        Destination: os.Stdout,
    })

    return &Observability{
        Logger:      logger,
        TracerProvider: trace.NewTracerProvider(
            trace.WithBatcher(traceExporter),
            trace.WithSampler(trace.TraceIDRatioBased(cfg.TraceSampleRate)),
        ),
        MetricsRegistry: promRegistry,
    }, nil
}
```

### Development Workflow Integration

#### Makefile Targets

```makefile
.PHONY: setup health-check verify-pipeline stack-logs stack-restart

## setup: Initialize local observability stack
setup:
 @echo "🚀 Setting up local observability stack..."
 @docker-compose -f deployments/docker-compose.yml up -d
 @echo "⏳ Waiting for services to start..."
 @sleep 15
 @./scripts/health-check.sh

## health-check: Check all services are healthy
health-check:
 @./scripts/health-check.sh

## verify-pipeline: Test end-to-end observability pipeline
verify-pipeline:
 @./scripts/verify-pipeline.sh

## stack-logs: Show logs from observability stack
stack-logs:
 @docker-compose -f deployments/docker-compose.yml logs -f

## stack-restart: Restart observability stack
stack-restart:
 @echo "🔄 Restarting observability stack..."
 @docker-compose -f deployments/docker-compose.yml restart
 @sleep 10
 @./scripts/health-check.sh

## hello: Run hello signals demo  
hello:
 @echo "👋 Running hello signals demo..."
 @go run cmd/hello-signals/main.go
```

### Cost Analysis and Migration Path

#### Local Development Costs

```bash
# Local resource usage (typical development machine)
CPU: ~2 cores (for all containers)
Memory: ~4GB RAM
Storage: ~2GB (with data retention)
Network: ~0 (local only)
Total Cost: $0
```

#### Cloud Migration Preparation

```go
// Cost estimation for cloud migration
type CloudCostEstimate struct {
    TracesPerDay    int
    MetricsPerDay   int
    LogsPerDay      int
    RetentionDays   int
}

func (c CloudCostEstimate) EstimateGCPCost() float64 {
    // Google Cloud Logging: $0.50 per GB ingested
    logsGB := float64(c.LogsPerDay) * 0.001 * 30  // Assume 1KB per log
    loggingCost := logsGB * 0.50

    // Google Cloud Trace: $0.20 per million spans
    spanCost := float64(c.TracesPerDay) * 30 / 1000000 * 0.20

    // Cloud Monitoring: $2.50 per GB for custom metrics
    metricsGB := float64(c.MetricsPerDay) * 0.0001 * 30  // Assume 100B per metric
    metricsCost := metricsGB * 2.50

    return loggingCost + spanCost + metricsCost
}

// Example usage
estimate := CloudCostEstimate{
    TracesPerDay:  10000,
    MetricsPerDay: 50000,
    LogsPerDay:    100000,
    RetentionDays: 30,
}

fmt.Printf("Estimated monthly GCP cost: $%.2f\n", estimate.EstimateGCPCost())
```

### Troubleshooting Common Issues

#### Docker Memory Issues

```bash
# Check Docker memory allocation
docker system df
docker stats

# Increase Docker memory limit (Docker Desktop)
# Settings → Resources → Memory → 4GB+
```

#### Port Conflicts

```bash
# Check for port conflicts
sudo netstat -tulpn | grep -E ":(3000|4318|8080|8888|9090|3200)"

# Solution: Change ports in docker-compose.yml or stop conflicting services
sudo systemctl stop apache2  # If using port 8080
sudo systemctl stop grafana-server  # If using port 3000
```

#### Collector Configuration Issues

```bash
# Validate collector configuration
docker run --rm -v $(pwd)/deployments/otel-collector/config.yml:/config.yml \
  otel/opentelemetry-collector-contrib:0.116.0 --config=/config.yml --dry-run

# Check collector logs
docker-compose -f deployments/docker-compose.yml logs otel-collector
```

### Consequences

**Positive:**

- **Faster learning velocity**: No authentication delays or quota limits
- **Complete signal visibility**: Inspect OTel Collector processing and Prometheus storage without cloud abstractions
- **Cost control**: Zero ingestion charges during development and experimentation
- **Reproducible environments**: Docker Compose ensures consistent behavior across machines
- **Easy debugging**: Full access to configuration files and service logs

**Negative:**

- **Two configuration paths**: Local and cloud configurations need maintenance
- **Delayed cloud learning**: Cannot test cloud-specific features until Phase 6
- **Resource overhead**: Local stack requires development machine resources
- **Limited scalability testing**: Cannot test cloud-scale performance characteristics

**Mitigation Strategies:**

- **Configuration templates**: Use environment variables for easy local↔cloud switching
- **Cloud simulation**: Use feature flags to simulate cloud behavior in local stack
- **Resource optimization**: Tune container memory limits and retention policies
- **Regular cloud testing**: Monthly cloud integration exercises

### Related ADRs

- [ADR-0001: Monolith-First Strategy](#adr-0001-monolith-first-strategy) - Supports learning objectives
- [ADR-0008: GCP-First Cloud Strategy](#adr-0008-gcp-first-cloud) - Cloud migration target
- [ADR-0010: Performance Budgets](#adr-0010-performance-budgets) - Local performance baselines

### References

- [OpenTelemetry Collector Documentation](https://opentelemetry.io/docs/collector/)
- [Grafana Tempo Documentation](https://grafana.com/docs/tempo/)
- [Prometheus Configuration](https://prometheus.io/docs/prometheus/latest/configuration/)
- [Docker Compose Best Practices](https://docs.docker.com/compose/production/)
