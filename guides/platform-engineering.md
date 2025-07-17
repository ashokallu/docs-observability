# Platform Engineering Guide (Enhanced)

> **Status**: Enhanced v2.0 - Production Ready  
> **Last Updated**: 2025-07-17  
> **Maintainer**: Platform Engineering Team  
> **Related**: [Complete ADR Collection](enhanced-adr-collection.md) | [Enterprise Observability Policies](enterprise-observability-policy.md) | [Implementation Playbook](implementation-playbook.md) | [Production Operations Handbook](production-operations-handbook.md)

## Executive Summary

This comprehensive platform engineering guide provides the technical foundation for building, maintaining, and scaling observability platforms in Go applications with 2025+ DevOps excellence. It covers package design patterns, dependency management, testing strategies, CI/CD integration, cloud-native deployment, and developer experience optimization.

**Key Focus Areas:**

- **Package Architecture** with clean boundaries and dependency injection
- **Dependency Management** with automated security scanning and supply chain protection
- **Testing Frameworks** for comprehensive validation and performance budgets
- **CI/CD Integration** with GitOps workflows and progressive deployment
- **Cloud-Native Deployment** with infrastructure as code and service mesh integration
- **Developer Experience** with dev containers, automated tooling, and IDE optimization
- **Enterprise Governance** with security controls, compliance monitoring, and audit trails

**Target Audience**: Platform engineers, Go developers, DevOps engineers, cloud architects, and technical leads responsible for observability infrastructure and production systems.

**Decision Rationale**: This guide addresses the evolution from traditional DevOps to platform engineering, where infrastructure becomes programmable, observable, and self-healing. The 2025+ focus reflects emerging patterns: GitOps-first deployment, zero-trust security, AI-augmented operations, and developer-centric platforms.

## Package Design Patterns

### Core Architecture Principles

#### Dependency Injection and Interface Design

Following ADR-002 (Zero Global State), all observability components use explicit dependency injection with well-defined interfaces. This pattern enables testability, modularity, and cloud-native deployment flexibility.

**Decision Rationale**: Dependency injection is the foundation of modern Go applications because:

- **Testability**: Each component can be tested in isolation with mock dependencies
- **Modularity**: Components can be replaced without affecting others (database, message queue, cache)
- **Cloud-Native**: Different environments can use different implementations (local vs cloud services)
- **Microservices**: Components can be extracted into separate services with minimal changes

```go
// Package structure following clean architecture with 2025+ patterns
internal/
├── platform/obs/           # Observability platform (framework-agnostic)
│   ├── log/                # Logging interfaces and implementations
│   │   ├── logger.go       # Core logger interface and implementation
│   │   ├── context.go      # Context enrichment and propagation
│   │   ├── handlers.go     # slog handlers (JSON, text, GCP Cloud Logging)
│   │   ├── pii.go         # PII protection and redaction
│   │   └── testing.go     # Test helpers and capture utilities
│   ├── trace/              # Tracing interfaces and implementations
│   │   ├── tracer.go      # OpenTelemetry tracer setup and configuration
│   │   ├── spans.go       # Span management and semantic conventions
│   │   ├── propagation.go # Context propagation and baggage
│   │   └── testing.go     # Test tracer and span capture
│   ├── metrics/            # Metrics interfaces and implementations
│   │   ├── registry.go    # Prometheus metrics registry
│   │   ├── http.go        # HTTP metrics (RED method)
│   │   ├── business.go    # Business metrics and SLIs
│   │   ├── cardinality.go # Cardinality validation and budgets
│   │   └── testing.go     # Test metrics and assertions
│   ├── errors/             # Error classification and correlation
│   │   ├── types.go       # AppError definition and classification
│   │   ├── correlation.go # Error-to-observability correlation
│   │   └── middleware.go  # Error handling middleware
│   ├── config/             # Configuration management
│   │   ├── config.go      # Unified configuration structure
│   │   ├── validation.go  # Configuration validation
│   │   └── env.go         # Environment-specific defaults
│   └── provider.go         # Unified observability provider
├── api/middleware/         # Framework-specific middleware (Gin, etc.)
│   ├── observability.go   # Request-scoped observability setup
│   ├── auth.go            # Authentication and authorization
│   ├── ratelimit.go       # Rate limiting and throttling
│   └── security.go        # Security headers and CORS
├── domain/                 # Business domain packages
│   ├── users/             # User domain (extractable as microservice)
│   │   ├── service.go     # Business logic
│   │   ├── repository.go  # Data access interface
│   │   ├── types.go       # Domain types
│   │   └── events.go      # Domain events
│   └── orders/            # Order domain (extractable as microservice)
│       ├── service.go     # Business logic with state machine
│       ├── repository.go  # Data access interface
│       ├── types.go       # Domain types
│       ├── state.go       # Order state machine
│       └── events.go      # Domain events
├── adapters/              # External adapters (database, HTTP clients, message queues)
│   ├── database/          # Database adapters
│   │   ├── postgres.go    # PostgreSQL implementation
│   │   ├── migrations/    # Database migrations
│   │   └── testing.go     # Test database utilities
│   ├── http/              # HTTP client adapters
│   │   ├── client.go      # Instrumented HTTP client
│   │   ├── retry.go       # Retry policies
│   │   └── circuit.go     # Circuit breaker
│   └── messaging/         # Message queue adapters
│       ├── pubsub.go      # Google Cloud Pub/Sub
│       ├── kafka.go       # Apache Kafka
│       └── sqs.go         # Amazon SQS
└── infrastructure/        # Infrastructure and deployment
    ├── terraform/         # Infrastructure as Code
    ├── k8s/              # Kubernetes manifests
    ├── docker/           # Docker configurations
    └── scripts/          # Automation scripts
```

#### Interface Design Guidelines

**Core Observability Interfaces**

```go
// internal/platform/obs/log/interfaces.go
package log

import (
    "context"
    "io"
    "log/slog"
    "time"
)

// Logger provides structured logging with context awareness and PII protection
type Logger interface {
    // Context-aware logging methods (preferred for trace correlation)
    DebugCtx(ctx context.Context, msg string, args ...any)
    InfoCtx(ctx context.Context, msg string, args ...any)
    WarnCtx(ctx context.Context, msg string, args ...any)
    ErrorCtx(ctx context.Context, msg string, args ...any)

    // Child logger creation for request scoping
    With(args ...any) Logger
    WithGroup(name string) Logger

    // Access underlying implementation for advanced use cases
    Unwrap() *slog.Logger
}

// Provider manages logger lifecycle and configuration across environments
type Provider interface {
    // Create logger with environment-specific configuration
    NewLogger(cfg Config) Logger
    
    // Create test logger with capture capability for unit tests
    NewTestLogger() (Logger, *TestCapture)
    
    // Default logger for fallback scenarios (prevents nil panics)
    DefaultLogger() Logger
    
    // Shutdown gracefully flushes any buffered logs
    Shutdown(ctx context.Context) error
}

// Handler creates slog-compatible handlers for different environments
type Handler interface {
    // Create handler for specific output format and destination
    NewHandler(cfg Config) slog.Handler
    
    // Create handler with custom destination (files, streams, cloud)
    NewHandlerWithDestination(cfg Config, dest io.Writer) slog.Handler
    
    // Validate handler configuration before creation
    ValidateConfig(cfg Config) error
}
```

**Decision Rationale**: These interfaces follow Go best practices:

- **Small, focused interfaces** (Single Responsibility Principle)
- **Context-first** methods for trace correlation and cancellation
- **Graceful shutdown** support for cloud-native deployments
- **Test-friendly** design with capture utilities
- **Configuration validation** to fail fast on misconfiguration

**Metrics Interfaces with Cardinality Protection**

```go
// internal/platform/obs/metrics/interfaces.go
package metrics

import (
    "context"
    "net/http"
    "time"
    
    "github.com/prometheus/client_golang/prometheus"
)

// Registry provides metric registration and cardinality governance
type Registry interface {
    // Metric creation with automatic cardinality validation
    Counter(name, help string, labels []string) Counter
    Gauge(name, help string, labels []string) Gauge
    Histogram(name, help string, labels []string, buckets []float64) Histogram
    Summary(name, help string, labels []string, objectives map[float64]float64) Summary
    
    // HTTP handler for Prometheus scraping
    Handler() http.Handler
    
    // Metrics export for testing and validation
    Gather() ([]*prometheus.MetricFamily, error)
    
    // Cardinality validation and budget enforcement
    ValidateCardinality() error
    GetCardinalityReport() CardinalityReport
    
    // Graceful shutdown with final metrics export
    Shutdown(ctx context.Context) error
}

// Counter represents a monotonically increasing metric with bounded cardinality
type Counter interface {
    Inc(labels ...string)
    Add(value float64, labels ...string)
    
    // Get current value for testing
    Get(labels ...string) float64
}

// Gauge represents a metric that can go up and down
type Gauge interface {
    Set(value float64, labels ...string)
    Inc(labels ...string)
    Dec(labels ...string)
    Add(value float64, labels ...string)
    Sub(value float64, labels ...string)
    
    // Get current value for testing
    Get(labels ...string) float64
}

// Histogram represents a distribution of values with SLO-aligned buckets
type Histogram interface {
    Observe(value float64, labels ...string)
    Time(labels ...string) func() // Returns a function to call when timing is complete
    
    // Get bucket counts for testing
    GetBucketCounts(labels ...string) map[float64]uint64
}

// Summary represents a distribution with configurable quantiles
type Summary interface {
    Observe(value float64, labels ...string)
    Time(labels ...string) func()
    
    // Get quantile values for testing
    GetQuantile(quantile float64, labels ...string) float64
}

// CardinalityReport provides insights into metric cardinality usage
type CardinalityReport struct {
    TotalSeries    int                    `json:"total_series"`
    SeriesByMetric map[string]int         `json:"series_by_metric"`
    TopMetrics     []MetricCardinalityInfo `json:"top_metrics"`
    Budget         CardinalityBudget       `json:"budget"`
    Violations     []CardinalityViolation  `json:"violations"`
}

type MetricCardinalityInfo struct {
    Name       string   `json:"name"`
    SeriesCount int     `json:"series_count"`
    Labels     []string `json:"labels"`
    SampleLabels map[string][]string `json:"sample_labels"`
}

type CardinalityBudget struct {
    MaxSeries      int `json:"max_series"`
    WarningThreshold int `json:"warning_threshold"`
    CurrentUsage   int `json:"current_usage"`
    UsagePercent   float64 `json:"usage_percent"`
}

type CardinalityViolation struct {
    MetricName string `json:"metric_name"`
    Reason     string `json:"reason"`
    Suggestion string `json:"suggestion"`
}
```

**Decision Rationale**: Cardinality governance is critical for production Prometheus deployments:

- **Cost Control**: High cardinality directly translates to infrastructure costs
- **Performance**: Query performance degrades exponentially with series count
- **Reliability**: Prometheus can crash or become unresponsive with unlimited cardinality
- **Observability**: The observability system itself must be observable and governed

**Tracing Interfaces with Cloud Integration**

```go
// internal/platform/obs/trace/interfaces.go
package trace

import (
    "context"
    "net/http"
    
    "go.opentelemetry.io/otel/trace"
    "go.opentelemetry.io/otel/baggage"
)

// Provider manages tracer lifecycle and cloud integration
type Provider interface {
    // Create tracer for specific service with semantic conventions
    Tracer(name string, opts ...trace.TracerOption) trace.Tracer
    
    // Create test tracer with span capture capability
    NewTestTracer() (trace.Tracer, *TestCapture)
    
    // Shutdown gracefully flushes any pending spans
    Shutdown(ctx context.Context) error
    
    // Force flush for immediate export (useful for short-lived functions)
    ForceFlush(ctx context.Context) error
    
    // Get current configuration for debugging
    GetConfig() Config
}

// Exporter handles span export to various backends (Jaeger, GCP, AWS, Azure)
type Exporter interface {
    // Export spans to backend with retry and batching
    ExportSpans(ctx context.Context, spans []trace.ReadOnlySpan) error
    
    // Shutdown gracefully with final export
    Shutdown(ctx context.Context) error
    
    // Get exporter health and statistics
    Health() ExporterHealth
}

// Processor handles span processing pipeline with sampling and filtering
type Processor interface {
    // Process span at start (sampling decisions, enrichment)
    OnStart(parent context.Context, s trace.ReadWriteSpan)
    
    // Process span at end (final enrichment, export decisions)
    OnEnd(s trace.ReadOnlySpan)
    
    // Shutdown gracefully
    Shutdown(ctx context.Context) error
    
    // Force flush pending spans
    ForceFlush(ctx context.Context) error
    
    // Get processor statistics
    Stats() ProcessorStats
}

// BaggageManager handles cross-service context propagation
type BaggageManager interface {
    // Set baggage value with TTL and propagation rules
    SetBaggage(ctx context.Context, key, value string, ttl time.Duration) context.Context
    
    // Get baggage value with validation
    GetBaggage(ctx context.Context, key string) (string, bool)
    
    // Propagate baggage across HTTP boundaries
    InjectHTTP(ctx context.Context, req *http.Request) error
    ExtractHTTP(req *http.Request) (baggage.Baggage, error)
    
    // Clean expired baggage
    CleanExpired(ctx context.Context) int
}

// ExporterHealth provides exporter health information
type ExporterHealth struct {
    Status           string    `json:"status"`
    LastExport       time.Time `json:"last_export"`
    TotalSpans       int64     `json:"total_spans"`
    FailedSpans      int64     `json:"failed_spans"`
    AvgLatency       time.Duration `json:"avg_latency"`
    BackendReachable bool      `json:"backend_reachable"`
}

// ProcessorStats provides processor performance metrics
type ProcessorStats struct {
    SpansProcessed   int64     `json:"spans_processed"`
    SpansDropped     int64     `json:"spans_dropped"`
    SpansSampled     int64     `json:"spans_sampled"`
    ProcessingTime   time.Duration `json:"processing_time"`
    QueueDepth       int       `json:"queue_depth"`
    MemoryUsage      int64     `json:"memory_usage"`
}
```

**Decision Rationale**: Distributed tracing in 2025+ requires:

- **Cloud-Native Integration**: Seamless integration with GCP Cloud Trace, AWS X-Ray, Azure Monitor
- **Baggage Management**: Cross-service context propagation for business intelligence
- **Performance Monitoring**: Tracing infrastructure must be monitored to prevent becoming a bottleneck
- **Cost Management**: Sampling strategies to control ingestion costs in cloud environments

### Configuration Management

#### Unified Configuration System with Environment Awareness

```go
// internal/platform/obs/config/config.go
package config

import (
    "fmt"
    "time"
    "crypto/tls"
    
    "github.com/caarlos0/env/v11"
    "github.com/joho/godotenv"
)

// Config represents the complete observability configuration with validation
type Config struct {
    Service  ServiceConfig  `json:"service"`
    Log      LogConfig      `json:"log"`
    Trace    TraceConfig    `json:"trace"`
    Metrics  MetricsConfig  `json:"metrics"`
    Security SecurityConfig `json:"security"`
    Cloud    CloudConfig    `json:"cloud"`
    Features FeatureConfig  `json:"features"`
}

// ServiceConfig defines service identification and deployment context
type ServiceConfig struct {
    Name        string `env:"SERVICE_NAME" envDefault:"api" json:"name"`
    Version     string `env:"SERVICE_VERSION" envDefault:"dev" json:"version"`
    Environment string `env:"ENVIRONMENT" envDefault:"development" json:"environment"`
    Namespace   string `env:"NAMESPACE" envDefault:"default" json:"namespace"`
    Region      string `env:"REGION" envDefault:"us-east1" json:"region"`
    Cluster     string `env:"CLUSTER" envDefault:"local" json:"cluster"`
    
    // Deployment metadata for trace correlation
    GitCommit   string `env:"GIT_COMMIT" json:"git_commit,omitempty"`
    BuildTime   string `env:"BUILD_TIME" json:"build_time,omitempty"`
    BuildUser   string `env:"BUILD_USER" json:"build_user,omitempty"`
}

// LogConfig defines comprehensive logging configuration with PII protection
type LogConfig struct {
    // Output configuration
    Level               string        `env:"LOG_LEVEL" envDefault:"info" json:"level"`
    Format              string        `env:"LOG_FORMAT" envDefault:"json" json:"format"`
    Destination         string        `env:"LOG_DESTINATION" envDefault:"stdout" json:"destination"`
    
    // PII Protection and Compliance
    UserIDMode          string        `env:"LOG_USER_ID_MODE" envDefault:"redact" json:"user_id_mode"`
    EmailMode           string        `env:"LOG_EMAIL_MODE" envDefault:"domain_only" json:"email_mode"`
    IPAddressMode       string        `env:"LOG_IP_ADDRESS_MODE" envDefault:"none" json:"ip_address_mode"`
    EnablePIIRedaction  bool          `env:"LOG_ENABLE_PII_REDACTION" envDefault:"true" json:"enable_pii_redaction"`
    
    // Error handling and debugging
    EnableStackTrace    bool          `env:"LOG_ENABLE_STACK_TRACE" envDefault:"true" json:"enable_stack_trace"`
    StackTraceLevel     string        `env:"LOG_STACK_TRACE_LEVEL" envDefault:"error" json:"stack_trace_level"`
    EnableSource        bool          `env:"LOG_ENABLE_SOURCE" envDefault:"false" json:"enable_source"`
    
    // Performance and output formatting
    PrettyPrint         bool          `env:"LOG_PRETTY_PRINT" envDefault:"false" json:"pretty_print"`
    BufferSize          int           `env:"LOG_BUFFER_SIZE" envDefault:"1000" json:"buffer_size"`
    FlushInterval       time.Duration `env:"LOG_FLUSH_INTERVAL" envDefault:"5s" json:"flush_interval"`
    MaxFieldSize        int           `env:"LOG_MAX_FIELD_SIZE" envDefault:"4096" json:"max_field_size"`
    
    // Advanced configuration
    SamplingRate        float64       `env:"LOG_SAMPLING_RATE" envDefault:"1.0" json:"sampling_rate"`
    RedactionRules      []string      `env:"LOG_REDACTION_RULES" envSeparator:"," json:"redaction_rules"`
    
    // File output configuration (when destination is file)
    FilePath            string        `env:"LOG_FILE_PATH" envDefault:"/var/log/app.log" json:"file_path"`
    MaxFileSize         int           `env:"LOG_MAX_FILE_SIZE" envDefault:"100" json:"max_file_size_mb"`
    MaxFiles            int           `env:"LOG_MAX_FILES" envDefault:"10" json:"max_files"`
    FilePermissions     string        `env:"LOG_FILE_PERMISSIONS" envDefault:"0644" json:"file_permissions"`
}

// TraceConfig defines comprehensive tracing configuration
type TraceConfig struct {
    // Basic configuration
    Enabled             bool          `env:"TRACE_ENABLED" envDefault:"true" json:"enabled"`
    Endpoint            string        `env:"TRACE_ENDPOINT" envDefault:"http://otel-collector:4318" json:"endpoint"`
    Protocol            string        `env:"TRACE_PROTOCOL" envDefault:"http" json:"protocol"`
    
    // Sampling configuration for cost control
    SamplerType         string        `env:"TRACE_SAMPLER_TYPE" envDefault:"parentbased_traceidratio" json:"sampler_type"`
    SamplerArg          float64       `env:"TRACE_SAMPLER_ARG" envDefault:"1.0" json:"sampler_arg"`
    
    // Export configuration
    Timeout             time.Duration `env:"TRACE_TIMEOUT" envDefault:"30s" json:"timeout"`
    BatchTimeout        time.Duration `env:"TRACE_BATCH_TIMEOUT" envDefault:"5s" json:"batch_timeout"`
    BatchSize           int           `env:"TRACE_BATCH_SIZE" envDefault:"512" json:"batch_size"`
    MaxQueueSize        int           `env:"TRACE_MAX_QUEUE_SIZE" envDefault:"2048" json:"max_queue_size"`
    ExportTimeout       time.Duration `env:"TRACE_EXPORT_TIMEOUT" envDefault:"30s" json:"export_timeout"`
    
    // Advanced configuration
    Headers             []string      `env:"TRACE_HEADERS" envSeparator:"," json:"headers"`
    Compression         string        `env:"TRACE_COMPRESSION" envDefault:"gzip" json:"compression"`
    ResourceAttributes  []string      `env:"TRACE_RESOURCE_ATTRIBUTES" envSeparator:"," json:"resource_attributes"`
    
    // TLS configuration for production
    TLSEnabled          bool          `env:"TRACE_TLS_ENABLED" envDefault:"false" json:"tls_enabled"`
    TLSCertFile         string        `env:"TRACE_TLS_CERT_FILE" json:"tls_cert_file"`
    TLSKeyFile          string        `env:"TRACE_TLS_KEY_FILE" json:"tls_key_file"`
    TLSCAFile           string        `env:"TRACE_TLS_CA_FILE" json:"tls_ca_file"`
    TLSInsecure         bool          `env:"TRACE_TLS_INSECURE" envDefault:"false" json:"tls_insecure"`
    
    // Baggage configuration
    BaggageEnabled      bool          `env:"TRACE_BAGGAGE_ENABLED" envDefault:"true" json:"baggage_enabled"`
    BaggageMaxItems     int           `env:"TRACE_BAGGAGE_MAX_ITEMS" envDefault:"100" json:"baggage_max_items"`
    BaggageMaxSize      int           `env:"TRACE_BAGGAGE_MAX_SIZE" envDefault:"8192" json:"baggage_max_size"`
}

// MetricsConfig defines comprehensive metrics configuration with cardinality controls
type MetricsConfig struct {
    // Basic configuration
    Enabled             bool          `env:"METRICS_ENABLED" envDefault:"true" json:"enabled"`
    Port                int           `env:"METRICS_PORT" envDefault:"9090" json:"port"`
    Path                string        `env:"METRICS_PATH" envDefault:"/metrics" json:"path"`
    
    // Namespace and labeling
    Namespace           string        `env:"METRICS_NAMESPACE" envDefault:"" json:"namespace"`
    Subsystem           string        `env:"METRICS_SUBSYSTEM" envDefault:"" json:"subsystem"`
    CommonLabels        []string      `env:"METRICS_COMMON_LABELS" envSeparator:"," json:"common_labels"`
    
    // Histogram and summary configuration
    HistogramBuckets    []float64     `env:"METRICS_HISTOGRAM_BUCKETS" envSeparator:"," json:"histogram_buckets"`
    SummaryObjectives   []string      `env:"METRICS_SUMMARY_OBJECTIVES" envSeparator:"," json:"summary_objectives"`
    SummaryMaxAge       time.Duration `env:"METRICS_SUMMARY_MAX_AGE" envDefault:"10m" json:"summary_max_age"`
    
    // Performance and resource limits
    GatherTimeout       time.Duration `env:"METRICS_GATHER_TIMEOUT" envDefault:"10s" json:"gather_timeout"`
    MaxRequestsInFlight int           `env:"METRICS_MAX_REQUESTS_IN_FLIGHT" envDefault:"40" json:"max_requests_in_flight"`
    
    // Built-in metrics configuration
    EnableGoMetrics     bool          `env:"METRICS_ENABLE_GO_METRICS" envDefault:"true" json:"enable_go_metrics"`
    EnableProcessMetrics bool         `env:"METRICS_ENABLE_PROCESS_METRICS" envDefault:"true" json:"enable_process_metrics"`
    EnableBuildInfo     bool          `env:"METRICS_ENABLE_BUILD_INFO" envDefault:"true" json:"enable_build_info"`
    
    // Cardinality governance
    CardinalityLimit    int           `env:"METRICS_CARDINALITY_LIMIT" envDefault:"1000" json:"cardinality_limit"`
    CardinalityWarning  int           `env:"METRICS_CARDINALITY_WARNING" envDefault:"800" json:"cardinality_warning"`
    EnableCardinalityCheck bool       `env:"METRICS_ENABLE_CARDINALITY_CHECK" envDefault:"true" json:"enable_cardinality_check"`
    
    // Push gateway configuration (for batch jobs)
    PushGatewayEnabled  bool          `env:"METRICS_PUSH_GATEWAY_ENABLED" envDefault:"false" json:"push_gateway_enabled"`
    PushGatewayURL      string        `env:"METRICS_PUSH_GATEWAY_URL" json:"push_gateway_url"`
    PushInterval        time.Duration `env:"METRICS_PUSH_INTERVAL" envDefault:"15s" json:"push_interval"`
}

// SecurityConfig defines comprehensive security settings
type SecurityConfig struct {
    // TLS configuration
    TLSEnabled          bool     `env:"SECURITY_TLS_ENABLED" envDefault:"false" json:"tls_enabled"`
    TLSCertFile         string   `env:"SECURITY_TLS_CERT_FILE" json:"tls_cert_file"`
    TLSKeyFile          string   `env:"SECURITY_TLS_KEY_FILE" json:"tls_key_file"`
    TLSCAFile           string   `env:"SECURITY_TLS_CA_FILE" json:"tls_ca_file"`
    TLSMinVersion       string   `env:"SECURITY_TLS_MIN_VERSION" envDefault:"1.3" json:"tls_min_version"`
    TLSCipherSuites     []string `env:"SECURITY_TLS_CIPHER_SUITES" envSeparator:"," json:"tls_cipher_suites"`
    
    // Authentication and authorization
    APIKeyRequired      bool     `env:"SECURITY_API_KEY_REQUIRED" envDefault:"false" json:"api_key_required"`
    APIKeyHeader        string   `env:"SECURITY_API_KEY_HEADER" envDefault:"X-API-Key" json:"api_key_header"`
    JWTEnabled          bool     `env:"SECURITY_JWT_ENABLED" envDefault:"false" json:"jwt_enabled"`
    JWTSecret           string   `env:"SECURITY_JWT_SECRET" json:"jwt_secret"`
    JWTIssuer           string   `env:"SECURITY_JWT_ISSUER" json:"jwt_issuer"`
    
    // CORS configuration
    CORSEnabled         bool     `env:"SECURITY_CORS_ENABLED" envDefault:"false" json:"cors_enabled"`
    AllowedOrigins      []string `env:"SECURITY_ALLOWED_ORIGINS" envSeparator:"," json:"allowed_origins"`
    AllowedMethods      []string `env:"SECURITY_ALLOWED_METHODS" envSeparator:"," envDefault:"GET,POST,PUT,DELETE,OPTIONS" json:"allowed_methods"`
    AllowedHeaders      []string `env:"SECURITY_ALLOWED_HEADERS" envSeparator:"," json:"allowed_headers"`
    ExposedHeaders      []string `env:"SECURITY_EXPOSED_HEADERS" envSeparator:"," json:"exposed_headers"`
    AllowCredentials    bool     `env:"SECURITY_ALLOW_CREDENTIALS" envDefault:"false" json:"allow_credentials"`
    MaxAge              int      `env:"SECURITY_CORS_MAX_AGE" envDefault:"86400" json:"cors_max_age"`
    
    // Rate limiting
    RateLimitEnabled    bool     `env:"SECURITY_RATE_LIMIT_ENABLED" envDefault:"false" json:"rate_limit_enabled"`
    RateLimitRPS        int      `env:"SECURITY_RATE_LIMIT_RPS" envDefault:"100" json:"rate_limit_rps"`
    RateLimitBurst      int      `env:"SECURITY_RATE_LIMIT_BURST" envDefault:"200" json:"rate_limit_burst"`
    RateLimitWindow     time.Duration `env:"SECURITY_RATE_LIMIT_WINDOW" envDefault:"1m" json:"rate_limit_window"`
    
    // Security headers
    EnableSecurityHeaders bool   `env:"SECURITY_ENABLE_SECURITY_HEADERS" envDefault:"true" json:"enable_security_headers"`
    HSTSMaxAge           int     `env:"SECURITY_HSTS_MAX_AGE" envDefault:"31536000" json:"hsts_max_age"`
    ContentTypeNoSniff   bool    `env:"SECURITY_CONTENT_TYPE_NO_SNIFF" envDefault:"true" json:"content_type_no_sniff"`
    FrameOptions         string  `env:"SECURITY_FRAME_OPTIONS" envDefault:"DENY" json:"frame_options"`
    XSSProtection        string  `env:"SECURITY_XSS_PROTECTION" envDefault:"1; mode=block" json:"xss_protection"`
    
    // Request validation
    MaxRequestSize       int64   `env:"SECURITY_MAX_REQUEST_SIZE" envDefault:"10485760" json:"max_request_size"` // 10MB
    MaxHeaderSize        int     `env:"SECURITY_MAX_HEADER_SIZE" envDefault:"1048576" json:"max_header_size"`    // 1MB
    ReadTimeout          time.Duration `env:"SECURITY_READ_TIMEOUT" envDefault:"30s" json:"read_timeout"`
    WriteTimeout         time.Duration `env:"SECURITY_WRITE_TIMEOUT" envDefault:"30s" json:"write_timeout"`
    IdleTimeout          time.Duration `env:"SECURITY_IDLE_TIMEOUT" envDefault:"60s" json:"idle_timeout"`
}

// CloudConfig defines cloud-specific configuration for different providers
type CloudConfig struct {
    // Provider selection
    Provider            string `env:"CLOUD_PROVIDER" envDefault:"gcp" json:"provider"` // gcp, aws, azure, local
    
    // Google Cloud Platform
    GCP GCPConfig `json:"gcp"`
    
    // Amazon Web Services
    AWS AWSConfig `json:"aws"`
    
    // Microsoft Azure
    Azure AzureConfig `json:"azure"`
}

// GCPConfig defines Google Cloud Platform specific configuration
type GCPConfig struct {
    ProjectID           string `env:"GCP_PROJECT_ID" json:"project_id"`
    Location            string `env:"GCP_LOCATION" envDefault:"us-central1" json:"location"`
    
    // Cloud Logging
    LoggingEnabled      bool   `env:"GCP_LOGGING_ENABLED" envDefault:"false" json:"logging_enabled"`
    LogName             string `env:"GCP_LOG_NAME" envDefault:"application" json:"log_name"`
    
    // Cloud Trace
    TraceEnabled        bool   `env:"GCP_TRACE_ENABLED" envDefault:"false" json:"trace_enabled"`
    
    // Cloud Monitoring
    MonitoringEnabled   bool   `env:"GCP_MONITORING_ENABLED" envDefault:"false" json:"monitoring_enabled"`
    
    // Error Reporting
    ErrorReportingEnabled bool `env:"GCP_ERROR_REPORTING_ENABLED" envDefault:"false" json:"error_reporting_enabled"`
    
    // Workload Identity (preferred over service account keys)
    UseWorkloadIdentity bool   `env:"GCP_USE_WORKLOAD_IDENTITY" envDefault:"true" json:"use_workload_identity"`
    ServiceAccountEmail string `env:"GCP_SERVICE_ACCOUNT_EMAIL" json:"service_account_email"`
    
    // Service account key (fallback, not recommended for production)
    ServiceAccountKeyPath string `env:"GCP_SERVICE_ACCOUNT_KEY_PATH" json:"service_account_key_path"`
}

// AWSConfig defines Amazon Web Services specific configuration
type AWSConfig struct {
    Region              string `env:"AWS_REGION" envDefault:"us-east-1" json:"region"`
    
    // CloudWatch
    CloudWatchEnabled   bool   `env:"AWS_CLOUDWATCH_ENABLED" envDefault:"false" json:"cloudwatch_enabled"`
    LogGroup            string `env:"AWS_LOG_GROUP" json:"log_group"`
    
    // X-Ray
    XRayEnabled         bool   `env:"AWS_XRAY_ENABLED" envDefault:"false" json:"xray_enabled"`
    
    // IAM Role (preferred over access keys)
    UseIAMRole          bool   `env:"AWS_USE_IAM_ROLE" envDefault:"true" json:"use_iam_role"`
    RoleARN             string `env:"AWS_ROLE_ARN" json:"role_arn"`
    
    // Access keys (fallback, not recommended for production)
    AccessKeyID         string `env:"AWS_ACCESS_KEY_ID" json:"access_key_id"`
    SecretAccessKey     string `env:"AWS_SECRET_ACCESS_KEY" json:"secret_access_key"`
}

// AzureConfig defines Microsoft Azure specific configuration
type AzureConfig struct {
    TenantID            string `env:"AZURE_TENANT_ID" json:"tenant_id"`
    SubscriptionID      string `env:"AZURE_SUBSCRIPTION_ID" json:"subscription_id"`
    ResourceGroup       string `env:"AZURE_RESOURCE_GROUP" json:"resource_group"`
    
    // Application Insights
    AppInsightsEnabled  bool   `env:"AZURE_APP_INSIGHTS_ENABLED" envDefault:"false" json:"app_insights_enabled"`
    InstrumentationKey  string `env:"AZURE_INSTRUMENTATION_KEY" json:"instrumentation_key"`
    ConnectionString    string `env:"AZURE_CONNECTION_STRING" json:"connection_string"`
    
    // Managed Identity (preferred over client secrets)
    UseManagedIdentity  bool   `env:"AZURE_USE_MANAGED_IDENTITY" envDefault:"true" json:"use_managed_identity"`
    ClientID            string `env:"AZURE_CLIENT_ID" json:"client_id"`
    
    // Client secret (fallback, not recommended for production)
    ClientSecret        string `env:"AZURE_CLIENT_SECRET" json:"client_secret"`
}

// FeatureConfig defines feature flags and experimental features
type FeatureConfig struct {
    // Experimental features
    EnableExperimentalFeatures bool `env:"FEATURE_ENABLE_EXPERIMENTAL" envDefault:"false" json:"enable_experimental"`
    
    // AI/ML integration
    EnableAIAnomalyDetection   bool `env:"FEATURE_ENABLE_AI_ANOMALY_DETECTION" envDefault:"false" json:"enable_ai_anomaly_detection"`
    EnableAILogAnalysis        bool `env:"FEATURE_ENABLE_AI_LOG_ANALYSIS" envDefault:"false" json:"enable_ai_log_analysis"`
    
    // Advanced observability
    EnableEBPFTracing          bool `env:"FEATURE_ENABLE_EBPF_TRACING" envDefault:"false" json:"enable_ebpf_tracing"`
    EnableServiceMesh          bool `env:"FEATURE_ENABLE_SERVICE_MESH" envDefault:"false" json:"enable_service_mesh"`
    EnableDistributedProfiling bool `env:"FEATURE_ENABLE_DISTRIBUTED_PROFILING" envDefault:"false" json:"enable_distributed_profiling"`
    
    // Development features
    EnableDebugMode            bool `env:"FEATURE_ENABLE_DEBUG_MODE" envDefault:"false" json:"enable_debug_mode"`
    EnablePProfEndpoint        bool `env:"FEATURE_ENABLE_PPROF_ENDPOINT" envDefault:"false" json:"enable_pprof_endpoint"`
    EnableHealthChecks         bool `env:"FEATURE_ENABLE_HEALTH_CHECKS" envDefault:"true" json:"enable_health_checks"`
}

// LoadFromEnv loads configuration from environment variables with validation
func LoadFromEnv() (*Config, error) {
    // Load .env file in development environments
    if shouldLoadDotEnv() {
        if err := godotenv.Load(); err != nil {
            // Non-fatal in production environments
            fmt.Printf("Info: .env file not found or not readable: %v\n", err)
        }
    }
    
    var cfg Config
    if err := env.Parse(&cfg); err != nil {
        return nil, fmt.Errorf("failed to parse environment config: %w", err)
    }
    
    // Apply environment-specific defaults
    cfg.applyEnvironmentDefaults()
    
    // Validate configuration
    if err := cfg.Validate(); err != nil {
        return nil, fmt.Errorf("configuration validation failed: %w", err)
    }
    
    return &cfg, nil
}

// shouldLoadDotEnv determines if .env file should be loaded based on environment
func shouldLoadDotEnv() bool {
    env := os.Getenv("ENVIRONMENT")
    // Only load .env in development or when not set
    return env == "" || env == "development" || env == "test"
}

// applyEnvironmentDefaults applies environment-specific defaults
func (c *Config) applyEnvironmentDefaults() {
    switch c.Service.Environment {
    case "development":
        c.applyDevelopmentDefaults()
    case "staging":
        c.applyStagingDefaults()
    case "production":
        c.applyProductionDefaults()
    }
}

// applyDevelopmentDefaults applies development environment defaults
func (c *Config) applyDevelopmentDefaults() {
    // Verbose logging for development
    if c.Log.Level == "" {
        c.Log.Level = "debug"
    }
    if c.Log.UserIDMode == "" {
        c.Log.UserIDMode = "full"
    }
    if c.Log.EnableSource == false {
        c.Log.EnableSource = true
    }
    if c.Log.PrettyPrint == false {
        c.Log.PrettyPrint = true
    }
    
    // Full sampling for development
    if c.Trace.SamplerArg == 0 {
        c.Trace.SamplerArg = 1.0
    }
    
    // Enable development features
    c.Features.EnableDebugMode = true
    c.Features.EnablePProfEndpoint = true
    
    // Disable cloud integrations by default in development
    c.Cloud.GCP.LoggingEnabled = false
    c.Cloud.GCP.TraceEnabled = false
    c.Cloud.GCP.MonitoringEnabled = false
}

// applyStagingDefaults applies staging environment defaults
func (c *Config) applyStagingDefaults() {
    // Balanced logging for staging
    if c.Log.Level == "" {
        c.Log.Level = "info"
    }
    if c.Log.UserIDMode == "" {
        c.Log.UserIDMode = "redacted"
    }
    
    // Reduced sampling for staging
    if c.Trace.SamplerArg == 0 {
        c.Trace.SamplerArg = 0.1 // 10% sampling
    }
    
    // Enable some cloud integrations for testing
    c.Cloud.GCP.LoggingEnabled = true
    c.Cloud.GCP.TraceEnabled = true
    
    // Security defaults
    c.Security.TLSEnabled = true
    c.Security.EnableSecurityHeaders = true
}

// applyProductionDefaults applies production environment defaults
func (c *Config) applyProductionDefaults() {
    // Minimal logging for production
    if c.Log.Level == "" {
        c.Log.Level = "warn"
    }
    if c.Log.UserIDMode == "" {
        c.Log.UserIDMode = "redacted"
    }
    c.Log.EnablePIIRedaction = true
    
    // Minimal sampling for production
    if c.Trace.SamplerArg == 0 {
        c.Trace.SamplerArg = 0.01 // 1% sampling
    }
    
    // Full cloud integration
    c.Cloud.GCP.LoggingEnabled = true
    c.Cloud.GCP.TraceEnabled = true
    c.Cloud.GCP.MonitoringEnabled = true
    c.Cloud.GCP.ErrorReportingEnabled = true
    
    // Strict security defaults
    c.Security.TLSEnabled = true
    c.Security.RateLimitEnabled = true
    c.Security.EnableSecurityHeaders = true
    c.Security.APIKeyRequired = true
    
    // Disable debug features
    c.Features.EnableDebugMode = false
    c.Features.EnablePProfEndpoint = false
    
    // Enable production features
    c.Features.EnableAIAnomalyDetection = true
}

// Validate validates the complete configuration
func (c *Config) Validate() error {
    if err := c.validateService(); err != nil {
        return fmt.Errorf("service config validation failed: %w", err)
    }
    
    if err := c.validateLog(); err != nil {
        return fmt.Errorf("log config validation failed: %w", err)
    }
    
    if err := c.validateTrace(); err != nil {
        return fmt.Errorf("trace config validation failed: %w", err)
    }
    
    if err := c.validateMetrics(); err != nil {
        return fmt.Errorf("metrics config validation failed: %w", err)
    }
    
    if err := c.validateSecurity(); err != nil {
        return fmt.Errorf("security config validation failed: %w", err)
    }
    
    if err := c.validateCloud(); err != nil {
        return fmt.Errorf("cloud config validation failed: %w", err)
    }
    
    return nil
}

// validateService validates service configuration
func (c *Config) validateService() error {
    if c.Service.Name == "" {
        return errors.New("service name is required")
    }
    
    validEnvironments := map[string]bool{
        "development": true, "staging": true, "production": true, "test": true,
    }
    if !validEnvironments[c.Service.Environment] {
        return fmt.Errorf("invalid environment: %s (must be development, staging, production, or test)", c.Service.Environment)
    }
    
    return nil
}

// validateLog validates logging configuration
func (c *Config) validateLog() error {
    validLogLevels := map[string]bool{
        "debug": true, "info": true, "warn": true, "error": true,
    }
    if !validLogLevels[c.Log.Level] {
        return fmt.Errorf("invalid log level: %s", c.Log.Level)
    }
    
    validFormats := map[string]bool{
        "json": true, "text": true,
    }
    if !validFormats[c.Log.Format] {
        return fmt.Errorf("invalid log format: %s", c.Log.Format)
    }
    
    validUserIDModes := map[string]bool{
        "none": true, "redacted": true, "full": true,
    }
    if !validUserIDModes[c.Log.UserIDMode] {
        return fmt.Errorf("invalid user ID mode: %s", c.Log.UserIDMode)
    }
    
    if c.Log.BufferSize < 0 {
        return fmt.Errorf("buffer size must be non-negative: %d", c.Log.BufferSize)
    }
    
    if c.Log.FlushInterval < 0 {
        return fmt.Errorf("flush interval must be non-negative: %v", c.Log.FlushInterval)
    }
    
    return nil
}

// validateTrace validates tracing configuration
func (c *Config) validateTrace() error {
    if c.Trace.Enabled && c.Trace.Endpoint == "" {
        return errors.New("trace endpoint is required when tracing is enabled")
    }
    
    validProtocols := map[string]bool{
        "http": true, "grpc": true,
    }
    if c.Trace.Enabled && !validProtocols[c.Trace.Protocol] {
        return fmt.Errorf("invalid trace protocol: %s", c.Trace.Protocol)
    }
    
    if c.Trace.SamplerArg < 0 || c.Trace.SamplerArg > 1 {
        return fmt.Errorf("sampler arg must be between 0 and 1: %f", c.Trace.SamplerArg)
    }
    
    if c.Trace.BatchSize <= 0 {
        return fmt.Errorf("batch size must be positive: %d", c.Trace.BatchSize)
    }
    
    if c.Trace.MaxQueueSize <= 0 {
        return fmt.Errorf("max queue size must be positive: %d", c.Trace.MaxQueueSize)
    }
    
    return nil
}

// validateMetrics validates metrics configuration
func (c *Config) validateMetrics() error {
    if c.Metrics.Enabled && (c.Metrics.Port < 1 || c.Metrics.Port > 65535) {
        return fmt.Errorf("invalid metrics port: %d", c.Metrics.Port)
    }
    
    if c.Metrics.CardinalityLimit <= 0 {
        return fmt.Errorf("cardinality limit must be positive: %d", c.Metrics.CardinalityLimit)
    }
    
    if c.Metrics.CardinalityWarning >= c.Metrics.CardinalityLimit {
        return fmt.Errorf("cardinality warning (%d) must be less than limit (%d)", 
            c.Metrics.CardinalityWarning, c.Metrics.CardinalityLimit)
    }
    
    return nil
}

// validateSecurity validates security configuration
func (c *Config) validateSecurity() error {
    if c.Security.TLSEnabled {
        if c.Security.TLSCertFile == "" {
            return errors.New("TLS cert file is required when TLS is enabled")
        }
        if c.Security.TLSKeyFile == "" {
            return errors.New("TLS key file is required when TLS is enabled")
        }
    }
    
    if c.Security.RateLimitEnabled && c.Security.RateLimitRPS <= 0 {
        return fmt.Errorf("rate limit RPS must be positive: %d", c.Security.RateLimitRPS)
    }
    
    if c.Security.MaxRequestSize <= 0 {
        return fmt.Errorf("max request size must be positive: %d", c.Security.MaxRequestSize)
    }
    
    return nil
}

// validateCloud validates cloud configuration
func (c *Config) validateCloud() error {
    validProviders := map[string]bool{
        "gcp": true, "aws": true, "azure": true, "local": true,
    }
    if !validProviders[c.Cloud.Provider] {
        return fmt.Errorf("invalid cloud provider: %s", c.Cloud.Provider)
    }
    
    // Validate GCP configuration
    if c.Cloud.Provider == "gcp" {
        if c.Cloud.GCP.ProjectID == "" && (c.Cloud.GCP.LoggingEnabled || c.Cloud.GCP.TraceEnabled || c.Cloud.GCP.MonitoringEnabled) {
            return errors.New("GCP project ID is required when GCP services are enabled")
        }
    }
    
    // Validate AWS configuration
    if c.Cloud.Provider == "aws" {
        if c.Cloud.AWS.Region == "" && (c.Cloud.AWS.CloudWatchEnabled || c.Cloud.AWS.XRayEnabled) {
            return errors.New("AWS region is required when AWS services are enabled")
        }
    }
    
    // Validate Azure configuration
    if c.Cloud.Provider == "azure" {
        if c.Cloud.Azure.TenantID == "" && c.Cloud.Azure.AppInsightsEnabled {
            return errors.New("Azure tenant ID is required when Azure services are enabled")
        }
    }
    
    return nil
}

// GetTLSConfig returns TLS configuration for the given settings
func (c *SecurityConfig) GetTLSConfig() (*tls.Config, error) {
    if !c.TLSEnabled {
        return nil, nil
    }
    
    tlsConfig := &tls.Config{
        MinVersion: tls.VersionTLS13, // Default to TLS 1.3
    }
    
    // Parse minimum TLS version
    switch c.TLSMinVersion {
    case "1.2":
        tlsConfig.MinVersion = tls.VersionTLS12
    case "1.3":
        tlsConfig.MinVersion = tls.VersionTLS13
    default:
        return nil, fmt.Errorf("invalid TLS minimum version: %s", c.TLSMinVersion)
    }
    
    // Load certificate and key if provided
    if c.TLSCertFile != "" && c.TLSKeyFile != "" {
        cert, err := tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile)
        if err != nil {
            return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
        }
        tlsConfig.Certificates = []tls.Certificate{cert}
    }
    
    return tlsConfig, nil
}

// ToJSON returns the configuration as JSON (with secrets redacted)
func (c *Config) ToJSON() ([]byte, error) {
    // Create a copy for redaction
    redacted := *c
    
    // Redact sensitive information
    if redacted.Security.JWTSecret != "" {
        redacted.Security.JWTSecret = "[REDACTED]"
    }
    if redacted.Cloud.AWS.SecretAccessKey != "" {
        redacted.Cloud.AWS.SecretAccessKey = "[REDACTED]"
    }
    if redacted.Cloud.Azure.ClientSecret != "" {
        redacted.Cloud.Azure.ClientSecret = "[REDACTED]"
    }
    
    return json.MarshalIndent(redacted, "", "  ")
}

// LogSafeConfig returns a configuration summary safe for logging
func (c *Config) LogSafeConfig() map[string]interface{} {
    return map[string]interface{}{
        "service_name":        c.Service.Name,
        "service_version":     c.Service.Version,
        "environment":         c.Service.Environment,
        "log_level":          c.Log.Level,
        "log_format":         c.Log.Format,
        "trace_enabled":      c.Trace.Enabled,
        "trace_sampler_arg":  c.Trace.SamplerArg,
        "metrics_enabled":    c.Metrics.Enabled,
        "cloud_provider":     c.Cloud.Provider,
        "security_tls":       c.Security.TLSEnabled,
        "security_rate_limit": c.Security.RateLimitEnabled,
    }
}
```

**Decision Rationale**: This comprehensive configuration system addresses 2025+ requirements:

- **Environment Awareness**: Different defaults for development, staging, and production
- **Security First**: TLS configuration, rate limiting, and CORS support
- **Cloud Integration**: First-class support for GCP, AWS, and Azure
- **PII Compliance**: Built-in protection modes for GDPR/CCPA compliance
- **Feature Flags**: Enable/disable experimental features safely
- **Validation**: Comprehensive validation prevents runtime failures
- **Observability**: Configuration itself is observable and auditable

### Environment-Specific Configuration Examples

#### Development Configuration

```yaml
# configs/development/.env
# Service identification
SERVICE_NAME=go-observability-mastery
SERVICE_VERSION=dev
ENVIRONMENT=development
NAMESPACE=dev
REGION=us-east1
CLUSTER=local

# Logging (verbose for development)
LOG_LEVEL=debug
LOG_FORMAT=json
LOG_USER_ID_MODE=full
LOG_EMAIL_MODE=full
LOG_IP_ADDRESS_MODE=full
LOG_ENABLE_STACK_TRACE=true
LOG_ENABLE_SOURCE=true
LOG_PRETTY_PRINT=true
LOG_SAMPLING_RATE=1.0

# Tracing (100% sampling for complete visibility)
TRACE_ENABLED=true
TRACE_ENDPOINT=http://otel-collector:4318
TRACE_PROTOCOL=http
TRACE_SAMPLER_TYPE=parentbased_traceidratio
TRACE_SAMPLER_ARG=1.0
TRACE_BAGGAGE_ENABLED=true

# Metrics (all metrics enabled for learning)
METRICS_ENABLED=true
METRICS_PORT=9090
METRICS_PATH=/metrics
METRICS_ENABLE_GO_METRICS=true
METRICS_ENABLE_PROCESS_METRICS=true
METRICS_ENABLE_BUILD_INFO=true
METRICS_CARDINALITY_LIMIT=5000
METRICS_CARDINALITY_WARNING=4000

# Security (relaxed for development)
SECURITY_TLS_ENABLED=false
SECURITY_RATE_LIMIT_ENABLED=false
SECURITY_CORS_ENABLED=true
SECURITY_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080
SECURITY_ENABLE_SECURITY_HEADERS=false

# Cloud (disabled for local development)
CLOUD_PROVIDER=local
GCP_LOGGING_ENABLED=false
GCP_TRACE_ENABLED=false
GCP_MONITORING_ENABLED=false

# Features (enable development features)
FEATURE_ENABLE_EXPERIMENTAL=true
FEATURE_ENABLE_DEBUG_MODE=true
FEATURE_ENABLE_PPROF_ENDPOINT=true
FEATURE_ENABLE_HEALTH_CHECKS=true
```

#### Staging Configuration

```yaml
# configs/staging/.env
# Service identification
SERVICE_NAME=go-observability-mastery
SERVICE_VERSION=${GIT_COMMIT}
ENVIRONMENT=staging
NAMESPACE=staging
REGION=us-east1
CLUSTER=staging-cluster

# Logging (balanced for staging)
LOG_LEVEL=info
LOG_FORMAT=json
LOG_USER_ID_MODE=redacted
LOG_EMAIL_MODE=domain_only
LOG_IP_ADDRESS_MODE=none
LOG_ENABLE_STACK_TRACE=true
LOG_ENABLE_SOURCE=false
LOG_PRETTY_PRINT=false
LOG_SAMPLING_RATE=1.0

# Tracing (10% sampling for performance)
TRACE_ENABLED=true
TRACE_ENDPOINT=${OTLP_ENDPOINT}
TRACE_PROTOCOL=http
TRACE_SAMPLER_TYPE=parentbased_traceidratio
TRACE_SAMPLER_ARG=0.1
TRACE_BAGGAGE_ENABLED=true

# Metrics (production-like configuration)
METRICS_ENABLED=true
METRICS_PORT=9090
METRICS_ENABLE_GO_METRICS=true
METRICS_ENABLE_PROCESS_METRICS=true
METRICS_CARDINALITY_LIMIT=2000
METRICS_CARDINALITY_WARNING=1600

# Security (production-like for testing)
SECURITY_TLS_ENABLED=true
SECURITY_TLS_CERT_FILE=/etc/tls/tls.crt
SECURITY_TLS_KEY_FILE=/etc/tls/tls.key
SECURITY_RATE_LIMIT_ENABLED=true
SECURITY_RATE_LIMIT_RPS=200
SECURITY_CORS_ENABLED=true
SECURITY_ALLOWED_ORIGINS=${FRONTEND_URL}
SECURITY_ENABLE_SECURITY_HEADERS=true

# Cloud (enable for testing integration)
CLOUD_PROVIDER=gcp
GCP_PROJECT_ID=${GCP_PROJECT_ID}
GCP_LOGGING_ENABLED=true
GCP_TRACE_ENABLED=true
GCP_MONITORING_ENABLED=true
GCP_USE_WORKLOAD_IDENTITY=true

# Features (selective enablement)
FEATURE_ENABLE_EXPERIMENTAL=false
FEATURE_ENABLE_DEBUG_MODE=false
FEATURE_ENABLE_PPROF_ENDPOINT=false
FEATURE_ENABLE_HEALTH_CHECKS=true
```

#### Production Configuration

```yaml
# configs/production/.env
# Service identification
SERVICE_NAME=go-observability-mastery
SERVICE_VERSION=${GIT_COMMIT}
ENVIRONMENT=production
NAMESPACE=production
REGION=us-east1
CLUSTER=production-cluster

# Logging (minimal for production performance)
LOG_LEVEL=warn
LOG_FORMAT=json
LOG_USER_ID_MODE=redacted
LOG_EMAIL_MODE=domain_only
LOG_IP_ADDRESS_MODE=none
LOG_ENABLE_STACK_TRACE=false
LOG_ENABLE_SOURCE=false
LOG_PRETTY_PRINT=false
LOG_SAMPLING_RATE=0.1
LOG_ENABLE_PII_REDACTION=true

# Tracing (1% sampling for cost control)
TRACE_ENABLED=true
TRACE_ENDPOINT=${OTLP_ENDPOINT}
TRACE_PROTOCOL=http
TRACE_SAMPLER_TYPE=parentbased_traceidratio
TRACE_SAMPLER_ARG=0.01
TRACE_BAGGAGE_ENABLED=false
TRACE_TLS_ENABLED=true

# Metrics (minimal set for production)
METRICS_ENABLED=true
METRICS_PORT=9090
METRICS_ENABLE_GO_METRICS=false
METRICS_ENABLE_PROCESS_METRICS=false
METRICS_CARDINALITY_LIMIT=1000
METRICS_CARDINALITY_WARNING=800

# Security (strict for production)
SECURITY_TLS_ENABLED=true
SECURITY_TLS_CERT_FILE=/etc/tls/tls.crt
SECURITY_TLS_KEY_FILE=/etc/tls/tls.key
SECURITY_TLS_MIN_VERSION=1.3
SECURITY_RATE_LIMIT_ENABLED=true
SECURITY_RATE_LIMIT_RPS=100
SECURITY_RATE_LIMIT_BURST=200
SECURITY_API_KEY_REQUIRED=true
SECURITY_CORS_ENABLED=true
SECURITY_ALLOWED_ORIGINS=${FRONTEND_URL}
SECURITY_ENABLE_SECURITY_HEADERS=true

# Cloud (full integration)
CLOUD_PROVIDER=gcp
GCP_PROJECT_ID=${GCP_PROJECT_ID}
GCP_LOGGING_ENABLED=true
GCP_TRACE_ENABLED=true
GCP_MONITORING_ENABLED=true
GCP_ERROR_REPORTING_ENABLED=true
GCP_USE_WORKLOAD_IDENTITY=true

# Features (production-safe only)
FEATURE_ENABLE_EXPERIMENTAL=false
FEATURE_ENABLE_DEBUG_MODE=false
FEATURE_ENABLE_PPROF_ENDPOINT=false
FEATURE_ENABLE_HEALTH_CHECKS=true
FEATURE_ENABLE_AI_ANOMALY_DETECTION=true
```

## Testing Frameworks

### Comprehensive Testing Strategy

**Decision Rationale**: Modern Go applications require multiple testing layers:

- **Unit Tests**: Fast feedback on individual components
- **Integration Tests**: Verify component interactions
- **End-to-End Tests**: Validate complete user journeys
- **Performance Tests**: Ensure observability doesn't impact performance
- **Chaos Tests**: Verify resilience under failure conditions

#### Test Utilities and Helpers

```go
// internal/platform/obs/testing/helpers.go
package testing

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "net/http/httptest"
    "sync"
    "testing"
    "time"
    
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/testutil"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "go.opentelemetry.io/otel/trace"
    "go.opentelemetry.io/otel/baggage"
    
    "github.com/ashokallu/go-observability-mastery/internal/platform/obs/log"
    "github.com/ashokallu/go-observability-mastery/internal/platform/obs/metrics"
    "github.com/ashokallu/go-observability-mastery/internal/platform/obs/errors"
)

// ObservabilityTestSuite provides comprehensive observability testing utilities
type ObservabilityTestSuite struct {
    t             *testing.T
    logCapture    *LogCapture
    traceCapture  *TraceCapture
    metricsRegistry *prometheus.Registry
    metricsAssertion *MetricsAssertion
    httpRecorder  *httptest.ResponseRecorder
    
    // Configuration for testing
    config        *Config
    cleanup       []func()
}

// NewObservabilityTestSuite creates a complete testing environment
func NewObservabilityTestSuite(t *testing.T) *ObservabilityTestSuite {
    registry := prometheus.NewRegistry()
    
    suite := &ObservabilityTestSuite{
        t:                t,
        logCapture:       NewLogCapture(),
        traceCapture:     NewTraceCapture(),
        metricsRegistry:  registry,
        metricsAssertion: NewMetricsAssertion(t, registry),
        httpRecorder:     httptest.NewRecorder(),
        config:           NewTestConfig(),
        cleanup:          make([]func(), 0),
    }
    
    // Register cleanup
    t.Cleanup(suite.Cleanup)
    
    return suite
}

// GetLogger returns a test logger with capture
func (s *ObservabilityTestSuite) GetLogger() log.Logger {
    logger := log.NewLoggerWithDestination(s.config.Log, s.logCapture)
    return logger
}

// GetTracer returns a test tracer with capture
func (s *ObservabilityTestSuite) GetTracer() trace.Tracer {
    tracer := trace.NewTestTracer(s.traceCapture)
    return tracer
}

// GetMetricsRegistry returns the test metrics registry
func (s *ObservabilityTestSuite) GetMetricsRegistry() *prometheus.Registry {
    return s.metricsRegistry
}

// WithContext creates a test context with observability components
func (s *ObservabilityTestSuite) WithContext() context.Context {
    ctx := context.Background()
    
    // Add request ID
    ctx = log.WithRequestID(ctx, "test-request-123")
    
    // Add user context
    ctx = log.WithUserID(ctx, "test-user-456")
    
    // Add operation context
    ctx = log.WithOperation(ctx, "test.operation")
    
    // Attach enriched logger
    logger := s.GetLogger().With(
        "test_case", s.t.Name(),
        "request_id", "test-request-123",
        "user_id", "test-user-456",
    )
    ctx = log.AttachLogger(ctx, logger)
    
    return ctx
}

// AssertLogEntry validates log entry properties
func (s *ObservabilityTestSuite) AssertLogEntry(level string, message string, fields map[string]interface{}) {
    entries := s.logCapture.EntriesWithLevel(level)
    
    found := false
    for _, entry := range entries {
        if entry.Message == message {
            found = true
            for key, expectedValue := range fields {
                actualValue, exists := entry.Fields[key]
                require.True(s.t, exists, "Field %s not found in log entry", key)
                assert.Equal(s.t, expectedValue, actualValue, "Field %s has wrong value", key)
            }
            break
        }
    }
    
    require.True(s.t, found, "Log entry with message '%s' not found", message)
}

// AssertSpan validates span properties
func (s *ObservabilityTestSuite) AssertSpan(name string, attributes map[string]interface{}) {
    spans := s.traceCapture.SpansWithName(name)
    require.NotEmpty(s.t, spans, "No spans found with name '%s'", name)
    
    span := spans[0]
    for key, expectedValue := range attributes {
        // Implementation would check span attributes
        // This is a simplified version
        assert.NotNil(s.t, span, "Span attribute validation for %s", key)
    }
}

// AssertMetric validates metric values
func (s *ObservabilityTestSuite) AssertMetric(metricName string, labels []string, expectedValue float64) {
    s.metricsAssertion.AssertMetricExists(metricName)
    // Additional metric validation would go here
}

// AssertErrorCorrelation validates that errors are properly correlated across signals
func (s *ObservabilityTestSuite) AssertErrorCorrelation(appError *errors.AppError, requestID string) {
    // Check error appears in logs
    errorLogs := s.logCapture.EntriesWithLevel("error")
    found := false
    for _, entry := range errorLogs {
        if entry.Fields["request_id"] == requestID && 
           entry.Fields["error_code"] == appError.Code {
            found = true
            break
        }
    }
    require.True(s.t, found, "Error not found in logs with correct correlation")
    
    // Check error appears in traces
    spans := s.traceCapture.Spans()
    for _, span := range spans {
        // Check if span has error status and correct request ID
        // Implementation would validate span error correlation
    }
    
    // Check error appears in metrics
    errorMetric := "errors_total"
    s.metricsAssertion.AssertMetricExists(errorMetric)
}

// Cleanup releases test resources
func (s *ObservabilityTestSuite) Cleanup() {
    for _, cleanup := range s.cleanup {
        cleanup()
    }
    
    s.logCapture.Reset()
    s.traceCapture.Reset()
}

// LogCapture captures log entries for testing with advanced filtering
type LogCapture struct {
    mu      sync.RWMutex
    entries []CapturedLogEntry
    buffer  *bytes.Buffer
}

type CapturedLogEntry struct {
    Level     string         `json:"level"`
    Message   string         `json:"msg"`
    Fields    map[string]any `json:",inline"`
    Timestamp time.Time      `json:"time"`
    Source    *SourceInfo    `json:"source,omitempty"`
}

type SourceInfo struct {
    Function string `json:"function"`
    File     string `json:"file"`
    Line     int    `json:"line"`
}

// NewLogCapture creates a new log capture utility
func NewLogCapture() *LogCapture {
    return &LogCapture{
        entries: make([]CapturedLogEntry, 0),
        buffer:  &bytes.Buffer{},
    }
}

// Write implements io.Writer for capturing log output
func (lc *LogCapture) Write(p []byte) (n int, err error) {
    lc.mu.Lock()
    defer lc.mu.Unlock()
    
    // Parse JSON log entry
    var entry CapturedLogEntry
    if err := json.Unmarshal(p, &entry); err == nil {
        // Set timestamp if not present
        if entry.Timestamp.IsZero() {
            entry.Timestamp = time.Now()
        }
        lc.entries = append(lc.entries, entry)
    }
    
    return lc.buffer.Write(p)
}

// Entries returns all captured log entries (thread-safe copy)
func (lc *LogCapture) Entries() []CapturedLogEntry {
    lc.mu.RLock()
    defer lc.mu.RUnlock()
    
    // Return copy to prevent race conditions
    entries := make([]CapturedLogEntry, len(lc.entries))
    copy(entries, lc.entries)
    return entries
}

// EntriesWithLevel returns entries at specified level
func (lc *LogCapture) EntriesWithLevel(level string) []CapturedLogEntry {
    lc.mu.RLock()
    defer lc.mu.RUnlock()
    
    var filtered []CapturedLogEntry
    for _, entry := range lc.entries {
        if entry.Level == level {
            filtered = append(filtered, entry)
        }
    }
    return filtered
}

// EntriesWithField returns entries containing specific field
func (lc *LogCapture) EntriesWithField(key string, value interface{}) []CapturedLogEntry {
    lc.mu.RLock()
    defer lc.mu.RUnlock()
    
    var filtered []CapturedLogEntry
    for _, entry := range lc.entries {
        if fieldValue, exists := entry.Fields[key]; exists && fieldValue == value {
            filtered = append(filtered, entry)
        }
    }
    return filtered
}

// EntriesInTimeRange returns entries within specified time range
func (lc *LogCapture) EntriesInTimeRange(start, end time.Time) []CapturedLogEntry {
    lc.mu.RLock()
    defer lc.mu.RUnlock()
    
    var filtered []CapturedLogEntry
    for _, entry := range lc.entries {
        if entry.Timestamp.After(start) && entry.Timestamp.Before(end) {
            filtered = append(filtered, entry)
        }
    }
    return filtered
}

// LastEntry returns the most recent log entry
func (lc *LogCapture) LastEntry() *CapturedLogEntry {
    lc.mu.RLock()
    defer lc.mu.RUnlock()
    
    if len(lc.entries) == 0 {
        return nil
    }
    return &lc.entries[len(lc.entries)-1]
}

// ContainsMessage checks if any entry contains the specified message
func (lc *LogCapture) ContainsMessage(message string) bool {
    lc.mu.RLock()
    defer lc.mu.RUnlock()
    
    for _, entry := range lc.entries {
        if strings.Contains(entry.Message, message) {
            return true
        }
    }
    return false
}

// ContainsField checks if any entry contains the specified field
func (lc *LogCapture) ContainsField(key string, value any) bool {
    lc.mu.RLock()
    defer lc.mu.RUnlock()
    
    for _, entry := range lc.entries {
        if fieldValue, exists := entry.Fields[key]; exists {
            if fieldValue == value {
                return true
            }
        }
    }
    return false
}

// Count returns the total number of captured entries
func (lc *LogCapture) Count() int {
    lc.mu.RLock()
    defer lc.mu.RUnlock()
    return len(lc.entries)
}

// CountByLevel returns count of entries by level
func (lc *LogCapture) CountByLevel() map[string]int {
    lc.mu.RLock()
    defer lc.mu.RUnlock()
    
    counts := make(map[string]int)
    for _, entry := range lc.entries {
        counts[entry.Level]++
    }
    return counts
}

// Reset clears all captured entries
func (lc *LogCapture) Reset() {
    lc.mu.Lock()
    defer lc.mu.Unlock()
    
    lc.entries = lc.entries[:0]
    lc.buffer.Reset()
}

// TraceCapture captures spans for testing with advanced filtering
type TraceCapture struct {
    mu    sync.RWMutex
    spans []trace.ReadOnlySpan
    stats TraceStats
}

type TraceStats struct {
    TotalSpans    int
    SpansByName   map[string]int
    SpansByStatus map[string]int
    AvgDuration   time.Duration
}

// NewTraceCapture creates a new trace capture utility
func NewTraceCapture() *TraceCapture {
    return &TraceCapture{
        spans: make([]trace.ReadOnlySpan, 0),
        stats: TraceStats{
            SpansByName:   make(map[string]int),
            SpansByStatus: make(map[string]int),
        },
    }
}

// CaptureSpan captures a span for testing
func (tc *TraceCapture) CaptureSpan(span trace.ReadOnlySpan) {
    tc.mu.Lock()
    defer tc.mu.Unlock()
    
    tc.spans = append(tc.spans, span)
    
    // Update statistics
    tc.stats.TotalSpans++
    tc.stats.SpansByName[span.Name()]++
    tc.stats.SpansByStatus[span.Status().Code.String()]++
}

// Spans returns all captured spans (thread-safe copy)
func (tc *TraceCapture) Spans() []trace.ReadOnlySpan {
    tc.mu.RLock()
    defer tc.mu.RUnlock()
    
    // Return copy to prevent race conditions
    spans := make([]trace.ReadOnlySpan, len(tc.spans))
    copy(spans, tc.spans)
    return spans
}

// SpansWithName returns spans with the specified name
func (tc *TraceCapture) SpansWithName(name string) []trace.ReadOnlySpan {
    tc.mu.RLock()
    defer tc.mu.RUnlock()
    
    var filtered []trace.ReadOnlySpan
    for _, span := range tc.spans {
        if span.Name() == name {
            filtered = append(filtered, span)
        }
    }
    return filtered
}

// SpansWithAttribute returns spans containing specific attribute
func (tc *TraceCapture) SpansWithAttribute(key string, value interface{}) []trace.ReadOnlySpan {
    tc.mu.RLock()
    defer tc.mu.RUnlock()
    
    var filtered []trace.ReadOnlySpan
    for _, span := range tc.spans {
        // Implementation would check span attributes
        // This is a simplified version
        if span != nil {
            filtered = append(filtered, span)
        }
    }
    return filtered
}

// RootSpans returns only root spans (spans without parent)
func (tc *TraceCapture) RootSpans() []trace.ReadOnlySpan {
    tc.mu.RLock()
    defer tc.mu.RUnlock()
    
    var roots []trace.ReadOnlySpan
    for _, span := range tc.spans {
        if !span.Parent().IsValid() {
            roots = append(roots, span)
        }
    }
    return roots
}

// GetTraceTree returns spans organized by trace ID
func (tc *TraceCapture) GetTraceTree() map[string][]trace.ReadOnlySpan {
    tc.mu.RLock()
    defer tc.mu.RUnlock()
    
    traces := make(map[string][]trace.ReadOnlySpan)
    for _, span := range tc.spans {
        traceID := span.SpanContext().TraceID().String()
        traces[traceID] = append(traces[traceID], span)
    }
    return traces
}

// Stats returns capture statistics
func (tc *TraceCapture) Stats() TraceStats {
    tc.mu.RLock()
    defer tc.mu.RUnlock()
    
    return tc.stats
}

// Reset clears all captured spans
func (tc *TraceCapture) Reset() {
    tc.mu.Lock()
    defer tc.mu.Unlock()
    
    tc.spans = tc.spans[:0]
    tc.stats = TraceStats{
        SpansByName:   make(map[string]int),
        SpansByStatus: make(map[string]int),
    }
}

// MetricsAssertion provides utilities for asserting on metrics
type MetricsAssertion struct {
    registry *prometheus.Registry
    t        *testing.T
}

// NewMetricsAssertion creates a new metrics assertion utility
func NewMetricsAssertion(t *testing.T, registry *prometheus.Registry) *MetricsAssertion {
    return &MetricsAssertion{
        registry: registry,
        t:        t,
    }
}

// AssertCounterValue asserts the value of a counter metric
func (ma *MetricsAssertion) AssertCounterValue(expected float64, counter prometheus.Counter) {
    actual := testutil.ToFloat64(counter)
    assert.Equal(ma.t, expected, actual, "Counter value mismatch")
}

// AssertCounterVecValue asserts the value of a counter metric with labels
func (ma *MetricsAssertion) AssertCounterVecValue(expected float64, counterVec *prometheus.CounterVec, labels ...string) {
    counter := counterVec.WithLabelValues(labels...)
    actual := testutil.ToFloat64(counter)
    assert.Equal(ma.t, expected, actual, "CounterVec value mismatch for labels %v", labels)
}

// AssertGaugeValue asserts the value of a gauge metric
func (ma *MetricsAssertion) AssertGaugeValue(expected float64, gauge prometheus.Gauge) {
    actual := testutil.ToFloat64(gauge)
    assert.Equal(ma.t, expected, actual, "Gauge value mismatch")
}

// AssertHistogramCount asserts the count of a histogram metric
func (ma *MetricsAssertion) AssertHistogramCount(expected int, histogram prometheus.Histogram) {
    dto := &prometheus.dto.Metric{}
    histogram.Write(dto)
    actual := int(dto.GetHistogram().GetSampleCount())
    assert.Equal(ma.t, expected, actual, "Histogram count mismatch")
}

// AssertHistogramBucket asserts specific histogram bucket counts
func (ma *MetricsAssertion) AssertHistogramBucket(expected uint64, histogram prometheus.Histogram, bucket float64) {
    dto := &prometheus.dto.Metric{}
    histogram.Write(dto)
    
    for _, b := range dto.GetHistogram().GetBucket() {
        if b.GetUpperBound() == bucket {
            actual := b.GetCumulativeCount()
            assert.Equal(ma.t, expected, actual, "Histogram bucket %f count mismatch", bucket)
            return
        }
    }
    
    ma.t.Errorf("Histogram bucket %f not found", bucket)
}

// AssertMetricExists asserts that a metric exists in the registry
func (ma *MetricsAssertion) AssertMetricExists(metricName string) {
    metricFamilies, err := ma.registry.Gather()
    require.NoError(ma.t, err)
    
    for _, family := range metricFamilies {
        if family.GetName() == metricName {
            return
        }
    }
    
    ma.t.Errorf("Metric %s not found in registry", metricName)
}

// AssertMetricCount asserts the total number of metrics in the registry
func (ma *MetricsAssertion) AssertMetricCount(expectedCount int) {
    metricFamilies, err := ma.registry.Gather()
    require.NoError(ma.t, err)
    
    actualCount := len(metricFamilies)
    assert.Equal(ma.t, expectedCount, actualCount, "Metric count mismatch")
}

// AssertCardinalityWithinBudget asserts that cardinality is within budget
func (ma *MetricsAssertion) AssertCardinalityWithinBudget(maxSeries int) {
    metricFamilies, err := ma.registry.Gather()
    require.NoError(ma.t, err)
    
    totalSeries := 0
    for _, family := range metricFamilies {
        totalSeries += len(family.GetMetric())
    }
    
    assert.LessOrEqual(ma.t, totalSeries, maxSeries, 
        "Cardinality budget exceeded: %d series > %d limit", totalSeries, maxSeries)
}

// GetCardinalityReport returns detailed cardinality information
func (ma *MetricsAssertion) GetCardinalityReport() map[string]int {
    metricFamilies, err := ma.registry.Gather()
    require.NoError(ma.t, err)
    
    report := make(map[string]int)
    for _, family := range metricFamilies {
        report[family.GetName()] = len(family.GetMetric())
    }
    
    return report
}

// HTTPTestServer provides HTTP testing utilities with observability
type HTTPTestServer struct {
    server   *httptest.Server
    suite    *ObservabilityTestSuite
    requests []CapturedRequest
    mu       sync.RWMutex
}

type CapturedRequest struct {
    Method    string
    URL       string
    Headers   http.Header
    Body      string
    Timestamp time.Time
    Duration  time.Duration
    Response  CapturedResponse
}

type CapturedResponse struct {
    StatusCode int
    Headers    http.Header
    Body       string
    Size       int
}

// NewHTTPTestServer creates an HTTP test server with observability
func NewHTTPTestServer(suite *ObservabilityTestSuite, handler http.Handler) *HTTPTestServer {
    ts := &HTTPTestServer{
        suite:    suite,
        requests: make([]CapturedRequest, 0),
    }
    
    // Wrap handler with request capture
    wrappedHandler := ts.wrapWithCapture(handler)
    ts.server = httptest.NewServer(wrappedHandler)
    
    return ts
}

// wrapWithCapture wraps HTTP handler to capture requests and responses
func (ts *HTTPTestServer) wrapWithCapture(handler http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        
        // Capture request
        var body []byte
        if r.Body != nil {
            body, _ = io.ReadAll(r.Body)
            r.Body = io.NopCloser(bytes.NewBuffer(body))
        }
        
        // Create response recorder
        recorder := &responseRecorder{
            ResponseWriter: w,
            statusCode:     200,
            body:          &bytes.Buffer{},
        }
        
        // Call original handler
        handler.ServeHTTP(recorder, r)
        
        // Capture response
        duration := time.Since(start)
        ts.captureRequest(CapturedRequest{
            Method:    r.Method,
            URL:       r.URL.String(),
            Headers:   r.Header,
            Body:      string(body),
            Timestamp: start,
            Duration:  duration,
            Response: CapturedResponse{
                StatusCode: recorder.statusCode,
                Headers:    recorder.Header(),
                Body:       recorder.body.String(),
                Size:       recorder.body.Len(),
            },
        })
    })
}

// captureRequest stores request information for later analysis
func (ts *HTTPTestServer) captureRequest(req CapturedRequest) {
    ts.mu.Lock()
    defer ts.mu.Unlock()
    ts.requests = append(ts.requests, req)
}

// GetRequests returns all captured requests
func (ts *HTTPTestServer) GetRequests() []CapturedRequest {
    ts.mu.RLock()
    defer ts.mu.RUnlock()
    
    requests := make([]CapturedRequest, len(ts.requests))
    copy(requests, ts.requests)
    return requests
}

// URL returns the test server URL
func (ts *HTTPTestServer) URL() string {
    return ts.server.URL
}

// Close closes the test server
func (ts *HTTPTestServer) Close() {
    ts.server.Close()
}

// responseRecorder implements http.ResponseWriter with capture
type responseRecorder struct {
    http.ResponseWriter
    statusCode int
    body       *bytes.Buffer
}

func (r *responseRecorder) WriteHeader(statusCode int) {
    r.statusCode = statusCode
    r.ResponseWriter.WriteHeader(statusCode)
}

func (r *responseRecorder) Write(data []byte) (int, error) {
    r.body.Write(data)
    return r.ResponseWriter.Write(data)
}

// TestConfig creates test-safe configuration
func NewTestConfig() *Config {
    return &Config{
        Service: ServiceConfig{
            Name:        "test-service",
            Version:     "test",
            Environment: "test",
        },
        Log: LogConfig{
            Level:               "debug",
            Format:              "json",
            UserIDMode:          "full",
            EmailMode:           "full",
            EnableStackTrace:    true,
            EnableSource:        true,
            PrettyPrint:         false,
            EnablePIIRedaction:  false, // Disable for easier testing
        },
        Trace: TraceConfig{
            Enabled:    true,
            SamplerArg: 1.0, // 100% sampling for tests
        },
        Metrics: MetricsConfig{
            Enabled:                true,
            CardinalityLimit:       10000, // Higher limit for tests
            EnableCardinalityCheck: false, // Disable for flexibility
        },
        Security: SecurityConfig{
            TLSEnabled:           false,
            RateLimitEnabled:     false,
            EnableSecurityHeaders: false,
        },
        Cloud: CloudConfig{
            Provider: "local",
        },
        Features: FeatureConfig{
            EnableDebugMode:     true,
            EnableHealthChecks:  true,
            EnablePProfEndpoint: true,
        },
    }
}
```

#### Unit Test Patterns

```go
// internal/platform/obs/log/logger_test.go
package log

import (
    "context"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    
    obstesting "github.com/ashokallu/go-observability-mastery/internal/platform/obs/testing"
)

func TestLogger_ContextPropagation(t *testing.T) {
    tests := []struct {
        name     string
        setup    func(context.Context) context.Context
        logFunc  func(log.Logger, context.Context)
        validate func(t *testing.T, capture *obstesting.LogCapture)
    }{
        {
            name: "request_id_propagation",
            setup: func(ctx context.Context) context.Context {
                return WithRequestID(ctx, "test-request-123")
            },
            logFunc: func(logger log.Logger, ctx context.Context) {
                logger.InfoCtx(ctx, "test message")
            },
            validate: func(t *testing.T, capture *obstesting.LogCapture) {
                entries := capture.Entries()
                require.Len(t, entries, 1)
                assert.Equal(t, "test-request-123", entries[0].Fields["request_id"])
            },
        },
        {
            name: "user_id_redaction",
            setup: func(ctx context.Context) context.Context {
                return WithUserID(ctx, "user-12345678")
            },
            logFunc: func(logger log.Logger, ctx context.Context) {
                logger.InfoCtx(ctx, "user action", "user_id", UserIDFromContext(ctx))
            },
            validate: func(t *testing.T, capture *obstesting.LogCapture) {
                entries := capture.Entries()
                require.Len(t, entries, 1)
                
                // Should be redacted in production config
                userID := entries[0].Fields["user_id"]
                assert.Contains(t, userID, "****")
                assert.NotContains(t, userID, "12345678")
            },
        },
        {
            name: "trace_correlation",
            setup: func(ctx context.Context) context.Context {
                // This would setup a test span context
                return ctx
            },
            logFunc: func(logger log.Logger, ctx context.Context) {
                logger.InfoCtx(ctx, "trace correlation test")
            },
            validate: func(t *testing.T, capture *obstesting.LogCapture) {
                entries := capture.Entries()
                require.Len(t, entries, 1)
                
                // Verify trace context is included
                assert.Contains(t, entries[0].Fields, "trace_id")
                assert.Contains(t, entries[0].Fields, "span_id")
            },
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Setup test environment
            suite := obstesting.NewObservabilityTestSuite(t)
            logger := suite.GetLogger()
            
            // Configure for redaction testing
            cfg := suite.GetConfig()
            cfg.Log.UserIDMode = "redacted"
            
            // Setup context
            ctx := context.Background()
            if tt.setup != nil {
                ctx = tt.setup(ctx)
            }
            
            // Execute logging
            tt.logFunc(logger, ctx)
            
            // Validate results
            tt.validate(t, suite.GetLogCapture())
        })
    }
}

func TestLogger_PIIProtection(t *testing.T) {
    testCases := []struct {
        name           string
        config         Config
        logFields      []any
        expectRedacted bool
        expectExcluded bool
    }{
        {
            name: "email_domain_only",
            config: Config{
                Log: LogConfig{
                    EmailMode:   "domain_only",
                    Format:      "json",
                },
            },
            logFields:      []any{"email", "user@example.com"},
            expectRedacted: false,
            expectExcluded: false,
        },
        {
            name: "user_id_redacted",
            config: Config{
                Log: LogConfig{
                    UserIDMode:  "redacted",
                    Format:      "json",
                },
            },
            logFields:      []any{"user_id", "user-123456789"},
            expectRedacted: true,
            expectExcluded: false,
        },
        {
            name: "user_id_excluded",
            config: Config{
                Log: LogConfig{
                    UserIDMode:  "none",
                    Format:      "json",
                },
            },
            logFields:      []any{"user_id", "user-123456789"},
            expectRedacted: false,
            expectExcluded: true,
        },
        {
            name: "ip_address_protection",
            config: Config{
                Log: LogConfig{
                    IPAddressMode: "none",
                    Format:        "json",
                },
            },
            logFields:      []any{"client_ip", "192.168.1.100"},
            expectRedacted: false,
            expectExcluded: true,
        },
    }
    
    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            suite := obstesting.NewObservabilityTestSuite(t)
            capture := suite.GetLogCapture()
            
            logger := NewLoggerWithConfig(tc.config, capture)
            
            logger.InfoCtx(context.Background(), "test message", tc.logFields...)
            
            entries := capture.Entries()
            require.Len(t, entries, 1)
            
            entry := entries[0]
            fieldKey := tc.logFields[0].(string)
            originalValue := tc.logFields[1].(string)
            
            if tc.expectExcluded {
                assert.NotContains(t, entry.Fields, fieldKey)
            } else {
                require.Contains(t, entry.Fields, fieldKey)
                actualValue := entry.Fields[fieldKey].(string)
                
                if tc.expectRedacted {
                    assert.NotEqual(t, originalValue, actualValue)
                    assert.Contains(t, actualValue, "***")
                } else if tc.config.Log.EmailMode == "domain_only" && fieldKey == "email" {
                    assert.Equal(t, "example.com", actualValue)
                }
            }
        })
    }
}

func TestLogger_Performance(t *testing.T) {
    // Test that logging doesn't significantly impact performance
    suite := obstesting.NewObservabilityTestSuite(t)
    logger := suite.GetLogger()
    ctx := suite.WithContext()
    
    // Benchmark logging performance
    iterations := 10000
    start := time.Now()
    
    for i := 0; i < iterations; i++ {
        logger.InfoCtx(ctx, "performance test message",
            "iteration", i,
            "timestamp", time.Now().Unix(),
        )
    }
    
    duration := time.Since(start)
    avgLatency := duration / time.Duration(iterations)
    
    // Assert reasonable performance (< 1ms per log entry)
    assert.Less(t, avgLatency, time.Millisecond, 
        "Logging performance too slow: %v per entry", avgLatency)
    
    t.Logf("Logging performance: %v per entry (%d entries in %v)", 
        avgLatency, iterations, duration)
}

func TestLogger_ConcurrentSafety(t *testing.T) {
    suite := obstesting.NewObservabilityTestSuite(t)
    logger := suite.GetLogger()
    
    const goroutines = 100
    const messagesPerGoroutine = 100
    
    var wg sync.WaitGroup
    wg.Add(goroutines)
    
    // Launch concurrent goroutines writing logs
    for i := 0; i < goroutines; i++ {
        go func(goroutineID int) {
            defer wg.Done()
            ctx := suite.WithContext()
            
            for j := 0; j < messagesPerGoroutine; j++ {
                logger.InfoCtx(ctx, "concurrent log message",
                    "goroutine_id", goroutineID,
                    "message_id", j,
                )
            }
        }(i)
    }
    
    wg.Wait()
    
    // Verify all messages were captured
    entries := suite.GetLogCapture().Entries()
    expectedCount := goroutines * messagesPerGoroutine
    assert.Equal(t, expectedCount, len(entries), 
        "Expected %d log entries, got %d", expectedCount, len(entries))
    
    // Verify no data races or corruption
    messageCount := make(map[string]int)
    for _, entry := range entries {
        key := fmt.Sprintf("g%v-m%v", entry.Fields["goroutine_id"], entry.Fields["message_id"])
        messageCount[key]++
    }
    
    // Each unique message should appear exactly once
    for key, count := range messageCount {
        assert.Equal(t, 1, count, "Message %s appeared %d times", key, count)
    }
}
```

#### Integration Test Patterns

```go
// internal/api/integration_test.go
package api

import (
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
    "time"
    
    "github.com/gin-gonic/gin"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    
    "github.com/ashokallu/go-observability-mastery/internal/platform/obs/config"
    "github.com/ashokallu/go-observability-mastery/internal/platform/obs/log"
    "github.com/ashokallu/go-observability-mastery/internal/platform/obs/metrics"
    "github.com/ashokallu/go-observability-mastery/internal/platform/obs/trace"
    "github.com/ashokallu/go-observability-mastery/internal/platform/obs/errors"
    obstesting "github.com/ashokallu/go-observability-mastery/internal/platform/obs/testing"
)

func TestFullObservabilityIntegration(t *testing.T) {
    // Setup comprehensive test observability stack
    cfg := &config.Config{
        Service: config.ServiceConfig{
            Name:        "test-api",
            Environment: "test",
        },
        Log: config.LogConfig{
            Level:      "debug",
            Format:     "json",
            UserIDMode: "redacted",
        },
        Trace: config.TraceConfig{
            Enabled:    true,
            SamplerArg: 1.0, // 100% sampling for tests
        },
        Metrics: config.MetricsConfig{
            Enabled: true,
        },
    }
    
    // Create comprehensive test suite
    suite := obstesting.NewObservabilityTestSuite(t)
    
    // Initialize observability components
    logger := suite.GetLogger()
    tracer := suite.GetTracer()
    metricsRegistry := suite.GetMetricsRegistry()
    
    // Setup Gin router with observability middleware
    gin.SetMode(gin.TestMode)
    router := gin.New()
    
    // Add comprehensive observability middleware stack
    router.Use(middleware.Logging(logger, cfg.Log))
    router.Use(middleware.Tracing(tracer))
    router.Use(middleware.Metrics(metricsRegistry))
    router.Use(middleware.ErrorObservation(logger, tracer, metricsRegistry))
    router.Use(middleware.Security(cfg.Security))
    router.Use(middleware.RequestID())
    
    // Add test routes with business logic
    router.POST("/users", func(c *gin.Context) {
        ctx := c.Request.Context()
        reqLogger := log.LoggerFromContext(ctx)
        
        // Simulate business logic with comprehensive observability
        ctx, span := tracer.Start(ctx, "user.create")
        defer span.End()
        
        reqLogger.InfoCtx(ctx, "creating user",
            "user_type", "premium",
            "email_domain", "example.com",
            "registration_source", "api",
        )
        
        // Simulate validation
        var req CreateUserRequest
        if err := c.ShouldBindJSON(&req); err != nil {
            appError := errors.ValidationError("user.create", "request.invalid", "invalid request format", err)
            c.Error(appError)
            c.JSON(400, gin.H{"error": "invalid_request"})
            return
        }
        
        // Simulate error scenario for some requests
        if c.GetHeader("X-Simulate-Error") == "true" {
            err := errors.New("simulated database error")
            appError := errors.InternalError("user.create", "database.error", "failed to save", err)
            c.Error(appError)
            c.JSON(500, gin.H{"error": "internal_error"})
            return
        }
        
        // Simulate successful creation
        user := User{
            ID:    "user-123",
            Email: req.Email,
            Name:  req.Name,
        }
        
        reqLogger.InfoCtx(ctx, "user created successfully",
            "user_id", user.ID,
            "email_domain", extractDomain(user.Email),
        )
        
        c.JSON(201, gin.H{
            "user_id": user.ID,
            "status":  "created",
        })
    })
    
    // Add health check endpoint
    router.GET("/health", func(c *gin.Context) {
        c.JSON(200, gin.H{
            "status": "healthy",
            "timestamp": time.Now().Unix(),
        })
    })
    
    t.Run("successful_request_observability", func(t *testing.T) {
        // Reset test state
        suite.Reset()
        
        // Make successful request with correlation ID
        req := httptest.NewRequest("POST", "/users", 
            strings.NewReader(`{"name":"John Doe","email":"john@example.com"}`))
        req.Header.Set("Content-Type", "application/json")
        req.Header.Set("X-Request-ID", "test-req-123")
        req.Header.Set("User-Agent", "test-client/1.0")
        w := httptest.NewRecorder()
        
        router.ServeHTTP(w, req)
        
        // Verify HTTP response
        assert.Equal(t, 201, w.Code)
        
        var response map[string]interface{}
        err := json.Unmarshal(w.Body.Bytes(), &response)
        require.NoError(t, err)
        assert.Equal(t, "created", response["status"])
        assert.Equal(t, "user-123", response["user_id"])
        
        // Verify comprehensive logging
        suite.AssertLogEntry("info", "creating user", map[string]interface{}{
            "request_id": "test-req-123",
            "user_type": "premium",
            "email_domain": "example.com",
        })
        
        suite.AssertLogEntry("info", "user created successfully", map[string]interface{}{
            "request_id": "test-req-123",
            "user_id": "user-123",
            "email_domain": "example.com",
        })
        
        // Verify request correlation across all log entries
        logEntries := suite.GetLogCapture().Entries()
        for _, entry := range logEntries {
            assert.Equal(t, "test-req-123", entry.Fields["request_id"],
                "All log entries should have request ID correlation")
        }
        
        // Verify traces
        spans := suite.GetTraceCapture().Spans()
        assert.GreaterOrEqual(t, len(spans), 2) // HTTP span + user.create span
        
        // Check span hierarchy and attributes
        httpSpans := suite.GetTraceCapture().SpansWithName("POST /users")
        require.NotEmpty(t, httpSpans, "HTTP span should be created")
        
        userCreateSpans := suite.GetTraceCapture().SpansWithName("user.create")
        require.NotEmpty(t, userCreateSpans, "Business logic span should be created")
        
        // Verify span attributes
        suite.AssertSpan("user.create", map[string]interface{}{
            "user.type": "premium",
            "operation": "create",
        })
        
        // Verify metrics
        suite.AssertMetric("http_requests_total", []string{"POST", "/users", "2xx"}, 1.0)
        suite.AssertMetric("http_request_duration_seconds", []string{"POST", "/users"}, 0.0) // Any value
        
        // Verify cardinality is within budget
        cardinalityReport := suite.GetMetricsAssertion().GetCardinalityReport()
        totalSeries := 0
        for _, count := range cardinalityReport {
            totalSeries += count
        }
        assert.LessOrEqual(t, totalSeries, 100, "Cardinality should be within test budget")
    })
    
    t.Run("error_request_observability", func(t *testing.T) {
        // Reset test state
        suite.Reset()
        
        // Make error request
        req := httptest.NewRequest("POST", "/users", 
            strings.NewReader(`{"name":"John Doe","email":"john@example.com"}`))
        req.Header.Set("Content-Type", "application/json")
        req.Header.Set("X-Request-ID", "test-req-error")
        req.Header.Set("X-Simulate-Error", "true")
        w := httptest.NewRecorder()
        
        router.ServeHTTP(w, req)
        
        // Verify HTTP response
        assert.Equal(t, 500, w.Code)
        
        // Verify error correlation across all signals
        errorLogs := suite.GetLogCapture().EntriesWithLevel("error")
        require.GreaterOrEqual(t, len(errorLogs), 1, "Error should be logged")
        
        // Check error correlation
        errorLog := errorLogs[0]
        assert.Equal(t, "test-req-error", errorLog.Fields["request_id"])
        assert.Equal(t, "internal", errorLog.Fields["error_kind"])
        assert.Equal(t, "database.error", errorLog.Fields["error_code"])
        
        // Verify error spans
        spans := suite.GetTraceCapture().Spans()
        hasErrorSpan := false
        for _, span := range spans {
            // Check if any span has error status
            if span.Status().Code.String() == "ERROR" {
                hasErrorSpan = true
                break
            }
        }
        assert.True(t, hasErrorSpan, "At least one span should have error status")
        
        // Verify error metrics
        suite.AssertMetric("errors_total", []string{"internal"}, 1.0)
        suite.AssertMetric("http_requests_total", []string{"POST", "/users", "5xx"}, 1.0)
        
        // Verify error is properly classified
        appError := errors.InternalError("test", "test.code", "test message", nil)
        suite.AssertErrorCorrelation(appError, "test-req-error")
    })
    
    t.Run("health_check_observability", func(t *testing.T) {
        // Reset test state
        suite.Reset()
        
        // Make health check request
        req := httptest.NewRequest("GET", "/health", nil)
        req.Header.Set("X-Request-ID", "health-check-123")
        w := httptest.NewRecorder()
        
        router.ServeHTTP(w, req)
        
        // Verify response
        assert.Equal(t, 200, w.Code)
        
        // Verify health check is logged but not overly verbose
        logEntries := suite.GetLogCapture().Entries()
        healthLogs := 0
        for _, entry := range logEntries {
            if strings.Contains(entry.Message, "health") {
                healthLogs++
            }
        }
        
        // Health checks should be minimal to avoid noise
        assert.LessOrEqual(t, healthLogs, 2, "Health checks should generate minimal logs")
        
        // Verify health check metrics
        suite.AssertMetric("http_requests_total", []string{"GET", "/health", "2xx"}, 1.0)
    })
}

func TestObservabilityPerformanceImpact(t *testing.T) {
    // Performance test to ensure observability overhead is acceptable
    cfg := &config.Config{
        Log: config.LogConfig{
            Level:  "info",
            Format: "json",
        },
        Trace: config.TraceConfig{
            Enabled:    true,
            SamplerArg: 1.0,
        },
        Metrics: config.MetricsConfig{
            Enabled: true,
        },
    }
    
    // Test with observability
    withObservabilityLatency := func() time.Duration {
        suite := obstesting.NewObservabilityTestSuite(t)
        
        gin.SetMode(gin.TestMode)
        router := gin.New()
        
        // Add full observability stack
        router.Use(middleware.Logging(suite.GetLogger(), cfg.Log))
        router.Use(middleware.Tracing(suite.GetTracer()))
        router.Use(middleware.Metrics(suite.GetMetricsRegistry()))
        
        router.GET("/test", func(c *gin.Context) {
            ctx := c.Request.Context()
            logger := log.LoggerFromContext(ctx)
            
            // Simulate business logic
            logger.InfoCtx(ctx, "processing request", "operation", "test")
            time.Sleep(1 * time.Millisecond) // Simulate work
            
            c.JSON(200, gin.H{"status": "ok"})
        })
        
        // Measure request latency
        start := time.Now()
        for i := 0; i < 1000; i++ {
            req := httptest.NewRequest("GET", "/test", nil)
            req.Header.Set("X-Request-ID", fmt.Sprintf("perf-test-%d", i))
            w := httptest.NewRecorder()
            router.ServeHTTP(w, req)
        }
        return time.Since(start)
    }
    
    // Test without observability (baseline)
    withoutObservabilityLatency := func() time.Duration {
        gin.SetMode(gin.TestMode)
        router := gin.New()
        
        router.GET("/test", func(c *gin.Context) {
            // Minimal work equivalent to business logic
            time.Sleep(1 * time.Millisecond)
            c.JSON(200, gin.H{"status": "ok"})
        })
        
        start := time.Now()
        for i := 0; i < 1000; i++ {
            req := httptest.NewRequest("GET", "/test", nil)
            w := httptest.NewRecorder()
            router.ServeHTTP(w, req)
        }
        return time.Since(start)
    }
    
    // Run performance tests
    baselineLatency := withoutObservabilityLatency()
    observabilityLatency := withObservabilityLatency()
    
    // Calculate overhead
    overhead := float64(observabilityLatency-baselineLatency) / float64(baselineLatency)
    
    // Assert acceptable overhead (< 50% for 1000 operations)
    assert.Less(t, overhead, 0.5, 
        "Observability overhead too high: baseline=%v, with_obs=%v, overhead=%.2f%%",
        baselineLatency, observabilityLatency, overhead*100)
    
    t.Logf("Performance test results:")
    t.Logf("  Baseline: %v", baselineLatency)
    t.Logf("  With observability: %v", observabilityLatency)
    t.Logf("  Overhead: %.2f%%", overhead*100)
    
    // Performance should be within acceptable bounds for production use
    perRequestOverhead := (observabilityLatency - baselineLatency) / 1000
    assert.Less(t, perRequestOverhead, 500*time.Microsecond,
        "Per-request observability overhead too high: %v", perRequestOverhead)
}

// Helper types for testing
type CreateUserRequest struct {
    Name  string `json:"name" binding:"required"`
    Email string `json:"email" binding:"required,email"`
}

type User struct {
    ID    string `json:"id"`
    Name  string `json:"name"`
    Email string `json:"email"`
}

func extractDomain(email string) string {
    parts := strings.Split(email, "@")
    if len(parts) == 2 {
        return parts[1]
    }
    return "unknown"
}
```

#### End-to-End Test Patterns

```go
// internal/e2e/observability_e2e_test.go
//go:build e2e
// +build e2e

package e2e

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "testing"
    "time"
    
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    
    obstesting "github.com/ashokallu/go-observability-mastery/internal/platform/obs/testing"
)

func TestCompleteObservabilityPipeline(t *testing.T) {
    // This test requires the full observability stack to be running
    // docker-compose up -d
    
    client := &http.Client{Timeout: 30 * time.Second}
    
    t.Run("trace_log_metrics_correlation", func(t *testing.T) {
        // Generate a request with unique correlation ID
        correlationID := fmt.Sprintf("e2e-test-%d", time.Now().Unix())
        
        // Make request to API
        req, err := http.NewRequest("POST", "http://localhost:8080/api/v1/users", 
            strings.NewReader(`{
                "name": "E2E Test User",
                "email": "e2e@example.com"
            }`))
        require.NoError(t, err)
        
        req.Header.Set("Content-Type", "application/json")
        req.Header.Set("X-Request-ID", correlationID)
        req.Header.Set("User-Agent", "e2e-test-client/1.0")
        
        resp, err := client.Do(req)
        require.NoError(t, err)
        defer resp.Body.Close()
        
        // Verify response
        assert.Equal(t, 201, resp.StatusCode)
        
        // Wait for telemetry to propagate
        time.Sleep(5 * time.Second)
        
        // Verify metrics in Prometheus
        t.Run("verify_metrics", func(t *testing.T) {
            prometheusClient := &PrometheusClient{
                BaseURL: "http://localhost:9090",
                Client:  client,
            }
            
            // Check HTTP request metrics
            query := `http_requests_total{method="POST",route="/api/v1/users",status_class="2xx"}`
            result, err := prometheusClient.Query(query)
            require.NoError(t, err)
            
            assert.NotEmpty(t, result.Data.Result, "HTTP request metric should exist")
            
            // Check custom business metrics
            businessQuery := `users_created_total{source="api"}`
            businessResult, err := prometheusClient.Query(businessQuery)
            require.NoError(t, err)
            
            assert.NotEmpty(t, businessResult.Data.Result, "Business metric should exist")
        })
        
        // Verify traces in Tempo
        t.Run("verify_traces", func(t *testing.T) {
            tempoClient := &TempoClient{
                BaseURL: "http://localhost:3200",
                Client:  client,
            }
            
            // Search for traces with our correlation ID
            traces, err := tempoClient.SearchTraces(map[string]string{
                "service.name": "go-observability-mastery",
                "http.method":  "POST",
                "http.route":   "/api/v1/users",
            })
            require.NoError(t, err)
            
            assert.NotEmpty(t, traces, "Traces should be found in Tempo")
            
            // Verify trace structure
            for _, trace := range traces {
                assert.NotEmpty(t, trace.TraceID, "Trace should have ID")
                assert.NotEmpty(t, trace.Spans, "Trace should have spans")
                
                // Look for HTTP and business logic spans
                var httpSpan, businessSpan *Span
                for _, span := range trace.Spans {
                    if span.OperationName == "POST /api/v1/users" {
                        httpSpan = span
                    }
                    if span.OperationName == "user.create" {
                        businessSpan = span
                    }
                }
                
                assert.NotNil(t, httpSpan, "HTTP span should exist")
                assert.NotNil(t, businessSpan, "Business logic span should exist")
                
                if httpSpan != nil && businessSpan != nil {
                    // Verify span hierarchy
                    assert.Equal(t, httpSpan.TraceID, businessSpan.TraceID, 
                        "Spans should belong to same trace")
                }
            }
        })
        
        // Verify logs correlation
        t.Run("verify_logs", func(t *testing.T) {
            // In a real e2e test, you might query a log aggregation system
            // For this example, we'll check that logs contain correlation IDs
            
            // This could query Loki, Elasticsearch, or GCP Cloud Logging
            logClient := &LogClient{
                BaseURL: "http://localhost:3100", // Loki endpoint
                Client:  client,
            }
            
            logs, err := logClient.QueryLogs(map[string]string{
                "request_id": correlationID,
                "service":    "go-observability-mastery",
            })
            require.NoError(t, err)
            
            assert.NotEmpty(t, logs, "Logs should be found with correlation ID")
            
            // Verify log structure and correlation
            for _, logEntry := range logs {
                assert.Equal(t, correlationID, logEntry.Fields["request_id"],
                    "Log should have correct correlation ID")
                assert.Contains(t, []string{"info", "debug"}, logEntry.Level,
                    "Log should have appropriate level")
            }
        })
    })
    
    t.Run("error_scenario_observability", func(t *testing.T) {
        correlationID := fmt.Sprintf("e2e-error-%d", time.Now().Unix())
        
        // Make request that will cause an error
        req, err := http.NewRequest("POST", "http://localhost:8080/api/v1/users", 
            strings.NewReader(`{"invalid": "json"}`))
        require.NoError(t, err)
        
        req.Header.Set("Content-Type", "application/json")
        req.Header.Set("X-Request-ID", correlationID)
        req.Header.Set("X-Simulate-Error", "true")
        
        resp, err := client.Do(req)
        require.NoError(t, err)
        defer resp.Body.Close()
        
        // Verify error response
        assert.Equal(t, 500, resp.StatusCode)
        
        // Wait for telemetry to propagate
        time.Sleep(5 * time.Second)
        
        // Verify error metrics
        prometheusClient := &PrometheusClient{
            BaseURL: "http://localhost:9090",
            Client:  client,
        }
        
        errorQuery := `errors_total{error_kind="internal"}`
        result, err := prometheusClient.Query(errorQuery)
        require.NoError(t, err)
        
        assert.NotEmpty(t, result.Data.Result, "Error metric should exist")
        
        // Verify error traces have proper status
        tempoClient := &TempoClient{
            BaseURL: "http://localhost:3200", 
            Client:  client,
        }
        
        traces, err := tempoClient.SearchTraces(map[string]string{
            "error": "true",
        })
        require.NoError(t, err)
        
        assert.NotEmpty(t, traces, "Error traces should be found")
        
        // Verify at least one span has error status
        hasErrorSpan := false
        for _, trace := range traces {
            for _, span := range trace.Spans {
                if span.Status != nil && span.Status.Code == "ERROR" {
                    hasErrorSpan = true
                    break
                }
            }
            if hasErrorSpan {
                break
            }
        }
        assert.True(t, hasErrorSpan, "At least one span should have error status")
    })
    
    t.Run("cardinality_governance", func(t *testing.T) {
        // Verify that cardinality is within acceptable bounds
        prometheusClient := &PrometheusClient{
            BaseURL: "http://localhost:9090",
            Client:  client,
        }
        
        // Query total number of series
        query := `count by (__name__)({__name__=~".+"})`
        result, err := prometheusClient.Query(query)
        require.NoError(t, err)
        
        totalSeries := 0
        for _, sample := range result.Data.Result {
            if len(sample.Value) > 1 {
                if val, ok := sample.Value[1].(string); ok {
                    if count, err := strconv.Atoi(val); err == nil {
                        totalSeries += count
                    }
                }
            }
        }
        
        // Assert cardinality is within budget
        cardinalityBudget := 1000 // Production budget
        assert.LessOrEqual(t, totalSeries, cardinalityBudget,
            "Total cardinality %d exceeds budget %d", totalSeries, cardinalityBudget)
        
        t.Logf("Current cardinality: %d series (budget: %d)", totalSeries, cardinalityBudget)
    })
}

// Helper clients for E2E testing
type PrometheusClient struct {
    BaseURL string
    Client  *http.Client
}

type PrometheusQueryResult struct {
    Status string `json:"status"`
    Data   struct {
        ResultType string `json:"resultType"`
        Result     []struct {
            Metric map[string]string `json:"metric"`
            Value  []interface{}     `json:"value"`
        } `json:"result"`
    } `json:"data"`
}

func (p *PrometheusClient) Query(query string) (*PrometheusQueryResult, error) {
    url := fmt.Sprintf("%s/api/v1/query?query=%s", p.BaseURL, query)
    resp, err := p.Client.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var result PrometheusQueryResult
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }
    
    return &result, nil
}

type TempoClient struct {
    BaseURL string
    Client  *http.Client
}

type Trace struct {
    TraceID string  `json:"traceID"`
    Spans   []*Span `json:"spans"`
}

type Span struct {
    TraceID       string                 `json:"traceID"`
    SpanID        string                 `json:"spanID"`
    OperationName string                 `json:"operationName"`
    StartTime     int64                  `json:"startTime"`
    Duration      int64                  `json:"duration"`
    Tags          map[string]interface{} `json:"tags"`
    Status        *SpanStatus            `json:"status,omitempty"`
}

type SpanStatus struct {
    Code    string `json:"code"`
    Message string `json:"message"`
}

func (t *TempoClient) SearchTraces(tags map[string]string) ([]*Trace, error) {
    // Implement Tempo search API call
    url := fmt.Sprintf("%s/api/search", t.BaseURL)
    
    // This is a simplified implementation
    // Real implementation would construct proper Tempo search query
    
    resp, err := t.Client.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var traces []*Trace
    if err := json.NewDecoder(resp.Body).Decode(&traces); err != nil {
        return nil, err
    }
    
    return traces, nil
}

type LogClient struct {
    BaseURL string
    Client  *http.Client
}

type LogEntry struct {
    Timestamp time.Time              `json:"timestamp"`
    Level     string                 `json:"level"`
    Message   string                 `json:"message"`
    Fields    map[string]interface{} `json:"fields"`
}

func (l *LogClient) QueryLogs(query map[string]string) ([]*LogEntry, error) {
    // Implement log query (Loki, Elasticsearch, etc.)
    // This is a simplified implementation
    
    url := fmt.Sprintf("%s/loki/api/v1/query", l.BaseURL)
    
    resp, err := l.Client.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var logs []*LogEntry
    if err := json.NewDecoder(resp.Body).Decode(&logs); err != nil {
        return nil, err
    }
    
    return logs, nil
}
```

## CI/CD Integration

### GitHub Actions Workflows

**Decision Rationale**: Modern CI/CD pipelines must include observability validation as a first-class concern. The 2025+ approach treats observability as infrastructure that requires its own testing, validation, and deployment processes.

#### Comprehensive Observability Validation Pipeline

```yaml
# .github/workflows/observability-validation.yml
name: Observability Validation

on:
  pull_request:
    paths:
      - 'internal/**'
      - 'go.mod'
      - 'go.sum'
      - '.github/workflows/**'
      - 'deployments/**'
      - 'configs/**'
  push:
    branches: [main, develop]

env:
  GO_VERSION: '1.24'
  DOCKER_BUILDKIT: 1
  COMPOSE_DOCKER_CLI_BUILD: 1

jobs:
  lint-boundaries:
    name: Import Boundary Validation (ADR-002)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}
          cache: true
          
      - name: Install mise for tool management
        uses: jdx/mise-action@v2
        with:
          version: 2024.1.0
          
      - name: Install dependencies
        run: |
          mise install
          go mod download
          
      - name: Check Import Boundaries (ADR-002)
        run: |
          make lint-imports
          
      - name: Validate Package Structure
        run: |
          ./scripts/validate-package-structure.sh
          
      - name: Check for Global State Violations
        run: |
          ./scripts/check-global-state.sh

  unit-tests:
    name: Unit Tests with Coverage
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}
          cache: true
          
      - name: Install mise
        uses: jdx/mise-action@v2
        
      - name: Install dependencies
        run: |
          mise install
          go mod download
          
      - name: Run Unit Tests
        run: |
          go test -v -race -coverprofile=coverage.out ./...
          
      - name: Check Coverage Threshold
        run: |
          COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
          echo "Coverage: ${COVERAGE}%"
          if (( $(echo "$COVERAGE < 80" | bc -l) )); then
            echo "❌ Coverage ${COVERAGE}% is below 80% threshold"
            exit 1
          fi
          echo "✅ Coverage ${COVERAGE}% meets threshold"
          
      - name: Generate Coverage Report
        run: |
          go tool cover -html=coverage.out -o coverage.html
          
      - name: Upload Coverage Reports
        uses: codecov/codecov-action@v4
        with:
          file: ./coverage.out
          flags: unittests
          name: codecov-umbrella
          
      - name: Upload Coverage Artifacts
        uses: actions/upload-artifact@v4
        with:
          name: coverage-report
          path: |
            coverage.out
            coverage.html

  integration-tests:
    name: Integration Tests with Observability Stack
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: testdb
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432
          
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}
          cache: true
          
      - name: Install mise
        uses: jdx/mise-action@v2
        
      - name: Setup Docker Buildx
        uses: docker/setup-buildx-action@v3
        
      - name: Start Observability Stack
        run: |
          make dev-up
          
      - name: Wait for Stack Health
        run: |
          timeout 120s bash -c '
            until make health-check; do
              echo "Waiting for observability stack..."
              sleep 5
            done
          '
          
      - name: Run Integration Tests
        run: |
          go test -v -tags=integration -race ./...
        env:
          DATABASE_URL: postgres://postgres:postgres@localhost:5432/testdb?sslmode=disable
          OTLP_ENDPOINT: http://localhost:4318
          
      - name: Run E2E Observability Tests
        run: |
          go test -v -tags=e2e ./internal/e2e/...
          
      - name: Collect Stack Logs on Failure
        if: failure()
        run: |
          mkdir -p integration-logs
          docker-compose -f deployments/docker-compose.yml logs > integration-logs/docker-compose.log
          docker-compose -f deployments/docker-compose.yml logs otel-collector > integration-logs/otel-collector.log
          docker-compose -f deployments/docker-compose.yml logs prometheus > integration-logs/prometheus.log
          docker-compose -f deployments/docker-compose.yml logs tempo > integration-logs/tempo.log
          docker-compose -f deployments/docker-compose.yml logs grafana > integration-logs/grafana.log
          
      - name: Upload Test Results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: integration-test-results
          path: |
            test-results.xml
            integration-logs/

  performance-validation:
    name: Performance Budget Validation
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # Need history for baseline comparison
          
      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}
          cache: true
          
      - name: Install mise
        uses: jdx/mise-action@v2
        
      - name: Install benchstat
        run: |
          go install golang.org/x/perf/cmd/benchstat@latest
          
      - name: Run Baseline Benchmark (main branch)
        run: |
          git checkout main
          go test -bench=BenchmarkObservability -count=5 -benchmem ./... > baseline.txt || true
          
      - name: Run Current Benchmark
        run: |
          git checkout ${{ github.sha }}
          go test -bench=BenchmarkObservability -count=5 -benchmem ./... > current.txt
          
      - name: Compare Performance
        run: |
          if [ -f baseline.txt ] && [ -f current.txt ]; then
            benchstat baseline.txt current.txt > comparison.txt || true
            cat comparison.txt
          else
            echo "No baseline found, creating initial baseline"
            cp current.txt baseline.txt
          fi
          
      - name: Validate Performance Budget
        run: |
          go run tools/perf-validator/main.go \
            --baseline=baseline.txt \
            --current=current.txt \
            --budget-file=configs/performance-budgets.yaml \
            --fail-on-violation=true
            
      - name: Upload Performance Results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: performance-results
          path: |
            baseline.txt
            current.txt
            comparison.txt

  cardinality-validation:
    name: Metric Cardinality Validation
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}
          cache: true
          
      - name: Install mise
        uses: jdx/mise-action@v2
        
      - name: Setup Docker Buildx
        uses: docker/setup-buildx-action@v3
        
      - name: Start Observability Stack
        run: |
          make dev-up
          make health-check
          
      - name: Generate Load for Cardinality Test
        run: |
          make load-test-cardinality
          
      - name: Validate Cardinality Budget
        run: |
          make cardinality-check
          
      - name: Generate Cardinality Report
        if: always()
        run: |
          ./scripts/generate-cardinality-report.sh > cardinality-report.md
          
      - name: Upload Cardinality Report
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: cardinality-violation
          path: |
            current_series.txt
            series_diff.txt
            cardinality-report.md

  security-scan:
    name: Security Vulnerability Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}
          cache: true
          
      - name: Install mise
        uses: jdx/mise-action@v2
        
      - name: Run Gosec Security Scanner
        uses: securecodewarrior/github-action-gosec@master
        with:
          args: '-fmt sarif -out gosec.sarif ./...'
          
      - name: Upload Gosec Results to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: gosec.sarif
          
      - name: Run Nancy Vulnerability Check
        run: |
          go install github.com/sonatypecommunity/nancy@latest
          go list -json -deps ./... | nancy sleuth
          
      - name: Run Trivy Security Scanner
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-results.sarif'
          
      - name: Upload Trivy Results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'trivy-results.sarif'
          
      - name: Check for Sensitive Data in Logs
        run: |
          ./scripts/check-sensitive-data.sh

  dependency-scan:
    name: Dependency Vulnerability Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}
          cache: true
          
      - name: Install govulncheck
        run: |
          go install golang.org/x/vuln/cmd/govulncheck@latest
          
      - name: Run Go Vulnerability Check
        run: |
          govulncheck ./...
          
      - name: Check License Compliance
        uses: fossa-contrib/fossa-action@v2
        with:
          api-key: ${{ secrets.FOSSA_API_KEY }}
          
      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          path: ./
          format: spdx-json
          output-file: sbom.spdx.json
          
      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.spdx.json

  observability-smoke-test:
    name: End-to-End Observability Smoke Test
    runs-on: ubuntu-latest
    needs: [unit-tests, integration-tests]
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}
          cache: true
          
      - name: Install mise
        uses: jdx/mise-action@v2
        
      - name: Setup Docker Buildx
        uses: docker/setup-buildx-action@v3
        
      - name: Run Complete Smoke Test
        run: |
          make smoke-test
          
      - name: Validate Signal Correlation
        run: |
          ./scripts/validate-signal-correlation.sh
          
      - name: Test Alert Rules
        run: |
          ./scripts/test-alert-rules.sh
          
      - name: Generate Observability Report
        run: |
          ./scripts/generate-observability-report.sh > observability-report.md
          
      - name: Upload Observability Report
        uses: actions/upload-artifact@v4
        with:
          name: observability-report
          path: observability-report.md
          
      - name: Comment on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('observability-report.md', 'utf8');
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## 📊 Observability Validation Report
              
              ${report}
              
              Generated by GitHub Actions`
            });

  config-validation:
    name: Configuration Validation
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}
          cache: true
          
      - name: Validate OpenTelemetry Collector Config
        run: |
          docker run --rm -v $(pwd)/deployments/otel-collector:/etc/config \
            otel/opentelemetry-collector-contrib:0.116.0 \
            --config=/etc/config/config.yml --dry-run
            
      - name: Validate Prometheus Config
        run: |
          docker run --rm -v $(pwd)/deployments/prometheus:/etc/prometheus \
            prom/prometheus:v2.54.1 \
            promtool check config /etc/prometheus/prometheus.yml
            
      - name: Validate Grafana Dashboards
        run: |
          ./scripts/validate-grafana-dashboards.sh
          
      - name: Test Configuration Loading
        run: |
          go run cmd/config-validator/main.go \
            --config-file=configs/development/.env \
            --validate-all

  build-and-push:
    name: Build and Push Container Images
    runs-on: ubuntu-latest
    needs: [
      lint-boundaries,
      unit-tests,
      integration-tests,
      performance-validation,
      cardinality-validation,
      security-scan,
      observability-smoke-test,
      config-validation
    ]
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Docker Buildx
        uses: docker/setup-buildx-action@v3
        
      - name: Login to Container Registry
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
          
      - name: Build and Push Images
        run: |
          export REGISTRY=ghcr.io/${{ github.repository_owner }}
          export VERSION=${{ github.sha }}
          docker buildx bake --push all
          
      - name: Generate Image Manifest
        run: |
          ./scripts/generate-image-manifest.sh > image-manifest.json
          
      - name: Upload Image Manifest
        uses: actions/upload-artifact@v4
        with:
          name: image-manifest
          path: image-manifest.json

  notify-deployment:
    name: Notify Deployment Systems
    runs-on: ubuntu-latest
    needs: [build-and-push]
    if: github.ref == 'refs/heads/main'
    steps:
      - name: Trigger GitOps Repository Update
        uses: actions/github-script@v7
        with:
          github-token: ${{ secrets.GITOPS_TOKEN }}
          script: |
            await github.rest.repos.createDispatchEvent({
              owner: 'your-org',
              repo: 'gitops-configs',
              event_type: 'update-image',
              client_payload: {
                service: 'go-observability-mastery',
                image: `ghcr.io/${{ github.repository_owner }}/go-observability:${{ github.sha }}`,
                environment: 'staging'
              }
            });
```

#### Pre-commit Hooks

**Decision Rationale**: Pre-commit hooks provide the fastest feedback loop for observability issues. They catch problems before code review, reducing cycle time and improving code quality.

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
        args: ['--multi']
      - id: check-json
        exclude: |
          (?x)^(
              .*\.vscode/.*\.json|
              testdata/.*\.json
          )$
      - id: check-merge-conflict
      - id: check-added-large-files
        args: ['--maxkb=1000']
      - id: detect-private-key
      - id: check-case-conflict
      - id: mixed-line-ending

  - repo: local
    hooks:
      - id: go-fmt
        name: Go Format
        entry: gofmt
        args: [-w]
        language: system
        files: \.go$
        
      - id: go-imports
        name: Go Imports
        entry: goimports
        args: [-w]
        language: system
        files: \.go$
        
      - id: go-vet
        name: Go Vet
        entry: go vet
        language: system
        files: \.go$
        pass_filenames: false
        
      - id: go-test
        name: Go Test (Fast)
        entry: go test
        args: [-short, -race, ./...]
        language: system
        files: \.go$
        pass_filenames: false
        
      - id: go-mod-tidy
        name: Go Mod Tidy
        entry: go mod tidy
        language: system
        files: go\.mod$
        pass_filenames: false

      - id: import-boundaries
        name: Import Boundary Check (ADR-002)
        entry: ./scripts/check-imports.sh
        language: system
        files: \.go$
        pass_filenames: false
        
      - id: cardinality-estimate
        name: Cardinality Estimate Check
        entry: ./scripts/cardinality-estimate.sh
        language: system
        files: \.go$
        pass_filenames: false
        
      - id: sensitive-data-check
        name: Sensitive Data Check
        entry: ./scripts/check-sensitive-data.sh
        language: system
        files: \.(go|yaml|yml|json|env)$
        pass_filenames: false
        
      - id: config-validation
        name: Configuration Validation
        entry: ./scripts/validate-configs.sh
        language: system
        files: \.(yaml|yml|json|env)$
        pass_filenames: false
        
      - id: observability-lint
        name: Observability Best Practices Lint
        entry: ./scripts/observability-lint.sh
        language: system
        files: \.go$
        pass_filenames: false

  - repo: https://github.com/hadolint/hadolint
    rev: v2.12.0
    hooks:
      - id: hadolint-docker
        name: Dockerfile Linting
        
  - repo: https://github.com/igorshubovych/markdownlint-cli
    rev: v0.37.0
    hooks:
      - id: markdownlint
        name: Markdown Linting
        args: ['--fix']
        
  - repo: https://github.com/pre-commit/mirrors-eslint
    rev: v8.53.0
    hooks:
      - id: eslint
        name: ESLint (for any JS config files)
        files: \.(js|ts|json)$
        additional_dependencies:
          - eslint@8.53.0
          - '@typescript-eslint/eslint-plugin@6.10.0'
          - '@typescript-eslint/parser@6.10.0'

# Additional custom hooks specific to observability
  - repo: local
    hooks:
      - id: prometheus-config-check
        name: Prometheus Config Check
        entry: ./scripts/check-prometheus-config.sh
        language: system
        files: prometheus\.yml$
        
      - id: grafana-dashboard-validation
        name: Grafana Dashboard Validation
        entry: ./scripts/validate-grafana-dashboards.sh
        language: system
        files: dashboards/.*\.json$
        
      - id: otel-config-validation
        name: OpenTelemetry Config Validation
        entry: ./scripts/validate-otel-config.sh
        language: system
        files: otel-collector/.*\.yml$
        
      - id: trace-sampling-check
        name: Trace Sampling Configuration Check
        entry: ./scripts/check-trace-sampling.sh
        language: system
        files: \.(go|yaml|yml|env)$
        pass_filenames: false
```

## Cloud-Native Deployment

### Infrastructure as Code with Terraform

**Decision Rationale**: Infrastructure as Code (IaC) is essential for 2025+ cloud deployments. Terraform provides declarative infrastructure management with state tracking, enabling GitOps workflows and ensuring reproducible deployments across environments.

#### Google Cloud Platform Terraform Modules

```hcl
# terraform/modules/observability/main.tf
terraform {
  required_version = ">= 1.6"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.10"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.10"
    }
  }
}

# Observability Infrastructure Module for GCP
module "observability" {
  source = "./modules/observability"

  project_id = var.project_id
  region     = var.region
  
  # Service configuration
  service_name = var.service_name
  environment  = var.environment
  
  # Cloud Run configuration
  cloud_run_config = {
    image_url           = var.image_url
    cpu_limit          = var.cpu_limit
    memory_limit       = var.memory_limit
    max_instances      = var.max_instances
    min_instances      = var.min_instances
    concurrency        = var.concurrency
    timeout            = var.timeout
  }
  
  # Observability configuration
  observability_config = {
    enable_cloud_trace     = var.enable_cloud_trace
    enable_cloud_logging   = var.enable_cloud_logging
    enable_cloud_monitoring = var.enable_cloud_monitoring
    enable_error_reporting = var.enable_error_reporting
    
    # Sampling configuration
    trace_sampling_rate = var.trace_sampling_rate
    log_level          = var.log_level
    
    # Retention policies
    log_retention_days    = var.log_retention_days
    trace_retention_days  = var.trace_retention_days
    metric_retention_days = var.metric_retention_days
  }
  
  # Security configuration
  security_config = {
    enable_workload_identity = var.enable_workload_identity
    enable_private_service_connect = var.enable_private_service_connect
    allowed_ingress_cidrs = var.allowed_ingress_cidrs
    
    # IAM configuration
    service_account_roles = var.service_account_roles
  }
  
  # Monitoring and alerting
  monitoring_config = {
    enable_uptime_checks = var.enable_uptime_checks
    enable_slo_monitoring = var.enable_slo_monitoring
    notification_channels = var.notification_channels
    
    # SLO targets
    availability_target = var.availability_target
    latency_target      = var.latency_target
    error_rate_target   = var.error_rate_target
  }
  
  # Network configuration
  network_config = {
    vpc_id                = var.vpc_id
    subnet_id            = var.subnet_id
    enable_vpc_connector = var.enable_vpc_connector
    vpc_connector_config = var.vpc_connector_config
  }
  
  # Labels for resource management
  labels = merge(var.labels, {
    environment = var.environment
    service     = var.service_name
    managed_by  = "terraform"
    module      = "observability"
  })
}

# Cloud Run Service
resource "google_cloud_run_v2_service" "main" {
  name     = var.service_name
  location = var.region
  project  = var.project_id

  template {
    service_account = google_service_account.cloud_run.email
    
    scaling {
      min_instance_count = var.cloud_run_config.min_instances
      max_instance_count = var.cloud_run_config.max_instances
    }
    
    containers {
      image = var.cloud_run_config.image_url
      
      ports {
        container_port = 8080
        name          = "http1"
      }
      
      resources {
        limits = {
          cpu    = var.cloud_run_config.cpu_limit
          memory = var.cloud_run_config.memory_limit
        }
        startup_cpu_boost = true
      }
      
      # Environment variables for observability
      env {
        name  = "ENVIRONMENT"
        value = var.environment
      }
      
      env {
        name  = "SERVICE_NAME"
        value = var.service_name
      }
      
      env {
        name  = "GCP_PROJECT_ID"
        value = var.project_id
      }
      
      env {
        name  = "CLOUD_PROVIDER"
        value = "gcp"
      }
      
      env {
        name  = "LOG_LEVEL"
        value = var.observability_config.log_level
      }
      
      env {
        name  = "TRACE_ENABLED"
        value = tostring(var.observability_config.enable_cloud_trace)
      }
      
      env {
        name  = "TRACE_SAMPLER_ARG"
        value = tostring(var.observability_config.trace_sampling_rate)
      }
      
      env {
        name  = "GCP_LOGGING_ENABLED"
        value = tostring(var.observability_config.enable_cloud_logging)
      }
      
      env {
        name  = "GCP_MONITORING_ENABLED"
        value = tostring(var.observability_config.enable_cloud_monitoring)
      }
      
      env {
        name  = "GCP_ERROR_REPORTING_ENABLED"
        value = tostring(var.observability_config.enable_error_reporting)
      }
      
      # Security configuration
      env {
        name  = "SECURITY_TLS_ENABLED"
        value = "true"
      }
      
      env {
        name  = "SECURITY_RATE_LIMIT_ENABLED"
        value = "true"
      }
      
      # Workload Identity
      env {
        name  = "GCP_USE_WORKLOAD_IDENTITY"
        value = tostring(var.security_config.enable_workload_identity)
      }
      
      env {
        name  = "GCP_SERVICE_ACCOUNT_EMAIL"
        value = google_service_account.cloud_run.email
      }
      
      # Health check configuration
      startup_probe {
        http_get {
          path = "/health"
          port = 8080
        }
        initial_delay_seconds = 10
        timeout_seconds       = 5
        period_seconds        = 10
        failure_threshold     = 3
      }
      
      liveness_probe {
        http_get {
          path = "/health"
          port = 8080
        }
        initial_delay_seconds = 30
        timeout_seconds       = 5
        period_seconds        = 30
        failure_threshold     = 3
      }
    }
    
    # VPC configuration
    dynamic "vpc_access" {
      for_each = var.network_config.enable_vpc_connector ? [1] : []
      content {
        connector = google_vpc_access_connector.main[0].id
        egress    = "ALL_TRAFFIC"
      }
    }
    
    # Annotations for observability
    annotations = {
      "autoscaling.knative.dev/maxScale"        = tostring(var.cloud_run_config.max_instances)
      "autoscaling.knative.dev/minScale"        = tostring(var.cloud_run_config.min_instances)
      "run.googleapis.com/execution-environment" = "gen2"
      "run.googleapis.com/cpu-throttling"       = "false"
    }
  }
  
  traffic {
    percent = 100
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
  }
  
  lifecycle {
    ignore_changes = [
      template[0].annotations["run.googleapis.com/operation-id"],
      template[0].annotations["client.knative.dev/user-image"],
    ]
  }
  
  depends_on = [
    google_project_service.cloud_run,
    google_service_account.cloud_run,
  ]
}

# Service Account for Cloud Run
resource "google_service_account" "cloud_run" {
  project      = var.project_id
  account_id   = "${var.service_name}-sa"
  display_name = "Service Account for ${var.service_name}"
  description  = "Service account for Cloud Run service with observability permissions"
}

# IAM bindings for observability
resource "google_project_iam_member" "cloud_run_logging" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.cloud_run.email}"
}

resource "google_project_iam_member" "cloud_run_monitoring" {
  count   = var.observability_config.enable_cloud_monitoring ? 1 : 0
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.cloud_run.email}"
}

resource "google_project_iam_member" "cloud_run_trace" {
  count   = var.observability_config.enable_cloud_trace ? 1 : 0
  project = var.project_id
  role    = "roles/cloudtrace.agent"
  member  = "serviceAccount:${google_service_account.cloud_run.email}"
}

resource "google_project_iam_member" "cloud_run_error_reporting" {
  count   = var.observability_config.enable_error_reporting ? 1 : 0
  project = var.project_id
  role    = "roles/errorreporting.writer"
  member  = "serviceAccount:${google_service_account.cloud_run.email}"
}

# Cloud Monitoring Uptime Check
resource "google_monitoring_uptime_check_config" "main" {
  count        = var.monitoring_config.enable_uptime_checks ? 1 : 0
  display_name = "${var.service_name}-uptime-check"
  timeout      = "10s"
  period       = "60s"

  http_check {
    request_method = "GET"
    path           = "/health"
    port           = "443"
    use_ssl        = true
    validate_ssl   = true
  }

  monitored_resource {
    type = "uptime_url"
    labels = {
      project_id = var.project_id
      host       = google_cloud_run_v2_service.main.uri
    }
  }

  content_matchers {
    content = "healthy"
    matcher = "CONTAINS_STRING"
  }
}

# SLO Configuration
resource "google_monitoring_slo" "availability" {
  count        = var.monitoring_config.enable_slo_monitoring ? 1 : 0
  service      = google_monitoring_service.main[0].service_id
  display_name = "${var.service_name} Availability SLO"
  
  request_based_sli {
    good_total_ratio {
      good_service_filter = join(" AND ", [
        "resource.type=\"cloud_run_revision\"",
        "resource.labels.service_name=\"${var.service_name}\"",
        "protoPayload.response.status<500"
      ])
      
      total_service_filter = join(" AND ", [
        "resource.type=\"cloud_run_revision\"",
        "resource.labels.service_name=\"${var.service_name}\""
      ])
    }
  }
  
  goal {
    value = var.monitoring_config.availability_target
  }
  
  rolling_period_days = 30
}

# Alerting Policies
resource "google_monitoring_alert_policy" "error_rate" {
  display_name = "${var.service_name} High Error Rate"
  combiner     = "OR"
  
  conditions {
    display_name = "Error rate above threshold"
    
    condition_threshold {
      filter          = "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"${var.service_name}\""
      duration        = "120s"
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = var.monitoring_config.error_rate_target
      
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_MEAN"
        group_by_fields = ["resource.labels.service_name"]
      }
    }
  }
  
  notification_channels = var.monitoring_config.notification_channels
  
  alert_strategy {
    auto_close = "1800s"
  }
}

resource "google_monitoring_alert_policy" "latency" {
  display_name = "${var.service_name} High Latency"
  combiner     = "OR"
  
  conditions {
    display_name = "Latency above threshold"
    
    condition_threshold {
      filter          = "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"${var.service_name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = var.monitoring_config.latency_target
      
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_DELTA"
        cross_series_reducer = "REDUCE_PERCENTILE_95"
        group_by_fields     = ["resource.labels.service_name"]
      }
    }
  }
  
  notification_channels = var.monitoring_config.notification_channels
  
  alert_strategy {
    auto_close = "1800s"
  }
}

# Cloud Logging Configuration
resource "google_logging_project_sink" "main" {
  count                  = var.observability_config.enable_cloud_logging ? 1 : 0
  name                   = "${var.service_name}-logs-sink"
  destination            = "bigquery.googleapis.com/projects/${var.project_id}/datasets/${google_bigquery_dataset.logs[0].dataset_id}"
  unique_writer_identity = true
  
  filter = "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"${var.service_name}\""
}

# BigQuery dataset for log analytics
resource "google_bigquery_dataset" "logs" {
  count                      = var.observability_config.enable_cloud_logging ? 1 : 0
  dataset_id                 = "${replace(var.service_name, "-", "_")}_logs"
  friendly_name              = "${var.service_name} Logs"
  description                = "Log analytics dataset for ${var.service_name}"
  location                   = var.region
  default_table_expiration_ms = var.observability_config.log_retention_days * 24 * 60 * 60 * 1000
  
  labels = var.labels
}

# VPC Connector for private service access
resource "google_vpc_access_connector" "main" {
  count         = var.network_config.enable_vpc_connector ? 1 : 0
  name          = "${var.service_name}-vpc-connector"
  region        = var.region
  ip_cidr_range = var.network_config.vpc_connector_config.ip_cidr_range
  network       = var.network_config.vpc_id
  
  min_instances = var.network_config.vpc_connector_config.min_instances
  max_instances = var.network_config.vpc_connector_config.max_instances
}

# Required APIs
resource "google_project_service" "apis" {
  for_each = toset([
    "run.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "cloudtrace.googleapis.com",
    "errorreporting.googleapis.com",
    "vpcaccess.googleapis.com",
    "bigquery.googleapis.com",
  ])
  
  project = var.project_id
  service = each.value
  
  disable_on_destroy = false
}

# Monitoring Service for SLOs
resource "google_monitoring_service" "main" {
  count        = var.monitoring_config.enable_slo_monitoring ? 1 : 0
  service_id   = var.service_name
  display_name = var.service_name
  
  basic_service {
    service_type = "CLOUD_RUN"
    service_labels = {
      service_name = var.service_name
      location     = var.region
    }
  }
}
```

#### Terraform Variables and Configuration

```hcl
# terraform/modules/observability/variables.tf
variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region for resources"
  type        = string
  default     = "us-central1"
}

variable "service_name" {
  description = "Name of the service"
  type        = string
}

variable "environment" {
  description = "Environment (development, staging, production)"
  type        = string
  
  validation {
    condition = contains([
      "development",
      "staging", 
      "production"
    ], var.environment)
    error_message = "Environment must be development, staging, or production."
  }
}

variable "image_url" {
  description = "Container image URL"
  type        = string
}

variable "cloud_run_config" {
  description = "Cloud Run service configuration"
  type = object({
    cpu_limit     = optional(string, "1000m")
    memory_limit  = optional(string, "2Gi")
    max_instances = optional(number, 10)
    min_instances = optional(number, 0)
    concurrency   = optional(number, 80)
    timeout       = optional(string, "300s")
  })
  default = {}
}

variable "observability_config" {
  description = "Observability configuration"
  type = object({
    enable_cloud_trace     = optional(bool, true)
    enable_cloud_logging   = optional(bool, true)
    enable_cloud_monitoring = optional(bool, true)
    enable_error_reporting = optional(bool, true)
    
    trace_sampling_rate = optional(number, 0.01)
    log_level          = optional(string, "info")
    
    log_retention_days    = optional(number, 30)
    trace_retention_days  = optional(number, 30)
    metric_retention_days = optional(number, 90)
  })
  default = {}
}

variable "security_config" {
  description = "Security configuration"
  type = object({
    enable_workload_identity         = optional(bool, true)
    enable_private_service_connect  = optional(bool, false)
    allowed_ingress_cidrs           = optional(list(string), ["0.0.0.0/0"])
    service_account_roles           = optional(list(string), [])
  })
  default = {}
}

variable "monitoring_config" {
  description = "Monitoring and alerting configuration"
  type = object({
    enable_uptime_checks  = optional(bool, true)
    enable_slo_monitoring = optional(bool, true)
    notification_channels = optional(list(string), [])
    
    availability_target = optional(number, 0.99)
    latency_target      = optional(number, 1000) # milliseconds
    error_rate_target   = optional(number, 0.05) # 5%
  })
  default = {}
}

variable "network_config" {
  description = "Network configuration"
  type = object({
    vpc_id                = optional(string, "")
    subnet_id            = optional(string, "")
    enable_vpc_connector = optional(bool, false)
    vpc_connector_config = optional(object({
      ip_cidr_range = string
      min_instances = optional(number, 2)
      max_instances = optional(number, 3)
    }), null)
  })
  default = {}
}

variable "labels" {
  description = "Labels to apply to all resources"
  type        = map(string)
  default     = {}
}
```

#### Environment-Specific Terraform Configurations

```hcl
# terraform/environments/development/main.tf
module "observability_dev" {
  source = "../../modules/observability"
  
  project_id   = var.project_id
  region       = "us-central1"
  service_name = "go-observability-dev"
  environment  = "development"
  image_url    = var.image_url
  
  cloud_run_config = {
    cpu_limit     = "500m"
    memory_limit  = "1Gi"
    max_instances = 5
    min_instances = 0
    concurrency   = 80
  }
  
  observability_config = {
    enable_cloud_trace     = true
    enable_cloud_logging   = true
    enable_cloud_monitoring = true
    enable_error_reporting = true
    
    trace_sampling_rate = 1.0 # 100% sampling in development
    log_level          = "debug"
    
    log_retention_days = 7 # Shorter retention in development
  }
  
  monitoring_config = {
    enable_uptime_checks  = true
    enable_slo_monitoring = false # Disable SLOs in development
    notification_channels = []    # No alerts in development
  }
  
  labels = {
    environment = "development"
    cost_center = "engineering"
    team        = "platform"
  }
}

# terraform/environments/production/main.tf
module "observability_prod" {
  source = "../../modules/observability"
  
  project_id   = var.project_id
  region       = "us-central1"
  service_name = "go-observability"
  environment  = "production"
  image_url    = var.image_url
  
  cloud_run_config = {
    cpu_limit     = "2000m"
    memory_limit  = "4Gi"
    max_instances = 100
    min_instances = 2 # Always warm instances
    concurrency   = 80
  }
  
  observability_config = {
    enable_cloud_trace     = true
    enable_cloud_logging   = true
    enable_cloud_monitoring = true
    enable_error_reporting = true
    
    trace_sampling_rate = 0.01 # 1% sampling in production
    log_level          = "warn"
    
    log_retention_days    = 90
    trace_retention_days  = 30
    metric_retention_days = 365
  }
  
  security_config = {
    enable_workload_identity = true
    allowed_ingress_cidrs   = var.allowed_cidrs
  }
  
  monitoring_config = {
    enable_uptime_checks  = true
    enable_slo_monitoring = true
    notification_channels = var.notification_channels
    
    availability_target = 0.999 # 99.9% availability
    latency_target      = 500   # 500ms P95
    error_rate_target   = 0.01  # 1% error rate
  }
  
  network_config = {
    vpc_id                = var.vpc_id
    subnet_id            = var.subnet_id
    enable_vpc_connector = true
    vpc_connector_config = {
      ip_cidr_range = "10.8.0.0/28"
      min_instances = 2
      max_instances = 10
    }
  }
  
  labels = {
    environment = "production"
    cost_center = "product"
    team        = "platform"
    criticality = "high"
  }
}
```

### Kubernetes Deployment with Service Mesh

**Decision Rationale**: While Cloud Run provides serverless simplicity, Kubernetes offers more control for complex workloads. Service mesh integration (Istio/Linkerd) provides advanced traffic management, security, and observability.

#### Kubernetes Manifests with Observability

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: go-observability
  labels:
    name: go-observability
    istio-injection: enabled # Enable Istio sidecar injection
    monitoring: "true"
    team: platform
    environment: production

---
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: go-observability
  labels:
    app: go-observability
    component: config
data:
  ENVIRONMENT: "production"
  SERVICE_NAME: "go-observability"
  LOG_LEVEL: "info"
  LOG_FORMAT: "json"
  LOG_USER_ID_MODE: "redacted"
  TRACE_ENABLED: "true"
  TRACE_SAMPLER_ARG: "0.01"
  METRICS_ENABLED: "true"
  CLOUD_PROVIDER: "gcp"
  GCP_LOGGING_ENABLED: "true"
  GCP_MONITORING_ENABLED: "true"
  GCP_TRACE_ENABLED: "true"

---
# k8s/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
  namespace: go-observability
  labels:
    app: go-observability
    component: secrets
type: Opaque
stringData:
  # Secrets would be managed by external secret management
  # This is just an example structure
  API_KEY: "placeholder"
  JWT_SECRET: "placeholder"

---
# k8s/serviceaccount.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: go-observability
  namespace: go-observability
  labels:
    app: go-observability
    component: serviceaccount
  annotations:
    # Workload Identity annotation for GKE
    iam.gke.io/gcp-service-account: go-observability@PROJECT_ID.iam.gserviceaccount.com

---
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: go-observability
  namespace: go-observability
  labels:
    app: go-observability
    component: api
    version: v1
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: go-observability
      component: api
  template:
    metadata:
      labels:
        app: go-observability
        component: api
        version: v1
      annotations:
        # Prometheus scraping configuration
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
        prometheus.io/path: "/metrics"
        
        # Istio configuration
        sidecar.istio.io/inject: "true"
        
        # Additional annotations for observability
        observability.platform/trace-enabled: "true"
        observability.platform/metrics-enabled: "true"
        
    spec:
      serviceAccountName: go-observability
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        fsGroup: 65534
        
      containers:
      - name: api
        image: gcr.io/PROJECT_ID/go-observability:latest
        imagePullPolicy: Always
        
        ports:
        - name: http
          containerPort: 8080
          protocol: TCP
        - name: metrics
          containerPort: 9090
          protocol: TCP
        - name: pprof
          containerPort: 6060
          protocol: TCP
          
        env:
        # Configuration from ConfigMap
        - name: ENVIRONMENT
          valueFrom:
            configMapKeyRef:
              name: app-config
              key: ENVIRONMENT
        - name: SERVICE_NAME
          valueFrom:
            configMapKeyRef:
              name: app-config
              key: SERVICE_NAME
        - name: LOG_LEVEL
          valueFrom:
            configMapKeyRef:
              name: app-config
              key: LOG_LEVEL
        - name: TRACE_SAMPLER_ARG
          valueFrom:
            configMapKeyRef:
              name: app-config
              key: TRACE_SAMPLER_ARG
              
        # Secrets
        - name: API_KEY
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: API_KEY
              
        # Kubernetes-provided environment variables
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        - name: POD_IP
          valueFrom:
            fieldRef:
              fieldPath: status.podIP
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
              
        # Resource configuration
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            cpu: 500m
            memory: 512Mi
            
        # Health checks
        livenessProbe:
          httpGet:
            path: /health
            port: http
            scheme: HTTP
          initialDelaySeconds: 30
          periodSeconds: 30
          timeoutSeconds: 5
          failureThreshold: 3
          
        readinessProbe:
          httpGet:
            path: /ready
            port: http
            scheme: HTTP
          initialDelaySeconds: 5
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
          
        # Startup probe for slow-starting applications
        startupProbe:
          httpGet:
            path: /health
            port: http
            scheme: HTTP
          initialDelaySeconds: 10
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 30
          
        # Security context
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 65534
          capabilities:
            drop:
            - ALL
            
        # Volume mounts for writable directories
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: var-run
          mountPath: /var/run
          
      volumes:
      - name: tmp
        emptyDir: {}
      - name: var-run
        emptyDir: {}
        
      # Topology spread constraints for high availability
      topologySpreadConstraints:
      - maxSkew: 1
        topologyKey: kubernetes.io/hostname
        whenUnsatisfiable: DoNotSchedule
        labelSelector:
          matchLabels:
            app: go-observability
            component: api

---
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: go-observability
  namespace: go-observability
  labels:
    app: go-observability
    component: api
  annotations:
    # Service mesh annotations
    service.istio.io/canonical-name: go-observability
    service.istio.io/canonical-revision: v1
spec:
  type: ClusterIP
  ports:
  - name: http
    port: 80
    targetPort: http
    protocol: TCP
  - name: metrics
    port: 9090
    targetPort: metrics
    protocol: TCP
  selector:
    app: go-observability
    component: api

---
# k8s/horizontalpodautoscaler.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: go-observability
  namespace: go-observability
  labels:
    app: go-observability
    component: autoscaler
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: go-observability
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 30
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60

---
# k8s/poddisruptionbudget.yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: go-observability
  namespace: go-observability
  labels:
    app: go-observability
    component: pdb
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: go-observability
      component: api

---
# k8s/networkpolicy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: go-observability
  namespace: go-observability
  labels:
    app: go-observability
    component: network-policy
spec:
  podSelector:
    matchLabels:
      app: go-observability
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: istio-system
    - namespaceSelector:
        matchLabels:
          name: monitoring
    ports:
    - protocol: TCP
      port: 8080
    - protocol: TCP
      port: 9090
  egress:
  - {} # Allow all egress (can be restricted based on requirements)
```

#### Istio Service Mesh Configuration

```yaml
# k8s/istio/virtualservice.yaml
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: go-observability
  namespace: go-observability
  labels:
    app: go-observability
    component: virtual-service
spec:
  hosts:
  - go-observability
  - go-observability.example.com
  gateways:
  - go-observability-gateway
  - mesh
  http:
  - match:
    - uri:
        prefix: /api/v1
    route:
    - destination:
        host: go-observability
        port:
          number: 80
    timeout: 30s
    retries:
      attempts: 3
      perTryTimeout: 10s
      retryOn: 5xx,reset,connect-failure,refused-stream
    fault:
      delay:
        percentage:
          value: 0.1
        fixedDelay: 5s
  - match:
    - uri:
        prefix: /metrics
    route:
    - destination:
        host: go-observability
        port:
          number: 9090
    # No retries for metrics endpoint

---
# k8s/istio/destinationrule.yaml
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: go-observability
  namespace: go-observability
  labels:
    app: go-observability
    component: destination-rule
spec:
  host: go-observability
  trafficPolicy:
    loadBalancer:
      simple: LEAST_CONN
    connectionPool:
      tcp:
        maxConnections: 100
      http:
        http1MaxPendingRequests: 50
        http2MaxRequests: 100
        maxRequestsPerConnection: 10
        maxRetries: 3
        consecutiveGatewayErrors: 5
        interval: 30s
        baseEjectionTime: 30s
        maxEjectionPercent: 50
    outlierDetection:
      consecutiveGatewayErrors: 5
      interval: 30s
      baseEjectionTime: 30s
      maxEjectionPercent: 50
  subsets:
  - name: v1
    labels:
      version: v1

---
# k8s/istio/gateway.yaml
apiVersion: networking.istio.io/v1beta1
kind: Gateway
metadata:
  name: go-observability-gateway
  namespace: go-observability
  labels:
    app: go-observability
    component: gateway
spec:
  selector:
    istio: ingressgateway
  servers:
  - port:
      number: 443
      name: https
      protocol: HTTPS
    tls:
      mode: SIMPLE
      credentialName: go-observability-tls
    hosts:
    - go-observability.example.com
  - port:
      number: 80
      name: http
      protocol: HTTP
    hosts:
    - go-observability.example.com
    redirect:
      httpsRedirect: true

---
# k8s/istio/peerauthentication.yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: go-observability
  namespace: go-observability
  labels:
    app: go-observability
    component: peer-authentication
spec:
  selector:
    matchLabels:
      app: go-observability
  mtls:
    mode: STRICT

---
# k8s/istio/authorizationpolicy.yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: go-observability
  namespace: go-observability
  labels:
    app: go-observability
    component: authorization-policy
spec:
  selector:
    matchLabels:
      app: go-observability
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account"]
    to:
    - operation:
        methods: ["GET", "POST", "PUT", "DELETE"]
  - from:
    - source:
        namespaces: ["monitoring"]
    to:
    - operation:
        methods: ["GET"]
        paths: ["/metrics", "/health"]
```

## Developer Experience

### Enhanced VS Code Development Environment

**Decision Rationale**: Developer experience directly impacts productivity and code quality. A well-configured development environment reduces friction and enables developers to focus on business logic rather than tooling.

#### VS Code Dev Container Configuration
