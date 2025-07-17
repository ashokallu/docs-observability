# ADR-0008: GCP-First Cloud Strategy with Multi-Cloud Readiness

**Status:** Accepted  
**Date:** 2025-07-17  
**Tags:** cloud, gcp, deployment, multi-cloud, strategy

## Context

Cloud platform choice affects observability architecture, deployment patterns, cost optimization, and long-term scalability. The decision impacts service selection, pricing models, integration complexity, and vendor lock-in risks.

### Problem Statement

Multiple cloud platform strategies exist:

- **Single cloud vendor**: Simplicity vs vendor lock-in risk
- **Multi-cloud from start**: Flexibility vs complexity overhead  
- **Cloud-agnostic**: Portability vs feature limitations
- **Hybrid cloud**: On-premises integration complexity

Platform choice impacts:

- **Observability services**: Different APIs, pricing models, feature sets
- **Deployment patterns**: Container orchestration, serverless options
- **Integration complexity**: Authentication, networking, service discovery
- **Cost optimization**: Pricing models, free tiers, long-term commitments
- **Compliance**: Data residency, security controls, certification requirements

### Forces & Considerations

| Strategy | Simplicity | Vendor Risk | Feature Access | Cost Optimization | Migration Effort |
|----------|------------|-------------|----------------|------------------|------------------|
| **GCP-Only** | High | High | Full | High | High |
| **Multi-Cloud** | Low | Low | Limited | Medium | Medium |
| **Cloud-Agnostic** | Medium | None | Limited | Low | Low |
| **GCP-First** | High | Medium | Full→Limited | High→Medium | Medium |

### Options Considered

#### Option 1: Cloud-Agnostic Architecture (Rejected)

Use only services available across all major cloud providers.

**Pros:**

- No vendor lock-in risk
- Easy migration between providers
- Consistent operations across clouds

**Cons:**

- Limited to lowest common denominator
- Cannot leverage cloud-specific optimizations
- Higher operational complexity
- Reduced feature availability

#### Option 2: Multi-Cloud from Start (Rejected)

Deploy to multiple cloud providers simultaneously.

**Pros:**

- Vendor independence from day one
- Risk distribution
- Best-of-breed service selection

**Cons:**

- Operational complexity
- Higher costs (multiple accounts/services)
- Authentication/networking complexity
- Limited deep integrations

#### Option 3: AWS-First Strategy (Rejected)

Focus on AWS as primary cloud provider.

**Pros:**

- Largest market share and ecosystem
- Mature observability services
- Extensive documentation

**Cons:**

- More complex pricing models
- Steeper learning curve for some services
- Higher cost for small workloads

#### Option 4: GCP-First with Multi-Cloud Readiness (Chosen)

Primary deployment on GCP with architecture supporting future multi-cloud.

**Pros:**

- Leverage GCP's observability excellence
- Competitive pricing for observability
- Clean APIs and developer experience
- Easier Kubernetes/cloud-native patterns

**Cons:**

- Vendor concentration risk
- Platform-specific optimizations may create coupling

### Decision

**Adopt GCP-first cloud strategy with architecture designed for multi-cloud readiness.**

### Rationale

#### GCP Observability Excellence

- **Integrated observability**: Cloud Logging, Cloud Monitoring, Cloud Trace, Cloud Profiler
- **OpenTelemetry native**: First-class OTel support across all services  
- **Operations Suite**: Unified observability platform with excellent correlation
- **Cost-effective**: Competitive pricing for high-volume observability data

#### Developer Experience Advantages

- **Clean APIs**: Consistent REST/gRPC APIs with excellent client libraries
- **Cloud Shell**: Integrated development environment with pre-configured tools
- **Documentation quality**: Clear, comprehensive documentation with examples
- **Terraform provider**: Mature Infrastructure as Code support

#### Strategic Multi-Cloud Readiness

- **OpenTelemetry standard**: Ensures telemetry data portability
- **Containerized workloads**: Cloud Run → Kubernetes → any cloud
- **Infrastructure as Code**: Terraform modules enable multi-cloud deployment
- **Standard protocols**: OTLP, Prometheus metrics, standard logging formats

### Implementation Strategy

#### Phase 1: GCP Foundation

```hcl
# terraform/gcp/main.tf - GCP-optimized infrastructure
terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

# Primary GCP deployment
module "observability_platform" {
  source = "./modules/observability"
  
  project_id = var.project_id
  region     = var.region  # Default: asia-south1
  
  # GCP-specific optimizations
  cloud_logging_enabled = true
  cloud_monitoring_enabled = true
  cloud_trace_enabled = true
  
  # Multi-cloud readiness
  export_metrics_to_prometheus = true
  export_traces_to_jaeger = false  # Start with GCP-native
  export_logs_to_fluentd = false   # Start with GCP-native
}

# Cloud Run deployment with observability
resource "google_cloud_run_service" "api" {
  name     = "go-observability-api"
  location = var.region

  template {
    spec {
      containers {
        image = var.container_image
        
        env {
          name  = "GOOGLE_CLOUD_PROJECT"
          value = var.project_id
        }
        
        env {
          name  = "OTEL_EXPORTER_OTLP_ENDPOINT"
          value = "https://cloudtrace.googleapis.com/v1/projects/${var.project_id}/traces"
        }
        
        # Automatic service mesh integration
        ports {
          container_port = 8080
        }
        
        resources {
          limits = {
            cpu    = "1000m"
            memory = "512Mi"
          }
        }
      }
    }
    
    metadata {
      annotations = {
        "autoscaling.knative.dev/maxScale" = "100"
        "run.googleapis.com/execution-environment" = "gen2"
        
        # Observability annotations
        "run.googleapis.com/cpu-throttling" = "false"
      }
    }
  }
}
```

#### GCP Observability Services Configuration

```yaml
# gcp-observability-config.yml
apiVersion: v1
kind: ConfigMap
metadata:
  name: observability-config
data:
  config.yaml: |
    # OpenTelemetry Collector configuration for GCP
    receivers:
      otlp:
        protocols:
          grpc:
            endpoint: 0.0.0.0:4317
          http:
            endpoint: 0.0.0.0:4318
    
    processors:
      batch:
        timeout: 1s
        send_batch_size: 1024
      
      resource:
        attributes:
          - key: gcp.project_id
            value: ${GOOGLE_CLOUD_PROJECT}
            action: insert
          - key: gcp.location
            value: ${GOOGLE_CLOUD_REGION}
            action: insert
    
    exporters:
      # GCP-native exporters
      google_cloud_logging:
        project: ${GOOGLE_CLOUD_PROJECT}
        
      google_cloud_monitoring:
        project: ${GOOGLE_CLOUD_PROJECT}
        metric_labels:
          environment: ${ENVIRONMENT}
          
      google_cloud_trace:
        project: ${GOOGLE_CLOUD_PROJECT}
      
      # Multi-cloud readiness exporters (initially disabled)
      prometheus:
        endpoint: "prometheus:9090"
        send_exemplars: true
        
      jaeger:
        endpoint: jaeger:14250
        tls:
          insecure: true
    
    service:
      pipelines:
        traces:
          receivers: [otlp]
          processors: [resource, batch]
          exporters: [google_cloud_trace]
          
        metrics:
          receivers: [otlp]
          processors: [resource, batch]
          exporters: [google_cloud_monitoring]
          
        logs:
          receivers: [otlp]
          processors: [resource, batch]
          exporters: [google_cloud_logging]
```

#### Application Configuration for GCP

```go
// internal/platform/obs/gcp/config.go
package gcp

import (
    "context"
    "fmt"
    
    "cloud.google.com/go/logging"
    "cloud.google.com/go/monitoring/apiv3"
    "contrib.go.opencensus.io/exporter/stackdriver"
    "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
)

type GCPObservabilityConfig struct {
    ProjectID    string `env:"GOOGLE_CLOUD_PROJECT" required:"true"`
    Region       string `env:"GOOGLE_CLOUD_REGION" envDefault:"asia-south1"`
    Environment  string `env:"ENVIRONMENT" envDefault:"production"`
    
    // Feature flags for gradual migration
    UseCloudLogging    bool `env:"USE_CLOUD_LOGGING" envDefault:"true"`
    UseCloudMonitoring bool `env:"USE_CLOUD_MONITORING" envDefault:"true"`
    UseCloudTrace      bool `env:"USE_CLOUD_TRACE" envDefault:"true"`
    
    // Multi-cloud readiness
    ExportToPrometheus bool `env:"EXPORT_TO_PROMETHEUS" envDefault:"false"`
    ExportToJaeger     bool `env:"EXPORT_TO_JAEGER" envDefault:"false"`
}

func NewGCPObservability(cfg GCPObservabilityConfig) (*Observability, error) {
    ctx := context.Background()
    
    // Initialize GCP services
    var logClient *logging.Client
    var err error
    
    if cfg.UseCloudLogging {
        logClient, err = logging.NewClient(ctx, cfg.ProjectID)
        if err != nil {
            return nil, fmt.Errorf("failed to create Cloud Logging client: %w", err)
        }
    }
    
    // Create OpenTelemetry trace exporter for Cloud Trace
    var traceExporter trace.SpanExporter
    if cfg.UseCloudTrace {
        traceExporter, err = otlptracehttp.New(ctx,
            otlptracehttp.WithEndpoint(fmt.Sprintf(
                "https://cloudtrace.googleapis.com/v1/projects/%s/traces", 
                cfg.ProjectID,
            )),
            otlptracehttp.WithHeaders(map[string]string{
                "Authorization": "Bearer " + getGCPToken(),
            }),
        )
        if err != nil {
            return nil, fmt.Errorf("failed to create Cloud Trace exporter: %w", err)
        }
    }
    
    return &Observability{
        Logger: newGCPLogger(logClient, cfg),
        TracerProvider: trace.NewTracerProvider(
            trace.WithBatcher(traceExporter),
            trace.WithResource(newGCPResource(cfg)),
        ),
        MetricsProvider: newGCPMetrics(cfg),
    }, nil
}

func newGCPResource(cfg GCPObservabilityConfig) *resource.Resource {
    return resource.NewWithAttributes(
        semconv.SchemaURL,
        semconv.CloudProvider("gcp"),
        semconv.CloudPlatform("gcp_cloud_run"),
        semconv.CloudRegion(cfg.Region),
        semconv.ServiceName("go-observability-api"),
        semconv.ServiceVersion(os.Getenv("SERVICE_VERSION")),
        semconv.DeploymentEnvironment(cfg.Environment),
        attribute.String("gcp.project_id", cfg.ProjectID),
        attribute.String("gcp.location", cfg.Region),
    )
}
```

#### Multi-Cloud Abstraction Layer

```go
// internal/platform/obs/cloud/provider.go - Multi-cloud abstraction
package cloud

type CloudProvider interface {
    Name() string
    LoggingService() LoggingService
    MonitoringService() MonitoringService
    TracingService() TracingService
}

type LoggingService interface {
    WriteLog(ctx context.Context, entry LogEntry) error
    QueryLogs(ctx context.Context, query LogQuery) ([]LogEntry, error)
}

type MonitoringService interface {
    WriteMetrics(ctx context.Context, metrics []Metric) error
    QueryMetrics(ctx context.Context, query MetricQuery) ([]MetricPoint, error)
}

type TracingService interface {
    WriteSpans(ctx context.Context, spans []Span) error
    QueryTraces(ctx context.Context, query TraceQuery) ([]Trace, error)
}

// GCP implementation
type gcpProvider struct {
    projectID string
    region    string
}

func (g *gcpProvider) Name() string {
    return "gcp"
}

func (g *gcpProvider) LoggingService() LoggingService {
    return &gcpLoggingService{projectID: g.projectID}
}

// AWS implementation (future)
type awsProvider struct {
    region    string
    accountID string
}

// Azure implementation (future)
type azureProvider struct {
    subscriptionID string
    resourceGroup  string
}

// Factory function
func NewCloudProvider(providerName string, config map[string]string) (CloudProvider, error) {
    switch providerName {
    case "gcp":
        return &gcpProvider{
            projectID: config["project_id"],
            region:    config["region"],
        }, nil
    case "aws":
        return &awsProvider{
            region:    config["region"],
            accountID: config["account_id"],
        }, nil
    case "azure":
        return &azureProvider{
            subscriptionID: config["subscription_id"],
            resourceGroup:  config["resource_group"],
        }, nil
    default:
        return nil, fmt.Errorf("unsupported cloud provider: %s", providerName)
    }
}
```

### GCP Service Selection and Rationale

#### Core Observability Services

```yaml
# GCP Services with rationale
services:
  cloud_run:
    rationale: "Serverless containers with automatic scaling, integrated observability"
    alternatives: ["GKE", "Compute Engine", "App Engine"]
    
  cloud_logging:
    rationale: "Structured logging with excellent search, retention policies, exports"
    alternatives: ["Elasticsearch", "Fluentd + external storage"]
    
  cloud_monitoring:
    rationale: "Native Prometheus compatibility, SLO/SLI support, alerting"
    alternatives: ["Prometheus + Grafana", "Datadog"]
    
  cloud_trace:
    rationale: "Native OpenTelemetry support, automatic correlation, performance insights"
    alternatives: ["Jaeger", "Zipkin"]
    
  cloud_profiler:
    rationale: "Continuous profiling with minimal overhead"
    alternatives: ["pprof + storage", "Pyroscope"]
    
  artifact_registry:
    rationale: "Container registry with vulnerability scanning, build integration"
    alternatives: ["Docker Hub", "GitHub Container Registry"]
    
  cloud_build:
    rationale: "Native CI/CD with automatic triggers, security scanning"
    alternatives: ["GitHub Actions", "GitLab CI"]
```

#### Infrastructure as Code Structure

```
terraform/
├── modules/
│   ├── observability/
│   │   ├── main.tf              # Core observability infrastructure
│   │   ├── monitoring.tf        # Cloud Monitoring configuration
│   │   ├── logging.tf           # Cloud Logging configuration
│   │   ├── trace.tf             # Cloud Trace configuration
│   │   └── variables.tf         # Module variables
│   ├── cloud-run/
│   │   ├── main.tf              # Cloud Run service configuration
│   │   ├── iam.tf               # Service accounts and permissions
│   │   └── variables.tf
│   └── networking/
│       ├── vpc.tf               # VPC and networking setup
│       ├── load-balancer.tf     # Load balancer configuration
│       └── dns.tf               # DNS configuration
├── environments/
│   ├── development/
│   │   ├── main.tf              # Dev environment configuration
│   │   └── terraform.tfvars     # Dev-specific variables
│   ├── staging/
│   │   ├── main.tf              # Staging environment configuration
│   │   └── terraform.tfvars     # Staging-specific variables
│   └── production/
│       ├── main.tf              # Production environment configuration
│       └── terraform.tfvars     # Production-specific variables
└── shared/
    ├── project.tf               # GCP project configuration
    ├── iam.tf                   # Project-level IAM
    └── apis.tf                  # Enable required APIs
```

### Cost Optimization Strategy

#### GCP Pricing Optimization

```yaml
# GCP cost optimization configuration
cost_optimization:
  cloud_logging:
    retention_days: 30              # Reduce from default 400 days
    exclusion_filters:              # Exclude noisy logs
      - "resource.type=cloud_run AND severity<WARNING"
      - "resource.type=cloud_run AND textPayload=~\"health check\""
    
  cloud_monitoring:
    metric_retention: "90d"         # Reduce from default 6 weeks
    alerting_policies: "essential"  # Only critical alerts
    
  cloud_trace:
    sampling_rate: 0.1              # 10% sampling in production
    trace_retention: "7d"           # 7 days retention
    
  cloud_run:
    min_instances: 0                # Scale to zero when not used
    max_instances: 10               # Limit maximum scale
    cpu_allocation: "1000m"         # Right-sized for workload
    memory: "512Mi"                 # Right-sized for workload

# Estimated monthly costs (asia-south1 region)
estimated_costs:
  cloud_run: "$20"                  # ~1M requests/month
  cloud_logging: "$5"               # ~10GB logs/month
  cloud_monitoring: "$15"           # ~100k metrics/month
  cloud_trace: "$2"                 # ~100k spans/month
  total_monthly: "$42"
```

#### Cost Monitoring and Alerting

```hcl
# terraform/modules/observability/cost-monitoring.tf
resource "google_monitoring_alert_policy" "cost_alert" {
  display_name = "Monthly Cost Alert"
  combiner     = "OR"

  conditions {
    display_name = "Monthly spend exceeds budget"
    
    condition_threshold {
      filter         = "resource.type=\"billing_account\""
      comparison     = "COMPARISON_GREATER_THAN"
      threshold_value = 100  # Alert if monthly spend exceeds $100
      duration        = "300s"
    }
  }

  alert_strategy {
    notification_rate_limit {
      period = "300s"
    }
    
    auto_close = "604800s"  # Auto-close after 7 days
  }

  notification_channels = [
    google_monitoring_notification_channel.email.id
  ]
}

resource "google_billing_budget" "observability_budget" {
  billing_account = var.billing_account
  display_name    = "Observability Budget"

  budget_filter {
    projects = ["projects/${var.project_id}"]
    services = [
      "services/cloud-logging",
      "services/cloud-monitoring", 
      "services/cloud-trace",
      "services/cloud-run"
    ]
  }

  amount {
    specified_amount {
      currency_code = "USD"
      units         = "100"  # $100 monthly budget
    }
  }

  threshold_rules {
    threshold_percent = 0.8  # Alert at 80%
    spend_basis      = "CURRENT_SPEND"
  }
  
  threshold_rules {
    threshold_percent = 1.0  # Alert at 100%
    spend_basis      = "CURRENT_SPEND"
  }
}
```

### Security and Compliance

#### GCP Security Configuration

```hcl
# terraform/modules/observability/security.tf
# Service account with minimal permissions
resource "google_service_account" "observability" {
  account_id   = "observability-sa"
  display_name = "Observability Service Account"
  description  = "Service account for observability workloads"
}

# Minimal IAM roles for observability
resource "google_project_iam_member" "observability_roles" {
  for_each = toset([
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter", 
    "roles/cloudtrace.agent",
    "roles/run.serviceAgent"
  ])
  
  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.observability.email}"
}

# VPC with private Google access
resource "google_compute_network" "observability_vpc" {
  name                    = "observability-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "observability_subnet" {
  name          = "observability-subnet"
  ip_cidr_range = "10.0.0.0/24"
  region        = var.region
  network       = google_compute_network.observability_vpc.id
  
  # Enable private Google access for Cloud APIs
  private_ip_google_access = true
}

# Firewall rules for observability
resource "google_compute_firewall" "observability_ingress" {
  name    = "observability-ingress"
  network = google_compute_network.observability_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["8080", "9090", "4317", "4318"]  # App, metrics, OTLP
  }

  source_ranges = ["10.0.0.0/8"]  # Internal traffic only
  target_tags   = ["observability"]
}
```

### Multi-Cloud Migration Readiness

#### Phase 2: Multi-Cloud Preparation

```go
// internal/platform/obs/cloud/config.go - Multi-cloud configuration
type MultiCloudConfig struct {
    Primary   CloudConfig   `yaml:"primary"`
    Secondary *CloudConfig  `yaml:"secondary,omitempty"`
    Tertiary  *CloudConfig  `yaml:"tertiary,omitempty"`
    
    // Migration settings
    MigrationMode    string  `yaml:"migration_mode"`     // "none", "read", "write", "full"
    TrafficSplitPct  int     `yaml:"traffic_split_pct"`  // Percentage to secondary
    
    // Failover settings
    FailoverEnabled  bool    `yaml:"failover_enabled"`
    HealthCheckURL   string  `yaml:"health_check_url"`
    FailoverTimeout  string  `yaml:"failover_timeout"`
}

type CloudConfig struct {
    Provider string            `yaml:"provider"`  // "gcp", "aws", "azure"
    Region   string            `yaml:"region"`
    Config   map[string]string `yaml:"config"`
}

// Example multi-cloud configuration
multicloud_config := MultiCloudConfig{
    Primary: CloudConfig{
        Provider: "gcp",
        Region:   "asia-south1",
        Config: map[string]string{
            "project_id": "my-observability-project",
        },
    },
    Secondary: &CloudConfig{
        Provider: "aws", 
        Region:   "ap-south-1",
        Config: map[string]string{
            "account_id": "123456789012",
        },
    },
    MigrationMode:   "read",       // Read from both, write to primary
    TrafficSplitPct: 10,           // 10% traffic to secondary
    FailoverEnabled: true,
}
```

#### Migration Tools and Utilities

```bash
#!/bin/bash
# scripts/migrate-to-multi-cloud.sh

echo "🌐 Preparing multi-cloud migration..."

# Step 1: Validate current GCP deployment
echo "Validating GCP deployment..."
terraform plan -target=module.gcp_observability

# Step 2: Create AWS/Azure infrastructure
echo "Creating secondary cloud infrastructure..."
terraform plan -target=module.aws_observability

# Step 3: Configure traffic splitting
echo "Configuring traffic splitting..."
kubectl apply -f k8s/traffic-split.yaml

# Step 4: Monitor migration health
echo "Setting up migration monitoring..."
./scripts/monitor-migration.sh

echo "✅ Multi-cloud migration preparation complete"
```

### Disaster Recovery and Business Continuity

#### Cross-Region Backup Strategy

```hcl
# terraform/modules/observability/backup.tf
# Automated backup of observability configuration
resource "google_storage_bucket" "observability_backup" {
  name     = "${var.project_id}-observability-backup"
  location = "ASIA"  # Multi-region for disaster recovery
  
  lifecycle_rule {
    condition {
      age = 90  # Delete backups older than 90 days
    }
    action {
      type = "Delete"
    }
  }
  
  versioning {
    enabled = true
  }
}

# Scheduled backup of monitoring configurations
resource "google_cloud_scheduler_job" "config_backup" {
  name     = "observability-config-backup"
  schedule = "0 2 * * *"  # Daily at 2 AM
  
  http_target {
    uri         = "https://backup-function-url"
    http_method = "POST"
    
    headers = {
      "Content-Type" = "application/json"
    }
    
    body = jsonencode({
      backup_type = "observability_config"
      retention_days = 30
    })
  }
}
```

### Consequences

**Positive:**

- **Integrated observability**: Seamless integration with GCP's observability suite
- **Cost effectiveness**: Competitive pricing for observability workloads
- **Developer experience**: Clean APIs and excellent tooling
- **Multi-cloud readiness**: Architecture supports future migration
- **Rapid deployment**: Serverless containers with automatic scaling

**Negative:**

- **Vendor concentration**: Primary dependency on single cloud provider
- **Migration complexity**: Future multi-cloud adoption requires planning
- **GCP-specific optimizations**: Some optimizations may create coupling
- **Regional limitations**: GCP coverage may not match requirements

**Mitigation Strategies:**

- **Multi-cloud abstraction**: Cloud provider interface layer
- **Standard protocols**: OpenTelemetry ensures data portability
- **Infrastructure as Code**: Terraform enables multi-cloud deployment
- **Regular migration exercises**: Quarterly multi-cloud deployment tests

### Related ADRs

- [ADR-0006: Local-First Observability](#adr-0006-local-first-observability) - Local development before cloud
- [ADR-0010: Performance Budgets](#adr-0010-performance-budgets) - Cloud cost as performance constraint
- [ADR-0011: Signal Access Control](#adr-0011-signal-access-retention) - Cloud-based access control

### References

- [Google Cloud Observability Documentation](https://cloud.google.com/docs/observability)
- [OpenTelemetry on Google Cloud](https://cloud.google.com/trace/docs/opentelemetry)
- [Terraform Google Provider](https://registry.terraform.io/providers/hashicorp/google/latest/docs)
- [GCP Pricing Calculator](https://cloud.google.com/products/calculator)
