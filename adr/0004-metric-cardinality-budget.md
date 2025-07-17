# ADR-0004: Metric Cardinality Budget & Governance

**Status:** Accepted  
**Date:** 2025-07-17  
**Tags:** metrics, prometheus, cost, sre, cardinality

## Context

Prometheus storage costs and query performance scale linearly with the number of unique time series. High-cardinality labels create combinatorial explosion that can bankrupt infrastructure budgets and cause query timeouts.

### Problem Statement

Common cardinality mistakes that kill production systems:

- **User IDs as labels**: 10k users = 10k+ series per metric
- **Full URL paths**: Unlimited series growth with dynamic routes
- **Timestamp labels**: Infinite cardinality with time-based data
- **Error messages**: Arbitrary string values as label values
- **Session IDs**: Unique values that never repeat

Real production incidents:

- Prometheus OOM crashes from 50M+ series
- Query timeouts exceeding 30 seconds
- Storage costs scaling to $50k+/month
- Alert lag causing SLA violations

### Forces & Considerations

| Approach | Cardinality | Query Performance | Storage Cost | Debugging Value |
|----------|-------------|------------------|--------------|-----------------|
| **Raw Values** | Unlimited | Poor | Expensive | High |
| **Templated Routes** | Bounded | Good | Predictable | Medium |
| **Status Bucketing** | Low | Excellent | Cheap | Medium |
| **No Metrics** | Zero | N/A | Free | None |

### Options Considered

#### Option 1: Unlimited Cardinality (Rejected)

```go
// ❌ DANGEROUS: Unbounded cardinality
httpRequests.WithLabelValues(
    r.Method,           // OK: Limited values
    r.URL.Path,         // ❌ BAD: /users/1, /users/2, /users/3...
    fmt.Sprint(status), // ❌ BAD: 200, 201, 204, 400, 401, 403...
    userID,             // ❌ CATASTROPHIC: Millions of users
).Inc()
```

**Pros:** Maximum debugging information  
**Cons:** Unlimited cost, poor performance, system failure

#### Option 2: Route Templating (Chosen)

```go
// ✅ GOOD: Bounded cardinality
httpRequests.WithLabelValues(
    r.Method,                    // OK: GET, POST, PUT, DELETE (~10 values)
    templateRoute(r.URL.Path),   // OK: /users/{id} (~100 routes)
    statusClass(status),         // OK: 2xx, 3xx, 4xx, 5xx (5 values)
).Inc()
// Total series: 10 * 100 * 5 = 5,000 series (manageable)
```

**Pros:** Bounded cost, good performance, actionable alerting  
**Cons:** Less granular debugging information

#### Option 3: Minimal Labels (Rejected)

```go
// Too restrictive: No route information
httpRequests.WithLabelValues(r.Method).Inc()
```

**Pros:** Very low cardinality  
**Cons:** Insufficient information for alerting and debugging

#### Option 4: High-Cardinality in Logs (Complementary)

```go
// Metrics: Bounded cardinality for alerting
httpRequests.WithLabelValues(method, routeTemplate, statusClass).Inc()

// Logs: Unlimited cardinality for debugging
logger.InfoCtx(ctx, "request completed",
    "method", r.Method,
    "path", r.URL.Path,          // Full path in logs
    "status", status,            // Exact status in logs
    "user_id", userID,           // User ID in logs
    "duration_ms", duration.Milliseconds(),
)
```

**Pros:** Best of both worlds  
**Cons:** Requires log aggregation for some debugging

### Decision

**Implement strict cardinality budgets enforced at multiple layers.**

### Cardinality Budgets

#### Production Limits

- **Target**: ≤1,000 active series per service
- **Warning**: 800 series (alert but don't fail)
- **Critical**: 1,200 series (immediate escalation)
- **Maximum**: 1,500 series (emergency circuit breaker)

#### Development Limits

- **Learning mode**: ≤5,000 series (higher for experimentation)
- **CI/CD validation**: Fail PR if >10% increase without approval
- **Load testing**: Generate realistic cardinality profiles

### Label Design Patterns

#### Approved High-Value Labels

```go
// HTTP Request Metrics
type HTTPLabels struct {
    Method      string // GET, POST, PUT, DELETE (~10 values)
    Route       string // /users/{id}, /orders/{id} (~100 routes)  
    StatusClass string // 2xx, 3xx, 4xx, 5xx (5 values)
}
// Max series: 10 * 100 * 5 = 5,000

// Database Operation Metrics  
type DBLabels struct {
    Operation string // SELECT, INSERT, UPDATE, DELETE (4 values)
    Table     string // users, orders, products (~20 tables)
    Status    string // success, error (2 values)
}
// Max series: 4 * 20 * 2 = 160

// Business Process Metrics
type BusinessLabels struct {
    Operation  string // user.create, order.process (~50 operations)
    EntityType string // user, order, product (~10 types)
    Outcome    string // success, validation_error, system_error (3 values)
}
// Max series: 50 * 10 * 3 = 1,500
```

#### Forbidden High-Cardinality Labels

```go
// ❌ NEVER USE: Unbounded cardinality
"user_id"        // Millions of users
"order_id"       // Millions of orders  
"session_id"     // Millions of sessions
"request_id"     // Unique per request
"ip_address"     // Thousands of IPs
"user_agent"     // Hundreds of variants
"error_message"  // Arbitrary strings
"timestamp"      // Time-based values
"uuid"           // Globally unique values
```

### Implementation Patterns

#### Route Templating

```go
func templateRoute(path string) string {
    if path == "" {
        return "unknown"
    }
    
    // Use Gin's built-in route templating
    // Gin provides c.FullPath() which returns "/users/:id"
    // Convert to Prometheus-friendly format
    templated := strings.ReplaceAll(path, ":", "")
    templated = strings.ReplaceAll(templated, "/", "_")
    
    if templated == "" {
        return "root"
    }
    
    return templated
}

// Example usage in Gin middleware
func MetricsMiddleware(metrics *HTTPMetrics) gin.HandlerFunc {
    return func(c *gin.Context) {
        start := time.Now()
        
        c.Next()
        
        duration := time.Since(start)
        
        labels := []string{
            c.Request.Method,              // GET, POST, etc.
            templateRoute(c.FullPath()),   // users_id, orders_id_items
            statusClass(c.Writer.Status()), // 2xx, 4xx, 5xx
        }
        
        metrics.RequestsTotal.WithLabelValues(labels...).Inc()
        metrics.RequestDuration.WithLabelValues(labels[:2]...).Observe(duration.Seconds())
    }
}
```

#### Status Classification

```go
func statusClass(code int) string {
    switch {
    case code < 300:
        return "2xx"
    case code < 400:
        return "3xx"
    case code < 500:
        return "4xx"
    default:
        return "5xx"
    }
}
```

#### Metric Registry with Cardinality Protection

```go
type MetricRegistry struct {
    registry      *prometheus.Registry
    seriesCount   prometheus.Gauge
    maxSeries     int
    alertThreshold int
}

func NewMetricRegistry(maxSeries, alertThreshold int) *MetricRegistry {
    reg := prometheus.NewRegistry()
    
    seriesCount := prometheus.NewGauge(prometheus.GaugeOpts{
        Name: "prometheus_metrics_series_count",
        Help: "Current number of metric series registered",
    })
    reg.MustRegister(seriesCount)
    
    return &MetricRegistry{
        registry:       reg,
        seriesCount:    seriesCount,
        maxSeries:      maxSeries,
        alertThreshold: alertThreshold,
    }
}

func (r *MetricRegistry) Register(collector prometheus.Collector) error {
    // Check cardinality before registration
    if err := r.validateCardinality(collector); err != nil {
        return fmt.Errorf("cardinality budget exceeded: %w", err)
    }
    
    return r.registry.Register(collector)
}

func (r *MetricRegistry) validateCardinality(collector prometheus.Collector) error {
    // Estimate series count for new collector
    estimatedSeries := estimateCollectorSeries(collector)
    currentSeries := r.getCurrentSeriesCount()
    
    if currentSeries+estimatedSeries > r.maxSeries {
        return fmt.Errorf("would exceed max series limit: current=%d, estimated=%d, max=%d",
            currentSeries, estimatedSeries, r.maxSeries)
    }
    
    if currentSeries+estimatedSeries > r.alertThreshold {
        log.Printf("WARNING: Approaching cardinality limit: current=%d, estimated=%d, threshold=%d",
            currentSeries, estimatedSeries, r.alertThreshold)
    }
    
    return nil
}
```

### Enforcement Mechanisms

#### 1. Golden File Validation

```bash
#!/bin/bash
# scripts/cardinality-check.sh

set -e

echo "📊 Checking metric cardinality..."

# Generate realistic load
make load-test-cardinality

# Query current series count
if command -v promtool >/dev/null 2>&1; then
    promtool query instant --url=http://localhost:9090 \
        'count by (__name__, job, instance)({__name__=~".+"})' \
        > current_series.txt
else
    # Fallback to curl
    curl -s 'http://localhost:9090/api/v1/query?query=count+by+(__name__,job,instance)({__name__=~".%2B"})' \
        | jq -r '.data.result[] | "\(.metric.__name__) \(.value[1])"' \
        > current_series.txt
fi

# Validate against approved baseline
if [ -f testdata/approved_series.txt ]; then
    if diff -u testdata/approved_series.txt current_series.txt > series_diff.txt; then
        echo "✅ Cardinality check passed"
        rm -f current_series.txt series_diff.txt
        exit 0
    else
        echo "❌ Cardinality change detected:"
        cat series_diff.txt
        echo ""
        echo "Current series count:"
        wc -l current_series.txt
        echo "Approved series count:"  
        wc -l testdata/approved_series.txt
        echo ""
        echo "If changes are expected, run:"
        echo "  cp current_series.txt testdata/approved_series.txt"
        echo "  git add testdata/approved_series.txt"
        echo "  git commit -m 'approve cardinality increase'"
        exit 1
    fi
else
    echo "⚠️  No baseline found. Creating initial baseline..."
    mkdir -p testdata
    cp current_series.txt testdata/approved_series.txt
    echo "✅ Baseline created: testdata/approved_series.txt"
    echo "Please commit this file to establish cardinality budget."
fi
```

#### 2. CI/CD Integration

```yaml
# .github/workflows/cardinality.yml
name: Cardinality Check

on:
  pull_request:
    paths:
      - 'internal/**'
      - 'go.mod'
      - 'go.sum'

jobs:
  cardinality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.24'
          
      - name: Start observability stack
        run: make setup
        
      - name: Wait for services
        run: make health-check
        
      - name: Run cardinality check
        run: make cardinality-check
        
      - name: Upload cardinality diff
        if: failure()
        uses: actions/upload-artifact@v3
        with:
          name: cardinality-diff
          path: |
            current_series.txt
            series_diff.txt
```

#### 3. Runtime Circuit Breaker

```go
type CardinalityCircuitBreaker struct {
    maxSeries     int
    currentSeries *atomic.Int64
    enabled       *atomic.Bool
    resetInterval time.Duration
    lastReset     *atomic.Int64
}

func NewCardinalityCircuitBreaker(maxSeries int) *CardinalityCircuitBreaker {
    return &CardinalityCircuitBreaker{
        maxSeries:     maxSeries,
        currentSeries: &atomic.Int64{},
        enabled:       &atomic.Bool{},
        resetInterval: 5 * time.Minute,
        lastReset:     &atomic.Int64{},
    }
}

func (cb *CardinalityCircuitBreaker) BeforeMetricIncrement(metricName string, labels []string) error {
    if !cb.enabled.Load() {
        return nil // Circuit breaker disabled
    }
    
    current := cb.currentSeries.Load()
    if current >= int64(cb.maxSeries) {
        // Check if we should reset
        lastReset := cb.lastReset.Load()
        if time.Since(time.Unix(lastReset, 0)) > cb.resetInterval {
            cb.currentSeries.Store(0)
            cb.lastReset.Store(time.Now().Unix())
            return nil
        }
        
        return fmt.Errorf("cardinality circuit breaker triggered: current=%d, max=%d",
            current, cb.maxSeries)
    }
    
    return nil
}

func (cb *CardinalityCircuitBreaker) AfterMetricIncrement(metricName string, labels []string) {
    cb.currentSeries.Add(1)
}
```

#### 4. Prometheus Alerting Rules

```yaml
# alerts/cardinality.yml
groups:
  - name: cardinality
    rules:
      - alert: HighCardinalityWarning
        expr: |
          count by (job) (
            {__name__=~".+"}
          ) > 800
        for: 5m
        labels:
          severity: warning
          component: metrics
        annotations:
          summary: "High metric cardinality detected"
          description: |
            Service {{ $labels.job }} has {{ $value }} active time series.
            This is approaching the 1000 series budget limit.
            
      - alert: HighCardinalityCritical  
        expr: |
          count by (job) (
            {__name__=~".+"}
          ) > 1200
        for: 1m
        labels:
          severity: critical
          component: metrics
          escalation: immediate
        annotations:
          summary: "Critical metric cardinality exceeded"
          description: |
            Service {{ $labels.job }} has {{ $value }} active time series.
            This exceeds the 1000 series budget and may impact system performance.
            
      - alert: CardinalityGrowthRate
        expr: |
          rate(prometheus_tsdb_samples_appended_total[5m]) > 100
        for: 2m
        labels:
          severity: warning
          component: metrics
        annotations:
          summary: "High rate of new metric series creation"
          description: |
            Prometheus is ingesting new series at {{ $value }} per second.
            This may indicate a cardinality explosion in progress.
```

### Development Workflow

#### Pre-commit Cardinality Check

```bash
#!/bin/bash
# .git/hooks/pre-commit

echo "Running cardinality pre-commit check..."

# Only check if metrics code changed
if git diff --cached --name-only | grep -q "metrics\|prometheus"; then
    # Quick cardinality estimate
    if make cardinality-estimate; then
        echo "✅ Cardinality check passed"
    else
        echo "❌ Cardinality check failed"
        echo "Run 'make cardinality-check' for detailed analysis"
        exit 1
    fi
fi
```

#### Cardinality Estimation

```go
// tools/cardinality-estimate/main.go
func estimateCardinality() {
    // Parse metric definitions from code
    metrics := parseMetricDefinitions("internal/")
    
    for _, metric := range metrics {
        estimate := 1
        for _, label := range metric.Labels {
            estimate *= estimateLabelCardinality(label)
        }
        
        fmt.Printf("Metric: %s, Estimated Series: %d\n", metric.Name, estimate)
        
        if estimate > 1000 {
            fmt.Printf("⚠️  HIGH CARDINALITY: %s has %d estimated series\n",
                metric.Name, estimate)
        }
    }
}

func estimateLabelCardinality(label string) int {
    switch label {
    case "method":
        return 10 // GET, POST, PUT, DELETE, etc.
    case "route":
        return 100 // Estimated API routes
    case "status_class":
        return 5 // 2xx, 3xx, 4xx, 5xx, timeout
    case "operation":
        return 50 // Business operations
    case "table":
        return 20 // Database tables
    default:
        return 5 // Conservative default
    }
}
```

### High-Cardinality Data Strategy

#### Use Logs for High-Cardinality Data

```go
func RecordHTTPRequest(ctx context.Context, r *http.Request, status int, duration time.Duration) {
    // Metrics: Bounded cardinality for alerting
    httpRequestsTotal.WithLabelValues(
        r.Method,
        templateRoute(r.URL.Path),
        statusClass(status),
    ).Inc()
    
    httpRequestDuration.WithLabelValues(
        r.Method,
        templateRoute(r.URL.Path),
    ).Observe(duration.Seconds())
    
    // Logs: Unlimited cardinality for debugging
    logger := LoggerFromContext(ctx)
    logger.InfoCtx(ctx, "http request completed",
        "method", r.Method,
        "path", r.URL.Path,           // Full path with IDs
        "status", status,             // Exact status code
        "duration_ms", duration.Milliseconds(),
        "user_agent", r.UserAgent(),  // Full user agent
        "remote_addr", r.RemoteAddr,  // Client IP
        "request_size", r.ContentLength,
    )
}
```

#### Sampling for High-Value Metrics

```go
type SamplingCounter struct {
    counter    prometheus.Counter
    sampleRate float64
    random     *rand.Rand
}

func (sc *SamplingCounter) Inc(labels []string) {
    // Only increment counter for sampled requests
    if sc.random.Float64() < sc.sampleRate {
        sc.counter.Inc()
    }
}

// Example: Track individual user actions with sampling
userActionsTotal := &SamplingCounter{
    counter:    prometheus.NewCounter(prometheus.CounterOpts{
        Name: "user_actions_sampled_total",
        Help: "Sampled count of user actions",
    }),
    sampleRate: 0.1, // 10% sampling
    random:     rand.New(rand.NewSource(time.Now().UnixNano())),
}
```

### Cardinality Analysis Tools

#### Series Growth Analysis

```bash
#!/bin/bash
# scripts/cardinality-analysis.sh

# Analyze series growth over time
promtool query range \
    --url=http://localhost:9090 \
    'count by (__name__)({__name__=~".+"})' \
    --start=$(date -d '24 hours ago' -u +%Y-%m-%dT%H:%M:%SZ) \
    --end=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
    --step=1h \
    > series_growth.json

# Identify top cardinality metrics
promtool query instant \
    --url=http://localhost:9090 \
    'topk(10, count by (__name__)({__name__=~".+"}))' \
    > top_cardinality_metrics.txt

echo "Top cardinality metrics:"
cat top_cardinality_metrics.txt
```

#### Label Value Analysis

```bash
# Find metrics with most label combinations
promtool query instant \
    --url=http://localhost:9090 \
    'count by (__name__) (group by (__name__, job, instance) ({__name__=~".+"}))' \
    > label_combinations.txt

# Identify problematic label values
for metric in $(cat top_cardinality_metrics.txt | cut -d' ' -f1); do
    echo "Analyzing metric: $metric"
    promtool query instant \
        --url=http://localhost:9090 \
        "count by ($(promtool query instant --url=http://localhost:9090 "group by (__name__) ({__name__=\"$metric\"})" | head -1 | cut -d'{' -f2 | cut -d'}' -f1)) ({__name__=\"$metric\"})" \
        > "${metric}_label_analysis.txt"
done
```

### Cost Analysis

#### Storage Cost Calculation

```go
// Cost calculation for cardinality planning
type CardinalityCost struct {
    SeriesCount    int
    SamplesPerHour int
    RetentionDays  int
    BytesPerSample int
}

func (c CardinalityCost) StorageGB() float64 {
    totalSamples := c.SeriesCount * c.SamplesPerHour * 24 * c.RetentionDays
    totalBytes := totalSamples * c.BytesPerSample
    return float64(totalBytes) / (1024 * 1024 * 1024)
}

func (c CardinalityCost) MonthlyCostUSD(pricePerGBMonth float64) float64 {
    return c.StorageGB() * pricePerGBMonth
}

// Example cost analysis
func analyzeCosts() {
    scenarios := []CardinalityCost{
        {SeriesCount: 1000, SamplesPerHour: 120, RetentionDays: 90, BytesPerSample: 8},
        {SeriesCount: 10000, SamplesPerHour: 120, RetentionDays: 90, BytesPerSample: 8},
        {SeriesCount: 100000, SamplesPerHour: 120, RetentionDays: 90, BytesPerSample: 8},
    }
    
    pricePerGB := 0.10 // $0.10 per GB-month (example pricing)
    
    for _, scenario := range scenarios {
        fmt.Printf("Series: %d, Storage: %.2f GB, Monthly Cost: $%.2f\n",
            scenario.SeriesCount,
            scenario.StorageGB(),
            scenario.MonthlyCostUSD(pricePerGB))
    }
}
```

### Migration Strategies

#### Existing High-Cardinality Metrics

```go
// Phase 1: Add new low-cardinality metric alongside existing
httpRequestsTotal := prometheus.NewCounterVec(
    prometheus.CounterOpts{
        Name: "http_requests_total",
        Help: "Total HTTP requests (legacy, high cardinality)",
    },
    []string{"method", "path", "status"}, // High cardinality
)

httpRequestsTotalV2 := prometheus.NewCounterVec(
    prometheus.CounterOpts{
        Name: "http_requests_total_v2",
        Help: "Total HTTP requests (bounded cardinality)",
    },
    []string{"method", "route", "status_class"}, // Bounded cardinality
)

// Phase 2: Dual recording during transition
func recordRequest(method, path string, status int) {
    // Legacy metric (will be deprecated)
    httpRequestsTotal.WithLabelValues(method, path, fmt.Sprint(status)).Inc()
    
    // New metric (bounded cardinality)
    httpRequestsTotalV2.WithLabelValues(
        method,
        templateRoute(path),
        statusClass(status),
    ).Inc()
}

// Phase 3: Remove legacy metric after validation period
```

### Consequences

**Positive:**

- **Predictable costs**: Bounded series count means predictable storage costs
- **Reliable queries**: Low cardinality ensures fast query performance  
- **Stable alerts**: Alerts fire reliably without cardinality-induced delays
- **Operational confidence**: System remains stable under load
- **Budget compliance**: Infrastructure costs remain within planned budgets

**Negative:**

- **Reduced granularity**: Cannot drill down to individual resource metrics
- **Development discipline**: Requires training and enforcement mechanisms
- **Migration effort**: Existing high-cardinality metrics need refactoring
- **Log dependency**: Some debugging requires log analysis instead of metrics

**Mitigation Strategies:**

- **High-cardinality logs**: Use structured logging for detailed debugging
- **Sampling strategies**: Sample high-value metrics at reduced rate
- **Layered observability**: Metrics for alerting, logs for debugging, traces for requests
- **Training and tools**: Provide cardinality estimation tools and guidelines

### Related ADRs

- [ADR-0005: Error Classification](#adr-0005-error-classification) - Error codes as bounded labels
- [ADR-0009: PII Governance](#adr-0009-pii-governance) - PII never in metric labels
- [ADR-0010: Performance Budgets](#adr-0010-performance-budgets) - Cardinality as performance constraint

### References

- [Prometheus Best Practices: Metric and Label Naming](https://prometheus.io/docs/practices/naming/)
- [Avoiding High Cardinality - Robust Perception](https://www.robustperception.io/cardinality-is-key)
- [Site Reliability Engineering: Monitoring Distributed Systems](https://sre.google/sre-book/monitoring-distributed-systems/)
