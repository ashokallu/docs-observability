## ADR-0010: Performance Budgets & SLO Management

**Status:** Accepted  
**Date:** 2025-07-17  
**Tags:** performance, slo, sli, monitoring, alerting

### Context

Observability systems themselves can impact application performance through instrumentation overhead, data collection, and processing. Without performance budgets, observability can degrade the user experience it's meant to protect.

### Problem Statement

Observability overhead commonly impacts production systems:

- **Instrumentation latency**: Logging, tracing, and metrics collection adds request latency
- **Memory allocation**: Telemetry data structures increase garbage collection pressure  
- **CPU utilization**: Data serialization and export consumes compute resources
- **Network bandwidth**: Telemetry export can saturate network connections
- **Storage costs**: High-frequency data collection creates storage cost pressure

Common performance anti-patterns:

- **Synchronous telemetry**: Blocking request processing for telemetry export
- **High-frequency sampling**: 100% trace sampling in production
- **Verbose logging**: Debug-level logging in production
- **Unbounded cardinality**: High-cardinality metrics causing storage issues
- **No performance monitoring**: No measurement of observability overhead

### Forces & Considerations

| Approach | Observability Quality | Performance Impact | Implementation Complexity | Cost |
|----------|----------------------|-------------------|---------------------------|------|
| **No Limits** | High | High | Low | High |
| **Fixed Budgets** | Medium | Low | Medium | Medium |
| **Adaptive Budgets** | Variable | Low | High | Medium |
| **SLO-Driven** | Optimized | Controlled | High | Optimized |

### Options Considered

#### Option 1: No Performance Constraints (Rejected)

Allow unlimited observability overhead.

**Pros:**

- Maximum observability data collection
- No implementation complexity
- Rich debugging capabilities

**Cons:**

- Unpredictable performance impact
- Potential user experience degradation
- Uncontrolled costs

#### Option 2: Fixed Performance Budgets (Rejected)

Static performance limits for all observability.

**Pros:**

- Predictable overhead
- Simple implementation
- Clear boundaries

**Cons:**

- Inflexible for different scenarios
- May be too restrictive or too permissive
- No adaptation to system load

#### Option 3: Adaptive Sampling (Rejected)

Dynamic sampling based on system load only.

**Pros:**

- Automatic adaptation to load
- Protects system under stress
- Maintains data quality

**Cons:**

- Complex implementation
- May miss important events during high load
- No cost optimization

#### Option 4: SLO-Driven Performance Management (Chosen)

Manage observability overhead based on Service Level Objectives.

**Pros:**

- Business-aligned performance management
- Automatic adaptation to requirements
- Cost optimization aligned with value
- Clear trade-off decisions

**Cons:**

- Complex implementation requiring SLO definition
- Requires performance monitoring
- May reduce observability during incidents

### Decision

**Implement SLO-driven performance budgets with automatic enforcement and graceful degradation.**

### Service Level Objectives Framework

#### Core SLOs Definition

```go
type ServiceLevelObjective struct {
    Name        string              `yaml:"name"`
    Description string              `yaml:"description"`
    SLI         ServiceLevelIndicator `yaml:"sli"`
    Target      SLOTarget           `yaml:"target"`
    ErrorBudget ErrorBudget         `yaml:"error_budget"`
    AlertPolicy AlertPolicy         `yaml:"alert_policy"`
}

type ServiceLevelIndicator struct {
    Type       string  `yaml:"type"`        // "latency", "availability", "throughput", "error_rate"
    Metric     string  `yaml:"metric"`      // Prometheus metric name
    Threshold  float64 `yaml:"threshold"`   // Threshold value
    Aggregation string  `yaml:"aggregation"` // "avg", "p95", "p99"
}

type SLOTarget struct {
    Objective    float64       `yaml:"objective"`    // 99.9% = 0.999
    TimeWindow   time.Duration `yaml:"time_window"`  // 30d, 7d, 1d
}

type ErrorBudget struct {
    Remaining    float64       `yaml:"remaining"`    // Calculated remaining budget
    BurnRate     float64       `yaml:"burn_rate"`    // Current burn rate
    BurnRateAlert float64      `yaml:"burn_rate_alert"` // Alert threshold
}

// Example SLO definitions
func DefaultSLOs() []ServiceLevelObjective {
    return []ServiceLevelObjective{
        {
            Name:        "API Latency",
            Description: "95% of API requests complete within 200ms",
            SLI: ServiceLevelIndicator{
                Type:        "latency",
                Metric:      "http_request_duration_seconds",
                Threshold:   0.2, // 200ms
                Aggregation: "p95",
            },
            Target: SLOTarget{
                Objective:  0.95,
                TimeWindow: 30 * 24 * time.Hour, // 30 days
            },
            ErrorBudget: ErrorBudget{
                BurnRateAlert: 5.0, // Alert if burning budget 5x faster than allowed
            },
        },
        {
            Name:        "API Availability",
            Description: "99.9% of API requests succeed",
            SLI: ServiceLevelIndicator{
                Type:        "availability", 
                Metric:      "http_requests_total",
                Threshold:   0.5, // 500+ status codes are failures
                Aggregation: "rate",
            },
            Target: SLOTarget{
                Objective:  0.999,
                TimeWindow: 30 * 24 * time.Hour,
            },
        },
        {
            Name:        "Observability Overhead",
            Description: "Observability adds <5% to request latency",
            SLI: ServiceLevelIndicator{
                Type:        "performance_overhead",
                Metric:      "observability_overhead_ratio",
                Threshold:   0.05, // 5% overhead
                Aggregation: "avg",
            },
            Target: SLOTarget{
                Objective:  0.95, // 95% of time under 5% overhead
                TimeWindow: 7 * 24 * time.Hour,
            },
        },
    }
}
```

#### Performance Budget Implementation

```go
type PerformanceBudget struct {
    MaxLatencyOverhead    time.Duration `yaml:"max_latency_overhead"`    // 50ms max
    MaxMemoryOverhead     int64         `yaml:"max_memory_overhead"`     // 100MB max
    MaxCPUOverheadPercent float64       `yaml:"max_cpu_overhead_percent"` // 10% max
    MaxNetworkBandwidth   int64         `yaml:"max_network_bandwidth"`   // 10MB/s max
    
    // Sampling configuration
    TraceSamplingRate     float64       `yaml:"trace_sampling_rate"`     // 0.1 = 10%
    MetricsScrapeInterval time.Duration `yaml:"metrics_scrape_interval"` // 30s
    LogLevel              string        `yaml:"log_level"`               // "warn"
    
    // Enforcement policies
    EnforcementMode       string        `yaml:"enforcement_mode"`        // "graceful", "strict"
    DegradationStrategy   string        `yaml:"degradation_strategy"`    // "reduce_sampling", "disable_features"
}

type PerformanceMonitor struct {
    budget        PerformanceBudget
    metrics       *PerformanceMetrics
    sloManager    *SLOManager
    
    // Current measurements
    currentOverhead   *OverheadMeasurement
    baselineMetrics   *BaselineMetrics
    
    // Adaptive controls
    adaptiveSampler   *AdaptiveSampler
    circuitBreaker    *ObservabilityCircuitBreaker
}

type OverheadMeasurement struct {
    Timestamp      time.Time     `json:"timestamp"`
    LatencyOverhead time.Duration `json:"latency_overhead"`
    MemoryOverhead int64         `json:"memory_overhead"`
    CPUOverhead    float64       `json:"cpu_overhead"`
    NetworkOverhead int64        `json:"network_overhead"`
}

func NewPerformanceMonitor(budget PerformanceBudget) *PerformanceMonitor {
    return &PerformanceMonitor{
        budget:          budget,
        metrics:         NewPerformanceMetrics(),
        adaptiveSampler: NewAdaptiveSampler(budget),
        circuitBreaker:  NewObservabilityCircuitBreaker(budget),
    }
}

func (p *PerformanceMonitor) MeasureOverhead(baseline, withObs BenchmarkResult) *OverheadMeasurement {
    return &OverheadMeasurement{
        Timestamp:       time.Now(),
        LatencyOverhead: withObs.AvgLatency - baseline.AvgLatency,
        MemoryOverhead:  withObs.MemoryUsage - baseline.MemoryUsage,
        CPUOverhead:     (withObs.CPUUsage - baseline.CPUUsage) / baseline.CPUUsage,
        NetworkOverhead: withObs.NetworkIO - baseline.NetworkIO,
    }
}

func (p *PerformanceMonitor) EnforceBudget(measurement *OverheadMeasurement) error {
    violations := p.checkBudgetViolations(measurement)
    
    if len(violations) == 0 {
        return nil // Within budget
    }
    
    switch p.budget.EnforcementMode {
    case "graceful":
        return p.applyGracefulDegradation(violations)
    case "strict":
        return p.applyStrictEnforcement(violations)
    default:
        return fmt.Errorf("unknown enforcement mode: %s", p.budget.EnforcementMode)
    }
}

func (p *PerformanceMonitor) applyGracefulDegradation(violations []BudgetViolation) error {
    for _, violation := range violations {
        switch violation.Type {
        case "latency_overhead":
            // Reduce trace sampling to decrease latency impact
            newRate := p.adaptiveSampler.ReduceSampling(violation.Severity)
            p.metrics.SamplingRateAdjustments.WithLabelValues("trace", "reduced").Inc()
            
        case "memory_overhead":
            // Reduce batch sizes to decrease memory usage
            p.adaptiveSampler.ReduceBatchSize(violation.Severity)
            p.metrics.SamplingRateAdjustments.WithLabelValues("batch_size", "reduced").Inc()
            
        case "cpu_overhead":
            // Switch to async-only processing
            p.circuitBreaker.EnableAsyncMode()
            p.metrics.SamplingRateAdjustments.WithLabelValues("processing", "async_only").Inc()
            
        case "network_overhead":
            // Reduce export frequency
            p.adaptiveSampler.ReduceExportFrequency(violation.Severity)
            p.metrics.SamplingRateAdjustments.WithLabelValues("export", "reduced").Inc()
        }
    }
    
    return nil
}
```

#### Adaptive Sampling Strategy

```go
type AdaptiveSampler struct {
    currentRates    map[string]float64  // Current sampling rates by type
    budgetManager   *PerformanceBudget
    sloManager      *SLOManager
    
    // Rate limiting
    rateLimiter     *rate.Limiter
    
    // Adaptive thresholds
    latencyThreshold   time.Duration
    errorRateThreshold float64
    loadThreshold      float64
}

func (a *AdaptiveSampler) ShouldSample(ctx context.Context, spanName string) bool {
    // Always sample errors
    if a.isErrorContext(ctx) {
        return true
    }
    
    // Check SLO status
    if a.sloManager.IsErrorBudgetExhausted("API Latency") {
        // Increase sampling during SLO violations
        return a.sampleWithRate(a.currentRates["error_budget_exhausted"])
    }
    
    // Check system load
    currentLoad := a.getCurrentSystemLoad()
    if currentLoad > a.loadThreshold {
        // Reduce sampling under high load
        return a.sampleWithRate(a.currentRates["high_load"])
    }
    
    // Check rate limits
    if !a.rateLimiter.Allow() {
        return false
    }
    
    // Normal sampling
    return a.sampleWithRate(a.currentRates["normal"])
}

func (a *AdaptiveSampler) AdjustSamplingRates(sloStatus SLOStatus) {
    if sloStatus.ErrorBudgetRemaining < 0.1 { // <10% budget remaining
        // Increase observability when approaching SLO violation
        a.currentRates["normal"] = 0.5        // 50% sampling
        a.currentRates["error_budget_exhausted"] = 1.0 // 100% sampling
    } else if sloStatus.ErrorBudgetRemaining > 0.8 { // >80% budget remaining
        // Reduce observability when comfortably within SLO
        a.currentRates["normal"] = 0.01       // 1% sampling
        a.currentRates["high_load"] = 0.001   // 0.1% under load
    } else {
        // Standard rates
        a.currentRates["normal"] = 0.1        // 10% sampling
        a.currentRates["high_load"] = 0.05    // 5% under load
    }
}
```

### SLO Monitoring and Alerting

#### Error Budget Calculation

```go
type SLOManager struct {
    slos        []ServiceLevelObjective
    metricStore MetricStore
    alertManager AlertManager
}

func (s *SLOManager) CalculateErrorBudget(slo ServiceLevelObjective) (*ErrorBudget, error) {
    timeWindow := slo.Target.TimeWindow
    startTime := time.Now().Add(-timeWindow)
    
    // Query metrics for the SLI
    total, err := s.metricStore.QueryCount(slo.SLI.Metric, startTime, time.Now())
    if err != nil {
        return nil, fmt.Errorf("failed to query total: %w", err)
    }
    
    good, err := s.metricStore.QueryGoodCount(slo.SLI.Metric, slo.SLI.Threshold, startTime, time.Now())
    if err != nil {
        return nil, fmt.Errorf("failed to query good: %w", err)
    }
    
    // Calculate current reliability
    currentReliability := float64(good) / float64(total)
    
    // Calculate error budget
    allowedFailures := float64(total) * (1.0 - slo.Target.Objective)
    actualFailures := float64(total - good)
    
    remainingBudget := (allowedFailures - actualFailures) / allowedFailures
    if remainingBudget < 0 {
        remainingBudget = 0 // Budget exhausted
    }
    
    // Calculate burn rate (failures per hour vs allowed failures per hour)
    hoursInWindow := timeWindow.Hours()
    allowedFailuresPerHour := allowedFailures / hoursInWindow
    
    recentFailures, _ := s.metricStore.QueryFailureCount(slo.SLI.Metric, time.Now().Add(-time.Hour), time.Now())
    currentBurnRate := float64(recentFailures) / allowedFailuresPerHour
    
    return &ErrorBudget{
        Remaining:     remainingBudget,
        BurnRate:      currentBurnRate,
        BurnRateAlert: slo.ErrorBudget.BurnRateAlert,
    }, nil
}

func (s *SLOManager) CheckSLOViolations() ([]SLOViolation, error) {
    var violations []SLOViolation
    
    for _, slo := range s.slos {
        budget, err := s.CalculateErrorBudget(slo)
        if err != nil {
            continue
        }
        
        // Check for budget exhaustion
        if budget.Remaining <= 0 {
            violations = append(violations, SLOViolation{
                SLOName:   slo.Name,
                Type:      "budget_exhausted", 
                Severity:  "critical",
                Message:   fmt.Sprintf("Error budget exhausted for %s", slo.Name),
                Budget:    budget,
            })
        }
        
        // Check for high burn rate
        if budget.BurnRate > budget.BurnRateAlert {
            violations = append(violations, SLOViolation{
                SLOName:  slo.Name,
                Type:     "high_burn_rate",
                Severity: "warning",
                Message:  fmt.Sprintf("High burn rate %.2fx for %s", budget.BurnRate, slo.Name),
                Budget:   budget,
            })
        }
    }
    
    return violations, nil
}
```

#### Performance Regression Detection

```go
type PerformanceRegression struct {
    detector *RegressionDetector
    baseline *PerformanceBaseline
    metrics  *PerformanceMetrics
}

type PerformanceBaseline struct {
    LatencyP50  time.Duration `json:"latency_p50"`
    LatencyP95  time.Duration `json:"latency_p95"`
    LatencyP99  time.Duration `json:"latency_p99"`
    Throughput  float64       `json:"throughput"`
    ErrorRate   float64       `json:"error_rate"`
    CPUUsage    float64       `json:"cpu_usage"`
    MemoryUsage int64         `json:"memory_usage"`
    Timestamp   time.Time     `json:"timestamp"`
}

func (p *PerformanceRegression) DetectRegression(current *PerformanceBaseline) (*RegressionReport, error) {
    if p.baseline == nil {
        return nil, fmt.Errorf("no baseline established")
    }
    
    report := &RegressionReport{
        Timestamp: time.Now(),
        Baseline:  p.baseline,
        Current:   current,
    }
    
    // Check latency regression (>20% increase in p95)
    latencyIncrease := float64(current.LatencyP95-p.baseline.LatencyP95) / float64(p.baseline.LatencyP95)
    if latencyIncrease > 0.2 {
        report.Regressions = append(report.Regressions, Regression{
            Metric:     "latency_p95",
            Baseline:   float64(p.baseline.LatencyP95.Milliseconds()),
            Current:    float64(current.LatencyP95.Milliseconds()),
            Increase:   latencyIncrease,
            Severity:   p.calculateSeverity(latencyIncrease),
        })
    }
    
    // Check throughput regression (>10% decrease)
    throughputDecrease := (p.baseline.Throughput - current.Throughput) / p.baseline.Throughput
    if throughputDecrease > 0.1 {
        report.Regressions = append(report.Regressions, Regression{
            Metric:     "throughput",
            Baseline:   p.baseline.Throughput,
            Current:    current.Throughput,
            Increase:   -throughputDecrease, // Negative because it's a decrease
            Severity:   p.calculateSeverity(throughputDecrease),
        })
    }
    
    // Check memory regression (>50% increase)
    memoryIncrease := float64(current.MemoryUsage-p.baseline.MemoryUsage) / float64(p.baseline.MemoryUsage)
    if memoryIncrease > 0.5 {
        report.Regressions = append(report.Regressions, Regression{
            Metric:     "memory_usage",
            Baseline:   float64(p.baseline.MemoryUsage),
            Current:    float64(current.MemoryUsage),
            Increase:   memoryIncrease,
            Severity:   p.calculateSeverity(memoryIncrease),
        })
    }
    
    return report, nil
}
```

### Automated Performance Testing

#### Continuous Performance Monitoring

```bash
#!/bin/bash
# scripts/performance-monitor.sh

set -e

echo "🏃 Running continuous performance monitoring..."

# Establish baseline without observability
echo "Measuring baseline performance..."
make bench-baseline > baseline.txt

# Measure with observability enabled
echo "Measuring performance with observability..."
make bench-observability > observability.txt

# Calculate overhead
python3 scripts/calculate-overhead.py baseline.txt observability.txt > overhead-report.json

# Check against performance budget
if python3 scripts/check-budget.py overhead-report.json performance-budget.yaml; then
    echo "✅ Performance within budget"
else
    echo "❌ Performance budget exceeded"
    cat overhead-report.json
    exit 1
fi

# Update performance baseline if significant improvement
python3 scripts/update-baseline.py overhead-report.json
```

#### Load Test Integration

```go
func TestObservabilityUnderLoad(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping load test in short mode")
    }
    
    // Start observability stack
    obs, cleanup := setupObservability(t)
    defer cleanup()
    
    // Create test server with observability
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        ctx := r.Context()
        
        // Add observability overhead
        logger := log.LoggerFromContext(ctx)
        logger.InfoCtx(ctx, "handling request", "path", r.URL.Path)
        
        // Simulate work
        time.Sleep(10 * time.Millisecond)
        
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("OK"))
    }))
    defer server.Close()
    
    // Run load test
    loadTestConfig := LoadTestConfig{
        Duration:       30 * time.Second,
        RPS:           100,
        MaxLatency:    100 * time.Millisecond,
        MaxErrorRate:  0.01, // 1%
    }
    
    results, err := RunLoadTest(server.URL, loadTestConfig)
    require.NoError(t, err)
    
    // Verify performance is within budget
    assert.LessOrEqual(t, results.P95Latency, 100*time.Millisecond, "P95 latency exceeded budget")
    assert.LessOrEqual(t, results.ErrorRate, 0.01, "Error rate exceeded budget")
    
    // Measure observability overhead
    overhead := MeasureObservabilityOverhead(results)
    assert.LessOrEqual(t, overhead.LatencyIncrease, 0.15, "Latency overhead >15%")
    assert.LessOrEqual(t, overhead.MemoryIncrease, 0.25, "Memory overhead >25%")
}
```

### Cost Optimization

#### Cost-Performance Trade-offs

```yaml
# Performance budget configuration with cost optimization
performance_budgets:
  development:
    max_latency_overhead: "100ms"     # Higher overhead acceptable
    trace_sampling_rate: 1.0          # 100% sampling for debugging
    log_level: "debug"                # Verbose logging
    metrics_scrape_interval: "5s"     # High frequency
    cost_priority: "observability"    # Favor observability over cost
    
  staging:
    max_latency_overhead: "50ms"      # Moderate overhead
    trace_sampling_rate: 0.3          # 30% sampling
    log_level: "info"                 # Standard logging
    metrics_scrape_interval: "15s"    # Moderate frequency
    cost_priority: "balanced"         # Balance cost and observability
    
  production:
    max_latency_overhead: "20ms"      # Strict overhead limits
    trace_sampling_rate: 0.05         # 5% sampling
    log_level: "warn"                 # Error logging only
    metrics_scrape_interval: "30s"    # Lower frequency
    cost_priority: "performance"      # Favor performance over observability
    
    # Adaptive rules
    adaptive_sampling:
      enabled: true
      slo_based: true
      error_boost: 10x                # 10x sampling on errors
      incident_boost: 100x            # 100x sampling during incidents
```

### Consequences

**Positive:**

- **Predictable performance**: Observability overhead stays within defined budgets
- **SLO alignment**: Performance management aligns with business objectives
- **Cost optimization**: Automatic cost control through adaptive sampling
- **Incident readiness**: Increased observability during problems
- **Performance transparency**: Clear measurement and reporting of overhead

**Negative:**

- **Implementation complexity**: Requires sophisticated monitoring and control systems
- **Reduced observability**: May miss events during budget enforcement
- **Configuration overhead**: Multiple budget configurations to maintain
- **False positives**: Performance budget alerts may fire unnecessarily

**Mitigation Strategies:**

- **Graceful degradation**: Reduce sampling before disabling observability
- **SLO-driven priorities**: Increase observability when approaching violations
- **Emergency overrides**: Manual override for critical debugging sessions
- **Comprehensive testing**: Regular load testing to validate budget settings

### Related ADRs

- [ADR-0004: Metric Cardinality Budget](#adr-0004-metric-cardinality-budget) - Cost control through cardinality
- [ADR-0008: GCP-First Cloud Strategy](#adr-0008-gcp-first-cloud) - Cloud cost optimization
- [ADR-0011: Signal Access Control](#adr-0011-signal-access-retention) - Access control for performance-sensitive data

### References

- [Google SRE: Service Level Objectives](https://sre.google/sre-book/service-level-objectives/)
- [Site Reliability Engineering: Error Budgets](https://sre.google/sre-book/embracing-risk/)
- [The Art of SLOs](https://www.usenix.org/conference/srecon18americas/presentation/hidalgo)
- [OpenTelemetry Performance](https://opentelemetry.io/docs/concepts/performance/)
