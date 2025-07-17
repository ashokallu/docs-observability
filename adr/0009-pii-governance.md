# ADR-0009: PII Governance & Tiered Exposure Controls

**Status:** Accepted  
**Date:** 2025-07-17  
**Tags:** privacy, pii, gdpr, compliance, security

## Context

Personal Identifiable Information (PII) in observability data creates regulatory compliance risks and privacy concerns. Different environments and use cases require different levels of PII exposure while maintaining debugging and operational capabilities.

### Problem Statement

Observability systems commonly collect PII in logs, traces, and metrics:

- **User identifiers**: Email addresses, user IDs, session tokens
- **Request data**: IP addresses, user agents, authentication headers
- **Business data**: Names, addresses, payment information
- **System data**: Error messages containing user input

Regulatory requirements vary by jurisdiction:

- **GDPR**: Right to erasure, data minimization, consent requirements
- **CCPA**: Right to delete, opt-out requirements
- **HIPAA**: Protected health information controls
- **SOC2**: Data classification and access controls

Current challenges:

- **Inconsistent handling**: No standard approach to PII in telemetry
- **Environment differences**: Production vs development PII requirements differ
- **Debugging needs**: Engineers need sufficient context for troubleshooting
- **Compliance audits**: Must demonstrate appropriate data handling

### Forces & Considerations

| Approach | Debugging Capability | Compliance Risk | Implementation Complexity | Performance Impact |
|----------|---------------------|-----------------|---------------------------|-------------------|
| **No PII** | Low | None | Low | None |
| **Full PII** | High | High | Low | None |
| **Redacted PII** | Medium | Low | Medium | Low |
| **Tiered Control** | Variable | Low | High | Low |

### Options Considered

#### Option 1: No PII in Observability (Rejected)

Completely exclude all PII from logs, traces, and metrics.

**Pros:**

- Zero compliance risk
- Simple implementation
- No privacy concerns

**Cons:**

- Severely limited debugging capability
- Cannot correlate user-specific issues
- Poor incident response capability

#### Option 2: Full PII Everywhere (Rejected)

Include all PII in observability data.

**Pros:**

- Maximum debugging capability
- Rich user context for analysis
- Simple implementation

**Cons:**

- High regulatory compliance risk
- Privacy violations
- Potential data breaches

#### Option 3: Environment-Based Controls (Rejected)

Different PII handling per environment only.

**Pros:**

- Development flexibility
- Production protection
- Moderate complexity

**Cons:**

- Binary choice limits flexibility
- No fine-grained control
- Difficult compliance demonstration

#### Option 4: Tiered PII Exposure Controls (Chosen)

Configurable PII exposure levels with automatic enforcement.

**Pros:**

- Flexible for different use cases
- Compliance-friendly with audit trails
- Balances debugging and privacy
- Environment-specific configurations

**Cons:**

- Higher implementation complexity
- Requires training and governance
- Performance overhead for redaction

### Decision

**Implement tiered PII exposure controls with environment-specific defaults and audit capabilities.**

### PII Classification Framework

#### PII Categories and Treatment

```go
type PIICategory int

const (
    PIINone PIICategory = iota      // No PII - safe for all uses
    PIILow                         // Low-risk identifiers (user_id, session_id)  
    PIIMedium                      // Medium-risk data (email domain, IP subnet)
    PIIHigh                        // High-risk data (email, phone, name)
    PIICritical                    // Critical data (SSN, payment info, health data)
)

type PIIExposureLevel int

const (
    ExposureNone PIIExposureLevel = iota    // No PII exposed
    ExposureLow                             // Only low-risk PII
    ExposureMedium                          // Low + medium-risk PII  
    ExposureHigh                            // Low + medium + high-risk PII
    ExposureFull                            // All PII (development only)
)

// Field classification mapping
var piiClassification = map[string]PIICategory{
    // Safe fields
    "user_id":          PIILow,     // System-generated, minimal risk
    "session_id":       PIILow,     // Temporary, system-generated
    "request_id":       PIINone,    // System-generated, no personal data
    "trace_id":         PIINone,    // System-generated, no personal data
    
    // Medium-risk fields  
    "email_domain":     PIIMedium,  // Organizational affiliation
    "ip_subnet":        PIIMedium,  // Geographic region indicator
    "user_agent_class": PIIMedium,  // Device type without specifics
    
    // High-risk fields
    "email":            PIIHigh,    // Direct personal identifier
    "ip_address":       PIIHigh,    // Can identify individual users
    "user_agent":       PIIHigh,    // Device fingerprinting possible
    "phone":            PIIHigh,    // Direct personal identifier
    "name":             PIIHigh,    // Personal identifier
    
    // Critical fields - never log
    "ssn":              PIICritical, // Government identifier
    "credit_card":      PIICritical, // Financial data
    "password":         PIICritical, // Authentication data
    "api_key":          PIICritical, // System credentials
}
```

#### Environment-Specific PII Policies

```go
type PIIPolicy struct {
    Environment     string            `yaml:"environment"`
    ExposureLevel   PIIExposureLevel  `yaml:"exposure_level"`
    RetentionDays   int               `yaml:"retention_days"`
    
    // Field-specific overrides
    FieldOverrides  map[string]PIIExposureLevel `yaml:"field_overrides"`
    
    // Redaction rules
    RedactionRules  []RedactionRule   `yaml:"redaction_rules"`
    
    // Audit requirements
    AuditLogging    bool              `yaml:"audit_logging"`
    AccessLogging   bool              `yaml:"access_logging"`
}

// Default policies by environment
func DefaultPIIPolicies() map[string]PIIPolicy {
    return map[string]PIIPolicy{
        "development": {
            Environment:   "development",
            ExposureLevel: ExposureFull,        // Full PII for debugging
            RetentionDays: 7,                   // Short retention
            AuditLogging:  false,               // No audit overhead
            AccessLogging: false,
        },
        "testing": {
            Environment:   "testing", 
            ExposureLevel: ExposureMedium,      // Limited PII for realistic testing
            RetentionDays: 3,                   // Very short retention
            AuditLogging:  true,                // Audit test data access
            AccessLogging: true,
        },
        "staging": {
            Environment:   "staging",
            ExposureLevel: ExposureLow,         // Minimal PII
            RetentionDays: 14,                  // Short retention
            AuditLogging:  true,                // Audit access
            AccessLogging: true,
            FieldOverrides: map[string]PIIExposureLevel{
                "email": ExposureNone,          // No emails in staging
            },
        },
        "production": {
            Environment:   "production",
            ExposureLevel: ExposureLow,         // Minimal PII only
            RetentionDays: 30,                  // Business requirement retention
            AuditLogging:  true,                // Full audit trail
            AccessLogging: true,
            FieldOverrides: map[string]PIIExposureLevel{
                "email":      ExposureNone,     // No emails in production logs
                "ip_address": ExposureNone,     // No IP addresses
                "user_agent": ExposureNone,     // No user agents
            },
            RedactionRules: []RedactionRule{
                {
                    Field:   "error_message",
                    Pattern: regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
                    Replace: func(s string) string { return "[EMAIL_REDACTED]" },
                },
                {
                    Field:   "request_body", 
                    Pattern: regexp.MustCompile(`"password":\s*"[^"]*"`),
                    Replace: func(s string) string { return `"password":"[REDACTED]"` },
                },
            },
        },
    }
}
```

### Implementation Strategy

#### PII-Aware Logging Framework

```go
// internal/platform/obs/log/pii.go
type PIIController struct {
    policy      PIIPolicy
    classifier  *PIIClassifier
    redactor    *PIIRedactor
    auditor     *PIIAuditor
}

func NewPIIController(policy PIIPolicy) *PIIController {
    return &PIIController{
        policy:     policy,
        classifier: NewPIIClassifier(piiClassification),
        redactor:   NewPIIRedactor(policy.RedactionRules),
        auditor:    NewPIIAuditor(policy.AuditLogging),
    }
}

func (p *PIIController) ProcessLogFields(fields map[string]interface{}) map[string]interface{} {
    processed := make(map[string]interface{})
    
    for key, value := range fields {
        category := p.classifier.ClassifyField(key, value)
        
        // Check if field is allowed based on policy
        if p.isFieldAllowed(key, category) {
            // Apply redaction if needed
            processed[key] = p.redactor.RedactValue(key, value)
            
            // Audit PII access
            if category >= PIIMedium {
                p.auditor.LogPIIAccess(key, category, "logged")
            }
        } else {
            // Field not allowed at current exposure level
            processed[key] = "[PII_REDACTED]"
            p.auditor.LogPIIAccess(key, category, "redacted")
        }
    }
    
    return processed
}

func (p *PIIController) isFieldAllowed(field string, category PIICategory) bool {
    // Check field-specific overrides first
    if override, exists := p.policy.FieldOverrides[field]; exists {
        return category <= PIICategory(override)
    }
    
    // Use general exposure level
    return category <= PIICategory(p.policy.ExposureLevel)
}
```

#### Smart PII Detection

```go
type PIIClassifier struct {
    fieldMap    map[string]PIICategory
    patterns    []PIIPattern
}

type PIIPattern struct {
    Name     string
    Pattern  *regexp.Regexp
    Category PIICategory
}

func NewPIIClassifier(fieldMap map[string]PIICategory) *PIIClassifier {
    patterns := []PIIPattern{
        {
            Name:     "email",
            Pattern:  regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
            Category: PIIHigh,
        },
        {
            Name:     "phone",
            Pattern:  regexp.MustCompile(`\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`),
            Category: PIIHigh,
        },
        {
            Name:     "ssn",
            Pattern:  regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
            Category: PIICritical,
        },
        {
            Name:     "credit_card",
            Pattern:  regexp.MustCompile(`\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`),
            Category: PIICritical,
        },
        {
            Name:     "ip_address",
            Pattern:  regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`),
            Category: PIIHigh,
        },
    }
    
    return &PIIClassifier{
        fieldMap: fieldMap,
        patterns: patterns,
    }
}

func (c *PIIClassifier) ClassifyField(field string, value interface{}) PIICategory {
    // Check explicit field mapping first
    if category, exists := c.fieldMap[field]; exists {
        return category
    }
    
    // Convert value to string for pattern matching
    strValue := fmt.Sprintf("%v", value)
    
    // Check content patterns
    highestCategory := PIINone
    for _, pattern := range c.patterns {
        if pattern.Pattern.MatchString(strValue) {
            if pattern.Category > highestCategory {
                highestCategory = pattern.Category
            }
        }
    }
    
    return highestCategory
}
```

#### Audit Trail Implementation

```go
type PIIAuditor struct {
    enabled   bool
    logger    log.Logger
    retention time.Duration
}

type PIIAuditEvent struct {
    Timestamp   time.Time     `json:"timestamp"`
    Field       string        `json:"field"`
    Category    PIICategory   `json:"category"`
    Action      string        `json:"action"`  // "logged", "redacted", "accessed"
    UserID      string        `json:"user_id,omitempty"`
    RequestID   string        `json:"request_id,omitempty"`
    Environment string        `json:"environment"`
}

func (a *PIIAuditor) LogPIIAccess(field string, category PIICategory, action string) {
    if !a.enabled {
        return
    }
    
    event := PIIAuditEvent{
        Timestamp:   time.Now(),
        Field:       field,
        Category:    category,
        Action:      action,
        Environment: os.Getenv("ENVIRONMENT"),
    }
    
    // Add context if available
    if ctx := context.Background(); ctx != nil {
        if userID := log.UserIDFromContext(ctx); userID != "" {
            event.UserID = userID
        }
        if requestID := log.RequestIDFromContext(ctx); requestID != "" {
            event.RequestID = requestID
        }
    }
    
    // Log to dedicated audit stream
    a.logger.InfoCtx(context.Background(), "pii_audit",
        "audit_event", event,
        "audit_type", "pii_access",
    )
}
```

### Configuration and Deployment

#### Environment Configuration

```yaml
# config/pii-policies.yml
environments:
  development:
    exposure_level: full
    retention_days: 7
    audit_logging: false
    access_logging: false
    
  testing:
    exposure_level: medium
    retention_days: 3
    audit_logging: true
    access_logging: true
    field_overrides:
      email: none  # Use synthetic emails in testing
      
  staging:
    exposure_level: low
    retention_days: 14
    audit_logging: true
    access_logging: true
    field_overrides:
      email: none
      ip_address: none
      
  production:
    exposure_level: low
    retention_days: 30
    audit_logging: true
    access_logging: true
    field_overrides:
      email: none
      ip_address: none
      user_agent: none
    redaction_rules:
      - field: "error_message"
        pattern: "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b"
        replacement: "[EMAIL_REDACTED]"
      - field: "*"
        pattern: "password\":\\s*\"[^\"]*\""
        replacement: "password\":\"[REDACTED]\""
```

#### Application Integration

```go
// cmd/api/main.go - Application startup with PII controls
func main() {
    // Load environment-specific PII policy
    env := os.Getenv("ENVIRONMENT")
    piiPolicies := LoadPIIPolicies("config/pii-policies.yml")
    piiPolicy := piiPolicies[env]
    
    // Initialize PII-aware logging
    logConfig := log.Config{
        Format:      log.FormatJSON,
        Level:       slog.LevelInfo,
        PIIPolicy:   piiPolicy,
    }
    
    logger := log.NewLogger(logConfig)
    
    // Initialize observability with PII controls
    obs, err := observability.New(observability.Config{
        Logger:    logger,
        PIIPolicy: piiPolicy,
    })
    if err != nil {
        log.Fatal("Failed to initialize observability:", err)
    }
    
    // Start application with PII-aware middleware
    server := api.NewServer(obs)
    server.Start()
}
```

### Compliance Features

#### Data Subject Rights Implementation

```go
// internal/platform/obs/compliance/rights.go
type DataSubjectRights struct {
    logger   log.Logger
    storage  ObservabilityStorage
    auditor  *PIIAuditor
}

func (d *DataSubjectRights) ProcessErasureRequest(userID string) error {
    d.auditor.LogPIIAccess("user_id", PIILow, "erasure_requested")
    
    // Find all observability data for user
    logs, err := d.storage.FindLogsByUserID(userID)
    if err != nil {
        return fmt.Errorf("failed to find logs: %w", err)
    }
    
    traces, err := d.storage.FindTracesByUserID(userID)
    if err != nil {
        return fmt.Errorf("failed to find traces: %w", err)
    }
    
    // Remove or anonymize data
    for _, logEntry := range logs {
        if err := d.storage.DeleteLog(logEntry.ID); err != nil {
            return fmt.Errorf("failed to delete log: %w", err)
        }
    }
    
    for _, trace := range traces {
        if err := d.storage.AnonymizeTrace(trace.ID); err != nil {
            return fmt.Errorf("failed to anonymize trace: %w", err)
        }
    }
    
    d.auditor.LogPIIAccess("user_id", PIILow, "erasure_completed")
    return nil
}

func (d *DataSubjectRights) ProcessAccessRequest(userID string) (*DataSubjectReport, error) {
    d.auditor.LogPIIAccess("user_id", PIILow, "access_requested")
    
    report := &DataSubjectReport{
        UserID:    userID,
        Timestamp: time.Now(),
    }
    
    // Collect all data for user
    logs, _ := d.storage.FindLogsByUserID(userID)
    traces, _ := d.storage.FindTracesByUserID(userID)
    
    report.LogCount = len(logs)
    report.TraceCount = len(traces)
    report.DataCategories = d.categorizeData(logs, traces)
    
    d.auditor.LogPIIAccess("user_id", PIILow, "access_completed")
    return report, nil
}
```

#### Automated Data Retention

```go
// internal/platform/obs/retention/manager.go
type RetentionManager struct {
    policies []RetentionPolicy
    storage  ObservabilityStorage
    logger   log.Logger
}

type RetentionPolicy struct {
    Environment   string        `yaml:"environment"`
    DataType      string        `yaml:"data_type"`  // "logs", "traces", "metrics"
    RetentionDays int           `yaml:"retention_days"`
    PIICategory   PIICategory   `yaml:"pii_category"`
}

func (r *RetentionManager) EnforceRetention() error {
    for _, policy := range r.policies {
        cutoffDate := time.Now().AddDate(0, 0, -policy.RetentionDays)
        
        switch policy.DataType {
        case "logs":
            deleted, err := r.storage.DeleteLogsOlderThan(cutoffDate, policy.PIICategory)
            if err != nil {
                return fmt.Errorf("failed to delete old logs: %w", err)
            }
            r.logger.InfoCtx(context.Background(), "retention policy enforced",
                "data_type", "logs",
                "environment", policy.Environment,
                "deleted_count", deleted,
                "cutoff_date", cutoffDate,
            )
            
        case "traces":
            deleted, err := r.storage.DeleteTracesOlderThan(cutoffDate, policy.PIICategory)
            if err != nil {
                return fmt.Errorf("failed to delete old traces: %w", err)
            }
            r.logger.InfoCtx(context.Background(), "retention policy enforced",
                "data_type", "traces",
                "environment", policy.Environment, 
                "deleted_count", deleted,
                "cutoff_date", cutoffDate,
            )
        }
    }
    
    return nil
}
```

### Testing and Validation

#### PII Policy Testing

```go
func TestPIIController_ProcessLogFields(t *testing.T) {
    tests := []struct {
        name           string
        policy         PIIPolicy
        input          map[string]interface{}
        expected       map[string]interface{}
        expectRedacted []string
    }{
        {
            name: "production policy redacts emails",
            policy: PIIPolicy{
                Environment:   "production",
                ExposureLevel: ExposureLow,
                FieldOverrides: map[string]PIIExposureLevel{
                    "email": ExposureNone,
                },
            },
            input: map[string]interface{}{
                "user_id": "user123",
                "email":   "user@example.com",
                "action":  "login",
            },
            expected: map[string]interface{}{
                "user_id": "user123",
                "email":   "[PII_REDACTED]",
                "action":  "login",
            },
            expectRedacted: []string{"email"},
        },
        {
            name: "development policy allows all PII",
            policy: PIIPolicy{
                Environment:   "development",
                ExposureLevel: ExposureFull,
            },
            input: map[string]interface{}{
                "user_id": "user123",
                "email":   "user@example.com",
                "ip":      "192.168.1.100",
            },
            expected: map[string]interface{}{
                "user_id": "user123",
                "email":   "user@example.com", 
                "ip":      "192.168.1.100",
            },
            expectRedacted: []string{},
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            controller := NewPIIController(tt.policy)
            result := controller.ProcessLogFields(tt.input)
            
            assert.Equal(t, tt.expected, result)
            
            // Verify audit trail
            for _, field := range tt.expectRedacted {
                // Check that redacted fields were audited
                // Implementation depends on audit system
            }
        })
    }
}
```

#### Compliance Validation

```bash
#!/bin/bash
# scripts/validate-pii-compliance.sh

echo "🔒 Validating PII compliance..."

# Check production logs for PII leakage
echo "Checking production logs for PII patterns..."
if grep -r "user@.*\.com\|[0-9]{3}-[0-9]{2}-[0-9]{4}" logs/production/ 2>/dev/null; then
    echo "❌ Found potential PII in production logs"
    exit 1
fi

# Validate audit trail completeness
echo "Validating audit trail..."
python3 scripts/audit-validator.py --environment production --days 7

# Check retention policy enforcement
echo "Checking data retention compliance..."
python3 scripts/retention-validator.py --check-all-environments

echo "✅ PII compliance validation passed"
```

### Consequences

**Positive:**

- **Regulatory compliance**: Meets GDPR, CCPA, HIPAA requirements with demonstrable controls
- **Flexible debugging**: Configurable PII exposure balances debugging needs with privacy
- **Audit readiness**: Complete audit trail for compliance demonstrations
- **Automated enforcement**: Reduces human error in PII handling
- **Data subject rights**: Built-in support for erasure and access requests

**Negative:**

- **Implementation complexity**: Requires sophisticated classification and redaction systems
- **Performance overhead**: PII detection and redaction adds processing time
- **Configuration management**: Multiple environment configurations need maintenance
- **Training requirements**: Engineers need education on PII handling policies

**Mitigation Strategies:**

- **Automated testing**: Comprehensive test suite for PII policy enforcement
- **Performance optimization**: Efficient redaction algorithms and caching
- **Configuration validation**: Automated checks for policy consistency
- **Documentation and training**: Clear guidelines and regular training sessions

### Related ADRs

- [ADR-0003: Context-First Propagation](#adr-0003-context-first-propagation) - PII flows through context
- [ADR-0005: Error Classification](#adr-0005-error-classification) - Errors may contain PII
- [ADR-0011: Signal Access Control](#adr-0011-signal-access-retention) - Access control includes PII protection

### References

- [GDPR Article 17: Right to Erasure](https://gdpr-info.eu/art-17-gdpr/)
- [CCPA Privacy Rights](https://oag.ca.gov/privacy/ccpa)
- [NIST Privacy Framework](https://www.nist.gov/privacy-framework)
- [OWASP Data Classification](https://owasp.org/www-project-data-security-top-10/)
