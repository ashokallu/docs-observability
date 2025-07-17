# ADR-0011: Signal Access Control & Data Retention Governance

**Status:** Draft  
**Date:** 2025-07-17  
**Tags:** security, access-control, retention, governance, rbac

## Context

Observability data contains sensitive operational and business information requiring access controls and retention policies. Different roles need different levels of access to logs, metrics, and traces while maintaining audit trails and compliance requirements.

### Problem Statement

Observability systems often lack proper access controls:

- **Unrestricted access**: Engineers can access all telemetry data regardless of necessity
- **No audit trails**: No tracking of who accessed what observability data when  
- **Indefinite retention**: Telemetry data stored indefinitely without business justification
- **Compliance gaps**: No data classification or handling procedures for observability data
- **Incident access**: Emergency access procedures poorly defined or non-existent

Access control challenges:

- **Role definition**: What observability data should different roles access?
- **Incident escalation**: How to provide emergency access during outages?
- **Audit requirements**: What access needs to be logged and monitored?
- **Data sensitivity**: How to classify and protect different types of telemetry?
- **Cross-team access**: How to enable collaboration while maintaining security?

### Forces & Considerations

| Approach | Security | Usability | Compliance | Operational Overhead |
|----------|----------|-----------|------------|---------------------|
| **Open Access** | Low | High | Poor | Low |
| **Role-Based** | Medium | Medium | Good | Medium |
| **Attribute-Based** | High | Medium | Excellent | High |
| **Just-in-Time** | High | Low | Excellent | High |

### Options Considered

#### Option 1: Unrestricted Access (Rejected)

All engineers have access to all observability data.

**Pros:**

- Simple implementation
- No access delays during incidents
- Maximum debugging capability

**Cons:**

- High security risk
- No compliance capabilities
- Potential PII exposure
- No audit trail

#### Option 2: Basic Role-Based Access (Rejected)

Simple roles like "read-only" and "admin".

**Pros:**

- Simple to implement
- Basic protection
- Easy to understand

**Cons:**

- Too coarse-grained
- Doesn't align with operational needs
- Limited compliance support

#### Option 3: Attribute-Based Access Control (Rejected)

Fine-grained access based on multiple attributes.

**Pros:**

- Very flexible
- Precise access control
- Strong compliance support

**Cons:**

- Complex to implement
- Difficult to manage
- High operational overhead

#### Option 4: Tiered RBAC with Emergency Access (Chosen)

Role-based access with emergency escalation and audit trails.

**Pros:**

- Balances security and usability
- Supports incident response
- Compliance-ready with audit trails
- Manageable operational overhead

**Cons:**

- Moderate implementation complexity
- Requires role management processes
- Emergency access needs governance

### Decision

**Implement tiered role-based access control with emergency escalation procedures and comprehensive audit trails.**

### Access Control Framework

#### Role Hierarchy and Permissions

```go
type ObservabilityRole string

const (
    RoleViewer         ObservabilityRole = "viewer"           // Read dashboards only
    RoleDeveloper      ObservabilityRole = "developer"       // Read logs/traces for owned services
    RoleOperator       ObservabilityRole = "operator"        // Read all operational data
    RoleIncidentCmdr   ObservabilityRole = "incident_commander" // Full access during incidents
    RoleSRE            ObservabilityRole = "sre"             // Full access + retention management
    RoleSecurityAuditor ObservabilityRole = "security_auditor" // Audit trail access only
    RoleAdmin          ObservabilityRole = "admin"           // Full system administration
)

type AccessPermission struct {
    Resource    string   `json:"resource"`     // "logs", "traces", "metrics", "dashboards"
    Actions     []string `json:"actions"`      // "read", "write", "delete", "export"
    Conditions  []string `json:"conditions"`   // "own_services", "time_limited", "emergency_only"
    Constraints map[string]interface{} `json:"constraints"` // Additional constraints
}

type RoleDefinition struct {
    Name         ObservabilityRole   `yaml:"name"`
    Description  string              `yaml:"description"`
    Permissions  []AccessPermission  `yaml:"permissions"`
    MaxDuration  *time.Duration      `yaml:"max_duration,omitempty"`  // Session duration limit
    RequiresMFA  bool                `yaml:"requires_mfa"`
    AuditLevel   string              `yaml:"audit_level"`  // "basic", "detailed", "full"
}

func DefaultRoleDefinitions() map[ObservabilityRole]RoleDefinition {
    return map[ObservabilityRole]RoleDefinition{
        RoleViewer: {
            Name:        RoleViewer,
            Description: "View pre-built dashboards and basic metrics",
            Permissions: []AccessPermission{
                {
                    Resource: "dashboards",
                    Actions:  []string{"read"},
                },
                {
                    Resource: "metrics",
                    Actions:  []string{"read"},
                    Conditions: []string{"aggregated_only"}, // No raw metrics
                },
            },
            RequiresMFA: false,
            AuditLevel:  "basic",
        },
        
        RoleDeveloper: {
            Name:        RoleDeveloper,
            Description: "Access logs and traces for owned services during business hours",
            Permissions: []AccessPermission{
                {
                    Resource: "logs",
                    Actions:  []string{"read"},
                    Conditions: []string{"own_services", "business_hours"},
                    Constraints: map[string]interface{}{
                        "max_time_range": "24h",
                        "pii_redacted":   true,
                    },
                },
                {
                    Resource: "traces",
                    Actions:  []string{"read"},
                    Conditions: []string{"own_services", "business_hours"},
                    Constraints: map[string]interface{}{
                        "max_time_range": "24h",
                        "pii_redacted":   true,
                    },
                },
                {
                    Resource: "metrics",
                    Actions:  []string{"read"},
                    Conditions: []string{"own_services"},
                },
            },
            MaxDuration: durationPtr(8 * time.Hour), // 8-hour sessions
            RequiresMFA: false,
            AuditLevel:  "detailed",
        },
        
        RoleOperator: {
            Name:        RoleOperator,
            Description: "Full operational access to all observability data",
            Permissions: []AccessPermission{
                {
                    Resource: "logs",
                    Actions:  []string{"read"},
                    Constraints: map[string]interface{}{
                        "max_time_range": "7d",
                        "pii_redacted":   true,
                    },
                },
                {
                    Resource: "traces", 
                    Actions:  []string{"read"},
                    Constraints: map[string]interface{}{
                        "max_time_range": "7d",
                        "pii_redacted":   true,
                    },
                },
                {
                    Resource: "metrics",
                    Actions:  []string{"read"},
                },
                {
                    Resource: "dashboards",
                    Actions:  []string{"read", "write"},
                },
            },
            MaxDuration: durationPtr(12 * time.Hour),
            RequiresMFA: true,
            AuditLevel:  "full",
        },
        
        RoleIncidentCmdr: {
            Name:        RoleIncidentCmdr,
            Description: "Emergency access during active incidents",
            Permissions: []AccessPermission{
                {
                    Resource: "logs",
                    Actions:  []string{"read"},
                    Conditions: []string{"active_incident"},
                    Constraints: map[string]interface{}{
                        "max_time_range": "30d",
                        "pii_exposure":   "medium", // Elevated PII access for debugging
                    },
                },
                {
                    Resource: "traces",
                    Actions:  []string{"read"},
                    Conditions: []string{"active_incident"},
                    Constraints: map[string]interface{}{
                        "max_time_range": "30d",
                        "pii_exposure":   "medium",
                    },
                },
                {
                    Resource: "metrics",
                    Actions:  []string{"read"},
                    Conditions: []string{"active_incident"},
                },
            },
            MaxDuration: durationPtr(4 * time.Hour), // Time-limited emergency access
            RequiresMFA: true,
            AuditLevel:  "full",
        },
        
        RoleSRE: {
            Name:        RoleSRE,
            Description: "Full access including system administration",
            Permissions: []AccessPermission{
                {
                    Resource: "logs",
                    Actions:  []string{"read", "delete"},
                    Constraints: map[string]interface{}{
                        "max_time_range": "90d",
                        "pii_exposure":   "low",
                    },
                },
                {
                    Resource: "traces",
                    Actions:  []string{"read", "delete"},
                    Constraints: map[string]interface{}{
                        "max_time_range": "90d", 
                        "pii_exposure":   "low",
                    },
                },
                {
                    Resource: "metrics",
                    Actions:  []string{"read", "write", "delete"},
                },
                {
                    Resource: "retention_policies",
                    Actions:  []string{"read", "write"},
                },
                {
                    Resource: "access_policies",
                    Actions:  []string{"read"},
                },
            },
            RequiresMFA: true,
            AuditLevel:  "full",
        },
    }
}
```

#### Access Control Implementation

```go
type AccessController struct {
    roleProvider    RoleProvider
    policyEnforcer  PolicyEnforcer
    auditor         AccessAuditor
    emergencyAccess EmergencyAccessManager
}

type AccessRequest struct {
    UserID      string              `json:"user_id"`
    Resource    string              `json:"resource"`
    Action      string              `json:"action"`
    Context     AccessContext       `json:"context"`
    Justification string            `json:"justification,omitempty"`
    Emergency   bool                `json:"emergency"`
}

type AccessContext struct {
    ServiceNames  []string          `json:"service_names,omitempty"`
    TimeRange     TimeRange         `json:"time_range"`
    IncidentID    string            `json:"incident_id,omitempty"`
    SessionID     string            `json:"session_id"`
    RemoteAddr    string            `json:"remote_addr"`
    UserAgent     string            `json:"user_agent"`
}

func (a *AccessController) CheckAccess(req AccessRequest) (*AccessDecision, error) {
    // Get user roles
    roles, err := a.roleProvider.GetUserRoles(req.UserID)
    if err != nil {
        return nil, fmt.Errorf("failed to get user roles: %w", err)
    }
    
    // Check emergency access if requested
    if req.Emergency {
        return a.emergencyAccess.CheckEmergencyAccess(req, roles)
    }
    
    // Evaluate access policies
    decision := &AccessDecision{
        UserID:    req.UserID,
        Resource:  req.Resource,
        Action:    req.Action,
        Allowed:   false,
        Timestamp: time.Now(),
    }
    
    for _, role := range roles {
        roleDefinition := DefaultRoleDefinitions()[role]
        
        for _, permission := range roleDefinition.Permissions {
            if a.matchesPermission(req, permission) {
                decision.Allowed = true
                decision.GrantedRole = role
                decision.Conditions = permission.Conditions
                decision.Constraints = permission.Constraints
                break
            }
        }
        
        if decision.Allowed {
            break
        }
    }
    
    // Apply additional constraints
    if decision.Allowed {
        decision = a.applyConstraints(decision, req)
    }
    
    // Audit the access decision
    a.auditor.LogAccessDecision(decision, req)
    
    return decision, nil
}

func (a *AccessController) applyConstraints(decision *AccessDecision, req AccessRequest) *AccessDecision {
    // Apply time range constraints
    if maxRange, exists := decision.Constraints["max_time_range"]; exists {
        maxDuration, _ := time.ParseDuration(maxRange.(string))
        if req.Context.TimeRange.Duration() > maxDuration {
            decision.Allowed = false
            decision.Reason = fmt.Sprintf("Time range exceeds maximum allowed: %s", maxDuration)
            return decision
        }
    }
    
    // Apply PII exposure constraints
    if piiLevel, exists := decision.Constraints["pii_exposure"]; exists {
        decision.PIIExposureLevel = piiLevel.(string)
    } else if redacted, exists := decision.Constraints["pii_redacted"]; exists && redacted.(bool) {
        decision.PIIExposureLevel = "redacted"
    }
    
    // Apply service ownership constraints
    if contains(decision.Conditions, "own_services") {
        ownedServices, err := a.roleProvider.GetOwnedServices(req.UserID)
        if err != nil || !hasIntersection(req.Context.ServiceNames, ownedServices) {
            decision.Allowed = false
            decision.Reason = "Access limited to owned services only"
            return decision
        }
    }
    
    // Apply business hours constraints
    if contains(decision.Conditions, "business_hours") {
        if !isBusinessHours(time.Now()) {
            decision.Allowed = false
            decision.Reason = "Access limited to business hours"
            return decision
        }
    }
    
    return decision
}
```

### Emergency Access Management

#### Break-Glass Access Procedures

```go
type EmergencyAccessManager struct {
    incidentProvider  IncidentProvider
    approvalWorkflow  ApprovalWorkflow
    auditor          AccessAuditor
    notifications    NotificationService
}

type EmergencyAccessRequest struct {
    AccessRequest
    IncidentID        string        `json:"incident_id"`
    Severity          string        `json:"severity"`
    Justification     string        `json:"justification"`
    RequestedDuration time.Duration `json:"requested_duration"`
    ApproverID        string        `json:"approver_id,omitempty"`
}

func (e *EmergencyAccessManager) RequestEmergencyAccess(req EmergencyAccessRequest) (*EmergencyAccessDecision, error) {
    // Validate active incident
    incident, err := e.incidentProvider.GetIncident(req.IncidentID)
    if err != nil {
        return nil, fmt.Errorf("invalid incident ID: %w", err)
    }
    
    if incident.Status != "active" {
        return nil, fmt.Errorf("emergency access only available for active incidents")
    }
    
    decision := &EmergencyAccessDecision{
        RequestID:     generateRequestID(),
        UserID:        req.UserID,
        IncidentID:    req.IncidentID,
        Severity:      req.Severity,
        Justification: req.Justification,
        Timestamp:     time.Now(),
    }
    
    // Automatic approval for critical incidents
    if incident.Severity == "critical" || incident.Severity == "sev1" {
        decision.Approved = true
        decision.ApprovalMethod = "automatic_critical"
        decision.ExpiresAt = time.Now().Add(req.RequestedDuration)
        decision.Constraints = map[string]interface{}{
            "incident_scoped": true,
            "max_time_range":  "7d",
            "pii_exposure":    "medium",
        }
    } else {
        // Require manual approval for lower severity
        approval, err := e.approvalWorkflow.RequestApproval(ApprovalRequest{
            RequestID:   decision.RequestID,
            UserID:      req.UserID,
            Type:        "emergency_observability_access",
            Justification: req.Justification,
            Context:     req,
        })
        
        if err != nil {
            return nil, fmt.Errorf("failed to request approval: %w", err)
        }
        
        decision.Approved = false
        decision.ApprovalRequired = true
        decision.ApprovalRequestID = approval.ID
    }
    
    // Log emergency access request
    e.auditor.LogEmergencyAccessRequest(decision)
    
    // Notify security team
    e.notifications.SendSecurityAlert("emergency_observability_access_requested", map[string]interface{}{
        "user_id":     req.UserID,
        "incident_id": req.IncidentID,
        "severity":    req.Severity,
        "auto_approved": decision.Approved,
    })
    
    return decision, nil
}
```

### Data Retention Governance

#### Retention Policy Framework

```go
type RetentionPolicy struct {
    Name          string        `yaml:"name"`
    DataType      string        `yaml:"data_type"`      // "logs", "traces", "metrics"
    Environment   string        `yaml:"environment"`
    Service       string        `yaml:"service,omitempty"`
    RetentionDays int           `yaml:"retention_days"`
    
    // Compliance requirements
    LegalHold     bool          `yaml:"legal_hold"`
    ComplianceTag string        `yaml:"compliance_tag,omitempty"` // "gdpr", "sox", "hipaa"
    
    // Cost optimization
    ColdStorageDays int         `yaml:"cold_storage_days,omitempty"`
    ArchiveDays     int         `yaml:"archive_days,omitempty"`
    
    // PII handling
    PIIHandling   PIIRetentionHandling `yaml:"pii_handling"`
}

type PIIRetentionHandling struct {
    AutoRedaction      bool `yaml:"auto_redaction"`       // Redact PII after X days
    RedactionAfterDays int  `yaml:"redaction_after_days"`
    AnonymizationDays  int  `yaml:"anonymization_days"`   // Convert to anonymous data
    PurgeAfterDays     int  `yaml:"purge_after_days"`     // Complete deletion
}

// Default retention policies by environment and data sensitivity
func DefaultRetentionPolicies() []RetentionPolicy {
    return []RetentionPolicy{
        {
            Name:        "production_logs_standard",
            DataType:    "logs",
            Environment: "production",
            RetentionDays: 90, // 90 days for production debugging
            ColdStorageDays: 30, // Move to cold storage after 30 days
            ArchiveDays:     60, // Archive after 60 days
            PIIHandling: PIIRetentionHandling{
                AutoRedaction:      true,
                RedactionAfterDays: 7,   // Redact PII after 1 week
                AnonymizationDays:  30,  // Anonymize after 30 days
                PurgeAfterDays:     90,  // Complete deletion after 90 days
            },
        },
        {
            Name:        "production_traces_standard",
            DataType:    "traces",
            Environment: "production",
            RetentionDays: 30, // Shorter retention for high-volume traces
            ColdStorageDays: 7,
            ArchiveDays:     14,
            PIIHandling: PIIRetentionHandling{
                AutoRedaction:      true,
                RedactionAfterDays: 3,   // Faster redaction for traces
                AnonymizationDays:  7,
                PurgeAfterDays:     30,
            },
        },
        {
            Name:        "production_metrics_standard",
            DataType:    "metrics",
            Environment: "production",
            RetentionDays: 365, // Long retention for trend analysis
            ColdStorageDays: 90,
            ArchiveDays:     180,
            PIIHandling: PIIRetentionHandling{
                AutoRedaction:      false, // Metrics should not contain PII
                RedactionAfterDays: 0,
                AnonymizationDays:  0,
                PurgeAfterDays:     365,
            },
        },
        {
            Name:        "development_logs_standard",
            DataType:    "logs",
            Environment: "development",
            RetentionDays: 7, // Short retention for development
            PIIHandling: PIIRetentionHandling{
                AutoRedaction:      false, // Full PII for debugging
                RedactionAfterDays: 0,
                AnonymizationDays:  0,
                PurgeAfterDays:     7,
            },
        },
        {
            Name:          "incident_logs_extended",
            DataType:      "logs",
            Environment:   "production",
            RetentionDays: 365, // Extended retention for incident analysis
            LegalHold:     true, // May be subject to legal hold
            ComplianceTag: "sox",
            PIIHandling: PIIRetentionHandling{
                AutoRedaction:      true,
                RedactionAfterDays: 14,  // Longer window for incident analysis
                AnonymizationDays:  60,
                PurgeAfterDays:     365,
            },
        },
    }
}
```

#### Automated Retention Enforcement

```go
type RetentionManager struct {
    policies       []RetentionPolicy
    storage        ObservabilityStorage
    auditor        AccessAuditor
    legalHoldMgr   LegalHoldManager
    notifier       NotificationService
    scheduler      *cron.Cron
}

func NewRetentionManager(policies []RetentionPolicy, storage ObservabilityStorage) *RetentionManager {
    rm := &RetentionManager{
        policies:  policies,
        storage:   storage,
        scheduler: cron.New(),
    }
    
    // Schedule daily retention enforcement
    rm.scheduler.AddFunc("0 2 * * *", rm.EnforceRetentionPolicies) // 2 AM daily
    
    // Schedule weekly compliance reporting
    rm.scheduler.AddFunc("0 1 * * 1", rm.GenerateComplianceReport) // Monday 1 AM
    
    rm.scheduler.Start()
    return rm
}

func (r *RetentionManager) EnforceRetentionPolicies() error {
    r.auditor.LogSystemEvent("retention_enforcement_started", map[string]interface{}{
        "timestamp": time.Now(),
        "policies":  len(r.policies),
    })
    
    for _, policy := range r.policies {
        if err := r.enforcePolicy(policy); err != nil {
            r.auditor.LogSystemEvent("retention_enforcement_error", map[string]interface{}{
                "policy": policy.Name,
                "error":  err.Error(),
            })
            continue
        }
    }
    
    r.auditor.LogSystemEvent("retention_enforcement_completed", map[string]interface{}{
        "timestamp": time.Now(),
    })
    
    return nil
}

func (r *RetentionManager) enforcePolicy(policy RetentionPolicy) error {
    // Check for legal holds
    if policy.LegalHold {
        holds, err := r.legalHoldMgr.GetActiveLegalHolds(policy.Environment, policy.Service)
        if err != nil {
            return fmt.Errorf("failed to check legal holds: %w", err)
        }
        if len(holds) > 0 {
            r.auditor.LogSystemEvent("retention_policy_suspended", map[string]interface{}{
                "policy":      policy.Name,
                "legal_holds": holds,
            })
            return nil // Skip enforcement due to legal hold
        }
    }
    
    now := time.Now()
    
    // Stage 1: Move to cold storage
    if policy.ColdStorageDays > 0 {
        coldStorageDate := now.AddDate(0, 0, -policy.ColdStorageDays)
        moved, err := r.storage.MoveToColdStorage(policy, coldStorageDate)
        if err != nil {
            return fmt.Errorf("failed to move to cold storage: %w", err)
        }
        if moved > 0 {
            r.auditor.LogSystemEvent("data_moved_cold_storage", map[string]interface{}{
                "policy":      policy.Name,
                "moved_count": moved,
                "cutoff_date": coldStorageDate,
            })
        }
    }
    
    // Stage 2: Archive data
    if policy.ArchiveDays > 0 {
        archiveDate := now.AddDate(0, 0, -policy.ArchiveDays)
        archived, err := r.storage.ArchiveData(policy, archiveDate)
        if err != nil {
            return fmt.Errorf("failed to archive data: %w", err)
        }
        if archived > 0 {
            r.auditor.LogSystemEvent("data_archived", map[string]interface{}{
                "policy":        policy.Name,
                "archived_count": archived,
                "cutoff_date":   archiveDate,
            })
        }
    }
    
    // Stage 3: PII redaction
    if policy.PIIHandling.AutoRedaction && policy.PIIHandling.RedactionAfterDays > 0 {
        redactionDate := now.AddDate(0, 0, -policy.PIIHandling.RedactionAfterDays)
        redacted, err := r.storage.RedactPII(policy, redactionDate)
        if err != nil {
            return fmt.Errorf("failed to redact PII: %w", err)
        }
        if redacted > 0 {
            r.auditor.LogSystemEvent("pii_redacted", map[string]interface{}{
                "policy":         policy.Name,
                "redacted_count": redacted,
                "cutoff_date":    redactionDate,
            })
        }
    }
    
    // Stage 4: Data anonymization
    if policy.PIIHandling.AnonymizationDays > 0 {
        anonymizationDate := now.AddDate(0, 0, -policy.PIIHandling.AnonymizationDays)
        anonymized, err := r.storage.AnonymizeData(policy, anonymizationDate)
        if err != nil {
            return fmt.Errorf("failed to anonymize data: %w", err)
        }
        if anonymized > 0 {
            r.auditor.LogSystemEvent("data_anonymized", map[string]interface{}{
                "policy":           policy.Name,
                "anonymized_count": anonymized,
                "cutoff_date":      anonymizationDate,
            })
        }
    }
    
    // Stage 5: Data deletion
    deletionDate := now.AddDate(0, 0, -policy.RetentionDays)
    deleted, err := r.storage.DeleteData(policy, deletionDate)
    if err != nil {
        return fmt.Errorf("failed to delete data: %w", err)
    }
    if deleted > 0 {
        r.auditor.LogSystemEvent("data_deleted", map[string]interface{}{
            "policy":        policy.Name,
            "deleted_count": deleted,
            "cutoff_date":   deletionDate,
        })
    }
    
    return nil
}
```

### Comprehensive Audit Trail

#### Access Audit Implementation

```go
type AccessAuditor struct {
    logger        log.Logger
    storage       AuditStorage
    alertManager  AlertManager
    config        AuditConfig
}

type AuditConfig struct {
    EnableDetailedLogging bool          `yaml:"enable_detailed_logging"`
    RetentionDays        int           `yaml:"retention_days"`
    AlertThresholds      AlertThresholds `yaml:"alert_thresholds"`
    ExportConfig         ExportConfig   `yaml:"export_config"`
}

type AlertThresholds struct {
    UnusualAccessPatterns  int `yaml:"unusual_access_patterns"`   // Alert after N unusual accesses
    EmergencyAccessCount   int `yaml:"emergency_access_count"`    // Alert after N emergency accesses
    FailedAccessCount      int `yaml:"failed_access_count"`       // Alert after N failed accesses
    OffHoursAccessCount    int `yaml:"off_hours_access_count"`    // Alert after N off-hours accesses
}

type AuditEvent struct {
    ID           string                 `json:"id"`
    Timestamp    time.Time              `json:"timestamp"`
    EventType    string                 `json:"event_type"`
    UserID       string                 `json:"user_id"`
    Resource     string                 `json:"resource"`
    Action       string                 `json:"action"`
    Result       string                 `json:"result"`        // "allowed", "denied"
    Reason       string                 `json:"reason,omitempty"`
    SessionID    string                 `json:"session_id"`
    RemoteAddr   string                 `json:"remote_addr"`
    UserAgent    string                 `json:"user_agent"`
    
    // Request context
    ServiceNames []string               `json:"service_names,omitempty"`
    TimeRange    *TimeRange            `json:"time_range,omitempty"`
    IncidentID   string                 `json:"incident_id,omitempty"`
    
    // Decision context
    GrantedRole  ObservabilityRole     `json:"granted_role,omitempty"`
    Conditions   []string              `json:"conditions,omitempty"`
    Constraints  map[string]interface{} `json:"constraints,omitempty"`
    
    // Compliance metadata
    DataClassification string           `json:"data_classification,omitempty"`
    PIIExposureLevel   string           `json:"pii_exposure_level,omitempty"`
    LegalBasis         string           `json:"legal_basis,omitempty"`
}

func (a *AccessAuditor) LogAccessDecision(decision *AccessDecision, request AccessRequest) {
    event := AuditEvent{
        ID:          generateAuditID(),
        Timestamp:   time.Now(),
        EventType:   "access_decision",
        UserID:      request.UserID,
        Resource:    request.Resource,
        Action:      request.Action,
        Result:      ternary(decision.Allowed, "allowed", "denied"),
        Reason:      decision.Reason,
        SessionID:   request.Context.SessionID,
        RemoteAddr:  request.Context.RemoteAddr,
        UserAgent:   request.Context.UserAgent,
        ServiceNames: request.Context.ServiceNames,
        TimeRange:   &request.Context.TimeRange,
        IncidentID:  request.Context.IncidentID,
        GrantedRole: decision.GrantedRole,
        Conditions:  decision.Conditions,
        Constraints: decision.Constraints,
        PIIExposureLevel: decision.PIIExposureLevel,
    }
    
    // Add data classification
    event.DataClassification = a.classifyDataAccess(request)
    
    // Store audit event
    if err := a.storage.StoreAuditEvent(event); err != nil {
        a.logger.ErrorCtx(context.Background(), "failed to store audit event", "error", err)
    }
    
    // Log to structured logging
    a.logger.InfoCtx(context.Background(), "observability access audited",
        "audit_event", event,
        "audit_type", "access_decision",
    )
    
    // Check for suspicious patterns
    a.checkSuspiciousActivity(event)
}

func (a *AccessAuditor) checkSuspiciousActivity(event AuditEvent) {
    ctx := context.Background()
    
    // Check for unusual access patterns
    if a.isUnusualAccess(event) {
        alert := SecurityAlert{
            Type:        "unusual_observability_access",
            Severity:    "medium",
            UserID:      event.UserID,
            Description: fmt.Sprintf("Unusual observability access pattern detected for user %s", event.UserID),
            Context:     event,
        }
        a.alertManager.SendSecurityAlert(alert)
    }
    
    // Check for failed access attempts
    if event.Result == "denied" {
        recentFailures := a.getRecentFailures(event.UserID, 1*time.Hour)
        if recentFailures >= a.config.AlertThresholds.FailedAccessCount {
            alert := SecurityAlert{
                Type:        "repeated_access_failures",
                Severity:    "high",
                UserID:      event.UserID,
                Description: fmt.Sprintf("User %s has %d failed access attempts in the last hour", event.UserID, recentFailures),
                Context:     event,
            }
            a.alertManager.SendSecurityAlert(alert)
        }
    }
    
    // Check for off-hours access
    if a.isOffHours(event.Timestamp) && event.Result == "allowed" {
        offHoursAccess := a.getOffHoursAccess(event.UserID, 24*time.Hour)
        if offHoursAccess >= a.config.AlertThresholds.OffHoursAccessCount {
            alert := SecurityAlert{
                Type:        "excessive_off_hours_access",
                Severity:    "medium",
                UserID:      event.UserID,
                Description: fmt.Sprintf("User %s has accessed observability data %d times outside business hours in the last 24 hours", event.UserID, offHoursAccess),
                Context:     event,
            }
            a.alertManager.SendSecurityAlert(alert)
        }
    }
    
    // Check for emergency access abuse
    if event.IncidentID != "" && event.Result == "allowed" {
        emergencyAccess := a.getEmergencyAccess(event.UserID, 7*24*time.Hour)
        if emergencyAccess >= a.config.AlertThresholds.EmergencyAccessCount {
            alert := SecurityAlert{
                Type:        "excessive_emergency_access",
                Severity:    "high",
                UserID:      event.UserID,
                Description: fmt.Sprintf("User %s has used emergency access %d times in the last 7 days", event.UserID, emergencyAccess),
                Context:     event,
            }
            a.alertManager.SendSecurityAlert(alert)
        }
    }
}
```

### Testing and Validation

#### Access Control Testing

```go
func TestAccessController_CheckAccess(t *testing.T) {
    tests := []struct {
        name           string
        userRole       ObservabilityRole
        request        AccessRequest
        expectedResult bool
        expectedPII    string
    }{
        {
            name:     "developer can access own service logs",
            userRole: RoleDeveloper,
            request: AccessRequest{
                UserID:   "dev123",
                Resource: "logs",
                Action:   "read",
                Context: AccessContext{
                    ServiceNames: []string{"user-service"},
                    TimeRange:    TimeRange{Duration: 12 * time.Hour},
                },
            },
            expectedResult: true,
            expectedPII:    "redacted",
        },
        {
            name:     "developer cannot access other service logs",
            userRole: RoleDeveloper,
            request: AccessRequest{
                UserID:   "dev123", 
                Resource: "logs",
                Action:   "read",
                Context: AccessContext{
                    ServiceNames: []string{"payment-service"}, // Not owned
                    TimeRange:    TimeRange{Duration: 12 * time.Hour},
                },
            },
            expectedResult: false,
        },
        {
            name:     "incident commander gets emergency access",
            userRole: RoleIncidentCmdr,
            request: AccessRequest{
                UserID:    "ic456",
                Resource:  "logs",
                Action:    "read",
                Emergency: true,
                Context: AccessContext{
                    IncidentID:   "inc-001",
                    ServiceNames: []string{"payment-service"},
                    TimeRange:    TimeRange{Duration: 7 * 24 * time.Hour},
                },
            },
            expectedResult: true,
            expectedPII:    "medium",
        },
        {
            name:     "viewer cannot access raw logs",
            userRole: RoleViewer,
            request: AccessRequest{
                UserID:   "viewer789",
                Resource: "logs",
                Action:   "read",
                Context: AccessContext{
                    ServiceNames: []string{"user-service"},
                    TimeRange:    TimeRange{Duration: 1 * time.Hour},
                },
            },
            expectedResult: false,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Setup mock role provider
            roleProvider := &mockRoleProvider{
                userRoles: map[string][]ObservabilityRole{
                    tt.request.UserID: {tt.userRole},
                },
                ownedServices: map[string][]string{
                    "dev123": {"user-service", "notification-service"},
                },
            }
            
            controller := &AccessController{
                roleProvider: roleProvider,
                auditor:      &mockAuditor{},
            }
            
            decision, err := controller.CheckAccess(tt.request)
            require.NoError(t, err)
            
            assert.Equal(t, tt.expectedResult, decision.Allowed)
            if tt.expectedResult && tt.expectedPII != "" {
                assert.Equal(t, tt.expectedPII, decision.PIIExposureLevel)
            }
        })
    }
}

func TestRetentionManager_EnforceRetentionPolicies(t *testing.T) {
    mockStorage := &mockObservabilityStorage{
        data: map[string][]DataRecord{
            "logs": {
                {ID: "log1", Timestamp: time.Now().AddDate(0, 0, -100), HasPII: true},
                {ID: "log2", Timestamp: time.Now().AddDate(0, 0, -50), HasPII: true},
                {ID: "log3", Timestamp: time.Now().AddDate(0, 0, -10), HasPII: false},
            },
        },
    }
    
    policies := []RetentionPolicy{
        {
            Name:          "test_logs",
            DataType:      "logs",
            Environment:   "test",
            RetentionDays: 90,
            PIIHandling: PIIRetentionHandling{
                AutoRedaction:      true,
                RedactionAfterDays: 30,
                PurgeAfterDays:     90,
            },
        },
    }
    
    manager := &RetentionManager{
        policies: policies,
        storage:  mockStorage,
        auditor:  &mockAuditor{},
    }
    
    err := manager.enforcePolicy(policies[0])
    require.NoError(t, err)
    
    // Verify data older than 90 days was deleted
    assert.False(t, mockStorage.hasRecord("log1"))
    
    // Verify data older than 30 days had PII redacted  
    record := mockStorage.getRecord("log2")
    assert.True(t, record.PIIRedacted)
    
    // Verify recent data unchanged
    record = mockStorage.getRecord("log3")
    assert.False(t, record.PIIRedacted)
}
```

#### Compliance Validation

```bash
#!/bin/bash
# scripts/validate-access-controls.sh

set -e

echo "🔐 Validating access control compliance..."

# Test role-based access
echo "Testing role-based access controls..."
python3 scripts/test-rbac.py --config config/access-control.yaml

# Validate audit trail completeness
echo "Validating audit trail..."
python3 scripts/audit-completeness-check.py --days 30

# Check retention policy enforcement
echo "Checking retention policy compliance..."
python3 scripts/retention-compliance-check.py --all-environments

# Validate emergency access procedures
echo "Testing emergency access procedures..."
python3 scripts/test-emergency-access.py --dry-run

# Generate compliance report
echo "Generating compliance report..."
python3 scripts/generate-compliance-report.py --output compliance-report.json

echo "✅ Access control validation completed"
```

### Consequences

**Positive:**

- **Enhanced security**: Proper access controls protect sensitive observability data
- **Audit readiness**: Comprehensive audit trails support compliance requirements
- **Incident response**: Emergency access procedures enable effective incident response
- **Cost optimization**: Automated retention policies control storage costs
- **Regulatory compliance**: Data handling meets GDPR, SOX, HIPAA requirements

**Negative:**

- **Implementation complexity**: Sophisticated RBAC and audit systems require significant development
- **Operational overhead**: Role management and access request processes add operational burden
- **Emergency access delays**: Approval workflows may slow incident response
- **Storage requirements**: Audit trails require additional storage and processing

**Mitigation Strategies:**

- **Automated role management**: Integration with identity providers for automatic role assignment
- **Break-glass procedures**: Pre-approved emergency access for critical incidents
- **Self-service access**: Automated approval for routine access requests
- **Audit automation**: Automated analysis and alerting on audit trails

### Related ADRs

- [ADR-0003: Context-First Propagation](#adr-0003-context-first-propagation) - Context includes user identity for access control
- [ADR-0009: PII Governance](#adr-0009-pii-governance) - PII protection integrated with access control
- [ADR-0010: Performance Budgets](#adr-0010-performance-budgets) - Access control as performance-sensitive system

### References

- [NIST Cybersecurity Framework: Access Control](https://www.nist.gov/cyberframework)
- [GDPR Article 32: Security of Processing](https://gdpr-info.eu/art-32-gdpr/)
- [SOX Section 404: Internal Controls](https://www.sarbanes-oxley-101.com/sarbanes-oxley-compliance.htm)
- [RBAC Standard: ANSI INCITS 359-2004](https://profsandhu.com/cs6393_s12/rbac-ansi.pdf)
