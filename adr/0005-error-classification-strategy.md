# ADR-0005: Error Classification & Observation Strategy

**Status:** Accepted  
**Date:** 2025-07-17  
**Tags:** errors, alerting, api, observability, go

## Context

Go errors are values without built-in classification, stack traces, or structured context. Effective observability requires consistent error handling that enables automated alerting, debugging, and user experience decisions.

### Problem Statement

Default Go error handling creates observability gaps:

- **No structured classification**: All errors treated equally by monitoring
- **Missing context**: Hard to debug without operation and request context
- **Inconsistent observation**: Errors logged/counted multiple times or not at all
- **Poor alerting**: Cannot distinguish retryable from permanent failures
- **Weak correlation**: Errors in logs don't correlate with spans and metrics

Common anti-patterns:

```go
// Anti-pattern: No classification
return fmt.Errorf("validation failed")

// Anti-pattern: String matching for behavior
if strings.Contains(err.Error(), "timeout") {
    // Retry logic
}

// Anti-pattern: Multiple observation points
func (h *Handler) CreateUser(c *gin.Context) {
    user, err := h.service.CreateUser(req)
    if err != nil {
        h.logger.Error("create failed", err)     // Observation #1
        h.metrics.Errors.Inc()                   // Observation #2
        c.JSON(500, gin.H{"error": "failed"})
        return
    }
}

func (s *Service) CreateUser(req CreateUserRequest) (*User, error) {
    if err := validate(req); err != nil {
        s.logger.Error("validation failed", err) // Observation #3 (duplicate!)
        return nil, err
    }
}
```

### Forces & Considerations

| Approach | Classification | Context | Observability | Complexity |
|----------|---------------|---------|---------------|------------|
| **Plain errors** | None | Minimal | Poor | Low |
| **Error types** | Type-based | Medium | Good | Medium |
| **Structured errors** | Rich | High | Excellent | High |
| **Error interfaces** | Interface-based | Medium | Good | Medium |

### Options Considered

#### Option 1: Plain Go Errors (Rejected)

```go
func CreateUser(req CreateUserRequest) error {
    if !isValidEmail(req.Email) {
        return errors.New("invalid email")
    }
    return nil
}
```

**Pros:** Simple, idiomatic Go  
**Cons:** No classification, poor observability

#### Option 2: Error Type Hierarchy (Rejected)

```go
type ValidationError struct{ message string }
type DatabaseError struct{ message string }
type ExternalError struct{ message string }

func (e ValidationError) Error() string { return e.message }
```

**Pros:** Type-safe classification  
**Cons:** Verbose, limited context, hard to extend

#### Option 3: Error Interfaces (Rejected)

```go
type Retryable interface {
    Retryable() bool
}

type HTTPStatus interface {
    HTTPStatus() int
}
```

**Pros:** Behavior-based classification  
**Cons:** Interface proliferation, limited context

#### Option 4: Structured Error Type (Chosen)

```go
type AppError struct {
    Op     string            // Operation context
    Kind   ErrorKind         // Classification for alerting
    Code   string            // Machine-readable identifier
    Msg    string            // Human-readable message
    Err    error             // Wrapped underlying error
    Fields map[string]any    // Structured context
    Stack  []uintptr         // Optional stack trace
}
```

**Pros:** Rich context, structured classification, extensible  
**Cons:** More complex than plain errors

### Decision

**Implement two-level error classification with automatic correlation.**

### Error Classification System

#### Two-Level Taxonomy

```go
type ErrorKind int

const (
    ErrValidation ErrorKind = iota // 4xx - client error, don't retry
    ErrAuth                        // 401/403 - authentication/authorization
    ErrNotFound                    // 404 - resource missing
    ErrConflict                    // 409 - state conflict (optimistic locking)
    ErrUnavailable                 // 503 - temporary failure, retry may succeed
    ErrInternal                    // 5xx - server error, investigate
)

func (k ErrorKind) String() string {
    switch k {
    case ErrValidation: return "validation"
    case ErrAuth: return "auth"
    case ErrNotFound: return "not_found"
    case ErrConflict: return "conflict"
    case ErrUnavailable: return "unavailable"
    case ErrInternal: return "internal"
    default: return "unknown"
    }
}

func (k ErrorKind) HTTPStatus() int {
    switch k {
    case ErrValidation: return 400
    case ErrAuth: return 401
    case ErrNotFound: return 404
    case ErrConflict: return 409
    case ErrUnavailable: return 503
    case ErrInternal: return 500
    default: return 500
    }
}

func (k ErrorKind) ShouldRetry() bool {
    switch k {
    case ErrUnavailable: return true
    case ErrInternal: return true // With backoff
    default: return false
    }
}

func (k ErrorKind) ShouldAlert() bool {
    switch k {
    case ErrInternal: return true
    case ErrUnavailable: return true // If persistent
    default: return false
    }
}
```

#### Structured Error Type

```go
type AppError struct {
    Op     string            // Operation context ("user.create", "order.process")
    Kind   ErrorKind         // Classification for alerting/handling
    Code   string            // Machine-readable code ("user.email.invalid")
    Msg    string            // Human-readable message
    Err    error             // Wrapped underlying error
    Fields map[string]any    // Structured context
    Stack  []uintptr         // Optional stack trace (expensive)
}

// Required methods for Go error interface
func (e *AppError) Error() string {
    if e == nil {
        return "<nil>"
    }
    
    var parts []string
    if e.Op != "" {
        parts = append(parts, e.Op)
    }
    if e.Code != "" {
        parts = append(parts, e.Code)
    }
    if e.Msg != "" {
        parts = append(parts, e.Msg)
    }
    if e.Err != nil {
        parts = append(parts, e.Err.Error())
    }
    
    return strings.Join(parts, ": ")
}

// Support error unwrapping
func (e *AppError) Unwrap() error {
    return e.Err
}

// Add structured context
func (e *AppError) WithField(key string, value any) *AppError {
    if e.Fields == nil {
        e.Fields = make(map[string]any)
    }
    e.Fields[key] = value
    return e
}

func (e *AppError) WithFields(fields map[string]any) *AppError {
    if e.Fields == nil {
        e.Fields = make(map[string]any)
    }
    for k, v := range fields {
        e.Fields[k] = v
    }
    return e
}

// Optional stack trace capture
func (e *AppError) WithStack() *AppError {
    if e.Stack == nil {
        pc := make([]uintptr, 32)
        n := runtime.Callers(2, pc)
        e.Stack = pc[:n]
    }
    return e
}
```

### Error Construction Helpers

#### Constructor Functions

```go
func ValidationError(op, code, msg string) *AppError {
    return &AppError{
        Op:   op,
        Kind: ErrValidation,
        Code: code,
        Msg:  msg,
    }
}

func AuthError(op, code, msg string) *AppError {
    return &AppError{
        Op:   op,
        Kind: ErrAuth,
        Code: code,
        Msg:  msg,
    }
}

func NotFoundError(op, code, msg string) *AppError {
    return &AppError{
        Op:   op,
        Kind: ErrNotFound,
        Code: code,
        Msg:  msg,
    }
}

func ConflictError(op, code, msg string) *AppError {
    return &AppError{
        Op:   op,
        Kind: ErrConflict,
        Code: code,
        Msg:  msg,
    }
}

func UnavailableError(op, code, msg string) *AppError {
    return &AppError{
        Op:   op,
        Kind: ErrUnavailable,
        Code: code,
        Msg:  msg,
    }
}

func InternalError(op, code, msg string, err error) *AppError {
    return &AppError{
        Op:   op,
        Kind: ErrInternal,
        Code: code,
        Msg:  msg,
        Err:  err,
    }
}
```

#### Wrapping External Errors

```go
func WrapDatabaseError(op string, err error) *AppError {
    if err == nil {
        return nil
    }
    
    // Classify database errors
    switch {
    case errors.Is(err, sql.ErrNoRows):
        return &AppError{
            Op:   op,
            Kind: ErrNotFound,
            Code: "resource.not_found",
            Msg:  "resource not found",
            Err:  err,
        }
    case isUniqueConstraintViolation(err):
        return &AppError{
            Op:   op,
            Kind: ErrConflict,
            Code: "resource.already_exists",
            Msg:  "resource already exists",
            Err:  err,
        }
    case isConnectionError(err):
        return &AppError{
            Op:   op,
            Kind: ErrUnavailable,
            Code: "database.connection_failed",
            Msg:  "database connection failed",
            Err:  err,
        }
    default:
        return &AppError{
            Op:   op,
            Kind: ErrInternal,
            Code: "database.unknown_error",
            Msg:  "database operation failed",
            Err:  err,
        }
    }
}

func WrapHTTPError(op string, resp *http.Response, err error) *AppError {
    if err != nil {
        return &AppError{
            Op:   op,
            Kind: ErrUnavailable,
            Code: "http.request_failed",
            Msg:  "HTTP request failed",
            Err:  err,
        }
    }
    
    switch {
    case resp.StatusCode >= 400 && resp.StatusCode < 500:
        return &AppError{
            Op:   op,
            Kind: ErrValidation,
            Code: fmt.Sprintf("http.client_error_%d", resp.StatusCode),
            Msg:  fmt.Sprintf("HTTP client error: %d", resp.StatusCode),
        }
    case resp.StatusCode >= 500:
        return &AppError{
            Op:   op,
            Kind: ErrUnavailable,
            Code: fmt.Sprintf("http.server_error_%d", resp.StatusCode),
            Msg:  fmt.Sprintf("HTTP server error: %d", resp.StatusCode),
        }
    }
    
    return nil // Success case
}
```

### Single Observation Point Pattern

#### Middleware-Based Error Observation

```go
func ErrorHandlerMiddleware(logger log.Logger, metrics *Metrics) gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Next()
        
        // Observe errors ONLY at the end of request processing
        if len(c.Errors) > 0 {
            err := c.Errors.Last().Err
            observeError(c.Request.Context(), logger, metrics, err)
        }
    }
}

func observeError(ctx context.Context, logger log.Logger, metrics *Metrics, err error) {
    var appErr *AppError
    if errors.As(err, &appErr) {
        // Update span status
        span := trace.SpanFromContext(ctx)
        span.SetStatus(codes.Error, appErr.Error())
        span.RecordError(appErr)
        
        // Add structured attributes to span
        span.SetAttributes(
            attribute.String("error.kind", appErr.Kind.String()),
            attribute.String("error.code", appErr.Code),
            attribute.String("error.operation", appErr.Op),
        )
        
        // Log with structured context
        logFields := []any{
            "error", appErr,
            "error_kind", appErr.Kind.String(),
            "error_code", appErr.Code,
            "operation", appErr.Op,
        }
        
        // Add custom fields
        for k, v := range appErr.Fields {
            logFields = append(logFields, k, v)
        }
        
        logger.ErrorCtx(ctx, appErr.Msg, logFields...)
        
        // Count for alerting (bounded cardinality)
        metrics.ErrorsTotal.WithLabelValues(appErr.Kind.String()).Inc()
        
        // Track error rate by operation
        if appErr.Op != "" {
            metrics.ErrorsByOperation.WithLabelValues(
                appErr.Op,
                appErr.Kind.String(),
            ).Inc()
        }
    } else {
        // Handle non-AppError errors
        span := trace.SpanFromContext(ctx)
        span.SetStatus(codes.Error, err.Error())
        span.RecordError(err)
        
        logger.ErrorCtx(ctx, "unclassified error", "error", err)
        metrics.ErrorsTotal.WithLabelValues("unknown").Inc()
    }
}
```

### Service Implementation Patterns

#### Domain Service Error Handling

```go
func (s *UserService) CreateUser(ctx context.Context, req CreateUserRequest) (*User, error) {
    logger := log.LoggerFromContext(ctx)
    
    // Validation errors
    if !isValidEmail(req.Email) {
        return nil, ValidationError("user.create", "user.email.invalid", "invalid email address").
            WithField("email_domain", extractDomain(req.Email)) // Safe: domain only
    }
    
    if len(req.Name) < 2 {
        return nil, ValidationError("user.create", "user.name.too_short", "name must be at least 2 characters")
    }
    
    // Check for existing user
    existing, err := s.repo.GetByEmail(ctx, req.Email)
    if err != nil {
        // Wrap repository errors
        if !errors.Is(err, sql.ErrNoRows) {
            return nil, WrapDatabaseError("user.create.check_existing", err)
        }
    }
    if existing != nil {
        return nil, ConflictError("user.create", "user.email.already_exists", "user with this email already exists").
            WithField("email_domain", extractDomain(req.Email))
    }
    
    // Create user
    user := &User{
        ID:    generateID(),
        Name:  req.Name,
        Email: req.Email,
    }
    
    if err := s.repo.Create(ctx, user); err != nil {
        return nil, WrapDatabaseError("user.create.save", err).
            WithFields(map[string]any{
                "user_id": user.ID,
                "email_domain": extractDomain(user.Email),
            })
    }
    
    logger.InfoCtx(ctx, "user created successfully",
        "user_id", user.ID,
        "email_domain", extractDomain(user.Email),
    )
    
    return user, nil
}
```

#### HTTP Handler Error Handling

```go
func (h *UserHandler) CreateUser(c *gin.Context) {
    var req CreateUserRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        // Add validation error to context for middleware observation
        c.Error(ValidationError("user.create.bind", "request.invalid_json", "invalid request format").
            WithField("bind_error", err.Error()))
        
        c.JSON(400, gin.H{
            "error": "invalid_request",
            "message": "Request format is invalid",
        })
        return
    }
    
    user, err := h.userService.CreateUser(c.Request.Context(), req)
    if err != nil {
        // Add error to context for middleware observation
        c.Error(err)
        
        // Convert to HTTP response
        var appErr *AppError
        if errors.As(err, &appErr) {
            c.JSON(appErr.Kind.HTTPStatus(), gin.H{
                "error": appErr.Code,
                "message": appErr.Msg,
            })
        } else {
            c.JSON(500, gin.H{
                "error": "internal_error",
                "message": "An internal error occurred",
            })
        }
        return
    }
    
    c.JSON(201, gin.H{
        "user": user,
    })
}
```

### Error Analysis and Helpers

#### Error Classification Detection

```go
func KindFromError(err error) ErrorKind {
    var appErr *AppError
    if errors.As(err, &appErr) {
        return appErr.Kind
    }
    return ErrInternal // Default for unclassified errors
}

func CodeFromError(err error) string {
    var appErr *AppError
    if errors.As(err, &appErr) {
        return appErr.Code
    }
    return "unknown"
}

func OperationFromError(err error) string {
    var appErr *AppError
    if errors.As(err, &appErr) {
        return appErr.Op
    }
    return ""
}

func FieldsFromError(err error) map[string]any {
    var appErr *AppError
    if errors.As(err, &appErr) {
        return appErr.Fields
    }
    return nil
}
```

#### Error Aggregation

```go
type ErrorStats struct {
    Total     int
    ByKind    map[ErrorKind]int
    ByCode    map[string]int
    ByOp      map[string]int
}

func AnalyzeErrors(errors []error) ErrorStats {
    stats := ErrorStats{
        ByKind: make(map[ErrorKind]int),
        ByCode: make(map[string]int),
        ByOp:   make(map[string]int),
    }
    
    for _, err := range errors {
        stats.Total++
        
        var appErr *AppError
        if errors.As(err, &appErr) {
            stats.ByKind[appErr.Kind]++
            stats.ByCode[appErr.Code]++
            if appErr.Op != "" {
                stats.ByOp[appErr.Op]++
            }
        } else {
            stats.ByKind[ErrInternal]++
            stats.ByCode["unknown"]++
        }
    }
    
    return stats
}
```

#### Error Retry Logic

```go
type RetryConfig struct {
    MaxAttempts   int
    BaseDelay     time.Duration
    MaxDelay      time.Duration
    BackoffFactor float64
}

func ShouldRetry(err error, attempt int, cfg RetryConfig) (bool, time.Duration) {
    if attempt >= cfg.MaxAttempts {
        return false, 0
    }
    
    var appErr *AppError
    if errors.As(err, &appErr) {
        if !appErr.Kind.ShouldRetry() {
            return false, 0
        }
    }
    
    // Exponential backoff with jitter
    delay := time.Duration(float64(cfg.BaseDelay) * math.Pow(cfg.BackoffFactor, float64(attempt-1)))
    if delay > cfg.MaxDelay {
        delay = cfg.MaxDelay
    }
    
    // Add jitter (±25%)
    jitter := time.Duration(rand.Float64() * float64(delay) * 0.5)
    if rand.Float64() < 0.5 {
        delay += jitter
    } else {
        delay -= jitter
    }
    
    return true, delay
}

func RetryWithBackoff(ctx context.Context, operation func() error, cfg RetryConfig) error {
    var lastErr error
    
    for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
        lastErr = operation()
        if lastErr == nil {
            return nil
        }
        
        shouldRetry, delay := ShouldRetry(lastErr, attempt, cfg)
        if !shouldRetry {
            return lastErr
        }
        
        select {
        case <-ctx.Done():
            return fmt.Errorf("operation cancelled: %w", ctx.Err())
        case <-time.After(delay):
            // Continue to next attempt
        }
    }
    
    return fmt.Errorf("operation failed after %d attempts: %w", cfg.MaxAttempts, lastErr)
}
```

### Testing Error Classification

#### Unit Tests for Error Behavior

```go
func TestErrorClassification(t *testing.T) {
    tests := []struct {
        name           string
        err            error
        expectedKind   ErrorKind
        expectedHTTP   int
        expectedRetry  bool
        expectedAlert  bool
    }{
        {
            name:           "validation error",
            err:            ValidationError("user.create", "user.email.invalid", "invalid email"),
            expectedKind:   ErrValidation,
            expectedHTTP:   400,
            expectedRetry:  false,
            expectedAlert:  false,
        },
        {
            name:           "not found error",
            err:            NotFoundError("user.get", "user.not_found", "user not found"),
            expectedKind:   ErrNotFound,
            expectedHTTP:   404,
            expectedRetry:  false,
            expectedAlert:  false,
        },
        {
            name:           "unavailable error",
            err:            UnavailableError("user.create", "database.connection_failed", "database unavailable"),
            expectedKind:   ErrUnavailable,
            expectedHTTP:   503,
            expectedRetry:  true,
            expectedAlert:  true,
        },
        {
            name:           "internal error",
            err:            InternalError("user.create", "database.unknown_error", "internal error", errors.New("raw error")),
            expectedKind:   ErrInternal,
            expectedHTTP:   500,
            expectedRetry:  true,
            expectedAlert:  true,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            var appErr *AppError
            require.True(t, errors.As(tt.err, &appErr))
            
            assert.Equal(t, tt.expectedKind, appErr.Kind)
            assert.Equal(t, tt.expectedHTTP, appErr.Kind.HTTPStatus())
            assert.Equal(t, tt.expectedRetry, appErr.Kind.ShouldRetry())
            assert.Equal(t, tt.expectedAlert, appErr.Kind.ShouldAlert())
        })
    }
}

func TestErrorObservation(t *testing.T) {
    logger, logCapture := log.NewTestLogger()
    metrics := metrics.NewTestRegistry()
    
    ctx := context.Background()
    err := ValidationError("user.create", "user.email.invalid", "invalid email").
        WithField("email_domain", "example.com")
    
    observeError(ctx, logger, metrics, err)
    
    // Assert logging
    entries := logCapture.EntriesWithLevel(slog.LevelError)
    assert.Len(t, entries, 1)
    assert.Equal(t, "invalid email", entries[0].Message)
    assert.Equal(t, "validation", entries[0].Fields["error_kind"])
    assert.Equal(t, "user.email.invalid", entries[0].Fields["error_code"])
    
    // Assert metrics
    counter := metrics.ErrorsTotal.WithLabelValues("validation")
    assert.Equal(t, 1.0, testutil.ToFloat64(counter))
}
```

### Migration from Standard Errors

#### Gradual Migration Strategy

```go
// Phase 1: Wrapper functions for existing code
func wrapValidationError(err error, op, code string) error {
    if err == nil {
        return nil
    }
    return ValidationError(op, code, err.Error()).WithField("original_error", err.Error())
}

// Phase 2: Update error sites incrementally
func (s *UserService) CreateUser_V1(ctx context.Context, req CreateUserRequest) (*User, error) {
    // Old: return fmt.Errorf("invalid email: %s", req.Email)
    // New: return ValidationError("user.create", "user.email.invalid", "invalid email address")
    
    if !isValidEmail(req.Email) {
        return nil, ValidationError("user.create", "user.email.invalid", "invalid email address").
            WithField("email_domain", extractDomain(req.Email))
    }
    
    return s.createUserInternal(ctx, req)
}

// Phase 3: Remove wrapper functions and use AppError directly
```

### Consequences

**Positive:**

- **Actionable alerting**: Error classification enables appropriate automated responses
- **Rich debugging context**: Structured errors with operation and request context
- **Consistent observability**: Single observation point prevents double-counting
- **User experience improvement**: Proper HTTP status codes and user-friendly messages
- **Operational efficiency**: Retry logic based on error classification reduces manual intervention

**Negative:**

- **Additional complexity**: More complex than plain Go errors
- **Training required**: Developers need to learn error classification patterns
- **Migration effort**: Existing error handling needs systematic refactoring
- **Performance overhead**: Error construction and observation adds minimal latency

**Mitigation Strategies:**

- **Training and documentation**: Clear guidelines for error classification
- **Code generation**: Tools to generate boilerplate error constructors
- **Linting support**: Custom rules to catch unclassified errors
- **Gradual migration**: Phase-by-phase adoption with wrapper functions

### Related ADRs

- [ADR-0002: Zero Global State](#adr-0002-zero-global-state) - Errors support dependency injection
- [ADR-0003: Context-First Propagation](#adr-0003-context-first-propagation) - Errors flow through context
- [ADR-0004: Metric Cardinality Budget](#adr-0004-metric-cardinality-budget) - Error codes as bounded labels

### References

- [Go Blog: Error Handling and Go](https://blog.golang.org/error-handling-and-go)
- [OpenTelemetry Semantic Conventions: Error Handling](https://opentelemetry.io/docs/specs/semconv/exceptions/)
- [Site Reliability Engineering: Error Classification](https://sre.google/sre-book/monitoring-distributed-systems/)
