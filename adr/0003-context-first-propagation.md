# ADR-0003: Context-First Propagation Policy

**Status:** Accepted  
**Date:** 2025-07-17  
**Tags:** go, context, tracing, logging, cancellation

## Context

Cross-cutting concerns (trace IDs, user context, request metadata, timeouts) need to flow through the entire request lifecycle. Go's goroutine model doesn't provide thread-local storage, requiring explicit propagation patterns.

### Problem Statement

Without systematic context propagation:

- **Trace correlation breaks** when context doesn't flow through call chains
- **Request timeouts** can't be honored in downstream services
- **User authentication** context gets lost in business logic
- **Request-scoped logging** becomes impossible to implement
- **Cancellation signals** don't propagate to background operations

### Forces & Considerations

| Approach | Pros | Cons | Go Idiom Alignment |
|----------|------|------|-------------------|
| **Global State** | Simple to access | Race conditions, untestable | ❌ Anti-pattern |
| **Parameter Passing** | Explicit, type-safe | Verbose, easy to forget | ⚠️ Partial |
| **Context.Context** | Standard library, cancellation, deadlines | Slight performance overhead | ✅ Idiomatic |
| **Thread-Local** | Transparent access | Not available in Go | ❌ Not supported |

### Options Considered

#### Option 1: Structured Parameters (Rejected)

```go
func ProcessOrder(userID, requestID, traceID string, timeout time.Duration, order Order) error
```

**Pros:** Type-safe, explicit  
**Cons:** Parameter explosion, easy to forget, no cancellation

#### Option 2: Context Bag Pattern (Chosen)

```go
func ProcessOrder(ctx context.Context, order Order) error
```

**Pros:** Standard library, cancellation, deadlines, trace integration  
**Cons:** Type assertions needed, slight performance cost

#### Option 3: Custom Request Object (Rejected)

```go
type Request struct {
    UserID    string
    RequestID string
    TraceID   string
    Timeout   time.Duration
}

func ProcessOrder(req Request, order Order) error
```

**Pros:** Type-safe, structured  
**Cons:** Duplicates context.Context functionality, no std lib integration

#### Option 4: Global Request Context (Rejected)

```go
var currentRequest = &RequestContext{}

func ProcessOrder(order Order) error {
    userID := currentRequest.UserID
}
```

**Pros:** Simple access  
**Cons:** Race conditions, goroutine unsafe, untestable

### Decision

**Use `context.Context` as the primary propagation mechanism for all cross-cutting concerns.**

### Decision Rules

1. **First parameter**: Every exported function that participates in request processing accepts `ctx context.Context` as first parameter
2. **Structured context keys**: Define typed keys for user ID, request ID, trace context
3. **Logger injection**: Attach enriched logger to context for automatic field injection (EAGER pattern)
4. **OpenTelemetry integration**: Leverage `context.Context` for automatic trace propagation
5. **Timeout propagation**: Use context deadlines for request timeout enforcement

### Implementation Patterns

#### Context Key Management

```go
// Use unexported type to prevent collisions
type ctxKey int

const (
    userIDKey ctxKey = iota
    requestIDKey
    operationKey
    tenantIDKey
    loggerKey
)

// Type-safe context helpers
func WithUserID(ctx context.Context, userID string) context.Context {
    return context.WithValue(ctx, userIDKey, userID)
}

func UserIDFromContext(ctx context.Context) string {
    if userID, ok := ctx.Value(userIDKey).(string); ok {
        return userID
    }
    return ""
}

func WithRequestID(ctx context.Context, requestID string) context.Context {
    return context.WithValue(ctx, requestIDKey, requestID)
}

func RequestIDFromContext(ctx context.Context) string {
    if requestID, ok := ctx.Value(requestIDKey).(string); ok {
        return requestID
    }
    return ""
}
```

#### EAGER Pattern - Logger Enrichment

```go
// Attach enriched logger ONCE in middleware
func LoggerMiddleware(baseLogger log.Logger, cfg Config) gin.HandlerFunc {
    return func(c *gin.Context) {
        ctx := c.Request.Context()
        
        // EAGER PATTERN: Create enriched logger ONCE per request
        reqLogger := baseLogger.With(
            "request_id", extractRequestID(c, cfg),
            "method", c.Request.Method,
            "route", c.FullPath(), // Template route like /users/{id}
            "remote_addr", c.ClientIP(),
        )
        
        // Add trace context if available
        if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
            reqLogger = reqLogger.With(
                "trace_id", span.SpanContext().TraceID().String(),
                "span_id", span.SpanContext().SpanID().String(),
            )
        }
        
        // Add user context if authenticated
        if userID := extractUserID(c); userID != "" {
            ctx = WithUserID(ctx, userID)
            reqLogger = enrichWithUserID(reqLogger, cfg, userID)
        }
        
        // Attach enriched logger to context
        ctx = AttachLogger(ctx, reqLogger)
        ctx = WithRequestID(ctx, extractRequestID(c, cfg))
        
        c.Request = c.Request.WithContext(ctx)
        c.Next()
    }
}

// Zero-allocation logger retrieval
func LoggerFromContext(ctx context.Context) log.Logger {
    if logger, ok := ctx.Value(loggerKey).(log.Logger); ok {
        return logger
    }
    return DefaultLogger() // Prevents nil panics
}

func AttachLogger(ctx context.Context, logger log.Logger) context.Context {
    return context.WithValue(ctx, loggerKey, logger)
}
```

#### Timeout and Cancellation

```go
func ProcessOrder(ctx context.Context, order Order) error {
    // Create timeout context for external API call
    apiCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
    defer cancel()
    
    // External API respects timeout
    if err := externalAPI.ValidateOrder(apiCtx, order); err != nil {
        return fmt.Errorf("validation failed: %w", err)
    }
    
    // Background processing with cancellation
    go func() {
        // Use original context to inherit cancellation
        if err := processOrderAsync(ctx, order); err != nil {
            logger := LoggerFromContext(ctx)
            logger.ErrorCtx(ctx, "async processing failed", "error", err)
        }
    }()
    
    return nil
}
```

#### Database Operations with Context

```go
type UserRepository interface {
    Create(ctx context.Context, user *User) error
    GetByID(ctx context.Context, id string) (*User, error)
    Update(ctx context.Context, user *User) error
    Delete(ctx context.Context, id string) error
}

func (r *PostgresUserRepository) Create(ctx context.Context, user *User) error {
    // Database operations inherit timeout and cancellation
    query := `INSERT INTO users (id, name, email) VALUES ($1, $2, $3)`
    
    _, err := r.db.ExecContext(ctx, query, user.ID, user.Name, user.Email)
    if err != nil {
        return fmt.Errorf("failed to create user: %w", err)
    }
    
    return nil
}
```

#### Service Layer Context Flow

```go
func (s *UserService) CreateUser(ctx context.Context, req CreateUserRequest) (*User, error) {
    // Logger is pre-enriched from context
    logger := LoggerFromContext(ctx)
    
    // Start tracing span (inherits parent from context)
    ctx, span := s.tracer.Start(ctx, "user.create")
    defer span.End()
    
    logger.InfoCtx(ctx, "creating user",
        "email_domain", extractDomain(req.Email), // Safe: domain only
        "user_type", req.Type,                    // Safe: enum value
    )
    
    // Validate request
    if err := s.validateUser(ctx, req); err != nil {
        span.SetStatus(codes.Error, "validation failed")
        logger.ErrorCtx(ctx, "validation failed", "error", err)
        return nil, err
    }
    
    // Repository call inherits context
    user, err := s.repo.Create(ctx, newUser)
    if err != nil {
        span.SetStatus(codes.Error, "create failed")
        logger.ErrorCtx(ctx, "failed to create user", "error", err)
        return nil, err
    }
    
    logger.InfoCtx(ctx, "user created successfully", "user_id", user.ID)
    return user, nil
}
```

### OpenTelemetry Integration

#### Automatic Trace Propagation

```go
import (
    "go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
    "go.opentelemetry.io/otel/trace"
)

func setupTracing() gin.HandlerFunc {
    return otelgin.Middleware("api-service")
}

func (s *UserService) ProcessUser(ctx context.Context, user User) error {
    // Automatically creates child span with proper parent from context
    ctx, span := s.tracer.Start(ctx, "user.process")
    defer span.End()
    
    // Context carries trace information through all calls
    return s.repository.Update(ctx, user)
}
```

#### Trace Context in Logs

```go
func LoggerFromContext(ctx context.Context) log.Logger {
    logger := getBaseLogger(ctx)
    
    // Automatically add trace context if available
    if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
        logger = logger.With(
            "trace_id", span.SpanContext().TraceID().String(),
            "span_id", span.SpanContext().SpanID().String(),
        )
    }
    
    return logger
}
```

### Context Value Guidelines

#### What TO Store in Context

- **Request-scoped identifiers**: request_id, correlation_id, trace_id
- **Authentication context**: user_id, tenant_id, permissions
- **Request metadata**: operation name, client version
- **Pre-enriched loggers**: performance optimization
- **Trace spans**: OpenTelemetry propagation

#### What NOT TO Store in Context

- **Business data**: User objects, Order details
- **Large objects**: Files, images, bulk data
- **Mutable state**: Counters, accumulators
- **Database connections**: Use dependency injection instead
- **Configuration**: Load once, inject into services

### Error Handling with Context

#### Timeout Handling

```go
func CallExternalAPI(ctx context.Context, request APIRequest) (*APIResponse, error) {
    client := &http.Client{}
    
    req, err := http.NewRequestWithContext(ctx, "POST", apiURL, body)
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }
    
    resp, err := client.Do(req)
    if err != nil {
        // Check if timeout occurred
        if ctx.Err() == context.DeadlineExceeded {
            return nil, fmt.Errorf("API call timed out: %w", err)
        }
        return nil, fmt.Errorf("API call failed: %w", err)
    }
    
    return parseResponse(resp)
}
```

#### Cancellation Handling

```go
func ProcessBatch(ctx context.Context, items []Item) error {
    for _, item := range items {
        // Check for cancellation before processing each item
        select {
        case <-ctx.Done():
            return fmt.Errorf("processing cancelled: %w", ctx.Err())
        default:
            // Continue processing
        }
        
        if err := processItem(ctx, item); err != nil {
            return fmt.Errorf("failed to process item %s: %w", item.ID, err)
        }
    }
    
    return nil
}
```

### Testing Context Patterns

#### Unit Test Context Setup

```go
func TestUserService_CreateUser(t *testing.T) {
    tests := []struct {
        name    string
        setup   func(context.Context) context.Context
        request CreateUserRequest
        wantErr bool
    }{
        {
            name: "valid user",
            setup: func(ctx context.Context) context.Context {
                return WithUserID(ctx, "admin-user")
            },
            request: validRequest,
            wantErr: false,
        },
        {
            name: "timeout context",
            setup: func(ctx context.Context) context.Context {
                ctx, cancel := context.WithTimeout(ctx, 1*time.Nanosecond)
                defer cancel()
                time.Sleep(2 * time.Nanosecond) // Force timeout
                return ctx
            },
            request: validRequest,
            wantErr: true,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            ctx := context.Background()
            if tt.setup != nil {
                ctx = tt.setup(ctx)
            }
            
            // Add test logger to context
            logger, _ := log.NewTestLogger()
            ctx = AttachLogger(ctx, logger)
            
            service := NewUserService(/* deps */)
            _, err := service.CreateUser(ctx, tt.request)
            
            if tt.wantErr {
                assert.Error(t, err)
            } else {
                assert.NoError(t, err)
            }
        })
    }
}
```

#### Integration Test Context

```go
func TestUserAPI_Integration(t *testing.T) {
    server := httptest.NewServer(handler)
    defer server.Close()
    
    // Create request with context
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    ctx = WithRequestID(ctx, "test-request-123")
    
    req, err := http.NewRequestWithContext(ctx, "POST", server.URL+"/users", body)
    require.NoError(t, err)
    
    resp, err := http.DefaultClient.Do(req)
    require.NoError(t, err)
    defer resp.Body.Close()
    
    assert.Equal(t, http.StatusCreated, resp.StatusCode)
}
```

### Performance Considerations

#### Context Value Performance

```go
// ✅ Good: Minimize context lookups
func ProcessUser(ctx context.Context, user User) error {
    logger := LoggerFromContext(ctx) // Look up once
    userID := UserIDFromContext(ctx) // Look up once
    
    // Use cached values
    logger.InfoCtx(ctx, "processing user", "user_id", userID)
    return processUserInternal(logger, userID, user)
}

// ❌ Bad: Repeated context lookups
func ProcessUser(ctx context.Context, user User) error {
    LoggerFromContext(ctx).InfoCtx(ctx, "start") // Lookup #1
    
    if UserIDFromContext(ctx) == "" {            // Lookup #2
        return errors.New("no user")
    }
    
    LoggerFromContext(ctx).InfoCtx(ctx, "end")   // Lookup #3
    return nil
}
```

#### Context Size Management

```go
// ✅ Good: Lightweight context values
type UserContext struct {
    ID       string
    TenantID string
    Roles    []string
}

// ❌ Bad: Heavy context values
type HeavyUserContext struct {
    User         *FullUserObject    // Large object
    Permissions  map[string]bool    // Large map
    Cache        *UserCache         // Stateful object
    Database     *sql.DB            // Connection object
}
```

### Migration Guidelines

#### From Global Request Variables

```go
// Before: Global request state
var currentUserID string
var currentRequestID string

func ProcessOrder(order Order) error {
    log.Printf("User %s processing order", currentUserID)
}

// After: Context-based propagation
func ProcessOrder(ctx context.Context, order Order) error {
    logger := LoggerFromContext(ctx)
    userID := UserIDFromContext(ctx)
    
    logger.InfoCtx(ctx, "processing order", "user_id", userID)
}
```

#### From Parameter Passing

```go
// Before: Parameter explosion
func ProcessOrder(userID, requestID, traceID string, timeout time.Duration, order Order) error {
    // Implementation
}

// After: Context-based
func ProcessOrder(ctx context.Context, order Order) error {
    userID := UserIDFromContext(ctx)
    requestID := RequestIDFromContext(ctx)
    // traceID automatically available via OpenTelemetry
    // timeout handled via context.WithTimeout
}
```

### Consequences

**Positive:**

- **Automatic trace propagation** across all instrumented code
- **Request-scoped logging** with correlation IDs
- **Timeout/cancellation signals** flow with telemetry context
- **Works seamlessly** with OpenTelemetry instrumentation libraries
- **Standard Go idiom** for request-scoped data
- **Type-safe context helpers** prevent key collisions

**Negative:**

- **Every function signature** requires `context.Context` parameter
- **Context key management** requires discipline to avoid conflicts
- **Debugging context flow** can be challenging
- **Slight performance overhead** for context value lookups

**Mitigation Strategies:**

- **EAGER pattern**: Pre-enrich context values in middleware
- **Typed context keys**: Use unexported types to prevent collisions
- **Context helpers**: Provide convenience functions for common operations
- **Performance testing**: Measure context overhead in benchmarks

### Related ADRs

- [ADR-0002: Zero Global State](#adr-0002-zero-global-state) - Context enables dependency injection
- [ADR-0005: Error Classification](#adr-0005-error-classification) - Errors flow through context
- [ADR-0009: PII Governance](#adr-0009-pii-governance) - Context controls PII exposure

### References

- [Go Blog: Contexts and Goroutines](https://blog.golang.org/contexts)
- [OpenTelemetry Go: Context Propagation](https://opentelemetry.io/docs/instrumentation/go/manual/#propagating-a-context)
- [Effective Go: Contexts](https://go.dev/doc/effective_go#context)