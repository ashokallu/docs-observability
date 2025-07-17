# ADR-0007: Gin Framework Strategy & Abstraction Boundaries

**Status:** Accepted  
**Date:** 2025-07-17  
**Tags:** http, framework, gin, abstraction, architecture

## Context

HTTP framework choice significantly impacts observability integration patterns, development velocity, and long-term architectural flexibility. The decision affects middleware design, request handling patterns, and framework-specific observability integrations.

### Problem Statement

Multiple HTTP framework options exist in the Go ecosystem:

- **Gin**: High performance, extensive middleware ecosystem, opinionated routing
- **Chi**: Stdlib-compatible, minimal dependencies, explicit routing patterns
- **Echo**: Feature-rich, built-in middleware, automatic JSON handling
- **Gorilla/Mux**: Mature, flexible, heavier with more features
- **Standard library**: Minimal, manual middleware, maximum control

Framework choice impacts:

- **Observability integration**: Different middleware patterns and request lifecycle hooks
- **Learning velocity**: Ecosystem size, documentation quality, example availability
- **Performance characteristics**: Request throughput, memory allocation patterns
- **Long-term flexibility**: Migration difficulty, abstraction layer requirements

### Forces & Considerations

| Framework | Performance | Ecosystem | Learning Curve | Abstraction Cost | Migration Difficulty |
|-----------|-------------|-----------|----------------|------------------|---------------------|
| **Gin** | High | Large | Low | Medium | Medium |
| **Chi** | High | Medium | Medium | Low | Low |
| **Echo** | High | Medium | Low | Medium | Medium |
| **Stdlib** | High | Small | High | None | N/A |

### Options Considered

#### Option 1: Framework-Agnostic Abstraction (Rejected)

Build HTTP abstraction layer from the start.

**Pros:**

- Framework independence
- Easy migration between frameworks
- Consistent patterns across implementations

**Cons:**

- Premature abstraction overhead
- Slower initial development
- May not leverage framework-specific optimizations
- Adds complexity without proven need

#### Option 2: Standard Library Only (Rejected)

Use only `net/http` without external frameworks.

**Pros:**

- No external dependencies
- Maximum control and flexibility
- Minimal abstractions

**Cons:**

- Manual middleware implementation
- Slower development velocity
- Reinventing common patterns
- Limited observability examples

#### Option 3: Chi for Stdlib Compatibility (Rejected)

Use Chi router for stdlib-compatible patterns.

**Pros:**

- Minimal dependency footprint
- Easy migration to stdlib
- Clean middleware patterns

**Cons:**

- Smaller ecosystem
- Fewer observability examples
- Manual JSON handling

#### Option 4: Gin-First with Boundaries (Chosen)

Start with Gin, maintain strict import boundaries for future abstraction.

**Pros:**

- Extensive observability ecosystem
- Fast development velocity
- Large community and examples
- High performance characteristics

**Cons:**

- Framework coupling (mitigated by boundaries)
- May require refactoring for multi-framework support

### Decision

**Start with Gin-specific implementation, maintain strict import boundaries for future abstraction.**

### Rationale

#### Learning Velocity Priority

- **Extensive ecosystem**: Gin has mature middleware for OpenTelemetry, Prometheus, and structured logging
- **Documentation quality**: Well-documented observability integration patterns
- **Community examples**: Abundant real-world observability implementations
- **Performance characteristics**: Battle-tested for high-throughput applications

#### Proven Patterns First

- **Real implementation before abstraction**: Build working observability middleware with one framework
- **Identify common patterns**: Extract interfaces based on actual usage, not theoretical needs
- **Framework-specific optimizations**: Leverage Gin's performance characteristics and ecosystem

#### Strategic Boundaries

- **Import boundary enforcement**: Keep framework code in `api/middleware`, core observability in `platform/obs`
- **Interface discovery**: Create abstractions when adding second framework, not before
- **Clean extraction path**: Design handler signatures to be framework-agnostic from start

### Implementation Strategy

#### Framework Isolation Architecture

```
internal/
├── api/middleware/          # Framework-specific code (Gin-coupled)
│   ├── observability.go    # Gin middleware implementations
│   ├── auth.go             # Gin authentication middleware
│   └── cors.go             # Gin CORS middleware
├── api/handlers/            # Framework-specific handlers (Gin-coupled)
│   ├── users.go            # Gin handler functions
│   └── orders.go           # Gin handler functions
├── users/                   # Domain module (framework-agnostic)
│   ├── service.go          # Business logic (no framework imports)
│   ├── repository.go       # Data access interface
│   └── types.go            # Domain types
├── orders/                  # Domain module (framework-agnostic)
└── platform/obs/           # Observability platform (framework-agnostic)
    ├── log/                # Logging interfaces and implementations
    ├── metrics/            # Metrics interfaces and implementations
    └── trace/              # Tracing interfaces and implementations
```

#### Gin-Specific Observability Middleware

```go
// internal/api/middleware/observability.go - Gin-specific layer
package middleware

import (
    "time"
    "context"
    
    "github.com/gin-gonic/gin"
    "github.com/google/uuid"
    "go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
    
    "github.com/ashokallu/go-observability-mastery/internal/platform/obs/log"
    "github.com/ashokallu/go-observability-mastery/internal/platform/obs/metrics"
)

// ObservabilityMiddleware creates comprehensive observability middleware for Gin
func ObservabilityMiddleware(
    baseLogger log.Logger,
    httpMetrics *metrics.HTTPMetrics,
    cfg log.Config,
) gin.HandlerFunc {
    
    // Combine OpenTelemetry tracing with custom observability
    otelMiddleware := otelgin.Middleware("api-service")
    
    return func(c *gin.Context) {
        // Apply OpenTelemetry tracing first
        otelMiddleware(c)
        
        start := time.Now()
        ctx := c.Request.Context()
        
        // Generate request ID if not present
        requestID := c.GetHeader("X-Request-ID")
        if requestID == "" {
            requestID = uuid.New().String()
            c.Header("X-Request-ID", requestID)
        }
        
        // EAGER PATTERN: Create enriched logger ONCE per request
        reqLogger := baseLogger.With(
            "request_id", requestID,
            "method", c.Request.Method,
            "route", c.FullPath(), // Template route like /users/:id
            "remote_addr", c.ClientIP(),
            "user_agent", c.Request.UserAgent(),
        )
        
        // Add trace context to logger if available
        if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
            reqLogger = reqLogger.With(
                "trace_id", span.SpanContext().TraceID().String(),
                "span_id", span.SpanContext().SpanID().String(),
            )
        }
        
        // Add user context if authenticated
        if userID := extractUserID(c); userID != "" {
            ctx = log.WithUserID(ctx, userID)
            reqLogger = log.EnrichWithUserID(reqLogger, cfg, userID)
        }
        
        // Attach enriched logger and context to request
        ctx = log.AttachLogger(ctx, reqLogger)
        ctx = log.WithRequestID(ctx, requestID)
        c.Request = c.Request.WithContext(ctx)
        
        // Log request start
        reqLogger.InfoCtx(ctx, "request started")
        
        // Process request
        c.Next()
        
        // Calculate duration and record metrics
        duration := time.Since(start)
        status := c.Writer.Status()
        
        // Record HTTP metrics (bounded cardinality)
        httpMetrics.RequestsTotal.WithLabelValues(
            c.Request.Method,
            templateRoute(c.FullPath()),
            statusClass(status),
        ).Inc()
        
        httpMetrics.RequestDuration.WithLabelValues(
            c.Request.Method,
            templateRoute(c.FullPath()),
        ).Observe(duration.Seconds())
        
        // Log request completion
        reqLogger.InfoCtx(ctx, "request completed",
            "status", status,
            "duration_ms", duration.Milliseconds(),
            "response_size", c.Writer.Size(),
        )
    }
}

// Error handling middleware with structured classification
func ErrorHandlerMiddleware(logger log.Logger, metrics *metrics.HTTPMetrics) gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Next()
        
        // Handle errors that occurred during request processing
        if len(c.Errors) > 0 {
            err := c.Errors.Last().Err
            observeError(c.Request.Context(), logger, metrics, err)
            
            // Convert AppError to appropriate HTTP response
            handleHTTPError(c, err)
        }
    }
}

// Framework-specific utility functions
func extractUserID(c *gin.Context) string {
    // Extract user ID from JWT token, session, or auth header
    if claims, exists := c.Get("claims"); exists {
        if jwtClaims, ok := claims.(*JWTClaims); ok {
            return jwtClaims.UserID
        }
    }
    return ""
}

func templateRoute(route string) string {
    if route == "" {
        return "unknown"
    }
    // Gin provides templated route like "/users/:id"
    // Convert to Prometheus-friendly format
    return strings.ReplaceAll(route, ":", "")
}

func statusClass(code int) string {
    switch {
    case code < 300: return "2xx"
    case code < 400: return "3xx"
    case code < 500: return "4xx"
    default: return "5xx"
    }
}

func handleHTTPError(c *gin.Context, err error) {
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
}
```

#### Framework-Agnostic Handler Design

```go
// internal/api/handlers/users.go - Gin-specific but minimally coupled
package handlers

import (
    "net/http"
    
    "github.com/gin-gonic/gin"
    
    "github.com/ashokallu/go-observability-mastery/internal/users"
    "github.com/ashokallu/go-observability-mastery/internal/platform/obs/log"
)

type UserHandler struct {
    userService users.Service  // Framework-agnostic interface
    logConfig   log.Config     // For PII handling
}

func NewUserHandler(userService users.Service, logConfig log.Config) *UserHandler {
    return &UserHandler{
        userService: userService,
        logConfig:   logConfig,
    }
}

// Gin-specific handler that delegates to framework-agnostic service
func (h *UserHandler) CreateUser(c *gin.Context) {
    ctx := c.Request.Context()
    logger := log.LoggerFromContext(ctx) // Framework-agnostic logging
    
    var req users.CreateUserRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.Error(ValidationError("user.create.bind", "request.invalid_json", "invalid request format"))
        return
    }
    
    // Delegate to framework-agnostic service
    user, err := h.userService.CreateUser(ctx, req)
    if err != nil {
        c.Error(err) // Let error middleware handle
        return
    }
    
    // Log success with PII protection
    log.LogUserAction(ctx, logger, h.logConfig, user.ID, "user_created")
    
    c.JSON(http.StatusCreated, gin.H{"user": user})
}

func (h *UserHandler) GetUser(c *gin.Context) {
    ctx := c.Request.Context()
    userID := c.Param("id")
    
    user, err := h.userService.GetUser(ctx, userID)
    if err != nil {
        c.Error(err)
        return
    }
    
    c.JSON(http.StatusOK, gin.H{"user": user})
}
```

#### Framework-Agnostic Domain Service

```go
// internal/users/service.go - Completely framework-agnostic
package users

import (
    "context"
    "github.com/ashokallu/go-observability-mastery/internal/platform/obs/log"
    "github.com/ashokallu/go-observability-mastery/internal/platform/obs/trace"
    "github.com/ashokallu/go-observability-mastery/internal/platform/obs/metrics"
)

type Service interface {
    CreateUser(ctx context.Context, req CreateUserRequest) (*User, error)
    GetUser(ctx context.Context, id string) (*User, error)
    UpdateUser(ctx context.Context, id string, req UpdateUserRequest) (*User, error)
    DeleteUser(ctx context.Context, id string) error
}

type service struct {
    logger  log.Logger           // Framework-agnostic interface
    tracer  trace.Tracer         // Framework-agnostic interface
    metrics *metrics.UserMetrics // Framework-agnostic metrics
    repo    Repository           // Domain interface
}

func NewService(
    logger log.Logger,
    tracer trace.Tracer,
    metrics *metrics.UserMetrics,
    repo Repository,
) Service {
    return &service{
        logger:  logger,
        tracer:  tracer,
        metrics: metrics,
        repo:    repo,
    }
}

func (s *service) CreateUser(ctx context.Context, req CreateUserRequest) (*User, error) {
    // Framework-agnostic tracing
    ctx, span := s.tracer.Start(ctx, "user.create")
    defer span.End()
    
    // Framework-agnostic logging
    logger := log.LoggerFromContext(ctx) // Gets pre-enriched logger
    
    logger.InfoCtx(ctx, "creating user",
        "email_domain", extractDomain(req.Email), // Safe: domain only
        "user_type", req.Type,                    // Safe: enum value
    )
    
    // Validation using framework-agnostic errors
    if !isValidEmail(req.Email) {
        return nil, ValidationError("user.create", "user.email.invalid", "invalid email address").
            WithField("email_domain", extractDomain(req.Email))
    }
    
    // Business logic...
    user := &User{
        ID:    generateID(),
        Name:  req.Name,
        Email: req.Email,
    }
    
    if err := s.repo.Create(ctx, user); err != nil {
        return nil, WrapDatabaseError("user.create.save", err)
    }
    
    // Framework-agnostic metrics
    s.metrics.UsersCreated.Inc()
    
    logger.InfoCtx(ctx, "user created successfully", "user_id", user.ID)
    return user, nil
}
```

### Import Boundary Enforcement

#### Automated Import Checking

```bash
#!/bin/bash
# scripts/check-imports.sh - Enhanced for framework boundaries

set -e

echo "🔍 Checking import boundaries..."

# Rule 1: Domain packages cannot import framework code
echo "Checking domain packages for framework imports..."
framework_imports=$(find internal/ -name "*.go" -path "*/users/*" -o -path "*/orders/*" | \
    xargs grep -l "github.com/gin-gonic/gin\|github.com/echo" 2>/dev/null || true)

if [ -n "$framework_imports" ]; then
    echo "❌ Domain packages importing framework code:"
    echo "$framework_imports"
    echo ""
    echo "Domain packages should only import platform/obs interfaces."
    echo "Move framework-specific code to internal/api/middleware/ or internal/api/handlers/"
    exit 1
fi

# Rule 2: Platform/obs packages cannot import framework code
echo "Checking platform/obs packages for framework imports..."
obs_framework_imports=$(find internal/platform/obs/ -name "*.go" | \
    xargs grep -l "github.com/gin-gonic/gin\|github.com/echo" 2>/dev/null || true)

if [ -n "$obs_framework_imports" ]; then
    echo "❌ Platform/obs packages importing framework code:"
    echo "$obs_framework_imports"
    echo ""
    echo "Framework code belongs in internal/api/middleware/"
    exit 1
fi

# Rule 3: Check for package-level variables (except constants and errors)
echo "Checking for package-level variables..."
package_vars=$(find internal/ -name "*.go" | \
    xargs grep -n "^var [a-zA-Z]" | \
    grep -v "var (" | \
    grep -v "Err\|err" | \
    grep -v "_test\.go" 2>/dev/null || true)

if [ -n "$package_vars" ]; then
    echo "⚠️  Found package-level variables (verify they're constants or error sentinels):"
    echo "$package_vars"
    echo ""
    echo "Use dependency injection instead of package-level variables."
fi

# Rule 4: Ensure proper interface usage
echo "Checking interface usage patterns..."
concrete_imports=$(find internal/users/ internal/orders/ -name "*.go" | \
    xargs grep -l "prometheus\|slog\.Logger\|otlp" 2>/dev/null || true)

if [ -n "$concrete_imports" ]; then
    echo "⚠️  Domain packages importing concrete observability types:"
    echo "$concrete_imports"
    echo ""
    echo "Use platform/obs interfaces instead of concrete types."
fi

echo "✅ Import boundaries look good!"
```

#### golangci-lint Configuration

```yaml
# .golangci.yml - Framework boundary enforcement
linters:
  enable:
    - depguard
    - gochecknoglobals
    - gochecknoinits

linters-settings:
  depguard:
    rules:
      domain-no-framework:
        files:
          - "**/users/**"
          - "**/orders/**"
        deny:
          - pkg: "github.com/gin-gonic/gin"
            desc: "Domain packages should not import HTTP frameworks"
          - pkg: "github.com/labstack/echo"
            desc: "Domain packages should not import HTTP frameworks"
          - pkg: "github.com/prometheus/client_golang"
            desc: "Domain packages should use platform/obs/metrics interfaces"
            
      obs-no-framework:
        files:
          - "**/platform/obs/**"
        deny:
          - pkg: "github.com/gin-gonic/gin"
            desc: "Observability platform should be framework-agnostic"
          - pkg: "github.com/labstack/echo"
            desc: "Observability platform should be framework-agnostic"

  gochecknoglobals:
    # Allow error sentinels and constants
    - "Err[A-Z].*"
    - "^[A-Z][A-Z_]*$"
```

### Migration Strategy for Multi-Framework Support

#### Phase 1: Single Framework (Current)

- Gin-specific implementation in `api/middleware` and `api/handlers`
- Framework-agnostic business logic in domain packages
- Clean import boundaries enforced

#### Phase 2: Interface Extraction (When Needed)

```go
// internal/platform/http/middleware.go - Framework abstraction
type HTTPMiddleware interface {
    LoggingMiddleware(logger log.Logger) Middleware
    MetricsMiddleware(metrics Metrics) Middleware
    ErrorHandlerMiddleware(logger log.Logger) Middleware
}

type Middleware func(Handler) Handler
type Handler func(Context) error

type Context interface {
    Request() *http.Request
    Response() ResponseWriter
    Param(name string) string
    Bind(obj interface{}) error
    JSON(code int, obj interface{}) error
}
```

#### Phase 3: Multi-Framework Support

```go
// internal/api/gin/middleware.go - Gin adapter
type ginMiddleware struct{}

func (g *ginMiddleware) LoggingMiddleware(logger log.Logger) Middleware {
    return func(next Handler) Handler {
        return func(ctx Context) error {
            // Convert Gin context to generic context
            // Apply logging middleware
            return next(ctx)
        }
    }
}

// internal/api/echo/middleware.go - Echo adapter  
type echoMiddleware struct{}

func (e *echoMiddleware) LoggingMiddleware(logger log.Logger) Middleware {
    // Echo-specific implementation
}
```

### Performance Considerations

#### Gin-Specific Optimizations

```go
// Leverage Gin's performance characteristics
func (h *UserHandler) BulkCreateUsers(c *gin.Context) {
    // Use Gin's efficient JSON binding
    var req []users.CreateUserRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.Error(ValidationError("user.bulk_create.bind", "request.invalid_json", "invalid request format"))
        return
    }
    
    // Leverage Gin's response writer efficiency
    c.JSON(http.StatusCreated, gin.H{
        "users": users,
        "count": len(users),
    })
}

// Gin middleware optimization for high-throughput
func OptimizedObservabilityMiddleware() gin.HandlerFunc {
    // Pre-allocate commonly used objects
    pool := sync.Pool{
        New: func() interface{} {
            return make(map[string]interface{}, 10)
        },
    }
    
    return func(c *gin.Context) {
        fields := pool.Get().(map[string]interface{})
        defer pool.Put(fields)
        
        // Use object pool for reduced allocations
        // Process request...
    }
}
```

#### Framework Comparison Benchmarks

```go
func BenchmarkGinHandler(b *testing.B) {
    router := gin.New()
    router.Use(ObservabilityMiddleware(logger, metrics, cfg))
    router.POST("/users", userHandler.CreateUser)
    
    b.ResetTimer()
    b.ReportAllocs()
    
    for i := 0; i < b.N; i++ {
        w := httptest.NewRecorder()
        req := httptest.NewRequest("POST", "/users", strings.NewReader(`{"name":"test"}`))
        router.ServeHTTP(w, req)
    }
}

// Target: <500ns/op, <3 allocs/op for middleware overhead
```

### Consequences

**Positive:**

- **Fast development velocity**: Leverage Gin's extensive ecosystem and documentation
- **High performance**: Battle-tested framework with optimized request handling
- **Rich observability examples**: Abundant real-world integration patterns
- **Clear extraction path**: Strict boundaries enable clean framework migration
- **Community support**: Large community with observability expertise

**Negative:**

- **Initial framework coupling**: Gin-specific code in API layer
- **Migration effort**: Requires refactoring when adding second framework
- **Ecosystem lock-in**: Gin-specific middleware and patterns
- **Learning transfer**: Gin patterns may not apply to other frameworks

**Mitigation Strategies:**

- **Boundary enforcement**: Automated import checking prevents coupling leakage
- **Interface design**: Handler signatures designed for framework independence
- **Regular extraction practice**: Monthly exercises creating framework adapters
- **Documentation**: Clear guidelines for framework vs domain code placement

### Related ADRs

- [ADR-0002: Zero Global State](#adr-0002-zero-global-state) - Dependency injection supports framework abstraction
- [ADR-0003: Context-First Propagation](#adr-0003-context-first-propagation) - Context flows through framework boundaries
- [ADR-0008: GCP-First Cloud Strategy](#adr-0008-gcp-first-cloud) - Framework choice impacts cloud deployment

### References

- [Gin Web Framework Documentation](https://gin-gonic.com/docs/)
- [Go Proverbs: Interface Discovery](https://go-proverbs.github.io/) - "Don't design with interfaces, discover them"
- [Clean Architecture: Framework Independence](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)
