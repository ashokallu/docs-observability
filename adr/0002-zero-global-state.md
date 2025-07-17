# ADR-0002: Zero Global State Architecture

**Status:** Accepted  
**Date:** 2025-07-17  
**Tags:** architecture, testability, config, go, dependency-injection

## Context

Package-level mutable state creates hidden dependencies that break test determinism, prevent parallel test execution, and couple components in non-obvious ways. Most Go observability examples use global singletons that create testing nightmares.

### Problem Statement

Common anti-patterns in Go observability code:

```go
// Anti-pattern: Hidden global state
var logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
otel.SetTracerProvider(provider)
prometheus.MustRegister(httpRequestsTotal)
```

This creates:

- **Hidden dependencies** that break testing
- **Inability to run parallel tests** with different configurations
- **Coupling between packages** through shared global state
- **Difficulty mocking telemetry** in unit tests
- **Race conditions** in concurrent test execution

### Forces & Considerations

| Consideration | Global State | Dependency Injection | Impact |
|---------------|--------------|---------------------|---------|
| **Test Isolation** | ❌ Shared state | ✅ Independent state | High |
| **Parallel Testing** | ❌ Race conditions | ✅ Safe concurrency | High |
| **Mocking/Stubbing** | ❌ Global replacement | ✅ Interface injection | High |
| **Code Clarity** | ❌ Hidden dependencies | ✅ Explicit dependencies | Medium |
| **Initialization Order** | ❌ init() complexity | ✅ Construction order | Medium |
| **Development Velocity** | ✅ Less boilerplate | ❌ More parameters | Low |

### Options Considered

#### Option 1: Package-Level Globals (Rejected)

```go
var logger = slog.New(...)
var tracer = otel.Tracer(...)

func ProcessUser(user User) {
    logger.Info("processing", "user_id", user.ID)
    span := tracer.Start(ctx, "process_user")
}
```

**Pros:** Simple, less boilerplate  
**Cons:** Untestable, race conditions, hidden coupling

#### Option 2: Singleton Pattern (Rejected)

```go
func Logger() *slog.Logger {
    once.Do(func() { instance = slog.New(...) })
    return instance
}
```

**Pros:** Lazy initialization, thread-safe  
**Cons:** Still global state, difficult to test, inflexible

#### Option 3: Constructor Injection (Chosen)

```go
type UserService struct {
    logger  log.Logger
    tracer  trace.Tracer
    metrics *UserMetrics
}

func NewUserService(logger log.Logger, tracer trace.Tracer, metrics *UserMetrics) *UserService {
    return &UserService{logger: logger, tracer: tracer, metrics: metrics}
}
```

**Pros:** Testable, explicit, flexible  
**Cons:** More verbose, requires wiring

#### Option 4: Service Locator (Rejected)

```go
func ProcessUser(user User) {
    logger := serviceLocator.Get("logger").(log.Logger)
}
```

**Pros:** Less parameter passing  
**Cons:** Runtime failures, implicit dependencies, anti-pattern

### Decision

**All observability dependencies injected via constructor parameters.**

### Decision Rules

1. **No mutable package-level variables** except compile-time constants and error sentinels
2. **Constructor injection**: All services receive dependencies as explicit parameters
3. **Interface boundaries**: Domain packages depend only on observability interfaces
4. **Context propagation**: All telemetry metadata flows through `context.Context`
5. **Composition root**: All dependency wiring happens in `main()` function

### Implementation Patterns

#### Service Construction

```go
type OrderService struct {
    logger  log.Logger           // Interface, not concrete
    tracer  trace.Tracer        // Interface, not concrete  
    metrics *OrderMetrics       // Concrete metrics (Prometheus-specific)
    repo    OrderRepository     // Domain interface
}

func NewOrderService(
    logger log.Logger,
    tracer trace.Tracer,
    metrics *OrderMetrics,
    repo OrderRepository,
) *OrderService {
    return &OrderService{
        logger:  logger,
        tracer:  tracer,
        metrics: metrics,
        repo:    repo,
    }
}
```

#### Composition Root

```go
func main() {
    // Load configuration
    cfg := config.LoadFromEnv()
    
    // Initialize observability
    logger := log.NewLogger(cfg.Log)
    tracer := trace.NewTracer(cfg.Trace)
    metrics := metrics.NewRegistry(cfg.Metrics)
    
    // Initialize repositories
    userRepo := postgres.NewUserRepository(cfg.DB)
    orderRepo := postgres.NewOrderRepository(cfg.DB)
    
    // Initialize services
    userService := users.NewService(logger, tracer, metrics.Users, userRepo)
    orderService := orders.NewService(logger, tracer, metrics.Orders, orderRepo)
    
    // Initialize HTTP server
    server := api.NewServer(cfg.HTTP, logger, tracer, metrics.HTTP)
    server.RegisterUserRoutes(userService)
    server.RegisterOrderRoutes(orderService)
    
    server.Start()
}
```

#### Test Construction

```go
func TestUserService_CreateUser(t *testing.T) {
    // Create test dependencies
    logger, logCapture := log.NewTestLogger()
    tracer, traceCapture := trace.NewTestTracer()
    metrics := metrics.NewTestRegistry()
    repo := &mockUserRepository{}
    
    // Create service under test
    service := users.NewService(logger, tracer, metrics, repo)
    
    // Test the service
    ctx := context.Background()
    user, err := service.CreateUser(ctx, validRequest)
    
    require.NoError(t, err)
    assert.NotEmpty(t, user.ID)
    
    // Assert observability behavior
    entries := logCapture.Entries()
    assert.Len(t, entries, 1)
    
    spans := traceCapture.Spans()
    assert.Len(t, spans, 1)
    assert.Equal(t, "user.create", spans[0].Name)
}
```

### Enforcement Mechanisms

#### Static Analysis

```bash
# scripts/check-globals.sh
# Detect package-level variables (excluding constants and errors)
forbidden_globals=$(find internal/ -name "*.go" | \
    xargs grep -n "^var [a-zA-Z]" | \
    grep -v "var (" | \
    grep -v "Err\|err" | \
    grep -v "_test\.go" || true)

if [ -n "$forbidden_globals" ]; then
    echo "❌ Found forbidden package-level variables:"
    echo "$forbidden_globals"
    exit 1
fi
```

#### golangci-lint Configuration

```yaml
# .golangci.yml
linters:
  enable:
    - gochecknoglobals  # Forbid global variables
    - gochecknoinits    # Forbid init() functions

linters-settings:
  gochecknoglobals:
    # Allow these patterns
    - "Err[A-Z].*"      # Error sentinels
    - "^[A-Z][A-Z_]*$"  # Constants
```

#### Import Boundary Checking

```bash
# scripts/check-imports.sh
# Ensure domain packages don't import framework code
framework_imports=$(find internal/ -name "*.go" -path "*/users/*" -o -path "*/orders/*" | \
    xargs grep -l "github.com/gin-gonic/gin\|github.com/prometheus/client_golang" || true)

if [ -n "$framework_imports" ]; then
    echo "❌ Domain packages importing framework code:"
    echo "$framework_imports"
    exit 1
fi
```

### Interface Design Guidelines

#### Observability Interfaces

```go
// internal/platform/obs/log/logger.go
type Logger interface {
    DebugCtx(ctx context.Context, msg string, args ...any)
    InfoCtx(ctx context.Context, msg string, args ...any)
    WarnCtx(ctx context.Context, msg string, args ...any)
    ErrorCtx(ctx context.Context, msg string, args ...any)
    With(args ...any) Logger
}

// internal/platform/obs/trace/tracer.go  
type Tracer interface {
    Start(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span)
}

// internal/platform/obs/metrics/metrics.go
type Registry interface {
    CounterVec(name, help string, labels []string) *prometheus.CounterVec
    HistogramVec(name, help string, labels []string, buckets []float64) *prometheus.HistogramVec
    Handler() http.Handler
}
```

#### Domain Service Interfaces

```go
// internal/users/service.go
type Service interface {
    CreateUser(ctx context.Context, req CreateUserRequest) (*User, error)
    GetUser(ctx context.Context, id string) (*User, error)
    UpdateUser(ctx context.Context, id string, req UpdateUserRequest) (*User, error)
    DeleteUser(ctx context.Context, id string) error
}

// internal/users/repository.go
type Repository interface {
    Create(ctx context.Context, user *User) error
    GetByID(ctx context.Context, id string) (*User, error)
    Update(ctx context.Context, user *User) error
    Delete(ctx context.Context, id string) error
}
```

### Configuration Management

#### Environment-Driven Configuration

```go
type Config struct {
    HTTP struct {
        Port         int           `env:"HTTP_PORT" envDefault:"8080"`
        ReadTimeout  time.Duration `env:"HTTP_READ_TIMEOUT" envDefault:"30s"`
        WriteTimeout time.Duration `env:"HTTP_WRITE_TIMEOUT" envDefault:"30s"`
    }
    
    Log struct {
        Level       string `env:"LOG_LEVEL" envDefault:"info"`
        Format      string `env:"LOG_FORMAT" envDefault:"json"`
        UserIDMode  string `env:"LOG_USER_ID_MODE" envDefault:"redact"`
    }
    
    Trace struct {
        Enabled      bool    `env:"TRACE_ENABLED" envDefault:"true"`
        SampleRate   float64 `env:"TRACE_SAMPLE_RATE" envDefault:"1.0"`
        OTLPEndpoint string  `env:"OTLP_ENDPOINT" envDefault:"http://otel-collector:4318"`
    }
    
    Metrics struct {
        Enabled bool   `env:"METRICS_ENABLED" envDefault:"true"`
        Path    string `env:"METRICS_PATH" envDefault:"/metrics"`
    }
}

func LoadFromEnv() Config {
    var cfg Config
    if err := env.Parse(&cfg); err != nil {
        log.Fatal("failed to parse config:", err)
    }
    return cfg
}
```

### Testing Strategies

#### Unit Test Patterns

```go
func TestUserService_Isolated(t *testing.T) {
    // Each test gets fresh dependencies
    logger, _ := log.NewTestLogger()
    tracer, _ := trace.NewTestTracer()
    metrics := metrics.NewTestRegistry()
    repo := &mockUserRepository{}
    
    service := users.NewService(logger, tracer, metrics, repo)
    
    // Test is completely isolated
    // No global state can interfere
}
```

#### Integration Test Patterns

```go
func TestUserService_Integration(t *testing.T) {
    // Spin up test database
    db := testcontainers.StartPostgreSQL(t)
    defer db.Cleanup()
    
    // Create real dependencies with test configuration
    logger, logCapture := log.NewTestLogger()
    tracer, traceCapture := trace.NewTestTracer()
    metrics := metrics.NewTestRegistry()
    repo := postgres.NewUserRepository(db.ConnectionString())
    
    service := users.NewService(logger, tracer, metrics, repo)
    
    // Test with real database
    ctx := context.Background()
    user, err := service.CreateUser(ctx, validRequest)
    
    require.NoError(t, err)
    
    // Verify observability signals
    assert.Contains(t, logCapture.Messages(), "user created")
    assert.Len(t, traceCapture.Spans(), 1)
}
```

#### Parallel Test Safety

```go
func TestUserService_Parallel(t *testing.T) {
    tests := []struct {
        name string
        req  CreateUserRequest
    }{
        {"valid user", validRequest},
        {"invalid email", invalidEmailRequest},
        {"duplicate email", duplicateEmailRequest},
    }
    
    for _, tt := range tests {
        tt := tt // Capture range variable
        t.Run(tt.name, func(t *testing.T) {
            t.Parallel() // Safe because no global state
            
            // Fresh dependencies for each parallel test
            logger, _ := log.NewTestLogger()
            tracer, _ := trace.NewTestTracer()
            metrics := metrics.NewTestRegistry()
            repo := &mockUserRepository{}
            
            service := users.NewService(logger, tracer, metrics, repo)
            
            // Test logic...
        })
    }
}
```

### Migration Guide

#### From Global Loggers

```go
// Before: Global logger
var logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))

func ProcessUser(user User) {
    logger.Info("processing user", "user_id", user.ID)
}

// After: Injected logger
type UserService struct {
    logger log.Logger
}

func (s *UserService) ProcessUser(ctx context.Context, user User) {
    s.logger.InfoCtx(ctx, "processing user", "user_id", user.ID)
}
```

#### From Global Metrics

```go
// Before: Global metrics
var httpRequests = prometheus.NewCounterVec(...)

func init() {
    prometheus.MustRegister(httpRequests)
}

func HandleRequest(w http.ResponseWriter, r *http.Request) {
    httpRequests.WithLabelValues(r.Method, r.URL.Path).Inc()
}

// After: Injected metrics
type HTTPMetrics struct {
    requests *prometheus.CounterVec
}

type Server struct {
    metrics *HTTPMetrics
}

func (s *Server) HandleRequest(w http.ResponseWriter, r *http.Request) {
    s.metrics.requests.WithLabelValues(r.Method, templateRoute(r.URL.Path)).Inc()
}
```

### Consequences

**Positive:**

- **Deterministic testing**: Each test gets isolated dependencies
- **Parallel test safety**: No shared state between test goroutines
- **Explicit dependencies**: Clear understanding of component relationships
- **Flexible configuration**: Different environments get different implementations
- **Easy mocking**: Interfaces enable test doubles
- **Better debugging**: No hidden global state mutations

**Negative:**

- **More verbose initialization**: Constructor parameters increase
- **Dependency wiring complexity**: main() function becomes larger
- **Parameter passing overhead**: More function parameters
- **Learning curve**: Requires understanding of dependency injection

**Mitigation Strategies:**

- **DI framework**: Consider lightweight DI frameworks for complex applications
- **Constructor helpers**: Provide reasonable defaults and factory functions
- **Interface design**: Keep interfaces small and focused
- **Documentation**: Clear examples of construction patterns

### Related ADRs

- [ADR-0003: Context-First Propagation](#adr-0003-context-first-propagation) - Context carries injected dependencies
- [ADR-0005: Error Classification](#adr-0005-error-classification) - Error interfaces support injection
- [ADR-0011: Signal Access & Retention](#adr-0011-signal-access-retention) - Access control via injected policies

### References

- [Dependency Injection Principles, Practices, and Patterns](https://www.manning.com/books/dependency-injection-principles-practices-patterns)
- [Go Proverbs - Rob Pike](https://go-proverbs.github.io/) - "Don't communicate by sharing memory"
- [Effective Go - Constructors](https://go.dev/doc/effective_go#constructors_and_composite_types)
