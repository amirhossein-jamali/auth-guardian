# Logger Package

This package provides a unified logging interface for the Auth Guardian application. It follows the hexagonal architecture pattern, with:

- **Public interface**: Defined in `pkg/logger/logger.go` 
- **Domain interface**: Defined in `internal/port/output/logger/logger.go`
- **Implementation**: Provided by ZapLogger in `internal/adapter/output/logger/zap/logger.go`
- **Adapter**: Converting between domain and pkg loggers in `internal/adapter/output/logger/pkg/adapter.go`
- **Factory**: Singleton pattern in `internal/adapter/output/logger/factory/factory.go`

## Architecture

The logger follows a layered approach:

1. **Public API** (`pkg/logger`): The interface exposed to application code
2. **Domain Layer** (`internal/port/output/logger`): The interface used within the domain
3. **Adapter Layer** (`internal/adapter/output/logger`): Contains implementations and converters
4. **Implementation** (`internal/adapter/output/logger/zap`): The actual ZapLogger implementation

## Usage

```go
import (
    "github.com/amirhossein-jamali/auth-guardian/internal/adapter/output/logger/factory"
    "github.com/amirhossein-jamali/auth-guardian/pkg/logger"
    "github.com/spf13/viper"
)

// Initialize logger (typically in main.go or bootstrap)
config := viper.New()
// ... configure viper ...
loggerFactory := factory.GetFactory(config)
_ = loggerFactory.GetPkgLogger() // This initializes the singleton

// Use package-level logger instance in any part of the application
log := factory.GetPkgLoggerInstance()
log.Info("Application started", logger.NewField("version", "1.0.0"))

// Create contextual logger
requestLogger := log.With(logger.NewField("request_id", "abc-123"))
requestLogger.Debug("Processing request")
```

## Helper Functions

The domain logger package provides helper functions for common logging patterns:

```go
import (
    "github.com/amirhossein-jamali/auth-guardian/internal/adapter/output/logger/factory"
    domainLogger "github.com/amirhossein-jamali/auth-guardian/internal/port/output/logger"
)

// Get the domain logger
log := factory.GetDomainLoggerInstance()

// Use helper functions
requestLogger := domainLogger.WithRequestID(log, "abc-123")
userLogger := domainLogger.WithUserID(log, "user-456")
```

## Log Levels

The logger provides multiple log levels:
- **Debug**: Development-time information
- **Info**: General operational information
- **Warn**: Warning conditions
- **Error**: Error conditions
- **Fatal**: Critical errors causing application termination

## Configuration

The logger behavior is controlled by the `app.production` configuration setting:
- When `true`: Uses production configuration with JSON formatting
- When `false`: Uses development configuration with colorized console output

## Structured Logging

The logger supports structured logging through fields:

```go
log.Info("User logged in", 
    logger.NewField("user_id", userID),
    logger.NewField("ip", clientIP),
)
``` 