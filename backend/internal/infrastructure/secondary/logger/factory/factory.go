package factory

import (
	domainLogger "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/secondary/logger/pkg"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/secondary/logger/zap"
	"sync"

	pkgLogger "github.com/amirhossein-jamali/auth-guardian/pkg/logger"
	"github.com/spf13/viper"
)

var (
	domainInstance domainLogger.Logger
	pkgInstance    pkgLogger.Logger
	instanceOnce   sync.Once
	factoryOnce    sync.Once
	factory        *Factory
)

// Factory creates and configures loggers
type Factory struct {
	config *viper.Viper
}

// GetFactory returns the singleton factory instance
func GetFactory(config *viper.Viper) *Factory {
	factoryOnce.Do(func() {
		factory = &Factory{
			config: config,
		}
	})
	return factory
}

// InitLoggers initializes both logger instances
func (f *Factory) InitLoggers() {
	instanceOnce.Do(func() {
		domainInstance = f.NewDomainLogger()
		pkgInstance = pkg.NewAdapter(domainInstance)
	})
}

// NewDomainLogger creates a new domain logger
func (f *Factory) NewDomainLogger() domainLogger.Logger {
	isProduction := f.config.GetBool("app.production")
	return zap.NewLogger(isProduction)
}

// NewPkgLogger creates a new pkg logger
func (f *Factory) NewPkgLogger() pkgLogger.Logger {
	// Create adapter that converts domain logger to pkg logger
	return pkg.NewAdapter(f.NewDomainLogger())
}

// GetDomainLogger returns the singleton domain logger instance
func (f *Factory) GetDomainLogger() domainLogger.Logger {
	if domainInstance == nil {
		f.InitLoggers()
	}
	return domainInstance
}

// GetPkgLogger returns the singleton pkg logger instance
func (f *Factory) GetPkgLogger() pkgLogger.Logger {
	if pkgInstance == nil {
		f.InitLoggers()
	}
	return pkgInstance
}

// GetDomainLoggerInstance returns the singleton domain logger instance
func GetDomainLoggerInstance() domainLogger.Logger {
	if domainInstance == nil {
		panic("Logger not initialized. Call GetFactory(config).GetDomainLogger() first")
	}
	return domainInstance
}

// GetPkgLoggerInstance returns the singleton pkg logger instance
func GetPkgLoggerInstance() pkgLogger.Logger {
	if pkgInstance == nil {
		panic("Logger not initialized. Call GetFactory(config).GetPkgLogger() first")
	}
	return pkgInstance
}

// ResetForTest resets the logger instance for testing purposes only
func ResetForTest() {
	domainInstance = nil
	pkgInstance = nil
	factory = nil
}
