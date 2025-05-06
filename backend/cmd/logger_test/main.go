package main

import (
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/secondary/logger/factory"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/configs"
	pkgLogger "github.com/amirhossein-jamali/auth-guardian/pkg/logger"
)

func main() {
	// Load configuration
	config := configs.LoadConfig()

	// Initialize logger
	loggerFactory := factory.GetFactory(config)
	log := loggerFactory.GetPkgLogger()

	// Test various log levels
	log.Debug("This is a debug message")
	log.Info("This is an info message")
	log.Warn("This is a warning message")
	log.Error("This is an error message")

	// Test with fields
	log.Info("Message with fields",
		pkgLogger.NewField("user_id", "12345"),
		pkgLogger.NewField("action", "login"),
		pkgLogger.NewField("timestamp", time.Now().Unix()),
	)

	// Test nested fields
	data := map[string]interface{}{
		"name":  "Test User",
		"roles": []string{"admin", "user"},
		"metadata": map[string]string{
			"last_login": time.Now().Format(time.RFC3339),
		},
	}
	log.Info("Complex data structure", pkgLogger.NewField("user_data", data))

	// Test with contextual logger
	contextLogger := log.With(
		pkgLogger.NewField("request_id", "abcd-1234"),
		pkgLogger.NewField("ip", "192.168.1.1"),
	)
	contextLogger.Info("Request processed successfully")
	contextLogger.Error("Request failed")

	// Test log formatting
	log.Info("Testing log formatting",
		pkgLogger.NewField("integer", 42),
		pkgLogger.NewField("float", 3.14),
		pkgLogger.NewField("boolean", true),
		pkgLogger.NewField("nil_value", nil),
	)
}
