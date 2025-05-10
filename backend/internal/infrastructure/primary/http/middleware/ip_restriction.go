package middleware

import (
	"net"
	"net/http"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger/model"
	"github.com/gin-gonic/gin"
)

// RestrictByIP middleware restricts access to specific IP addresses or CIDR ranges
func RestrictByIP(logger logger.Logger, allowedIPs []string) gin.HandlerFunc {
	// Check if the allowed IPs list is empty
	if len(allowedIPs) == 0 {
		// If list is empty, log a warning and allow all IPs
		if logger != nil {
			logger.Warn("Empty allowed IP list. All IPs will be allowed.")
		}
		return func(c *gin.Context) {
			c.Next() // Allow all access
		}
	}

	// Parse allowed IP ranges
	allowedNets := make([]*net.IPNet, 0, len(allowedIPs))
	allowedSpecifics := make([]net.IP, 0, len(allowedIPs))

	for _, ipStr := range allowedIPs {
		if ipStr == "" {
			// Skip empty strings
			continue
		}

		// Check if it's a CIDR
		if _, network, err := net.ParseCIDR(ipStr); err == nil {
			allowedNets = append(allowedNets, network)
		} else if ip := net.ParseIP(ipStr); ip != nil {
			allowedSpecifics = append(allowedSpecifics, ip)
		} else {
			// Ensure logger is not nil before using it
			if logger != nil {
				logger.Warn("Invalid IP or CIDR in allowed list", model.NewField("ip", ipStr))
			}
		}
	}

	// If no valid IPs were found
	if len(allowedNets) == 0 && len(allowedSpecifics) == 0 {
		if logger != nil {
			logger.Warn("No valid IPs in allowed list. All IPs will be allowed.")
		}
		return func(c *gin.Context) {
			c.Next() // Allow all access
		}
	}

	return func(c *gin.Context) {
		// Get client IP
		clientIP := c.ClientIP()
		if clientIP == "" {
			if logger != nil {
				logger.Warn("Empty client IP")
			}
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		ip := net.ParseIP(clientIP)
		if ip == nil {
			if logger != nil {
				logger.Warn("Failed to parse client IP", model.NewField("ip", clientIP))
			}
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		// Check if IP is allowed
		allowed := false

		// Check specific IPs
		for _, allowedIP := range allowedSpecifics {
			if allowedIP.Equal(ip) {
				allowed = true
				break
			}
		}

		// Check CIDRs
		if !allowed {
			for _, network := range allowedNets {
				if network.Contains(ip) {
					allowed = true
					break
				}
			}
		}

		if !allowed {
			if logger != nil {
				logger.Warn("Unauthorized access attempt to restricted endpoint",
					model.NewField("ip", ip.String()),
					model.NewField("path", c.Request.URL.Path))
			}
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		c.Next()
	}
}
