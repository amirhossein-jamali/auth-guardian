package middleware

import (
	"net"
	"net/http"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	"github.com/gin-gonic/gin"
)

// IPRestrictionMiddleware restricts access to specific IP addresses
type IPRestrictionMiddleware struct {
	logger      logger.Logger
	allowedNets []*net.IPNet
	allowedIPs  []net.IP
}

// NewIPRestrictionMiddleware creates a new instance of IPRestrictionMiddleware
func NewIPRestrictionMiddleware(logger logger.Logger, allowedIPs []string) *IPRestrictionMiddleware {
	// Initialize the middleware
	m := &IPRestrictionMiddleware{
		logger:      logger,
		allowedNets: make([]*net.IPNet, 0, len(allowedIPs)),
		allowedIPs:  make([]net.IP, 0, len(allowedIPs)),
	}

	// Check if the allowed IPs list is empty
	if len(allowedIPs) == 0 {
		if logger != nil {
			logger.Warn("Empty allowed IP list. All IPs will be allowed.", map[string]any{})
		}
		return m
	}

	// Parse allowed IP ranges
	for _, ipStr := range allowedIPs {
		if ipStr == "" {
			// Skip empty strings
			continue
		}

		// Check if it's a CIDR
		if _, network, err := net.ParseCIDR(ipStr); err == nil {
			m.allowedNets = append(m.allowedNets, network)
		} else if ip := net.ParseIP(ipStr); ip != nil {
			m.allowedIPs = append(m.allowedIPs, ip)
		} else {
			if logger != nil {
				logger.Warn("Invalid IP or CIDR in allowed list", map[string]any{
					"ip": ipStr,
				})
			}
		}
	}

	// If no valid IPs were found
	if len(m.allowedNets) == 0 && len(m.allowedIPs) == 0 {
		if logger != nil {
			logger.Warn("No valid IPs in allowed list. All IPs will be allowed.", map[string]any{})
		}
	}

	return m
}

// RestrictByIP restricts access to allowed IPs
func (m *IPRestrictionMiddleware) RestrictByIP() gin.HandlerFunc {
	// If no restrictions, allow all
	if len(m.allowedNets) == 0 && len(m.allowedIPs) == 0 {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	return func(c *gin.Context) {
		// Get client IP
		clientIP := c.ClientIP()
		if clientIP == "" {
			if m.logger != nil {
				m.logger.Warn("Empty client IP", map[string]any{})
			}
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		ip := net.ParseIP(clientIP)
		if ip == nil {
			if m.logger != nil {
				m.logger.Warn("Failed to parse client IP", map[string]any{
					"ip": clientIP,
				})
			}
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		// Check if IP is allowed
		allowed := false

		// Check specific IPs
		for _, allowedIP := range m.allowedIPs {
			if allowedIP.Equal(ip) {
				allowed = true
				break
			}
		}

		// Check CIDRs
		if !allowed {
			for _, network := range m.allowedNets {
				if network.Contains(ip) {
					allowed = true
					break
				}
			}
		}

		if !allowed {
			if m.logger != nil {
				m.logger.Warn("Unauthorized access attempt to restricted endpoint", map[string]any{
					"ip":   ip.String(),
					"path": c.Request.URL.Path,
				})
			}
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		c.Next()
	}
}
