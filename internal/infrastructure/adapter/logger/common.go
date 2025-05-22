package logger

import (
	"context"
)

// extractUserID extracts the user ID from metadata
func extractUserID(metadata map[string]any) string {
	userID, _ := metadata["userId"].(string)
	if userID == "" {
		userID, _ = metadata["user_id"].(string)
	}
	return userID
}

// extractRequestID extracts the request ID from context
func extractRequestID(ctx context.Context) string {
	if reqID, ok := ctx.Value("requestId").(string); ok {
		return reqID
	}
	return ""
}

// cleanMetadata creates a copy of metadata without specified keys
func cleanMetadata(metadata map[string]any, excludeKeys []string) map[string]any {
	result := make(map[string]any)
	for k, v := range metadata {
		exclude := false
		for _, excludeKey := range excludeKeys {
			if k == excludeKey {
				exclude = true
				break
			}
		}
		if !exclude {
			result[k] = v
		}
	}
	return result
}
