package converter

import (
	domainModel "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger/model"
	pkgModel "github.com/amirhossein-jamali/auth-guardian/pkg/logger/model"
	"go.uber.org/zap"
)

// DomainToZap converts domain logger fields to zap fields
func DomainToZap(fields ...domainModel.Field) []zap.Field {
	result := make([]zap.Field, 0, len(fields))

	for _, field := range fields {
		result = append(result, zap.Any(field.Key, field.Value))
	}

	return result
}

// PkgToDomain converts pkg logger fields to domain logger fields
func PkgToDomain(fields ...pkgModel.Field) []domainModel.Field {
	result := make([]domainModel.Field, 0, len(fields))

	for _, field := range fields {
		result = append(result, domainModel.Field{
			Key:   field.Key,
			Value: field.Value,
		})
	}

	return result
}

// DomainToPkg converts domain logger fields to pkg logger fields
func DomainToPkg(fields ...domainModel.Field) []pkgModel.Field {
	result := make([]pkgModel.Field, 0, len(fields))

	for _, field := range fields {
		result = append(result, pkgModel.Field{
			Key:   field.Key,
			Value: field.Value,
		})
	}

	return result
}
