package repository

import (
	"context"
	"errors"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	domainErr "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	portRepo "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/repository"
	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/model"
	"gorm.io/gorm"
)

// GormOTPRepository implements the OTP repository interface using GORM
type GormOTPRepository struct {
	db           *gorm.DB
	logger       logger.Logger
	timeProvider tport.Provider
}

// mapDBError maps database errors to domain errors
func mapDBError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return domainErr.ErrNotFound
	}

	// Handle other specific DB errors if needed

	// Default to internal error
	return domainErr.ErrInternalServer
}

// NewGormOTPRepository creates a new GormOTPRepository
func NewGormOTPRepository(db *gorm.DB, logger logger.Logger, timeProvider tport.Provider) portRepo.OTPRepository {
	return &GormOTPRepository{
		db:           db,
		logger:       logger,
		timeProvider: timeProvider,
	}
}

// Create creates a new OTP record
func (r *GormOTPRepository) Create(ctx context.Context, otp *entity.OTP) error {
	otpModel := &model.OTP{
		ID:           string(otp.ID),
		PhoneNumber:  otp.PhoneNumber,
		Code:         otp.Code,
		CreatedAt:    otp.CreatedAt,
		ExpiresAt:    otp.ExpiresAt,
		IsUsed:       otp.IsUsed,
		AttemptCount: otp.AttemptCount,
	}

	if err := r.db.WithContext(ctx).Create(otpModel).Error; err != nil {
		r.logger.Error("Failed to create OTP record", map[string]any{
			"otpID":    otp.ID,
			"phone":    otp.PhoneNumber,
			"error":    err.Error(),
			"callsite": "GormOTPRepository.Create",
		})
		return mapDBError(err)
	}

	return nil
}

// GetByPhoneNumber gets the latest active OTP for a phone number
func (r *GormOTPRepository) GetByPhoneNumber(ctx context.Context, phoneNumber string) (*entity.OTP, error) {
	var otpModel model.OTP

	// Get the most recent OTP for this phone number
	if err := r.db.WithContext(ctx).
		Where("phone_number = ?", phoneNumber).
		Order("created_at DESC").
		First(&otpModel).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domainErr.ErrNotFound
		}

		r.logger.Error("Failed to get OTP by phone number", map[string]any{
			"phone":    phoneNumber,
			"error":    err.Error(),
			"callsite": "GormOTPRepository.GetByPhoneNumber",
		})
		return nil, mapDBError(err)
	}

	otp := &entity.OTP{
		ID:           entity.ID(otpModel.ID),
		PhoneNumber:  otpModel.PhoneNumber,
		Code:         otpModel.Code,
		CreatedAt:    otpModel.CreatedAt,
		ExpiresAt:    otpModel.ExpiresAt,
		IsUsed:       otpModel.IsUsed,
		AttemptCount: otpModel.AttemptCount,
	}

	return otp, nil
}

// Update updates an OTP record
func (r *GormOTPRepository) Update(ctx context.Context, otp *entity.OTP) error {
	updates := map[string]interface{}{
		"is_used":       otp.IsUsed,
		"attempt_count": otp.AttemptCount,
		"expires_at":    otp.ExpiresAt,
	}

	if err := r.db.WithContext(ctx).
		Model(&model.OTP{}).
		Where("id = ?", string(otp.ID)).
		Updates(updates).Error; err != nil {
		r.logger.Error("Failed to update OTP record", map[string]any{
			"otpID":    otp.ID,
			"error":    err.Error(),
			"callsite": "GormOTPRepository.Update",
		})
		return mapDBError(err)
	}

	return nil
}

// Delete deletes an OTP record
func (r *GormOTPRepository) Delete(ctx context.Context, otpID entity.ID) error {
	if err := r.db.WithContext(ctx).
		Where("id = ?", string(otpID)).
		Delete(&model.OTP{}).Error; err != nil {
		r.logger.Error("Failed to delete OTP record", map[string]any{
			"otpID":    otpID,
			"error":    err.Error(),
			"callsite": "GormOTPRepository.Delete",
		})
		return mapDBError(err)
	}

	return nil
}

// DeleteExpired deletes all expired OTP records
func (r *GormOTPRepository) DeleteExpired(ctx context.Context) (int, error) {
	now := r.timeProvider.Now()
	result := r.db.WithContext(ctx).
		Where("expires_at < ?", now).
		Delete(&model.OTP{})

	if result.Error != nil {
		r.logger.Error("Failed to delete expired OTP records", map[string]any{
			"error":    result.Error.Error(),
			"callsite": "GormOTPRepository.DeleteExpired",
		})
		return 0, mapDBError(result.Error)
	}

	return int(result.RowsAffected), nil
} 