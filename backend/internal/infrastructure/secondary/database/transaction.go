package database

import (
	"context"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger/model"
	"gorm.io/gorm"
)

// RunInTransaction runs a function within a transaction
func (m *PostgresManager) RunInTransaction(ctx context.Context, fn func(tx *gorm.DB) error) error {
	if ctx.Err() != nil {
		m.logger.Warn("Context already canceled before starting transaction")
		return ctx.Err()
	}

	m.logger.Info("Starting database transaction")

	err := m.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		err := fn(tx)
		if err != nil {
			m.logger.Error("Transaction failed, rolling back",
				model.NewField("error", err.Error()))
			return err
		}
		m.logger.Info("Transaction successful, committing")
		return nil
	})

	if err != nil {
		return err
	}

	return nil
}
