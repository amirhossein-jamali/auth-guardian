package database

import (
	"context"
	"database/sql"

	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
)

// SQLDatabase defines operations for a SQL database connection
// This interface allows us to abstract away direct time package dependencies
type SQLDatabase interface {
	SetMaxOpenConns(n int)
	SetMaxIdleConns(n int)
	SetConnMaxLifetime(d tport.Duration, provider tport.Provider)
	Ping() error
	PingContext(ctx context.Context) error
	Close() error
}

// sqlDatabaseWrapper wraps *sql.DB to implement our domain-centric interface
type sqlDatabaseWrapper struct {
	db *sql.DB
}

// newSQLDatabaseWrapper creates a new wrapper for *sql.DB
func newSQLDatabaseWrapper(db *sql.DB) SQLDatabase {
	return &sqlDatabaseWrapper{db: db}
}

// SetMaxOpenConns sets the maximum number of open connections
func (w *sqlDatabaseWrapper) SetMaxOpenConns(n int) {
	w.db.SetMaxOpenConns(n)
}

// SetMaxIdleConns sets the maximum number of idle connections
func (w *sqlDatabaseWrapper) SetMaxIdleConns(n int) {
	w.db.SetMaxIdleConns(n)
}

// SetConnMaxLifetime sets the maximum lifetime of a connection
// This is where the conversion from domain Duration to time.Duration happens
func (w *sqlDatabaseWrapper) SetConnMaxLifetime(d tport.Duration, provider tport.Provider) {
	// Convert from domain Duration to standard time.Duration only at this boundary
	w.db.SetConnMaxLifetime(d.Std())
}

// Ping verifies connection to the database
func (w *sqlDatabaseWrapper) Ping() error {
	return w.db.Ping()
}

// Close closes the database connection
func (w *sqlDatabaseWrapper) Close() error {
	return w.db.Close()
}

// PingContext verifies connection to the database with context
func (w *sqlDatabaseWrapper) PingContext(ctx context.Context) error {
	return w.db.PingContext(ctx)
}
