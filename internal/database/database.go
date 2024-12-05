package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type DB struct {
	db *sqlx.DB
}

type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
}

func NewDB(config *Config) (*DB, error) {
	connStr := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Host,
		config.Port,
		config.User,
		config.Password,
		config.DBName,
		config.SSLMode,
	)

	db, err := sqlx.Connect("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("error connecting to database: %v", err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	return &DB{db: db}, nil
}

func (db *DB) Close() error {
	return db.db.Close()
}

// Add methods to access sqlx functionality
func (db *DB) NamedExecContext(ctx interface{}, query string, arg interface{}) (sql.Result, error) {
	return db.db.NamedExecContext(ctx.(context.Context), query, arg)
}

func (db *DB) GetContext(ctx interface{}, dest interface{}, query string, args ...interface{}) error {
	return db.db.GetContext(ctx.(context.Context), dest, query, args...)
}

func (db *DB) SelectContext(ctx interface{}, dest interface{}, query string, args ...interface{}) error {
	return db.db.SelectContext(ctx.(context.Context), dest, query, args...)
}

func (db *DB) ExecContext(ctx interface{}, query string, args ...interface{}) (sql.Result, error) {
	return db.db.ExecContext(ctx.(context.Context), query, args...)
}

func (db *DB) Ping() error {
	return db.db.Ping()
}
