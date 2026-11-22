package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// isUniqueViolation reports whether err is a Postgres unique-constraint error.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// isForeignKeyViolation reports whether err is a Postgres foreign-key error.
// In the background workers it means the host (or rule) was deleted while a
// cycle was running: there is nothing left to store, and nothing to report.
func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

//go:embed schema.sql
var schemaSQL string

func openDB(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = 10

	// Postgres may not be ready the instant the app starts; retry briefly.
	var pool *pgxpool.Pool
	deadline := time.Now().Add(60 * time.Second)
	for {
		pool, err = pgxpool.NewWithConfig(ctx, cfg)
		if err == nil {
			if err = pool.Ping(ctx); err == nil {
				break
			}
			pool.Close()
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("database not reachable: %w", err)
		}
		time.Sleep(time.Second)
	}

	if _, err := pool.Exec(ctx, schemaSQL); err != nil {
		pool.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	return pool, nil
}

// defaultProfiles are created for every new organization. The first is default.
var defaultProfiles = []struct {
	Name       string
	IntervalS  int
	PingCount  int
	PacketSize int
	Default    bool
}{
	{"Standard", 60, 20, 56, true},
	{"Fast", 30, 20, 56, false},
	{"Coarse", 300, 20, 56, false},
	{"Large packet", 60, 15, 1400, false},
}
