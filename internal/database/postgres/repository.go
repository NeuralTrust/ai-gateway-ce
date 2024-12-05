package postgres

import (
	"context"
	"database/sql"
)

type Repository struct {
	db *sql.DB
}

func (r *Repository) SubdomainExists(ctx context.Context, subdomain string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM organizations WHERE subdomain = $1)`
	err := r.db.QueryRowContext(ctx, query, subdomain).Scan(&exists)
	return exists, err
}
