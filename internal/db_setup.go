package internal

import (
	"context"
	"fmt"
	"io/fs"
	"net/url"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/tern/v2/migrate"
	"github.com/ttab/elephantine"
	"github.com/ttab/flerr"
)

type DBSetup struct {
	conn    string
	connURL *url.URL
	fs      fs.FS
}

func NewDBSetup(connString string, migrationsFS fs.FS) (*DBSetup, error) {
	c, err := url.Parse(connString)
	if err != nil {
		return nil, fmt.Errorf("parse connection string: %w", err)
	}

	return &DBSetup{
		conn:    connString,
		connURL: c,
		fs:      migrationsFS,
	}, nil
}

func (ds *DBSetup) EnsureDatabases(ctx context.Context) (outErr error) {
	adminConn, err := pgx.Connect(ctx, ds.conn)
	if err != nil {
		return fmt.Errorf("open admin connction: %w", err)
	}

	defer elephantine.Close(
		"admin connection", newCtxCloser(ctx, adminConn.Close), &outErr)

	databases, err := ds.listDatabases(ctx, adminConn)
	if err != nil {
		return fmt.Errorf("list databases: %w", err)
	}

	dbList, err := fs.ReadDir(ds.fs, ".")
	if err != nil {
		return fmt.Errorf("read migrations directory: %w", err)
	}

	var clean flerr.Cleaner

	defer clean.FlushTo(&outErr)

	for _, dir := range dbList {
		if !dir.IsDir() {
			continue
		}

		ident := pgx.Identifier{dir.Name()}.Sanitize()

		if !slices.Contains(databases, dir.Name()) {
			_, err := adminConn.Exec(ctx,
				"CREATE DATABASE "+ident)
			if err != nil {
				return fmt.Errorf("create application db %s: %w",
					ident, err)
			}
		}

		dbCs := ds.ConnString(dir.Name())

		dbConn, err := pgx.Connect(ctx, dbCs)
		if err != nil {
			return fmt.Errorf("open connection to %s: %w",
				ident, err)
		}

		clean.Addf(func() error {
			return dbConn.Close(ctx)
		}, "close %s database", ident)

		m, err := migrate.NewMigrator(ctx, dbConn, "schema_version")
		if err != nil {
			return fmt.Errorf("create migrator: %w", err)
		}

		dbFs, err := fs.Sub(ds.fs, dir.Name())
		if err != nil {
			return fmt.Errorf("create %s migrations subfs: %w",
				dir.Name(), err)
		}

		err = m.LoadMigrations(dbFs)
		if err != nil {
			return fmt.Errorf("load %s migrations: %w",
				dir.Name(), err)
		}

		err = m.Migrate(ctx)
		if err != nil {
			return fmt.Errorf("apply %s migrations: %w",
				dir.Name(), err)
		}

		err = clean.Flush()
		if err != nil {
			return err //nolint: wrapcheck
		}
	}

	return nil
}

func (ds *DBSetup) ConnString(database string) string {
	u := ds.connURL.ResolveReference(&url.URL{
		Path: "/" + database,
	})

	u.RawQuery = ds.connURL.RawQuery

	return u.String()
}

func (ds *DBSetup) listDatabases(
	ctx context.Context, conn *pgx.Conn,
) (_ []string, outErr error) {
	res, err := conn.Query(ctx, "SELECT datname FROM pg_database")
	if err != nil {
		return nil, fmt.Errorf("query for databases: %w", err)
	}

	defer res.Close()

	var names []string

	for res.Next() {
		var name string

		err := res.Scan(&name)
		if err != nil {
			return nil, fmt.Errorf("read database name: %w", err)
		}

		names = append(names, name)
	}

	err = res.Err()
	if err != nil {
		return nil, fmt.Errorf("read query response: %w", err)
	}

	return names, nil
}

func newCtxCloser(
	ctx context.Context,
	fn func(ctx context.Context) error,
) *ctxCloser {
	return &ctxCloser{
		ctx: ctx,
		fn:  fn,
	}
}

type ctxCloser struct {
	ctx context.Context
	fn  func(ctx context.Context) error
}

func (cc *ctxCloser) Close() error {
	return cc.fn(cc.ctx)
}
