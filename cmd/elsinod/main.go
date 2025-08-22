package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/joho/godotenv"
	"github.com/ttab/elephantine"
	"github.com/ttab/elsinod"
	"github.com/ttab/elsinod/howdah"
	"github.com/ttab/elsinod/internal"
	"github.com/urfave/cli/v2"
)

func main() {
	err := godotenv.Load()
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Error("exiting: ",
			elephantine.LogKeyError, err)
		os.Exit(1)
	}

	runCmd := cli.Command{
		Name:        "run",
		Description: "Runs the elephant demo helper",
		Action:      runAction,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "log-level",
				EnvVars: []string{"LOG_LEVEL"},
				Value:   "info",
			},
			&cli.StringFlag{
				Name:    "addr",
				Usage:   "Listen address",
				EnvVars: []string{"ADDR"},
				Value:   ":1080",
			},
			&cli.StringFlag{
				Name:    "public-url",
				Usage:   "Publicly visible base URL",
				EnvVars: []string{"PUBLIC_URL"},
				Value:   "http://localhost:1080",
			},
			&cli.StringFlag{
				Name:    "profile-addr",
				Usage:   "Profile listen address",
				EnvVars: []string{"PROFILE_ADDR"},
				Value:   ":1081",
			},
			&cli.StringFlag{
				Name:    "db",
				Value:   "postgres://postgres:pass@database/postgres",
				EnvVars: []string{"CONN_STRING"},
			},
			&cli.StringFlag{
				Name:     "client-secret",
				Usage:    "Client secret shared by all clients",
				EnvVars:  []string{"CLIENT_SECRET"},
				Required: true,
			},
			&cli.StringFlag{
				Name:    "organisation",
				Usage:   "The organisation used for the install",
				EnvVars: []string{"ORGANISATION"},
				Value:   "demo",
			},
			&cli.StringFlag{
				Name:     "demo-password",
				Usage:    "Demo password for simulating login",
				EnvVars:  []string{"DEMO_PASSWORD"},
				Required: true,
			},
			&cli.StringFlag{
				Name:    "s3-endpoint",
				Usage:   "Override the S3 endpoint for use with Minio",
				EnvVars: []string{"S3_ENDPOINT"},
			},
			&cli.StringFlag{
				Name:    "s3-key-id",
				Usage:   "Access key ID to use as a static credential with Minio",
				EnvVars: []string{"S3_ACCESS_KEY_ID"},
			},
			&cli.StringFlag{
				Name:    "s3-key-secret",
				Usage:   "Access key secret to use as a static credential with Minio",
				EnvVars: []string{"S3_ACCESS_KEY_SECRET"},
			},
			&cli.StringSliceFlag{
				Name:    "bucket",
				Usage:   "Buckets to create if they are missing",
				EnvVars: []string{"S3_BUCKETS"},
			},
		},
	}

	app := cli.App{
		Name:  "elsinod",
		Usage: "Elephant demo helper",
		Commands: []*cli.Command{
			&runCmd,
		},
	}

	if err := app.Run(os.Args); err != nil {
		slog.Error("error", "err", err.Error())
		os.Exit(1)
	}
}

func runAction(c *cli.Context) (outErr error) {
	ctx := c.Context

	var (
		addr         = c.String("addr")
		profileAddr  = c.String("profile-addr")
		publicURL    = c.String("public-url")
		org          = c.String("organisation")
		clientSecret = c.String("client-secret")
		demoPassword = c.String("demo-password")
		logLevel     = c.String("log-level")
		db           = c.String("db")
		buckets      = c.StringSlice("bucket")
	)

	logger := elephantine.SetUpLogger(logLevel, os.Stderr)

	s3Client, err := internal.S3Client(ctx, internal.S3Options{
		Endpoint:        c.String("s3-endpoint"),
		AccessKeyID:     c.String("s3-key-id"),
		AccessKeySecret: c.String("s3-key-secret"),
	})
	if err != nil {
		return fmt.Errorf("create S3 client: %w", err)
	}

	err = internal.EnsureBuckets(ctx, s3Client, buckets)
	if err != nil {
		return fmt.Errorf("ensure buckets: %w", err)
	}

	dbSetup, err := internal.NewDBSetup(db,
		mustSubFs(elsinod.DBMigrationsFS, "migrations"))
	if err != nil {
		return fmt.Errorf("create DB setup helper: %w", err)
	}

	err = dbSetup.EnsureDatabases(ctx)
	if err != nil {
		return fmt.Errorf("initialise databases: %w", err)
	}

	dbConn, err := pgx.Connect(ctx, dbSetup.ConnString("elsinod"))
	if err != nil {
		return fmt.Errorf(
			"open application database connection to: %w", err)
	}

	defer elephantine.Close("db connection", closerFunc(func() error {
		ctx, cancel := context.WithTimeout(context.Background(),
			5*time.Second)
		defer cancel()

		return dbConn.Close(ctx)
	}), &outErr)

	server := elephantine.NewAPIServer(logger, addr, profileAddr)

	els, err := internal.NewElsinod(ctx, dbConn,
		publicURL, clientSecret, demoPassword, org)
	if err != nil {
		return fmt.Errorf("create elsinod application: %w", err)
	}

	components := []howdah.Component{
		els,
	}

	app, err := howdah.NewApplication(
		logger,
		server.Mux,
		mustSubFs(elsinod.TemplateFS, "templates"),
		mustSubFs(elsinod.LocaleFS, "locales"),
		mustSubFs(elsinod.AssetFS, "assets"),
		components,
	)
	if err != nil {
		return fmt.Errorf("create application: %w", err)
	}

	defer app.Cleanup()

	err = server.ListenAndServe(ctx)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve website: %w", err)
	}

	return nil
}

func mustSubFs(f embed.FS, directory string) fs.FS {
	s, err := fs.Sub(f, directory)
	if err != nil {
		panic(fmt.Errorf("create %q sub FS from embedded fs: %w",
			directory, err))
	}

	return s
}

type closerFunc func() error

func (cf closerFunc) Close() error {
	return cf()
}
