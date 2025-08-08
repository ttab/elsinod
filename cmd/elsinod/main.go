package main

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"

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
				Name:    "internal-url",
				Usage:   "Internally visible base URL",
				EnvVars: []string{"INTERNAL_URL"},
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
				Value:   "postgres://postgres:pass@elephant-database/postgres",
				EnvVars: []string{"CONN_STRING"},
			},
			&cli.StringFlag{
				Name:     "client-secret",
				Usage:    "Client secret shared by all clients",
				EnvVars:  []string{"CLIENT_SECRET"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "demo-password",
				Usage:    "Demo password for simulating login",
				EnvVars:  []string{"DEMO_PASSWORD"},
				Required: true,
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

func runAction(c *cli.Context) error {
	ctx := c.Context

	var (
		addr         = c.String("addr")
		profileAddr  = c.String("profile-addr")
		publicURL    = c.String("public-url")
		internalURL  = c.String("internal-url")
		clientSecret = c.String("client-secret")
		demoPassword = c.String("demo-password")
		logLevel     = c.String("log-level")
	)

	logger := elephantine.SetUpLogger(logLevel, os.Stderr)

	server := elephantine.NewAPIServer(logger, addr, profileAddr)

	els, err := internal.NewElsinod(ctx,
		internalURL, publicURL,
		clientSecret, demoPassword)
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
