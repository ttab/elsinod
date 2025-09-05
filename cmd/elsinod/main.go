package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/joho/godotenv"
	"github.com/ttab/elephantine"
	"github.com/ttab/elsinod"
	"github.com/ttab/elsinod/internal"
	"github.com/ttab/howdah"
	"github.com/urfave/cli/v2"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
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

	runDeploy := cli.Command{
		Name:        "deploy",
		Description: "Deploy to minikube",
		Action:      runDeploy,
		Flags: []cli.Flag{
			&cli.PathFlag{
				Name:     "spec",
				Required: true,
			},
		},
	}

	app := cli.App{
		Name:  "elsinod",
		Usage: "Elephant demo helper",
		Commands: []*cli.Command{
			&runCmd,
			&runDeploy,
		},
	}

	if err := app.Run(os.Args); err != nil {
		slog.Error("error", "err", err.Error())
		os.Exit(1)
	}
}

type DeploySpec struct {
	BaseDomain   string          `yaml:"baseDomain"`
	Applications []DeployAppSpec `yaml:"applications"`
}

type DeployAppSpec struct {
	Name      string   `yaml:"name"`
	Repo      string   `yaml:"repo"`
	Version   string   `yaml:"version"`
	DependsOn []string `yaml:"depends_on"`
	Upgrade   bool
}

func uiPrint(format string, a ...any) {
	//nolint: forbidigo
	fmt.Printf(format, a...)
	//nolint: forbidigo
	fmt.Println()
}

func runDeploy(c *cli.Context) (outErr error) {
	deployed, err := listDeployedApplications()
	if err != nil {
		return fmt.Errorf("list deployed applications: %w", err)
	}

	specFile, err := os.Open(c.String("spec"))
	if err != nil {
		return fmt.Errorf("open spec file: %w", err)
	}

	defer elephantine.Close("spec file", specFile, &outErr)

	var spec DeploySpec

	dec := yaml.NewDecoder(specFile)

	err = dec.Decode(&spec)
	if err != nil {
		return fmt.Errorf("decode spec: %w", err)
	}

	grp, gCtx := errgroup.WithContext(c.Context)

	var m sync.Mutex

	for _, app := range spec.Applications {
		grp.Go(func() error {
			uiPrint("deploying %s %s", app.Name, app.Version)

			app.Upgrade = deployed[app.Name]

			return startService(gCtx, &m, spec.BaseDomain, app)
		})
	}

	err = grp.Wait()
	if err != nil {
		return fmt.Errorf("failed to start services: %w", err)
	}

	return nil
}

func startService(
	ctx context.Context,
	m *sync.Mutex,
	baseDomain string,
	spec DeployAppSpec,
) error { //nolint: forbidgo
	for _, name := range spec.DependsOn {
		var ok bool

		var delay time.Duration

		for !ok {
			time.Sleep(delay)

			hCtx, cancel := context.WithTimeout(ctx, 1*time.Second)

			defer cancel()

			req, err := http.NewRequestWithContext(hCtx, http.MethodGet,
				fmt.Sprintf("https://%s.%s/health/alive", name, baseDomain), nil)
			if err != nil {
				return fmt.Errorf("create healthcheck URL: %w", err)
			}

			uiPrint("%s checking for %s", spec.Name, req.URL.Host)

			res, err := http.DefaultClient.Do(req)
			if err == nil {
				_ = res.Body.Close()
			}

			if err != nil || res.StatusCode != http.StatusOK {
				delay = 500 * time.Millisecond

				uiPrint("waiting for %s", req.URL.Host)

				continue
			}

			ok = true
		}
	}

	mode := "install"

	if spec.Upgrade {
		mode = "upgrade"
	}

	// This is not functionally necessary, and actually slows the deploy
	// down a bit, but it makes the CLI output more readable by serialising the .
	m.Lock()
	defer m.Unlock()

	uiPrint("-> deploying %s %s", spec.Name, spec.Version)

	uiPrint("$ %s", strings.Join([]string{
		"helm", mode, spec.Name, spec.Repo,
		"--version", spec.Version,
		"--values", fmt.Sprintf("%s.minikube.yaml", spec.Name),
	}, " "))

	//nolint: gosec
	cmd := exec.Command("helm", mode, spec.Name, spec.Repo,
		"--version", spec.Version,
		"--values", fmt.Sprintf("%s.minikube.yaml", spec.Name))

	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to %s %s: %w", mode, spec.Name, err)
	}

	return nil
}

func listDeployedApplications() (map[string]bool, error) {
	cmd := exec.Command("helm", "list", "-o", "json")

	cmd.Stderr = os.Stderr

	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("create helm list pipe: %w", err)
	}

	dec := json.NewDecoder(pipe)

	err = cmd.Start()
	if err != nil {
		return nil, fmt.Errorf("run helm list: %w", err)
	}

	var list []struct {
		Name string `json:"name"`
	}

	err = dec.Decode(&list)
	if err != nil {
		return nil, fmt.Errorf("parse helm list output: %w", err)
	}

	m := make(map[string]bool)

	for _, item := range list {
		m[item.Name] = true
	}

	err = cmd.Wait()
	if err != nil {
		return nil, fmt.Errorf("wait for helm list to exit: %w", err)
	}

	return m, nil
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

	keystore, err := elsinod.NewDBKeyStore(ctx, dbConn)
	if err != nil {
		return fmt.Errorf("create keystore: %w", err)
	}

	els, err := elsinod.New(ctx, keystore,
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
