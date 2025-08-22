package elsinod

import "embed"

//go:embed locales
var LocaleFS embed.FS

//go:embed templates
var TemplateFS embed.FS

//go:embed assets
var AssetFS embed.FS

//go:embed migrations
var DBMigrationsFS embed.FS
