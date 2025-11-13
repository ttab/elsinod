package elsinod

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/ttab/elephantine"
	"github.com/ttab/howdah"
	"github.com/viccon/sturdyc"
)

func init() { //nolint: gochecknoinits
	// This is sooo ugly!
	jwt.MarshalSingleStringAsArray = true
}

func New(
	ctx context.Context,
	keystore KeyStore,
	publicURL string,
	clientSecret string,
	demoPassword string,
	organisation string,
) (*Elsinod, error) {
	baseURL, err := url.Parse(publicURL)
	if err != nil {
		return nil, fmt.Errorf("invalid public URL: %w", err)
	}

	issuerURL := baseURL.String()

	conf := func(hostURL *url.URL) elephantine.OpenIDConnectConfig {
		return elephantine.OpenIDConnectConfig{
			Issuer:                issuerURL,
			UserinfoEndpoint:      hostURL.JoinPath("user-info").String(),
			TokenEndpoint:         hostURL.JoinPath("token").String(),
			AuthorizationEndpoint: hostURL.JoinPath("protocol", "openid-connect", "auth").String(),
			JwksURI:               hostURL.JoinPath(".well-known", "jwks.json").String(),
			GrantTypesSupported: []string{
				"authorization_code",
				"refresh_token",
				"client_credentials",
				"urn:ietf:params:oauth:grant-type:token-exchange",
			},
			ResponseTypesSupported: []string{
				"code",
				"token",
				"id_token",
			},
			IDTokenSigningAlgValuesSupported: []string{
				"ES384",
			},
			TokenEndpointAuthMethodsSupported: []string{
				"client_secret_post",
			},
			TokenEndpointAuthSigningAlgValuesSupported: []string{
				"ES384",
			},
		}
	}

	codes := sturdyc.New[issuedCode](1000, 1, 12*time.Second, 20,
		sturdyc.WithEvictionInterval(time.Second),
	)

	e := Elsinod{
		keystore:     keystore,
		issuerURL:    issuerURL,
		publicURL:    publicURL,
		clientSecret: clientSecret,
		demoPassword: demoPassword,
		oidc:         conf,
		codes:        codes,
		org:          organisation,
	}

	e.authParser = elephantine.NewJWTAuthInfoParser(ctx, e.keyFunc, elephantine.JWTAuthInfoParserOptions{
		Audience: "elephant",
		Issuer:   publicURL,
	})

	return &e, nil
}

type Elsinod struct {
	keystore KeyStore

	issuerURL    string
	publicURL    string
	clientSecret string
	demoPassword string
	oidc         func(hostURL *url.URL) elephantine.OpenIDConnectConfig
	codes        *sturdyc.Client[issuedCode]
	authParser   elephantine.AuthInfoParser
	org          string
}

type issuedCode struct {
	Code      string
	Challenge string
	Scope     string
	ClientID  string
	Name      string
	Email     string
	Sub       string
	Units     []string
}

func (e *Elsinod) RegisterRoutes(mux *howdah.PageMux) {
	mux.HandleFunc("GET /.well-known/openid-configuration", e.oidcConfig)
	mux.HandleFunc("GET /.well-known/jwks.json", e.jwks)
	mux.HandleFunc("POST /token", e.tokenEndpoint)
	mux.HandleFunc("GET /protocol/openid-connect/auth", e.authPage)
	mux.HandleFunc("POST /protocol/openid-connect/auth", e.authPage)
	mux.HandleFunc("POST /", func(
		_ context.Context, _ http.ResponseWriter, r *http.Request,
	) (*howdah.Page, error) {
		slog.Warn("unknown route", "path", r.URL.Path)

		return nil, errors.New("not implemented")
	})
	mux.HandleFunc("GET /protocol/openid-connect/logout", func(
		_ context.Context, w http.ResponseWriter, r *http.Request,
	) (*howdah.Page, error) {
		redirURL := r.FormValue("post_logout_redirect_uri")

		http.Redirect(w, r, redirURL, http.StatusFound)

		return nil, howdah.ErrSkipRender
	})
}

func (e *Elsinod) oidcConfig(
	_ context.Context, w http.ResponseWriter, r *http.Request,
) (*howdah.Page, error) {
	hostURL := getHostURLFromReq(r)

	oidc := e.oidc(hostURL)

	data, err := json.MarshalIndent(oidc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_, err = w.Write(data)
	if err != nil {
		return nil, howdah.ErrSkipRender
	}

	return nil, howdah.ErrSkipRender
}

func getHostURLFromReq(r *http.Request) *url.URL {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	return &url.URL{
		Scheme: scheme,
		Host:   r.Host,
	}
}

func (e *Elsinod) keyFunc(t *jwt.Token) (any, error) {
	keyID, ok := t.Header["kid"].(string)
	if !ok {
		return nil, errors.New("invalid key ID")
	}

	key, err := e.keystore.GetKey(context.Background(), keyID)
	if err != nil {
		return nil, err //nolint: wrapcheck
	}

	return key.PrivateKey.PublicKey, nil
}

type jwks struct {
	Keys []JWK `json:"keys"`
}

func (e *Elsinod) jwks(
	ctx context.Context, w http.ResponseWriter, _ *http.Request,
) (*howdah.Page, error) {
	stored, err := e.keystore.GetKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("get signing keys: %w", err)
	}

	keys := make([]JWK, len(stored))

	for i := range stored {
		keys[i] = stored[i].JWK
	}

	data, err := json.MarshalIndent(jwks{
		Keys: keys,
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal keyset: %w", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_, err = w.Write(data)
	if err != nil {
		return nil, howdah.ErrSkipRender
	}

	return nil, howdah.ErrSkipRender
}

func badRequest(format string, a ...any) error {
	return howdah.HTTPErrorf(http.StatusBadRequest,
		howdah.TL("BadRequest", "Invalid request"),
		format, a...,
	)
}

type AuthContents struct {
	Error *InPageError

	Scope               string
	ClientID            string
	RedirectURI         string
	ResponseType        string
	CodeChallenge       string
	CodeChallengeMethod string
	State               string

	DefaultUserName  string
	DefaultUserEmail string
	Units            []UnitOption
}

type UnitOption struct {
	Name     string
	Label    howdah.TextLabel
	Selected bool
}

type InPageError struct {
	Label howdah.TextLabel
}

func (ie InPageError) Error() string {
	return "in page error"
}

func (e *Elsinod) authPage(
	_ context.Context, w http.ResponseWriter, r *http.Request,
) (*howdah.Page, error) {
	values := r.URL.Query()

	scope := values.Get("scope")
	if scope == "" {
		return nil, badRequest("scope is required")
	}

	clientID := values.Get("client_id")
	if clientID == "" {
		return nil, badRequest("client_id is required")
	}

	redirectURI := values.Get("redirect_uri")
	if redirectURI == "" {
		return nil, badRequest("redirect_uri is required")
	}

	responseType := values.Get("response_type")
	if responseType != "code" {
		return nil, badRequest("response_type must be 'code'")
	}

	codeChallenge := values.Get("code_challenge")
	if codeChallenge == "" {
		return nil, badRequest("code_challenge is required")
	}

	codeChallengeMethod := values.Get("code_challenge_method")
	if codeChallengeMethod == "" {
		return nil, badRequest("code_challenge_method is required")
	}

	contents := AuthContents{
		Scope:               scope,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		ResponseType:        responseType,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		State:               values.Get("state"),

		DefaultUserName:  "Test User",
		DefaultUserEmail: "test.user@example.com",

		Units: []UnitOption{
			{
				Name:     "redaktionen",
				Label:    howdah.TL("EditorialStaff", "Editorial staff"),
				Selected: true,
			},
		},
	}

	status := http.StatusOK

	if r.Method == http.MethodPost {
		var inPage InPageError

		err := e.handleAuthSubmit(w, r, &contents)
		if errors.As(err, &inPage) {
			status = http.StatusForbidden
			contents.Error = &inPage
		} else if err != nil {
			return nil, err
		}
	}

	return &howdah.Page{
		Status:   status,
		Template: "login.html",
		Title:    howdah.TL("MockLogin", "Mock login"),
		Contents: contents,
	}, nil
}

func (e *Elsinod) handleAuthSubmit(
	w http.ResponseWriter,
	r *http.Request,
	contents *AuthContents,
) error {
	err := r.ParseForm()
	if err != nil {
		return badRequest("invalid form: %w", err)
	}

	redirectURI, err := url.Parse(contents.RedirectURI)
	if err != nil {
		return badRequest("invalid redirect URI: %w", err)
	}

	userName := r.FormValue("user-name")
	userEmail := r.FormValue("user-email")

	contents.DefaultUserName = userName
	contents.DefaultUserEmail = userEmail

	if userName == "" {
		return InPageError{
			Label: howdah.TL("UserNameRequired", "User name is required"),
		}
	}

	if userEmail == "" {
		return InPageError{
			Label: howdah.TL("UserEmailRequired", "User email is required"),
		}
	}

	password := r.FormValue("password")
	if password == "" {
		return InPageError{
			Label: howdah.TL("PasswordRequired", "Password is required"),
		}
	}

	if password != e.demoPassword {
		return InPageError{
			Label: howdah.TL("InvalidPassword", "Invalid password"),
		}
	}

	var units []string

	for k, v := range r.Form {
		if strings.HasPrefix(k, "unit_") {
			units = append(units, "/"+v[0])
		}
	}

	values := redirectURI.Query()

	code := uuid.NewString()

	values.Set("code", code)
	values.Set("session_state", uuid.NewString())
	values.Set("iss", e.publicURL)

	if contents.State != "" {
		values.Set("state", contents.State)
	}

	redirectURI.RawQuery = values.Encode()

	madeUpUserID := uuid.NewSHA1(uuid.NameSpaceURL, []byte(userEmail))

	e.codes.Set(code, issuedCode{
		Code:      code,
		Challenge: contents.CodeChallenge,
		Scope:     contents.Scope,
		ClientID:  contents.ClientID,
		Name:      userName,
		Email:     userEmail,
		Sub:       "core://user/" + madeUpUserID.String(),
		Units:     units,
	})

	http.Redirect(w, r, redirectURI.String(), http.StatusFound)

	return howdah.ErrSkipRender
}

func (e *Elsinod) tokenEndpoint(
	ctx context.Context, w http.ResponseWriter, r *http.Request,
) (*howdah.Page, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, badRequest("invalid form: %w", err)
	}

	grantType := r.FormValue("grant_type")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	accessExpiresIn := 500
	refreshExpiresIn := 604800
	idExpiresIn := refreshExpiresIn

	key, err := e.keystore.GetCurrentSigningKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("no signing keys available: %w", err)
	}

	switch grantType {
	case "client_credentials":
		if clientSecret != e.clientSecret {
			return nil, howdah.HTTPErrorf(http.StatusForbidden,
				howdah.TL("AccessDenied", "Access denied"),
				"invalid client secret",
			)
		}

		expiresIn := 300
		issued := time.Now()
		expires := time.Now().Add(time.Duration(expiresIn) * time.Second)

		claims := JWTClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				ID:        uuid.NewString(),
				IssuedAt:  jwt.NewNumericDate(issued),
				ExpiresAt: jwt.NewNumericDate(expires),
				Issuer:    e.issuerURL,
				Subject:   "core://application/" + clientID,
			},
			Type:     "Bearer",
			Scope:    r.FormValue("scope"),
			ClientID: clientID,
			Org:      "core://org/" + e.org,
			// TODO: Client unit memberships.

		}

		token, err := JWTToken(key.PrivateKey, key.JWK.ID, claims)
		if err != nil {
			return nil, fmt.Errorf("sign access token: %w", err)
		}

		response := tokenResponse{
			AccessToken: token,
			ExpiresIn:   expiresIn,
			TokenType:   claims.Type,
			Scope:       claims.Scope,
		}

		data, err := json.MarshalIndent(response, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshal response: %w", err)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		_, err = w.Write(data)
		if err != nil {
			return nil, howdah.ErrSkipRender
		}
	case "authorization_code":
		code := r.FormValue("code")
		codeVerifier := r.FormValue("code_verifier")

		spec, ok := e.codes.Get(code)
		if !ok {
			return nil, badRequest("unknown authorization code")
		}

		hash := sha256.Sum256([]byte(codeVerifier))

		computedChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
		if computedChallenge != spec.Challenge {
			return nil, badRequest("invalid verifier")
		}

		issued := time.Now()
		expires := time.Now().Add(
			time.Duration(accessExpiresIn) * time.Second)

		// Naive, I know, but just for testing purposes.
		given, family, _ := strings.Cut(spec.Name, " ")

		claims := JWTClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				ID:        uuid.NewString(),
				IssuedAt:  jwt.NewNumericDate(issued),
				ExpiresAt: jwt.NewNumericDate(expires),
				Issuer:    e.issuerURL,
				Subject:   spec.Sub,
				Audience:  jwt.ClaimStrings{"elephant"},
			},
			Type:              "Bearer",
			AuthorizedParty:   clientID,
			Scope:             spec.Scope,
			ClientID:          spec.ClientID,
			Org:               "core://org/" + e.org,
			Units:             spec.Units,
			PreferredUsername: spec.Email,
			Name:              spec.Name,
			GivenName:         given,
			FamilyName:        family,
			Email:             spec.Email,
			EmailVerified:     true,
		}

		token, err := JWTToken(key.PrivateKey, key.JWK.ID, claims)
		if err != nil {
			return nil, fmt.Errorf("sign access token: %w", err)
		}

		refreshToken, err := e.getRefreshToken(key, claims, refreshExpiresIn)
		if err != nil {
			return nil, err
		}

		idToken, err := e.getIDToken(key, claims, idExpiresIn)
		if err != nil {
			return nil, err
		}

		response := tokenResponse{
			IDToken:          idToken,
			AccessToken:      token,
			RefreshToken:     refreshToken,
			ExpiresIn:        accessExpiresIn,
			RefreshExpiresIn: refreshExpiresIn,
			TokenType:        claims.Type,
			Scope:            claims.Scope,
		}

		data, err := json.MarshalIndent(response, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshal response: %w", err)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		_, err = w.Write(data)
		if err != nil {
			return nil, howdah.ErrSkipRender
		}
	case "refresh_token":
		if clientSecret != e.clientSecret {
			return nil, howdah.HTTPErrorf(http.StatusForbidden,
				howdah.TL("AccessDenied", "Access denied"),
				"invalid client secret",
			)
		}

		refreshClaim := r.FormValue("refresh_token")
		if refreshClaim == "" {
			return nil, badRequest("refresh_token is required")
		}

		claims, err := e.accessTokenClaimsFromRefresh(refreshClaim, accessExpiresIn)
		if err != nil {
			return nil, badRequest("validate refresh: %w", err)
		}

		token, err := JWTToken(key.PrivateKey, key.JWK.ID, claims)
		if err != nil {
			return nil, fmt.Errorf("sign access token: %w", err)
		}

		refreshToken, err := e.getRefreshToken(key, claims, refreshExpiresIn)
		if err != nil {
			return nil, err
		}

		response := tokenResponse{
			AccessToken:      token,
			RefreshToken:     refreshToken,
			ExpiresIn:        accessExpiresIn,
			RefreshExpiresIn: refreshExpiresIn,
			TokenType:        claims.Type,
			Scope:            claims.Scope,
		}

		data, err := json.MarshalIndent(response, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshal response: %w", err)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		_, err = w.Write(data)
		if err != nil {
			return nil, howdah.ErrSkipRender
		}
	default:
		return nil, howdah.HTTPErrorf(http.StatusBadRequest,
			howdah.TL("BadRequest", "Invalid request"),
			"unsupported grant_type %q", grantType,
		)
	}

	return nil, howdah.ErrSkipRender
}

func (e *Elsinod) accessTokenClaimsFromRefresh(
	token string, expiresIn int,
) (JWTClaims, error) {
	var claims JWTClaims

	_, err := e.authParser.ValidateTokenWithClaims(token, claims)
	if err != nil {
		return JWTClaims{}, fmt.Errorf("invalid refresh token: %w", err)
	}

	if claims.Type != "refresh" {
		return JWTClaims{}, errors.New("not a refresh token")
	}

	expires := time.Now().Add(
		time.Duration(expiresIn) * time.Second)

	claims.Type = "Bearer"
	claims.ExpiresAt = jwt.NewNumericDate(expires)

	return claims, nil
}

func (e *Elsinod) getRefreshToken(key StoreKey, claims JWTClaims, expiresIn int) (string, error) {
	expires := time.Now().Add(
		time.Duration(expiresIn) * time.Second)

	refreshClaims := claims

	refreshClaims.Type = "refresh"
	refreshClaims.ExpiresAt = jwt.NewNumericDate(expires)

	refreshToken, err := JWTToken(key.PrivateKey, key.JWK.ID, refreshClaims)
	if err != nil {
		return "", fmt.Errorf("sign refresh token: %w", err)
	}

	return refreshToken, nil
}

func (e *Elsinod) getIDToken(key StoreKey, claims JWTClaims, expiresIn int) (string, error) {
	expires := time.Now().Add(
		time.Duration(expiresIn) * time.Second)

	refreshClaims := claims

	refreshClaims.Type = "id_token"
	refreshClaims.ExpiresAt = jwt.NewNumericDate(expires)

	refreshToken, err := JWTToken(key.PrivateKey, key.JWK.ID, refreshClaims)
	if err != nil {
		return "", fmt.Errorf("sign refresh token: %w", err)
	}

	return refreshToken, nil
}

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	IDToken          string `json:"id_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	TokenType        string `json:"token_type"`
	Scope            string `json:"scope"`
}

func bigIntToBase64RawURL(i *big.Int, l uint) string {
	var b []byte

	if l != 0 {
		b = make([]byte, l)

		i.FillBytes(b)
	} else {
		b = i.Bytes()
	}

	return base64.RawURLEncoding.EncodeToString(b)
}
