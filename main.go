package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"
	"github.com/namsral/flag"
	"github.com/op/go-logging"
)

// Vars
//var db = *sql.DB
var log = logging.MustGetLogger("traefik-forward-auth")
var (
	fw      *ForwardAuth
	DB_HOST string
	DB_PORT string
	DB_NAME string
	DB_USER string
	DB_PASS string
)

func ok(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "OK", 500)
}

// Primary handler
func handler(w http.ResponseWriter, r *http.Request) {
	// Handle callback
	state := r.FormValue("state")
	code := r.FormValue("code")
	if len(state) > 0 && len(code) > 0 {
		handleCallback(w, r, state, code)
		return
	}

	// Get auth cookie
	c, err := r.Cookie(fw.CookieName)
	if err != nil {
		// Error indicates no cookie, generate nonce
		err, nonce := fw.Nonce()
		if err != nil {
			log.Error("Error generating nonce")
			http.Error(w, "Service unavailable", 503)
			return
		}

		// Forward them on
		http.Redirect(w, r, fw.GetLoginURL(r, nonce), http.StatusTemporaryRedirect)

		return
	}

	// Validate cookie
	valid, email, err := fw.ValidateCookie(r, c)
	if !valid {
		log.Debugf("Invlaid cookie: %s", err)
		http.Error(w, "Not authorized", 401)
		return
	}

	// Validate user
	valid = fw.ValidateEmail(email)
	if !valid {
		log.Debugf("Invalid email: %s", email)
		http.Error(w, "Not authorized", 401)
		return
	}

	// Valid request
	w.WriteHeader(200)
}

// Authenticate user after they have come back from google
func handleCallback(w http.ResponseWriter, r *http.Request, state string, code string) {

	redirect := state[33:]

	// Clear CSRF cookie
	http.SetCookie(w, fw.ClearCSRFCookie(r))

	// Exchange code for token
	token, err := fw.ExchangeCode(r, code)
	if err != nil {
		log.Debugf("Code exchange failed with: %s\n", err)
		http.Error(w, "Service unavailable", 503)
		return
	}

	// Get user
	user, err := fw.GetUser(token)
	if err != nil {
		log.Debugf("Error getting user: %s\n", err)
		return
	}

	// Generate cookie
	http.SetCookie(w, fw.MakeCookie(r, user.Email))
	log.Debugf("Generated auth cookie for %s\n", user.Email)

	// TODO generate JWT
	jwt := "jwtstring"

	// Inject token
	redirect = "/ok"
	fmt.Fprintf(w, "<html>OK<script>window.localStorage.setItem('token', '"+jwt+"'); window.location = '"+redirect+"';</script></html>")
}

// Main
func main() {
	DB_HOST = os.Getenv("DB_HOST")
	DB_PORT = os.Getenv("DB_PORT")
	DB_NAME = os.Getenv("DB_NAME")
	DB_USER = os.Getenv("DB_USER")
	DB_PASS = os.Getenv("DB_PASS")

	db, err := sql.Open("postgres", fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", DB_USER, DB_PASS, DB_HOST, DB_PORT, DB_NAME))
	if err != nil {
		fmt.Println("i")
		panic(err)
	}
	if err = db.Ping(); err != nil {
		fmt.Println("x")
		panic(err)
	}

	// Parse options
	flag.String(flag.DefaultConfigFlagname, "", "Path to config file")
	path := flag.String("url-path", "_oauth", "Callback URL")
	address := flag.String("address", "_oauth", "Your instance address")
	lifetime := flag.Int("lifetime", 43200, "Session length in seconds")
	secret := flag.String("secret", "", "*Secret used for signing (required)")
	authHost := flag.String("auth-host", "", "Central auth login")
	clientId := flag.String("client-id", "", "*Google Client ID (required)")
	clientSecret := flag.String("client-secret", "", "*Google Client Secret (required)")
	cookieName := flag.String("cookie-name", "_forward_auth", "Cookie Name")
	cSRFCookieName := flag.String("csrf-cookie-name", "_forward_auth_csrf", "CSRF Cookie Name")
	cookieDomainList := flag.String("cookie-domains", "", "Comma separated list of cookie domains") //todo
	cookieSecret := flag.String("cookie-secret", "", "depreciated")
	cookieSecure := flag.Bool("cookie-secure", true, "Use secure cookies")
	domainList := flag.String("domain", "", "Comma separated list of email domains to allow")
	emailWhitelist := flag.String("whitelist", "", "Comma separated list of emails to allow")
	prompt := flag.String("prompt", "", "Space separated list of OpenID prompt options")

	flag.Parse()

	// Backwards compatability
	if *secret == "" && *cookieSecret != "" {
		*secret = *cookieSecret
	}

	// Check for show stopper errors
	stop := false
	if *clientId == "" {
		stop = true
		log.Critical("client-id must be set")
	}
	if *clientSecret == "" {
		stop = true
		log.Critical("client-secret must be set")
	}
	if *secret == "" {
		stop = true
		log.Critical("secret must be set")
	}
	if stop {
		return
	}

	// Parse lists
	var cookieDomains []CookieDomain
	if *cookieDomainList != "" {
		for _, d := range strings.Split(*cookieDomainList, ",") {
			cookieDomain := NewCookieDomain(d)
			cookieDomains = append(cookieDomains, *cookieDomain)
		}
	}

	var domain []string
	if *domainList != "" {
		domain = strings.Split(*domainList, ",")
	}
	var whitelist []string
	if *emailWhitelist != "" {
		whitelist = strings.Split(*emailWhitelist, ",")
	}

	// Setup
	callbackPath := fmt.Sprintf("%s", *path)
	if callbackPath[0:1] == "/" && address != nil {
		callbackPath = fmt.Sprintf("%s", *address) + callbackPath
	}
	fw = &ForwardAuth{
		Path:     callbackPath,
		Lifetime: time.Second * time.Duration(*lifetime),
		Secret:   []byte(*secret),
		AuthHost: *authHost,

		ClientId:     *clientId,
		ClientSecret: *clientSecret,
		Scope:        "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email",
		LoginURL: &url.URL{
			Scheme: "https",
			Host:   "accounts.google.com",
			Path:   "/o/oauth2/auth",
		},
		TokenURL: &url.URL{
			Scheme: "https",
			Host:   "www.googleapis.com",
			Path:   "/oauth2/v3/token",
		},
		UserURL: &url.URL{
			Scheme: "https",
			Host:   "www.googleapis.com",
			Path:   "/oauth2/v2/userinfo",
		},

		CookieName:     *cookieName,
		CSRFCookieName: *cSRFCookieName,
		CookieDomains:  cookieDomains,
		CookieSecure:   *cookieSecure,

		Domain:    domain,
		Whitelist: whitelist,

		Prompt: *prompt,
	}

	// Attach handler
	http.HandleFunc("/", handler)
	http.HandleFunc("/ok", ok)
	/*
		  callbackPath = fmt.Sprintf("%s", *path)
		  if callbackPath[0:1] == "/" {
			  http.HandleFunc("/oauth2/callback", oauthCallbackHandler)
		  }
	*/

	log.Debugf("Staring with options: %#v", fw)
	log.Notice("Litening on :4181")
	log.Notice(http.ListenAndServe(":4181", nil))
}
