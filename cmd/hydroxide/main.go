package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"golang.org/x/term"

	"github.com/emersion/hydroxide/auth"
	"github.com/emersion/hydroxide/carddav"
	"github.com/emersion/hydroxide/config"
	"github.com/emersion/hydroxide/events"
	"github.com/emersion/hydroxide/protonmail"
)

const (
	defaultAPIEndpoint = "https://mail.proton.me/api"
	defaultAppVersion  = "Other"
)

var (
	debug       bool
	apiEndpoint string
	appVersion  string
)

func newClient() *protonmail.Client {
	// Create HTTP client with 30 second timeout to prevent hanging
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}
	
	return &protonmail.Client{
		RootURL:    apiEndpoint,
		AppVersion: appVersion,
		Debug:      debug,
		HTTPClient: httpClient,
	}
}

func askPass(prompt string) ([]byte, error) {
	f := os.Stdin
	if !term.IsTerminal(int(f.Fd())) {
		// This can happen if stdin is used for piping data
		// TODO: the following assumes Unix
		var err error
		if f, err = os.Open("/dev/tty"); err != nil {
			return nil, err
		}
		defer f.Close()
	}
	fmt.Fprintf(os.Stderr, "%v: ", prompt)
	b, err := term.ReadPassword(int(f.Fd()))
	if err == nil {
		fmt.Fprintf(os.Stderr, "\n")
	}
	return b, err
}

func askBridgePass() (string, error) {
	if v := os.Getenv("HYDROXIDE_BRIDGE_PASS"); v != "" {
		return v, nil
	}
	b, err := askPass("Bridge password")
	return string(b), err
}





func listenAndServeCardDAV(addr string, authManager *auth.Manager, eventsManager *events.Manager, tlsConfig *tls.Config) error {
	handlers := make(map[string]http.Handler)

	s := &http.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
		Handler: http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			// Log incoming requests
			log.Printf("debug: CardDAV request: %s %s (Content-Length: %d)", req.Method, req.URL.Path, req.ContentLength)
			
			// Handle .well-known/carddav redirect
			if req.URL.Path == "/.well-known/carddav" {
				log.Printf("debug: Redirecting .well-known/carddav to /contacts/default/")
				resp.Header().Set("Location", "/contacts/default/")
				resp.WriteHeader(http.StatusMovedPermanently)
				return
			}

			resp.Header().Set("WWW-Authenticate", "Basic")

			username, password, ok := req.BasicAuth()
			if !ok {
				log.Printf("debug: No basic auth credentials provided")
				resp.WriteHeader(http.StatusUnauthorized)
				io.WriteString(resp, "Credentials are required")
				return
			}

			log.Printf("debug: Authenticating user: %s", username)
			c, privateKeys, primaryKeyID, err := authManager.Auth(username, password)
			if err != nil {
				log.Printf("debug: Authentication failed for %s: %v", username, err)
				if err == auth.ErrUnauthorized {
					resp.WriteHeader(http.StatusUnauthorized)
				} else {
					resp.WriteHeader(http.StatusInternalServerError)
				}
				io.WriteString(resp, err.Error())
				return
			}

			h, ok := handlers[username]
			if !ok {
				log.Printf("debug: Creating new handler for user %s", username)
				ch := make(chan *protonmail.Event)
				eventsManager.Register(c, username, ch, nil)
				h = carddav.NewHandler(c, privateKeys, primaryKeyID, ch)

				handlers[username] = h
			}

			log.Printf("debug: Passing request to CardDAV handler for user %s", username)
			h.ServeHTTP(resp, req)
		}),
	}

	if s.TLSConfig != nil {
		log.Println("CardDAV server listening with TLS on", s.Addr)
		return s.ListenAndServeTLS("", "")
	}

	log.Println("CardDAV server listening on", s.Addr)
	return s.ListenAndServe()
}


const usage = `usage: hydroxide [options...] <command>
Commands:
	auth <username>		Login to ProtonMail via hydroxide
	carddav			Run hydroxide as a CardDAV server
	export-secret-keys <username> Export secret keys
	serve			Run all servers
	status			View hydroxide status

Global options:
	-debug
		Enable debug logs
	-api-endpoint <url>
		ProtonMail API endpoint
	-app-version <version>
		ProtonMail application version
	-carddav-host example.com
	-carddav-port example.com
		CardDAV port on which hydroxide listens, defaults to 8080
	-disable-carddav
		Disable CardDAV for hydroxide serve
	-tls-cert /path/to/cert.pem
		Path to the certificate to use for incoming connections (Optional)
	-tls-key /path/to/key.pem
		Path to the certificate key to use for incoming connections (Optional)
	-tls-client-ca /path/to/ca.pem
		If set, clients must provide a certificate signed by the given CA (Optional)

Environment variables:
	HYDROXIDE_BRIDGE_PASS	Don't prompt for the bridge password, use this variable instead
`

func main() {
	flag.BoolVar(&debug, "debug", false, "Enable debug logs")
	flag.StringVar(&apiEndpoint, "api-endpoint", defaultAPIEndpoint, "ProtonMail API endpoint")
	flag.StringVar(&appVersion, "app-version", defaultAppVersion, "ProtonMail app version")



	carddavHost := flag.String("carddav-host", "127.0.0.1", "Allowed CardDAV email hostname on which hydroxide listens, defaults to 127.0.0.1")
	carddavPort := flag.String("carddav-port", "8080", "CardDAV port on which hydroxide listens, defaults to 8080")
	disableCardDAV := flag.Bool("disable-carddav", false, "Disable CardDAV for hydroxide serve")

	tlsCert := flag.String("tls-cert", "", "Path to the certificate to use for incoming connections")
	tlsCertKey := flag.String("tls-key", "", "Path to the certificate key to use for incoming connections")
	tlsClientCA := flag.String("tls-client-ca", "", "If set, clients must provide a certificate signed by the given CA")

	authCmd := flag.NewFlagSet("auth", flag.ExitOnError)
	exportSecretKeysCmd := flag.NewFlagSet("export-secret-keys", flag.ExitOnError)

	flag.Usage = func() {
		fmt.Print(usage)
	}

	flag.Parse()

	tlsConfig, err := config.TLS(*tlsCert, *tlsCertKey, *tlsClientCA)
	if err != nil {
		log.Fatal(err)
	}

	cmd := flag.Arg(0)
	switch cmd {
	case "auth":
		authCmd.Parse(flag.Args()[1:])
		username := authCmd.Arg(0)
		if username == "" {
			log.Fatal("usage: hydroxide auth <username>")
		}

		c := newClient()

		var a *protonmail.Auth
		/*if cachedAuth, ok := auths[username]; ok {
			var err error
			a, err = c.AuthRefresh(a)
			if err != nil {
				// TODO: handle expired token error
				log.Fatal(err)
			}
		}*/

		var loginPassword string
		if a == nil {
			if pass, err := askPass("Password"); err != nil {
				log.Fatal(err)
			} else {
				loginPassword = string(pass)
			}

			authInfo, err := c.AuthInfo(username)
			if err != nil {
				log.Fatal(err)
			}

			a, err = c.Auth(username, loginPassword, authInfo)
			if err != nil {
				log.Fatal(err)
			}

			if a.TwoFactor.Enabled != 0 {
				if a.TwoFactor.TOTP != 1 {
					log.Fatal("Only TOTP is supported as a 2FA method")
				}

				scanner := bufio.NewScanner(os.Stdin)
				fmt.Printf("2FA TOTP code: ")
				scanner.Scan()
				code := scanner.Text()

				scope, err := c.AuthTOTP(code)
				if err != nil {
					log.Fatal(err)
				}
				a.Scope = scope
			}
		}

		var mailboxPassword string
		if a.PasswordMode == protonmail.PasswordSingle {
			mailboxPassword = loginPassword
		}
		if mailboxPassword == "" {
			prompt := "Password"
			if a.PasswordMode == protonmail.PasswordTwo {
				prompt = "Mailbox password"
			}
			if pass, err := askPass(prompt); err != nil {
				log.Fatal(err)
			} else {
				mailboxPassword = string(pass)
			}
		}

		keySalts, err := c.ListKeySalts()
		if err != nil {
			log.Fatal(err)
		}

		_, _, err = c.Unlock(a, keySalts, mailboxPassword)
		if err != nil {
			log.Fatal(err)
		}

		secretKey, bridgePassword, err := auth.GeneratePassword()
		if err != nil {
			log.Fatal(err)
		}

		err = auth.EncryptAndSave(&auth.CachedAuth{
			Auth:            *a,
			LoginPassword:   loginPassword,
			MailboxPassword: mailboxPassword,
			KeySalts:        keySalts,
		}, username, secretKey)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("Bridge password:", bridgePassword)
	case "status":
		usernames, err := auth.ListUsernames()
		if err != nil {
			log.Fatal(err)
		}

		if len(usernames) == 0 {
			fmt.Printf("No logged in user.\n")
		} else {
			fmt.Printf("%v logged in user(s):\n", len(usernames))
			for _, u := range usernames {
				fmt.Printf("- %v\n", u)
			}
		}
	case "export-secret-keys":
		exportSecretKeysCmd.Parse(flag.Args()[1:])
		username := exportSecretKeysCmd.Arg(0)
		if username == "" {
			log.Fatal("usage: hydroxide export-secret-keys <username>")
		}

		bridgePassword, err := askBridgePass()
		if err != nil {
			log.Fatal(err)
		}

		_, privateKeys, _, err := auth.NewManager(newClient).Auth(username, bridgePassword)
		if err != nil {
			log.Fatal(err)
		}

		wc, err := armor.Encode(os.Stdout, openpgp.PrivateKeyType, nil)
		if err != nil {
			log.Fatal(err)
		}

		for _, key := range privateKeys {
			if err := key.SerializePrivate(wc, nil); err != nil {
				log.Fatal(err)
			}
		}

		if err := wc.Close(); err != nil {
			log.Fatal(err)
		}
	case "carddav":
		addr := *carddavHost + ":" + *carddavPort
		authManager := auth.NewManager(newClient)
		eventsManager := events.NewManager()
		log.Fatal(listenAndServeCardDAV(addr, authManager, eventsManager, tlsConfig))
	case "serve":
		carddavAddr := *carddavHost + ":" + *carddavPort

		authManager := auth.NewManager(newClient)
		eventsManager := events.NewManager()

		if !*disableCardDAV {
			log.Fatal(listenAndServeCardDAV(carddavAddr, authManager, eventsManager, tlsConfig))
		} else {
			log.Fatal("CardDAV is disabled - no services to run")
		}
	default:
		fmt.Print(usage)
		if cmd != "help" {
			log.Fatal("Unrecognized command")
		}
	}
}
