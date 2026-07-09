package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lucientong/wormhole/pkg/auth"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	loginOIDCIssuer string
	loginClientID   string
	loginScopes     []string
	loginServer     string
	loginCredsPath  string
)

// loginCmd implements the `wormhole login` command.
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with an OIDC provider and save credentials",
	Long: `Authenticate with an OIDC/OAuth2 provider using the Device Authorization Grant.

This command starts a device-code flow, prints a short user code and a
verification URL, and polls until you complete authentication in the browser.
On success, the access/ID token is saved to ~/.wormhole/credentials.json.

Examples:
  # Log in with Google (requires a Google OAuth2 client ID)
  wormhole login --issuer https://accounts.google.com --client-id YOUR_CLIENT_ID

  # Log in with a custom OIDC provider and save for a specific server
  wormhole login --issuer https://auth.example.com --client-id myapp --server tunnel.example.com:7000

  # Log in with custom scopes
  wormhole login --issuer https://auth.example.com --client-id myapp --scopes openid,email,groups`,
	Run: runLogin,
}

func init() {
	loginCmd.Flags().StringVar(&loginOIDCIssuer, "issuer", "", "OIDC issuer URL (required)")
	loginCmd.Flags().StringVar(&loginClientID, "client-id", "", "OAuth2 client ID (required)")
	loginCmd.Flags().StringSliceVar(&loginScopes, "scopes", []string{"openid", "email", "profile"}, "OAuth2 scopes to request")
	loginCmd.Flags().StringVar(&loginServer, "server", "localhost:7000", "Wormhole server to associate credentials with")
	loginCmd.Flags().StringVar(&loginCredsPath, "credentials-path", "", "Path to credentials file (default: ~/.wormhole/credentials.json)")

	_ = loginCmd.MarkFlagRequired("issuer")
	_ = loginCmd.MarkFlagRequired("client-id")
}

func runLogin(_ *cobra.Command, _ []string) {
	ctx, cancel := context.WithCancel(context.Background())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Info().Msg("Login canceled")
		cancel()
	}()

	cfg := auth.DeviceFlowConfig{
		Issuer:   loginOIDCIssuer,
		ClientID: loginClientID,
		Scopes:   loginScopes,
	}

	fmt.Printf("Starting OAuth2 Device Authorization Flow...\n")
	fmt.Printf("Provider: %s\n\n", loginOIDCIssuer)

	dc, err := auth.StartDeviceFlow(ctx, cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to start device flow")
	}

	// Display the verification URL and user code.
	fmt.Printf("╔══════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║  Open the following URL in your browser:                 ║\n")
	fmt.Printf("║                                                          ║\n")
	if dc.VerificationURIComplete != "" {
		fmt.Printf("║  %s\n", dc.VerificationURIComplete)
	} else {
		fmt.Printf("║  %s\n", dc.VerificationURI)
		fmt.Printf("║                                                          ║\n")
		fmt.Printf("║  Enter code:  %-10s                               ║\n", dc.UserCode)
	}
	fmt.Printf("║                                                          ║\n")
	fmt.Printf("║  Expires in %d seconds.                                 ║\n", dc.ExpiresIn)
	fmt.Printf("╚══════════════════════════════════════════════════════════╝\n\n")
	fmt.Printf("Waiting for authentication...")

	result, err := auth.PollDeviceFlow(ctx, dc)
	if err != nil {
		fmt.Println()
		log.Fatal().Err(err).Msg("Authentication failed")
	}

	fmt.Println(" done!")

	token := result.Token()

	// Prefer the JWT's own `exp` claim over the device code's ExpiresIn
	// (which bounds the login window, not the issued token's lifetime).
	expiresAt := auth.ParseJWTExpiry(token)
	if expiresAt.IsZero() && result.ExpiresIn > 0 {
		expiresAt = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	}

	credsPath := loginCredsPath
	creds := auth.Credentials{
		Server:        loginServer,
		Token:         token,
		ExpiresAt:     expiresAt,
		RefreshToken:  result.RefreshToken,
		OIDCIssuer:    loginOIDCIssuer,
		ClientID:      loginClientID,
		TokenEndpoint: dc.TokenEndpoint,
	}
	if err := auth.SaveCredentialsFull(credsPath, creds); err != nil {
		log.Fatal().Err(err).Msg("Failed to save credentials")
	}

	if credsPath == "" {
		credsPath = auth.DefaultCredentialsPath()
	}

	fmt.Printf("\n✅ Credentials saved to %s\n", credsPath)
	if result.RefreshToken != "" {
		fmt.Printf("   (includes a refresh token — wormhole client will renew it automatically when it expires)\n")
	}
	fmt.Printf("\nYou can now run:\n")
	fmt.Printf("  wormhole client --server %s --local 8080\n", loginServer)
	fmt.Printf("(credentials are loaded automatically — no need to pass --token)\n")
	fmt.Printf("\nOr configure the server with:\n")
	fmt.Printf("  wormhole server --require-auth --oidc-issuer %s --oidc-client-id %s\n\n",
		loginOIDCIssuer, loginClientID)
}
