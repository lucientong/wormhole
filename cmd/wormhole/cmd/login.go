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

	token, err := auth.PollDeviceFlow(ctx, dc)
	if err != nil {
		fmt.Println()
		log.Fatal().Err(err).Msg("Authentication failed")
	}

	fmt.Println(" done!")

	// Determine expiry from the device code's ExpiresIn field as an approximation.
	// A proper implementation would parse the ID token's exp claim.
	expiresAt := time.Time{}

	credsPath := loginCredsPath
	if err := auth.SaveCredentials(credsPath, loginServer, token, expiresAt); err != nil {
		log.Fatal().Err(err).Msg("Failed to save credentials")
	}

	if credsPath == "" {
		credsPath = auth.DefaultCredentialsPath()
	}

	fmt.Printf("\n✅ Credentials saved to %s\n", credsPath)
	fmt.Printf("\nYou can now run:\n")
	fmt.Printf("  wormhole client --server %s --local 8080 --token $(cat %s | jq -r '.[\"%s\"].token')\n",
		loginServer, credsPath, loginServer)
	fmt.Printf("\nOr configure the server with:\n")
	fmt.Printf("  wormhole server --require-auth --oidc-issuer %s --oidc-client-id %s\n\n",
		loginOIDCIssuer, loginClientID)
}
