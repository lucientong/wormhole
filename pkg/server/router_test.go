package server

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRouter(t *testing.T) {
	r := NewRouter("tunnel.example.com")

	assert.NotNil(t, r)
	assert.Equal(t, "tunnel.example.com", r.domain)
	assert.NotNil(t, r.subdomains)
	assert.NotNil(t, r.hostnames)
	assert.NotNil(t, r.paths)
	assert.Equal(t, 0, r.ActiveRoutes())
}

func TestRouter_RegisterSubdomain(t *testing.T) {
	r := NewRouter("tunnel.example.com")
	client := &ClientSession{ID: "test-client"}

	// Register subdomain.
	err := r.RegisterSubdomain("myapp", client)
	require.NoError(t, err)
	assert.Equal(t, 1, r.ActiveRoutes())

	// Duplicate registration should fail.
	err = r.RegisterSubdomain("myapp", client)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")

	// Case insensitive.
	err = r.RegisterSubdomain("MYAPP", client)
	assert.Error(t, err)

	// Different subdomain should succeed.
	client2 := &ClientSession{ID: "test-client-2"}
	err = r.RegisterSubdomain("otherapp", client2)
	require.NoError(t, err)
	assert.Equal(t, 2, r.ActiveRoutes())
}

func TestRouter_RegisterHostname(t *testing.T) {
	r := NewRouter("tunnel.example.com")
	client := &ClientSession{ID: "test-client"}

	// Register custom hostname.
	err := r.RegisterHostname("custom.mycompany.com", client)
	require.NoError(t, err)
	assert.Equal(t, 1, r.ActiveRoutes())

	// Duplicate registration should fail.
	err = r.RegisterHostname("custom.mycompany.com", client)
	assert.Error(t, err)

	// Case insensitive.
	err = r.RegisterHostname("CUSTOM.MYCOMPANY.COM", client)
	assert.Error(t, err)
}

func TestRouter_RegisterPath(t *testing.T) {
	r := NewRouter("tunnel.example.com")
	client := &ClientSession{ID: "test-client"}

	// Register path.
	err := r.RegisterPath("/api/v1", client)
	require.NoError(t, err)
	assert.Equal(t, 1, r.ActiveRoutes())

	// Duplicate registration should fail.
	err = r.RegisterPath("/api/v1/", client)
	assert.Error(t, err) // normalizePath makes /api/v1 == /api/v1/

	// Different path should succeed.
	client2 := &ClientSession{ID: "test-client-2"}
	err = r.RegisterPath("/api/v2", client2)
	require.NoError(t, err)
	assert.Equal(t, 2, r.ActiveRoutes())
}

func TestRouter_Route_Subdomain(t *testing.T) {
	r := NewRouter("tunnel.example.com")
	client := &ClientSession{ID: "test-client"}

	err := r.RegisterSubdomain("myapp", client)
	require.NoError(t, err)

	// Should match subdomain.
	found := r.Route("myapp.tunnel.example.com", "/")
	assert.Equal(t, client, found)

	// Should match with port.
	found = r.Route("myapp.tunnel.example.com:443", "/any/path")
	assert.Equal(t, client, found)

	// Case insensitive.
	found = r.Route("MYAPP.tunnel.example.com", "/")
	assert.Equal(t, client, found)

	// Wrong subdomain should not match.
	found = r.Route("other.tunnel.example.com", "/")
	assert.Nil(t, found)

	// Non-subdomain host should not match.
	found = r.Route("myapp.other.com", "/")
	assert.Nil(t, found)
}

func TestRouter_Route_Hostname(t *testing.T) {
	r := NewRouter("tunnel.example.com")
	client := &ClientSession{ID: "test-client"}

	err := r.RegisterHostname("custom.mycompany.com", client)
	require.NoError(t, err)

	// Should match custom hostname.
	found := r.Route("custom.mycompany.com", "/")
	assert.Equal(t, client, found)

	// Should match with port.
	found = r.Route("custom.mycompany.com:8080", "/")
	assert.Equal(t, client, found)

	// Case insensitive.
	found = r.Route("CUSTOM.MYCOMPANY.COM", "/")
	assert.Equal(t, client, found)

	// Wrong hostname should not match.
	found = r.Route("other.mycompany.com", "/")
	assert.Nil(t, found)
}

func TestRouter_Route_Path(t *testing.T) {
	r := NewRouter("tunnel.example.com")
	client1 := &ClientSession{ID: "client-1"}
	client2 := &ClientSession{ID: "client-2"}

	err := r.RegisterPath("/api", client1)
	require.NoError(t, err)

	err = r.RegisterPath("/api/v2", client2)
	require.NoError(t, err)

	// Should match longer path prefix.
	found := r.Route("tunnel.example.com", "/api/v2/users")
	assert.Equal(t, client2, found)

	// Should match shorter path if longer doesn't exist.
	found = r.Route("tunnel.example.com", "/api/v1/users")
	assert.Equal(t, client1, found)

	// Should match exact path.
	found = r.Route("tunnel.example.com", "/api/")
	assert.Equal(t, client1, found)

	// Should not match if no path prefix matches.
	found = r.Route("tunnel.example.com", "/other/")
	assert.Nil(t, found)
}

func TestRouter_Route_Priority(t *testing.T) {
	r := NewRouter("tunnel.example.com")
	hostnameClient := &ClientSession{ID: "hostname-client"}
	subdomainClient := &ClientSession{ID: "subdomain-client"}
	pathClient := &ClientSession{ID: "path-client"}

	// Register all three types.
	err := r.RegisterHostname("custom.example.com", hostnameClient)
	require.NoError(t, err)

	err = r.RegisterSubdomain("myapp", subdomainClient)
	require.NoError(t, err)

	err = r.RegisterPath("/api", pathClient)
	require.NoError(t, err)

	// Hostname should have highest priority.
	found := r.Route("custom.example.com", "/api")
	assert.Equal(t, hostnameClient, found)

	// Subdomain should have second priority.
	found = r.Route("myapp.tunnel.example.com", "/api")
	assert.Equal(t, subdomainClient, found)

	// Path should be fallback.
	found = r.Route("unknown.example.com", "/api/test")
	assert.Equal(t, pathClient, found)
}

func TestRouter_Unregister(t *testing.T) {
	r := NewRouter("tunnel.example.com")
	client := &ClientSession{ID: "test-client"}

	// Register multiple routes for the same client.
	err := r.RegisterSubdomain("sub1", client)
	require.NoError(t, err)
	err = r.RegisterSubdomain("sub2", client)
	require.NoError(t, err)
	err = r.RegisterHostname("custom.com", client)
	require.NoError(t, err)
	err = r.RegisterPath("/api", client)
	require.NoError(t, err)

	assert.Equal(t, 4, r.ActiveRoutes())

	// Unregister client.
	r.Unregister(client)
	assert.Equal(t, 0, r.ActiveRoutes())

	// Routes should no longer work.
	assert.Nil(t, r.Route("sub1.tunnel.example.com", "/"))
	assert.Nil(t, r.Route("custom.com", "/"))
}

func TestRouter_SubdomainURL(t *testing.T) {
	r := NewRouter("tunnel.example.com")

	// HTTP URL.
	url := r.SubdomainURL("myapp", false)
	assert.Equal(t, "http://myapp.tunnel.example.com", url)

	// HTTPS URL.
	url = r.SubdomainURL("myapp", true)
	assert.Equal(t, "https://myapp.tunnel.example.com", url)
}

func TestRouter_ExtractSubdomain(t *testing.T) {
	r := NewRouter("tunnel.example.com")

	// Note: extractSubdomain is an internal method called after host is lowercased by Route.
	// So we test with lowercase hosts (which is how it's actually used).
	tests := []struct {
		host     string
		expected string
	}{
		{"myapp.tunnel.example.com", "myapp"},
		{"tunnel.example.com", ""},           // No subdomain
		{"myapp.other.com", ""},              // Different domain
		{"sub.myapp.tunnel.example.com", ""}, // Multiple subdomains (not allowed)
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			result := r.extractSubdomain(tt.host)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "/"},
		{"/", "/"},
		{"/api", "/api/"},
		{"/api/", "/api/"},
		{"api", "/api/"},
		{"api/", "/api/"},
		{"/api/v1", "/api/v1/"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizePath(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRouter_Concurrency(t *testing.T) {
	r := NewRouter("tunnel.example.com")

	// Concurrent registrations.
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			client := &ClientSession{ID: string(rune('a' + idx))}
			_ = r.RegisterSubdomain(string(rune('a'+idx)), client)
		}(i % 26) // Use letters a-z
	}
	wg.Wait()

	// Concurrent routes.
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_ = r.Route(string(rune('a'+idx%26))+".tunnel.example.com", "/")
		}(i)
	}
	wg.Wait()

	// Verify no panic or deadlock occurred and router is still functional.
	assert.Greater(t, r.ActiveRoutes(), 0, "should have active routes after concurrent operations")
}
