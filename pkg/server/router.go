package server

import (
	"fmt"
	"strings"
	"sync"
)

// Router manages the mapping between hostnames/paths and client sessions.
// It supports both subdomain-based routing (e.g., myapp.tunnel.example.com)
// and path-based routing (e.g., tunnel.example.com/myapp/).
type Router struct {
	domain string

	// Subdomain-based routes: subdomain -> client.
	subdomains map[string]*ClientSession

	// Custom hostname routes: hostname -> client.
	hostnames map[string]*ClientSession

	// Path-based routes: path prefix -> client.
	paths map[string]*ClientSession

	mu sync.RWMutex
}

// NewRouter creates a new router with the given base domain.
func NewRouter(domain string) *Router {
	return &Router{
		domain:     domain,
		subdomains: make(map[string]*ClientSession),
		hostnames:  make(map[string]*ClientSession),
		paths:      make(map[string]*ClientSession),
	}
}

// isStaleOwner reports whether an existing route owner is safe to reclaim:
// a different *ClientSession* pointer whose underlying mux has already
// gone away. A nil Mux (as in some unit tests that construct a
// *ClientSession by hand) is never treated as stale, to avoid accidentally
// reclaiming routes in tests that don't wire up a real Mux.
//
// Reclaiming also requires the incoming client to belong to the same team
// as the stale owner (or either side to have no team, i.e. auth disabled
// or single-tenant deployments): without this, a client from team B
// racing to claim the exact subdomain team A's client just dropped (e.g.
// a network blip mid-reconnect) could transiently steal a route that
// legitimately belongs to team A, before team A's own reconnect attempt
// lands (see docs/architecture.md "Multi-tenancy").
func isStaleOwner(existing, incoming *ClientSession) bool {
	if existing == incoming || existing.Mux == nil || !existing.Mux.IsClosed() {
		return false
	}
	return existing.TeamName == "" || incoming.TeamName == "" || existing.TeamName == incoming.TeamName
}

// RegisterSubdomain registers a subdomain route for a client session. If
// the subdomain is currently held by a session whose connection has already
// died (Mux.IsClosed()) but hasn't been cleaned up yet server-side, the
// stale entry is reclaimed instead of rejecting the new registration:
// otherwise a client reconnecting faster than the old session's death is
// detected — e.g. a network blip with no clean FIN — would be wrongly
// told its own subdomain is "already registered").
func (r *Router) RegisterSubdomain(subdomain string, client *ClientSession) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	subdomain = strings.ToLower(subdomain)
	if existing, exists := r.subdomains[subdomain]; exists && !isStaleOwner(existing, client) {
		return fmt.Errorf("subdomain %q already registered", subdomain)
	}

	r.subdomains[subdomain] = client
	return nil
}

// RegisterHostname registers a custom hostname route for a client session.
// See RegisterSubdomain's doc comment for the stale-owner reclaim rule.
func (r *Router) RegisterHostname(hostname string, client *ClientSession) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	hostname = strings.ToLower(hostname)
	if existing, exists := r.hostnames[hostname]; exists && !isStaleOwner(existing, client) {
		return fmt.Errorf("hostname %q already registered", hostname)
	}

	r.hostnames[hostname] = client
	return nil
}

// RegisterPath registers a path-based route for a client session.
// See RegisterSubdomain's doc comment for the stale-owner reclaim rule.
func (r *Router) RegisterPath(pathPrefix string, client *ClientSession) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	pathPrefix = normalizePath(pathPrefix)
	if existing, exists := r.paths[pathPrefix]; exists && !isStaleOwner(existing, client) {
		return fmt.Errorf("path %q already registered", pathPrefix)
	}

	r.paths[pathPrefix] = client
	return nil
}

// UnregisterSubdomain removes a single subdomain route, if present.
// Used when an individual tunnel is closed but the client connection
// (and its other tunnels) remain active.
func (r *Router) UnregisterSubdomain(subdomain string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.subdomains, strings.ToLower(subdomain))
}

// UnregisterHostname removes a single custom hostname route, if present.
func (r *Router) UnregisterHostname(hostname string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.hostnames, strings.ToLower(hostname))
}

// UnregisterPath removes a single path-prefix route, if present.
func (r *Router) UnregisterPath(pathPrefix string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.paths, normalizePath(pathPrefix))
}

// Unregister removes all routes for the given client session.
func (r *Router) Unregister(client *ClientSession) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Remove subdomain routes.
	for subdomain, c := range r.subdomains {
		if c == client {
			delete(r.subdomains, subdomain)
		}
	}

	// Remove hostname routes.
	for hostname, c := range r.hostnames {
		if c == client {
			delete(r.hostnames, hostname)
		}
	}

	// Remove path routes.
	for path, c := range r.paths {
		if c == client {
			delete(r.paths, path)
		}
	}
}

// LookupSubdomain returns the client session registered for the given
// subdomain, or nil if no client currently owns it. Unlike Route, this
// matches on the subdomain label itself rather than a full host header —
// used by P2P target matching (`wormhole connect <subdomain>`), which
// addresses peers by subdomain regardless of the public base domain.
func (r *Router) LookupSubdomain(subdomain string) *ClientSession {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.subdomains[strings.ToLower(subdomain)]
}

// Route resolves a host and path to a client session.
// It checks in order: custom hostname, subdomain, path prefix.
func (r *Router) Route(host, path string) *ClientSession {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Strip port from host if present.
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}
	host = strings.ToLower(host)

	// 1. Try custom hostname match.
	if client, ok := r.hostnames[host]; ok {
		return client
	}

	// 2. Try subdomain match.
	subdomain := r.extractSubdomain(host)
	if subdomain != "" {
		if client, ok := r.subdomains[subdomain]; ok {
			return client
		}
	}

	// 3. Try path prefix match (longest match wins).
	return r.matchPath(path)
}

// SubdomainURL returns the public URL for a subdomain.
func (r *Router) SubdomainURL(subdomain string, useTLS bool) string {
	scheme := schemeHTTP
	if useTLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s.%s", scheme, subdomain, r.domain)
}

// ActiveRoutes returns the number of active routes.
func (r *Router) ActiveRoutes() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.subdomains) + len(r.hostnames) + len(r.paths)
}

// extractSubdomain extracts the subdomain from a host given the base domain.
// For example, "myapp.tunnel.example.com" with domain "tunnel.example.com" returns "myapp".
func (r *Router) extractSubdomain(host string) string {
	domain := strings.ToLower(r.domain)

	// Host must end with ".domain".
	suffix := "." + domain
	if !strings.HasSuffix(host, suffix) {
		return ""
	}

	subdomain := host[:len(host)-len(suffix)]
	// Subdomain should be a single label (no dots).
	if strings.Contains(subdomain, ".") {
		return ""
	}

	return subdomain
}

// matchPath finds the client session matching the longest path prefix.
func (r *Router) matchPath(reqPath string) *ClientSession {
	reqPath = normalizePath(reqPath)

	var bestMatch *ClientSession
	bestLen := 0

	for prefix, client := range r.paths {
		if strings.HasPrefix(reqPath, prefix) && len(prefix) > bestLen {
			bestMatch = client
			bestLen = len(prefix)
		}
	}

	return bestMatch
}

// normalizePath ensures the path starts with "/" and ends with "/".
func normalizePath(p string) string {
	if p == "" {
		p = "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return p
}
