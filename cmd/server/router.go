package main

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

// RegisterSubdomain registers a subdomain route for a client session.
func (r *Router) RegisterSubdomain(subdomain string, client *ClientSession) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	subdomain = strings.ToLower(subdomain)
	if _, exists := r.subdomains[subdomain]; exists {
		return fmt.Errorf("subdomain %q already registered", subdomain)
	}

	r.subdomains[subdomain] = client
	return nil
}

// RegisterHostname registers a custom hostname route for a client session.
func (r *Router) RegisterHostname(hostname string, client *ClientSession) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	hostname = strings.ToLower(hostname)
	if _, exists := r.hostnames[hostname]; exists {
		return fmt.Errorf("hostname %q already registered", hostname)
	}

	r.hostnames[hostname] = client
	return nil
}

// RegisterPath registers a path-based route for a client session.
func (r *Router) RegisterPath(pathPrefix string, client *ClientSession) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	pathPrefix = normalizePath(pathPrefix)
	if _, exists := r.paths[pathPrefix]; exists {
		return fmt.Errorf("path %q already registered", pathPrefix)
	}

	r.paths[pathPrefix] = client
	return nil
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
	scheme := "http"
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
