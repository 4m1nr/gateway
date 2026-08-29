package web

import (
	"io/fs"
	"net/http"
	"path"
	"strings"

	gateway "github.com/am1nr/gateway"
)

// Assets returns the built dashboard's file tree, rooted at its index.
func Assets() (fs.FS, error) {
	return fs.Sub(gateway.Dashboard, "dashboard/dist")
}

// serveStatic serves the built dashboard, falling back to index.html so a
// client-side route survives a page reload.
func (s *Server) serveStatic() http.HandlerFunc {
	assets, err := Assets()
	if err != nil {
		return func(w http.ResponseWriter, r *http.Request) {
			s.fail(w, http.StatusInternalServerError, "the dashboard assets are missing")
		}
	}
	files := http.FileServer(http.FS(assets))

	return func(w http.ResponseWriter, r *http.Request) {
		clean := path.Clean(strings.TrimPrefix(r.URL.Path, "/"))
		if clean == "." || clean == "/" {
			clean = "index.html"
		}

		if _, err := fs.Stat(assets, clean); err != nil {
			// An unknown path under /api is a missing endpoint, not a page.
			// Serving the SPA there turns a typo into a confusing HTML body.
			if strings.HasPrefix(r.URL.Path, "/api/") {
				s.fail(w, http.StatusNotFound, "not found")
				return
			}
			// Anything else is a client-side route: serve the app and let the
			// router decide, so a reload on /clients does not 404.
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		}

		s.securityHeaders(w)
		// Hashed asset filenames may be cached hard; index.html must not be, or
		// a redeploy serves the old app against the new API.
		if strings.HasPrefix(clean, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	}
}
