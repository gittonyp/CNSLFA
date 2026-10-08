package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	addr := flag.String("addr", ":8812", "listen address")
	dbPath := flag.String("db", "phantomqr.db", "sqlite path")
	webDir := flag.String("web", "web", "static files dir")
	flag.Parse()

	db, err := openDB(*dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	// ---- API ----
	http.HandleFunc("/api/student/enroll", func(w http.ResponseWriter, r *http.Request) { handleEnroll(db, w, r) })
	http.HandleFunc("/api/staff/login", func(w http.ResponseWriter, r *http.Request) { handleStaffLogin(db, w, r) })
	http.HandleFunc("/api/staff/logout", func(w http.ResponseWriter, r *http.Request) { handleStaffLogout(db, w, r) })
	http.HandleFunc("/api/staff/me", func(w http.ResponseWriter, r *http.Request) { handleStaffMe(db, w, r) })
	http.HandleFunc("/api/staff/password", func(w http.ResponseWriter, r *http.Request) { handleStaffPassword(db, w, r) })
	http.HandleFunc("/api/admin/revoke", func(w http.ResponseWriter, r *http.Request) { handleAdminRevoke(db, w, r) })
	http.HandleFunc("/api/admin/reset", func(w http.ResponseWriter, r *http.Request) { handleAdminReset(db, w, r) })
	http.HandleFunc("/api/session/open", func(w http.ResponseWriter, r *http.Request) { handleSessionOpen(db, w, r) })
	http.HandleFunc("/api/session/close", func(w http.ResponseWriter, r *http.Request) { handleSessionClose(db, w, r) })
	http.HandleFunc("/api/attendance/scan", func(w http.ResponseWriter, r *http.Request) { handleScan(db, w, r) })
	http.HandleFunc("/api/dashboard", func(w http.ResponseWriter, r *http.Request) { handleDashboard(db, w, r) })
	http.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]any{"ok": true}) })

	// ---- Pages (exact routes from spec) ----
	pages := map[string]string{
		"/":               "index.html",
		"/student/enroll": "enroll.html",
		"/student":        "student.html",
		"/staff/login":    "staff.html",
		"/staff/session":  "session.html",
		"/staff/scanner":  "scanner.html",
		"/dashboard":      "dashboard.html",
		"/attacks":        "attacks.html",
	}
	for route, file := range pages {
		route, file := route, file
		http.HandleFunc(route, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != route {
				http.NotFound(w, r)
				return
			}
			http.ServeFile(w, r, filepath.Join(*webDir, file))
		})
	}
	// vendored + shared assets
	http.Handle("/web/", http.StripPrefix("/web/", http.FileServer(http.Dir(*webDir))))

	fmt.Printf("PhantomQR on http://localhost%s  (db=%s)\n", *addr, *dbPath)
	if err := http.ListenAndServe(*addr, nil); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
