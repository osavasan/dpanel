package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var templates *template.Template

func main() {
	var err error
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "app.db"
	}
	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatal(err)
	}
	if err := initDB(); err != nil {
		log.Fatal(err)
	}

	templates = template.Must(template.ParseGlob("templates/*.html"))

	mux := http.NewServeMux()
	mux.HandleFunc("/", requireAuth(dashboardHandler))
	mux.HandleFunc("/dashboard", requireAuth(dashboardHandler))
	mux.HandleFunc("/topn", requireAuth(topnHandler))
	mux.HandleFunc("/dockerstats", requireAuth(dockerstatsHandler))
	mux.HandleFunc("/dockerfiles", requireAuth(dockerfilesHandler))
	mux.HandleFunc("/dockerfiles/add", requireAuth(addDockerfileHandler))
	mux.HandleFunc("/dockerfiles/delete", requireAuth(deleteDockerfileHandler))
	// container inspect page and API
	mux.HandleFunc("/container", requireAuth(containerPageHandler))
	mux.HandleFunc("/api/inspect", requireAuth(inspectAPIHandler))
	mux.HandleFunc("/users", requireAuth(usersHandler))
	mux.HandleFunc("/users/create", requireAuth(createUserHandler))
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/logout", logoutHandler)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// CLI flag and env var for port (required)
	port := flag.Int("port", 0, "port to listen on (required)")
	flag.Parse()

	// allow PORT env var as fallback
	if *port == 0 {
		if p := os.Getenv("PORT"); p != "" {
			if v, err := strconv.Atoi(p); err == nil {
				*port = v
			}
		}
	}

	if *port == 0 {
		flag.Usage()
		log.Fatal("port is required: provide -port flag or set PORT env var")
	}

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func initDB() error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password TEXT NOT NULL,
			created_at DATETIME
		);

		CREATE TABLE IF NOT EXISTS docker_files (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			path TEXT NOT NULL UNIQUE,
			created_at DATETIME
		);
	`)
	return err
}

// ---------------- session helper (simple HMAC-signed cookie) ----------------
func sessionKey() []byte {
	k := os.Getenv("SESSION_KEY")
	if k == "" {
		k = "default_dev_session_key_change_me"
	}
	return []byte(k)
}

func setSession(w http.ResponseWriter, userID int64) {
	expires := time.Now().Add(24 * time.Hour).Unix()
	payload := fmt.Sprintf("%d|%d", userID, expires)
	mac := hmac.New(sha256.New, sessionKey())
	mac.Write([]byte(payload))
	sig := mac.Sum(nil)
	token := base64.URLEncoding.EncodeToString([]byte(payload + "|" + base64.URLEncoding.EncodeToString(sig)))
	cookie := &http.Cookie{Name: "dpsess", Value: token, Path: "/", HttpOnly: true}
	http.SetCookie(w, cookie)
}

func clearSession(w http.ResponseWriter) {
	cookie := &http.Cookie{Name: "dpsess", Value: "", Path: "/", MaxAge: -1}
	http.SetCookie(w, cookie)
}

func getSession(r *http.Request) (int64, error) {
	c, err := r.Cookie("dpsess")
	if err != nil {
		return 0, err
	}
	raw, err := base64.URLEncoding.DecodeString(c.Value)
	if err != nil {
		return 0, err
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 {
		return 0, errors.New("invalid session format")
	}
	payload := parts[0] + "|" + parts[1]
	sigEncoded := parts[2]
	sig, err := base64.URLEncoding.DecodeString(sigEncoded)
	if err != nil {
		return 0, err
	}
	mac := hmac.New(sha256.New, sessionKey())
	mac.Write([]byte(payload))
	expected := mac.Sum(nil)
	if !hmac.Equal(sig, expected) {
		return 0, errors.New("invalid session signature")
	}
	// payload: userID|expires
	uid, _ := strconv.ParseInt(parts[0], 10, 64)
	exp, _ := strconv.ParseInt(parts[1], 10, 64)
	if time.Now().Unix() > exp {
		return 0, errors.New("session expired")
	}
	return uid, nil
}

// ---------------- middleware ----------------
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, err := getSession(r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

// ---------------- handlers ----------------
func loginHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{"title": "Login", "Error": nil}
	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "login.html", data)
		return
	}
	// POST
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	// if no users exist, allow ADMIN_PASSWORD env var to create admin
	var count int
	_ = db.QueryRow("SELECT COUNT(1) FROM users").Scan(&count)
	if count == 0 {
		// require ADMIN_PASSWORD
		adminPass := os.Getenv("ADMIN_PASSWORD")
		if adminPass == "" {
			http.Error(w, "no users and ADMIN_PASSWORD not set", http.StatusInternalServerError)
			return
		}
		if password == adminPass {
			// create admin user
			hashed, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			res, err := db.Exec("INSERT INTO users (username, password, created_at) VALUES (?, ?, datetime('now'))", "admin", string(hashed))
			if err != nil {
				http.Error(w, "failed to create admin user", http.StatusInternalServerError)
				return
			}
			id, _ := res.LastInsertId()
			setSession(w, id)
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
		data["Error"] = fmt.Sprintf("invalid admin password.")
		templates.ExecuteTemplate(w, "login.html", data)
		return
	}

	// normal login flow: find user by username
	var id int64
	var hash string
	err := db.QueryRow("SELECT id, password FROM users WHERE username = ?", username).Scan(&id, &hash)
	if err != nil {
		templates.ExecuteTemplate(w, "login.html", map[string]string{"Error": "invalid credentials"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		templates.ExecuteTemplate(w, "login.html", map[string]string{"Error": "invalid credentials"})
		return
	}
	setSession(w, id)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	clearSession(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	out, err := exec.Command("df", "-H").CombinedOutput()
	df := string(out)
	if err != nil {
		df = fmt.Sprintf("error running df: %v\n%s", err, df)
	}
	data := map[string]any{"title": "Dashboard", "DF": df}
	templates.ExecuteTemplate(w, "dashboard.html", data)
}

func topnHandler(w http.ResponseWriter, r *http.Request) {
	out, err := exec.Command("top", "-b", "-n", "1").CombinedOutput()
	top := string(out)
	if err != nil {
		top = fmt.Sprintf("error running top: %v\n%s", err, top)
	}
	data := map[string]any{"title": "TopN", "Command": "top -b -n 1", "Output": top}
	err = templates.ExecuteTemplate(w, "output.html", data)
	if err != nil {
		fmt.Println("error:", err)
	}
}

func dockerstatsHandler(w http.ResponseWriter, r *http.Request) {
	type DS struct {
		Container string
		Name      string
		CPU       string
		MemUsage  string
		MemPerc   string
		NetIO     string
		BlockIO   string
		PIDs      string
	}
	var stats []DS
	format := "{{.Container}}|{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}|{{.NetIO}}|{{.BlockIO}}|{{.PIDs}}"
	out, err := exec.Command("docker", "stats", "--no-stream", "--format", format).CombinedOutput()
	data := map[string]any{"title": "Docker Stats", "Command": "docker stats --no-stream --format '" + format + "'", "Output": string(out), "Error": nil, "list": stats}
	if err != nil {
		fmt.Println("error:", err)
		data["Error"] = fmt.Sprintf("error running docker stats: %v\n%s", err, string(out))
		templates.ExecuteTemplate(w, "dockerstats.html", data)
		return
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, ln := range lines {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		parts := strings.SplitN(ln, "|", 8)
		if len(parts) < 8 {
			continue
		}
		stats = append(stats, DS{Container: parts[0], Name: parts[1], CPU: parts[2], MemUsage: parts[3], MemPerc: parts[4], NetIO: parts[5], BlockIO: parts[6], PIDs: parts[7]})
	}
	data["list"] = stats
	err = templates.ExecuteTemplate(w, "dockerstats.html", data)
	if err != nil {
		fmt.Println("error:", err)
	}
}

// container page: shows UI and will fetch inspect data via JS
func containerPageHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "missing container id", http.StatusBadRequest)
		return
	}
	data := map[string]any{"title": "Container Inspect", "ID": id}
	templates.ExecuteTemplate(w, "container.html", data)
}

// API: run `docker inspect <id>` and return JSON
func inspectAPIHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	out, err := exec.Command("docker", "inspect", id).CombinedOutput()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, fmt.Sprintf("error running docker inspect: %v\n%s", err, string(out)), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

func usersHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, username, created_at FROM users ORDER BY id DESC")
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type U struct {
		ID                int
		Username, Created string
	}
	var list []U
	for rows.Next() {
		var u U
		rows.Scan(&u.ID, &u.Username, &u.Created)
		list = append(list, u)
	}
	data := map[string]any{"title": "Users", "list": list}
	templates.ExecuteTemplate(w, "users.html", data)
}

func createUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/users", http.StatusSeeOther)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if username == "" || password == "" {
		http.Error(w, "username and password required", http.StatusBadRequest)
		return
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "failed to hash password", http.StatusInternalServerError)
		return
	}
	_, err = db.Exec("INSERT INTO users (username, password, created_at) VALUES (?, ?, datetime('now'))", username, string(hashed))
	if err != nil {
		http.Error(w, "failed to create user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// ---------------- docker files handlers ----------------
func dockerfilesHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, path, created_at FROM docker_files ORDER BY id DESC")
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type DF struct {
		ID      int
		Path    string
		Created string
	}
	var list []DF
	for rows.Next() {
		var d DF
		rows.Scan(&d.ID, &d.Path, &d.Created)
		list = append(list, d)
	}
	data := map[string]any{"title": "Docker Files", "list": list}
	templates.ExecuteTemplate(w, "dockerfiles.html", data)
}

func addDockerfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/dockerfiles", http.StatusSeeOther)
		return
	}
	path := strings.TrimSpace(r.FormValue("path"))
	if path == "" {
		http.Error(w, "path is required", http.StatusBadRequest)
		return
	}
	// check file exists
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		http.Error(w, "file does not exist at given path", http.StatusBadRequest)
		return
	}
	// avoid duplicates
	var count int
	_ = db.QueryRow("SELECT COUNT(1) FROM docker_files WHERE path = ?", path).Scan(&count)
	if count > 0 {
		http.Redirect(w, r, "/dockerfiles", http.StatusSeeOther)
		return
	}
	_, err = db.Exec("INSERT INTO docker_files (path, created_at) VALUES (?, datetime('now'))", path)
	if err != nil {
		http.Error(w, "failed to add record: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/dockerfiles", http.StatusSeeOther)
}

func deleteDockerfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/dockerfiles", http.StatusSeeOther)
		return
	}
	idStr := r.FormValue("id")
	if idStr == "" {
		http.Redirect(w, r, "/dockerfiles", http.StatusSeeOther)
		return
	}
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Redirect(w, r, "/dockerfiles", http.StatusSeeOther)
		return
	}
	_, err = db.Exec("DELETE FROM docker_files WHERE id = ?", id)
	if err != nil {
		http.Error(w, "failed to delete: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/dockerfiles", http.StatusSeeOther)
}
