package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/lib/pq"
)

//go:embed web/*
var webFS embed.FS

const defaultDSN = "postgres://localhost:5432/messaging_app?sslmode=disable"

var db *sql.DB

type user struct {
	Username   string    `json:"username"`
	Location   string    `json:"location"`
	University string    `json:"university"`
	Salt       string    `json:"-"`
	Hash       string    `json:"-"`
	CreatedAt  time.Time `json:"createdAt"`
}

type message struct {
	From   string    `json:"from"`
	To     string    `json:"to"`
	Body   string    `json:"body"`
	SentAt time.Time `json:"sentAt"`
}

type authContext struct {
	username string
}

type messageResult struct {
	sentAt time.Time
	err    error
}

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = defaultDSN
	}

	var err error
	db, err = sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("unable to open database: %v", err)
	}

	if err := db.Ping(); err != nil {
		log.Fatalf("unable to reach database: %v", err)
	}
	if err := ensureSchema(db); err != nil {
		log.Fatalf("schema setup failed: %v", err)
	}

	mux := http.NewServeMux()
	static, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatalf("unable to read embedded files: %v", err)
	}
	mux.Handle("/", http.FileServer(http.FS(static)))
	mux.HandleFunc("/api/register", handleRegister)
	mux.HandleFunc("/api/login", handleLogin)
	mux.HandleFunc("/api/logout", handleLogout)
	mux.Handle("/api/profile", withAuth(handleProfile))
	mux.Handle("/api/messages", withAuth(handleMessages))

	server := &http.Server{
		Addr:         ":8080",
		Handler:      logging(mux),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	log.Printf("server listening on http://localhost%s", server.Addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server error: %v", err)
	}
}

func ensureSchema(db *sql.DB) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS users(
			username TEXT PRIMARY KEY,
			hash TEXT NOT NULL,
			salt TEXT NOT NULL,
			location TEXT,
			university TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS sessions(
			token TEXT PRIMARY KEY,
			username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS messages(
			id SERIAL PRIMARY KEY,
			sender TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
			recipient TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
			body TEXT NOT NULL,
			sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
	}

	for _, stmt := range statements {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		Location   string `json:"location"`
		University string `json:"university"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if payload.Username == "" || payload.Password == "" {
		http.Error(w, "username and password are required", http.StatusBadRequest)
		return
	}

	salt := randomToken(16)
	hashed := hashPassword(payload.Password, salt)
	_, err := db.Exec(
		`INSERT INTO users (username, hash, salt, location, university) VALUES ($1, $2, $3, $4, $5)`,
		payload.Username, hashed, salt, payload.Location, payload.University,
	)
	if err != nil {
		if isUniqueViolation(err) {
			http.Error(w, "user already exists", http.StatusConflict)
			return
		}
		log.Printf("register error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"message": "registered",
	})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var u user
	err := db.QueryRow(
		`SELECT username, location, university, salt, hash, created_at FROM users WHERE username=$1`,
		payload.Username,
	).Scan(&u.Username, &u.Location, &u.University, &u.Salt, &u.Hash, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if err != nil {
		log.Printf("login query error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if u.Hash != hashPassword(payload.Password, u.Salt) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	sessionToken := randomToken(32)
	if _, err := db.Exec(
		`INSERT INTO sessions (token, username) VALUES ($1, $2)`,
		sessionToken, u.Username,
	); err != nil {
		log.Printf("session insert error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(24 * time.Hour),
	})

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "logged in",
	})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cookie, err := r.Cookie("session_token")
	if err == nil {
		if _, err := db.Exec(`DELETE FROM sessions WHERE token=$1`, cookie.Value); err != nil {
			log.Printf("logout delete error: %v", err)
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
	})

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "logged out",
	})
}

func handleProfile(w http.ResponseWriter, r *http.Request, ctx authContext) {
	var u user
	err := db.QueryRow(
		`SELECT username, location, university, created_at FROM users WHERE username=$1`,
		ctx.username,
	).Scan(&u.Username, &u.Location, &u.University, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("profile query error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, u)
}

func handleMessages(w http.ResponseWriter, r *http.Request, ctx authContext) {
	switch r.Method {
	case http.MethodGet:
		rows, err := db.Query(
			`SELECT sender, recipient, body, sent_at FROM messages WHERE sender=$1 OR recipient=$1 ORDER BY sent_at DESC`,
			ctx.username,
		)
		if err != nil {
			log.Printf("messages query error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var results []message
		for rows.Next() {
			var m message
			if err := rows.Scan(&m.From, &m.To, &m.Body, &m.SentAt); err != nil {
				log.Printf("messages scan error: %v", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			results = append(results, m)
		}
		writeJSON(w, http.StatusOK, results)

	case http.MethodPost:
		var payload struct {
			To   string `json:"to"`
			Body string `json:"body"`
		}
		if err := decodeJSON(r, &payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if payload.To == "" || payload.Body == "" {
			http.Error(w, "recipient and body are required", http.StatusBadRequest)
			return
		}

		var exists string
		if err := db.QueryRow(`SELECT username FROM users WHERE username=$1`, payload.To).Scan(&exists); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				http.Error(w, "recipient not found", http.StatusNotFound)
				return
			}
			log.Printf("recipient lookup error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		resultCh := make(chan messageResult, 1)
		go func() {
			var sentAt time.Time
			err := db.QueryRow(
				`INSERT INTO messages (sender, recipient, body) VALUES ($1, $2, $3) RETURNING sent_at`,
				ctx.username, payload.To, payload.Body,
			).Scan(&sentAt)
			resultCh <- messageResult{sentAt: sentAt, err: err}
			close(resultCh)
		}()
		res := <-resultCh
		if res.err != nil {
			log.Printf("message insert error: %v", res.err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusCreated, message{
			From:   ctx.username,
			To:     payload.To,
			Body:   payload.Body,
			SentAt: res.sentAt,
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func withAuth(next func(http.ResponseWriter, *http.Request, authContext)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, ok := authenticate(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r, ctx)
	})
}

func authenticate(r *http.Request) (authContext, bool) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return authContext{}, false
	}

	var username string
	err = db.QueryRow(`SELECT username FROM sessions WHERE token=$1`, cookie.Value).Scan(&username)
	if err != nil {
		return authContext{}, false
	}
	return authContext{username: username}, true
}

func decodeJSON(r *http.Request, dest any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dest); err != nil {
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("unable to encode response: %v", err)
	}
}

func hashPassword(password, salt string) string {
	sum := sha256.Sum256([]byte(password + ":" + salt))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func randomToken(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func isUniqueViolation(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "23505"
	}
	return false
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).String())
	})
}
