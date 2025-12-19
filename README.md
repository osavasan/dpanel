# DPanel (minimal)

Simple Go web app with sqlite, Bootstrap and jQuery.

Environment:
- `ADMIN_PASSWORD` - initial admin password used to create first user if DB empty
- `SESSION_KEY` - secret used to sign session cookie (set to a secure random value in production)
- `DB_PATH` - optional path to sqlite file (default: app.db)

Run:

```bash
go mod tidy
go run ./ -port 8897
```

Open http://localhost:8080

Initial login: if DB has no users, login with any username and the password set in `ADMIN_PASSWORD` to create the `admin` user.
