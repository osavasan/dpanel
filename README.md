DPanel --- Minimal Docker Compose Admin Panel
===========================================

**DPanel** is a lightweight web-based admin panel for managing **Docker Compose** projects and observing running containers.

It's designed to be:

-   **Minimal** -- no heavy dependencies

-   **Fast** -- single Go binary

-   **Self-hosted** -- run it on any lean server

Built with **Go**, **SQLite**, **Bootstrap**, and **jQuery**.

* * * * *

Features
--------

-   View and manage Docker Compose services

-   Observe container status and basic runtime information

-   Web-based UI with session authentication

-   Single binary deployment

-   SQLite-backed storage (no external DB required)

* * * * *

Requirements
------------

-   Go 1.21+ (or compatible)

-   Docker & Docker Compose available on the host

* * * * *

Configuration
-------------

DPanel is configured via environment variables:

| Variable | Description |
| --- | --- |
| `ADMIN_PASSWORD` | Initial admin password used to create the first user if the database is empty |
| `SESSION_KEY` | Secret key used to sign session cookies (**must be random & secure in production**) |
| `DB_PATH` | Optional path to the SQLite database file (default: `app.db`) |

Example:

`export ADMIN_PASSWORD=changeme
export SESSION_KEY=$(openssl rand -hex 32)`

* * * * *

Running Locally
---------------

`go mod tidy
go run ./ -port 8080`

Then open:

`http://localhost:8080`

* * * * *

First Login Behavior
--------------------

-   If the database contains **no users**:

    -   You may log in with **any username**

    -   Use the password defined in `ADMIN_PASSWORD`

    -   This will automatically create the first `admin` user

After the initial admin user is created, normal authentication rules apply.

* * * * *

Production Notes
----------------

-   Always set a **strong `SESSION_KEY`**

-   Run behind a reverse proxy (Caddy / Nginx / Traefik) for TLS

-   Limit Docker socket access appropriately

* * * * *

Philosophy
----------

DPanel intentionally avoids complexity.\
If you want a heavy Docker UI, this is not it.\
If you want a **small, understandable, hackable control panel**, this is.

* * * * *

