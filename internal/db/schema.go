package db

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
)

// TableColumn defines the column name and column definition for schema checks.
type TableColumn struct {
	Name string
	Type string
}

// ExpectedSchema maps table names to their expected columns.
var ExpectedSchema = map[string][]TableColumn{
	"users": {
		{Name: "id", Type: "INTEGER PRIMARY KEY AUTOINCREMENT"},
		{Name: "username", Type: "TEXT NOT NULL UNIQUE"},
		{Name: "password", Type: "TEXT NOT NULL"},
		{Name: "created_at", Type: "DATETIME"},
	},
	"docker_files": {
		{Name: "id", Type: "INTEGER PRIMARY KEY AUTOINCREMENT"},
		{Name: "path", Type: "TEXT NOT NULL UNIQUE"},
		{Name: "created_at", Type: "DATETIME"},
	},
}

// DefaultSchemaSQL is fallback SQL if the schema file cannot be read.
const DefaultSchemaSQL = `
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
`

// EnsureSchema initializes missing tables and adds any missing columns on boot.
func EnsureSchema(db *sql.DB, schemaPath string) error {
	var sqlContent string
	if schemaPath != "" {
		content, err := os.ReadFile(schemaPath)
		if err == nil {
			sqlContent = string(content)
		}
	}
	if strings.TrimSpace(sqlContent) == "" {
		sqlContent = DefaultSchemaSQL
	}

	// 1. Create missing tables
	if _, err := db.Exec(sqlContent); err != nil {
		return fmt.Errorf("failed executing schema sql: %w", err)
	}

	// 2. Check each table for missing columns
	for table, columns := range ExpectedSchema {
		existingCols, err := getExistingColumns(db, table)
		if err != nil {
			return fmt.Errorf("failed getting columns for table %s: %w", table, err)
		}

		for _, col := range columns {
			// Skip primary key column alter since sqlite handles PK on CREATE TABLE
			if strings.Contains(strings.ToUpper(col.Type), "PRIMARY KEY") {
				continue
			}
			if !existingCols[strings.ToLower(col.Name)] {
				// Column is missing, add it
				// SQLite ALTER TABLE ADD COLUMN does not allow NOT NULL without default value,
				// so strip NOT NULL for dynamically added columns if necessary.
				colDef := col.Type
				if strings.Contains(strings.ToUpper(colDef), "NOT NULL") && !strings.Contains(strings.ToUpper(colDef), "DEFAULT") {
					colDef = strings.ReplaceAll(colDef, "NOT NULL", "")
					colDef = strings.ReplaceAll(colDef, "not null", "")
					colDef = strings.TrimSpace(colDef)
				}
				alterQuery := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, col.Name, colDef)
				if _, err := db.Exec(alterQuery); err != nil {
					return fmt.Errorf("failed to add missing column %s to table %s: %w", col.Name, table, err)
				}
			}
		}
	}

	return nil
}

// getExistingColumns retrieves map of column names for a given table using PRAGMA table_info.
func getExistingColumns(db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dfltValue sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			return nil, err
		}
		cols[strings.ToLower(name)] = true
	}
	return cols, rows.Err()
}
