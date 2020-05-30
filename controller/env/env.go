package env

import (
	"os"
	"path/filepath"
)

var (
	ProjectRoot, _ = os.Getwd()
	ConfigRoot     = filepath.Join(ProjectRoot, "configs")
	SessionConfig  = filepath.Join(ConfigRoot, "session.json")
	DBConfig       = filepath.Join(ConfigRoot, "database.json")
	JWTSecret      = filepath.Join(ConfigRoot, "jwtsecret.key")
)
