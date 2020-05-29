package model

import (
	"github.com/jinzhu/gorm"
)

// Base Migration Function. Call model specific migration here
func Migration(db *gorm.DB) *gorm.DB {
	db = MigrateUser(db)

	return db
}
