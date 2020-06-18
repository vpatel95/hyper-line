package model

import (
	"github.com/jinzhu/gorm"
)

type JSON = map[string]interface{}

// Base Migration Function. Call model specific migration here
func Migration(db *gorm.DB) *gorm.DB {
	db = MigrateUser(db)
	db = MigrateTask(db)
	db = MigrateWorker(db)
	db = MigrateStage(db)

	return db
}
