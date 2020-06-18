package model

import (
	_ "time"

	"github.com/jinzhu/gorm"
)

type Stage struct {
	gorm.Model
	Number   uint   `gorm:"column:number" json:"number"`
	Function string `gorm:"column:function" json:"function"`

	TaskID   uint `gorm:"column:task_id" json:"task_id"`
	WorkerID uint `gorm:"column:worker_id" json:"worker_id"`
	Worker   Worker
}

func (s *Stage) Serialize() JSON {
	return JSON{
		"id":        s.ID,
		"number":    s.Number,
		"function":  s.Function,
		"worker_id": s.WorkerID,
	}
}

func (s *Stage) Load(data JSON) {
	s.ID = data["id"].(uint)
	s.Number = data["number"].(uint)
	s.Function = data["function"].(string)
	s.WorkerID = data["worker_id"].(uint)
}

// User Migration changes. Update this whenever user table is modified
func MigrateStage(db *gorm.DB) *gorm.DB {
	db.AutoMigrate(&Stage{})
	return db
}
