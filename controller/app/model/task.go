package model

import (
	_ "time"

	"github.com/jinzhu/gorm"
)

type Task struct {
	gorm.Model
	Name       string `gorm:"column:name;unique_index;not null" json:"name"`
	InputFile  string `gorm:"column:input_file" json:"input_file"`
	OutputFile string `gorm:"column:output_file" json:"output_file"`
	TaskFile   string `gorm:"column:task_file" json:"task_file"`

	UserID uint `gorm:"column:user_id" json:"user_id"`
	Stages []Stage
}

func (t *Task) Serialize() JSON {
	return JSON{
		"id":          t.ID,
		"name":        t.Name,
		"input_file":  t.InputFile,
		"output_file": t.OutputFile,
		"task_file":   t.TaskFile,
		"user_id":     t.UserID,
	}
}

func (t *Task) Load(data JSON) {
	t.ID = data["id"].(uint)
	t.Name = data["name"].(string)
	t.InputFile = data["input_file"].(string)
	t.OutputFile = data["output_file"].(string)
	t.TaskFile = data["task_file"].(string)
	t.UserID = data["user_id"].(uint)
}

// Task Migration changes. Update this whenever task table is modified
func MigrateTask(db *gorm.DB) *gorm.DB {
	db.AutoMigrate(&Task{})
	return db
}
