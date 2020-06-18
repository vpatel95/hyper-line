package model

import (
	_ "time"

	"github.com/jinzhu/gorm"
)

type Worker struct {
	gorm.Model
	ServerAddr string `gorm:"column:server_addr" json:"server_addr"`
	ServerPort uint   `gorm:"column:server_port" json:"server_port"`
	PeerAddr   string `gorm:"column:peer_addr" json:"peer_addr"`
	PeerPort   uint   `gorm:"column:peer_port" json:"peer_port"`

	UserID uint `gorm:"column:user_id" json:"user_id"`
}

func (w *Worker) Serialize() JSON {
	return JSON{
		"id":          w.ID,
		"server_addr": w.ServerAddr,
		"server_port": w.ServerPort,
		"peer_addr":   w.PeerAddr,
		"peer_port":   w.PeerPort,
		"user_id":     w.UserID,
	}
}

func (w *Worker) Load(data JSON) {
	w.ID = data["id"].(uint)
	w.ServerAddr = data["server_addr"].(string)
	w.ServerPort = data["server_port"].(uint)
	w.PeerAddr = data["peer_addr"].(string)
	w.PeerPort = data["peer_port"].(uint)
	w.UserID = data["user_id"].(uint)
}

// Task Migration changes. Update this whenever task table is modified
func MigrateWorker(db *gorm.DB) *gorm.DB {
	db.AutoMigrate(&Worker{})
	return db
}
