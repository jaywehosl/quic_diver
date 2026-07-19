package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Cluster — кто в сети мастер и какого он поколения.
type Cluster struct {
	// Epoch — поколение мастера. Растёт при каждом промоушене.
	Epoch int64 `json:"epoch"`
	// MasterID — идентификатор узла-мастера.
	MasterID string `json:"master_id"`
	// UpdatedAt — когда состояние менялось.
	UpdatedAt time.Time `json:"updated_at"`
}

// ClusterState читает состояние кластера.
//
// Пустая таблица — не ошибка: так выглядит одиночный узел, который ещё никто не
// объявлял мастером. Он и есть мастер по факту (пишет сам себе).
func (s *SQLite) ClusterState(ctx context.Context) (Cluster, error) {
	var c Cluster
	var upd int64
	err := s.db.QueryRowContext(ctx,
		`SELECT epoch, master_id, updated_at FROM cluster WHERE id = 1`).
		Scan(&c.Epoch, &c.MasterID, &upd)
	if errors.Is(err, sql.ErrNoRows) {
		return Cluster{Epoch: 0}, nil
	}
	if err != nil {
		return Cluster{}, fmt.Errorf("db: состояние кластера: %w", err)
	}
	c.UpdatedAt = time.Unix(0, upd)
	return c, nil
}

// ErrStaleEpoch — попытка объявить мастера поколением не выше текущего.
var ErrStaleEpoch = errors.New("db: поколение мастера не выше текущего")

// Promote объявляет узел мастером, повышая поколение.
//
// Поколение обязано вырасти: иначе вернувшийся старый мастер объявил бы себя
// заново тем же номером, и сеть получила бы двух пишущих.
func (s *SQLite) Promote(ctx context.Context, nodeID string) (Cluster, error) {
	cur, err := s.ClusterState(ctx)
	if err != nil {
		return Cluster{}, err
	}
	next := Cluster{Epoch: cur.Epoch + 1, MasterID: nodeID, UpdatedAt: time.Now()}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO cluster (id, epoch, master_id, updated_at) VALUES (1, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET epoch=excluded.epoch, master_id=excluded.master_id,
		   updated_at=excluded.updated_at`,
		next.Epoch, next.MasterID, next.UpdatedAt.UnixNano())
	if err != nil {
		return Cluster{}, fmt.Errorf("db: промоушен: %w", err)
	}
	return next, nil
}

// AdoptCluster принимает состояние кластера из чужого снимка.
//
// Применяем только поколение СТРОГО выше своего. Иначе отставшая реплика,
// раздав свой старый снимок, могла бы откатить сеть к прежнему мастеру.
func (s *SQLite) AdoptCluster(ctx context.Context, c Cluster) error {
	cur, err := s.ClusterState(ctx)
	if err != nil {
		return err
	}
	if c.Epoch <= cur.Epoch {
		return ErrStaleEpoch
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO cluster (id, epoch, master_id, updated_at) VALUES (1, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET epoch=excluded.epoch, master_id=excluded.master_id,
		   updated_at=excluded.updated_at`,
		c.Epoch, c.MasterID, time.Now().UnixNano())
	if err != nil {
		return fmt.Errorf("db: принять состояние кластера: %w", err)
	}
	return nil
}

// BootstrapMaster прописывает узлу, у кого забирать базу при первой установке.
//
// Свежепоставленная реплика о сети не знает ничего: мастера ей называет
// администратор при установке. Дальше она узнаёт всё сама из снимков, поэтому
// делается это ровно один раз — если поколение уже не нулевое, узел уже в сети,
// и переназначать мастера флагом запуска нельзя (это дело admin-API, осознанно и
// с подтверждением).
//
// Возвращает false, если bootstrap не потребовался.
func (s *SQLite) BootstrapMaster(ctx context.Context, node Node) (bool, error) {
	cur, err := s.ClusterState(ctx)
	if err != nil {
		return false, err
	}
	if cur.Epoch > 0 {
		return false, nil // узел уже знает сеть
	}
	// Хеш токена мастера нам неизвестен и не нужен: к нему идём мы, предъявляя
	// СВОЙ токен. Его хеш приедет со снимком.
	if err := s.PutNode(ctx, node); err != nil {
		return false, err
	}
	if err := s.AdoptCluster(ctx, Cluster{Epoch: 1, MasterID: node.ID}); err != nil {
		return false, err
	}
	return true, nil
}

// IsMaster — этот ли узел пишет базу.
//
// Одиночный узел (никого не объявляли) считается мастером: иначе первая же
// установка получила бы базу, в которую нельзя писать.
func (c Cluster) IsMaster(nodeID string) bool {
	return c.MasterID == "" || c.MasterID == nodeID
}
