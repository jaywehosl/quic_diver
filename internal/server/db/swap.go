package db

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Live — хранилище с горячей подменой файла базы.
//
// Реплика получает от мастера свежий снимок и обязана применить его, не
// перезапускаясь: рестарт каждые несколько минут рвал бы все туннели узла.
// Поэтому снимок открывается рядом как отдельная база, а затем указатель
// переключается одним атомарным присваиванием. Запросы, начатые на старой базе,
// доживают на ней — она закрывается с задержкой.
//
// Реализует Store, поэтому остальной код о подмене не знает.
type Live struct {
	cur atomic.Pointer[SQLite]

	mu sync.Mutex
	// base — путь, указанный при открытии; сами данные лежат в файле поколения.
	base string
	// file — файл, на котором работает текущая база.
	file string
	// gen — номер текущего поколения (0 — исходный файл base).
	gen int
	// retired — базы, снятые с эксплуатации; закрываются после grace-периода.
	retired []*SQLite
}

// retireAfter — сколько держать снятую базу открытой.
//
// Закрыть сразу нельзя: запрос, начатый до подмены, продолжает читать старое
// соединение и получил бы «database is closed» на ровном месте.
const retireAfter = 30 * time.Second

// genSuffix отделяет номер поколения в имени файла.
//
// Подменить файл под открытым SQLite нельзя: журналы WAL он ищет по имени, и
// переименование основного файла из-под работающего соединения рвёт базу.
// Поэтому каждый снимок ложится в СВОЙ файл, а на старте берётся самый свежий —
// так узел и после перезапуска поднимается на последних полученных данных.
const genSuffix = ".gen"

// NewLive открывает базу с возможностью горячей подмены.
//
// Если рядом лежит снимок новее исходного файла — поднимаемся на нём.
func NewLive(path string) (*Live, error) {
	l := &Live{base: path, file: path}
	if gen, file, ok := latestGeneration(path); ok {
		l.gen, l.file = gen, file
	}
	s, err := Open(l.file)
	if err != nil {
		return nil, err
	}
	l.cur.Store(s)
	l.dropStaleGenerations()
	return l, nil
}

// latestGeneration ищет самый свежий пригодный снимок рядом с базой.
func latestGeneration(path string) (int, string, bool) {
	for _, gen := range generations(path) {
		file := genFile(path, gen)
		if err := ValidateSnapshot(context.Background(), file); err != nil {
			// Битый снимок (например, узел умер в момент записи) — не трогаем
			// его молча в сторону, а просто пропускаем: пусть остаётся уликой.
			log.Printf("снимок %s непригоден, пропускаю: %v", filepath.Base(file), err)
			continue
		}
		return gen, file, true
	}
	return 0, "", false
}

// generations — номера лежащих рядом поколений, от новых к старым.
func generations(path string) []int {
	matches, err := filepath.Glob(path + genSuffix + "*")
	if err != nil {
		return nil
	}
	var out []int
	for _, m := range matches {
		// Отсекаем журналы WAL: они тоже попадают под маску.
		if strings.HasSuffix(m, "-wal") || strings.HasSuffix(m, "-shm") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(m, path+genSuffix))
		if err != nil {
			continue
		}
		out = append(out, n)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(out)))
	return out
}

func genFile(path string, gen int) string {
	return path + genSuffix + strconv.Itoa(gen)
}

// DB — текущая база.
func (l *Live) DB() *SQLite { return l.cur.Load() }

// Path — файл, на котором база работает сейчас.
func (l *Live) Path() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file
}

// SwapFile подменяет базу файлом snapshot, оставляя прежнюю дожить.
//
// Снимок проверяется ДО подмены: применить битый файл значило бы потерять
// рабочий реестр узлов из-за одной неудачной передачи.
func (l *Live) SwapFile(snapshot string) error {
	if err := ValidateSnapshot(context.Background(), snapshot); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	next := genFile(l.base, l.gen+1)
	if err := os.Rename(snapshot, next); err != nil {
		return fmt.Errorf("db: подготовить снимок: %w", err)
	}
	// Снимок несёт данные мастера, но не то, что узел наблюдал у себя: сессии,
	// устройства, счётчики трафика, свои выходы. Переносим их до подмены, иначе
	// реплика теряла бы учёт с частотой обновлений.
	if err := carryLocal(context.Background(), next, l.file); err != nil {
		removeDBFiles(next)
		return err
	}
	fresh, err := Open(next)
	if err != nil {
		removeDBFiles(next)
		return fmt.Errorf("db: открыть снимок: %w", err)
	}

	old := l.cur.Load()
	oldFile := l.file
	l.cur.Store(fresh) // с этого мгновения новые запросы идут в свежую базу
	l.gen++
	l.file = next
	l.retired = append(l.retired, old)

	go l.retire(old, oldFile)
	return nil
}

// retire закрывает снятую базу, дав начатым запросам доработать.
func (l *Live) retire(old *SQLite, file string) {
	time.Sleep(retireAfter)
	l.mu.Lock()
	for i, s := range l.retired {
		if s == old {
			l.retired = append(l.retired[:i], l.retired[i+1:]...)
			break
		}
	}
	l.mu.Unlock()
	if err := old.Close(); err != nil {
		log.Printf("закрытие прежней базы: %v", err)
		return
	}
	// Исходный файл базы не трогаем: он мог быть подложен администратором
	// вручную, и удалять его за него мы не вправе.
	if file != l.base {
		removeDBFiles(file)
	}
}

// dropStaleGenerations убирает снимки старше того, на котором работаем.
func (l *Live) dropStaleGenerations() {
	for _, gen := range generations(l.base) {
		if gen < l.gen {
			removeDBFiles(genFile(l.base, gen))
		}
	}
}

// removeDBFiles сносит файл базы вместе с её журналами.
func removeDBFiles(path string) {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Remove(path + suffix); err != nil && !os.IsNotExist(err) {
			log.Printf("удаление %s: %v", filepath.Base(path+suffix), err)
		}
	}
}

// Close гасит текущую и все снятые базы.
func (l *Live) Close() error {
	l.mu.Lock()
	retired := l.retired
	l.retired = nil
	l.mu.Unlock()
	for _, s := range retired {
		_ = s.Close()
	}
	return l.cur.Load().Close()
}

// --- Store: всё уходит в текущую базу ---

func (l *Live) Lookup(ctx context.Context, hash string) (TokenInfo, error) {
	return l.DB().Lookup(ctx, hash)
}

func (l *Live) Assignment(ctx context.Context, hash string) (string, error) {
	return l.DB().Assignment(ctx, hash)
}

func (l *Live) AllocateAddress(ctx context.Context, hash string, pool netip.Prefix) (netip.Addr, error) {
	return l.DB().AllocateAddress(ctx, hash, pool)
}

var _ Store = (*Live)(nil)
