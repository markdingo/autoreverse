package database

import (
	"sync"
)

// Getter supports atomically switching databases on the fly - this occurs most often due
// to expired zone reloads. All database access for each request should go via
// Getter.Current() and go-routines should not hold on to the returned values of Getter()
// for longer than a single set of related accesses (such as an SOA query which might
// access SOA, NS and address RRs).
//
// The Getter exists because the database is read-only once populated and rather than
// having update capabilities they are simply replaced. Getter makes that easier.
type Getter struct {
	mu sync.RWMutex
	db *Database
}

// NewGetter creates a Getter with valid databases. This ensures Getter.Current() always
// returns valid pointers to database structs. After a Getter is created, all access
// functions are mutex protected to ensure concurrent access is ok.
func NewGetter() *Getter {
	return &Getter{db: NewDatabase()}
}

// Replace the current database. The old database will eventually garbage collect
// out of existence once the go-routines re-get via Current(). Replace can be called with
// a nil replacement pointer, in which case Replace() does nothing.
//
// The replacement occurs under the protection of a mutex making it concurrency safe.
func (t *Getter) Replace(newDB *Database) {
	if newDB == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.db = newDB
}

// Current returns the current database pointers under mutex protection.
func (t *Getter) Current() *Database {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.db
}
