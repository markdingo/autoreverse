package database_test

import (
	"testing"

	"github.com/markdingo/autoreverse/database"
)

func TestGetter(t *testing.T) {
	getter := database.NewGetter()
	db1 := getter.Current()
	getter.Replace(database.NewDatabase())
	db2 := getter.Current()
	if db1 == db2 {
		t.Error("Current() returned old", db1, db2)
	}
}
