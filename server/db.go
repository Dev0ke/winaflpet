package main

import (
	"database/sql"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/Masterminds/squirrel"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sgabe/structable"
	"github.com/spf13/viper"
)

const (
	DB_FLAVOR = "sqlite3"
	DB_SOURCE = "database.db"
)

func createDB(dataDir string, dataSrc string) {
	log.Println("Creating database file")

	if err := os.MkdirAll(dataDir, os.ModePerm); err != nil {
		log.Fatal(err.Error())
	}

	file, err := os.Create(dataSrc)
	if err != nil {
		log.Fatal(err.Error())
	}
	file.Close()
	log.Println("Database file created")
}

func initDB(dataType string, dataSrc string) {
	con, _ := sql.Open(dataType, dataSrc)
	defer con.Close()

	aStatements := map[string]string{
		TB_NAME_AGENTS:  TB_SCHEMA_AGENTS,
		TB_NAME_JOBS:    TB_SCHEMA_JOBS,
		TB_NAME_CRASHES: TB_SCHEMA_CRASHES,
		TB_NAME_STATS:   TB_SCHEMA_STATS,
		TB_NAME_USERS:   TB_SCHEMA_USERS,
	}

	for n, s := range aStatements {
		log.Printf("Creating '%s' table\n", n)
		statement, err := con.Prepare(s)
		if err != nil {
			log.Fatal(err.Error())
		}
		statement.Exec()
		log.Printf("Table '%s' created\n", n)
	}
}

func tableColumns(con *sql.DB, table string) (map[string]bool, error) {
	cols := map[string]bool{}
	rows, err := con.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return cols, err
	}
	defer rows.Close()

	// cid, name, type, notnull, dflt_value, pk
	for rows.Next() {
		var (
			cid       int
			name      string
			typ       string
			notnull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dfltValue, &pk); err != nil {
			return cols, err
		}
		cols[name] = true
	}
	return cols, rows.Err()
}

func ensureJobColumns(con *sql.DB) error {
	cols, err := tableColumns(con, TB_NAME_JOBS)
	if err != nil {
		return err
	}

	type colSpec struct {
		name string
		ddl  string
	}

	need := []colSpec{
		{name: "ignore_hitcount", ddl: "ALTER TABLE jobs ADD COLUMN ignore_hitcount INTEGER"},
		{name: "env_vars", ddl: "ALTER TABLE jobs ADD COLUMN env_vars TEXT"},
		{name: "instrument_transitive", ddl: "ALTER TABLE jobs ADD COLUMN instrument_transitive TEXT"},
		{name: "afl_f_mode", ddl: "ALTER TABLE jobs ADD COLUMN afl_f_mode INTEGER"},
		{name: "afl_f_dir", ddl: "ALTER TABLE jobs ADD COLUMN afl_f_dir TEXT"},
		{name: "afl_f_suffix", ddl: "ALTER TABLE jobs ADD COLUMN afl_f_suffix TEXT"},
		{name: "analysis_script", ddl: "ALTER TABLE jobs ADD COLUMN analysis_script TEXT"},
		{name: "analysis_windbg", ddl: "ALTER TABLE jobs ADD COLUMN analysis_windbg TEXT"},
		{name: "analysis_mem", ddl: "ALTER TABLE jobs ADD COLUMN analysis_mem INTEGER"},
		{name: "analysis_timeout", ddl: "ALTER TABLE jobs ADD COLUMN analysis_timeout INTEGER"},
		{name: "analysis_pageheap", ddl: "ALTER TABLE jobs ADD COLUMN analysis_pageheap INTEGER"},
		{name: "analysis_retries", ddl: "ALTER TABLE jobs ADD COLUMN analysis_retries INTEGER"},
		{name: "analysis_interval_min", ddl: "ALTER TABLE jobs ADD COLUMN analysis_interval_min INTEGER"},
		{name: "target_args", ddl: "ALTER TABLE jobs ADD COLUMN target_args TEXT"},
		{name: "drio_persistence_in_app", ddl: "ALTER TABLE jobs ADD COLUMN drio_persistence_in_app INTEGER"},
		{name: "ti_persist", ddl: "ALTER TABLE jobs ADD COLUMN ti_persist INTEGER"},
		{name: "ti_loop", ddl: "ALTER TABLE jobs ADD COLUMN ti_loop INTEGER"},
		{name: "basic_extra_args", ddl: "ALTER TABLE jobs ADD COLUMN basic_extra_args TEXT"},
		{name: "inst_extra_args", ddl: "ALTER TABLE jobs ADD COLUMN inst_extra_args TEXT"},
	}

	for _, c := range need {
		if cols[c.name] {
			continue
		}
		if _, err := con.Exec(c.ddl); err != nil {
			// Be forgiving if another process already added it.
			if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
				continue
			}
			return err
		}
	}
	return nil
}

func getDB() squirrel.DBProxyBeginner {
	dataType := DB_FLAVOR
	dataDir := viper.GetString("data.dir")
	dataSrc := filepath.Join(dataDir, DB_SOURCE)

	if !fileExists(dataSrc) {
		createDB(dataDir, dataSrc)
		initDB(dataType, dataSrc)
		initUser()
	}

	con, _ := sql.Open(dataType, dataSrc)
	// Best-effort migrations for existing databases.
	if err := ensureJobColumns(con); err != nil {
		log.Println(err)
	}
	cache := squirrel.NewStmtCacheProxy(con)

	return cache
}

func listWhere(d structable.Recorder, fn structable.WhereFunc) ([]structable.Recorder, error) {
	var tn string = d.TableName()
	var cols []string = d.Columns(true)
	buf := []structable.Recorder{}

	// Base query
	q := d.Builder().Select(cols...).From(tn)

	// Allow the fn to modify our query
	var err error
	q, err = fn(d, q)
	if err != nil {
		return buf, err
	}

	rows, err := q.Query()
	if err != nil || rows == nil {
		return buf, err
	}
	defer rows.Close()

	v := reflect.Indirect(reflect.ValueOf(d))
	t := v.Type()
	for rows.Next() {
		nv := reflect.New(t)

		// Bind an empty base object. Basically, we fetch the object out of
		// the DbRecorder, and then construct an empty one.
		rec := reflect.New(reflect.Indirect(reflect.ValueOf(d.(*structable.DbRecorder).Interface())).Type())
		nv.Interface().(structable.Recorder).Bind(d.TableName(), rec.Interface())

		s := nv.Interface().(structable.Recorder)
		s.Init(d.DB(), d.Driver())
		dest := s.FieldReferences(true)

		if err := rows.Scan(dest...); err != nil {
			return buf, err
		}

		buf = append(buf, s)
	}

	return buf, rows.Err()
}
