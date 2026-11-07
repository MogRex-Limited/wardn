// Package integration runs wardn's SQL store against real databases. It is a
// separate module so database drivers never become dependencies of wardn.
//
// SQLite always runs. Postgres, MySQL and MariaDB run when their DSNs are set:
//
//	WARDN_TEST_POSTGRES_DSN, WARDN_TEST_MYSQL_DSN, WARDN_TEST_MARIADB_DSN
//
// Set WARDN_TEST_REQUIRE_ALL=1 to fail instead of skipping a database whose
// DSN is missing (CI does). `make integration` starts all three in Docker and
// runs the tests.
package integration
