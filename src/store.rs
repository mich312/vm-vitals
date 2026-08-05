//! Embedded time-series store (SQLite) with tiered rollups, so charts can show
//! real history cheaply. Each metric is sampled at raw resolution every tick;
//! a periodic compactor aggregates old raw points into 5-minute and 1-hour
//! buckets and prunes beyond the retention window.
//!
//! Resolutions (seconds): 15 (raw) → 300 (5-min) → 3600 (1-hour).
//! Retention: raw 48h · 5-min 30d · 1-hour 180d.
//!
//! Three design points that are load-bearing:
//!
//! * **`PRIMARY KEY(res, ts, mid)`** — time-major. A tick writes many metrics at
//!   one `ts`, so they land on adjacent pages instead of scattering one page per
//!   metric. Metric-major keying costs ~87x the WAL traffic per tick.
//! * **Metric names are interned** into `metric(id, name)`. Repeating the string
//!   on every row costs ~27% of the file, and the SPEC called for interning.
//! * **Rollups are bounded to buckets that can still change.** An unbounded
//!   `GROUP BY` recomputes buckets whose source rows have already been pruned,
//!   overwriting correct aggregates with partial ones — permanently.

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::Context;
use rusqlite::{params, Connection, OpenFlags};

const RAW: i64 = 15;
const FIVE_MIN: i64 = 300;
const HOUR: i64 = 3600;

const RAW_RETENTION: i64 = 172_800; // 48h
const FIVE_MIN_RETENTION: i64 = 2_592_000; // 30d
const HOUR_RETENTION: i64 = 15_552_000; // 180d

/// Bump when the schema changes. The history is derived and disposable, so an
/// older file is rebuilt rather than migrated — but that must be a decision the
/// code makes explicitly, not something `CREATE TABLE IF NOT EXISTS` papers over.
const SCHEMA_VERSION: i64 = 1;

pub struct Store {
    /// Writer + compactor. Serialized; SQLite allows one writer.
    write: Mutex<Connection>,
    /// Reader for `/api/series`. WAL permits a reader concurrent with the
    /// writer, so a chart request never waits behind a compaction.
    read: Mutex<Connection>,
    /// name → metric id, so the hot write path doesn't hit the DB per metric.
    ids: Mutex<HashMap<String, i64>>,
}

impl Store {
    pub fn open(path: &str) -> anyhow::Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("opening {path}"))?;
        // Before `configure` switches on WAL: SQLite gives the -wal/-shm
        // siblings the same mode as the main file, so tightening it first
        // covers all three. The metric names are a container inventory.
        restrict(path);
        Self::configure(&conn)?;
        Self::migrate(&conn, path)?;

        let read = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| format!("opening {path} read-only"))?;
        Self::configure(&read)?;

        Ok(Self {
            write: Mutex::new(conn),
            read: Mutex::new(read),
            ids: Mutex::new(HashMap::new()),
        })
    }

    fn configure(conn: &Connection) -> anyhow::Result<()> {
        // busy_timeout matters as soon as there are two connections (and for any
        // external `sqlite3` shell): without it a contended open fails instantly.
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA busy_timeout=5000;
             PRAGMA cache_size=-16384;
             PRAGMA mmap_size=268435456;",
        )?;
        Ok(())
    }

    fn migrate(conn: &Connection, path: &str) -> anyhow::Result<()> {
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        let has_tables: bool = conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('samples','metric')",
            [],
            |r| r.get::<_, i64>(0),
        )? > 0;

        if has_tables && version != SCHEMA_VERSION {
            tracing::warn!(
                "history schema v{version} != v{SCHEMA_VERSION}; rebuilding {path} \
                 (metrics history is derived data and will be re-collected)"
            );
            conn.execute_batch("DROP TABLE IF EXISTS samples; DROP TABLE IF EXISTS metric;")?;
        }

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS metric(
                id   INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE
             );
             CREATE TABLE IF NOT EXISTS samples(
                res INTEGER NOT NULL,
                ts  INTEGER NOT NULL,
                mid INTEGER NOT NULL,
                avg REAL NOT NULL,
                min REAL NOT NULL,
                max REAL NOT NULL,
                n   INTEGER NOT NULL,
                PRIMARY KEY(res, ts, mid)
             ) WITHOUT ROWID;
             -- Serves `WHERE mid=? AND res=? AND ts BETWEEN ?`; without it a
             -- chart request scans the whole time range across every metric.
             CREATE INDEX IF NOT EXISTS ix_samples_mid_res_ts ON samples(mid, res, ts);
             CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v INTEGER NOT NULL);",
        )?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        Ok(())
    }

    /// Resolve (and create) a metric id, memoized.
    fn metric_id(&self, conn: &Connection, name: &str) -> rusqlite::Result<i64> {
        if let Some(id) = self.ids.lock().unwrap().get(name) {
            return Ok(*id);
        }
        conn.prepare_cached("INSERT OR IGNORE INTO metric(name) VALUES(?1)")?
            .execute(params![name])?;
        let id: i64 = conn
            .prepare_cached("SELECT id FROM metric WHERE name=?1")?
            .query_row(params![name], |r| r.get(0))?;
        self.ids.lock().unwrap().insert(name.to_string(), id);
        Ok(id)
    }

    /// Append one raw sample per metric at `ts`.
    pub fn write(&self, ts: u64, points: &[(String, f64)]) {
        if let Err(e) = self.try_write(ts, points) {
            // A monitor that silently stops recording — because the disk it was
            // watching filled up — is the failure this project exists to catch.
            tracing::warn!("store write failed ({} points): {e:#}", points.len());
        }
    }

    fn try_write(&self, ts: u64, points: &[(String, f64)]) -> anyhow::Result<()> {
        let mut conn = self.write.lock().map_err(|_| anyhow::anyhow!("write lock poisoned"))?;
        let tx = conn.transaction().context("begin")?;
        {
            let mut st = tx
                .prepare_cached(
                    "INSERT OR REPLACE INTO samples(res,ts,mid,avg,min,max,n)
                     VALUES(?1,?2,?3,?4,?4,?4,1)",
                )
                .context("prepare insert")?;
            for (m, v) in points {
                // Non-finite values would violate the NOT NULL columns (SQLite
                // stores NaN as NULL) and be rejected row-by-row; skip loudly.
                if !v.is_finite() {
                    tracing::debug!("skipping non-finite sample for {m}");
                    continue;
                }
                let mid = self.metric_id(&tx, m).with_context(|| format!("metric id {m}"))?;
                st.execute(params![RAW, ts as i64, mid, v])
                    .with_context(|| format!("insert {m}"))?;
            }
        }
        tx.commit().context("commit")?;
        Ok(())
    }

    /// Points for a metric in [from,to] at a resolution, capped at `limit` rows.
    pub fn series(
        &self,
        metric: &str,
        from: i64,
        to: i64,
        res: i64,
        limit: usize,
    ) -> anyhow::Result<Series> {
        let conn = self.read.lock().map_err(|_| anyhow::anyhow!("read lock poisoned"))?;
        let mut out = Series::default();

        let mid: Option<i64> = conn
            .prepare_cached("SELECT id FROM metric WHERE name=?1")?
            .query_row(params![metric], |r| r.get(0))
            .ok();
        let Some(mid) = mid else { return Ok(out) }; // unknown metric = empty, not an error

        let mut st = conn.prepare_cached(
            "SELECT ts,avg,min,max FROM samples
             WHERE mid=?1 AND res=?2 AND ts>=?3 AND ts<=?4 ORDER BY ts LIMIT ?5",
        )?;
        let rows = st.query_map(params![mid, res, from, to, limit as i64], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, f64>(1)?,
                r.get::<_, f64>(2)?,
                r.get::<_, f64>(3)?,
            ))
        })?;
        for row in rows {
            let (t, avg, min, max) = row?;
            out.t.push(t);
            out.avg.push(avg);
            out.min.push(min);
            out.max.push(max);
        }
        Ok(out)
    }

    /// Roll raw→5min→1hour and prune past retention.
    pub fn compact(&self, now: i64) {
        if let Err(e) = self.try_compact(now) {
            tracing::warn!("store compact: {e:#}");
        }
    }

    fn try_compact(&self, now: i64) -> anyhow::Result<()> {
        let mut conn = self.write.lock().map_err(|_| anyhow::anyhow!("write lock poisoned"))?;

        let last: i64 = conn
            .query_row("SELECT v FROM meta WHERE k='last_compact'", [], |r| r.get(0))
            .unwrap_or(0);

        let raw_cut = now - RAW_RETENTION;
        let fm_cut = now - FIVE_MIN_RETENTION;
        let hr_cut = now - HOUR_RETENTION;

        // Recompute only buckets that (a) may still gain samples and (b) are
        // wholly inside the retained window of the tier below. Rounding *up* to
        // a bucket boundary at the cut is what stops a bucket from being
        // rewritten from a truncated suffix after its early rows were pruned.
        let lo5 = ceil_bucket(last.min(now - 2 * FIVE_MIN).max(raw_cut), FIVE_MIN);
        let lo60 = ceil_bucket(last.min(now - 2 * HOUR).max(fm_cut), HOUR);

        let tx = conn.transaction()?;
        // avg is weighted by the sample count so a partially-filled bucket does
        // not count the same as a full one when it rolls up a tier.
        tx.execute(
            "INSERT OR REPLACE INTO samples(res,ts,mid,avg,min,max,n)
               SELECT ?1, (ts/?1)*?1, mid,
                      sum(avg*n)/sum(n), min(min), max(max), sum(n)
               FROM samples WHERE res=?2 AND ts>=?3
               GROUP BY mid, ts/?1",
            params![FIVE_MIN, RAW, lo5],
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO samples(res,ts,mid,avg,min,max,n)
               SELECT ?1, (ts/?1)*?1, mid,
                      sum(avg*n)/sum(n), min(min), max(max), sum(n)
               FROM samples WHERE res=?2 AND ts>=?3
               GROUP BY mid, ts/?1",
            params![HOUR, FIVE_MIN, lo60],
        )?;

        tx.execute("DELETE FROM samples WHERE res=?1 AND ts<?2", params![RAW, raw_cut])?;
        tx.execute("DELETE FROM samples WHERE res=?1 AND ts<?2", params![FIVE_MIN, fm_cut])?;
        tx.execute("DELETE FROM samples WHERE res=?1 AND ts<?2", params![HOUR, hr_cut])?;

        // Metric names outlive their containers otherwise: a container that
        // existed for one tick would keep its series in the namespace for the
        // full 180-day window, so churn grows the file without bound.
        tx.execute(
            "DELETE FROM metric WHERE id NOT IN (SELECT DISTINCT mid FROM samples)",
            [],
        )?;

        tx.execute(
            "INSERT OR REPLACE INTO meta(k,v) VALUES('last_compact',?1)",
            params![now],
        )?;
        tx.commit()?;

        // Names may have been GC'd; drop the memo so a returning container
        // re-inserts rather than writing against a dangling id.
        self.ids.lock().unwrap().clear();
        Ok(())
    }
}

/// Best-effort `0600` on the database file. Belt-and-braces alongside the
/// unit's `UMask=0077`; a deployment that forgets it shouldn't leak.
#[cfg(unix)]
fn restrict(path: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        tracing::debug!("could not restrict {path}: {e}");
    }
}

#[cfg(not(unix))]
fn restrict(_path: &str) {}

/// Smallest bucket boundary >= `t`.
fn ceil_bucket(t: i64, width: i64) -> i64 {
    if t <= 0 {
        return 0;
    }
    // `i64::div_ceil` is still unstable; this is the same thing for t, width > 0.
    ((t + width - 1) / width) * width
}

/// Columnar series result (matches what the chart wants).
#[derive(Default, serde::Serialize)]
pub struct Series {
    pub t: Vec<i64>,
    pub avg: Vec<f64>,
    pub min: Vec<f64>,
    pub max: Vec<f64>,
}

/// Coarsest resolution that keeps a range under ~500 points.
pub fn pick_res(span_secs: i64) -> i64 {
    if span_secs <= 3600 {
        RAW
    } else if span_secs <= 86_400 {
        FIVE_MIN
    } else {
        HOUR
    }
}

/// Only the three tiers actually exist; anything else is a client error.
pub fn is_valid_res(res: i64) -> bool {
    res == RAW || res == FIVE_MIN || res == HOUR
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        let dir = std::env::temp_dir().join(format!("vitals-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(format!("{:?}.db", std::time::SystemTime::now()));
        Store::open(path.to_str().unwrap()).unwrap()
    }

    #[test]
    fn ceil_bucket_rounds_up_to_boundary() {
        assert_eq!(ceil_bucket(0, 300), 0);
        assert_eq!(ceil_bucket(1, 300), 300);
        assert_eq!(ceil_bucket(300, 300), 300);
        assert_eq!(ceil_bucket(301, 300), 600);
    }

    #[test]
    fn round_trips_samples() {
        let s = store();
        s.write(1_000, &[("host.cpu".into(), 42.0)]);
        let got = s.series("host.cpu", 0, 2_000, RAW, 100).unwrap();
        assert_eq!(got.t, vec![1_000]);
        assert_eq!(got.avg, vec![42.0]);
    }

    #[test]
    fn unknown_metric_is_empty_not_an_error() {
        let s = store();
        assert!(s.series("nope", 0, i64::MAX, RAW, 100).unwrap().t.is_empty());
    }

    #[test]
    fn non_finite_samples_are_skipped() {
        let s = store();
        s.write(10, &[("a".into(), f64::NAN), ("b".into(), 1.0)]);
        assert!(s.series("a", 0, 100, RAW, 10).unwrap().t.is_empty());
        assert_eq!(s.series("b", 0, 100, RAW, 10).unwrap().avg, vec![1.0]);
    }

    #[test]
    fn limit_caps_returned_points() {
        let s = store();
        for i in 0..50 {
            s.write(i * RAW as u64, &[("m".into(), i as f64)]);
        }
        assert_eq!(s.series("m", 0, i64::MAX, RAW, 10).unwrap().t.len(), 10);
    }

    /// The regression that matters: a 5-minute bucket must never be rewritten
    /// from a partial suffix after its early raw rows are pruned.
    #[test]
    fn rollup_is_not_corrupted_by_pruning() {
        let s = store();
        let bucket = 300i64; // first 5-min bucket, samples at t=0..285
        for i in 0..20 {
            s.write((bucket + i * RAW) as u64, &[("m".into(), 100.0)]);
        }
        // Compact while all raw rows are present: bucket should read 100.
        s.compact(bucket + 1_200);
        let rolled = s.series("m", 0, i64::MAX, FIVE_MIN, 10).unwrap();
        assert_eq!(rolled.avg, vec![100.0]);

        // Now add newer cheap data and compact far in the future, so the raw
        // rows behind that bucket fall outside retention and are pruned.
        s.write((bucket + RAW_RETENTION + 10_000) as u64, &[("m".into(), 1.0)]);
        s.compact(bucket + RAW_RETENTION + 20_000);

        let after = s.series("m", 0, bucket + 299, FIVE_MIN, 10).unwrap();
        assert_eq!(
            after.avg,
            vec![100.0],
            "rollup was recomputed from pruned/partial raw data"
        );
    }
}
