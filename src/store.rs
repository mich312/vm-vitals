//! Embedded time-series store (SQLite) with tiered rollups, so charts can show
//! real history cheaply. Each metric is sampled at raw resolution every tick;
//! a periodic compactor aggregates old raw points into 5-minute and 1-hour
//! buckets and prunes beyond the retention window. One file, a few MB.
//!
//! Resolutions (seconds): 15 (raw) → 300 (5-min) → 3600 (1-hour).
//! Retention: raw 48h · 5-min 30d · 1-hour 180d.

use std::sync::Mutex;

use rusqlite::{params, Connection};

const RAW: i64 = 15;
const FIVE_MIN: i64 = 300;
const HOUR: i64 = 3600;

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &str) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS samples(
                metric TEXT NOT NULL,
                res    INTEGER NOT NULL,
                ts     INTEGER NOT NULL,
                avg    REAL NOT NULL,
                min    REAL NOT NULL,
                max    REAL NOT NULL,
                PRIMARY KEY(metric, res, ts)
             ) WITHOUT ROWID;",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Append one raw sample per metric at `ts`.
    pub fn write(&self, ts: u64, points: &[(String, f64)]) {
        let mut conn = self.conn.lock().unwrap();
        let tx = match conn.transaction() {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("store write tx: {e}");
                return;
            }
        };
        {
            let mut st = tx
                .prepare_cached(
                    "INSERT OR REPLACE INTO samples(metric,res,ts,avg,min,max) VALUES(?1,?2,?3,?4,?4,?4)",
                )
                .unwrap();
            for (m, v) in points {
                let _ = st.execute(params![m, RAW, ts as i64, v]);
            }
        }
        let _ = tx.commit();
    }

    /// Points for a metric in [from,to] at a resolution. Returns (ts, avg, min, max).
    pub fn series(&self, metric: &str, from: i64, to: i64, res: i64) -> Series {
        let conn = self.conn.lock().unwrap();
        let mut out = Series::default();
        if let Ok(mut st) = conn.prepare_cached(
            "SELECT ts,avg,min,max FROM samples WHERE metric=?1 AND res=?2 AND ts>=?3 AND ts<=?4 ORDER BY ts",
        ) {
            let rows = st.query_map(params![metric, res, from, to], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, f64>(1)?, r.get::<_, f64>(2)?, r.get::<_, f64>(3)?))
            });
            if let Ok(rows) = rows {
                for row in rows.flatten() {
                    out.t.push(row.0);
                    out.avg.push(row.1);
                    out.min.push(row.2);
                    out.max.push(row.3);
                }
            }
        }
        out
    }

    /// Roll raw→5min→1hour (idempotent) and prune past retention.
    pub fn compact(&self, now: i64) {
        let conn = self.conn.lock().unwrap();
        let sql = format!(
            "INSERT OR REPLACE INTO samples(metric,res,ts,avg,min,max)
               SELECT metric,{FIVE_MIN},(ts/{FIVE_MIN})*{FIVE_MIN},avg(avg),min(min),max(max)
               FROM samples WHERE res={RAW} GROUP BY metric, ts/{FIVE_MIN};
             INSERT OR REPLACE INTO samples(metric,res,ts,avg,min,max)
               SELECT metric,{HOUR},(ts/{HOUR})*{HOUR},avg(avg),min(min),max(max)
               FROM samples WHERE res={FIVE_MIN} GROUP BY metric, ts/{HOUR};
             DELETE FROM samples WHERE res={RAW}      AND ts < {raw_cut};
             DELETE FROM samples WHERE res={FIVE_MIN} AND ts < {fm_cut};
             DELETE FROM samples WHERE res={HOUR}     AND ts < {hr_cut};",
            raw_cut = now - 172_800,     // 48h
            fm_cut = now - 2_592_000,    // 30d
            hr_cut = now - 15_552_000,   // 180d
        );
        if let Err(e) = conn.execute_batch(&sql) {
            tracing::warn!("store compact: {e}");
        }
    }
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
