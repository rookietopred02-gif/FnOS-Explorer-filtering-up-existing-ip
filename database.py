import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(__file__), 'vuln_targets.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # 创建 targets 表：存储扫描结果
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            base_url TEXT UNIQUE,  -- 例如 https://1.1.1.1:8080
            host TEXT,             -- 域名或 IP
            ip TEXT,
            port TEXT,
            protocol TEXT,         -- http 或 https
            country TEXT,          -- 国家代码，如 CN, US
            region TEXT,           -- 省份/州，如 广东省, California
            city TEXT,             -- 城市，如 Dongguan, Brea
            status TEXT,           -- 'Vulnerable', 'Safe', 'Pending', 'Error'
            root_content TEXT      -- 根目录的 HTML 响应快照
        )
    ''')
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS nsfw_scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            remote_path TEXT NOT NULL,
            dir_path TEXT NOT NULL,
            filename TEXT NOT NULL,
            media_type TEXT,
            score REAL,
            threshold REAL,
            decision TEXT,          -- 'nsfw' | 'clean' | 'error' | 'unsupported'
            model TEXT,
            details_json TEXT,
            error TEXT,
            scanned_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(target_id, remote_path)
        )
        """
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_nsfw_scan_results_score ON nsfw_scan_results(score)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_nsfw_scan_results_target ON nsfw_scan_results(target_id)"
    )
    conn.commit()
    conn.close()

def add_target(base_url, host, ip, port, protocol, country, region, city, status, root_content):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT OR REPLACE INTO targets (base_url, host, ip, port, protocol, country, region, city, status, root_content)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (base_url, host, ip, port, protocol, country, region, city, status, root_content))
        conn.commit()
    except Exception as e:
        print(f"DB Error: {e}")
    finally:
        conn.close()

def add_target_batch(targets_list):
    """批量添加目标，去重（已存在的记录保持原状态）"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        # 使用 INSERT OR IGNORE 会跳过已存在的记录，保持原状态
        cursor.executemany('''
            INSERT OR IGNORE INTO targets (base_url, host, ip, port, protocol, country, region, city, status, root_content)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', targets_list)
        conn.commit()
        return cursor.rowcount
    except Exception as e:
        print(f"DB Batch Error: {e}")
        return 0
    finally:
        conn.close()

def get_pending_targets():
    """获取所有待检查的目标"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM targets WHERE status = 'Pending'")
    rows = cursor.fetchall()
    conn.close()
    return rows

def update_target_status(target_id, status, root_content):
    """更新目标状态"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            UPDATE targets SET status = ?, root_content = ? WHERE id = ?
        ''', (status, root_content, target_id))
        conn.commit()
    except Exception as e:
        print(f"DB Update Error: {e}")
    finally:
        conn.close()

def get_all_targets():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM targets ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_targets_paginated(page=1, per_page=50, status_filter=None, search_query=None, dedup_ip=False):
    """分页获取目标，支持筛选和搜索"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # 构建查询条件
    conditions = []
    params = []
    
    if status_filter and status_filter != 'all':
        conditions.append("status = ?")
        params.append(status_filter)
    
    if search_query:
        conditions.append("(ip LIKE ? OR host LIKE ? OR base_url LIKE ? OR city LIKE ?)")
        params.extend([f"%{search_query}%", f"%{search_query}%", f"%{search_query}%", f"%{search_query}%"])
    
    where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""
    

    # 获取总数（根据是否去重计算）
    if dedup_ip:
        # 去重规则：同一个 ip 只显示一条（取该 ip 的最新记录：MAX(id)）
        # 对于 ip 为空/NULL 的记录，不做去重（原样全部显示）
        count_query = f'''
        WITH filtered AS (
            SELECT * FROM targets{where_clause}
        ),
        deduped AS (
            SELECT MAX(id) AS id FROM filtered
            WHERE ip IS NOT NULL AND TRIM(ip) <> ''
            GROUP BY ip
            UNION ALL
            SELECT id FROM filtered
            WHERE ip IS NULL OR TRIM(ip) = ''
        )
        SELECT COUNT(*) AS total FROM deduped
        '''
        cursor.execute(count_query, params)
        total = cursor.fetchone()['total']

        offset = (page - 1) * per_page
        data_query = f'''
        WITH filtered AS (
            SELECT * FROM targets{where_clause}
        ),
        deduped AS (
            SELECT MAX(id) AS id FROM filtered
            WHERE ip IS NOT NULL AND TRIM(ip) <> ''
            GROUP BY ip
            UNION ALL
            SELECT id FROM filtered
            WHERE ip IS NULL OR TRIM(ip) = ''
        )
        SELECT t.* FROM targets t
        JOIN deduped d ON t.id = d.id
        ORDER BY t.id DESC
        LIMIT ? OFFSET ?
        '''
        cursor.execute(data_query, params + [per_page, offset])
        rows = cursor.fetchall()
    else:
        count_query = f"SELECT COUNT(*) as total FROM targets{where_clause}"
        cursor.execute(count_query, params)
        total = cursor.fetchone()['total']

        offset = (page - 1) * per_page
        data_query = f"SELECT * FROM targets{where_clause} ORDER BY id DESC LIMIT ? OFFSET ?"
        cursor.execute(data_query, params + [per_page, offset])
        rows = cursor.fetchall()

    conn.close()

    return {
        'items': rows,
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': (total + per_page - 1) // per_page
    }


def get_status_counts(dedup_ip: bool = False):
    """获取各状态的数量统计。

    当 dedup_ip=True 时，统计口径与列表去重显示一致：同一个 ip 只计入一条（取该 ip 的最新记录：MAX(id)）。
    对于 ip 为空/NULL 的记录，不做去重（原样计数）。
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    if dedup_ip:
        cursor.execute("""
            WITH deduped AS (
                SELECT MAX(id) AS id
                FROM targets
                WHERE ip IS NOT NULL AND TRIM(ip) <> ''
                GROUP BY ip
                UNION ALL
                SELECT id
                FROM targets
                WHERE ip IS NULL OR TRIM(ip) = ''
            )
            SELECT t.status, COUNT(*) AS count
            FROM targets t
            JOIN deduped d ON t.id = d.id
            GROUP BY t.status
        """)
    else:
        cursor.execute("""
            SELECT status, COUNT(*) as count 
            FROM targets 
            GROUP BY status
        """)

    rows = cursor.fetchall()
    conn.close()

    counts = {'all': 0}
    for status, cnt in rows:
        counts[status] = cnt
        counts['all'] += cnt

    return counts

def get_target_by_id(tid):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM targets WHERE id = ?", (tid,))
    row = cursor.fetchone()
    conn.close()
    return row


def get_targets_by_status(status: str, dedup_ip: bool = False):
    """Get all targets filtered by status.

    When dedup_ip=True, same dedup semantics as the main list: one row per IP (latest id).
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if dedup_ip:
        cursor.execute(
            """
            WITH filtered AS (
                SELECT * FROM targets
                WHERE status = ?
            ),
            deduped AS (
                SELECT MAX(id) AS id
                FROM filtered
                WHERE ip IS NOT NULL AND TRIM(ip) <> ''
                GROUP BY ip
                UNION ALL
                SELECT id
                FROM filtered
                WHERE ip IS NULL OR TRIM(ip) = ''
            )
            SELECT t.*
            FROM targets t
            JOIN deduped d ON t.id = d.id
            ORDER BY t.id DESC
            """,
            (status,),
        )
    else:
        cursor.execute("SELECT * FROM targets WHERE status = ? ORDER BY id DESC", (status,))

    rows = cursor.fetchall()
    conn.close()
    return rows


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def upsert_nsfw_scan_result(
    *,
    target_id: int,
    remote_path: str,
    dir_path: str,
    filename: str,
    media_type: str | None,
    score: float | None,
    threshold: float | None,
    decision: str,
    model: str | None,
    details_json: str | None,
    error: str | None,
):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    now = _utc_now_iso()
    try:
        cursor.execute(
            """
            INSERT INTO nsfw_scan_results
              (target_id, remote_path, dir_path, filename, media_type, score, threshold, decision, model, details_json, error, scanned_at, updated_at)
            VALUES
              (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(target_id, remote_path) DO UPDATE SET
              dir_path=excluded.dir_path,
              filename=excluded.filename,
              media_type=excluded.media_type,
              score=excluded.score,
              threshold=excluded.threshold,
              decision=excluded.decision,
              model=excluded.model,
              details_json=excluded.details_json,
              error=excluded.error,
              updated_at=excluded.updated_at
            """,
            (
                target_id,
                remote_path,
                dir_path,
                filename,
                media_type,
                score,
                threshold,
                decision,
                model,
                details_json,
                error,
                now,
                now,
            ),
        )
        conn.commit()
    except Exception as e:
        print(f"DB upsert nsfw_scan_results error: {e}")
    finally:
        conn.close()


def get_nsfw_scan_result(target_id: int, remote_path: str):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM nsfw_scan_results WHERE target_id = ? AND remote_path = ?",
        (target_id, remote_path),
    )
    row = cursor.fetchone()
    conn.close()
    return row


def get_nsfw_scan_results_for_paths(target_id: int, remote_paths: list[str]):
    if not remote_paths:
        return {}

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    results: dict[str, sqlite3.Row] = {}
    try:
        chunk_size = 900
        for start in range(0, len(remote_paths), chunk_size):
            chunk = remote_paths[start : start + chunk_size]
            placeholders = ",".join("?" for _ in chunk)
            cursor.execute(
                f"""
                SELECT * FROM nsfw_scan_results
                WHERE target_id = ? AND remote_path IN ({placeholders})
                """,
                [target_id, *chunk],
            )
            for row in cursor.fetchall():
                results[row["remote_path"]] = row
    finally:
        conn.close()

    return results


def list_nsfw_flagged(*, threshold: float = 0.7, limit: int = 2000):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT
          n.*,
          t.base_url AS base_url,
          t.ip AS ip,
          t.port AS port,
          t.host AS host,
          t.region AS region,
          t.city AS city,
          t.status AS status
        FROM nsfw_scan_results n
        JOIN targets t ON t.id = n.target_id
        WHERE n.score IS NOT NULL AND n.score >= ?
        ORDER BY n.score DESC, n.updated_at DESC
        LIMIT ?
        """,
        (threshold, limit),
    )
    rows = cursor.fetchall()
    conn.close()
    return rows
