from flask import Flask, render_template, request, redirect, url_for, send_file, Response, jsonify, stream_with_context
from database import (
    init_db,
    get_all_targets,
    get_target_by_id,
    get_targets_paginated,
    get_status_counts,
    get_targets_by_status,
    get_nsfw_scan_results_for_paths,
    list_nsfw_flagged,
)
from scanner import process_csv, import_all_csv_files, scan_pending_targets
from file_ops import get_remote_content, recursive_zip_download
import file_ops as file_ops_module
import nsfw_batch_scan
from bs4 import BeautifulSoup
import io
import os
import mimetypes
import requests

app = Flask(__name__)

# 初始化数据库
init_db()

NSFW_THRESHOLD_DEFAULT = 0.7


def get_flag_emoji(country_code):
    """将国家代码转换为国旗 emoji"""
    if not country_code or len(country_code) != 2:
        return '🏳️'
    
    # 将国家代码转换为区域指示符号（Regional Indicator Symbols）
    # A-Z 对应 Unicode 0x1F1E6-0x1F1FF
    return ''.join(chr(0x1F1E6 + ord(c) - ord('A')) for c in country_code.upper())


def get_file_icon(filename):
    """根据文件扩展名返回对应的 emoji 图标"""
    ext = filename.split('.')[-1].lower() if '.' in filename else ''
    
    icon_map = {
        # 图片
        'jpg': '🖼️', 'jpeg': '🖼️', 'png': '🖼️', 'gif': '🖼️', 'bmp': '🖼️', 'svg': '🖼️', 'webp': '🖼️', 'ico': '🖼️', 'heic': '🖼️', 'heif': '🖼️',
        # 文档
        'pdf': '📕', 'doc': '📘', 'docx': '📘', 'xls': '📗', 'xlsx': '📗', 'ppt': '📙', 'pptx': '📙',
        # 文本
        'txt': '📝', 'log': '📋', 'md': '📝', 'json': '📋', 'xml': '📋', 'csv': '📊',
        # 代码
        'py': '🐍', 'js': '📜', 'html': '🌐', 'css': '🎨', 'java': '☕', 'c': '©️', 'cpp': '©️', 'sh': '🔧',
        # 压缩
        'zip': '📦', 'rar': '📦', 'tar': '📦', 'gz': '📦', '7z': '📦',
        # 音视频
        'mp3': '🎵', 'wav': '🎵', 'mp4': '🎬', 'mov': '🎬', 'avi': '🎬', 'mkv': '🎬',
    }
    
    return icon_map.get(ext, '📄')


def _normalize_mimetype(value):
    if not value:
        return None
    value = str(value).strip()
    if not value:
        return None
    return value.split(';', 1)[0].strip() or None


def _guess_mimetype(filename, header_mimetype):
    # Prefer a non-generic header mimetype (FnOS sometimes returns octet-stream).
    header = _normalize_mimetype(header_mimetype)
    if header and header != 'application/octet-stream':
        return header

    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    if ext == 'mov':
        return 'video/quicktime'
    if ext in ('heic', 'heif'):
        return 'image/heic'

    guessed, _ = mimetypes.guess_type(filename)
    return guessed or header or 'application/octet-stream'


def _convert_heic_to_jpeg_bytes(heic_bytes: bytes) -> bytes:
    from pillow_heif import register_heif_opener
    register_heif_opener()

    from PIL import Image

    with Image.open(io.BytesIO(heic_bytes)) as img:
        img = img.convert('RGB')
        out = io.BytesIO()
        img.save(out, format='JPEG', quality=92)
        return out.getvalue()


def _proxy_remote_video(base_url: str, remote_path: str, filename: str):
    target_url = file_ops_module._build_target_url(base_url, remote_path)
    headers = {}
    range_header = request.headers.get("Range")
    if range_header:
        headers["Range"] = range_header
    headers["Accept-Encoding"] = "identity"

    try:
        upstream = requests.get(
            target_url,
            headers=headers,
            verify=False,
            timeout=(10, 600),
            stream=True,
        )
    except Exception as e:
        return Response(f"Upstream request failed: {e}", status=502)

    if range_header and upstream.status_code == 416:
        try:
            upstream.close()
        except Exception:
            pass
        headers.pop("Range", None)
        try:
            upstream = requests.get(
                target_url,
                headers=headers,
                verify=False,
                timeout=(10, 600),
                stream=True,
            )
        except Exception as e:
            return Response(f"Upstream request failed: {e}", status=502)

    mimetype = _guess_mimetype(filename, upstream.headers.get("Content-Type"))

    def generate():
        try:
            for chunk in upstream.iter_content(chunk_size=256 * 1024):
                if chunk:
                    yield chunk
        finally:
            try:
                upstream.close()
            except Exception:
                pass

    resp = Response(stream_with_context(generate()), status=upstream.status_code, mimetype=mimetype)
    # Forward essential range headers when present.
    for header_name in ("Accept-Ranges", "Content-Range", "Content-Length"):
        header_value = upstream.headers.get(header_name)
        if header_value:
            resp.headers[header_name] = header_value
    if "Accept-Ranges" not in resp.headers:
        resp.headers["Accept-Ranges"] = "bytes"
    return resp


def _get_file_extension(name: str) -> str:
    name = (name or "").strip().lower()
    if not name or name.endswith("/"):
        return ""
    if "." not in name:
        return ""
    # Treat ".env" as an extension-like sensitive name.
    if name.startswith(".") and name.count(".") == 1:
        return name[1:]
    return name.rsplit(".", 1)[-1]


def _classify_sensitive_item(name: str, is_dir: bool):
    raw = (name or "").strip()
    if not raw:
        return None

    cleaned = raw[:-1] if raw.endswith("/") else raw
    lower = cleaned.lower()

    media_image_exts = {
        "jpg",
        "jpeg",
        "png",
        "gif",
        "bmp",
        "webp",
        "svg",
        "ico",
        "heic",
        "heif",
        "tif",
        "tiff",
    }
    media_video_exts = {"mov", "mp4", "mkv", "avi", "m4v", "webm", "mts", "m2ts"}
    archive_exts = {"zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz", "bak", "backup", "old"}
    db_exts = {"db", "sqlite", "sqlite3", "sql", "mdb", "accdb"}
    key_exts = {"pem", "key", "pfx", "p12", "ppk", "csr", "crt", "cer", "der", "kdbx"}

    sensitive_name_keywords = (
        ".env",
        "passwd",
        "shadow",
        "credentials",
        "token",
        "apikey",
        "api_key",
        "secret",
        "secrets",
        "id_rsa",
        "id_ed25519",
        "authorized_keys",
        "known_hosts",
        ".git-credentials",
        ".npmrc",
        ".pypirc",
    )

    ext = _get_file_extension(cleaned)

    if is_dir:
        sensitive_dir_names = {
            ".ssh",
            ".git",
            "secrets",
            "secret",
            "private",
            "backup",
            "backups",
            "keys",
            "key",
            # Common system roots that indicate full filesystem exposure.
            "etc",
            "root",
            "home",
            "var",
            "share",
        }
        if lower in sensitive_dir_names:
            if lower in {"etc", "root"}:
                return {"sensitive": True, "category": "System Dir", "severity": "critical", "name": cleaned, "is_dir": True}
            if lower in {"home", "share"}:
                return {"sensitive": True, "category": "User Data Dir", "severity": "high", "name": cleaned, "is_dir": True}
            return {"sensitive": True, "category": "Sensitive Dir", "severity": "high", "name": cleaned, "is_dir": True}
        return None

    if ext in key_exts or any(lower == k or k in lower for k in sensitive_name_keywords):
        return {"sensitive": True, "category": "Credentials/Secrets", "severity": "critical", "name": cleaned, "is_dir": False}
    if ext in db_exts:
        return {"sensitive": True, "category": "Database", "severity": "high", "name": cleaned, "is_dir": False}
    if ext in archive_exts:
        return {"sensitive": True, "category": "Archive/Backup", "severity": "high", "name": cleaned, "is_dir": False}
    if ext in media_image_exts:
        return {"sensitive": True, "category": "Image", "severity": "privacy", "name": cleaned, "is_dir": False}
    if ext in media_video_exts:
        return {"sensitive": True, "category": "Video", "severity": "privacy", "name": cleaned, "is_dir": False}

    return None


def _analyze_root_snapshot_risk(root_content: str, top_limit: int = 8):
    if not root_content:
        return {"critical": 0, "high": 0, "privacy": 0, "total": 0, "top": []}

    try:
        soup = BeautifulSoup(root_content, "html.parser")
        items = []
        for a in soup.find_all("a"):
            href = (a.get("href") or "").strip()
            text = (a.text or "").strip()
            if not text:
                continue
            if href in {"../", "./", "size=../../../../"} or text in {"../", "./"}:
                continue
            is_dir = href.endswith("/") or text.endswith("/")
            items.append((text, is_dir))
    except Exception:
        return {"critical": 0, "high": 0, "privacy": 0, "total": 0, "top": []}

    findings = []
    for name, is_dir in items:
        result = _classify_sensitive_item(name, is_dir)
        if result:
            findings.append(result)

    severity_weight = {"critical": 3, "high": 2, "privacy": 1}
    findings.sort(key=lambda x: (severity_weight.get(x.get("severity"), 0), x.get("name", "")), reverse=True)

    critical = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    privacy = sum(1 for f in findings if f.get("severity") == "privacy")

    top = [
        {
            "name": f.get("name"),
            "is_dir": bool(f.get("is_dir")),
            "category": f.get("category"),
            "severity": f.get("severity"),
        }
        for f in findings[: max(0, int(top_limit))]
    ]

    return {"critical": critical, "high": high, "privacy": privacy, "total": len(findings), "top": top}


def _normalize_remote_path(remote_path: str) -> str:
    remote_path = (remote_path or "").strip() or "/"
    if not remote_path.startswith("/"):
        remote_path = "/" + remote_path
    return remote_path


def _join_remote_path(parent: str, href: str) -> str:
    parent = _normalize_remote_path(parent)
    href = (href or "").strip()
    if not href:
        return parent
    if href.startswith("/"):
        return href
    if parent.endswith("/"):
        return parent + href.lstrip("/")
    return parent + "/" + href.lstrip("/")


# 注册为模板函数
# Register template helpers
app.jinja_env.globals.update(get_flag_emoji=get_flag_emoji)
app.jinja_env.globals.update(get_file_icon=get_file_icon)


@app.route('/')
def index():
    # 获取分页参数
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    status_filter = request.args.get('status', 'Vulnerable')  # 默认筛选漏洞
    search_query = request.args.get('search', '')
    dedup_ip_values = request.args.getlist('dedup_ip')
    dedup_ip = ('1' in dedup_ip_values) if dedup_ip_values else True
    
    # 获取分页数据
    pagination = get_targets_paginated(
        page=page,
        per_page=per_page,
        status_filter=status_filter if status_filter != 'all' else None,
        search_query=search_query if search_query else None,
        dedup_ip=dedup_ip
    )
    
    # 获取状态统计
    status_counts = get_status_counts(dedup_ip=dedup_ip)
    
    return render_template('index.html', 
                         targets=pagination['items'],
                         pagination=pagination,
                         status_counts=status_counts,
                         current_status=status_filter,
                         search_query=search_query,
                         dedup_ip=dedup_ip)


@app.route('/import', methods=['POST'])
def import_csv_route():
    if 'file' not in request.files:
        return redirect(url_for('index'))

    file = request.files['file']
    if file.filename == '':
        return redirect(url_for('index'))

    process_csv(file)
    return redirect(url_for('index'))


@app.route('/import_all', methods=['POST'])
def import_all_route():
    """一键导入所有 CSV 文件"""
    result = import_all_csv_files()
    return jsonify(result)

@app.route('/scan_pending', methods=['POST'])
def scan_pending_route():
    """扫描所有待检查的目标"""
    # 获取线程数配置
    data = request.get_json() or {}
    max_workers = data.get('max_workers', 32)
    
    # 验证线程数范围
    if not isinstance(max_workers, int) or max_workers < 1 or max_workers > 100:
        return jsonify({"success": False, "message": "线程数必须在 1-100 之间"})
    
    result = scan_pending_targets(max_workers=max_workers)
    return jsonify(result)


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """获取统计数据 API"""
    dedup_ip_values = request.args.getlist('dedup_ip')
    dedup_ip = ('1' in dedup_ip_values) if dedup_ip_values else True
    status_counts = get_status_counts(dedup_ip=dedup_ip)
    return jsonify(status_counts)


@app.route('/api/vulnerable_targets', methods=['GET'])
def get_vulnerable_targets():
    """Get all Vulnerable (red) targets for quick maintenance triage.

    Note: This only aggregates existing database records and does NOT crawl remote directories.
    """
    dedup_ip_values = request.args.getlist('dedup_ip')
    dedup_ip = ('1' in dedup_ip_values) if dedup_ip_values else True
    include_risk_values = request.args.getlist('include_risk')
    include_risk = ('1' in include_risk_values) if include_risk_values else True

    rows = get_targets_by_status('Vulnerable', dedup_ip=dedup_ip)
    items = []
    for r in rows:
        items.append(
            {
                "id": r["id"],
                "base_url": r["base_url"],
                "host": r["host"],
                "ip": r["ip"],
                "port": r["port"],
                "protocol": r["protocol"],
                "country": r["country"],
                "region": r["region"],
                "city": r["city"],
                "status": r["status"],
                "risk": _analyze_root_snapshot_risk(r["root_content"], top_limit=8) if include_risk else None,
            }
        )

    return jsonify({"success": True, "count": len(items), "dedup_ip": dedup_ip, "include_risk": include_risk, "items": items})


@app.route('/export/vulnerable.csv', methods=['GET'])
def export_vulnerable_csv():
    dedup_ip_values = request.args.getlist('dedup_ip')
    dedup_ip = ('1' in dedup_ip_values) if dedup_ip_values else True

    rows = get_targets_by_status('Vulnerable', dedup_ip=dedup_ip)

    import csv as _csv

    buffer = io.StringIO()
    buffer.write("\ufeff")  # UTF-8 BOM for Excel
    writer = _csv.writer(buffer)
    writer.writerow(["id", "base_url", "host", "ip", "port", "protocol", "country", "region", "city", "status"])
    for r in rows:
        writer.writerow(
            [
                r["id"],
                r["base_url"],
                r["host"],
                r["ip"],
                r["port"],
                r["protocol"],
                r["country"],
                r["region"],
                r["city"],
                r["status"],
            ]
        )

    resp = Response(buffer.getvalue(), mimetype="text/csv; charset=utf-8")
    resp.headers["Content-Disposition"] = "attachment; filename=vulnerable_targets.csv"
    return resp


@app.route('/api/nsfw/batch_scan/start', methods=['POST'])
def api_nsfw_batch_scan_start():
    data = request.get_json(silent=True) or {}

    def as_bool(value, default: bool) -> bool:
        if value is None:
            return bool(default)
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        text = str(value).strip().lower()
        if text in {"1", "true", "yes", "y", "on"}:
            return True
        if text in {"0", "false", "no", "n", "off", ""}:
            return False
        return bool(default)

    def as_int(value, default, min_v=None, max_v=None):
        try:
            n = int(value)
        except Exception:
            n = int(default)
        if min_v is not None:
            n = max(int(min_v), n)
        if max_v is not None:
            n = min(int(max_v), n)
        return n

    def as_float(value, default, min_v=None, max_v=None):
        try:
            f = float(value)
        except Exception:
            f = float(default)
        if min_v is not None:
            f = max(float(min_v), f)
        if max_v is not None:
            f = min(float(max_v), f)
        return f

    roots = data.get("roots")
    if not isinstance(roots, list):
        roots = None

    cfg = nsfw_batch_scan.BatchScanConfig(
        threshold=as_float(data.get("threshold"), NSFW_THRESHOLD_DEFAULT, 0.0, 1.0),
        dedup_ip=as_bool(data.get("dedup_ip"), True),
        include_images=as_bool(data.get("include_images"), True),
        include_videos=as_bool(data.get("include_videos"), True),
        roots=roots,
        max_targets=as_int(data.get("max_targets", 0), 0, 0, 50000),
        max_depth=as_int(data.get("max_depth", 20), 20, 0, 50),
        max_dirs_per_target=as_int(data.get("max_dirs_per_target", 5000), 5000, 1, 200000),
        max_files_per_target=as_int(data.get("max_files_per_target", 50000), 50000, 1, 2000000),
        max_bytes_image=as_int(data.get("max_bytes_image", 25 * 1024 * 1024), 25 * 1024 * 1024, 0, 2_000_000_000),
        max_bytes_video=as_int(data.get("max_bytes_video", 1024 * 1024 * 1024), 1024 * 1024 * 1024, 0, 5_000_000_000),
        target_workers=as_int(data.get("target_workers", 0), 0, 0, 256),
        score_workers=as_int(data.get("score_workers", 0), 0, 0, 64),
    )

    status = nsfw_batch_scan.default_scanner.start(cfg)
    return jsonify({"success": True, "status": status.__dict__})


@app.route('/api/nsfw/batch_scan/status', methods=['GET'])
def api_nsfw_batch_scan_status():
    status = nsfw_batch_scan.default_scanner.status()
    return jsonify({"success": True, "status": status.__dict__})


@app.route('/api/nsfw/batch_scan/stop', methods=['POST'])
def api_nsfw_batch_scan_stop():
    status = nsfw_batch_scan.default_scanner.stop()
    return jsonify({"success": True, "status": status.__dict__})


@app.route('/api/nsfw/flagged', methods=['GET'])
def api_nsfw_flagged():
    threshold = request.args.get("threshold", default=NSFW_THRESHOLD_DEFAULT, type=float)
    limit = request.args.get("limit", default=2000, type=int)
    if limit < 1:
        limit = 1
    if limit > 50000:
        limit = 50000

    rows = list_nsfw_flagged(threshold=threshold, limit=limit)
    items = []
    for r in rows:
        items.append(
            {
                "target_id": r["target_id"],
                "base_url": r["base_url"],
                "ip": r["ip"],
                "port": r["port"],
                "status": r["status"],
                "remote_path": r["remote_path"],
                "dir_path": r["dir_path"],
                "filename": r["filename"],
                "media_type": r["media_type"],
                "score": r["score"],
                "threshold": r["threshold"],
                "decision": r["decision"],
                "updated_at": r["updated_at"],
            }
        )

    return jsonify({"success": True, "count": len(items), "threshold": threshold, "items": items})


@app.route('/export/nsfw_flagged.csv', methods=['GET'])
def export_nsfw_flagged_csv():
    threshold = request.args.get("threshold", default=NSFW_THRESHOLD_DEFAULT, type=float)
    limit = request.args.get("limit", default=50000, type=int)
    if limit < 1:
        limit = 1
    if limit > 200000:
        limit = 200000

    rows = list_nsfw_flagged(threshold=threshold, limit=limit)

    import csv as _csv

    buffer = io.StringIO()
    buffer.write("\ufeff")  # UTF-8 BOM for Excel
    writer = _csv.writer(buffer)
    writer.writerow(
        [
            "target_id",
            "ip",
            "port",
            "base_url",
            "status",
            "dir_path",
            "filename",
            "remote_path",
            "media_type",
            "score",
            "threshold",
            "decision",
            "updated_at",
        ]
    )
    for r in rows:
        writer.writerow(
            [
                r["target_id"],
                r["ip"],
                r["port"],
                r["base_url"],
                r["status"],
                r["dir_path"],
                r["filename"],
                r["remote_path"],
                r["media_type"],
                r["score"],
                r["threshold"],
                r["decision"],
                r["updated_at"],
            ]
        )

    resp = Response(buffer.getvalue(), mimetype="text/csv; charset=utf-8")
    resp.headers["Content-Disposition"] = "attachment; filename=nsfw_flagged.csv"
    return resp

@app.route('/explore/<int:target_id>')
def explore(target_id):
    """文件浏览主视图"""
    target = get_target_by_id(target_id)
    if not target:
        return "Target not found", 404

    # 获取当前请求的路径，默认为根目录
    current_path = request.args.get('path', '/')
    base_url = target['base_url']

    # Fast-path for video streaming: avoid downloading the whole file into memory.
    action = request.args.get('action', 'view')
    filename = current_path.split('/')[-1]
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    if action == 'view' and ext in ('mov', 'mp4'):
        return _proxy_remote_video(base_url, current_path, filename)

    data = get_remote_content(base_url, current_path)

    if data['type'] == 'file':
        # 如果是文件，判断是预览还是下载
        action = request.args.get('action', 'view')

        # 获取文件名
        filename = current_path.split('/')[-1]
        ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        
        # 下载时添加 ID 前缀
        if action == 'download':
            download_filename = f"{target_id}_{filename}"
            return send_file(
                io.BytesIO(data['content']),
                mimetype='application/octet-stream',
                as_attachment=True,
                download_name=download_filename
            )

        # NSFW scoring is handled by the batch scan (main UI) to keep previews responsive.
        
        # 预览模式
        if ext in ('heic', 'heif'):
            try:
                jpeg_bytes = _convert_heic_to_jpeg_bytes(data['content'])
                return send_file(io.BytesIO(jpeg_bytes), mimetype='image/jpeg')
            except Exception:
                # Fall back to serving the original file if conversion isn't available.
                pass

        mimetype = _guess_mimetype(filename, data.get('mimetype'))

        return send_file(io.BytesIO(data['content']), mimetype=mimetype)

    elif data['type'] == 'directory':
        # 计算面包屑导航
        parts = [p for p in current_path.split('/') if p]
        breadcrumbs = []
        acc = ""
        for p in parts:
            acc += "/" + p
            breadcrumbs.append({'name': p, 'path': acc})

        # 检测 WebDAV 快捷目录
        webdav_shortcuts = []
        
        # 如果在 /share/home 目录，检测子目录
        if current_path.rstrip('/') == '/share/home' or current_path.rstrip('/').startswith('/share/home/'):
            # 获取 home 目录下的所有子目录
            if current_path.rstrip('/') == '/share/home':
                # 当前就在 home 目录，列出所有数字目录
                for item in data['items']:
                    if item['is_dir'] and item['name'].rstrip('/').isdigit():
                        user_id = item['name'].rstrip('/')
                        webdav_path = f"/share/home/{user_id}/webdav"
                        webdav_shortcuts.append({
                            'user_id': user_id,
                            'path': webdav_path
                        })
            else:
                # 在某个用户目录下，检测其他用户目录
                home_data = get_remote_content(base_url, '/share/home')
                if home_data['type'] == 'directory':
                    for item in home_data['items']:
                        if item['is_dir'] and item['name'].rstrip('/').isdigit():
                            user_id = item['name'].rstrip('/')
                            webdav_path = f"/share/home/{user_id}/webdav"
                            webdav_shortcuts.append({
                                'user_id': user_id,
                                'path': webdav_path
                            })

        file_remote_paths = []
        for item in data.get('items') or []:
            if item.get('is_dir'):
                continue
            remote_child = _join_remote_path(current_path.rstrip('/'), item.get('href') or item.get('name') or '')
            file_remote_paths.append(remote_child)

        nsfw_map = get_nsfw_scan_results_for_paths(target_id, file_remote_paths)
        for item in data.get('items') or []:
            if item.get('is_dir'):
                continue
            remote_child = _join_remote_path(current_path.rstrip('/'), item.get('href') or item.get('name') or '')
            row = nsfw_map.get(remote_child)
            if row is None:
                continue
            item['nsfw'] = {
                'score': row['score'],
                'threshold': row['threshold'],
                'decision': row['decision'],
            }

        return render_template('explorer.html',
                               target=target,
                               items=data['items'],
                               current_path=current_path,
                               breadcrumbs=breadcrumbs,
                               target_id=target_id,
                               webdav_shortcuts=webdav_shortcuts)
    else:
        return f"Error: {data.get('msg')}", 500


@app.route('/download_folder/<int:target_id>')
def download_folder_route(target_id):
    """触发递归下载"""
    target = get_target_by_id(target_id)
    path = request.args.get('path', '/')

    zip_stream = recursive_zip_download(target['base_url'], path)

    filename = f"download_{target['ip']}_{path.replace('/', '_')}.zip"
    return send_file(
        zip_stream,
        mimetype='application/zip',
        as_attachment=True,
        download_name=filename
    )


if __name__ == '__main__':
    app.run(debug=True, port=5000)
