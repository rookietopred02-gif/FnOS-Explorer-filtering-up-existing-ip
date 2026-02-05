import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


IMAGE_EXTS = {
    "jpg",
    "jpeg",
    "png",
    "gif",
    "bmp",
    "webp",
    "tif",
    "tiff",
}
HEIF_EXTS = {"heic", "heif"}
VIDEO_EXTS = {"mp4", "mov", "mkv", "avi", "m4v", "webm"}


@dataclass(frozen=True)
class ScoreResult:
    score: Optional[float]
    media_type: str
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"score": self.score, "media_type": self.media_type, "details": self.details}


def _get_ext(path: str) -> str:
    name = Path(path).name.lower()
    if "." not in name:
        return ""
    return name.rsplit(".", 1)[-1]


def _lazy_import_opennsfw2():
    import opennsfw2  # noqa: WPS433

    return opennsfw2


def score_image(image_path: str) -> float:
    opennsfw2 = _lazy_import_opennsfw2()
    score = opennsfw2.predict_image(image_path)
    return float(score)


def _convert_heif_to_jpeg(src_path: str, dst_path: str) -> str:
    heif_convert = shutil.which("heif-convert")
    if heif_convert:
        subprocess.run(
            [heif_convert, src_path, dst_path],
            check=True,
            capture_output=True,
            text=True,
        )
        return "heif-convert"

    try:
        from pillow_heif import register_heif_opener  # noqa: WPS433
        from PIL import Image  # noqa: WPS433
    except Exception as e:  # pragma: no cover
        raise RuntimeError(f"HEIC/HEIF conversion unavailable (install pillow-heif or heif-convert): {e}") from e

    register_heif_opener()
    with Image.open(src_path) as img:
        img = img.convert("RGB")
        img.save(dst_path, format="JPEG", quality=92)
    return "pillow-heif"


def _extract_video_frames_ffmpeg(
    video_path: str,
    out_dir: str,
    max_frames: int = 12,
    fps_interval_seconds: int = 10,
) -> list[str]:
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        raise RuntimeError("ffmpeg not found in PATH")

    # Use PNG to avoid MJPEG encoder issues on some ffmpeg builds.
    out_pattern = str(Path(out_dir) / "frame_%03d.png")

    cmd = [
        ffmpeg,
        "-hide_banner",
        "-loglevel",
        "error",
        "-y",
        "-i",
        video_path,
        "-vf",
        f"fps=1/{fps_interval_seconds}",
        "-frames:v",
        str(max_frames),
        out_pattern,
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError:
        # Some inputs/ffmpeg builds can fail with specific filter+encoder combos.
        # Fall back to extracting the first frame below.
        pass

    frames = sorted(str(p) for p in Path(out_dir).glob("frame_*.png"))
    if frames:
        return frames

    # Fallback: try extracting the first frame.
    cmd = [
        ffmpeg,
        "-hide_banner",
        "-loglevel",
        "error",
        "-y",
        "-i",
        video_path,
        "-frames:v",
        "1",
        out_pattern,
    ]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    return sorted(str(p) for p in Path(out_dir).glob("frame_*.png"))


def _score_video_with_details(video_path: str) -> tuple[float, int]:
    opennsfw2 = _lazy_import_opennsfw2()

    with tempfile.TemporaryDirectory(prefix="fnos_nsfw_frames_") as tmp_dir:
        frames = _extract_video_frames_ffmpeg(video_path, tmp_dir, max_frames=12, fps_interval_seconds=10)
        if not frames:
            return 0.0, 0

        scores = opennsfw2.predict_images(frames, batch_size=8)
        return (float(max(scores)) if scores else 0.0), len(frames)


def score_video(video_path: str) -> float:
    score, _ = _score_video_with_details(video_path)
    return score


def score_file(path: str) -> dict[str, Any]:
    ext = _get_ext(path)
    if ext in HEIF_EXTS:
        with tempfile.TemporaryDirectory(prefix="fnos_heif_") as tmp_dir:
            converted = str(Path(tmp_dir) / "converted.jpg")
            converter = _convert_heif_to_jpeg(path, converted)
            score = score_image(converted)
            return ScoreResult(
                score=score,
                media_type="image",
                details={"source_ext": ext, "converter": converter, "model": "opennsfw2"},
            ).to_dict()

    if ext in IMAGE_EXTS:
        score = score_image(path)
        return ScoreResult(
            score=score,
            media_type="image",
            details={"source_ext": ext, "model": "opennsfw2"},
        ).to_dict()

    if ext in VIDEO_EXTS:
        score, frame_count = _score_video_with_details(path)
        return ScoreResult(
            score=score,
            media_type="video",
            details={"source_ext": ext, "model": "opennsfw2", "aggregation": "max", "frame_count": frame_count},
        ).to_dict()

    return ScoreResult(
        score=None,
        media_type="unsupported",
        details={"source_ext": ext, "reason": "unsupported_extension"},
    ).to_dict()


def dumps_details(details: dict[str, Any]) -> str:
    return json.dumps(details, ensure_ascii=False, separators=(",", ":"))
