"""Command-line converter from StepMania SSC files to SM files.

Place this script anywhere (for example, in
``C:\\Users\\Malloy\\Downloads\\Tech-Bit Adventures``) and point it at a
folder that contains ``.ssc`` files. It will convert every SSC it finds in that
folder and its subfolders into the SM format, writing the results alongside the
original files. A detailed log is printed to the console and saved under a
``logs`` directory next to the script.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import logging
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

LOGGER = logging.getLogger(__name__)


@dataclass
class SscHeader:
    version: Optional[str] = None
    title: Optional[str] = None
    subtitle: Optional[str] = None
    artist: Optional[str] = None
    title_translit: Optional[str] = None
    subtitle_translit: Optional[str] = None
    artist_translit: Optional[str] = None
    genre: Optional[str] = None
    credit: Optional[str] = None
    banner: Optional[str] = None
    background: Optional[str] = None
    lyricspath: Optional[str] = None
    cd_title: Optional[str] = None
    music: Optional[str] = None
    offset: Optional[str] = None
    sample_start: Optional[str] = None
    sample_length: Optional[str] = None
    selectable: Optional[str] = None
    display_bpm: Optional[str] = None
    bpms: Optional[str] = None
    stops: Optional[str] = None
    delays: Optional[str] = None
    warps: Optional[str] = None
    time_signatures: Optional[str] = None
    tick_counts: Optional[str] = None
    combos: Optional[str] = None
    speeds: Optional[str] = None
    scrolls: Optional[str] = None
    fakes: Optional[str] = None
    labels: Optional[str] = None
    bg_changes: Optional[str] = None
    keysounds: Optional[str] = None
    attacks: Optional[str] = None
    origin: Optional[str] = None
    preview_vid: Optional[str] = None
    jacket: Optional[str] = None
    cd_image: Optional[str] = None
    disc_image: Optional[str] = None


@dataclass
class SscNoteData:
    step_style: Optional[str] = None
    chart_name: Optional[str] = None
    description: Optional[str] = None
    chart_style: Optional[str] = None
    difficulty: Optional[str] = None
    meter: Optional[str] = None
    radar_values: Optional[str] = None
    notes: Optional[str] = None
    bpms: Optional[str] = None
    stops: Optional[str] = None
    display_bpm: Optional[str] = None


@dataclass
class SscModel:
    header: SscHeader
    note_data: List[SscNoteData]


@dataclass
class SmHeader:
    title: str
    subtitle: Optional[str]
    artist: Optional[str]
    title_translit: Optional[str]
    subtitle_translit: Optional[str]
    artist_translit: Optional[str]
    genre: Optional[str]
    credit: Optional[str]
    banner: Optional[str]
    background: Optional[str]
    lyricspath: Optional[str]
    cd_title: Optional[str]
    origin: Optional[str]
    preview_vid: Optional[str]
    jacket: Optional[str]
    cd_image: Optional[str]
    disc_image: Optional[str]
    music: Optional[str]
    offset: Optional[str]
    sample_start: Optional[str]
    sample_length: Optional[str]
    selectable: Optional[str]
    display_bpm: Optional[str]
    bpms: Optional[str]
    stops: Optional[str]
    delays: Optional[str]
    warps: Optional[str]
    time_signatures: Optional[str]
    tick_counts: Optional[str]
    combos: Optional[str]
    speeds: Optional[str]
    scrolls: Optional[str]
    fakes: Optional[str]
    labels: Optional[str]
    bg_changes: Optional[str]
    keysounds: Optional[str]
    attacks: Optional[str]


@dataclass
class SmNoteData:
    step_style: str
    description: str
    difficulty: str
    meter: str
    radar_values: str
    notes: str


@dataclass
class SmModel:
    header: SmHeader
    note_data: List[SmNoteData]

    def to_file_contents(self) -> str:
        sections: List[str] = []

        def add_field(key: str, value: Optional[str]) -> None:
            sections.append(f"#{key}:{'' if value is None else value};\n")

        add_field("TITLE", self.header.title)
        add_field("SUBTITLE", self.header.subtitle)
        add_field("ARTIST", self.header.artist)
        add_field("TITLETRANSLIT", self.header.title_translit)
        add_field("SUBTITLETRANSLIT", self.header.subtitle_translit)
        add_field("ARTISTTRANSLIT", self.header.artist_translit)
        add_field("GENRE", self.header.genre)
        add_field("CREDIT", self.header.credit)
        add_field("BANNER", self.header.banner)
        add_field("BACKGROUND", self.header.background)
        add_field("LYRICSPATH", self.header.lyricspath)
        add_field("CDTITLE", self.header.cd_title)
        add_field("ORIGIN", self.header.origin)
        add_field("PREVIEWVID", self.header.preview_vid)
        add_field("JACKET", self.header.jacket)
        add_field("CDIMAGE", self.header.cd_image)
        add_field("DISCIMAGE", self.header.disc_image)
        add_field("MUSIC", self.header.music)
        add_field("OFFSET", self.header.offset)
        add_field("SAMPLESTART", self.header.sample_start)
        add_field("SAMPLELENGTH", self.header.sample_length)
        add_field("SELECTABLE", self.header.selectable)
        add_field("DISPLAYBPM", self.header.display_bpm)
        add_field("BPMS", self.header.bpms)
        add_field("STOPS", self.header.stops)
        add_field("DELAYS", self.header.delays)
        add_field("WARPS", self.header.warps)
        add_field("TIMESIGNATURES", self.header.time_signatures)
        add_field("TICKCOUNTS", self.header.tick_counts)
        add_field("COMBOS", self.header.combos)
        add_field("SPEEDS", self.header.speeds)
        add_field("SCROLLS", self.header.scrolls)
        add_field("FAKES", self.header.fakes)
        add_field("LABELS", self.header.labels)
        add_field("BGCHANGES", self.header.bg_changes)
        add_field("KEYSOUNDS", self.header.keysounds)
        add_field("ATTACKS", self.header.attacks)

        for nd in self.note_data:
            sections.append("\n")
            description = nd.description if nd.description is not None else ""
            sections.append(f"//---------------{nd.step_style} - {description}----------------\n")
            sections.append("#NOTES:\n")
            sections.append(f"     {nd.step_style}:\n")
            sections.append(f"     {description}:\n")
            sections.append(f"     {nd.difficulty}:\n")
            sections.append(f"     {nd.meter}:\n")
            sections.append(f"     {nd.radar_values}:\n")
            notes_text = nd.notes or ""
            if not notes_text.endswith("\n"):
                notes_text += "\n"
            sections.append(notes_text)
            sections.append(";\n")

        return "".join(sections)


def _clean_comments(raw_text: str) -> str:
    return re.sub(r"//.*", "", raw_text)


def _parse_ssc_fields(ssc_contents: str) -> List[Tuple[str, str]]:
    clean_text = _clean_comments(ssc_contents.replace("\r\n", "\n").replace("\r", "\n"))
    pattern = re.compile(r"#([A-Za-z0-9]+):(.*?);", re.DOTALL)
    fields: List[Tuple[str, str]] = []
    for match in pattern.finditer(clean_text):
        key = match.group(1).upper()
        value = match.group(2)
        if value.startswith("\n"):
            value = value[1:]
        fields.append((key, value))
    LOGGER.debug("Parsed %d fields from SSC", len(fields))
    return fields


def parse_ssc_model(ssc_contents: str) -> SscModel:
    fields = _parse_ssc_fields(ssc_contents)
    header_fields: Dict[str, str] = {}
    note_blocks: List[Dict[str, str]] = []
    current_note: Optional[Dict[str, str]] = None

    for key, value in fields:
        if key == "NOTEDATA":
            if current_note is not None:
                note_blocks.append(current_note)
            current_note = {}
            LOGGER.debug("Starting new NOTEDATA block")
            continue
        if current_note is None:
            header_fields[key] = value
        else:
            current_note[key] = value

    if current_note is not None:
        note_blocks.append(current_note)

    header = SscHeader(
        version=header_fields.get("VERSION"),
        title=header_fields.get("TITLE"),
        subtitle=header_fields.get("SUBTITLE"),
        artist=header_fields.get("ARTIST"),
        title_translit=header_fields.get("TITLETRANSLIT"),
        subtitle_translit=header_fields.get("SUBTITLETRANSLIT"),
        artist_translit=header_fields.get("ARTISTTRANSLIT"),
        genre=header_fields.get("GENRE"),
        credit=header_fields.get("CREDIT"),
        banner=header_fields.get("BANNER"),
        background=header_fields.get("BACKGROUND"),
        lyricspath=header_fields.get("LYRICSPATH"),
        cd_title=header_fields.get("CDTITLE"),
        music=header_fields.get("MUSIC"),
        offset=header_fields.get("OFFSET"),
        sample_start=header_fields.get("SAMPLESTART"),
        sample_length=header_fields.get("SAMPLELENGTH"),
        selectable=header_fields.get("SELECTABLE"),
        display_bpm=header_fields.get("DISPLAYBPM"),
        bpms=header_fields.get("BPMS"),
        stops=header_fields.get("STOPS"),
        delays=header_fields.get("DELAYS"),
        warps=header_fields.get("WARPS"),
        time_signatures=header_fields.get("TIMESIGNATURES"),
        tick_counts=header_fields.get("TICKCOUNTS"),
        combos=header_fields.get("COMBOS"),
        speeds=header_fields.get("SPEEDS"),
        scrolls=header_fields.get("SCROLLS"),
        fakes=header_fields.get("FAKES"),
        labels=header_fields.get("LABELS"),
        bg_changes=header_fields.get("BGCHANGES"),
        keysounds=header_fields.get("KEYSOUNDS"),
        attacks=header_fields.get("ATTACKS"),
        origin=header_fields.get("ORIGIN"),
        preview_vid=header_fields.get("PREVIEWVID"),
        jacket=header_fields.get("JACKET"),
        cd_image=header_fields.get("CDIMAGE"),
        disc_image=header_fields.get("DISCIMAGE"),
    )

    note_data = [
        SscNoteData(
            step_style=block.get("STEPSTYPE"),
            chart_name=block.get("CHARTNAME"),
            description=block.get("DESCRIPTION"),
            chart_style=block.get("CHARTSTYLE"),
            difficulty=block.get("DIFFICULTY"),
            meter=block.get("METER"),
            radar_values=block.get("RADARVALUES"),
            notes=block.get("NOTES"),
            bpms=block.get("BPMS"),
            stops=block.get("STOPS"),
            display_bpm=block.get("DISPLAYBPM"),
        )
        for block in note_blocks
    ]

    return SscModel(header=header, note_data=note_data)
def _sanitize_filename(name: str) -> str:
    return re.sub(r'[<>:"/\\|?*]', "_", name)


def convert_ssc_contents(ssc_contents: str, output_base_name: Optional[str] = None) -> Dict[str, str]:
    model = parse_ssc_model(ssc_contents)
    base_title = model.header.title or "Untitled"

    valid_notes: List[SscNoteData] = []
    for nd in model.note_data:
        if nd.step_style and nd.difficulty and nd.meter and nd.notes:
            valid_notes.append(nd)
        else:
            LOGGER.warning("Skipping NOTEDATA block missing required fields: %s", nd)

    if not valid_notes:
        raise ValueError("No complete NOTEDATA blocks were found in the SSC file.")

    header = SmHeader(
        title=base_title,
        subtitle=model.header.subtitle,
        artist=model.header.artist,
        title_translit=model.header.title_translit,
        subtitle_translit=model.header.subtitle_translit,
        artist_translit=model.header.artist_translit,
        genre=model.header.genre,
        credit=model.header.credit,
        banner=model.header.banner,
        background=model.header.background,
        lyricspath=model.header.lyricspath,
        cd_title=model.header.cd_title,
        origin=model.header.origin,
        preview_vid=model.header.preview_vid,
        jacket=model.header.jacket,
        cd_image=model.header.cd_image,
        disc_image=model.header.disc_image,
        music=model.header.music,
        offset=model.header.offset,
        sample_start=model.header.sample_start,
        sample_length=model.header.sample_length,
        selectable=model.header.selectable,
        display_bpm=model.header.display_bpm,
        bpms=model.header.bpms,
        stops=model.header.stops,
        delays=model.header.delays,
        warps=model.header.warps,
        time_signatures=model.header.time_signatures,
        tick_counts=model.header.tick_counts,
        combos=model.header.combos,
        speeds=model.header.speeds,
        scrolls=model.header.scrolls,
        fakes=model.header.fakes,
        labels=model.header.labels,
        bg_changes=model.header.bg_changes,
        keysounds=model.header.keysounds,
        attacks=model.header.attacks,
    )

    sm_notes = [
        SmNoteData(
            step_style=nd.step_style,
            description=nd.description or nd.chart_name or "",
            difficulty=nd.difficulty,
            meter=nd.meter,
            radar_values=nd.radar_values or "0,0,0,0,0",
            notes=nd.notes or "",
        )
        for nd in valid_notes
    ]

    sm_model = SmModel(header=header, note_data=sm_notes)
    base_name = output_base_name or sm_model.header.title
    name = f"{base_name}.sm"
    safe_name = _sanitize_filename(name)
    LOGGER.debug("Prepared SM file %s", safe_name)
    return {safe_name: sm_model.to_file_contents()}


def find_ssc_files(root: Path) -> List[Path]:
    return sorted(path for path in root.rglob("*.ssc") if path.is_file())


def convert_directory(root: Path, log_file: Path) -> None:
    ssc_files = find_ssc_files(root)
    LOGGER.info("Found %d SSC files under %s", len(ssc_files), root)
    if not ssc_files:
        return

    for ssc_path in ssc_files:
        LOGGER.info("Processing %s", ssc_path)
        try:
            contents = ssc_path.read_text(encoding="utf-8", errors="replace")
            results = convert_ssc_contents(contents, output_base_name=ssc_path.stem)
            for sm_name, sm_contents in results.items():
                destination = ssc_path.with_name(sm_name)
                destination.write_text(sm_contents, encoding="utf-8")
                LOGGER.info("Wrote %s", destination)
        except Exception:
            LOGGER.exception("Failed to convert %s", ssc_path)

    LOGGER.info("Conversion complete. Log file located at %s", log_file)


def setup_logging(log_dir: Path) -> Path:
    log_dir.mkdir(parents=True, exist_ok=True)
    timestamp = _dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"ssc_to_sm_{timestamp}.log"
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.DEBUG)

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.handlers.clear()
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

    LOGGER.debug("Logging initialized; writing to %s", log_file)
    return log_file


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Convert StepMania SSC files to SM files.")
    parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        help="Path to a folder containing SSC files (conversion includes subfolders).",
    )
    parser.add_argument(
        "--logs-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "logs",
        help="Directory to store conversion logs (default: alongside the script).",
    )
    args = parser.parse_args(argv)

    log_file = setup_logging(args.logs_dir)
    LOGGER.info("Log file: %s", log_file)

    if args.path is None:
        try:
            user_input = input("Enter the path to the folder containing SSC files: ").strip()
        except EOFError:
            LOGGER.error("No path provided and interactive input is unavailable.")
            return 1
        if not user_input:
            LOGGER.error("No path provided.")
            return 1
        args.path = Path(user_input.strip("\"'"))

    if not args.path.exists():
        LOGGER.error("Provided path does not exist: %s", args.path)
        return 1
    if not args.path.is_dir():
        LOGGER.error("Provided path is not a directory: %s", args.path)
        return 1

    convert_directory(args.path, log_file)
    return 0


if __name__ == "__main__":
    sys.exit(main())
