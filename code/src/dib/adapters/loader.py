from __future__ import annotations

import csv
import json
import tarfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

@dataclass(slots=True)
class DatasetValidationIssue:
    dataset: str
    path: str
    reason: str


@dataclass(slots=True)
class DatasetInventoryEntry:
    dataset: str
    role: str
    file_count: int
    device_count: int
    record_count: int
    files: list[str] = field(default_factory=list)


class DatasetLoader(ABC):
    """Base class for adapters that ingest manually staged real datasets."""

    name: str
    role: str

    @abstractmethod
    def validate_dataset(self) -> list[DatasetValidationIssue]:
        """Return a list of validation issues; empty list means the dataset is structurally sound."""
        raise NotImplementedError

    @abstractmethod
    def inventory(self) -> DatasetInventoryEntry:
        """Return per-dataset counts used for outputs/dataset_summary.csv and dataset_inventory.json."""
        raise NotImplementedError

    @staticmethod
    def load_csv(path: Path) -> list[dict[str, str]]:
        with path.open(newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))

    @staticmethod
    def load_pcap(path: Path) -> Path:
        """Return the validated PCAP path; parsing is delegated to dataset-specific extractors."""
        if path.suffix.lower() not in {".pcap", ".pcapng"}:
            raise ValueError(f"{path} is not a PCAP file")
        if not path.exists():
            raise FileNotFoundError(path)
        return path

    @staticmethod
    def load_mud_profile(path: Path) -> dict[str, object]:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"{path} does not contain a MUD profile object")
        return payload


class UNSWIoTrafficLoader(DatasetLoader):
    name = "unsw_iotraffic_2025"
    role = "Primary source of packet, flow, and protocol observations"

    def __init__(self, flows_dir: Path, protocols_dir: Path) -> None:
        self.flows_dir = flows_dir
        self.protocols_dir = protocols_dir

    def validate_dataset(self) -> list[DatasetValidationIssue]:
        issues: list[DatasetValidationIssue] = []
        if not self.flows_dir.exists():
            issues.append(DatasetValidationIssue(self.name, str(self.flows_dir), "flows directory missing"))
            return issues
        flow_files = sorted(self.flows_dir.glob("*_flows.csv"))
        if not flow_files:
            issues.append(DatasetValidationIssue(self.name, str(self.flows_dir), "no *_flows.csv files found"))
        for path in flow_files:
            with path.open(newline="", encoding="utf-8") as handle:
                reader = csv.DictReader(handle)
                missing = {"srcIp", "dstIp", "dstPort", "time"} - set(reader.fieldnames or [])
                if missing:
                    issues.append(
                        DatasetValidationIssue(
                            self.name, str(path), f"missing columns: {', '.join(sorted(missing))}"
                        )
                    )
        if not self.protocols_dir.exists():
            issues.append(
                DatasetValidationIssue(self.name, str(self.protocols_dir), "protocols directory missing")
            )
        return issues

    def inventory(self) -> DatasetInventoryEntry:
        flow_files = sorted(self.flows_dir.glob("*_flows.csv")) if self.flows_dir.exists() else []
        record_count = 0
        for path in flow_files:
            with path.open(newline="", encoding="utf-8") as handle:
                record_count += max(sum(1 for _ in handle) - 1, 0)
        return DatasetInventoryEntry(
            dataset=self.name,
            role=self.role,
            file_count=len(flow_files),
            device_count=len(flow_files),
            record_count=record_count,
            files=[path.name for path in flow_files],
        )


class MUDProfileLoader(DatasetLoader):
    name = "unsw_mud_profiles"
    role = "Ground truth for profile comparison"

    def __init__(self, profiles_dir: Path) -> None:
        self.profiles_dir = profiles_dir

    def validate_dataset(self) -> list[DatasetValidationIssue]:
        issues: list[DatasetValidationIssue] = []
        if not self.profiles_dir.exists():
            issues.append(DatasetValidationIssue(self.name, str(self.profiles_dir), "profiles directory missing"))
            return issues
        for path in sorted(self.profiles_dir.glob("*.json")):
            try:
                self.load_mud_profile(path)
            except (ValueError, json.JSONDecodeError) as exc:
                issues.append(DatasetValidationIssue(self.name, str(path), f"malformed profile: {exc}"))
        return issues

    def inventory(self) -> DatasetInventoryEntry:
        files = sorted(self.profiles_dir.glob("*.json")) if self.profiles_dir.exists() else []
        return DatasetInventoryEntry(
            dataset=self.name,
            role=self.role,
            file_count=len(files),
            device_count=len(files),
            record_count=len(files),
            files=[path.name for path in files],
        )


class MoniotrObservationLoader(DatasetLoader):
    name = "moniotr"
    role = "External-validity source of IoT flow observations"

    def __init__(self, input_dir: Path) -> None:
        self.input_dir = input_dir
        self._inventory: DatasetInventoryEntry | None = None
        self._issues: list[DatasetValidationIssue] | None = None

    def validate_dataset(self) -> list[DatasetValidationIssue]:
        self._ensure_loaded()
        return self._issues or []

    def inventory(self) -> DatasetInventoryEntry:
        self._ensure_loaded()
        assert self._inventory is not None
        return self._inventory

    def has_staged_files(self) -> bool:
        if not self.input_dir.exists():
            return False
        return any(
            path.is_file()
            and (
                path.suffix.lower() in {".csv", ".zip", ".tgz", ".tbz2"}
                or [suffix.lower() for suffix in path.suffixes][-2:]
                in ([".tar", ".gz"], [".tar", ".bz2"], [".tar", ".xz"])
            )
            for path in self.input_dir.rglob("*")
        )

    def _ensure_loaded(self) -> None:
        if self._inventory is not None and self._issues is not None:
            return
        files = [
            path
            for path in sorted(self.input_dir.rglob("*"))
            if path.is_file() and path.suffix.lower() in {".csv", ".zip", ".tar", ".tgz", ".tbz2", ".gz", ".bz2", ".xz"}
        ]
        self._issues = []
        for path in files:
            if path.suffix.lower() in {".tar", ".tgz", ".tbz2", ".gz", ".bz2", ".xz"}:
                try:
                    with tarfile.open(path, mode="r:*"):
                        pass
                except tarfile.TarError as exc:
                    self._issues.append(DatasetValidationIssue(self.name, str(path), f"unreadable archive: {exc}"))
        self._inventory = DatasetInventoryEntry(
            dataset=self.name,
            role=self.role,
            file_count=len(files),
            device_count=0,
            record_count=0,
            files=[path.name for path in files],
        )


def generate_dataset_report(loaders: list[DatasetLoader]) -> tuple[list[dict[str, object]], dict[str, object]]:
    """Build the dataset_summary.csv rows and dataset_inventory.json payload for Phase 1."""
    summary_rows: list[dict[str, object]] = []
    inventory_payload: dict[str, object] = {"datasets": []}
    for loader in loaders:
        issues = loader.validate_dataset()
        entry = loader.inventory()
        summary_rows.append(
            {
                "dataset": entry.dataset,
                "role": entry.role,
                "file_count": entry.file_count,
                "device_count": entry.device_count,
                "record_count": entry.record_count,
                "issue_count": len(issues),
                "valid": len(issues) == 0,
            }
        )
        inventory_payload["datasets"].append(
            {
                "dataset": entry.dataset,
                "role": entry.role,
                "file_count": entry.file_count,
                "device_count": entry.device_count,
                "record_count": entry.record_count,
                "files": entry.files,
                "issues": [
                    {"path": issue.path, "reason": issue.reason} for issue in issues
                ],
            }
        )
    return summary_rows, inventory_payload
