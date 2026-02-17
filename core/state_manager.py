"""
core/state_manager.py - JSON Persistence for Audit State

Handles loading, saving, and merging of AuditState to/from a local
audit_state.json file. Thread-safe writes via a file lock pattern.
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.schema import AuditState, ConfirmedFinding, RejectedFinding

logger = logging.getLogger(__name__)

DEFAULT_STATE_FILE = "audit_state.json"


# ---------------------------------------------------------------------------
# State Manager
# ---------------------------------------------------------------------------


class StateManager:
    """
    Manages persistent storage of AuditState as a JSON file.
    Provides atomic writes to prevent corruption on crash.
    """

    def __init__(self, state_file: str = DEFAULT_STATE_FILE):
        self.state_file = Path(state_file)
        self._lock_file = Path(f"{state_file}.lock")

    # ------------------------------------------------------------------ I/O

    def load(self) -> Optional[AuditState]:
        """
        Load AuditState from the JSON file.
        Returns None if the file doesn't exist or is corrupt.
        """
        if not self.state_file.exists():
            logger.debug("State file not found at %s", self.state_file)
            return None

        try:
            raw = self.state_file.read_text(encoding="utf-8")
            data = json.loads(raw)
            state = AuditState.model_validate(data)
            logger.info(
                "Loaded audit state: session=%s, %d files pending",
                state.session_id,
                len(state.pending_files),
            )
            return state
        except json.JSONDecodeError as e:
            logger.error("Corrupt state file at %s: %s", self.state_file, e)
            self._backup_corrupt_file()
            return None
        except Exception as e:
            logger.error("Failed to load state: %s", e)
            return None

    def save(self, state: AuditState) -> bool:
        """
        Atomically write AuditState to disk using a temp-file + rename pattern.
        Returns True on success, False on failure.
        """
        try:
            data = state.model_dump(mode="json")
            json_str = json.dumps(data, indent=2, ensure_ascii=False)

            # Write to a temp file in the same directory, then rename
            dir_ = self.state_file.parent
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".tmp",
                dir=dir_,
                delete=False,
                encoding="utf-8",
            ) as tmp:
                tmp.write(json_str)
                tmp_path = tmp.name

            # Atomic rename
            shutil.move(tmp_path, str(self.state_file))
            logger.debug("State saved to %s", self.state_file)
            return True

        except Exception as e:
            logger.error("Failed to save state: %s", e)
            try:
                os.unlink(tmp_path)  # type: ignore[possibly-undefined]
            except Exception:
                pass
            return False

    def save_checkpoint(self, state: AuditState, label: str = "") -> None:
        """Save a timestamped checkpoint copy (non-atomic, best-effort)."""
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        suffix = f"_{label}" if label else ""
        checkpoint_path = (
            self.state_file.parent / f"audit_state_{ts}{suffix}.checkpoint.json"
        )
        try:
            data = state.model_dump(mode="json")
            checkpoint_path.write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            logger.info("Checkpoint saved: %s", checkpoint_path)
        except Exception as e:
            logger.warning("Checkpoint save failed: %s", e)

    def _backup_corrupt_file(self) -> None:
        """Move a corrupt state file aside so we can start fresh."""
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup = self.state_file.with_suffix(f".corrupt.{ts}.json")
        try:
            shutil.move(str(self.state_file), str(backup))
            logger.warning("Corrupt state file moved to %s", backup)
        except Exception:
            pass

    # ------------------------------------------------------- Report Export

    def export_report(
        self, state: AuditState, output_path: Optional[str] = None
    ) -> str:
        """
        Export a human-readable JSON security report from the current state.
        Returns the path to the exported file.
        """
        report_path = Path(output_path or f"security_report_{state.session_id}.json")

        report: Dict[str, Any] = {
            "report_metadata": {
                "session_id": state.session_id,
                "target_repo": state.target_repo,
                "started_at": state.started_at,
                "exported_at": datetime.utcnow().isoformat(),
                "tool": "test Security Auditor",
                "version": "1.0.0",
            },
            "summary": {
                "total_files_scanned": len(state.scanned_files),
                "total_files_pending": len(state.pending_files),
                "confirmed_findings": len(state.confirmed_findings),
                "rejected_as_false_positive": len(state.rejected_findings),
                "total_errors": len(state.error_log),
            },
            "severity_breakdown": self._severity_breakdown(state.confirmed_findings),
            "confirmed_findings": [
                f.model_dump(mode="json") for f in state.confirmed_findings
            ],
            "rejected_findings": [
                r.model_dump(mode="json") for r in state.rejected_findings
            ],
            "scanned_files": state.scanned_files,
            "failed_files": state.failed_files,
            "error_log": state.error_log[-20:],  # Last 20 errors max
        }

        report_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info("Security report exported to %s", report_path)
        return str(report_path)

    @staticmethod
    def _severity_breakdown(findings: List[ConfirmedFinding]) -> Dict[str, int]:
        """Count findings by severity level."""
        breakdown: Dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }
        for finding in findings:
            sev = str(finding.severity).upper()
            if sev in breakdown:
                breakdown[sev] += 1
        return breakdown

    # ---------------------------------------------------- Merge / Reconcile

    def merge_findings(
        self,
        state: AuditState,
        new_confirmed: Optional[ConfirmedFinding] = None,
        new_rejected: Optional[RejectedFinding] = None,
    ) -> AuditState:
        """
        Safely merge new findings into state, deduplicating by finding_id.
        Returns the updated state.
        """
        existing_confirmed_ids = {f.finding_id for f in state.confirmed_findings}
        existing_rejected_ids = {r.finding_id for r in state.rejected_findings}

        if new_confirmed and new_confirmed.finding_id not in existing_confirmed_ids:
            state.confirmed_findings.append(new_confirmed)
            logger.info(
                "Confirmed finding added: [%s] %s",
                new_confirmed.severity,
                new_confirmed.title,
            )

        if new_rejected and new_rejected.finding_id not in existing_rejected_ids:
            state.rejected_findings.append(new_rejected)
            logger.info("Finding rejected as FP: %s", new_rejected.title)

        return state

    def mark_file_scanned(self, state: AuditState, file_path: str) -> AuditState:
        """Move a file from pending to scanned."""
        if file_path in state.pending_files:
            state.pending_files.remove(file_path)
        if file_path not in state.scanned_files:
            state.scanned_files.append(file_path)
        return state

    def mark_file_failed(
        self, state: AuditState, file_path: str, reason: str
    ) -> AuditState:
        """Move a file to the failed list and log the error."""
        if file_path in state.pending_files:
            state.pending_files.remove(file_path)
        if file_path not in state.failed_files:
            state.failed_files.append(file_path)
        state.error_log.append(
            f"[{datetime.utcnow().isoformat()}] File scan failed: {file_path} — {reason}"
        )
        return state
