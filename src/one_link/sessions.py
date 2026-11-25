"""Explicit peer session protocol definitions.

This is a lightweight runtime mirror of the coherence_lang session-protocol
idea: every peer conversation has a named, ordered shape that audit tools and
tests can inspect.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Step:
    direction: str
    message: str
    note: str = ""


@dataclass(frozen=True)
class Protocol:
    name: str
    steps: tuple[Step, ...]
    completion_message: str = "ACK"
    completion_requirement: str = "authenticated receiver acknowledgement"
    capability: str | None = None

    def to_dict(self) -> dict:
        return {
            "schema_version": 2,
            "name": self.name,
            "steps": [asdict(s) for s in self.steps],
            "completion_message": self.completion_message,
            "completion_requirement": self.completion_requirement,
            "capability": self.capability,
        }


PROTOCOLS = (
    Protocol(
        "chat_text",
        (
            Step("send", "CAPS", "advertise capabilities"),
            Step("send", "TEXT", "deliver one chat message"),
            Step("recv", "ACK", "receiver persisted message"),
        ),
    ),
    Protocol(
        "file_cdc_transfer",
        (
            Step("send", "CAPS"),
            Step("send", "FILE_OFFER", "includes whole-file hash and CDC chunk index"),
            Step("recv", "FILE_WANTS", "receiver names missing chunk indexes"),
            Step("send", "FILE_CDC_CHUNK", "only missing chunks cross the wire"),
            Step("recv", "ACK", "per chunk integrity/sequence acknowledgment"),
            Step("recv", "FILE_COMMIT", "whole-file identity and durable receiver completion"),
        ),
        completion_message="FILE_COMMIT",
        completion_requirement=(
            "validated delivery ID, blob hash, byte count, name and durable receiver commit; "
            "legacy chunk ACKs alone remain sent_unconfirmed"
        ),
        capability="file_commit_receipt_v1",
    ),
    Protocol(
        "file_binary_stream",
        (
            Step("send", "CAPS", "advertise file_binary_frame support"),
            Step("send", "FILE_OFFER", "announces stream-compatible file"),
            Step("recv", "ACK", "receiver accepts stream offer"),
            Step("send", "FILE_BIN_CHUNK", "encrypted raw bytes, no base64 expansion"),
            Step("recv", "ACK", "bounded pipelined chunk acknowledgment"),
            Step("recv", "FILE_COMMIT", "whole-file identity and durable receiver completion"),
        ),
        completion_message="FILE_COMMIT",
        completion_requirement=(
            "validated delivery ID, blob hash, byte count, name and durable receiver commit; "
            "legacy chunk ACKs alone remain sent_unconfirmed"
        ),
        capability="file_commit_receipt_v1",
    ),
    Protocol(
        "folder_merkle_sync",
        (
            Step("send", "CAPS"),
            Step("send", "MANIFEST_PUSH", "includes Merkle root and manifest rows"),
            Step("recv", "MANIFEST_WANTS", "empty when Merkle roots already match"),
            Step("send", "BLOB_OFFER"),
            Step("send", "BLOB_CHUNK"),
            Step("send", "FOLDER_SYNC_VERIFY", "bind the sync attempt to the materialized manifest"),
            Step("recv", "FOLDER_SYNC_COMMIT", "receiver verifies materialized content and commits"),
        ),
        completion_message="FOLDER_SYNC_COMMIT",
        completion_requirement="validated sync ID, manifest identity and receiver materialization evidence",
        capability="folder_sync_commit_v1",
    ),
    Protocol(
        "pairing",
        (
            Step("send", "PAIR_REQUEST"),
            Step("recv", "ACK"),
            Step("send", "PAIR_CONFIRM"),
            Step("recv", "ACK"),
        ),
    ),
)


def protocol_catalog() -> list[dict]:
    return [p.to_dict() for p in PROTOCOLS]
