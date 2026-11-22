"""Optional Chroma adapter with gateway-owned tenant filtering."""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit


class ChromaConfigurationError(ValueError):
    """Raised when the configured Chroma endpoint is not safe to use."""


class ChromaRAGAdapter:
    """Query one operator-selected Chroma collection with a verified tenant ID.

    The tenant predicate is generated inside this adapter and applied both at
    Chroma query time and again to returned metadata before content is exposed.
    The browser cannot supply a collection, filter, or tenant override.
    """

    def __init__(self) -> None:
        url = os.getenv("SENTINEL_CHROMA_URL", "").strip()
        if not url:
            raise ChromaConfigurationError("SENTINEL_CHROMA_URL is not configured")
        parsed = urlsplit(url)
        hostname = (parsed.hostname or "").lower()
        try:
            port = parsed.port
        except ValueError as exc:
            raise ChromaConfigurationError("Chroma URL has an invalid port") from exc
        try:
            loopback = bool(hostname) and ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            loopback = hostname == "localhost"
        if (
            parsed.scheme not in {"http", "https"}
            or not hostname
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or (parsed.scheme != "https" and not loopback)
        ):
            raise ChromaConfigurationError("Chroma URL must be a root HTTP(S) URL without credentials or query data")
        token = os.getenv("SENTINEL_CHROMA_TOKEN", "").strip()
        if not loopback and not token:
            raise ChromaConfigurationError("A Chroma service token is required for non-loopback endpoints")
        try:
            import chromadb
        except ImportError as exc:  # pragma: no cover - depends on the optional install
            raise RuntimeError("Install LLMSentinel with the 'enterprise' extra to enable Chroma") from exc

        headers = {"x-chroma-token": token} if token else None
        self.client: Any = chromadb.HttpClient(
            host=hostname,
            port=port or (443 if parsed.scheme == "https" else 8000),
            ssl=parsed.scheme == "https",
            headers=headers,
            tenant=os.getenv("SENTINEL_CHROMA_TENANT", "default_tenant"),
            database=os.getenv("SENTINEL_CHROMA_DATABASE", "default_database"),
        )
        self.collection_name = os.getenv("SENTINEL_CHROMA_COLLECTION", "llmsentinel-documents")
        if not self.collection_name or len(self.collection_name) > 128:
            raise ChromaConfigurationError("SENTINEL_CHROMA_COLLECTION must contain 1 to 128 characters")

    def query(self, query_text: str, tenant_id: str, top_k: int) -> dict[str, Any]:
        collection = self.client.get_collection(name=self.collection_name)
        response = collection.query(
            query_texts=[query_text],
            n_results=top_k,
            where={"tenant_id": tenant_id},
            include=["documents", "metadatas", "distances"],
        )
        if not isinstance(response, Mapping):
            raise RuntimeError("Chroma returned an invalid query result")
        ids = response.get("ids")
        documents = response.get("documents")
        metadatas = response.get("metadatas")
        distances = response.get("distances")
        if not all(isinstance(value, list) and value for value in (ids, documents, metadatas)):
            return {"matches": [], "discarded_unscoped": 0}
        if not isinstance(ids, list) or not isinstance(documents, list) or not isinstance(metadatas, list):
            return {"matches": [], "discarded_unscoped": 0}
        first_ids, first_documents, first_metadatas = ids[0], documents[0], metadatas[0]
        id_rows = first_ids if isinstance(first_ids, list) else []
        document_rows = first_documents if isinstance(first_documents, list) else []
        metadata_rows = first_metadatas if isinstance(first_metadatas, list) else []
        distance_rows = distances[0] if isinstance(distances, list) and distances and isinstance(distances[0], list) else []
        matches: list[dict[str, Any]] = []
        discarded = 0
        for index, record_id in enumerate(id_rows[:top_k]):
            metadata = metadata_rows[index] if index < len(metadata_rows) else None
            if not isinstance(metadata, dict) or metadata.get("tenant_id") != tenant_id:
                discarded += 1
                continue
            document = document_rows[index] if index < len(document_rows) else ""
            distance = distance_rows[index] if index < len(distance_rows) else None
            matches.append(
                {
                    "id": str(record_id)[:256],
                    "document": document[:8192] if isinstance(document, str) else "",
                    "metadata": metadata,
                    "distance": distance if isinstance(distance, (int, float)) else None,
                }
            )
        return {"matches": matches, "discarded_unscoped": discarded}
