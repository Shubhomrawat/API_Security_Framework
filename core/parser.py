"""
core/parser.py — Parses OpenAPI / Swagger specs into structured endpoint data
"""
from __future__ import annotations
import json
import yaml
from pathlib import Path
from typing import Any
from dataclasses import dataclass, field

from core.logger import get_logger

logger = get_logger("parser")


@dataclass
class EndpointParam:
    name: str
    location: str          # query | path | header | cookie | body
    required: bool
    schema: dict[str, Any]
    description: str = ""


@dataclass
class Endpoint:
    path: str
    method: str
    summary: str
    description: str
    parameters: list[EndpointParam] = field(default_factory=list)
    request_body: dict[str, Any] | None = None
    responses: dict[str, Any] = field(default_factory=dict)
    security: list[dict] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass
class APISpec:
    title: str
    version: str
    base_url: str
    description: str
    auth_type: str          # none | apiKey | http | oauth2 | openIdConnect
    endpoints: list[Endpoint] = field(default_factory=list)
    servers: list[str] = field(default_factory=list)


class SpecParser:
    """Parses OpenAPI 3.x / Swagger 2.x specifications."""

    def parse(self, source: str | Path | dict) -> APISpec:
        raw = self._load(source)
        logger.info(f"Parsing spec: {raw.get('info', {}).get('title', 'Unknown')}")

        if "swagger" in raw:
            return self._parse_swagger2(raw)
        return self._parse_openapi3(raw)

    # ── Loaders ──────────────────────────────────────────────────────────────

    def _load(self, source: str | Path | dict) -> dict:
        if isinstance(source, dict):
            return source
        path = Path(source)
        text = path.read_text(encoding="utf-8")
        if path.suffix in (".yaml", ".yml"):
            return yaml.safe_load(text)
        return json.loads(text)

    # ── OpenAPI 3.x ──────────────────────────────────────────────────────────

    def _parse_openapi3(self, raw: dict) -> APISpec:
        info = raw.get("info", {})
        servers = [s.get("url", "") for s in raw.get("servers", [])]
        base_url = servers[0] if servers else ""
        auth_type = self._detect_auth(raw.get("components", {}).get("securitySchemes", {}))

        endpoints = []
        for path, path_item in raw.get("paths", {}).items():
            for method, op in path_item.items():
                if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                    continue
                params = self._parse_params(op.get("parameters", []) + path_item.get("parameters", []))
                endpoints.append(Endpoint(
                    path=path,
                    method=method.upper(),
                    summary=op.get("summary", ""),
                    description=op.get("description", ""),
                    parameters=params,
                    request_body=self._parse_request_body(op.get("requestBody")),
                    responses=op.get("responses", {}),
                    security=op.get("security", raw.get("security", [])),
                    tags=op.get("tags", []),
                ))

        logger.info(f"Discovered {len(endpoints)} endpoints")
        return APISpec(
            title=info.get("title", "Unknown API"),
            version=info.get("version", "0.0.0"),
            base_url=base_url,
            description=info.get("description", ""),
            auth_type=auth_type,
            endpoints=endpoints,
            servers=servers,
        )

    # ── Swagger 2.x ──────────────────────────────────────────────────────────

    def _parse_swagger2(self, raw: dict) -> APISpec:
        info = raw.get("info", {})
        host = raw.get("host", "localhost")
        base_path = raw.get("basePath", "/")
        schemes = raw.get("schemes", ["https"])
        base_url = f"{schemes[0]}://{host}{base_path}"
        auth_type = self._detect_auth(raw.get("securityDefinitions", {}))

        endpoints = []
        for path, path_item in raw.get("paths", {}).items():
            for method, op in path_item.items():
                if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                    continue
                params = self._parse_params(op.get("parameters", []))
                endpoints.append(Endpoint(
                    path=path,
                    method=method.upper(),
                    summary=op.get("summary", ""),
                    description=op.get("description", ""),
                    parameters=params,
                    request_body=None,
                    responses=op.get("responses", {}),
                    security=op.get("security", []),
                    tags=op.get("tags", []),
                ))

        return APISpec(
            title=info.get("title", "Unknown API"),
            version=info.get("version", "0.0.0"),
            base_url=base_url,
            description=info.get("description", ""),
            auth_type=auth_type,
            endpoints=endpoints,
            servers=[base_url],
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _parse_params(self, raw_params: list[dict]) -> list[EndpointParam]:
        seen, result = set(), []
        for p in raw_params:
            key = (p.get("name"), p.get("in"))
            if key in seen:
                continue
            seen.add(key)
            result.append(EndpointParam(
                name=p.get("name", ""),
                location=p.get("in", "query"),
                required=p.get("required", False),
                schema=p.get("schema", p),
                description=p.get("description", ""),
            ))
        return result

    def _parse_request_body(self, body: dict | None) -> dict | None:
        if not body:
            return None
        content = body.get("content", {})
        for mime, media in content.items():
            return {"mime": mime, "schema": media.get("schema", {}), "required": body.get("required", False)}
        return None

    def _detect_auth(self, schemes: dict) -> str:
        for scheme in schemes.values():
            t = scheme.get("type", "").lower()
            if t in {"apikey", "http", "oauth2", "openidconnect"}:
                return t
        return "none"
