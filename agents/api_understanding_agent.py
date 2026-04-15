"""
agents/api_understanding_agent.py
Reads API specs / raw traffic and extracts structured endpoint knowledge.
Now uses the multi-LLM provider abstraction.
"""
from __future__ import annotations
import json
from typing import Any

from providers.factory import get_provider
from core.parser import SpecParser, APISpec, Endpoint, EndpointParam
from core.logger import get_logger

logger = get_logger("api_understanding_agent")


class APIUnderstandingAgent:
    def __init__(self, provider_name: str | None = None):
        self.parser = SpecParser()
        self.provider = get_provider(provider_name)

    def analyze(self, source: str | dict, base_url_override: str | None = None) -> APISpec:
        logger.info("[APIUnderstandingAgent] Analyzing API spec …")
        spec: APISpec = self.parser.parse(source)
        if base_url_override:
            spec.base_url = base_url_override
        enriched = self._enrich_with_llm(spec)
        logger.info(f"[APIUnderstandingAgent] {len(spec.endpoints)} endpoints understood (provider: {self.provider.name})")
        return enriched

    def analyze_raw_text(self, description: str, base_url: str) -> APISpec:
        logger.info("[APIUnderstandingAgent] Extracting spec from raw description …")
        prompt = f"""You are an expert API analyst. Extract structured endpoint information from the
following API documentation and return ONLY valid JSON matching this schema:

{{
  "title": "string",
  "version": "string",
  "base_url": "{base_url}",
  "description": "string",
  "auth_type": "none|apiKey|http|oauth2",
  "endpoints": [
    {{
      "path": "/example",
      "method": "GET",
      "summary": "Short summary",
      "description": "Longer description",
      "parameters": [
        {{"name":"id","location":"path","required":true,"schema":{{"type":"string"}}}}
      ],
      "request_body": null,
      "responses": {{"200": {{"description": "Success"}}}},
      "tags": []
    }}
  ]
}}

API Documentation:
{description}"""
        resp = self.provider.chat_json([{"role": "user", "content": prompt}])
        data = json.loads(resp.content)
        endpoints = []
        for ep in data.get("endpoints", []):
            params = [EndpointParam(**p) for p in ep.get("parameters", [])]
            endpoints.append(Endpoint(
                path=ep["path"], method=ep["method"],
                summary=ep.get("summary", ""), description=ep.get("description", ""),
                parameters=params, request_body=ep.get("request_body"),
                responses=ep.get("responses", {}), tags=ep.get("tags", []),
            ))
        return APISpec(
            title=data.get("title", "Unknown"),
            version=data.get("version", "1.0"),
            base_url=base_url,
            description=data.get("description", ""),
            auth_type=data.get("auth_type", "none"),
            endpoints=endpoints,
        )

    def _enrich_with_llm(self, spec: APISpec) -> APISpec:
        if not spec.endpoints:
            return spec
        endpoint_list = "\n".join(
            f"  {e.method} {e.path} — {e.summary}" for e in spec.endpoints[:30]
        )
        prompt = f"""You are an API security and testing expert. Given these API endpoints, return a JSON
object where each key is "METHOD /path" and the value has:
  - "risk": "low" | "medium" | "high"
  - "note": one-sentence insight for a tester

Endpoints:
{endpoint_list}

Return ONLY valid JSON, no markdown."""
        try:
            resp = self.provider.chat_json([{"role": "user", "content": prompt}])
            insights: dict[str, Any] = json.loads(resp.content)
            for ep in spec.endpoints:
                key = f"{ep.method} {ep.path}"
                if key in insights:
                    ep.description = (ep.description or "") + f" [LLM: {insights[key].get('note', '')}]"
        except Exception as exc:
            logger.warning(f"LLM enrichment failed: {exc}")
        return spec
