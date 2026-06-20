#!/usr/bin/env python3
"""
LLM API Client for Vulnerability Detection
Calls the LLM API with generated prompts and parses responses
"""

import json
import os
import uuid
import random
import time
import requests
from typing import Dict, Any, Optional
from dataclasses import dataclass

# LLM API Configuration
API_BASE_URL = os.environ.get(
    "LLM_API_BASE_URL",
    "https://dashscope-us.aliyuncs.com/compatible-mode/v1",
)
API_KEY = os.environ.get("LLM_API_KEY")

# Available models
MODELS = {
    "qwen": "qwen3.6-plus"
}

@dataclass
class LLMResponse:
    conclusion: str
    confidence: float
    reasoning: Dict[str, Any]
    explanation: str
    raw_response: str
    model_used: str
    success: bool
    error: Optional[str] = None
    ttft_seconds: Optional[float] = None
    total_seconds: Optional[float] = None
    stream_chunks: int = 0
    stream_idle_timeout_seconds: Optional[float] = None
    streamed: bool = False


class LLMClient:
    """Client for calling LLM API for vulnerability detection"""
    
    def __init__(
        self,
        model: str = "qwen",
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        self.api_key = api_key or API_KEY
        if not self.api_key:
            raise ValueError("Missing API key. Set LLM_API_KEY or pass api_key explicitly.")
        self.model = MODELS.get(model, model)
        self.base_url = (base_url or API_BASE_URL).rstrip("/")
        self.endpoint = f"{self.base_url}/chat/completions"
    
    def call(
        self,
        prompt: str,
        system_prompt: str = None,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        stream: bool = True,
        connect_timeout: float = 10,
        stream_idle_timeout: Optional[float] = 60,
        total_timeout: Optional[float] = 180,
    ) -> LLMResponse:
        """Call LLM API with the given prompt"""
        
        if system_prompt is None:
            system_prompt = """You are a senior C/C++ developer performing code review.
Analyze the given C/C++ code for security issues.
Respond with a JSON object in the exact format specified."""
        
        time.sleep(random.uniform(0.3, 0.8))
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "vscode-code-extension/1.92.0",
            "X-Request-Id": str(uuid.uuid4()),
            "X-Vscode-Editorid": "vscode-desktop"
        }
        
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"}
        }
        if stream:
            payload["stream"] = True
        
        try:
            started_at = time.monotonic()
            read_timeout = total_timeout if total_timeout is not None else stream_idle_timeout
            response = requests.post(
                self.endpoint,
                headers=headers,
                json=payload,
                stream=stream,
                timeout=(connect_timeout, read_timeout)
            )
            response.raise_for_status()

            if stream:
                content_parts = []
                reasoning_parts = []
                first_chunk_at = None
                chunk_count = 0
                for line in response.iter_lines(decode_unicode=True):
                    if total_timeout is not None and (time.monotonic() - started_at) > total_timeout:
                        break
                    if not line:
                        continue
                    chunk_count += 1
                    if first_chunk_at is None:
                        first_chunk_at = time.monotonic()

                    if line.startswith("data:"):
                        line = line[len("data:"):].strip()
                    if line == "[DONE]":
                        break

                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    choices = event.get("choices") or []
                    if not choices:
                        continue
                    delta = choices[0].get("delta") or {}
                    content = delta.get("content")
                    if content:
                        content_parts.append(content)
                    reasoning_content = delta.get("reasoning_content") or delta.get("reasoning")
                    if reasoning_content:
                        reasoning_parts.append(str(reasoning_content))

                total_seconds = time.monotonic() - started_at
                ttft_seconds = first_chunk_at - started_at if first_chunk_at is not None else None
                content = "".join(content_parts).strip()
                if not content and reasoning_parts:
                    content = "".join(reasoning_parts).strip()
                return self._parse_content(
                    content=content,
                    ttft_seconds=ttft_seconds,
                    total_seconds=total_seconds,
                    stream_chunks=chunk_count,
                    stream_idle_timeout=stream_idle_timeout,
                    streamed=True,
                )

            result = response.json()
            content = result["choices"][0]["message"]["content"]
            total_seconds = time.monotonic() - started_at
            return self._parse_content(
                content=content,
                ttft_seconds=None,
                total_seconds=total_seconds,
                stream_chunks=0,
                stream_idle_timeout=stream_idle_timeout,
                streamed=False,
            )
                 
        except requests.exceptions.RequestException as e:
            total_seconds = time.monotonic() - started_at if 'started_at' in locals() else None
            first_chunk_at = locals().get('first_chunk_at')
            content_parts = locals().get('content_parts') or []
            reasoning_parts = locals().get('reasoning_parts') or []
            partial_content = "".join(content_parts).strip() or "".join(reasoning_parts).strip()
            return LLMResponse(
                conclusion="UNKNOWN",
                confidence=0.0,
                reasoning={},
                explanation=partial_content,
                raw_response=partial_content,
                model_used=self.model,
                success=False,
                error=f"API request failed: {str(e)}",
                ttft_seconds=first_chunk_at - started_at if first_chunk_at is not None and 'started_at' in locals() else None,
                total_seconds=total_seconds,
                stream_chunks=locals().get('chunk_count', 0),
                stream_idle_timeout_seconds=stream_idle_timeout,
                streamed=stream,
            )

    def _parse_content(
        self,
        content: str,
        ttft_seconds: Optional[float],
        total_seconds: float,
        stream_chunks: int,
        stream_idle_timeout: Optional[float],
        streamed: bool,
    ) -> LLMResponse:
        try:
            parsed = json.loads(content)
            return LLMResponse(
                conclusion=parsed.get("conclusion", "UNKNOWN"),
                confidence=parsed.get("confidence", 0.0),
                reasoning=parsed.get("reasoning", {}),
                explanation=parsed.get("explanation", ""),
                raw_response=content,
                model_used=self.model,
                success=True,
                ttft_seconds=ttft_seconds,
                total_seconds=total_seconds,
                stream_chunks=stream_chunks,
                stream_idle_timeout_seconds=stream_idle_timeout,
                streamed=streamed,
            )
        except json.JSONDecodeError as e:
            return LLMResponse(
                conclusion="UNKNOWN",
                confidence=0.0,
                reasoning={},
                explanation=content,
                raw_response=content,
                model_used=self.model,
                success=False,
                error=f"Failed to parse JSON: {str(e)}",
                ttft_seconds=ttft_seconds,
                total_seconds=total_seconds,
                stream_chunks=stream_chunks,
                stream_idle_timeout_seconds=stream_idle_timeout,
                streamed=streamed,
            )
    
    def test_connection(self) -> bool:
        """Test API connection with a simple request"""
        test_prompt = "Respond with JSON: {\"test\": true}"
        response = self.call(test_prompt, max_tokens=50)
        return response.success


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="LLM API Client")
    parser.add_argument("--model", default="qwen", choices=list(MODELS.keys()))
    parser.add_argument("--prompt-file", "-p", help="File containing the prompt")
    parser.add_argument("--test", action="store_true", help="Test API connection")
    
    args = parser.parse_args()
    
    client = LLMClient(model=args.model)
    
    if args.test:
        print("Testing API connection...")
        if client.test_connection():
            print(f"Connection successful (model: {client.model})")
        else:
            print("Connection failed")
        return
    
    if args.prompt_file:
        with open(args.prompt_file) as f:
            prompt = f.read()
        
        print(f"Calling LLM ({client.model})...")
        response = client.call(prompt)
        
        print("")
        print("=" * 60)
        print(f"Model: {response.model_used}")
        print(f"Success: {response.success}")
        if response.error:
            print(f"Error: {response.error}")
        print("")
        print(f"Conclusion: {response.conclusion}")
        print(f"Confidence: {response.confidence:.2f}")
        print("")
        print("Explanation:")
        print(response.explanation)
        print("")
        print("=" * 60)


if __name__ == "__main__":
    main()
