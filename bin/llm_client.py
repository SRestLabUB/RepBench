#!/usr/bin/env python3
"""
LLM API Client for Vulnerability Detection
Calls the LLM API with generated prompts and parses responses
"""

import json
import requests
from typing import Dict, Any, Optional
from dataclasses import dataclass

# LLM API Configuration
API_BASE_URL = "YOUR_LLM_API_BASE_URL"  # Replace with actual API base URL
API_KEY = "YOUR_API_KEY"  # Replace with your actual API key

# Available models
MODELS = {
    "qwen": "qwen3.5-plus",
    "kimi": "kimi-k2.5",
    "glm": "glm-5",
    "minimax": "MiniMax-M2.5",
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


class LLMClient:
    """Client for calling LLM API for vulnerability detection"""
    
    def __init__(self, model: str = "qwen", api_key: str = API_KEY):
        self.api_key = api_key
        self.model = MODELS.get(model, model)
        self.base_url = API_BASE_URL
        self.endpoint = f"{self.base_url}/v1/chat/completions"
    
    def call(
        self,
        prompt: str,
        system_prompt: str = None,
        temperature: float = 0.1,
        max_tokens: int = 2048
    ) -> LLMResponse:
        """Call LLM API with the given prompt"""
        
        if system_prompt is None:
            system_prompt = """You are a vulnerability detection expert. 
Analyze the given C/C++ code for security vulnerabilities.
Respond with a JSON object in the exact format specified."""
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
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
        
        try:
            response = requests.post(
                self.endpoint,
                headers=headers,
                json=payload,
                timeout=120
            )
            response.raise_for_status()
            
            result = response.json()
            content = result["choices"][0]["message"]["content"]
            
            try:
                parsed = json.loads(content)
                return LLMResponse(
                    conclusion=parsed.get("conclusion", "UNKNOWN"),
                    confidence=parsed.get("confidence", 0.0),
                    reasoning=parsed.get("reasoning", {}),
                    explanation=parsed.get("explanation", ""),
                    raw_response=content,
                    model_used=self.model,
                    success=True
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
                    error=f"Failed to parse JSON: {str(e)}"
                )
                
        except requests.exceptions.RequestException as e:
            return LLMResponse(
                conclusion="UNKNOWN",
                confidence=0.0,
                reasoning={},
                explanation="",
                raw_response="",
                model_used=self.model,
                success=False,
                error=f"API request failed: {str(e)}"
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
