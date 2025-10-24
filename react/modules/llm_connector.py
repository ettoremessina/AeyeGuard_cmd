"""
LLM Connector module for interfacing with LM Studio.

Provides connection, retry logic, and interaction with local LLM via LangChain.
"""

import time
import logging
import requests
from typing import Optional, Dict, Any
from langchain.callbacks.manager import CallbackManager
from langchain.callbacks.streaming_stdout import StreamingStdOutCallbackHandler

logger = logging.getLogger(__name__)


class LLMConnector:
    """Handles connection and communication with LM Studio via LangChain."""

    def __init__(self, config):
        """
        Initialize LLM connector.

        Args:
            config: Configuration object containing LLM settings
        """
        self.config = config
        self.model_name = config.model
        self.base_url = config.lm_studio_url
        self.temperature = config.temperature
        self.max_tokens = config.max_tokens
        self.timeout = config.timeout
        self.retry_attempts = config.retry_attempts
        self.retry_delay = config.retry_delay

        # LM Studio's OpenAI-compatible endpoint
        self.api_url = f"{self.base_url}/v1/chat/completions"
        self.models_url = f"{self.base_url}/v1/models"

        logger.info(f"Initialized LLM connector for {self.base_url}")

    def test_connection(self) -> bool:
        """
        Test connection to LM Studio server.

        Returns:
            True if connection successful, False otherwise
        """
        try:
            logger.debug(f"Testing connection to {self.models_url}")
            response = requests.get(self.models_url, timeout=5)

            if response.status_code == 200:
                data = response.json()
                models = data.get('data', [])

                if models:
                    available_models = [m.get('id') for m in models]
                    logger.info(f"Connected to LM Studio. Available models: {available_models}")

                    # Check if requested model is available
                    if self.model_name not in available_models:
                        logger.warning(f"Requested model '{self.model_name}' not found in available models")
                        logger.warning(f"Available models: {available_models}")
                        logger.warning("Proceeding anyway - LM Studio may map the request to loaded model")

                    return True
                else:
                    logger.warning("Connected to LM Studio but no models loaded")
                    logger.warning("Please load a model in LM Studio")
                    return True  # Connection works, but no model loaded

            logger.error(f"LM Studio returned status code: {response.status_code}")
            return False

        except requests.exceptions.ConnectionError:
            logger.error(f"Cannot connect to LM Studio at {self.base_url}")
            logger.error("Please ensure LM Studio is running")
            return False
        except requests.exceptions.Timeout:
            logger.error("Connection to LM Studio timed out")
            return False
        except Exception as e:
            logger.error(f"Error testing connection: {e}")
            return False

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> Optional[str]:
        """
        Generate response from LLM with retry logic.

        Args:
            prompt: The user prompt to send to the LLM
            system_prompt: Optional system prompt for context

        Returns:
            Generated text response or None if failed
        """
        for attempt in range(self.retry_attempts):
            try:
                logger.debug(f"Attempt {attempt + 1}/{self.retry_attempts}")

                response = self._call_llm(prompt, system_prompt)

                if response:
                    logger.info(f"Successfully generated response ({len(response)} characters)")
                    return response

            except Exception as e:
                logger.warning(f"Attempt {attempt + 1} failed: {e}")

                if attempt < self.retry_attempts - 1:
                    logger.info(f"Retrying in {self.retry_delay} seconds...")
                    time.sleep(self.retry_delay)
                else:
                    logger.error(f"All {self.retry_attempts} attempts failed")

        return None

    def _call_llm(self, prompt: str, system_prompt: Optional[str] = None) -> Optional[str]:
        """
        Make actual API call to LM Studio.

        Args:
            prompt: User prompt
            system_prompt: System prompt

        Returns:
            Response text or None
        """
        messages = []

        # Add system prompt if provided
        if system_prompt:
            messages.append({
                "role": "system",
                "content": system_prompt
            })

        # Add user prompt
        messages.append({
            "role": "user",
            "content": prompt
        })

        # Prepare request payload
        payload = {
            "model": self.model_name,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "stream": False
        }

        logger.debug(f"Sending request to {self.api_url}")
        logger.debug(f"Payload: model={self.model_name}, temp={self.temperature}, max_tokens={self.max_tokens}")

        try:
            response = requests.post(
                self.api_url,
                json=payload,
                timeout=self.timeout,
                headers={"Content-Type": "application/json"}
            )

            if response.status_code == 200:
                data = response.json()

                # Extract response text
                choices = data.get('choices', [])
                if choices:
                    message = choices[0].get('message', {})
                    content = message.get('content', '')

                    # Log token usage if available
                    usage = data.get('usage', {})
                    if usage:
                        logger.debug(f"Token usage: {usage}")

                    return content.strip()
                else:
                    logger.error("No choices in response")
                    return None

            else:
                logger.error(f"API request failed with status {response.status_code}")
                logger.error(f"Response: {response.text}")
                return None

        except requests.exceptions.Timeout:
            logger.error(f"Request timed out after {self.timeout} seconds")
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            raise

    def generate_structured(
        self,
        prompt: str,
        system_prompt: Optional[str] = None
    ) -> Optional[str]:
        """
        Generate response from LLM (returns plain text).

        Args:
            prompt: User prompt
            system_prompt: System prompt

        Returns:
            Text response or None
        """
        response_text = self.generate(prompt, system_prompt)
        return response_text

    def get_model_info(self) -> Optional[Dict[str, Any]]:
        """
        Get information about the loaded model.

        Returns:
            Model information dictionary or None
        """
        try:
            response = requests.get(self.models_url, timeout=5)

            if response.status_code == 200:
                return response.json()

            return None

        except Exception as e:
            logger.error(f"Error getting model info: {e}")
            return None
