# -*- coding: utf-8 -*-
#
# Copyright (c) 2025-2026 Virtual Cable S.L.U.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright notice,
#      this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#    * Neither the name of Virtual Cable S.L.U. nor the names of its contributors
#      may be used to endorse or promote products derived from this software
#      without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""Tests for config module — loading configuration from YAML and env vars."""

from __future__ import annotations

import os
import tempfile

import pytest
import yaml

from app.config import AppConfig, load_config


class TestLoadConfig:
    """Configuration loading tests."""

    def test_load_from_file(self) -> None:
        """Loading from a valid YAML file returns correct AppConfig."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({"hmac_key": "my-hmac-key"}, f)
            config_path = f.name
        try:
            config = load_config(config_path)
            assert config.hmac_key == "my-hmac-key"
            assert config.listen_host == "127.0.0.1"  # default
            assert config.listen_port == 8080  # default
        finally:
            os.unlink(config_path)

    def test_load_with_env_overrides(self) -> None:
        """Environment variables override listen_host and listen_port."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({"hmac_key": "env-test-key"}, f)
            config_path = f.name
        try:
            os.environ["CLIENT_CERT_AUTH_LISTEN_HOST"] = "0.0.0.0"
            os.environ["CLIENT_CERT_AUTH_LISTEN_PORT"] = "9090"
            config = load_config(config_path)
            assert config.hmac_key == "env-test-key"
            assert config.listen_host == "0.0.0.0"
            assert config.listen_port == 9090
        finally:
            os.unlink(config_path)
            del os.environ["CLIENT_CERT_AUTH_LISTEN_HOST"]
            del os.environ["CLIENT_CERT_AUTH_LISTEN_PORT"]

    def test_load_missing_file(self) -> None:
        """Loading from a non-existent file raises an error."""
        with pytest.raises(FileNotFoundError):
            load_config("/tmp/nonexistent-config-file.yaml")

    def test_load_missing_hmac_key(self) -> None:
        """Loading a YAML without hmac_key raises KeyError."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({"other_key": "value"}, f)
            config_path = f.name
        try:
            with pytest.raises(KeyError):
                load_config(config_path)
        finally:
            os.unlink(config_path)

    def test_config_is_frozen(self) -> None:
        """AppConfig is frozen (immutable)."""
        config = AppConfig(hmac_key="k", listen_host="h", listen_port=1)
        with pytest.raises(AttributeError):
            config.hmac_key = "new-key"  # type: ignore[misc]

    def test_config_dataclass(self) -> None:
        """AppConfig dataclass stores values correctly."""
        config = AppConfig(hmac_key="key123", listen_host="0.0.0.0", listen_port=8080)
        assert config.hmac_key == "key123"
        assert config.listen_host == "0.0.0.0"
        assert config.listen_port == 8080

    def test_env_var_config_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """CLIENT_CERT_AUTH_CONFIG env var sets the config path."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({"hmac_key": "from-env-path"}, f)
            config_path = f.name
        try:
            monkeypatch.setenv("CLIENT_CERT_AUTH_CONFIG", config_path)
            config = load_config()  # no path argument
            assert config.hmac_key == "from-env-path"
        finally:
            os.unlink(config_path)
