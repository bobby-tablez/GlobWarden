"""Tests for the LLMProvider ABC / LLMResponse contract itself."""

import pytest

from globwarden.llm.base import LLMProvider, LLMResponse


def test_llm_provider_cannot_be_instantiated_directly():
    with pytest.raises(TypeError):
        LLMProvider()  # abstract methods complete()/is_available() unimplemented


def test_llm_response_defaults():
    resp = LLMResponse(text="hi", model="some-model", provider="fake")
    assert resp.raw is None


def test_llm_response_carries_raw_dict():
    raw = {"id": "abc", "choices": []}
    resp = LLMResponse(text="hi", model="m", provider="p", raw=raw)
    assert resp.raw is raw


def test_subclass_missing_methods_cannot_instantiate():
    class Incomplete(LLMProvider):
        name = "incomplete"

        def complete(self, system_prompt, user_prompt, images=None, json_mode=False):
            raise NotImplementedError

    with pytest.raises(TypeError):
        Incomplete()


def test_full_subclass_instantiates_and_conforms():
    class Fake(LLMProvider):
        name = "fake"

        def complete(self, system_prompt, user_prompt, images=None, json_mode=False):
            return LLMResponse(text="ok", model="fake-model", provider=self.name)

        def is_available(self):
            return True

    provider = Fake()
    assert provider.is_available() is True
    resp = provider.complete("sys", "user")
    assert resp.text == "ok"
    assert resp.provider == "fake"
