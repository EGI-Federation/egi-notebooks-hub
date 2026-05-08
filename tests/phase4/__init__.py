from typing import Any, ClassVar

import httpx


class DummyResponse:
    """
    Small helper that mimics enough of httpx.Response for our tests.

    Why this helper exists:
    - api_wrapper expects objects that support raise_for_status()
    - some tests inspect json()
    - some tests rely on raw content/text behavior

    This fake keeps those interactions explicit and easy to reason about.
    """

    def __init__(self, status_code=200, json_data=None, content=b""):
        self.status_code = status_code
        self._json_data = json_data
        self.content = content
        self.text = (
            content.decode("utf-8", "replace")
            if isinstance(content, bytes)
            else str(content)
        )

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("GET", "http://dummy")
            response = httpx.Response(
                self.status_code, request=request, content=self.content
            )
            raise httpx.HTTPStatusError("error", request=request, response=response)

    def json(self):
        if self._json_data is not None:
            return self._json_data
        raise ValueError("not json")


class FakeAsyncClient:
    """Fake httpx.AsyncClient used across phase4 integration tests."""

    calls: ClassVar[list[dict[str, Any]]] = []
    login_response = DummyResponse(
        status_code=200, json_data={"token": "hub-user-token"}
    )
    forwarded_response = DummyResponse(status_code=200, json_data={"ok": True})
    responses: ClassVar[dict[str, DummyResponse]] = {}

    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    @classmethod
    def reset(cls):
        cls.calls = []
        cls.login_response = DummyResponse(
            status_code=200, json_data={"token": "hub-user-token"}
        )
        cls.forwarded_response = DummyResponse(status_code=200, json_data={"ok": True})
        cls.responses = {}

    def _record(self, method: str, url: str, content=None, headers=None, **kwargs):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "content": content,
                "headers": headers or {},
                "kwargs": kwargs,
            }
        )
        return type(self).responses.get(url, type(self).forwarded_response)

    async def get(self, url, headers=None, content=None, **kwargs):
        self.calls.append(
            {
                "method": "GET",
                "url": url,
                "content": content,
                "headers": headers or {},
                "kwargs": kwargs,
            }
        )
        if url.endswith("/jwt_login"):
            return type(self).login_response
        return type(self).responses.get(url, type(self).forwarded_response)

    async def post(self, url, content=None, headers=None, **kwargs):
        return self._record("POST", url, content, headers, **kwargs)
