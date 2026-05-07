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

