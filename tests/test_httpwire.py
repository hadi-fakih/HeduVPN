import asyncio

from heduvpn.httpwire import decoy_response, read_request


def test_read_request_and_rest():
    async def scenario():
        reader = asyncio.StreamReader()
        reader.feed_data(
            b"POST /submit?x=1 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nX-Thing: A\r\nX-Thing: B\r\n\r\nhello"
        )
        reader.feed_eof()
        req = await read_request(reader)
        assert req.method == "POST"
        assert req.path == "/submit"
        assert req.host == "example.com"
        assert req.rest == b"hello"
        assert req.get("x-thing") == "A, B"

    asyncio.run(scenario())


def test_decoy_pages_look_ordinary():
    home = decoy_response("/")
    assert home.startswith(b"HTTP/1.1 200 OK\r\n")
    assert b"Server: nginx/" in home
    assert b"Content-Length:" in home
    assert b"HeduVPN" not in home
    not_found = decoy_response("/admin")
    assert not_found.startswith(b"HTTP/1.1 404 Not Found\r\n")
    bad = decoy_response("/", status=400)
    assert bad.startswith(b"HTTP/1.1 400 Bad Request\r\n")
    head = decoy_response("/x", method="HEAD")
    assert head.startswith(b"HTTP/1.1 404")
