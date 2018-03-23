import asyncio
from unittest import mock

def AsyncMock(*args, **kwargs):
    m = mock.MagicMock(*args, **kwargs)
    
    async def mock_coro(*args, **kwargs):
        return m(*args, **kwargs)

    mock_coro.mock = m
    return mock_coro
