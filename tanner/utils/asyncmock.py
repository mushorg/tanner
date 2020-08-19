import asyncio
from unittest.mock import Mock
from aioftp.errors import AIOFTPException


class AsyncMock(Mock):  # custom function defined to mock asyncio coroutines

    def __call__(self, *args, **kwargs):
        sup = super(AsyncMock, self)

        async def coro():
            return sup.__call__(*args, **kwargs)
        return coro()

    def __await__(self):
        return self().__await__()


class AysncFTPMock(Mock):

    def __aenter__():
        raise AIOFTPException
