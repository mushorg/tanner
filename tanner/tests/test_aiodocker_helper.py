import asyncio
import unittest

from tanner.utils.aiodocker_helper import AIODockerHelper


class TestAioDockerHelper(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.handler = AIODockerHelper()
        self.image = None
        self.expected_result = None
        self.returned_result = None

    def test_setup_host_image(self):
        self.image = "busybox:latest"

        async def test():
            await self.handler.setup_host_image()
            self.returned_result = await self.handler.docker_client.images.list(filter=self.image)

        self.loop.run_until_complete(test())
        self.assertTrue(len(self.returned_result) > 0)

    def test_get_container(self):
        container_name = "test_get_container"

        async def test():
            await self.handler.create_container(container_name)
            self.returned_result = await self.handler.get_container(container_name)
            await self.handler.delete_container(container_name)

        self.loop.run_until_complete(test())
        self.assertTrue(self.returned_result._id)

    def test_create_container(self):
        container_name = "test_create_container"

        async def test():
            container = await self.handler.create_container(container_name=container_name)
            await container.start()
            self.returned_result = await container.show()
            await self.handler.delete_container(container_name)

        self.loop.run_until_complete(test())
        self.assertFalse(self.returned_result["State"]["Running"])

    def test_execute_cmd(self):
        cmd = ["sh", "-c", "echo 'Hello!'"]

        async def test():
            self.returned_result = await self.handler.execute_cmd(cmd)

        self.loop.run_until_complete(test())
        self.expected_result = "Hello!"
        self.assertIn(self.expected_result, self.returned_result)

    def test_delete_container(self):
        container_name = "test_delete_container"

        async def test():
            await self.handler.create_container(container_name)
            await self.handler.delete_container(container_name)
            self.returned_result = await self.handler.get_container(container_name)

        self.loop.run_until_complete(test())
        self.assertEqual(self.returned_result, None)

    def tearDown(self):
        self.loop.run_until_complete(self.handler.docker_client.close())
        self.loop.close()
