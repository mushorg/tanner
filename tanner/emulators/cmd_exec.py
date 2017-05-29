import asyncio
import docker
import re
import urllib.parse

from tanner.config import TannerConfig
from tanner.utils import patterns

class CmdExecEmulator:
	def __init__(self):
		self.docker_client = docker.from_env(version='auto')
		self.host_image = TannerConfig.get('CMD_EXEC', 'host_image')
		self.setup_host_image()

	def setup_host_image(self):
		if not self.docker_client.images.list(self.host_image):
			self.docker_client.images.pull(self.host_image)

	async def get_container(self, container_name):
		container_if_exists = self.docker_client.containers.list(all = True,
																 filters = dict(name = container_name)
																 )
		container = None
		if container_if_exists:
			container = container_if_exists[0]
		return container
	
	async def create_attacker_env(self, session):
		container_name = 'attacker_' + session.sess_uuid.hex
		container = await self.get_container(container_name)
		if not container:
			container = self.docker_client.containers.create(image = self.host_image,
															 stdin_open = True, 
															 name = container_name
															 )
		session.associate_env(container_name)
		return container

	async def get_cmd_exec_results(self, container, cmd):
		container.start()
		execute_result = container.exec_run(cmd).decode('utf-8')
		container.kill()
		if 'error' in execute_result:
			execute_result = 'bash: command not found: {}'.format(cmd)
		result = dict(value=execute_result, page='/index.html')
		return result

	async def delete_env(self, container_name):
		container = await self.get_container(container_name)
		if container:
			container.remove(force = True)

	async def handle(self, value, session=None):
		container = await self.create_attacker_env(session)
		result = await self.get_cmd_exec_results(container, value)
		return result