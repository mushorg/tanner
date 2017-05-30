import asyncio
import docker
import logging

from tanner.config import TannerConfig
from tanner.utils import patterns

class CmdExecEmulator:
	def __init__(self):
		try:
			self.docker_client = docker.from_env(version='auto')
		except docker.errors as docker_error:
			self.logger.error('Error while connecting to docker service %s', docker_error)
		self.host_image = TannerConfig.get('CMD_EXEC', 'host_image')
		self.logger = logging.getLogger('tanner.cmd_exec_emulator.CmdExecEmulator')

	async def setup_host_image(self):
		try:
			if not self.docker_client.images.list(self.host_image):
				self.docker_client.images.pull(self.host_image)
		except docker.errors as docker_error:
			self.logger.error('Error while pulling %s image %s', self.host_image, docker_error)
		
	async def get_container(self, container_name):
		container = None
		try:
			container_if_exists = self.docker_client.containers.list(all= True,
																	 filters= dict(name= container_name)
																	 )
			if container_if_exists:
				container = container_if_exists[0]
		except docker.errors.APIError as server_error:
			self.logger.error('Error while fetching container list %s', server_error)
		return container
	
	async def create_attacker_env(self, session):
		await self.setup_host_image()
		container_name = 'attacker_' + session.sess_uuid.hex
		container = await self.get_container(container_name)
		if not container:
			try:
				container = self.docker_client.containers.create(image= self.host_image,
																 stdin_open= True, 
																 name= container_name
																 )
				session.associate_env(container_name)
			except docker.errors as docker_error:
				self.logger.error('Error while creating a container %s', docker_error)
		return container

	async def get_cmd_exec_results(self, container, cmd):
		execute_result = None
		try:
			container.start()
			execute_result = container.exec_run(cmd).decode('utf-8')
			container.kill()
		except docker.errors.APIError as server_error:
			self.logger.error('Error while executing command %s in container %s', cmd, server_error)
		if execute_result is not None and 'error' in execute_result:
			execute_result = 'bash: command not found: {}'.format(cmd)
		result = dict(value= execute_result, page= '/index.html')
		return result

	async def delete_env(self, container_name):
		container = await self.get_container(container_name)
		try:
			if container:
				container.remove(force = True)
		except docker.errors.APIError as server_error:
			self.logger.error('Error while removing container %s', server_error)
		

	async def handle(self, value, session= None):
		container = await self.create_attacker_env(session)
		result = await self.get_cmd_exec_results(container, value)
		return result