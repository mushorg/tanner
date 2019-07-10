import logging
import docker

from tanner.config import TannerConfig

# TODO : Replace docker with aiodocker


class DockerHelper:
    def __init__(self):
        self.logger = logging.getLogger('tanner.docker_helper.DockerHelper')
        try:
            self.docker_client = docker.from_env(version='auto')
        except docker.errors.APIError as docker_error:
            self.logger.exception('Error while connecting to docker service %s', docker_error)
        self.host_image = TannerConfig.get('DOCKER', 'host_image')
        self.image = None

    async def setup_host_image(self, path_to_file=None, tag=None):
        try:
            if path_to_file is not None:
                self.image = self.docker_client.images.build(path=path_to_file, tag=tag)
            if not self.docker_client.images.list(self.host_image):
                self.docker_client.images.pull(self.host_image)
        except docker.errors.APIError as docker_error:
            self.logger.exception('Error while pulling %s image %s', self.host_image, docker_error)

    async def get_container(self, container_name):
        container = None
        try:
            container_if_exists = self.docker_client.containers.list(all=True,
                                                                     filters=dict(name=container_name)
                                                                     )
            if container_if_exists:
                container = container_if_exists[0]
        except docker.errors.APIError as server_error:
            self.logger.exception('Error while fetching container list %s', server_error)
        return container

    async def create_container(self, container_name):
        await self.setup_host_image()
        container = await self.get_container(container_name)
        if not container:
            try:
                container = self.docker_client.containers.create(image=self.host_image,
                                                                 stdin_open=True,
                                                                 name=container_name
                                                                 )
            except (docker.errors.APIError, docker.errors.ImageNotFound) as docker_error:
                self.logger.exception('Error while creating a container %s', docker_error)
        return container

    async def delete_env(self, container_name):
        container = await self.get_container(container_name)
        try:
            if container:
                container.remove(force=True)
        except docker.errors.APIError as server_error:
            self.logger.exception('Error while removing container %s', server_error)

    async def execute_cmd(self, container, cmd):
        execute_result = None
        try:
            container.start()
            execute_result = container.exec_run(['sh', '-c', cmd])
            container.kill()
        except docker.errors.APIError as server_error:
            self.logger.exception('Error while executing command %s in container %s', cmd, server_error)
        return execute_result.output.decode('utf-8')
