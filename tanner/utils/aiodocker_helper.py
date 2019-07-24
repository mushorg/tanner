import aiodocker
import logging

from tanner.config import TannerConfig


class AIODockerHelper:
    def __init__(self):

        self.logger = logging.getLogger('tanner.aiodocker_helper.AIODockerHelper')

        self.docker_client = aiodocker.Docker()
        self.host_image = TannerConfig.get('DOCKER', 'host_image')

    async def setup_host_image(self, remote_path=None, tag=None):

        try:
            if remote_path and tag is not None:
                params = {"tag": tag, "remote": remote_path}
                await self.docker_client.images.build(**params)

            image = await self.docker_client.images.list(filter=self.host_image)
            if not image:
                await self.docker_client.images.pull(self.host_image)

        except aiodocker.exceptions.DockerError as docker_error:
            self.logger.exception('Error while pulling %s image %s', self.host_image, docker_error)

    async def get_container(self, container_name):
        container = None
        try:
            container = await self.docker_client.containers.get(container=container_name)

        except aiodocker.exceptions.DockerError as server_error:
            self.logger.exception('Error while fetching %s container %s', container_name, server_error)
        return container

    async def create_container(self, container_name, cmd=None, image=None):
        await self.setup_host_image()
        container = None
        if image is None:
            image = self.host_image

        config = {
            "Cmd": cmd,
            "Image": image,
        }
        try:
            container = await self.docker_client.containers.create_or_replace(config=config, name=container_name)

        except (aiodocker.exceptions.DockerError or aiodocker.exceptions.DockerContainerError) as docker_error:
            self.logger.exception('Error while creating a container %s', docker_error)
        return container

    async def execute_cmd(self, cmd, image=None):
        execute_result = None
        try:
            if image is None:
                image = self.host_image

            config = {"Cmd": cmd, "Image": image}
            container = await self.docker_client.containers.run(config=config)

            await container.wait()
            result_exists = await container.log(stdout=True, stderr=True)
            if result_exists:
                execute_result = ''.join(result_exists)

            # Deleting the used container
            await container.delete(force=True)

        except (aiodocker.exceptions.DockerError or aiodocker.exceptions.DockerContainerError) as server_error:
            self.logger.error('Error while executing command %s in container %s', cmd, server_error)
        return execute_result

    async def delete_container(self, container_name):
        container = await self.get_container(container_name)
        try:
            if container:
                await container.delete(force=True)
        except aiodocker.exceptions.DockerError as server_error:
            self.logger.exception('Error while removing %s container %s', container_name, server_error)
