import aiodocker
import logging

from tanner.config import TannerConfig


class AIODockerHelper:
    def __init__(self):

        self.logger = logging.getLogger("tanner.aiodocker_helper.AIODockerHelper")

        self.docker_client = aiodocker.Docker()
        self.host_image = TannerConfig.get("DOCKER", "host_image")

    async def setup_host_image(self, remote_path=None, tag=None):
        """
        Helper to pull host image or build an image with remote Dockerfile
        :param remote_path (str): remote path of Dockerfile
        :param tag (str): tag to be given to new image build ex: 'myimage:latest'
        """

        try:
            if remote_path and tag is not None:
                params = {"tag": tag, "remote": remote_path}
                await self.docker_client.images.build(**params)

            else:
                image = await self.docker_client.images.list(filter=self.host_image)
                if not image:
                    await self.docker_client.images.pull(self.host_image)

        except aiodocker.exceptions.DockerError as docker_error:
            self.logger.exception("Error while pulling %s image %s", self.host_image, docker_error)

    async def get_container(self, container_name):
        """
        Gets the container object having specified name
        :param container_name (str): name of the target container
        :return: container (object)
        """
        container = None
        try:
            container = await self.docker_client.containers.get(container=container_name)

        except aiodocker.exceptions.DockerError as server_error:
            self.logger.exception("Error while fetching %s container %s", container_name, server_error)
        return container

    async def create_container(self, container_name, cmd=None, image=None):
        """
        Helper to create or replace a container (initially pulls the given image)
        :param container_name (str): name to be given to new container or replace existing if any
        :param cmd (list): contains commands to run in the container. ex: ["sh", "-c", "echo 'Hello'"]
        :param image (str): name of image to be used
        :return: container (object): newly created container object
        """
        await self.setup_host_image()
        container = None
        if image is None:
            image = self.host_image

        config = {"Cmd": cmd, "Image": image}
        try:
            container = await self.docker_client.containers.create_or_replace(config=config, name=container_name)

        except (aiodocker.exceptions.DockerError or aiodocker.exceptions.DockerContainerError) as docker_error:
            self.logger.exception("Error while creating a container %s", docker_error)
        return container

    async def execute_cmd(self, cmd, image=None):
        """
        Creates a new container, runs the cmd in it and deletes the used container
        :param cmd (list): contains commands to run in the container. ex: ["sh", "-c", "echo 'Hello'"]
        :param image (str): name of image to be used
        :return: execute_result (str): execution output/errors of cmd from the container
        """
        execute_result = None
        try:
            if image is None:
                image = self.host_image

            config = {"Cmd": cmd, "Image": image}
            container = await self.docker_client.containers.run(config=config)

            await container.wait()
            result_exists = await container.log(stdout=True, stderr=True)
            if result_exists:
                execute_result = "".join(result_exists)

            # Deleting the used container
            await container.delete(force=True)

        except (aiodocker.exceptions.DockerError or aiodocker.exceptions.DockerContainerError) as server_error:
            self.logger.error("Error while executing command %s in container %s", cmd, server_error)
        return execute_result

    async def delete_container(self, container_name):
        """
        Delete an existing container
        :param container_name (str): name of container to be deleted
        """
        container = await self.get_container(container_name)
        try:
            if container:
                await container.delete(force=True)
        except aiodocker.exceptions.DockerError as server_error:
            self.logger.exception("Error while removing %s container %s", container_name, server_error)
