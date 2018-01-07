import json
import os
import logging
from redteam.core import ResourceConnectorFactory
from redteam.core import FILE_CONNECTOR

class Resource(object):

    def __init__(self, location, tlsverify=True, resource_connector=None, logger=None, transform_cls=None):

        connector_args = {'tlsverify': tlsverify}
        self.log = None
        if logger:
            connector_args = {'logger': logger}
            self.log = logging.getLogger(logger)

        if transform_cls:
            connector_args = {'transform_cls': transform_cls}

        if not resource_connector:
            self.connector = ResourceConnectorFactory.create_connector(location, **connector_args)
        else:
            self.connector = resource_connector

        self.in_memory_data = None

    def update(self):
        if self.log:
            self.log.debug("Update for resource location %s", self.location)
        return self.connector.open()

    def read(self):
        data = Resource.update(self)

        if isinstance(data, str):
            try:
                return json.loads(data)
            except ValueError:
                pass
        return data

    def delete(self):
        if self.exists:
            self.connector.delete()

    def write(self, content):
        self.connector.write(content)

    @property
    def connector_type(self):
        return self.connector.type

    @property
    def exists(self):
        return self.connector.exists()

    @property
    def data(self):
        if not self.in_memory_data:
            self.in_memory_data = self.read()

        return self.in_memory_data

    @property
    def location(self):
        return self.connector.location

    @property
    def filename(self):
        if not self.connector_type == FILE_CONNECTOR:
            pass
        return os.path.split(self.location)[1]

    @property
    def filepath(self):
        if not self.connector_type == FILE_CONNECTOR:
            pass
        return os.path.split(self.location)[0]