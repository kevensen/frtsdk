import json
import os
from redteam.core import Resource
from redteam.core import MBOX_CONNECTOR
from redteam.core import MBoxResouceConnector
class ResourceWithCache(Resource):

    def __init__(self, location, cache_location=None, tlsverify=True, resource_connector=None, logger=None):

        super(ResourceWithCache, self).__init__(location, tlsverify, resource_connector, logger)

        if cache_location:
            if self.connector_type == MBOX_CONNECTOR:
                self.cache = Resource(cache_location,
                                      resource_connector=MBoxResouceConnector(cache_location,
                                                                              tlsverify=tlsverify,
                                                                              logger=logger))
            else:
                self.cache = Resource(cache_location)
            if not os.path.isdir(self.cache_path):
                os.makedirs(self.cache_path)
        else:
            self.cache = None


    def configure_cache(self, cachepath):
        self.cache = Resource(cachepath)

    def delete_cache(self):
        if self.log:
            self.log.debug("Resource - deleting cache at %s", self.location)
        if self.cache:
            self.cache.delete()

    @property
    def location(self):
        if self.cache:
            return self.cache.location
        return self.location

    @property
    def cache_path(self):
        if self.cache:
            return self.cache.filepath
        return ''

    def update(self):
        if self.cache:
            self.cache.delete()

        data = self.connector.open()

        if self.cache:
            self.cache.write(data)
        return data

    def read(self):
        data = None
        if self.cache and self.cache.exists:
            if self.log:
                self.log.debug("Resource - reading from cache %s", self.cache.location)
            data = self.cache.data
        else:
            data = self.update()
            if self.log:
                self.log.debug("Resource - reading from source %s", self.location)

        if isinstance(data, str):
            try:
                return json.loads(data)
            except ValueError:
                pass
        return data
