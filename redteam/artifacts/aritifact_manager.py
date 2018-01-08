import logging
from redteamcore import Resource
from redteam.core import MongoEngineResourceConnector

class ArtifactManager(Resource):
    def __init__(self, **kwargs):
        if kwargs and kwargs['location']:
            logger = None
            if 'logger' in kwargs.keys():
                logger = kwargs['logger']
            resource_connector = MongoEngineResourceConnector(kwargs['location'], logger=logger)
            super(ArtifactManager, self).__init__(kwargs['location'], resource_connector=resource_connector)
            kwargs.pop('location')
            self.connector.open()
        self.log = None
        if kwargs and kwargs['logger']:
            self.log = logging.getLogger(kwargs['logger'])
            kwargs.pop('logger')