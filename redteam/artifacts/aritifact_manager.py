import logging
from redteam.core import Resource

class ArtifactManager(Resource):
    def __init__(self, **kwargs):
        if kwargs and kwargs['location']:
            super(ArtifactManager, self).__init__(kwargs['location'])
            kwargs.pop('location')
            self.connector.open()
        self.log = None
        if kwargs and kwargs['logger']:
            self.log = logging.getLogger(kwargs['logger'])
            kwargs.pop('logger')