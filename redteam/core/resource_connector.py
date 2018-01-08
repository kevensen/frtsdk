import mongoengine
import logging

MONGO_ENGINE_CONNECTOR = 4
class MongoEngineResourceConnector(object):
    def __init__(self, location, **kwargs):
        self.location = location
        self.type = MONGO_ENGINE_CONNECTOR
        self.log = None
        try:
            self.log = logging.getLogger(kwargs['logger'])
        except KeyError:
            pass

    def open(self):
        if self.log:
            self.log.debug("Mongo Engine Connector - opening location %s", self.location)
        mongoengine.connect(host=self.location)