import collections
import os
import json
from redteam.core import Resource

class TransformableDict(collections.MutableMapping):
    def __init__(self, *args, **kwargs):
        self.store = dict()
        self.update(dict(*args, **kwargs))  # use the free update to set keys

    def __getitem__(self, key):
        return self.store[self.__keytransform__(key)]

    def __setitem__(self, key, value):
        self.store[self.__keytransform__(key)] = value

    def __delitem__(self, key):
        del self.store[self.__keytransform__(key)]

    def __iter__(self):
        return iter(self.store)

    def __len__(self):
        return len(self.store)

    def __keytransform__(self, key):
        return key

    def json(self):
        return json.dumps(dict(self), indent=4, sort_keys=True)


class SaveableLoadableDict(TransformableDict, Resource):

    def __init__(self, *args, **kwargs):

        TransformableDict.__init__(self, *args, **kwargs)
        try:
            location = kwargs.pop('location')
            try:
                logger = kwargs.pop('logger')
            except KeyError:
                logger = None
            Resource.__init__(self, location, logger=logger, transform_cls=JSONTransformableDictEncoder)

        except KeyError:
            pass
        
        try:
            self.name = kwargs['name']
        except KeyError:
            pass

    def __setitem__(self, key, value):
        self.store[self.__keytransform__(key)] = value

        if self.__keytransform__(key) == 'name':
            self.name = value

    def save_json(self):
        _, file_extension = os.path.splitext(self.location)
        if file_extension != '.json':
            self.location.replace(file_extension, '.json')
        self.write(self.json())

class JSONTransformableDictEncoder(json.JSONEncoder):
    def default(self, obj): # pylint: disable=E0202,W0221
        if isinstance(obj, TransformableDict):
            return dict(obj)
        return json.JSONEncoder.default(self, obj)
