import collections
import os
import json

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


class SaveableLoadableDict(TransformableDict):

    def __init__(self, *args, **kwargs):
        try:
            self.type = kwargs.pop('type')
        except KeyError:
            self.type = ''
        super(SaveableLoadableDict, self).__init__(*args, **kwargs)
        try:
            self.name = kwargs['name']
        except KeyError:
            pass

    def __setitem__(self, key, value):
        self.store[self.__keytransform__(key)] = value

        if self.__keytransform__(key) == 'name':
            self.name = value

    def save_json(self, location, **kwargs):
        file_path = os.path.join(location, self.type, self.name + ".json")
        with open(file_path, 'w') as json_file_obj:
            if 'cls' in kwargs:
                json.dump(dict(self), json_file_obj, indent=4, sort_keys=True, cls=kwargs['cls'])
            else:
                json.dump(dict(self), json_file_obj, indent=4, sort_keys=True)

    @classmethod
    def load(cls, location):
        with open(location, 'r') as json_file_obj:
            data = json.load(json_file_obj)
        return cls(data)

class JSONTransformableDictEncoder(json.JSONEncoder):
    def default(self, obj): # pylint: disable=E0202,W0221
        if isinstance(obj, TransformableDict):
            return dict(obj)
        return json.JSONEncoder.default(self, obj)
