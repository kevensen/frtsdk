from mongoengine import EmbeddedDocument
from mongoengine import StringField
from mongoengine import FloatField
from mongoengine import IntField

class Package(EmbeddedDocument):
    name = StringField(required=True)
    version = StringField(required=True)
    release_num = StringField(required=True)
    release_product = StringField(required=True)

    def __init__(self, **data):
        super(Package, self).__init__(**data)

    @property
    def fullname(self):
        release = '.'.join([self.release_num,
                            self.release_product])
        return '-'.join([self.name, 
                         self.version, 
                         release])
