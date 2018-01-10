from mongoengine import StringField
from mongoengine import EmbeddedDocument
from mongoengine import URLField

class Bugzilla(EmbeddedDocument):
    bug_id = StringField(required=True, primary_key=True)
    bug_description = StringField(required=True)
    bug_url = URLField(required=True)

    @property
    def description(self):
        return self.bug_description.replace("=\n", '')

    @property
    def url(self):
        return self.bug_url.replace('3D', '')
