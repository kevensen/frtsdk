from datetime import datetime
from mongoengine import Document
from mongoengine import StringField
from mongoengine import SequenceField
from mongoengine import ReferenceField
from mongoengine import ListField
from mongoengine import IntField
from mongoengine import DateTimeField
from mongoengine import URLField
from mongoengine import BooleanField
from redteamcore import HttpResourceConnector
from redteamcore import MBoxResouceConnector

class SourceStatus(Document):
    source_id = IntField(required=True)
    status = StringField(choices=['never synced', 'failed', 'success'], default='never synced')
    date = DateTimeField(required=True)

    def __init__(self, **kwargs):
        super(SourceStatus, self).__init__(**kwargs)

class Source(Document):
    section = StringField(required=True, key_word=True)
    source_id = SequenceField()
    statuses = ListField(ReferenceField(SourceStatus))
    last_status = ReferenceField(SourceStatus, required=True)
    location = URLField(required=True, unique=True)
    kind = StringField(required=True)
    tlsverify = BooleanField(required=True, default=True)

    def __init__(self, **kwargs):
        super(Source, self).__init__(**kwargs)
        data = dict(tlsverify=kwargs['tlsverify'])
        location = kwargs['location']
        if self.kind == 'url':
            self.connector = HttpResourceConnector(location, **data)
        elif self.kind == 'mbox':
            self.connector = MBoxResouceConnector(location, **data)

        if not self.last_status:
            self.last_status = SourceStatus(source_id=self.source_id,
                                            date=datetime.now())
            self.last_status.save()
            self.last_status.reload()
            # pylint: disable=E1101
            self.statuses.append(self.last_status)


    def sync(self):
        return self.connector.open()


    def set_status(self, status_string):
        self.last_status = SourceStatus(source_id=self.source_id,
                                        date=datetime.now(),
                                        status=status_string)
        self.last_status.save()
        self.last_status.reload()
        # pylint: disable=E1101
        self.statuses.append(self.last_status)

    def set_success(self):
        self.set_status('success')

    def set_failed(self):
        self.set_status('failed')

    def set_never_synced(self):
        self.set_status('never synced')

    @property
    def summary(self):
        return dict(source_id=self.source_id,
                    location=self.location,
                    last_status=self.last_status.status,
                    last_status_data=self.last_status.date)

    @property
    def source_type(self):
        # pylint: disable=E1101
        return self.section.split(':')[1]

    @property
    def source_sub_type(self):
        # pylint: disable=E1101
        return self.section.split(':')[2]

    @property
    def source_date(self):
        # pylint: disable=E1101
        return self.section.split(':')[-1]

