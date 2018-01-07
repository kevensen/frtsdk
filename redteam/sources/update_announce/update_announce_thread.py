import re
from datetime import datetime
from mongoengine import Document
from mongoengine import URLField
from mongoengine import DateTimeField
from mongoengine import ReferenceField
from mongoengine import ListField
from redteam.core import Resource
from redteam.sources.update_announce import UpdateAnnounceMessage

CVE_REGEX = re.compile(r'CVE-\d{4}-\d{1,}', re.MULTILINE)
ADVISORY_REGEX = re.compile(r'^(\s*FEDORA\-.*|\s*RHSA-.*|\s*CESA-.*)$', re.MULTILINE)

class UpdateAnnounceThread(Document, Resource):
    last_updated = DateTimeField(required=True)
    location = URLField(required=True, primary_key=True)
    messages = ListField(ReferenceField(UpdateAnnounceMessage))

    def __init__(self, **data):
        location = data['location']
        try:
            tlsverify = data['tlsverify']
            logger = data['logger']
            mbox_resource_connector = data['resource_connector']
            Resource.__init__(self, location=location,
                              tlsverify=tlsverify,
                              logger=logger,
                              resource_connector=mbox_resource_connector)
        except KeyError:
            pass
        
        Document.__init__(self)

        self.location = location
        self.last_updated = datetime.now()

    def build(self):
        built_messages = []
        for message in self.data:
            mid = message['message-id']
            if not self.has_update_announce_message(mid) and UpdateAnnounceThread.message_is_security_relevant(message):
                message_args = dict(message_id=mid,
                                    text=message.as_string(),
                                    message_date=message['date'])
                uam = UpdateAnnounceMessage(**message_args)
                uam.save()
                # pylint: disable=E1101
                self.messages.append(uam)

                built_messages.append(mid)
        return built_messages

    def update_announce_message(self, mid):
        # pylint: disable=E1101
        return UpdateAnnounceMessage.objects(message_id=mid)

    def has_update_announce_message(self, mid):
        if self.update_announce_message(mid):
            return True
        return False

    @classmethod
    def message_is_security_relevant(cls, message):
        cve_match = CVE_REGEX.search(message.as_string())
        advisory_match = ADVISORY_REGEX.search(message.as_string())
        if (cve_match or 'security' in message['subject'].lower()) and advisory_match:
            return True
        return False
