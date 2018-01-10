from datetime import datetime
from mongoengine import Document
from mongoengine import StringField
from mongoengine import DateTimeField

class UpdateAnnounceMessage(Document):
    message_id = StringField(primary_key=True)
    message_date = DateTimeField(required=True)
    message_text = StringField()
    
    meta = {'ordering': ['-message_date'],
            'indexes': ['message_date']}

    def __init__(self, **kwargs):
        super(UpdateAnnounceMessage, self).__init__()
        if not self.message_id:
            try:
                self.message_id = kwargs['message_id']
            except KeyError:
                self.message_id = kwargs['messageId']

        if isinstance(kwargs['message_date'], datetime):
            self.message_date = kwargs['message_date']
        else:
            simple_date = kwargs['message_date']
            if '+' in simple_date:
                simple_date = simple_date.split('+')[0].strip()
            elif '-' in simple_date:
                simple_date = simple_date.split('-')[0].strip()
            try:
                self.message_date = datetime.strptime(simple_date, '%a, %d %b %Y %H:%M:%S')
            except ValueError:
                self.message_date = datetime.strptime(simple_date, '%a %b %d %H:%M:%S %Y')
        try:
            self.message_text = kwargs['text']
        except KeyError:
            self.message_text = kwargs['message_text']
