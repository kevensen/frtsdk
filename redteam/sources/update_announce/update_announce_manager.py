import logging
import calendar
from datetime import datetime
from datetime import timedelta
from datetime import date
from redteam.core import Resource
from redteam.core import MBoxResouceConnector
from redteam.core import HTTPResourceReadError
from redteam.sources.update_announce import UpdateAnnounceMessage
from redteam.sources.update_announce import UpdateAnnounceThread

class UpdateAnnounceManager(Resource):
    def __init__(self, **kwargs):
        if kwargs and kwargs['location']:
            super(UpdateAnnounceManager, self).__init__(kwargs['location'])
            kwargs.pop('location')
            self.connector.open()
        self.log = None
        if kwargs and kwargs['logger']:
            self.log = logging.getLogger(kwargs['logger'])
            kwargs.pop('logger')

        self.tlsverify = kwargs['tlsverify']

        self.uam_sources = dict()

    # https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/export/announce@lists.fedoraproject.org-May-2006.mbox.gz?start=2006-05-01&end=2006-06-01
    # https://lists.centos.org/pipermail/centos-announce/2005-March.txt.gz
    def build(self, force=False, alldata=False):
        added_locations = []
        built_messages = []
        if force:
            UpdateAnnounceThread.drop_collection()
            UpdateAnnounceMessage.drop_collection()
        urls_to_query = self.fedora_urls(alldata)
        while urls_to_query:
            url = urls_to_query[0]
            self.log.debug("%d locations left to query.", len(urls_to_query))
            try:
                if not self.has_message_thread(url):
                    thread = UpdateAnnounceThread(location=url,
                                                  logger='console',
                                                  tlsverify=self.tlsverify,
                                                  resource_connector=MBoxResouceConnector(url, tlsverify=self.tlsverify)
                                                 )
                    built_messages += thread.build()
                    if alldata:
                        thread.save(cascade=True)

                    added_locations.append(url)
                urls_to_query.remove(url)
            except HTTPResourceReadError as httpex:
                self.log.warning("Unable to successfuly download from %s with message: %s  Will try again.  Use Crtrl-c to skip this source.", url, str(httpex))
            except KeyboardInterrupt:
                self.log.warning("Skipping source %s.", url)
                urls_to_query.remove(url)
        # pylint: disable=E1101
        added_advisories = UpdateAnnounceMessage.objects.filter(message_id__in=built_messages).distinct('advisory_id')
        return added_locations, built_messages, added_advisories

    def fedora_urls(self, alldata):
        urls = []
        stop_date = self._add_months(datetime.now(), 1)
        if alldata:
            start_date = date(2006, 5, 1)
        else:
            start_date = datetime.now() + timedelta(-30)

        end_date = self._add_months(start_date, 1)
        while end_date <= stop_date:
            url_first_part = datetime.strftime(start_date, 'https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/export/announce@lists.fedoraproject.org-%m-%Y.mbox.gz?start=%Y-%m-%d')
            url_second_part = datetime.strftime(end_date, 'end=%Y-%m-%d')
            url = "&".join([url_first_part, url_second_part])
            urls.append(url)
            start_date = end_date
            end_date = self._add_months(start_date, 1)
        return urls

    def centos_urls(self, alldata):
        urls = []
        stop_date = self._add_months(datetime.now(), 1)
        if alldata:
            start_date = date(2006, 5, 1)
        else:
            start_date = datetime.now() + timedelta(-30)

        end_date = self._add_months(start_date, 1)
        while end_date <= stop_date:
            url = datetime.strftime(start_date, 'https://lists.centos.org/pipermail/centos-announce/%Y-%B.txt.gz')
            urls.append(url)
            start_date = end_date
            end_date = self._add_months(start_date, 1)
        return urls

    def _add_months(self, sourcedate, months):
        month = sourcedate.month - 1 + months
        year = int(sourcedate.year + month / 12)
        month = month % 12 + 1
        day = min(sourcedate.day, calendar.monthrange(year, month)[1])
        return date(year, month, day)

    def message_thread(self, location):
        # pylint: disable=E1101
        return UpdateAnnounceThread.objects(location=location)

    def has_message_thread(self, location):
        if self.message_thread(location):
            return True
        return False
