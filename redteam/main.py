from datetime import datetime
import json
import sys
import re
from redteamcore import FRTLogger
from redteamcore import HTTPResourceReadError
from redteam.core import MongoEngineResourceConnector
from redteam import FRTConfiguration
from redteam.sources import Source
from redteam.sources import SourceStatus
from redteam.sources import CveItem
from redteam.sources import UpdateAnnounceMessage
from redteam.artifacts import CVRF
from redteam.artifacts import ProductName
from redteam.artifacts import Package
from redteam.artifacts import ProductRelationship


SEVERITIES = dict(LOW=1, MEDIUM=2, MODERATE=2, HIGH=3, CRITICAL=4, NONE=0)
CVE_REGEX = re.compile(r'CVE-\d{4}-\d{1,}', re.MULTILINE)
ADVISORY_REGEX = re.compile(r"""(^\s*FEDORA\-.*|^\s*RHSA-.*|^\s*CESA-.*)""", re.MULTILINE)
ADVISORY_DATE_REGEX = re.compile(r'^([\d]{4}-[\d]{2}-[\d]{2})[\s\d:\.]*$', re.MULTILINE)
SUMMARY_REGEX = re.compile(r'^Summary\W*(.*)$', re.MULTILINE)
PRODUCT_REGEX = re.compile(r"\s*Product\s*:\s*(.*)", re.MULTILINE)
PACAKGE_NAME_REGEX = re.compile(r"^\s*Name\s*:\s*(.*)", re.MULTILINE)
PACAKGE_VERSION_REGEX = re.compile(r"^\s*Version\s*:\s*(.*)", re.MULTILINE)
PACAKGE_RELEASE_REGEX = re.compile(r"\s*Release\s*:\s*(.*)", re.MULTILINE)
ARCH_REGEX = re.compile(r'(i386|i486|i586|i686|athlon|geode|pentium3|pentium4|x86_64|amd64|ia64|alpha|alphaev5|alphaev56|alphapca56|alphaev6|alphaev67|sparcsparcv8|sparcv9|sparc64|sparc64v|sun4|sun4csun4d|sun4m|sun4u|armv3l|armv4b|armv4larmv5tel|armv5tejl|armv6l|armv7l|mips|mipselppc|ppciseries|ppcpseries|ppc64|ppc8260|ppc8560|ppc32dy4|m68k|m68kmint|atarist|atariste|ataritt|falcon|atariclone|milan|hades|Sgi|rs6000|i370|s390x|s390|noarch)')
BUGZILLA_REGEX = re.compile(r"""(\s*\[ \d \] Bug \#(\d+) - (.+)
\s*(https:\/\/bugzilla\.redhat\.com.*))+?""", re.MULTILINE)

class RedTeam(object):
    def __init__(self, loglevel, mongo_host, mongo_port, mongodb, mongo_username=None, mongo_password=None, no_tls_verify=False):
        self.tls_verify = not no_tls_verify
        #self.basehost = basehost

        self.frt_config = FRTConfiguration()
        self.config = self.frt_config.read_config()

        self.mongo_location = 'mongodb://'
        if mongo_username and mongo_password:
            self.mongo_location += mongo_username
            self.mongo_location += ':'
            self.mongo_location += mongo_password
            self.mongo_location += '@'
        self.mongo_location += mongo_host
        self.mongo_location += ':'
        self.mongo_location += str(mongo_port)
        self.mongo_location += '/'
        self.mongo_location += mongodb

        FRTLogger.set_logging_level(loglevel)
        self.mongo_connect = MongoEngineResourceConnector(location=self.mongo_location,
                                                          tlsverify=not no_tls_verify)
        self.mongo_connect.open()

    def list_types(self):
        return self.frt_config.source_types()

    def load_sources(self, clean=False):
        if clean:
            Source.drop_collection()
            SourceStatus.drop_collection()
        for section in self.config.sections():
            if section.startswith('source:') and not RedTeam.source_exists(section):
                source = Source(section=section, 
                                location=self.config.get(section, 'location'),
                                kind=self.config.get(section, 'kind'),
                                tlsverify=self.tls_verify)
                source.save()
            elif section.startswith('source:') and RedTeam.source_exists(section):
                source = self.source_by_section(section)
                source.kind = self.config.get(section, 'kind')
                source.location = self.config.get(section, 'location')
                source.tlsverify = self.config.get(section, 'tlsverify')
                source.save()

    # pylint: disable=E1101
    def list_sources(self, status):
        if status == 'all':
            return [source.summary for source in Source.objects]
        source_statuses = SourceStatus.objects.filter(status=unicode(status)).only("source_id")
        sources = Source.objects.filter(last_status__in=source_statuses)
        return [source.summary for source in sources]

    def reset_sources(self, source_id=None):
        if source_id:
            source = Source.objects.filter(source_id=source_id).first()
            FRTLogger.debug("Resseting status for source ID %d with location %s and status %s.",
                            source.source_id,
                            source.location,
                            source.last_status.status)
            source.set_never_synced()
            source.save()
            source.reload()
            FRTLogger.debug("Status reset for source ID %d with location %s and status %s.",
                            source.source_id,
                            source.location,
                            source.last_status.status)

        else:
            for source in Source.objects:
                FRTLogger.debug("Resseting status for source ID %d with location %s and status %s.",
                                source.source_id,
                                source.location,
                                source.last_status.status)
                source.set_never_synced()
                source.save()
                source.reload()
                FRTLogger.debug("Status reset for source ID %d with location %s and status %s.",
                                source.source_id,
                                source.location,
                                source.last_status.status)



    def sync(self, never_synced=False, failed=False, success=False, source_id=None, skip_failures=False):
        sources_to_sync = []
        if never_synced:
            sources_to_sync += self.list_sources('never synced')
        if failed:
            sources_to_sync += self.list_sources('failed')
        if success:
            sources_to_sync += self.list_sources('success')
        if source_id:
            sources_to_sync.append(Source.objects.filter(source_id=source_id).first())

        # The default behavior is to sync everything that hasn't successfuly synced.
        if not never_synced and not failed and not success and not source_id:
            sources_to_sync += self.list_sources('failed')
            sources_to_sync += self.list_sources('never synced')


        while sources_to_sync:
            try:
                source = Source.objects.filter(source_id=sources_to_sync[0]['source_id']).first()
                if source.source_type == 'nvd':
                    added, modified, not_touched = RedTeam.process_cves(source.sync())
                    FRTLogger.debug('Added %d, modified %d, and didn\'t change %d CVE\'s for source %s',
                                    len(added),
                                    len(modified),
                                    len(not_touched),
                                    source.location)
                elif source.source_type == 'package-announce':
                    added_messages = RedTeam.process_messages(source.sync())
                    FRTLogger.debug("Added %d messages from source %s", len(added_messages), source.location)
                source.set_success()
                sources_to_sync.pop(0)
            except HTTPResourceReadError as e:
                FRTLogger.warn("Failed to read resource: %s", source.location)
                source.set_failed()
                if not skip_failures:
                    FRTLogger.warn("Not skipping failure.  Exiting...")
                    sys.exit(1)
                
            finally:
                source.save(cascade=True)



    @classmethod
    def source_exists(cls, section):
        if RedTeam.source_by_section(section):
            return True
        return False

    @classmethod
    def source_by_section(cls, section):
        # pylint: disable=E1101
        return Source.objects.filter(section=section).first()

    @classmethod
    def source_by_location(cls, url):
        # pylint: disable=E1101
        return Source.objects.filter(location=url).first()


    @classmethod
    def process_cves(cls, data):
        cves_added = []
        cves_modified = []
        cves_untouched = []
        
        for cve_item_def in [cveitem for cveitem in json.loads(data)['CVE_Items']]:
            cveid_to_add = cve_item_def['cve']['CVE_data_meta']['ID']
            cve_to_add_last_modified = datetime.strptime(cve_item_def['lastModifiedDate'], '%Y-%m-%dT%H:%MZ')

            if not RedTeam.has_cve_item(cveid_to_add):
                cve_item = CveItem(**cve_item_def)
                cve_item.save()
                cves_added.append(cve_item.cveid)
            elif cve_to_add_last_modified > RedTeam.cve_item(cveid_to_add).lastModifiedDate:
                cve_item = CveItem(**cve_item_def)
                cve_item.save()
                cves_modified.append(cve_item.cveid)
            else:
                cves_untouched.append(cveid_to_add)
        return cves_added, cves_modified, cves_untouched

    @classmethod
    def cve_item(cls, cveid):
        # pylint: disable=E1101
        return CveItem.objects.filter(cveid=cveid).first()

    @classmethod
    def has_cve_item(cls, cveid):
        if RedTeam.cve_item(cveid):
            return True
        return False

    @classmethod
    def process_messages(cls, data):
        built_messages = []
        for message in data:
            mid = message['message-id']
            if not RedTeam.has_update_announce_message(mid):
                try:
                    message_args = dict(message_id=mid,
                                        text=message.as_string(),
                                        message_date=message['date'])
                    uam = UpdateAnnounceMessage(**message_args)
                    uam.save()
                # TODO: There are advisories (e.g. FEDORA-EXTRAS-2006-003 with product Fedora Extras [5 devel])
                # that are not being properly processed.  Will have to revisit this.
                except AttributeError:
                    pass
                # pylint: disable=E1101
                built_messages.append(mid)
        return built_messages

    @classmethod
    def update_announce_message(cls, mid):
        # pylint: disable=E1101
        return UpdateAnnounceMessage.objects(message_id=mid)

    @classmethod
    def has_update_announce_message(cls, mid):
        if RedTeam.update_announce_message(mid):
            return True
        return False

    def cvrf_refresh(self, clean=False):
        if clean:
            CVRF.drop_collection()

        for message in UpdateAnnounceMessage.objects:
            
            try:
                advisory_id = ADVISORY_REGEX.search(message['message_text']).group(1)
                cves = list(set(CVE_REGEX.findall(message['message_text'])))
                if not cves:
                    continue
                cvrf = RedTeam.cvrf(advisory_id)
                if not cvrf:
                    cvrf = CVRF()
                    cvrf.advisory_id = advisory_id
                    cvrf.save()

                cvrf.modify(add_to_set__cves=cves)

                cvrf.modify(set__summary=SUMMARY_REGEX.search(message['message_text']).group(1))


                product_string = PRODUCT_REGEX.search(message['message_text']).group(1)
                product_name = ProductName()
                product_name.name = product_string
                cvrf.modify(add_to_set__product_names=product_name)


                rpmname = PACAKGE_NAME_REGEX.search(message['message_text']).group(1)
                rpmversion = PACAKGE_VERSION_REGEX.search(message['message_text']).group(1)
                rpmrelease = PACAKGE_RELEASE_REGEX.search(message['message_text']).group(1)

                package = Package()
                package.name = rpmname.replace(" ","").replace("\n","")
                package.version = rpmversion.replace(" ","").replace("\n","")
                try:
                    package.release_num = rpmrelease.replace(" ","").replace("\n","").split('.')[0]
                    package.release_product = rpmrelease.replace(" ","").replace("\n","").split('.')[1]
                except IndexError:
                    package.release_num = rpmrelease.replace(" ","").replace("\n","")

                cvrf.modify(add_to_set__packages=package)

                relationship = ProductRelationship()
                relationship.product_name = product_name
                relationship.package = package
                cvrf.modify(add_to_set__relationships=relationship)
                
                cvrf.modify(add_to_set__messages=message)

                cvrf.modify(set__advisory_date=datetime.strptime(ADVISORY_DATE_REGEX.search(message['message_text']).group(1), '%Y-%m-%d'))

            except AttributeError:
                pass

    @classmethod
    def cvrf(cls, advisory_id):
        return CVRF.objects.filter(advisory_id=advisory_id).first()

    @classmethod
    def has_cvrf(cls, advisory_id):
        if RedTeam.cvrf(advisory_id):
            return True
        return False

    def advisories_for_rpm(self, name, version=None, release=None):
        advisory_ids = CVRF.advisory_ids_for_rpm(package_name=name, package_version=version, package_release=release)
        return CVRF.objects.filter(advisory_id__in=advisory_ids)
        
    def cves_for_rpm(self, name, version=None, release=None):
        return list(set([cve for advisory in self.advisories_for_rpm(name, version, release) for cve in advisory.cves]))

        