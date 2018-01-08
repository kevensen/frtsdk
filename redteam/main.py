import logging
import json
from redteam import setup_console_logger
from redteam.sources.update_announce import UpdateAnnounceManager
from redteam.sources.update_announce import UpdateAnnounceMessage
from redteam.sources.nvd import NvdManager
from redteam.artifacts import ArtifactManager
from redteam.artifacts import CVRF
from redteam.artifacts import CVE

class RedTeam(object):
    def __init__(self, loglevel, mongo_host, mongo_port, mongodb, mongo_username=None, mongo_password=None, no_tls_verify=False):
        self.tls_verify = not no_tls_verify
        #self.basehost = basehost

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

        setup_console_logger(loglevel)
        self.logger = logging.getLogger("console")
        self.mongo_connect_args = dict(location=self.mongo_location,
                                  tlsverify=not no_tls_verify,
                                  logger='console')

    def build_nvd_cves(self, alldata=False, force=False, update=False):
        self.logger.info("Loading data from NVD sources.")
        nvd_manager = NvdManager(**self.mongo_connect_args)
        added_cves, updated_cves, untouched_cves = nvd_manager.build(alldata=alldata, force=force, update=update)
        self.logger.info("Finished adding %d, updating %d, and not touching %d CVE\'s from NVD sources.", len(added_cves), len(updated_cves), len(untouched_cves))

    def build_update_announce_messages(self, alldata=False, force=False, update=False):
        self.logger.info("Adding message threads and messages.")
        message_thread_manager = UpdateAnnounceManager(**self.mongo_connect_args)
        added_locations, built_messages, added_advisories = message_thread_manager.build(alldata=alldata, force=force)
        self.logger.info("Finished adding message %d messages with %d advisories from %d locations", len(built_messages), len(added_advisories), len(added_locations))
        return added_advisories

    # def build_cvrfs(self, advisory_ids_to_build):
    #     artifact_manager = ArtifactManager(**self.mongo_connect_args)

    #     if not advisory_ids_to_build:
    #         self.logger.info("No new advisories to build")
    #         return
    #     self.logger.info("Re/building %d advisories.", len(advisory_ids_to_build))
    #     for aid in advisory_ids_to_build:
    #         cvrf = CVRF(advisory_id=aid)
    #         cvrf.save()
    #     self.logger.info("Finished re/building %d advisories.", len(advisory_ids_to_build))


    def query_cvrf_index(self, page=1, per_page=1000, before_date=None, after_date=None,
                         bug=None, cve=None, severity=None, package=None, output_format='json'):

        end_message_index = page * per_page
        start_message_index = end_message_index - per_page
        # pylint: disable=E1101
        messages = UpdateAnnounceMessage.objects[start_message_index:end_message_index]
        if before_date:
            messages = messages.filter(advisory_date__lt=before_date)
        if after_date:
            messages = messages.filter(advisory_date__gt=after_date)
        if bug:
            messages = messages.filter(__raw__={'bugzillas.id': bug})
        if cve:
            messages = messages.filter(cve_list=cve)
        if package:
            messages = messages.filter(rpm_list__contains=package)
        if severity:
            messages = messages.filter(severity__contains=severity)


        return json.dumps([{message.advisory_type: message.advisory_id,
                            'released_on': message.advisory_date.isoformat(),
                            'CVEs': message.cve_list,
                            'bugzillas': [bugzilla['id'] for bugzilla in message.bugzillas],
                            'released_packages': message.rpm_list,
                            'severity': message.severity,
                            'resource_url': self.basehost + '/cvrf/' + message.advisory_id + '.' + output_format
                            } for message in messages], indent=4, sort_keys=False)
    
    def query_cvrf(self, cvrfid, output_format='json', basehost='http://localhost'):
        # pylint: disable=W0612
        artifact_manager = ArtifactManager(**self.mongo_connect_args)
        # pylint: disable=E1101
        cvrf = CVRF(cvrfid)
       
        return json.dumps(dict(cvrf), indent=4, sort_keys=False)


    def query_cve(self, cveid, output_format='json', basehost='http://localhost'):
        # pylint: disable=W0612
        artifact_manager = ArtifactManager(**self.mongo_connect_args)
        cve = CVE(cveid)
        return json.dumps(dict(cve), indent=4, sort_keys=False)

    def dump(self, datadir, output_format='all', basehost='http://localhost'):
        artifact_manager = ArtifactManager(**self.mongo_connect_args)
        advisory_ids = []
        # pylint: disable=E1101
        #uam_count = UpdateAnnounceMessage.objects.count()
        for uam in UpdateAnnounceMessage.objects.no_cache():
            print type(uam)


        #print uam_count
        # 
        # for advisory_id in advisories:
        #     cvrf = CVRF(advisory_id, data_dir=datadir, logger='console')
        #     cvrf.save_json()


