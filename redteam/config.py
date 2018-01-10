import os
import sys
import shutil
import ConfigParser

class FRTConfiguration(object):

    FRT_CONF_ENV = 'FRTCONFPATH'

    def __init__(self):
        if os.getenv(self.FRT_CONF_ENV):
            self.path = os.getenv(self.FRT_CONF_ENV)
        elif hasattr(sys, 'real_prefix'):
            self.path = os.path.join(sys.prefix, '.frt')
        else:
            self.path = os.path.join(os.path.expanduser("~"), '.frt')

        # In Python 2.6, the virtualenv cache is funky. 
        if not os.path.isdir(self.path):
            os.makedirs(self.path)

        self.file = os.path.join(self.path, "redteam.conf")

        dir_path = os.path.dirname(os.path.realpath(__file__))
        source_config = os.path.join(dir_path, 'config', 'redteam.conf')
        if not os.path.isfile(self.file):
            print "{0} doesn't exist".format(self.file)
            shutil.copy(source_config, self.file)
        #End workaround for funky

    def read_config(self):
        config = ConfigParser.ConfigParser()
        config.readfp(open(self.file))
        return config
            
    def source_types(self):
        config = self.read_config()
        return dict(config.items('sources'))

    def sources_by_type(self, kind):
        section_result = dict()
        config = self.read_config()
        for section in config.sections():
            if section.startswith(kind):
                section_result.update({section: dict(config.items(section))})
        return section_result
