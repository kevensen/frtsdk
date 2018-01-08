# -*- coding: utf-8 -*-
"""
vulnerability_data_reader
"""
import logging
from redteamcore import Resource
from redteam.sources.nvd import CveItem
from redteam.sources.nvd import NvdSource
from redteam.core import MongoEngineResourceConnector

DATA_STREAMS = {2006: dict(url='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2006.json.gz', meta='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2006.meta'),
                2007: dict(url='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2007.json.gz', meta='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2007.meta'),
                2008: dict(url='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2008.json.gz', meta='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2008.meta'),
                2009: dict(url='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2009.json.gz', meta='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2009.meta'),
                2010: dict(url='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2010.json.gz', meta='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2010.meta'),
                2011: dict(url='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2011.json.gz', meta='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2011.meta'),
                2012: dict(url='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2012.json.gz', meta='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2012.meta'),
                2013: dict(url='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2013.json.gz', meta='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2013.meta'),
                2014: dict(url='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2014.json.gz', meta='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2014.meta'),
                2015: dict(url='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2015.json.gz', meta='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2015.meta'),
                2016: dict(url='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2016.json.gz', meta='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2016.meta'),
                2017: dict(url='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2017.json.gz', meta='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2017.meta'),
                2018: dict(url='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2018.json.gz', meta='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2018.meta'),
                'recent': dict(url='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.json.gz', meta='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.meta'),
                'modified': dict(url='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.gz', meta='https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.meta')}

YEARS = [2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018]

class NvdManager(Resource):
    def __init__(self, **kwargs):
        if kwargs and kwargs['location']:
            logger = None
            if 'logger' in kwargs.keys():
                logger = kwargs['logger']
            resource_connector = MongoEngineResourceConnector(kwargs['location'], logger=logger)
            
            super(NvdManager, self).__init__(kwargs['location'], resource_connector=resource_connector)
            kwargs.pop('location')
            self.connector.open()
        self.log = None
        if kwargs and kwargs['logger']:
            self.log = logging.getLogger(kwargs['logger'])
            kwargs.pop('logger')

        self.nvd_sources = dict()
        self.tlsverify = kwargs['tlsverify']

    def build(self, force=False, alldata=False, update=False):
        total_added_cves = []
        total_modified_cves = []
        total_untouched_cves = []
        if force:
            CveItem.drop_collection()
            NvdSource.drop_collection()
        for location in self._nvd_urls(alldata=alldata, update=update):
            if not self.has_nvd_source(location):
                source = NvdSource(location=location,
                                   logger='console',
                                   tlsverify=self.tlsverify)
                added_cves, modifed_cves, untouched_cves = source.build()
                total_added_cves += added_cves
                total_modified_cves += modifed_cves
                total_untouched_cves += untouched_cves
                if alldata:
                    source.save()
        return total_added_cves, total_modified_cves, total_untouched_cves


    def _nvd_urls(self, alldata=False, update=False):
        urls = []
        if alldata:
            for year in YEARS:
                urls.append(DATA_STREAMS[year]['url'])
        else:
            urls.append(DATA_STREAMS['recent']['url'])

        if update:
            urls.append(DATA_STREAMS['modified']['url'])
        return urls

    def nvd_source(self, location):
        # pylint: disable=E1101
        return NvdSource.objects(location=location)

    def has_nvd_source(self, location):
        if self.nvd_source(location):
            return True
        return False
