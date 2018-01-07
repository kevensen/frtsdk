import re
import os
import zlib
import gzip
import json
import mailbox
import tempfile
import logging
import requests
import mongoengine

HTTP_CONNECTOR = 0
FILE_CONNECTOR = 1
DIRECTORY_CONNECTOR = 2
MBOX_CONNECTOR = 3
MONGO_ENGINE_CONNECTOR = 4

class ResourceConnectorFactory(object):

    def __init__(self):
        pass

    @classmethod
    def location_is_url(cls, location):
        url_regex = re.compile(r'^(?:http|ftp)s?://' # http:// or https://
                               r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
                               r'localhost|' #localhost...
                               r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
                               r'(?::\d+)?' # optional port
                               r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        if url_regex.match(location):
            return True
        return False

    # @classmethod
    # def location_is_mongo(cls, location):
    #     mongo_regex = re.compile(r'^mongodb\:\/\/([_\w]+):([\w]+)@([\.\w]+):(\d+)/([_\w]+)$|^mongodb\:\/\/([\.\w]+):(\d+)/([_\w]+)$|^mongodb\:\/\/([\.\w]+)/([_\w]+)$')
    #     if mongo_regex.match(location):
    #         return True
    #     return False

    @classmethod
    def create_connector(cls, location, **kwargs):
        if location.startswith('mongodb'):
            return MongoEngineResourceConnector(location, **kwargs)
        elif ResourceConnectorFactory.location_is_url(location):
            return HttpResourceConnector(location, **kwargs)
        elif os.path.isdir(location):
            return DirectoryResourceConnector(location, **kwargs)
        else:
            return FileResourceConnector(location, **kwargs)

class HttpResourceConnector(object):
    def __init__(self, location, **kwargs):
        self.location = location
        self.type = HTTP_CONNECTOR
        self.log = None
        try:
            self.tlsverify = kwargs['tlsverify']
        except KeyError:
            self.tlsverify = True

        try:
            self.log = logging.getLogger(kwargs['logger'])
        except KeyError:
            pass
        
    def open(self):
        if self.log:
            self.log.debug("HTTP Connector - opening location %s", self.location)
        data = None
        try:
            response = requests.get(self.location, verify=self.tlsverify, stream=True)
            response.raise_for_status()
            if 'json' in response.headers.get('content-type') or 'text' in response.headers.get('content-type'):
                data = response.content
            elif 'gzip' in response.headers.get('content-type'):
                data = HttpResourceConnector._decode_compressed_content(response)
            #TODO: Maybe parse before returning?  One day?
            elif 'xml' in response.headers.get('content-type'):
                data = response.content
        except (requests.exceptions.HTTPError, zlib.error) as ex:
            raise HTTPResourceReadError(ex)
        return data

    def exists(self):
        response = requests.get(self.location, verify=self.tlsverify, stream=True)
        if response.status_code >= 299:
            return False
        return True

    def delete(self):
        pass

    @classmethod
    def _decode_compressed_content(cls, response):
        if isinstance(response, str):
            return zlib.decompress(response, zlib.MAX_WBITS|32)
        return zlib.decompress(response.content, zlib.MAX_WBITS|32)

class FileResourceConnector(object):
    def __init__(self, location, **kwargs):
        self.location = location
        self.type = FILE_CONNECTOR
        self.log = None
        try:
            self.log = logging.getLogger(kwargs['logger'])
        except KeyError:
            pass

    def open(self):
        if self.log:
            self.log.debug("File Connector - opening location %s", self.location)
        file_content = ''
        if self.location.endswith(".gz"):
            with gzip.open(self.location, 'rb') as gzip_file_obj:
                file_content = gzip_file_obj.read()
        else:
            with open(self.location, 'r') as file_obj:
                file_content = file_obj.read()
        return file_content.decode('string-escape').strip('"')

    def write(self, file_content):
        _, file_extension = os.path.splitext(self.location)
        if file_extension == '.gzip' or file_extension == '.gz':
            with gzip.open(self.location, 'wb') as gzip_file_obj:
                gzip_file_obj.write(json.dumps(file_content))
        elif file_extension == '.json':
            with open(self.location, "w") as json_file_obj:
                json.dump(file_content, json_file_obj, indent=4, sort_keys=True)
        else:
            with open(self.location, "w") as file_obj:
                file_obj.write(file_content)

    def exists(self):
        return os.path.isfile(self.location)

    def delete(self):
        os.remove(self.location)

class DirectoryResourceConnector(object):

    def __init__(self, location, **kwargs):
        self.location = location
        self.type = DIRECTORY_CONNECTOR
        self.log = None
        try:
            self.log = logging.getLogger(kwargs['logger'])
        except KeyError:
            pass

    def open(self):
        if self.log:
            self.log.debug("Directory Connector - opening location %s", self.location)
        filenames = [os.path.join(d, x)
                     for d, _, files in os.walk(self.location)
                     for x in files]
        return filenames

    def exists(self):
        return os.path.isdir(self.location)

    def delete(self):
        os.remove(self.location)

class MBoxResouceConnector(object):
    def __init__(self, location, **kwargs):
        self.location = location
        self.type = MBOX_CONNECTOR
        self.connector = ResourceConnectorFactory.create_connector(location, **kwargs)
        self.log = None
        try:
            self.log = logging.getLogger(kwargs['logger'])
        except KeyError:
            pass

    def open(self):
        if self.log:
            self.log.debug("MBox Connector - opening location %s", self.location)
        data = None
        if self.connector.type == HTTP_CONNECTOR:
            mbox_tempfile = tempfile.NamedTemporaryFile(delete=False)
            mbox_tempfile.write(self.connector.open())
            mbox_tempfile.close()
            data = mailbox.mbox(mbox_tempfile.name)
        elif self.connector.type == FILE_CONNECTOR:
            data = mailbox.mbox(self.connector.location)

        return data
        
    def exists(self):
        return self.connector.exists()

    def delete(self):
        if self.connector.type == HTTP_CONNECTOR:
            pass
        self.connector.delete()

    def write(self, data):
        mbox_file = mailbox.mbox(self.location)
        for message in data:
            mbox_file.add(message)
        mbox_file.flush()
        mbox_file.close()

class MongoEngineResourceConnector(object):
    def __init__(self, location, **kwargs):
        self.location = location
        self.type = MONGO_ENGINE_CONNECTOR
        self.log = None
        try:
            self.log = logging.getLogger(kwargs['logger'])
        except KeyError:
            pass

    def open(self):
        if self.log:
            self.log.debug("Mongo Engine Connector - opening location %s", self.location)
        mongoengine.connect(host=self.location)

class HTTPResourceReadError(Exception):
    def __init__(self, exception_type):
        if isinstance(exception_type, requests.exceptions.HTTPError):
            message = "HTTP Error Code {0}".format(exception_type.status_code)
        elif isinstance(exception_type, zlib.error):
            message = "Error decompressing the stream."
        super(HTTPResourceReadError, self).__init__(message)