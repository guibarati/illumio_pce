import requests, time, code
from requests.auth import HTTPBasicAuth
import urllib3
requests.packages.urllib3.disable_warnings() #type: ignore
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class IllumioPCE:
    def __init__(self, pce_url, api_key, api_secret, org_id=1):
        self.pce_url = pce_url
        self.api_key = api_key
        self.api_secret = api_secret
        self.org_id = org_id
        self.session = requests.Session()
        self.session.auth = HTTPBasicAuth(api_key, api_secret)
        self.session.headers.update({'Accept': 'application/json'})
        self._workloads = None
        self._labels = None
        self._rulesets = None
        self._ip_lists = None
        self._services = None

    def filter(self, attribute, **kwargs):
        data = getattr(self, attribute)
        return [item for item in data if all(item.get(k) == v for k, v in kwargs.items())]

    def _request(self, method, endpoint, **kwargs):
        base_url = f"{self.pce_url}/api/v2"
        base_url_orgid = f"{base_url}/orgs/{self.org_id}"
        url = f"{base_url_orgid}{endpoint}"
        response = self.session.request(method, url, verify=False, **kwargs)
        response.raise_for_status()
        if method == 'GET':
            total_objects = int(response.headers.get('X-Total-Count')) #type: ignore
            total_returned = len(response.json())
            if total_objects > total_returned:
                response = self._async_request(url, **kwargs)
        return response.json()
        
    def _async_request(self, url, **kwargs):
        base_url = f"{self.pce_url}/api/v2"
        self.session.headers.update({'Prefer': 'respond-async'})
        response = self.session.request('GET', url, verify=False, **kwargs)
        async_job = response.headers['location']
        async_status = 'in_progress'
        url = f'{base_url}{async_job}'
        while async_status != 'done':
            response = self.session.request('GET', url, verify=False)
            async_status = response.json()['status']
            time.sleep(5)
        url = f'{base_url}{response.json()['result']['href']}'
        response = self.session.request('GET', url, verify=False)
        return response

    def get_workloads(self, params=None):
        #params = {'key1': 'value1', 'key2': 'value2'}
        return self._request('GET', '/workloads', params=params)

    def get_labels(self, params=None):
        #params = {'key1': 'value1', 'key2': 'value2'}
        return self._request('GET', '/labels', params=params)

    def get_rulesets(self, params=None):
        #params = {'key1': 'value1', 'key2': 'value2'}
        return self._request('GET', '/sec_policy/draft/rule_sets', params=params)

    def get_ip_lists(self, params=None):
        #params = {'key1': 'value1', 'key2': 'value2'}
        return self._request('GET', '/sec_policy/draft/ip_lists', params=params)

    def get_services(self, params=None):
        #params = {'key1': 'value1', 'key2': 'value2'}
        return self._request('GET', '/sec_policy/draft/services', params=params)

    def get_labelgroups(self, params=None):
        #params = {'key1': 'value1', 'key2': 'value2'}
        return self._request('GET', '/sec_policy/draft/label_groups', params=params)

    @property
    def workloads(self):
        if not self._workloads:
            self._workloads = self.get_workloads()
        return self._workloads
    
    @property
    def labels(self):
        if not self._labels:
            self._labels = self.get_labels()
        return self._labels
    
    @property
    def rulesets(self):
        if not self._rulesets:
            self._rulesets = self.get_rulesets()
        return self._rulesets
    
    @property
    def ip_lists(self):
        if not self._ip_lists:
            self._ip_lists = self.get_ip_lists()
        return self._ip_lists
    
    @property
    def services(self):
        if not self._services:
            self._services = self.get_services()
        return self._services
    
    @property
    def labelgroups(self):
        if not self._labelgroups:
            self._labelgroups = self.get_labelgroups()
        return self._labelgroups




api_key = 'api_1b53c4ca7de48f01f'
api_secret = '783033263852d6756fb67e878780551c801d144ebb0b3f11cffafe20c7e62b82'
pce_url = 'https://pce235.lab.local:8443'
org_id = 1

pce = IllumioPCE(pce_url, api_key, api_secret, org_id)