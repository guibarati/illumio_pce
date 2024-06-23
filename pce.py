import requests
from requests.auth import HTTPBasicAuth


class IllumioPCE:
    def __init__(self, pce_url, api_key, api_secret, org_id=1):
        self.pce_url = pce_url
        self.api_key = api_key
        self.api_secret = api_secret
        self.org_id = org_id
        self.session = requests.Session()
        self.session.auth = HTTPBasicAuth(api_key, api_secret)
        self.session.headers.update({'Accept': 'application/json'})

    def _request(self, method, endpoint, **kwargs):
        url = f"{self.pce_url}/api/v2/orgs/{self.org_id}{endpoint}"
        response = self.session.request(method, url, **kwargs)
        response.raise_for_status()
        return response.json()

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
        return self._request('GET', '/ip_lists', params=params)

    def get_services(self, params=None):
        #params = {'key1': 'value1', 'key2': 'value2'}
        return self._request('GET', '/services', params=params)