import requests, time, code
from requests.auth import HTTPBasicAuth
import urllib3
requests.packages.urllib3.disable_warnings() #type: ignore
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class IllumioPCE:

    class Collection:
        def __init__(self, name_key='name'):
            self._data = None
            self.name_key = name_key

        def set_data(self, data):
            self._data = data

        def get_data(self):
            return self._data

        def filter(self, **kwargs):
            if self._data is None:
                return []
            try:
                # Normalize the keys and values in kwargs to lowercase
                kwargs_lower = {k.lower(): v.lower() for k, v in kwargs.items()}
                # Check if all normalized keys exist in any item
                missing_keys = [k for k in kwargs_lower if not any(k in {key.lower() for key in item} for item in self._data)]
                if missing_keys:
                    return f"Key(s) not found: {', '.join(missing_keys)}"
                # Perform the filtering with normalized keys and values
                return [
                    item for item in self._data 
                    if all(k in {key.lower() for key in item} and item.get(key, '').lower() == v for k, v in kwargs_lower.items() for key in item if key.lower() == k)
                ]
            except AttributeError: #The value is not a string and cannot be converted to lowercase
                # Normalize the keys in kwargs to lowercase
                kwargs_lower = {k.lower(): v for k, v in kwargs.items()}
                # Check if all normalized keys exist in any item
                missing_keys = [k for k in kwargs_lower if not any(k in {key.lower() for key in item} for item in self._data)]
                if missing_keys:
                    return f"Key(s) not found: {', '.join(missing_keys)}"
                # Perform the filtering with normalized keys
                return [
                    item for item in self._data 
                    if all(k in {key.lower() for key in item} and item.get(key, '') == v for k, v in kwargs_lower.items() for key in item if key.lower() == k)
                ]

        def labels(self, *args):
            if self._data is None:
                return []
            
            if not all(isinstance(item, dict) and 'labels' in item for item in self._data):
                return "This collection does not support label filtering."
            
            if len(args) == 1 and isinstance(args[0], list):
                labels = [label.lower() for label in args[0]]  # Single list of labels
                match_all = True
            else:
                labels = [label.lower() for label in args]  # Separate labels
                match_all = False
            #have to check if the labels are in the workload format by having the "value" key in the dictionary
            def labels_match(workload, labels, match_all):
                workload_labels = {label['value'].lower() for label in workload.get('labels', [])}
                if match_all:
                    return all(label in workload_labels for label in labels)
                else:
                    return any(label in workload_labels for label in labels)

            return [item for item in self._data if labels_match(item, labels, match_all)]

        def href(self, identifier):
            is_href = identifier.startswith('/')
            if is_href:
                for item in self._data: #type: ignore
                    if item.get('href') == identifier:
                        return item.get(self.name_key)
            else:
                for item in self._data: #type: ignore
                    if item.get(self.name_key).lower() == identifier.lower():
                        return item.get('href')
            return None
        
        def __repr__(self):
            return repr(self._data)
        
        def __iter__(self):
            return iter(self._data if self._data is not None else [])
        
        def __getitem__(self, index):
            return self._data[index] if self._data is not None else None
        
        def __len__(self):
            return len(self._data) if self._data is not None else 0
        
        def __call__(self):
            return self._data

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
        self._vens = None

    def filter(self, attribute, **kwargs):
        collection = getattr(self, attribute)
        return collection.filter(**kwargs)
    
    def href(self, identifier):
        # Define a mapping of attribute names to the key used for the object name
        attribute_keys = {
            'workloads': 'hostname',
            'labels': 'value',
            'rulesets': 'name',
            'ip_lists': 'name',
            'services': 'name',
            'labelgroups': 'name',
            'vens': 'hostname'
        }
        # Iterate over each collection
        for attribute, key in attribute_keys.items():
            collection = getattr(self, attribute)
            result = collection.href(identifier)
            if result:
                return result
        return None  # Return None if no match is found

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
            time.sleep(1)
        url = f"{base_url}{response.json()['result']['href']}"
        response = self.session.request('GET', url, verify=False)
        del self.session.headers['Prefer']
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
    
    def get_vens(self, params=None):
        #params = {'key1': 'value1', 'key2': 'value2'}
        return self._request('GET', '/vens', params=params)

    @property
    def workloads(self):
        if self._workloads is None:
            self._workloads = self.Collection(name_key='hostname')
            self._workloads.set_data(self.get_workloads())
        return self._workloads

    @property
    def labels(self):
        if self._labels is None:
            self._labels = self.Collection(name_key='value')
            self._labels.set_data(self.get_labels())
        return self._labels

    @property
    def rulesets(self):
        if self._rulesets is None:
            self._rulesets = self.Collection()
            self._rulesets.set_data(self.get_rulesets())
        return self._rulesets

    @property
    def ip_lists(self):
        if self._ip_lists is None:
            self._ip_lists = self.Collection()
            self._ip_lists.set_data(self.get_ip_lists())
        return self._ip_lists

    @property
    def services(self):
        if self._services is None:
            self._services = self.Collection()
            self._services.set_data(self.get_services())
        return self._services

    @property
    def labelgroups(self):
        if self._labelgroups is None:
            self._labelgroups = self.Collection()
            self._labelgroups.set_data(self.get_labelgroups())
        return self._labelgroups
    
    @property
    def vens(self):
        if self._vens is None:
            self._vens = self.Collection(name_key='hostname')
            self._vens.set_data(self.get_vens())
        return self._vens





api_key = 'api_1b53c4ca7de48f01f'
api_secret = '783033263852d6756fb67e878780551c801d144ebb0b3f11cffafe20c7e62b82'
pce_url = 'https://pce235.lab.local:8443'
org_id = 1

pce = IllumioPCE(pce_url, api_key, api_secret, org_id)