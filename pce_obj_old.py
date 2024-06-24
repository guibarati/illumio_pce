#PCE objects
#Currently not treating label groups
#code.interact(local=dict(globals(),**locals()))
import pce_ld  #_dev as pce_ld
import pce_auth
from obj_works import iplist_num_ips,rule_builder,scope_parser
from ip_check import ipv4
import code,json
from itertools import product

def login():
    global auth_creds, server,base_url_orgid,base_url
    auth_creds,base_url_orgid,base_url = pce_auth.connect()
    pce_ld.auth_creds = auth_creds
    pce_ld.base_url_orgid = base_url_orgid
    pce_ld.base_url = base_url


class Label():
    def __init__(self,href,name,key):
        self.href = href
        self.name = name
        self.type = key
    def __repr__(self):
        return f"Label(href='{self.href}', name='{self.name}', type={self.type})"


class Workload():
    def __init__(self,href,name,ips,labels):
        self.href = href
        self.name = name
        self.ips = ips
        self.labels = labels

    def match_label_all(self,search_labels):
        return all(label in self.labels for label in search_labels)

    def __repr__(self):
        return f"Workload(href='{self.href}', name='{self.name}', ips={self.ips}, labels={self.labels})"


class IPList():
    def __init__(self,href,name,num_ips):
        self.href = href
        self.name = name
        self.num_ips = num_ips
        self.type = 'IPList'

    def __repr__(self):
        return f"IPList(href='{self.href}', name='{self.name}', num_ips={self.num_ips})"


class Service():
    def __init__(self,href,name,services):
        self.href = href
        self.name = name
        self.services = services
        self.score = self.service_score(services,name)
        
    def service_score(self,services,name):
        dynamic_ports_services = ['S-HIGH-TCP-PORTS','S-HIGH-UDP-PORTS']
        all_services = ['All Services']
        items_score = 0
        for i in services:
            if 'to_port' in i:
                if i['port'] == 49152 and i['to_port'] == 65535:
                    item_score = 1
                else:
                    item_score = int(i['to_port']) - int(i['port'])
            else:
                item_score = 0
            items_score = items_score + item_score
        total_score = items_score + len(services)
        if name in dynamic_ports_services:
            total_score = 1
        if name in all_services:
            total_score = 65535
        return total_score

    def match(self,port,protocol):
        if str(protocol).lower() == 'tcp':
            protocol = 6
        if str(protocol).lower() == 'udp':
            protocol = 17
        for i in self.services:
            if 'to_port' in i:
                if port >= i['port'] and port <= i['to_port'] and protocol == i['proto']:
                    return True
            elif port == i['port'] and protocol == i['proto']:
                return True
        return False
                
                

    def __repr__(self):
        return f"Service(href='{self.href}', name='{self.name}', services={self.services}, score={self.score})"


class Rule:
    def __init__(self, href, consumer, provider,services,intrascope,obj):
        self.href = href
        self.consumer = consumer
        self.provider = provider
        self.services = services
        self.intrascope = intrascope
        self.consumer_scores = self.combination_score(obj,self.combination_m(obj,consumer))
        self.provider_scores = self.combination_score(obj,self.combination_m(obj,provider))
        self.consumer_total_score = self.total_score_m(obj,self.consumer_scores)
        self.provider_total_score = self.total_score_m(obj,self.provider_scores)
        self.service_score = self.service_score(services,obj)
        self.rule_total_score = self.rule_score(self.consumer_total_score,self.provider_total_score,self.service_score)
        

    def service_score (self,services,obj):
        services_score = 0
        item_score = 0
        for service in services:
            if isinstance(service, dict):
                if 'to_port' in service:
                    item_score = int(service['to_port']) - int(service['port'])
                    if service['port'] == 49152 and service['to_port'] == 65535:
                        item_score = 1
                else:
                    item_score = 1
            else:
                item_score = obj.get('name',service).score
            services_score += item_score
        return services_score
                    
    def rule_score(self,consumer_total_score,provider_total_score,service_score):
        rule_total_score = consumer_total_score * provider_total_score * service_score
        return rule_total_score

    def total_score_m(self,obj,cons_or_prov_scores):
        total_score = 0
        for scores in cons_or_prov_scores:
            total_score += scores['score']
        return total_score

    def combination_score(self,obj,cons_or_prov_combinations):
        comb_scores = []
        for combination in cons_or_prov_combinations:
            comb_score = {}
            score = len(obj.get_wkld_by_labels(combination))
            if 'All Workloads' in combination:
                score = len(obj.get_by_type(Workload))
            for item in combination:
                if obj.get('name',item).type == 'IPList':
                    score = score + obj.get('name',item).num_ips
            if 'All Workloads' in combination and 'Any (0.0.0.0/0 and ::/0)' in combination:
                score = len(obj.get_by_type(Workload))
            comb_score['comb'] = combination
            comb_score['score'] = score
            comb_scores.append(comb_score)
        return comb_scores

    def combination_m(self,obj,cons_or_prov):
        labels_breakdown = self.label_breakdown_m(obj,cons_or_prov)
        values = list(labels_breakdown.values())
        combinations = product(*values)
        combined_lists = [list(combination) for combination in combinations]
        return combined_lists

    def label_breakdown_m(self,obj,cons_or_prov):
        label_types = list({obj.get('name', i).type for i in cons_or_prov})
        label_type_grouping = {}
        for label_type in label_types:
            label_type_grouping[label_type] = []
            for ind_label in cons_or_prov:
                if obj.get('name',ind_label).type == label_type:
                    label_type_grouping[label_type].append(ind_label)
        return label_type_grouping

    def __repr__(self):
        return f"Rule(href={self.href}, consumer={self.consumer}, provider={self.provider}, services={self.services}, intrascope={self.intrascope},\
consumer_total_score = {self.consumer_total_score}, provider_total_score = {self.provider_total_score}, service_score = {self.service_score}, rule_total_score = {self.rule_total_score})"


class Ruleset():
    def __init__(self,href,name,scopes,rules=None):
        self.href = href
        self.name = name
        self.scopes = scopes
        self.rules = rules if rules is not None else []

    def add_rule(self, rule):
        if isinstance(rule, Rule):
            self.rules.append(rule)
        else:
            raise ValueError("Can only add instances of Rule")

    def __repr__(self):
        return f"Ruleset(href={self.href}, name={self.name}, scopes={self.scopes}, rules={self.rules})"

    

class Objects():
    def __init__(self):
        self.objs = []

    def add(self,obj):
        self.objs.append(obj)

    def get(self,attr,value,type='n'):
        if type == 'n':
            for obj in self.objs:
                if hasattr(obj,attr) and getattr(obj,attr) == value:
                    return obj
        else:
            for obj in self.objs:
                if hasattr(obj,attr) and getattr(obj,attr) == value and isinstance(obj,type):
                    return obj            
            
    def get_by_type(self, type):
        return [obj for obj in self.objs if isinstance(obj, type)]

    def get_wkld_by_labels(self, search_labels):
        return [obj for obj in self.objs if isinstance(obj, Workload) and all(label in obj.labels for label in search_labels)]

    def get_rule_by(self,attr,value):
        rules = []
        for ruleset in self.get_by_type(Ruleset):
            for rule in ruleset.rules:
                if getattr(rule,attr) == value or value in getattr(rule,attr):
                    rules.append(rule)
        return rules
            

    def print(self, type):
        r = [obj for obj in self.objs if isinstance(obj, type)]
        for i in r:
            print(i)
            print('')

  
def load_rulesets(obj):
    ruleset_list = pce_ld.get_rulesets()
    for i in ruleset_list:
        href = i['href']
        name = i['name']
        scopes = scope_parser(i['scopes'],obj)
        obj.add(Ruleset(href,name,scopes))
        rules = rule_builder(scopes,i['rules'],obj)
        for rule in rules:
            rule_obj = Rule(rule['href'],rule['consumers'],rule['providers'],rule['services'],rule['intrascope'],obj)
            obj.get('href',href).add_rule(rule_obj)


def load_labels(obj):
    label_list = pce_ld.get_labels()
    for i in label_list:
        obj.add(Label(i['href'],i['value'],i['key']))
    obj.add(Label('no-href','All Workloads','no-key'))
    


def load_workloads(obj):
    workload_list = pce_ld.get_workloads()
    for i in workload_list:
        wkld_href = i['href']
        
        if i['hostname'] != '':
            wkld_name = i['hostname']
        elif i['name'] != '':
            wkld_name = i['name']

        wkld_ips = []
        for j in i['interfaces']:
            if ipv4(j['address']):
                wkld_ips.append(j['address'])

        wkld_labels = []
        for j in i['labels']:
            wkld_labels.append(j['value'])
            
        obj.add(Workload(wkld_href,wkld_name,wkld_ips,wkld_labels))


def load_iplists(obj):
    iplist_list = pce_ld.get_iplists()
    for i in iplist_list:
        href = i['href']
        name = i['name']
        ip_ranges = i['ip_ranges']
        num_ips = iplist_num_ips(ip_ranges)
        if len(i['fqdns']) > 0:
            num_ips += len(i['fqdns'])
        obj.add(IPList(href,name,num_ips))


def load_services(obj):
    services = pce_ld.get_services()
    for i in services:
        href = i.get('href')
        name = i.get('name')
        services = i.get('service_ports',[])
        obj.add(Service(href,name,services))



#Draft methods:
def get_empty_consumer_comb(obj):
    for i in obj.get_by_type(Ruleset):
        for j in i.rules:
            for k in j.consumer_scores:
                if k['score'] == 0:
                    print(i.name)
                    print(k, ' ', j.provider, ' ', j.services, ' ',j.intrascope)
                    print('')

#login()
obj = Objects()
print('loading workloads')
load_workloads(obj)
print('loading ip lists')
load_iplists(obj)
print('loading labels')
load_labels(obj)
print('loading services')
load_services(obj)
print('loading rulesets')
load_rulesets(obj)

