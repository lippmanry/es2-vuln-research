#imports
import json
import glob
import os
import re

#base dir
output = "./output"

#grab files
files = glob.glob(os.path.join(output, f'*.json'), recursive=False)

names = {}
datas = {}
prowler_details = {}
for f in files:
    #dynamically assign names
    name = re.match(r'^.+\\(\w+)', f).group(1)
    
    #open files, assign these datas to nested dictionary :)
    try:
        with open(f, "r") as file:
            data = json.load(file)
            datas.update({name:data})
            
            #check prowler's status report
            if 'prowler' in name and datas[name][0].get('status_code').lower() == 'fail':
                    
                    #exposure variable, maybe for later
                    is_publicly_exposed = True
                    
                    #keep the important bits
                    message = datas[name][0].get('status_detail')
                    mitre_exploit = datas['prowler'][0].get('unmapped', {}).get('compliance',{}).get('MITRE-ATTACK')
                    ISO = datas['prowler'][0].get('unmapped', {}).get('compliance',{}).get('ISO27001-2022')
                    SOC2 = datas['prowler'][0].get('unmapped', {}).get('compliance',{}).get('SOC2')
                    time = datas['prowler'][0].get('time_dt')
                    iso_time = datas['prowler'][0].get('time')
                    title = datas['prowler'][0].get('finding_info',{}).get('title')
                    severity = datas['prowler'][0].get('severity',{})
                    instance_id = datas['prowler'][0].get('resources',[{}])[0].get('name')
                    remediation = datas['prowler'][0].get('remediation',{}).get('desc')
                    
                    #add to dictionary
                    prowler_details.update({'title': title,
                                            'time': time,
                                            'iso_time': iso_time,
                                            'instance_id': instance_id,
                                            'publicly_exposed': is_publicly_exposed,
                                            'severity': severity,                                            
                                            'mitre_techniques': mitre_exploit,
                                            'ISO27001': ISO,
                                            'SOC2': SOC2,
                                            'details': message,
                                            'remediation': remediation})
                    
            
    except json.JSONDecodeError as e:
        raise ValueError(f'Invalid JSON format: {e}')