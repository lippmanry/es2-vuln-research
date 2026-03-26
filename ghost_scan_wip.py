#imports
import json
import glob
import os
import re
from datetime import datetime

#base dir
output = "./output"

#grab files
files = glob.glob(os.path.join(output, f'*.json'), recursive=False)

names = {}
datas = {}
prowler_details = []
trivy_details = []
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
                    prowler_details.append({'title': title,
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
                    
        results = datas['trivy_report'].get('Results', [])
        tr_dt = datetime.fromisoformat(datas['trivy_report'].get('CreatedAt'))
        artifact = datas['trivy_report'].get('ArtifactName')
        #match prowler timestamps
        iso_report_time = int(tr_dt.timestamp())
        report_time = tr_dt.replace(tzinfo=None).isoformat()
        

        for result in results:
            #get the target location and class
            target_location = result.get('Target', 'Uknown')
            target_class = result.get('Class', 'Unknown')
            
            #get vulnerabilities
            vulnerabilities = result.get('Vulnerabilities', [])
            
            for vuln in vulnerabilities:
                #get the important stuff
                
                package = vuln.get('PkgID', 'Uknown')
                vuln_id = vuln.get('VulnerabilityID', 'Unknown')
                severity = vuln.get('Severity', 'Uknown')
                cwes = vuln.get('CweIDs', 'Unknown')
                title = vuln.get('Title', 'Unknown')
                details = vuln.get('Description', 'Unknown')

                trivy_details.append({
                                    'title':title,
                                    'time':report_time,
                                    'iso_time': iso_report_time,
                                    'artifact': artifact,
                                    'target_location': target_location,
                                    'target_class': target_class,
                                    'package': package,
                                    'vuln_id': vuln_id,
                                    'severity': severity,
                                    'cwes': cwes,
                                    'details': details
                                    })
    
            
    except json.JSONDecodeError as e:
        raise ValueError(f'Invalid JSON format: {e}')