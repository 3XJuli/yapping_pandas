from neo4j import GraphDatabase
import requests
import json

def fetch_cve_details(cve_id):
    base_url = f"https://cve.circl.lu/api/cve/{cve_id}"
    response = requests.get(base_url)
    if response.status_code == 200:
        return response.json()
    else:
        return f"Error fetching CVE details: {response.status_code}"

def convert_cpe2to3(cpe):
    base_url = f"https://cve.circl.lu/api/cpe2.3/{cpe}"
    response = requests.get(base_url)
    if response.status_code == 200:
        return response.json()
    else:
        return f"Error fetching CVE details: {response.status_code}"

def fetch_information_from_cpe(cpe):
    fields = cpe.split(":")
    if fields[1]=="2.3":
        #part = fields[2]
        publisher = fields[3] #if fields[3] != "*" else '''~ ".*" '''
        product = fields[4] #if fields[4] != "*" else '''~ ".*" '''
        version = fields[5] #if fields[4].__contains__("*") else '''~ ".*" '''
    else:
        fields = cpe[5:].split(":")
        publisher = fields[1]
        product = fields[2]
        version = fields[3]
    return publisher,product,version





URI = "neo4j+s://hackatum-one.graphdatabase.ninja:443"
AUTH = ("attendee12", "EXPL$76699")


def find_Node_By_Id (session,id):
    node=session.run(f'''MATCH (n) WHERE id(n)={id} RETURN n''')
    return node.single()

def fetch_connections_by_type(session, intial_nodes_by_type):
    results = session.run(f"MATCH (n:{intial_nodes_by_type})-[r]->(m) RETURN n, type(r), m")
    connections = [{'node': record['n'], 'relationship_type': record['type(r)'], 'connected_node': record['m']} for record in results]
    return connections

def fetch_connections_by_id(session, id):
    results = session.run(f"MATCH (n)-[r]->(m) WHERE id(n)={id} RETURN n, type(r), m")
    connections = [{'node': record['n'], 'relationship_type': record['type(r)'], 'connected_node': record['m']} for record in results]
    return connections

def fetch_connections_for_incidents(session, intial_nodes):
    results = session.run(f"MATCH (n:{intial_nodes})-[r]->(m) RETURN n, type(r), m")
    return results

def find_Node_By_type (session,type):
    results=session.run(f'''MATCH (n:{type}) RETURN n''')
    results = [record['n'] for record in results]
    return results

def find_Node_By_type_and_parameter (session,type,parameter):
    results=session.run(f'''MATCH (n:{type}) WHERE n.status = {parameter} RETURN n''')
    results = [record['n'] for record in results]
    return results


def find_infected_softwareInstallation_from_CVE(session,cve_id):
    try:
        cve=fetch_cve_details(cve_id)
        cpes=cve['vulnerable_configuration']
        if len(cpes)==0:
            print("No CPES found")
            return "No CPES found"
    except:
        return "Error with CVE"
    vulnerable_SoftwareInstallation=[]
    for cpe in cpes:
        publisher,product,version=fetch_information_from_cpe(cpe['id'])
        results = session.run(f'''MATCH (c:SoftwareInstallation) WHERE toLower(c.publisher)=toLower("{publisher}") AND toLower(c.product)= toLower("{product}") AND toLower(c.version)="{version}" RETURN elementId(c)''')
        records = [record['elementId(c)'] for record in results]
        if len(records) != 0:
            vulnerable_SoftwareInstallation.append(records)
            print(f"CVE Found with ID:{cve_id}")
            print(f"CVE Found with publisher: {publisher},product: {product}, version: {version}")
    return vulnerable_SoftwareInstallation










with GraphDatabase.driver(URI, auth=AUTH) as driver:
    driver.verify_connectivity()
    sess = driver.session()

    #incidents=find_Node_By_type(sess,"Incident")
    #neighbors=fetch_connections_by_type(sess,"Incident")
    #node=fetch_connections_by_id(sess,11975044)

    #print([inc['n'] for inc in incidents])
    #print(fetch_connections_for_incidents(sess,incidents))
    #neighbors=fetch_connections_for_incidents(sess,"Incident").data()
    #print(neighbors)
    #print(incidents)
    #print(node)
    #print(fetch_cve_details("CVE-2024-39300"))
    #print(convert_cpe2to3("cpe:/a:cpuid:cpu-z:1.88.0.0"))
    #SoftwareInstallation=find_Node_By_type_and_parameter(sess,"SoftwareInstallation","key")
    cve_to_software_map = {}
    results=sess.run(f'''MATCH (n:Vulnerability) RETURN n.cve''')
    cves = [record['n.cve'] for record in results]
    #cves=["CVE-2024-8386"]
    #print(len(cves))
    # for i,cve in enumerate(cves):
    #     print(find_infected_softwareInstallation_from_CVE(sess,cve))
    #     i=i+1
    #     if (i==10000):
    #         break
    for i, cve_id in enumerate(cves):
        try:
            software_list = find_infected_softwareInstallation_from_CVE(sess, cve_id)
            cve_to_software_map[cve_id] = software_list
            print(f"Processed CVE {i}/{len(cves)}: {cve_id}")
        except Exception as e:
            print(f"Error processing CVE {cve_id}: {e}")

        #if i == 50:  # Limit to 10,000 CVEs
            #break
        i=i+1

    # Save the results to a JSON file
    with open('cve_to_software_map.json', 'w') as json_file:
        json.dump(cve_to_software_map, json_file, indent=4)
    print("Results saved to cve_to_software_map.json")




