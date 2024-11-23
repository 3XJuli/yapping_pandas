from neo4j import GraphDatabase
import requests

def fetch_cve_details(cve_id):
    base_url = f"https://cve.circl.lu/api/cve/{cve_id}"
    response = requests.get(base_url)
    if response.status_code == 200:
        return response.json()
    else:
        return f"Error fetching CVE details: {response.status_code}"


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
    print(fetch_cve_details("CVE-2024-39300"))




