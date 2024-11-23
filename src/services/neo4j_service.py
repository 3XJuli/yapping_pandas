import logging
from typing import List

from requests import get
from neo4j import GraphDatabase

from src.services.postgres_service import SingletonService
from src.settings import APP_SETTINGS

logger = logging.getLogger(__name__)


class Neo4JService(SingletonService):
    def __init__(self, driver: GraphDatabase | None = None) -> None:
        self.driver = driver or GraphDatabase.driver(APP_SETTINGS.neo4j_url,
                                                     auth=(APP_SETTINGS.neo4j_user.user, APP_SETTINGS.neo4j_password))

    def find_Node_By_Id(self, id):
        with self.driver.session() as session:
            node = session.run(f'''MATCH (n) WHERE id(n)={id} RETURN n''')
            return node.single()

    def fetch_connections_by_type(self, intial_nodes_by_type):
        with self.driver.session() as session:
            results = session.run(f'MATCH (n:{intial_nodes_by_type})-[r]->(m) RETURN n, type(r), m')
            connections = [{'node': record['n'], 'relationship_type': record['type(r)'], 'connected_node': record['m']}
                           for
                           record in results]
            return connections

    def fetch_connections_by_id(self, id):
        with self.driver.session() as session:
            results = session.run(f'MATCH (n)-[r]->(m) WHERE id(n)={id} RETURN n, type(r), m')
            connections = [{'node': record['n'], 'relationship_type': record['type(r)'], 'connected_node': record['m']}
                           for
                           record in results]
            return connections

    def fetch_connections_by_id_rev_and_source(self, id, source):
        with self.driver.session() as session:
            results = session.run(f'MATCH (n)<-[r]-(m:{source}) WHERE id(n)={id} RETURN n, type(r), m, elementId(m)')
            connections = [{'node': record['n'], 'relationship_type': record['type(r)'], 'connected_node': record['m'],
                            'connected_elementId': record['elementId(m)']}
                           for
                           record in results]
            return connections

    def fetch_connections_for_incidents(self, intial_nodes):
        with self.driver.session() as session:
            return session.run(f"MATCH (n:{intial_nodes})-[r]->(m) RETURN n, type(r), m")

    def find_Node_By_type(self, type):
        with self.driver.session() as session:
            results = session.run(f'''MATCH (n:{type}) RETURN n''')
            return [record['n'] for record in results]

    def find_Node_By_type_and_parameter(self, type, parameter):
        with self.driver.session() as session:
            results = session.run(f'''MATCH (n:{type}) WHERE n.status = {parameter} RETURN n''')
            results = [record['n'] for record in results]
            return results

    def find_infected_softwareInstallation_from_CVE(self, cve_id):
        with self.driver.session() as session:
            try:
                cve = fetch_cve_details(cve_id)
                cpes = cve['vulnerable_configuration']
                if len(cpes) == 0:
                    print("No CPES found")
                    return "No CPES found"
            except:
                return "Error with CVE"
            vulnerable_SoftwareInstallation = []
            for cpe in cpes:
                publisher, product, version = fetch_information_from_cpe(cpe['id'])
                results = session.run(
                    f'''MATCH (c:SoftwareInstallation) WHERE toLower(c.publisher)=toLower("{publisher}") AND toLower(c.product)= toLower("{product}") AND toLower(c.version)="{version}" RETURN elementId(c)''')
                records = [record['elementId(c)'] for record in results]
                if len(records) != 0:
                    vulnerable_SoftwareInstallation.append(records)
                    print(f"CVE Found with ID:{cve_id}")
                    print(f"CVE Found with publisher: {publisher},product: {product}, version: {version}")
            return vulnerable_SoftwareInstallation

    def get_system_provider(self, system_id) -> str:
        provider = self.fetch_connections_by_id_rev_and_source(system_id, "ServiceProvider")
        if len(provider) == 0:
            return "No Provider specified"

        return provider[0]['connected_node']['name']

    # return country codes ISO-3166-2
    def get_system_location(self, system_id) -> List[str]:
        countries = self.fetch_connections_by_id_rev_and_source(system_id, "Country")
        return [country['connected_node']['cc'] for country in countries]


def fetch_cve_details(cve_id):
    base_url = f"https://cve.circl.lu/api/cve/{cve_id}"
    response = get(base_url)
    if response.status_code == 200:
        return response.json()
    else:
        return f"Error fetching CVE details: {response.status_code}"


def convert_cpe2to3(cpe):
    base_url = f"https://cve.circl.lu/api/cpe2.3/{cpe}"
    response = get(base_url)
    if response.status_code == 200:
        return response.json()
    else:
        return f"Error fetching CVE details: {response.status_code}"


def fetch_information_from_cpe(cpe):
    fields = cpe.split(":")
    if fields[1] == "2.3":
        # part = fields[2]
        publisher = fields[3]  # if fields[3] != "*" else '''~ ".*" '''
        product = fields[4]  # if fields[4] != "*" else '''~ ".*" '''
        version = fields[5]  # if fields[4].__contains__("*") else '''~ ".*" '''
    else:
        fields = cpe[5:].split(":")
        publisher = fields[1]
        product = fields[2]
        version = fields[3]
    return publisher, product, version
