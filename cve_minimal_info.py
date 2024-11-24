from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import List, Optional

import requests
from neo4j import GraphDatabase
from pydantic import BaseModel

from src.services.postgres_service import PostgresService
from src.services.simulation.db_models import VulnerabilitySql

MAX_WORKER = 20

class Capec(BaseModel):
    id: str
    name: str
    prerequisites: str
    related_weakness: List[str]
    solutions: str
    summary: str


class VulnerableConfiguration(BaseModel):
    id: str
    title: str


class JSONModel(BaseModel):
    Published: datetime
    capec: Optional[List[Capec]] = None


class Description(BaseModel):
    cweId: Optional[Optional[str]] = None
    lang: Optional[str] = None
    description: Optional[str] = None
    type: Optional[str] = None


class ProblemType(BaseModel):
    descriptions: Optional[List[Description]] = None


class CVSSV3_1(BaseModel):
    baseScore: Optional[float] = None
    baseSeverity: Optional[str] = None


class Metric(BaseModel):
    cvssV3_1: Optional[CVSSV3_1] = None


class DescriptionText(BaseModel):
    lang: Optional[str] = None
    value: Optional[str] = None


class CNAContainer(BaseModel):
    title: Optional[str] = None
    metrics: Optional[List[Metric]] = None
    descriptions: Optional[List[DescriptionText]] = None


class ADPContainer(BaseModel):
    metrics: Optional[List[Metric]] = None


class Containers(BaseModel):
    cna: Optional[CNAContainer] = None
    adp: Optional[List[ADPContainer]] = None


class CVERecord(BaseModel):
    containers: Optional[Containers] = None


postgres = PostgresService(
    url="postgresql://postgres:postgres@localhost:5432/yapyap",
    model=VulnerabilitySql,
    pool_size=5
)

def useful_cve(v: VulnerabilitySql) -> bool:
    return v.cve is not None and v.score > 0.0

class Transformer:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def get_cve(self):
        query = """MATCH (f:Finding)-[:related_weakness]->(v:Vulnerability) WITH DISTINCT v.cve AS cve, f.title as title, f.severity as severity return title, severity, cve limit 50000"""

        with self.driver.session() as session:
            result = session.run(query)

            # Make Dict and only keep last
            with ThreadPoolExecutor(max_workers=MAX_WORKER) as executor:
                all_vulnerabilities = list(executor.map(lambda r: self.build_vulnerability(r["cve"], r["severity"], r["title"]),  result))
                dict_vulnerabilities = {v.cve: v for v in all_vulnerabilities}
                all_vulnerabilities = list(filter(useful_cve, dict_vulnerabilities.values()))

        postgres.add_all(all_vulnerabilities)

    def build_vulnerability(self, cve: str, severity: str, title: str) -> VulnerabilitySql:
        try:
            solution = self.fetch_cve_details(cve)
            remaining = self.fetch_cve_two(cve)
            url = f"https://cve.circl.lu/cve/{cve}"
            print(cve)

            return VulnerabilitySql(
                cve=cve,
                title=title,
                solution=solution,
                score=remaining["score"],
                severity=severity,
                description=remaining["description"],
                url=url)

        except Exception as e:
            print(e)
            return VulnerabilitySql()




    def fetch_cve_details(self, cve: str) -> str:
        base_url = f"https://cve.circl.lu/api/cve/{cve}"
        response = requests.get(base_url)
        if response.status_code == 200:
            result = JSONModel.model_validate_json(response.text)
            if result.capec:
                return result.capec[0].solutions
            else:
                return ""
        else:
            return f"Error fetching CVE details: {response.status_code}"

    def fetch_cve_two(self, cve: str):
        resp = requests.get(f"https://cveawg.mitre.org/api/cve/{cve}")
        if resp.status_code != 200:
            print(f"Failed to get CVE information: {cve}")
            return

        report = CVERecord.model_validate_json(resp.text)
        severity = "unknown"
        score = 0.0
        description = ""
        if report.containers.adp and report.containers.adp[0] and report.containers.adp[0].metrics and report.containers.adp[0].metrics[0].cvssV3_1:
            severity = report.containers.adp[0].metrics[0].cvssV3_1.baseSeverity
            score = report.containers.adp[0].metrics[0].cvssV3_1.baseScore

        if report.containers and report.containers.cna and report.containers.cna.descriptions and report.containers.cna.descriptions[0]:
            description = report.containers.cna.descriptions[0].value
        return {
            "severity": severity,
            "score": score,
            "description": description
        }


def main():
    URI = "neo4j+ssc://hackatum-one.graphdatabase.ninja:443"
    USER = "attendee12"
    PASSWORD = "EXPL$76699"

    transformer = Transformer(URI, USER, PASSWORD)
    transformer.get_cve()
    transformer.close()


if __name__ == "__main__":
    main()
