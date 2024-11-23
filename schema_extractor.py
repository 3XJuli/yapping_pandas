from neo4j import GraphDatabase


class SchemaExtractor:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def extract_schema(self):
        query = """
        CALL db.schema.nodeTypeProperties() YIELD nodeType, propertyName, propertyTypes
        RETURN nodeType, propertyName, propertyTypes
        """
        with self.driver.session() as session:
            result = session.run(query)
            schema = {}
            for record in result:
                node = record["nodeType"]
                property_name = record["propertyName"]
                property_types = record["propertyTypes"]
                if node not in schema:
                    schema[node] = {}
                schema[node][property_name] = property_types
            return schema


def generate_models(schema):
    models = []
    for node, properties in schema.items():
        class_def = f"class {node[2:-1]}(StructuredNode):\n"
        for prop, types in properties.items():
            py_type = (
                "str" if "String" in types else "int" if "Long" in types else "float"
            )
            class_def += f"    {prop} = StringProperty()\n"
        class_def += "\n"
        models.append(class_def)
    return "\n".join(models)


def main():
    URI = "neo4j+ssc://hackatum-one.graphdatabase.ninja:443"
    USER = "attendee12"
    PASSWORD = "EXPL$76699"

    extractor = SchemaExtractor(URI, USER, PASSWORD)
    schema = extractor.extract_schema()
    extractor.close()

    # Generate Neomodel classes
    model_code = generate_models(schema)
    print(model_code)


if __name__ == "__main__":
    main()
