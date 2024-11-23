from dataclasses import dataclass


@dataclass
class PostgresServiceConfig:
    pool_size: int = 10
