import logging

import pycountry

from src.gateway.v1.models.responses import Country

logger = logging.getLogger(__name__)


def country_from_alpha2(country: str) -> Country | None:
    if country is None or len(country) != 2:
        return None

    try:
        result = pycountry.countries.lookup(country)
        return Country(name=result.name, alpha_2=result.alpha_2, alpha_3=result.alpha_3)
    except LookupError as e:
        logger.error(f"Error looking up country {country}: {e}")
        return None
