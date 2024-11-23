from typing import Any
from geoalchemy2 import WKBElement
from geoalchemy2.shape import from_shape, to_shape
from shapely.geometry import shape
from geojson_pydantic.geometries import Geometry


def geojson_to_wkb_serializer(value: Geometry, handler, info):
    if info.mode == "python":
        return from_shape(shape(value), srid=4326)
    return value


def strip_none(data: dict[str, Any]) -> dict[str, Any]:
    """Remove None values from a dictionary."""
    return {k: v for k, v in data.items() if v is not None}


def wkb_to_geojson_validator(v: Any) -> Any:
    if isinstance(v, WKBElement):
        return to_shape(v).__geo_interface__
    return v
