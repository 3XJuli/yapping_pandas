from alembic_utils.pg_extension import PGExtension

postgis = PGExtension(schema="public", signature="postgis")
postgis_raster = PGExtension(schema="public", signature="postgis_raster")
