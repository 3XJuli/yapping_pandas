from datetime import datetime
from pydantic import BaseModel


class FloatRange(BaseModel):
    min: float | None
    max: float | None

    def get_filter(self, column):
        filters = []
        if self.min:
            filters.append(column >= self.min)
        if self.max:
            filters.append(column <= self.max)
        return filters


class DatetimeRange(BaseModel):
    min: datetime | None
    max: datetime | None

    def get_filter(self, column) -> list:
        filters = []
        if self.min:
            filters.append(column >= self.min)
        if self.max:
            filters.append(column <= self.max)
        return filters


class DateTimeFilter(BaseModel):
    created_at_range: DatetimeRange | None = None
    updated_at_range: DatetimeRange | None = None

    def get_datetime_filters(self, created_at_column, updated_at_column):
        filters = []
        if self.created_at_range:
            filters += self.created_at_range.get_filter(created_at_column)
        if self.updated_at_range:
            filters += self.updated_at_range.get_filter(updated_at_column)
        return filters


class BoilerplateFilter(DateTimeFilter, BaseModel):
    pass
