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

    def get_datetime_filters(self, published_at_column):
        filters = []
        if self.created_at_range:
            filters += self.created_at_range.get_filter(published_at_column)
        return filters

class ScoreFilter(FloatRange):
    min: float = 0
    max: float = 10

    def get_score_filters(self, score):
        return self.get_filter(score)


class VulnerabilityFilter(DateTimeFilter, ScoreFilter, BaseModel):
    pass
