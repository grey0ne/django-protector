"""
    All this SQL is terribly horribly wrong.
    Django devs decided to get rid of subqueries in extra/tables
    https://djangosnippets.org/snippets/236/
    https://code.djangoproject.com/ticket/7907
    Explaining that raw() could replace it completely, but is doesn't.
    So we got what we've got. I am kinda hate those guys now.
    Also, there are some minor performance issues on pre 5.5 MySQL,
    because it can't do const subquery
"""


class Query(object):
    """
        Class helps to construct a custom SQL query
        It holds params to pass to ORM in array
    """
    conditions = None
    params = None
    fields = None
    tables = None

    def __init__(self, conditions=None, params=None, fields=None, tables=None):
        self.conditions = conditions or []
        self.params = params or {}
        self.fields = fields or []
        self.tables = tables or []

    def get_query(self):
        conditions_string = ") AND (".join(self.conditions)
        tables_string = ", ".join(self.tables)
        fields_string = ", ".join(self.fields)
        result = "SELECT {fields!s} FROM {tables!s}".format(
            fields=fields_string,
            tables=tables_string
        )
        if self.conditions:
            result += " WHERE({conditions!s})".format(conditions=conditions_string)
        return result

    def get_raw_query(self):
        return self.get_query().format(**self.params)
