"""Read id and text from a Postgres table. The session is read-only."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from ..exceptions import ConfigurationError
from ..models.memory import MemoryRecord
from .source import DEFAULT_BATCH_SIZE, missing_extra, quote_ident, take, to_record


class PgVectorScanSource:
    """`SELECT` an id column and a text column from a Postgres table.

    The session is read-only. Pass `connection` in tests: it should look
    like a psycopg connection. Otherwise `dsn` opens a new connection with
    `default_transaction_read_only=on`.
    """

    def __init__(
        self,
        *,
        dsn: str | None = None,
        table: str,
        text_column: str,
        id_column: str = "id",
        connection: Any | None = None,
    ) -> None:
        """Name the table and columns, and how to connect.

        Args:
            dsn: Postgres connection string. Required unless `connection`
                is set.
            table: Table name. `schema.table` is allowed. Quoted before use.
            text_column: Column that holds the memory text. Quoted before use.
            id_column: Column that holds the record id. Default `"id"`.
            connection: An open connection. When set, `dsn` is not used and
                the caller keeps ownership of the connection.

        Raises:
            ConfigurationError: `connection` is omitted and `dsn` is missing,
                or a name is not a safe SQL identifier.
        """
        if connection is None and not dsn:
            raise ConfigurationError("pgvector scan needs --dsn.")
        self._dsn = dsn
        self._table = quote_ident(table)
        self._text_column = quote_ident(text_column)
        self._id_column = quote_ident(id_column)
        self._connection = connection

    def records(
        self, *, batch_size: int = DEFAULT_BATCH_SIZE, sample: int | None = None
    ) -> Iterator[MemoryRecord]:
        """Yield each row as a `MemoryRecord`.

        Args:
            batch_size: Rows fetched per round trip when the cursor supports
                `fetchmany`. Default 500.
            sample: Stop after this many rows. Applied as `LIMIT` in SQL
                when this object opened the connection.

        Returns:
            An iterator of records. A `None` text cell becomes an empty string.

        Raises:
            ConfigurationError: `psycopg` is not installed, or the query fails.
        """
        if self._connection is not None:
            yield from take(
                self._stream(self._connection, batch_size=batch_size, sample=sample),
                sample=None,
            )
            return
        try:
            import psycopg
        except ImportError as exc:
            raise missing_extra("pgvector", "pgvector") from exc
        try:
            with psycopg.connect(
                self._dsn,
                options="-c default_transaction_read_only=on",
            ) as conn:
                yield from take(
                    self._stream(conn, batch_size=batch_size, sample=sample),
                    sample=None,
                )
        except ConfigurationError:
            raise
        except Exception as exc:
            raise ConfigurationError(f"Postgres scan failed: {exc}") from exc

    def _stream(self, conn: Any, *, batch_size: int, sample: int | None) -> Iterator[MemoryRecord]:
        sql = f"SELECT {self._id_column}, {self._text_column} FROM {self._table}"
        params: tuple[Any, ...] = ()
        if sample is not None:
            sql += " LIMIT %s"
            params = (int(sample),)
        execute = getattr(conn, "execute", None)
        if callable(execute):
            try:
                execute("SET TRANSACTION READ ONLY")
            except Exception:
                pass
        cursor_factory = conn.cursor
        try:
            cursor = cursor_factory(name="memorysec_scan")
        except TypeError:
            cursor = cursor_factory()
        with cursor as cur:
            if params:
                cur.execute(sql, params)
            else:
                cur.execute(sql)
            fetchmany = getattr(cur, "fetchmany", None)
            if callable(fetchmany):
                while True:
                    rows = fetchmany(batch_size)
                    if not rows:
                        break
                    for row in rows:
                        yield _row_to_record(row)
                return
            for row in cur:
                yield _row_to_record(row)


def _row_to_record(row: Any) -> MemoryRecord:
    if isinstance(row, dict):
        memory_id = next(iter(row.values()))
        content = list(row.values())[1] if len(row) > 1 else ""
    else:
        memory_id = row[0]
        content = row[1] if len(row) > 1 else ""
    return to_record(memory_id, "" if content is None else str(content))


__all__ = ["PgVectorScanSource"]
