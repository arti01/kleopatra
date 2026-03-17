package arti.example.repository;

import arti.example.model.KeyImportLogEntity;
import io.micronaut.data.jdbc.annotation.JdbcRepository;
import io.micronaut.data.model.query.builder.sql.Dialect;
import io.micronaut.data.repository.CrudRepository;

@JdbcRepository(dialect = Dialect.POSTGRES)
public interface KeyImportLogRepository extends CrudRepository<KeyImportLogEntity, Long> {
}