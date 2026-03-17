package arti.example.repository;

import arti.example.model.PublicKeyEntity;
import io.micronaut.data.annotation.Query;
import io.micronaut.data.jdbc.annotation.JdbcRepository;
import io.micronaut.data.model.query.builder.sql.Dialect;
import io.micronaut.data.repository.CrudRepository;

import java.time.Instant;
import java.util.Optional;

@JdbcRepository(dialect = Dialect.POSTGRES)
public interface PublicKeyRepository extends CrudRepository<PublicKeyEntity, Long> {

    Optional<PublicKeyEntity> findByAlias(String alias);

    // Szukamy najnowszego (id DESC), który nie wygasł LUB nie ma daty wygaśnięcia
    @Query("SELECT * FROM public_keys WHERE email = :email " +
            "AND (expires_at IS NULL OR expires_at > NOW()) " +
            "ORDER BY created_at DESC LIMIT 1")
    Optional<PublicKeyEntity> findValidKeyByEmail(String email);

    //robi to samo :)
    Optional<PublicKeyEntity> findFirstByEmailAndExpiresAtGreaterThanOrExpiresAtIsNullOrderByCreatedAtDesc(
            String email,
            Instant now
    );
    Optional<PublicKeyEntity> findByFingerprint(String fingerprint);
}