package arti.example.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.data.annotation.*;
import io.micronaut.serde.annotation.Serdeable;
import java.time.Instant;

@Serdeable
@MappedEntity("key_import_logs")
public record KeyImportLogEntity(
        @Id
        @GeneratedValue(GeneratedValue.Type.AUTO)
        @Nullable
        Long id,

        @Nullable
        @Relation(Relation.Kind.MANY_TO_ONE) // Relacja Many-to-One
        @JsonIgnoreProperties({"publicKeyPem"})
        PublicKeyEntity publicKey,

        @DateCreated
        @Nullable
        Instant attemptTimestamp,

        boolean success,

        @Nullable
        String errorMessage,

        @Nullable
        String attemptedAlias
) {}