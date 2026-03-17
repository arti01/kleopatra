package arti.example.model;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.data.annotation.*;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.validation.constraints.NotBlank;
import java.time.Instant;

@Serdeable
@MappedEntity("public_keys")
public record PublicKeyEntity(
        @Id
        @GeneratedValue(GeneratedValue.Type.AUTO)
        @Nullable
        Long id,

        @NotBlank
        @MappedProperty(definition = "VARCHAR(255) UNIQUE")
        String alias,

        @Nullable
        String email,

        @NotBlank
        @MappedProperty(definition = "VARCHAR(64) UNIQUE") // DODAJ TO
        String fingerprint,

        @NotBlank
        @MappedProperty(definition = "TEXT") // To wymusi typ TEXT w Postgresie
        String publicKeyPem,

        @DateCreated
        @Nullable
        Instant createdAt,

        @Nullable
        Instant expiresAt
) {}