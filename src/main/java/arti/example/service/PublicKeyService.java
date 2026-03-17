package arti.example.service;

import arti.example.model.KeyImportLogEntity;
import arti.example.model.PublicKeyEntity;
import arti.example.repository.KeyImportLogRepository;
import arti.example.repository.PublicKeyRepository;
import arti.example.utils.PgpUtils;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.exceptions.HttpStatusException;
import jakarta.inject.Singleton;

import java.time.Instant;
import java.util.Optional;

@Singleton
public class PublicKeyService {

    private final PublicKeyRepository repository;
    private final KeyImportLogRepository logRepository;

    public PublicKeyService(PublicKeyRepository repository, KeyImportLogRepository logRepository) {
        this.repository = repository;
        this.logRepository = logRepository;
    }

    public PublicKeyEntity saveKey(String alias, String pgpContent) {
        String error = null;
        PublicKeyEntity savedEntity = null;

        try {
            // 1. Wyciąganie danych
            String fingerprint = PgpUtils.extractFingerprint(pgpContent);
            Instant expiryDate = PgpUtils.extractExpiryDate(pgpContent);
            String email = PgpUtils.extractEmail(pgpContent);

            // 2. Walidacja: Czy nie wygasł?
            if (expiryDate != null && expiryDate.isBefore(Instant.now())) {
                error = "Klucz już wygasł (data: " + expiryDate + ")";
            }
            // 3. Walidacja: Czy fingerprint istnieje?
            else if (repository.findByFingerprint(fingerprint).isPresent()) {
                error = "Klucz o tym fingerprincie już istnieje!";
            }
            // 4. Walidacja: Czy alias istnieje?
            else if (repository.findByAlias(alias).isPresent()) {
                error = "Alias '" + alias + "' jest już zajęty!";
            }

            if (error == null) {
                PublicKeyEntity entity = new PublicKeyEntity(
                        null, alias, email, fingerprint, pgpContent, null, expiryDate
                );
                savedEntity = repository.save(entity);
            }

        } catch (Exception e) {
            error = "Błąd techniczny PGP: " + e.getMessage();
        }

        // ZAPIS LOGU (zawsze!)
        logRepository.save(new KeyImportLogEntity(
                null,
                savedEntity, // Przekazujemy cały obiekt (lub null)
                null,        // attemptTimestamp (Micronaut uzupełni @DateCreated)
                savedEntity != null,
                error,
                alias
        ));

        if (error != null) {
            throw new HttpStatusException(HttpStatus.BAD_REQUEST, error);
        }

        return savedEntity;
    }

    public Optional<PublicKeyEntity> getKey(String alias) {
        return repository.findByAlias(alias);
    }

    public byte[] encryptFileForEmail(String email, byte[] fileData) {
        // 1. Znajdź odpowiedni klucz
        PublicKeyEntity keyEntity = repository.findValidKeyByEmail(email)
                .orElseThrow(() -> new HttpStatusException(HttpStatus.NOT_FOUND,
                        "Nie znaleziono ważnego klucza dla: " + email));

        // 2. Wywołaj magię PGP (zaraz dopiszemy to do PgpUtils)
        try {
            return PgpUtils.encrypt(fileData, keyEntity.publicKeyPem());
        } catch (Exception e) {
            throw new HttpStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Błąd podczas szyfrowania: " + e.getMessage());
        }
    }

    public byte[] encryptForEmail(String email, byte[] dataToEncrypt) {
        PublicKeyEntity key = repository.findValidKeyByEmail(email)
                .orElseThrow(() -> new HttpStatusException(HttpStatus.NOT_FOUND, "Brak klucza dla " + email));

        try {
            return PgpUtils.encrypt(dataToEncrypt, key.publicKeyPem());
        } catch (Exception e) {
            throw new RuntimeException("Szyfrowanie padło: " + e.getMessage(), e);
        }
    }
}