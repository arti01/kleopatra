package arti.example.service;

import arti.example.model.KeyImportLogEntity;
import arti.example.model.PublicKeyEntity;
import arti.example.repository.KeyImportLogRepository;
import arti.example.repository.PublicKeyRepository;
import arti.example.utils.PgpUtils;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.exceptions.HttpStatusException;
import io.micronaut.transaction.TransactionDefinition;
import io.micronaut.transaction.annotation.Transactional;
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

    public KeyImportLogEntity saveKey(String alias, String pgpContent) {
        String error = null;
        PublicKeyEntity existingOrSavedEntity = null;

        try {
            String fingerprint = PgpUtils.extractFingerprint(pgpContent);
            Instant expiryDate = PgpUtils.extractExpiryDate(pgpContent);
            String email = PgpUtils.extractEmail(pgpContent);

            // 1. Walidacja: Czy nie wygasł?
            if (expiryDate != null && expiryDate.isBefore(Instant.now())) {
                error = "Klucz już wygasł (data: " + expiryDate + ")";
            }
            else {
                // 2. Szukamy duplikatu po fingerprincie
                var duplicateFingerprint = repository.findByFingerprint(fingerprint);
                if (duplicateFingerprint.isPresent()) {
                    error = "Klucz o tym fingerprincie już istnieje!";
                    existingOrSavedEntity = duplicateFingerprint.get(); // ŁĄCZYMY Z ISTNIEJĄCYM
                }
                else {
                    // 3. Szukamy duplikatu po aliasie
                    var duplicateAlias = repository.findByAlias(alias);
                    if (duplicateAlias.isPresent()) {
                        error = "Alias '" + alias + "' jest już zajęty!";
                        existingOrSavedEntity = duplicateAlias.get(); // ŁĄCZYMY Z ISTNIEJĄCYM
                    }
                }
            }

            // Jeśli nie ma błędów, zapisujemy nowy
            if (error == null) {
                PublicKeyEntity entity = new PublicKeyEntity(
                        null, alias, email, fingerprint, pgpContent, null, expiryDate
                );
                existingOrSavedEntity = repository.save(entity);
            }

        } catch (Exception e) {
            error = "Błąd techniczny PGP: " + e.getMessage();
            e.printStackTrace();
        }

        // ZAPIS LOGU - teraz existingOrSavedEntity może być kluczem z bazy LUB nowym kluczem
        return saveLogIndependent(existingOrSavedEntity, error, alias);
    }

    @Transactional(propagation = TransactionDefinition.Propagation.REQUIRES_NEW)
    public KeyImportLogEntity saveLogIndependent(PublicKeyEntity entity, String error, String alias) {
        try {
            //System.out.println(">>> PRÓBA ZAPISU LOGU DLA ALIASU: " + alias);

            KeyImportLogEntity log = new KeyImportLogEntity(
                    null,
                    entity,
                    null, // importDate - upewnij się, że w bazie to TIMESTAMP
                    error == null,
                    error,
                    alias
            );

            // Tutaj może nastąpić wybuch, jeśli pola się nie zgadzają!
            return logRepository.save(log);

        } catch (Exception e) {
            System.err.println("!!! KRYTYCZNY BŁĄD PODCZAS ZAPISU LOGU !!!");
            System.err.println("Wiadomość: " + e.getMessage());
            e.printStackTrace(); // To pokaże nam brakujące kolumny w SQL
            return null;
        }
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