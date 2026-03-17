package arti.example.service;

import arti.example.model.PublicKeyEntity;
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

    public PublicKeyService(PublicKeyRepository repository) {
        this.repository = repository;
    }

    public PublicKeyEntity saveKey(String alias, String pgpContent) {
        if (repository.findByAlias(alias).isPresent()) {
            throw new HttpStatusException(HttpStatus.CONFLICT, "Alias '" + alias + "' już istnieje!");
        }
        // Wyciągamy dane z klucza PGP
        Instant expiryDate = PgpUtils.extractExpiryDate(pgpContent);
        String email = PgpUtils.extractEmail(pgpContent); // Tę metodę dodaj do PgpUtils poniżej

        PublicKeyEntity entity = new PublicKeyEntity(
                null,       // id
                alias,      // alias
                email,      // email (NOWOŚĆ)
                pgpContent, // publicKeyPem
                null,       // createdAt (Micronaut sam to uzupełni)
                expiryDate  // expiresAt
        );
        return repository.save(entity);
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