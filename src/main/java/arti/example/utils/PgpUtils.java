package arti.example.utils;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Date;
import java.util.Iterator;

public class PgpUtils {

    public static Instant extractExpiryDate(String pgpContent) {
        try {
            // Obsługa formatu Armored (tekstowego)
            InputStream is = new ByteArrayInputStream(pgpContent.getBytes(StandardCharsets.UTF_8));
            InputStream decodedStream = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(is);

            PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
                    decodedStream, new JcaKeyFingerprintCalculator());

            Iterator<PGPPublicKeyRing> keyRingIter = pgpPub.getKeyRings();
            if (keyRingIter.hasNext()) {
                PGPPublicKeyRing keyRing = keyRingIter.next();
                PGPPublicKey masterKey = keyRing.getPublicKey();

                long validSeconds = masterKey.getValidSeconds();
                if (validSeconds == 0) {
                    return null; // Klucz nie wygasa
                }

                // Data stworzenia + czas ważności
                return masterKey.getCreationTime().toInstant().plusSeconds(validSeconds);
            }
        } catch (Exception e) {
            // Przy BB 63 logujemy błąd i zwracamy null, ale w produkcji warto rzucić wyjątek
            System.err.println("Błąd parsowania klucza PGP: " + e.getMessage());
        }
        return null;
    }

    public static String extractEmail(String pgpContent) {
        try {
            InputStream is = new ByteArrayInputStream(pgpContent.getBytes(StandardCharsets.UTF_8));
            InputStream decodedStream = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(is);
            PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
                    decodedStream, new JcaKeyFingerprintCalculator());

            Iterator<PGPPublicKeyRing> keyRingIter = pgpPub.getKeyRings();
            if (keyRingIter.hasNext()) {
                PGPPublicKey key = keyRingIter.next().getPublicKey();
                Iterator<String> userIds = key.getUserIDs();
                if (userIds.hasNext()) {
                    String userId = userIds.next(); // np. "Arti B <arti4077@gmail.com>"
                    if (userId.contains("<") && userId.contains(">")) {
                        return userId.substring(userId.indexOf("<") + 1, userId.indexOf(">"));
                    }
                    return userId;
                }
            }
        } catch (Exception e) {
            System.err.println("Błąd wyciągania email: " + e.getMessage());
        }
        return null;
    }

    public static byte[] encrypt(byte[] data, String publicKeyPem) throws Exception {
        // 1. Wyciągamy klucz publiczny z PEM
        InputStream keyIn = new ByteArrayInputStream(publicKeyPem.getBytes(StandardCharsets.UTF_8));
        InputStream decoderStream = PGPUtil.getDecoderStream(keyIn);
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
                decoderStream,
                new JcaKeyFingerprintCalculator()
        );
        PGPPublicKey encryptionKey = null;
        Iterator<PGPPublicKeyRing> keyRingIter = pgpPub.getKeyRings();

        while (keyRingIter.hasNext() && encryptionKey == null) {
            PGPPublicKeyRing keyRing = keyRingIter.next();
            Iterator<PGPPublicKey> keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext()) {
                PGPPublicKey k = keyIter.next();

                // WARUNEK 1: Czy biblioteka uważa, że to klucz do szyfrowania?
                // WARUNEK 2: Czy to NIE JEST klucz główny? (Klucz główny ma k.isMasterKey() == true)
                if (k.isEncryptionKey() && !k.isMasterKey()) {
                    encryptionKey = k;
                    break;
                }

                // REZERWA: Jeśli Twój klucz główny TO JEDNOCZEŚNIE klucz do szyfrowania
                if (k.isEncryptionKey() && encryptionKey == null) {
                    encryptionKey = k;
                }
            }
        }

        if (encryptionKey == null) {
            throw new IllegalArgumentException("Brak klucza zdolnego do szyfrowania w podanym bloku PGP.");
        }

        // 2. Przygotowanie strumieni
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // ArmoredOutputStream sprawi, że wynik to będzie tekstowe "-----BEGIN PGP MESSAGE-----"
        try (OutputStream armoredOut = new ArmoredOutputStream(out)) {

            // 3. Konfiguracja szyfrowania (używamy AES-256)
            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256)
                            .setWithIntegrityPacket(true)
                            .setSecureRandom(new SecureRandom()));

            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey));

            try (OutputStream encryptedOut = encGen.open(armoredOut, new byte[4096])) {
                // 4. "Literal Data" - pakowanie surowych bajtów do PGP
                PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
                try (OutputStream pOut = lData.open(encryptedOut, PGPLiteralData.BINARY, "file.dat", data.length, new Date())) {
                    pOut.write(data);
                }
            }
        }
        return out.toByteArray();
    }
    public static String extractFingerprint(String publicKeyPem) throws Exception {
        InputStream keyIn = new ByteArrayInputStream(publicKeyPem.getBytes(StandardCharsets.UTF_8));
        InputStream decoderStream = PGPUtil.getDecoderStream(keyIn);
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
                decoderStream, new JcaKeyFingerprintCalculator());

        Iterator<PGPPublicKeyRing> keyRingIter = pgpPub.getKeyRings();
        if (keyRingIter.hasNext()) {
            PGPPublicKeyRing keyRing = keyRingIter.next();
            // Fingerprint bierzemy z klucza głównego (Master Key)
            byte[] fingerprint = keyRing.getPublicKey().getFingerprint();

            // Konwersja na Hex
            StringBuilder hexString = new StringBuilder();
            for (byte b : fingerprint) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString().toUpperCase();
        }
        throw new IllegalArgumentException("Nie znaleziono klucza w bloku PGP.");
    }

    public static String transformToArmoredString(PGPPublicKeyRing ring) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ArmoredOutputStream aos = new ArmoredOutputStream(baos)) {

            // Zapisujemy cały "pierścień" (klucz główny + podklucze)
            ring.encode(aos);
            aos.close(); // Ważne: zamknięcie dopisuje stopkę -----END PGP...

            return baos.toString();
        } catch (IOException e) {
            throw new RuntimeException("Błąd podczas generowania bloku ASCII: " + e.getMessage());
        }
    }
}