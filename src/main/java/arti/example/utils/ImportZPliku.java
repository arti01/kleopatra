package arti.example.utils;

import arti.example.service.PublicKeyService;
import io.micronaut.context.annotation.Prototype;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Iterator;

@Prototype
public class ImportZPliku {
    private final PublicKeyService publicKeyService;

    public ImportZPliku(PublicKeyService publicKeyService) {
        this.publicKeyService = publicKeyService;
    }

    public ImportSummary wykonaj(String trescPliku) {
        long total = 0;
        long success = 0;
        long failed = 0;

        try {
            InputStream is = PGPUtil.getDecoderStream(new ByteArrayInputStream(trescPliku.getBytes()));
            PGPPublicKeyRingCollection collection = new PGPPublicKeyRingCollection(is, new JcaKeyFingerprintCalculator());

            Iterator<PGPPublicKeyRing> ringIterator = collection.getKeyRings();
            while (ringIterator.hasNext()) {
                total++;
                PGPPublicKeyRing ring = ringIterator.next();
                try {
                    String armored = PgpUtils.transformToArmoredString(ring);
                    String aliasRoboczy = "IMPORT_" + System.currentTimeMillis() + "_" + total;

                    var log = publicKeyService.saveKey(aliasRoboczy, armored);

                    if (log.success()) {
                        success++;
                    } else {
                        failed++;
                    }
                } catch (Exception e) {
                    failed++; // Błąd przy transformacji pojedynczego klucza
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Błąd kontenera: " + e.getMessage());
        }
        return new ImportSummary(total, success, failed);
    }

    public static record ImportSummary(long total, long success, long failed) {
        public long ignored() { return total - success - failed; }
    }
}