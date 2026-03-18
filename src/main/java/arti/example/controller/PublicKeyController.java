package arti.example.controller;

import arti.example.model.KeyImportLogEntity;
import arti.example.model.PublicKeyEntity;
import arti.example.service.PublicKeyService;
import arti.example.utils.ImportZPliku;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.*;

import java.nio.charset.StandardCharsets;

@Controller("/keys")
public class PublicKeyController {

    private final PublicKeyService service;
    private final ImportZPliku importer; // Wstrzyknij w konstruktorze!

    public PublicKeyController(PublicKeyService service, ImportZPliku importer) {
        this.service = service;
        this.importer = importer;
    }
    @Consumes(MediaType.TEXT_PLAIN)
    @Post("/import/{alias}")
    public HttpResponse<KeyImportLogEntity> addKey(String alias, @Body String keyContent) {
        KeyImportLogEntity log = service.saveKey(alias, keyContent);

        // Jeśli zapis się udał (success == true), zwracamy 201 i log
        if (log.success()) {
            return HttpResponse.created(log);
        }

        // Jeśli się nie udał, zwracamy 400 i log z opisem błędu
        return HttpResponse.badRequest(log);
    }

    @Post(value = "/encrypt", consumes = MediaType.MULTIPART_FORM_DATA)
    public HttpResponse<String> encryptFile(
            @Header("X-User-Email") String email,
            @Part("file") byte[] fileData) {

        byte[] encrypted = service.encryptForEmail(email, fileData);
        return HttpResponse.ok(new String(encrypted, StandardCharsets.UTF_8));
    }

    @Post("/mass-import")
    @Consumes(MediaType.TEXT_PLAIN)
    public HttpResponse<String> massImport(@Body String hugeKeyContent) {
        var summary = importer.wykonaj(hugeKeyContent);

        String message = String.format(
                "Przetworzono plik.\n" +
                        "Łącznie znaleziono: %d\n" +
                        "Zapisano nowych: %d\n" +
                        "Odrzucono (duplikaty/wygasłe/błędy): %d",
                summary.total(), summary.success(), summary.failed()
        );

        return HttpResponse.ok(message);
    }
}