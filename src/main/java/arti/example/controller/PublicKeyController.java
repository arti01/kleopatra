package arti.example.controller;

import arti.example.model.PublicKeyEntity;
import arti.example.service.PublicKeyService;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.*;

import java.nio.charset.StandardCharsets;

@Controller("/keys")
public class PublicKeyController {

    private final PublicKeyService service;

    public PublicKeyController(PublicKeyService service) {
        this.service = service;
    }
    @Consumes(MediaType.TEXT_PLAIN)
    @Post("/{alias}")
    public HttpResponse<PublicKeyEntity> addKey(String alias, @Body String keyContent) {
        return HttpResponse.created(service.saveKey(alias, keyContent));
    }
    @Post(value = "/encrypt", consumes = MediaType.MULTIPART_FORM_DATA)
    public HttpResponse<String> encryptFile(
            @Header("X-User-Email") String email,
            @Part("file") byte[] fileData) {

        byte[] encrypted = service.encryptForEmail(email, fileData);
        return HttpResponse.ok(new String(encrypted, StandardCharsets.UTF_8));
    }
}