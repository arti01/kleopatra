-- 1. Tabela z kluczami (Rodzic)
CREATE TABLE public_keys (
                             id BIGSERIAL PRIMARY KEY,
                             alias VARCHAR(255) NOT NULL UNIQUE,
                             email VARCHAR(255),
                             fingerprint VARCHAR(255) NOT NULL UNIQUE,
                             public_key_pem TEXT NOT NULL,
                             created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                             expires_at TIMESTAMP
);

-- 2. Tabela z logami (Dziecko z Kluczem Obcym)
CREATE TABLE key_import_logs (
                                 id BIGSERIAL PRIMARY KEY,
                                 public_key_id BIGINT,
                                 attempt_timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                 success BOOLEAN NOT NULL,
                                 error_message TEXT,
                                 attempted_alias VARCHAR(255),
    -- TU JEST NASZA RELACJA (Klucz Obcy)
                                 CONSTRAINT fk_public_key
                                     FOREIGN KEY (public_key_id)
                                         REFERENCES public_keys(id)
                                         ON DELETE SET NULL -- Jeśli skasujesz klucz, log zostanie, ale z null
);
