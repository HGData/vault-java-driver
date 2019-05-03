package com.bettercloud.vault.api;

import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.json.JsonObject;
import com.bettercloud.vault.response.TransitResponse;
import com.bettercloud.vault.rest.Rest;
import com.bettercloud.vault.rest.RestException;
import com.bettercloud.vault.rest.RestResponse;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * <p>The implementing class for Vault's Transit Engine operations (e.g. encrypt, decrypt).</p>
 *
 * <p>This class is not intended to be constructed directly.  Rather, it is meant to used by way of <code>Vault</code>
 * in a DSL-style builder pattern.  See the Javadoc comments of each <code>public</code> method for usage examples.</p>
 */
public class Transit {
    private final VaultConfig config;

    public enum transitOperations {encrypt, decrypt}

    public Transit(VaultConfig config) {
        this.config = config;
    }

    public TransitResponse encrypt(String keyRing, String data) {
        int retryCount = 0;
        while (true) {
            try {
                JsonObject postBody = new JsonObject();
                JsonObject plaintext = new JsonObject().add("plaintext", Base64.getEncoder().encodeToString(data.getBytes(StandardCharsets.UTF_8)));
                postBody.add("data", plaintext);

                final RestResponse response = new Rest()
                        .url(config.getAddress() + "/v1/" + keyRing)
                        .header("X-Vault-Token", config.getToken())
                        .body(postBody.toString().getBytes(StandardCharsets.UTF_8))
                        .connectTimeoutSeconds(config.getOpenTimeout())
                        .readTimeoutSeconds(config.getReadTimeout())
                        .sslVerification(config.getSslConfig().isVerify())
                        .sslContext(config.getSslConfig().getSslContext())
                        .post();

                // Validate response
                if (response.getStatus() != 200) {
                    throw new VaultException("Vault responded with HTTP status code: " + response.getStatus()
                            + "\nResponse body: " + new String(response.getBody(), StandardCharsets.UTF_8),
                            response.getStatus());
                }

                return new TransitResponse(response, retryCount, transitOperations.encrypt);
            } catch (RuntimeException | VaultException | RestException e) {

            }
        }
    }
}
