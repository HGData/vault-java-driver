package com.bettercloud.vault.api;

import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.json.Json;
import com.bettercloud.vault.response.TransitResponse;
import com.bettercloud.vault.rest.Rest;
import com.bettercloud.vault.rest.RestException;
import com.bettercloud.vault.rest.RestResponse;

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

    public TransitResponse encrypt(String keyRing, String data) throws VaultException {
        int retryCount = 0;
        while (true) {
            try {
                String postBody = Json.object().add("plaintext", Base64.getEncoder().encodeToString(data.getBytes(StandardCharsets.UTF_8))).toString();

                final RestResponse response = new Rest()
                        .url(config.getAddress() + "/v1/transit/encrypt/" + keyRing)
                        .header("X-Vault-Token", config.getToken())
                        .body(postBody.getBytes(StandardCharsets.UTF_8))
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
                if (retryCount < config.getMaxRetries()) {
                    retryCount++;
                    try {
                        final int retryIntervalMilliseconds = config.getRetryIntervalMilliseconds();
                        Thread.sleep(retryIntervalMilliseconds);
                    } catch (InterruptedException e1) {
                        e1.printStackTrace();
                    }
                } else if (e instanceof VaultException) {
                    // ... otherwise, give up.
                    throw (VaultException) e;
                } else {
                    throw new VaultException(e);
                }
            }
        }
    }

    public TransitResponse decrypt(String keyRing, String cipherText) throws VaultException {
        int retryCount = 0;
        while (true) {
            try {
                String postBody = Json.object().add("ciphertext", cipherText).toString();

                final RestResponse response = new Rest()
                        .url(config.getAddress() + "/v1/transit/decrypt/" + keyRing)
                        .header("X-Vault-Token", config.getToken())
                        .body(postBody.getBytes(StandardCharsets.UTF_8))
                        .connectTimeoutSeconds(config.getOpenTimeout())
                        .readTimeoutSeconds(config.getReadTimeout())
                        .sslVerification(config.getSslConfig().isVerify())
                        .sslContext(config.getSslConfig().getSslContext())
                        .post();

                if (response.getStatus() != 200) {
                    throw new VaultException("Vault responded with HTTP status code: " + response.getStatus()
                            + "\nResponse body: " + new String(response.getBody(), StandardCharsets.UTF_8),
                            response.getStatus());
                }

                return new TransitResponse(response, retryCount, transitOperations.decrypt);
            } catch (RuntimeException | VaultException | RestException e) {
                if (retryCount < config.getMaxRetries()) {
                    retryCount++;
                    try {
                        final int retryIntervalMilliseconds = config.getRetryIntervalMilliseconds();
                        Thread.sleep(retryIntervalMilliseconds);
                    } catch (InterruptedException e1) {
                        e1.printStackTrace();
                    }
                } else if (e instanceof VaultException) {
                    // ... otherwise, give up.
                    throw (VaultException) e;
                } else {
                    throw new VaultException(e);
                }
            }
        }
    }
}
