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
        String postBody = Json.object().add("plaintext", Base64.getEncoder().encodeToString(data.getBytes(StandardCharsets.UTF_8))).toString();
        return makeTransitRequestWithRetries(
          keyRing,
          transitOperations.encrypt,
          postBody,
          config.getMaxRetries(),
          config.getRetryIntervalMilliseconds()
        );
    }

    public TransitResponse decrypt(String keyRing, String cipherText) throws VaultException {
        String postBody = Json.object().add("ciphertext", cipherText).toString();
        return makeTransitRequestWithRetries(
          keyRing,
          transitOperations.decrypt,
          postBody,
          config.getMaxRetries(),
          config.getRetryIntervalMilliseconds()
        );
    }

    private TransitResponse makeTransitRequestWithRetries(String keyRing,
                                                          transitOperations operation,
                                                          String postBody,
                                                          int maxRetryCount,
                                                          int retryIntervalMilliseconds) throws VaultException {
        int retryCount = 0;
        while (true) {
            try {
                final RestResponse response = makeTransitRestRequest(keyRing, operation, postBody);

                if (response.getStatus() != 200) {
                    throw new VaultException("Vault responded with HTTP status code: " + response.getStatus()
                      + "\nResponse body: " + new String(response.getBody(), StandardCharsets.UTF_8),
                      response.getStatus());
                }

                return new TransitResponse(response, retryCount, transitOperations.decrypt);
            } catch (RuntimeException | VaultException | RestException e) {
                if (retryCount < maxRetryCount) {
                    retryCount++;
                    try {
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

    private RestResponse makeTransitRestRequest(String keyRing, transitOperations operation, String postBody) throws RestException {
        return new Rest()
          .url(config.getAddress() + "/v1/transit/" + operationURIEndpoint(operation) + "/" + keyRing)
          .header("X-Vault-Token", config.getToken())
          .body(postBody.getBytes(StandardCharsets.UTF_8))
          .connectTimeoutSeconds(config.getOpenTimeout())
          .readTimeoutSeconds(config.getReadTimeout())
          .sslVerification(config.getSslConfig().isVerify())
          .sslContext(config.getSslConfig().getSslContext())
          .post();
    }

    private String operationURIEndpoint(Transit.transitOperations operation) {
        switch (operation) {
            case decrypt: return "decrypt";
            case encrypt: return "encrypt";
        }
    }
}
