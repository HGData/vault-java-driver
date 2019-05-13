package com.bettercloud.vault.response;

import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.api.Transit;
import com.bettercloud.vault.json.Json;
import com.bettercloud.vault.json.JsonObject;
import com.bettercloud.vault.rest.RestResponse;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * This class is a container for the information returned by Vault in transit API
 * operations (e.g. encrypt, decrypt).
 */
public class TransitResponse extends VaultResponse {
    public static final String CIPHER_TEXT = "ciphertext";
    public static final String PLAIN_TEXT = "plaintext";

    private String leaseId;
    private Boolean renewable;
    private Long leaseDuration;
    private String result;

    public TransitResponse(final RestResponse restResponse, final int retries, final Transit.transitOperations operation) {
        super(restResponse, retries);
        parseMetadataFields();
        parseResponseData(operation);
    }

    public String getResult() { return result; }

    public String getLeaseId() {
        return leaseId;
    }

    public Boolean getRenewable() {
        return renewable;
    }

    public Long getLeaseDuration() {
        return leaseDuration;
    }

    private void parseMetadataFields() {
        try {
            final String jsonString = new String(getRestResponse().getBody(), StandardCharsets.UTF_8);
            final JsonObject jsonObject = Json.parse(jsonString).asObject();

            this.leaseId = jsonObject.get("lease_id").asString();
            this.renewable = jsonObject.get("renewable").asBoolean();
            this.leaseDuration = jsonObject.get("lease_duration").asLong();
        } catch (Exception ignored) {
        }
    }

    private void parseResponseData(final Transit.transitOperations operation) {
        try {
            final String jsonString = new String(getRestResponse().getBody(), StandardCharsets.UTF_8);
            JsonObject jsonObject = Json.parse(jsonString).asObject();
            JsonObject resultObject = jsonObject.get("data").asObject();

            if (operation == Transit.transitOperations.encrypt) {
                result = resultObject.get(CIPHER_TEXT).asString();
            } else if (operation == Transit.transitOperations.decrypt) {
                result = new String(Base64.getDecoder().decode(resultObject.get(PLAIN_TEXT).asString()));
            } else {
                throw new VaultException("Unknown transit operation: " + operation);
            }
        } catch (Exception ignored) {
        }
    }
}
