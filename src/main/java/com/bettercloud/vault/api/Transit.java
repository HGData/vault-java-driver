package com.bettercloud.vault.api;

import com.bettercloud.vault.VaultConfig;

/**
 * <p>The implementing class for Vault's Transit Engine operations (e.g. encrypt, decrypt).</p>
 *
 * <p>This class is not intended to be constructed directly.  Rather, it is meant to used by way of <code>Vault</code>
 * in a DSL-style builder pattern.  See the Javadoc comments of each <code>public</code> method for usage examples.</p>
 */
public class Transit {
    private final VaultConfig config;

    private String keyRing;

    public enum transitOperations {encrypt, decrypt}

    public Transit(VaultConfig config) {
        this.config = config;
    }
}
