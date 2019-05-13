package com.bettercloud.vault.api;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.response.TransitResponse;
import com.bettercloud.vault.util.VaultContainer;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

import static junit.framework.TestCase.assertTrue;
import static junit.framework.TestCase.assertEquals;

import java.io.IOException;

public class TransitTests {

    @ClassRule
    public static final VaultContainer container = new VaultContainer();

    @BeforeClass
    public static void setupClass() throws IOException, InterruptedException, VaultException {
        container.initAndUnsealVault();
        container.setupBackendUserPass();
        container.setEngineVersions();
        final Vault vault = container.getVault();
        vault.auth().loginByUserPass(VaultContainer.USER_ID, VaultContainer.PASSWORD);
    }

    @Test
    public void testTransitEncrypt() throws VaultException {
        final Vault vault = container.getRootVault();
        TransitResponse response = vault.transit().encrypt("hello", "world");

        assertTrue(response.getResult().contains("vault:v1:"));
    }

    @Test
    public void testTransitDecrypt() throws VaultException {
        final Vault vault = container.getRootVault();
        final String data = "world";
        TransitResponse encryptResponse = vault.transit().encrypt("hello", data);
        TransitResponse decryptResponse = vault.transit().decrypt("hello", encryptResponse.getResult());

        assertEquals(data, decryptResponse.getResult());
    }
}
