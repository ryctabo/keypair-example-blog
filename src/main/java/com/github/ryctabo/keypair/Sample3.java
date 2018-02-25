/*
 * Copyright 2018 Gustavo Pacheco.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.ryctabo.keypair;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Logger;

/**
 * @author Gustavo Pacheco (ryctabo at gmail.com)
 * @version 1.0
 */
public class Sample3 {

    private static final Logger LOG = Logger.getLogger(Sample3.class.getName());

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // Generate private key object from bytes
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(getBytesFromUri("id_bin_rsa.key"));
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        // Generate the public key object from bytes
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(getBytesFromUri("id_bin_rsa.pub"));
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        // Print PRIVATE and PUBLIC key format
        LOG.info(String.format("Private key format: %s", privateKey.getFormat()));
        LOG.info(String.format("Public key format: %s", publicKey.getFormat()));
    }

    private static byte[] getBytesFromUri(String uri) throws IOException {
        // Read all bytes from the private key file
        Path path = Paths.get(uri);
        return Files.readAllBytes(path);
    }
}
