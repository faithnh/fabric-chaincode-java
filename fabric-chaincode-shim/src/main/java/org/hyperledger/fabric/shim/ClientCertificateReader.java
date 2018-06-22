/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.hyperledger.fabric.shim;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Collectors;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

import java.security.PrivateKey;

public class ClientCertificateReader {
//    public static void main(String[] args) {
//        byte[] privateKey = (
//                "-----BEGIN EC PRIVATE KEY-----\n" +
//                "MHcCAQEEIEOFvlcbPnZrJPr2Asy8oV9orkGzkLRINywzLrh7Fn3uoAoGCCqGSM49\n" +
//                "AwEHoUQDQgAE9jL4rq2T8YAXEyzRHpoSBV8SnvInS/NSbORkezJewNP+NlTayxYZ\n" +
//                "VskubLwo7U4l11Dy+Ojc83xLEGXJJo/2Hw==\n" +
//                "-----END EC PRIVATE KEY-----"
//        ).getBytes(StandardCharsets.UTF_8);
//
//        ClientCertificateReader.convertPrivateKeyFromPkcs1ToPkcs8(privateKey);
//    }

    private static Log logger = LogFactory.getLog(ClientCertificateReader.class);

    // FIXME: 配置は適切じゃないがとりあえず配置
    public static InputStream readPrivateKeyForPkcs1(String pkcs1PrivateKeyPath) throws IOException {
        byte[] encodedPrivateKey = readBase64(pkcs1PrivateKeyPath);
        PrivateKey k = convertPrivateKeyFromPkcs1ToPkcs8(encodedPrivateKey);

        return new ByteArrayInputStream(k.getEncoded());
    }

    public static InputStream readCertificate(String certificatefilePath) throws IOException {
        byte[] encodedPrivateKey = readBase64(certificatefilePath);

        return new ByteArrayInputStream(encodedPrivateKey);
    }

    private static byte[] readBase64(final String path) throws IOException {
        String base64String = Files.lines(Paths.get(path), Charset.forName("UTF-8"))
                .collect(Collectors.joining(System.getProperty("line.separator")));

        return Base64.getDecoder().decode(base64String.getBytes());
    }

    private static PrivateKey convertPrivateKeyFromPkcs1ToPkcs8(byte[] privateKey) {
        try {
            System.out.println("Input String as PKCS1 Private Key: \n" + new String(privateKey, StandardCharsets.UTF_8));

            // remove header and decode private key
            String privKeyPEM = new String(privateKey, StandardCharsets.UTF_8).replace(
                    "-----BEGIN EC PRIVATE KEY-----\n", "")
                    .replace("-----END EC PRIVATE KEY-----", "").replace("\n", "");
            byte[] decodedPrivateKey = Base64.getDecoder().decode(privKeyPEM);
            ASN1Sequence seq = ASN1Sequence.getInstance(decodedPrivateKey);
            org.bouncycastle.asn1.sec.ECPrivateKey pKey = org.bouncycastle.asn1.sec.ECPrivateKey.getInstance(seq);
            AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, pKey.getParameters());
            byte[] server_pkcs8 = new PrivateKeyInfo(algId, pKey).getEncoded();
            KeyFactory fact = KeyFactory.getInstance("EC");
            return fact.generatePrivate (new PKCS8EncodedKeySpec(server_pkcs8));
        } catch (IOException e2) {
            throw new IllegalStateException();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException(e);
        }
    }
}
