/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.hyperledger.fabric.shim;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Base64;
import java.util.Enumeration;
import java.util.stream.Collectors;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import java.security.PrivateKey;

public class Base64Reader {
    private static Log logger = LogFactory.getLog(Base64Reader.class);

    // FIXME: 配置は適切じゃないがとりあえず配置
    public static InputStream toPkcs8(byte[] pkcs1KeyString) throws IOException {

        PrivateKey k = generatePrivateKeyAsPkcs1(pkcs1KeyString);

        final String keyFormat = k.getFormat();

        if (keyFormat.equals("PKCS#8")) {
            return new ByteArrayInputStream(k.getEncoded());
        }

        else if (keyFormat.equals("PKCS#1")) {
            try (ASN1InputStream asn1InputStream = new ASN1InputStream(k.getEncoded())) {
                DERObject rsaPrivateKey = asn1InputStream.readObject();
                return  new ByteArrayInputStream(new PrivateKeyInfo(
                        new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption), rsaPrivateKey)
                        .getDEREncoded());
            }
        }

        throw new IOException("Unexpected key format" + keyFormat);
    }

    public static byte[] readBase64(final String path) throws IOException {
        String base64String = Files.lines(Paths.get(path), Charset.forName("UTF-8"))
                .collect(Collectors.joining(System.getProperty("line.separator")));

        //デコード後に文字列に置き換える際のCharset
        Charset charset = StandardCharsets.UTF_8;

        return Base64.getDecoder().decode(base64String.getBytes());
    }

    private static PrivateKey generatePrivateKeyAsPkcs1(byte[] encodedPrivateKey) {
        try {
            logger.debug("Input String as PKCS1 Private Key: \n" + new String(encodedPrivateKey, StandardCharsets.UTF_8));
            ASN1Sequence primitive = (ASN1Sequence) ASN1Sequence
                    .fromByteArray(encodedPrivateKey);
            Enumeration<?> e = primitive.getObjects();
            BigInteger v = ((DERInteger) e.nextElement()).getValue();

            int version = v.intValue();
            if (version != 0 && version != 1) {
                throw new IllegalArgumentException("wrong version for RSA private key");
            }
            /**
             * In fact only modulus and private exponent are in use.
             */
            BigInteger modulus = ((DERInteger) e.nextElement()).getValue();
            BigInteger publicExponent = ((DERInteger) e.nextElement()).getValue();
            BigInteger privateExponent = ((DERInteger) e.nextElement()).getValue();
            BigInteger prime1 = ((DERInteger) e.nextElement()).getValue();
            BigInteger prime2 = ((DERInteger) e.nextElement()).getValue();
            BigInteger exponent1 = ((DERInteger) e.nextElement()).getValue();
            BigInteger exponent2 = ((DERInteger) e.nextElement()).getValue();
            BigInteger coefficient = ((DERInteger) e.nextElement()).getValue();

            RSAPrivateKeySpec spec = new RSAPrivateKeySpec(modulus, privateExponent);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey pk = kf.generatePrivate(spec);
            return pk;
        } catch (IOException e2) {
            throw new IllegalStateException();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException(e);
        }
    }
}
