package org.hyperledger.fabric.shim;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.stream.Collectors;


public class Base64Reader {
    public static InputStream readBase64(final String path) throws IOException {
        String base64String = Files.lines(Paths.get(path), Charset.forName("UTF-8"))
                .collect(Collectors.joining(System.getProperty("line.separator")));

        //デコード後に文字列に置き換える際のCharset
        Charset charset = StandardCharsets.UTF_8;

        return new ByteArrayInputStream(Base64.getDecoder().decode(base64String.getBytes()));
    }
}
