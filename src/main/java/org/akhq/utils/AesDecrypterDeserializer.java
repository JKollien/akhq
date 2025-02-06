package org.akhq.utils;

import lombok.extern.slf4j.Slf4j;
import org.akhq.models.KeyValue;
import org.w3c.dom.Document;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.zip.GZIPInputStream;

@Slf4j
public class AesDecrypterDeserializer {

    public static final String USER_HOME = System.getProperty("user.home");
    public static final byte[] AES_KEY;

    static {
        try {
            Path keyPath = Paths.get(USER_HOME, ".aes-key");
            if (!Files.exists(keyPath)) {
                Files.createFile(keyPath);
            }
            AES_KEY = Base64.getDecoder().decode(Files.readString(keyPath).trim());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        if (AES_KEY.length == 0) {
            throw new RuntimeException("Missing AES key. Add it to file " + USER_HOME + "/.aes-key");
        }
    }

    private static byte[] getAesKeyFromFile() throws IOException {
        Path keyPath = Paths.get(USER_HOME, ".aes-key");
        if (!Files.exists(keyPath)) {
            Files.createFile(keyPath);
            return new byte[0];
        }
        return Base64.getDecoder().decode(Files.readString(keyPath).trim());
    }

    public static String deserialize(List<KeyValue<String, String>> headers, byte[] data) {
        try {
            if (data == null) {
                log.warn("No data received to deserialize");
                return null;
            }

            log.trace("Deserializing...");
            String ivString = headers.stream().filter(kv -> "aes_iv".equals(kv.getKey())).findAny().orElseThrow().getValue();
//            byte[] iv = ContentUtils.hexToBytes(ivString);
            byte[] iv = ByteBuffer.allocate(Long.BYTES).putLong(Long.parseLong(ivString)).array();
            byte[] decryptedBytes = decrypt(data, AES_KEY, iv);
            //format xml
            return formatXml(decryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error when deserializing (decrypting+decompressing): ", e);
        }
    }

    public static byte[] decrypt(byte[] encryptedBytes, byte[] aesKey, byte[] iv) throws IOException, InvalidAlgorithmParameterException, InvalidKeyException {
        var cipherInputStream = createCipherStream(encryptedBytes, aesKey, iv);
        return decompress(cipherInputStream);
    }

    private static CipherInputStream createCipherStream(byte[] encryptedBytes, byte[] aesKey, byte[] iv) throws InvalidAlgorithmParameterException, InvalidKeyException {
        int ivNumBits = 8 * iv.length;

        Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error creating cipher: cipher algorithm is not available", e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException("Error creating cipher: padding is not supported", e);
        }

        SecretKeySpec secretKey = new SecretKeySpec(aesKey, "AES");

        cipher.init(2, secretKey, new GCMParameterSpec(ivNumBits, iv));
        return new CipherInputStream(new ByteArrayInputStream(encryptedBytes), cipher);
    }

    private static byte[] decompress(CipherInputStream compressedInput) throws IOException {
        byte[] var6;
        try (
            GZIPInputStream gzipInputStream = new GZIPInputStream(compressedInput);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream(1024);
        ) {
            byte[] buffer = new byte[1024];

            int bytesRead;
            while ((bytesRead = gzipInputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }

            var6 = outputStream.toByteArray();
        }

        return var6;
    }

    public static String formatXml(byte[] input) throws Exception {
        String xmlContent = new String(input, StandardCharsets.UTF_8).trim();

        Document document;
        try {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(xmlContent.getBytes(StandardCharsets.UTF_8));
            document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(byteArrayInputStream);
        } catch (Exception e) {
            log.debug("Likely no XML to format found, skipping. Exception:", e);
            return new String(input, StandardCharsets.UTF_8);
        }

        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(outputStream));

        return outputStream.toString();
    }
}
