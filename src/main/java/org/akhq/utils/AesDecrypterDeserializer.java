package org.akhq.utils;

import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.common.header.Headers;
import org.apache.kafka.common.serialization.Deserializer;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.XMLConstants;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.zip.GZIPInputStream;

@Slf4j
public class AesDecrypterDeserializer implements Deserializer<byte[]> {

    public static final String USER_HOME = System.getProperty("user.home");

    @Override
    public byte[] deserialize(String topic, byte[] data) {
        log.warn("No headers received to deserialize");
        return data;
    }

    @Override
    public byte[] deserialize(String topic, Headers headers, byte[] data) {
        try {
            if (data == null) {
                log.warn("No data received to deserialize");
                return null;
            }

            byte[] aesKeyFromFile = getAesKeyFromFile();
            if (aesKeyFromFile.length == 0) {
                throw new RuntimeException("Missing AES key. Add it to file " + USER_HOME + "/.aes-key");
            }

            log.trace("Deserializing...");
            byte[] decryptedBytes = decrypt(data, aesKeyFromFile, headers.lastHeader("aes_iv").value());
            //format xml
            decryptedBytes = formatXml(decryptedBytes);
            return decryptedBytes;
        } catch (Exception e) {
            throw new RuntimeException("Error when deserializing (decrypting+decompressing): ", e);
        }
    }

    private byte[] getAesKeyFromFile() throws IOException {
        Path keyPath = Paths.get(USER_HOME, ".aes-key");
        if (!Files.exists(keyPath)) {
            Files.createFile(keyPath);
            return new byte[0];
        }
        return Base64.getDecoder().decode(Files.readString(keyPath).trim());
    }

    public byte[] decrypt(byte[] encryptedBytes, byte[] aesKey, byte[] iv) throws IOException, InvalidAlgorithmParameterException, InvalidKeyException {
        var cipherInputStream = this.createCipherStream(encryptedBytes, aesKey, iv);
        return decompress(cipherInputStream);
    }

    private CipherInputStream createCipherStream(byte[] encryptedBytes, byte[] aesKey, byte[] iv) throws InvalidAlgorithmParameterException, InvalidKeyException {
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

    private byte[] decompress(CipherInputStream compressedInput) throws IOException {
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

    public byte[] formatXml(byte[] input) throws Exception {

        try {
            Source xmlInput = new StreamSource(new StringReader(new String(input, StandardCharsets.UTF_8).trim()));
            StreamResult xmlOutput = new StreamResult(new StringWriter());

            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            transformerFactory.setAttribute("indent-number", "2");
            transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");

            Transformer transformer = transformerFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.transform(xmlInput, xmlOutput);
            return xmlOutput.getWriter().toString().getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.info("Error when pretty formatting: ", e);
            return input;
        }
    }
}
