package aero.icarus2020.decryptionmanager.service.impl;

import aero.icarus2020.decryptionmanager.service.DecryptionService;
import aero.icarus2020.decryptionmanager.util.DecryptionUtil;
import com.mongodb.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.MessageDigest;
import java.util.*;

@Component
@RequiredArgsConstructor
@Log4j2
public class DecryptionServiceImpl implements DecryptionService {

  private final DecryptionUtil decryptionUtil;

  @Value("${icarus.mongodb.url}")
  private String mongoUrl;

  @Value("${icarus.decryption.jwt}")
  private String decryptionJwt;

  @Value("${icarus.decryption.file-path}")
  private String decryptionFilePath;

  @Value("${icarus.decryption.batch-size}")
  private int decryptionBatchSize;

  private static final String TOKEN_HEADER = "Token";

  // Decryption function that decrypts for the organization owner the specific dataset
  public String decryptData(Long mid, HttpServletRequest httpServletRequest) {
    return this.decrypt(mid, null, httpServletRequest);
  }

  // Decryption function that decrypts only the columns indicated by the respective argument.
  public String decryptContractData(Long mid, List<String> columns, HttpServletRequest httpServletRequest) {
    return this.decrypt(mid, columns, httpServletRequest);
  }

  // Decryption function that passes unencrypted open dataset to the organization.
  public String decryptOpenData(Long mid, HttpServletRequest httpServletRequest,List<String> columns) {
    if (httpServletRequest.getHeader(TOKEN_HEADER) == null || !httpServletRequest.getHeader(TOKEN_HEADER).equals(this.decryptionJwt)) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
    }

    log.info("Decrypting open dataset with id {}.", mid);

    return this.handleOpenDataset(mid,columns);
  }

  private String decrypt(Long mid, List<String> columns, HttpServletRequest httpServletRequest) {
    if (httpServletRequest.getHeader(TOKEN_HEADER) == null || !httpServletRequest.getHeader(TOKEN_HEADER).equals(this.decryptionJwt)) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
    }

    ResponseEntity<String> response = decryptionUtil.login();

    if (!response.getStatusCode().is2xxSuccessful()) {
      log.error("Received a status code of {} from key-pair manager during login.", response.getStatusCode());
      throw new ResponseStatusException(response.getStatusCode());
    }

    ResponseEntity<String> secretKey = decryptionUtil.getKeyForSecureSpace(mid, response);

    if (!secretKey.getStatusCode().is2xxSuccessful()) {
      log.error("Received a status code of {} from key-pair manager while getting key.", secretKey.getStatusCode());
      throw new ResponseStatusException(secretKey.getStatusCode());
    }

    if (secretKey.getBody() == null) {
      log.info("Key-pair manager response body is null. Treating dataset as open.");

      return this.handleOpenDataset(mid,columns);
    } else {
      String secret = secretKey.getBody();

      try (MongoClient mongoClient = new MongoClient(new MongoClientURI(this.mongoUrl))) {
        DBCollection dbCollection = mongoClient.getDB("icarus").getCollection(mid.toString());

        if (columns == null) {
          log.info("Decrypting dataset with id {}.", mid);
          return this.storeDecryptedData(secret, mid.toString(), dbCollection, this.getMongoFields(dbCollection));
        } else {
          log.info("Decrypting contract dataset with id {}.", mid);
          return this.storeDecryptedData(secret, mid.toString(), dbCollection, columns);
        }
      } catch (Exception e) {
        log.error("An exception occurred while opening MongoDB connection.", e);
        return null;
      }
    }
  }

  private String handleOpenDataset(Long mid,List<String> columns) {
    if (columns == null) { // An open dataset or a private unencrypted has been asked to be decrypted.
      try (MongoClient mongoClient = new MongoClient(new MongoClientURI(this.mongoUrl))) {
        DBCollection dbCollection = mongoClient.getDB("icarus").getCollection(mid.toString());
        return this.storeOpenData(mid.toString(), dbCollection, this.getMongoFields(dbCollection));
      } catch (Exception e) {
        log.error("An exception occurred while opening MongoDB connection.", e);
        return null;
      }
    } else { // An unencrypted dataset, that is involved in a contract, has been asked to be decrypted.
      try (MongoClient mongoClient = new MongoClient(new MongoClientURI(this.mongoUrl))) {
        DBCollection dbCollection = mongoClient.getDB("icarus").getCollection(mid.toString());
        return this.storeOpenData(mid.toString(), dbCollection, columns);
      } catch (Exception e) {
        log.error("An exception occurred while opening MongoDB connection.", e);
        return null;
      }
    }
  }

  private String storeDecryptedData(String secret, String id, DBCollection dbCollection, List<String> keys) {
    Iterator<DBObject> cursor = dbCollection.find();

    String csvHeader = String.join(",", keys).concat("\n");
    List<String> csvRows = new ArrayList<>();
    String csvFileName = String.format("%s/decrypted_dataset_%s_%s.csv", this.decryptionFilePath, id, System.currentTimeMillis());

    try (BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(csvFileName))) {
      // Write header
      bufferedWriter.write(csvHeader);

      while (cursor.hasNext()) {
        this.extractDecryptedDataRow(cursor.next(), keys, csvRows, secret);

        if (csvRows.size() >= this.decryptionBatchSize) {
          for (String row: csvRows) {
            bufferedWriter.write(row);
          }

          csvRows = new ArrayList<>();
        }
      }

      if (!csvRows.isEmpty()) {
        for (String row: csvRows) {
          bufferedWriter.write(row);
        }
      }

      return csvFileName;
    } catch (NoSuchElementException e) {
      return null;
    } catch (IOException e) {
      log.error("IOException", e);
      return null;
    }
  }

  private void extractDecryptedDataRow(DBObject current, List<String> keys, List<String> csvRows, String secret) {
    StringBuilder csvRow = new StringBuilder();

    for (String key: keys) {
      try {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] cipherData = Base64.getDecoder().decode(current.get(key).toString());
        byte[] saltData = Arrays.copyOfRange(cipherData, 8, 16);
        final byte[][] keyAndIV = this.generateKeyAndIv(32, 16, 1, saltData, secret.getBytes(StandardCharsets.UTF_8), md5);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyAndIV[0], "AES");
        IvParameterSpec iv = new IvParameterSpec(keyAndIV[1]);
        byte[] encrypted = Arrays.copyOfRange(cipherData, 16, cipherData.length);
        Cipher aesCBC = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCBC.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);
        byte[] decryptedData = aesCBC.doFinal(encrypted);
        String decryptedText = new String(decryptedData, StandardCharsets.UTF_8);

        csvRow.append("\"").append(decryptedText).append("\",");
      } catch (Exception e) {
        if (current.get(key) != null) {
          csvRow.append("\"").append(current.get(key).toString().trim()).append("\",");
        } else {
          csvRow.append("\"\",");
        }
      }
    }

    if (csvRow.length() > 0) {
      csvRows.add(csvRow.deleteCharAt(csvRow.length() - 1).append("\n").toString());
    }
  }

  private String storeOpenData(String id, DBCollection dbCollection, List<String> keys) {
    String csvHeader = String.join(",", keys).concat("\n");
    List<String> csvRows = new ArrayList<>();
    String csvFileName = String.format("%s/decrypted_dataset_%s_%s.csv", this.decryptionFilePath, id, System.currentTimeMillis());

    Iterator<DBObject> cursor = dbCollection.find();

    try (BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(csvFileName))) {
      // Write header
      bufferedWriter.write(csvHeader);

      while (cursor.hasNext()) {
        this.extractOpenDataRow(cursor.next(), keys, csvRows);

        if (csvRows.size() >= this.decryptionBatchSize) {
          for (String row: csvRows) {
            bufferedWriter.write(row);
          }

          csvRows = new ArrayList<>();
        }
      }

      if (!csvRows.isEmpty()) {
        for (String row: csvRows) {
          bufferedWriter.write(row);
        }
      }

      return csvFileName;
    } catch (NoSuchElementException e) {
      return null;
    } catch (IOException e) {
      log.error(e);
      return null;
    }
  }

  private void extractOpenDataRow(DBObject current, List<String> keys, List<String> csvRows) {
    StringBuilder csvRow = new StringBuilder();
    for (String key: keys) {
      try {
        String value = current.get(key).toString();
        csvRow.append("\"").append(value).append("\",");
      } catch (Exception e) {
        csvRow.append("\"\",");
      }
    }

    if (csvRow.length() > 0) {
      csvRows.add(csvRow.deleteCharAt(csvRow.length() - 1).append("\n").toString());
    }
  }

  // Return mongo fields, through executing a map-reduce query.
  // In order to avoid picking randomly a document with one or more unset fields.
  private List<String> getMongoFields(DBCollection dbCollection) {
    String map = "function() {"
        + "            for (var key in this){"
        + "                emit(key, null);"
        + "            }"
        + "        }";

    String reduce = "function(key, value){"
        + "            return null;"
        + "        }";

    MapReduceCommand mapReduceCommand = new MapReduceCommand(dbCollection, map, reduce,null, MapReduceCommand.OutputType.INLINE,null);
    MapReduceOutput mapReduceOutput = dbCollection.mapReduce(mapReduceCommand);

    // append to keys list the fields found by map-reduce operation.
    List<String> keys = new ArrayList<>();

    for (DBObject o: mapReduceOutput.results()) {
      String key = o.get("_id").toString();
      if (!key.equals("_id")) {
        keys.add(key);
      }
    }

    return keys;
  }

  private byte[][] generateKeyAndIv(int keyLength, int ivLength, int iterations, byte[] salt, byte[] password, MessageDigest md) {
    int digestLength = md.getDigestLength();
    int requiredLength = (keyLength + ivLength + digestLength - 1) / digestLength * digestLength;
    byte[] generatedData = new byte[requiredLength];
    int generatedLength = 0;

    try {
      md.reset();

      // Repeat process until sufficient data has been generated
      while (generatedLength < keyLength + ivLength) {

        // Digest data (last digest if available, password data, salt if available)
        if (generatedLength > 0) {
          md.update(generatedData, generatedLength - digestLength, digestLength);
        }
        md.update(password);
        if (salt != null) {
          md.update(salt, 0, 8);
        }
        md.digest(generatedData, generatedLength, digestLength);

        // additional rounds
        for (int i = 1; i < iterations; i++) {
          md.update(generatedData, generatedLength, digestLength);
          md.digest(generatedData, generatedLength, digestLength);
        }

        generatedLength += digestLength;
      }

      // Copy key and IV into separate byte arrays
      byte[][] result = new byte[2][];
      result[0] = Arrays.copyOfRange(generatedData, 0, keyLength);
      if (ivLength > 0) {
        result[1] = Arrays.copyOfRange(generatedData, keyLength, keyLength + ivLength);
      }

      return result;

    } catch (DigestException e) {
      throw new RuntimeException(e);

    } finally {
      // Clean out temporary data
      Arrays.fill(generatedData, (byte)0);
    }
  }
}
