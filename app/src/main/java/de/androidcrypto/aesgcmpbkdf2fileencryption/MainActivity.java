package de.androidcrypto.aesgcmpbkdf2fileencryption;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {

    EditText plaintext, passphrase, ciphertext, decryptedtext;
    Button encrypt, decrypt;

    String plaintextString;
    String ciphertextBase64;
    byte[] dataToSave;
    private static final int REQUEST_PERMISSION_WRITE_EXTERNAL_STORAGE = 100;
    Context contextSave;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);
        contextSave = getApplicationContext();
        plaintext = findViewById(R.id.etPlaintext);
        passphrase = findViewById(R.id.etPassphrase);
        ciphertext = findViewById(R.id.etCiphertext);
        decryptedtext = findViewById(R.id.etDecryptedtext);
        encrypt = findViewById(R.id.btnEncrypt);
        decrypt = findViewById(R.id.btnDecrypt);

        encrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                ciphertext.setText("");
                decryptedtext.setText("");
                ciphertextBase64 = "";
                dataToSave = null;
                // get the passphrase from EditText as char array
                int passphraseLength = passphrase.length();
                char[] passphraseChar = new char[passphraseLength];
                passphrase.getText().getChars(0, passphraseLength, passphraseChar, 0);
                // do not run the encryption on main gui thread as it may block
                //String ciphertextData = doEncryptionAesGcmPbkdf2(passphraseChar, plaintext.getText().toString().getBytes(StandardCharsets.UTF_8));
                //ciphertext.setText(ciphertextData);
                // run the encryption in a different thread instead
                Thread thread = new Thread(){
                    public void run(){
                        doAesEncryption(passphraseChar, plaintext.getText().toString().getBytes(StandardCharsets.UTF_8));
                    }
                };
                thread.start();
            }
        });

        decrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // get the passphrase from EditText as char array
                int passphraseLength = passphrase.length();
                char[] passphraseChar = new char[passphraseLength];
                passphrase.getText().getChars(0, passphraseLength, passphraseChar, 0);
                byte[] ciphertext = null; // todo get the ciphertext from a file

                // do not run the decryption on main gui thread as it may block
                // String decryptedtextData = doDecryptionAesGcmPbkdf2(passphraseChar, ciphertext.getText().toString());
                // decryptedtext.setText(decryptedtextData);
                // run the encryption in a different thread instead
                Thread thread = new Thread(){
                    public void run(){
                        doAesDecryption(passphraseChar, ciphertext);
                    }
                };
                thread.start();
            }
        });
    }

    // you need to use this method to write to the textview from a background thread
    // source: https://stackoverflow.com/a/25488292/8166854
    private void setText(final EditText editText,final String value){
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                editText.setText(value);
            }
        });
    }

    // this method is running in a thread, so don't update the ui directly
    private void doAesEncryption(char[] passphraseChar, byte[] plaintextByte) {
        dataToSave = doEncryptionAesGcmPbkdf2(passphraseChar, plaintextByte);
        ciphertextBase64 = base64Encoding(dataToSave);
        setText(ciphertext, ciphertextBase64);
    }

    // this method is running in a thread, so don't update the ui directly
    private void doAesDecryption(char[] passphraseChar, byte[] ciphertext) {
        String decryptedtextData = doDecryptionAesGcmPbkdf2(passphraseChar, ciphertext);
        setText(decryptedtext, decryptedtextData);
    }

    private byte[] doEncryptionAesGcmPbkdf2(char[] passphraseChar, byte[] plaintextByte) {
        final int PBKDF2_ITERATIONS = 10000; // fixed as minimum
        final String TRANSFORMATION_GCM = "AES/GCM/NoPadding";
        int saltLength = 32;
        int nonceLength = 12;
        // generate 32 byte random salt for pbkdf2
        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = new byte[saltLength];
        secureRandom.nextBytes(salt);
        // generate 12 byte random nonce for AES GCM
        byte[] nonce = new byte[nonceLength];
        secureRandom.nextBytes(nonce);
        byte[] secretKey = new byte[0];
        SecretKeyFactory secretKeyFactory = null;
        // we are deriving the secretKey from the passphrase with PBKDF2 and using
        // the hash algorithm Hmac256, this is built in from SDK >= 26
        // for older SDKs we are using the own PBKDF2 function
        // api between 23 - 25
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M &
                Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            try {
                // uses 3rd party PBKDF function to get PBKDF2withHmacSHA256
                // PBKDF2withHmacSHA256	is available API 26+
                byte[] passphraseByte = charArrayToByteArray(passphraseChar);
                secretKey = PBKDF.pbkdf2("HmacSHA256", passphraseByte, salt, PBKDF2_ITERATIONS, 32);
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
                Log.e("APP_TAG", "generateAndStoreSecretKeyFromPassphrase error: " + e.toString());
                return null;
            }
        }
        // api 26+ has HmacSHA256 available
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            try {
                secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec keySpec = new PBEKeySpec(passphraseChar, salt, PBKDF2_ITERATIONS, 32 * 8);
                secretKey = secretKeyFactory.generateSecret(keySpec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                e.printStackTrace();
                return null;
            }
        }
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * 8, nonce);
        Cipher cipher = null;
        byte[] ciphertext = new byte[0];
        try {
            cipher = Cipher.getInstance(TRANSFORMATION_GCM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);
            ciphertext = cipher.doFinal(plaintextByte);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            return null;
        }
        // concatenating salt, nonce and ciphertext
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(salt);
            outputStream.write(nonce);
            outputStream.write(ciphertext);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
        return outputStream.toByteArray();
    }

    private String doDecryptionAesGcmPbkdf2(char[] passphraseChar, byte[] ciphertextComplete) {
        final int PBKDF2_ITERATIONS = 10000; // fixed as minimum
        final String TRANSFORMATION_GCM = "AES/GCM/NoPadding";
        int saltLength = 32;
        int nonceLength = 12;
        // split the complete ciphertext into salt, nonce and ciphertext
        ByteBuffer bb = ByteBuffer.wrap(ciphertextComplete);
        byte[] salt = new byte[saltLength];
        byte[] nonce = new byte[nonceLength];
        byte[] ciphertext = new byte[(ciphertextComplete.length - saltLength - nonceLength)];
        bb.get(salt, 0, salt.length);
        bb.get(nonce, 0, nonce.length);
        bb.get(ciphertext, 0, ciphertext.length);
        SecretKeyFactory secretKeyFactory = null;
        byte[] secretKey = new byte[0];
        // we are deriving the secretKey from the passphrase with PBKDF2 and using
        // the hash algorithm Hmac256, this is built in from SDK >= 26
        // for older SDKs we are using the own PBKDF2 function
        // api between 23 - 25
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M &
                Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            try {
                // uses 3rd party PBKDF function to get PBKDF2withHmacSHA256
                // PBKDF2withHmacSHA256	is available API 26+
                byte[] passphraseByte = charArrayToByteArray(passphraseChar);
                secretKey = PBKDF.pbkdf2("HmacSHA256", passphraseByte, salt, PBKDF2_ITERATIONS, 32);
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
                Log.e("APP_TAG", "generateAndStoreSecretKeyFromPassphrase error: " + e.toString());
                return "";
            }
        }
        // api 26+ has HmacSHA256 available
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            try {
                secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec keySpec = new PBEKeySpec(passphraseChar, salt, PBKDF2_ITERATIONS, 32 * 8);
                secretKey = secretKeyFactory.generateSecret(keySpec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                e.printStackTrace();
                return "";
            }
        }
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * 8, nonce);
        Cipher cipher = null;
        byte[] decryptedtextByte = new byte[0];
        try {
            cipher = Cipher.getInstance(TRANSFORMATION_GCM);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);
            decryptedtextByte = cipher.doFinal(ciphertext);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            return "ERROR: The passphrase may be wrong or the ciphertext is corrupted";
        }
        return new String(decryptedtextByte, StandardCharsets.UTF_8);
    }

    private String doEncryptionAesGcmPbkdf2Base64(char[] passphraseChar, byte[] plaintextByte) {
        final int PBKDF2_ITERATIONS = 10000; // fixed as minimum
        final String TRANSFORMATION_GCM = "AES/GCM/NoPadding";
        int saltLength = 32;
        int nonceLength = 12;
        // generate 32 byte random salt for pbkdf2
        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = new byte[saltLength];
        secureRandom.nextBytes(salt);
        // generate 12 byte random nonce for AES GCM
        byte[] nonce = new byte[nonceLength];
        secureRandom.nextBytes(nonce);
        byte[] secretKey = new byte[0];
        SecretKeyFactory secretKeyFactory = null;
        // we are deriving the secretKey from the passphrase with PBKDF2 and using
        // the hash algorithm Hmac256, this is built in from SDK >= 26
        // for older SDKs we are using the own PBKDF2 function
        // api between 23 - 25
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M &
                Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            try {
                // uses 3rd party PBKDF function to get PBKDF2withHmacSHA256
                // PBKDF2withHmacSHA256	is available API 26+
                byte[] passphraseByte = charArrayToByteArray(passphraseChar);
                secretKey = PBKDF.pbkdf2("HmacSHA256", passphraseByte, salt, PBKDF2_ITERATIONS, 32);
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
                Log.e("APP_TAG", "generateAndStoreSecretKeyFromPassphrase error: " + e.toString());
                return "";
            }
        }
        // api 26+ has HmacSHA256 available
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            try {
                secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec keySpec = new PBEKeySpec(passphraseChar, salt, PBKDF2_ITERATIONS, 32 * 8);
                secretKey = secretKeyFactory.generateSecret(keySpec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                e.printStackTrace();
                return "";
            }
        }
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * 8, nonce);
        Cipher cipher = null;
        byte[] ciphertext = new byte[0];
        try {
            cipher = Cipher.getInstance(TRANSFORMATION_GCM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);
            ciphertext = cipher.doFinal(plaintextByte);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            return "";
        }
        // concatenating salt, nonce and ciphertext
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(salt);
            outputStream.write(nonce);
            outputStream.write(ciphertext);
        } catch (IOException e) {
            e.printStackTrace();
            return "";
        }
        return base64Encoding(outputStream.toByteArray());
    }

    private String doDecryptionAesGcmPbkdf2FromBase64(char[] passphraseChar, String ciphertextBase64) {
        final int PBKDF2_ITERATIONS = 10000; // fixed as minimum
        final String TRANSFORMATION_GCM = "AES/GCM/NoPadding";
        int saltLength = 32;
        int nonceLength = 12;
        // split the complete ciphertext into salt, nonce and ciphertext
        byte[] ciphertextComplete = new byte[0];
        try {
            ciphertextComplete = base64Decoding(ciphertextBase64);
        } catch (IllegalArgumentException exception) {
            return "ERROR: The input data (ciphertext) was corrupted.";
        }
        ByteBuffer bb = ByteBuffer.wrap(ciphertextComplete);
        byte[] salt = new byte[saltLength];
        byte[] nonce = new byte[nonceLength];
        byte[] ciphertext = new byte[(ciphertextComplete.length - saltLength - nonceLength)];
        bb.get(salt, 0, salt.length);
        bb.get(nonce, 0, nonce.length);
        bb.get(ciphertext, 0, ciphertext.length);
        SecretKeyFactory secretKeyFactory = null;
        byte[] secretKey = new byte[0];
        // we are deriving the secretKey from the passphrase with PBKDF2 and using
        // the hash algorithm Hmac256, this is built in from SDK >= 26
        // for older SDKs we are using the own PBKDF2 function
        // api between 23 - 25
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M &
                Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            try {
                // uses 3rd party PBKDF function to get PBKDF2withHmacSHA256
                // PBKDF2withHmacSHA256	is available API 26+
                byte[] passphraseByte = charArrayToByteArray(passphraseChar);
                secretKey = PBKDF.pbkdf2("HmacSHA256", passphraseByte, salt, PBKDF2_ITERATIONS, 32);
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
                Log.e("APP_TAG", "generateAndStoreSecretKeyFromPassphrase error: " + e.toString());
                return "";
            }
        }
        // api 26+ has HmacSHA256 available
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            try {
                secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec keySpec = new PBEKeySpec(passphraseChar, salt, PBKDF2_ITERATIONS, 32 * 8);
                secretKey = secretKeyFactory.generateSecret(keySpec).getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                e.printStackTrace();
                return "";
            }
        }
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * 8, nonce);
        Cipher cipher = null;
        byte[] decryptedtextByte = new byte[0];
        try {
            cipher = Cipher.getInstance(TRANSFORMATION_GCM);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);
            decryptedtextByte = cipher.doFinal(ciphertext);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            return "ERROR: The passphrase may be wrong or the ciphertext is corrupted";
        }
        return new String(decryptedtextByte, StandardCharsets.UTF_8);
    }

    // https://stackoverflow.com/a/9670279/8166854
    byte[] charArrayToByteArray(char[] chars) {
        CharBuffer charBuffer = CharBuffer.wrap(chars);
        ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(charBuffer);
        byte[] bytes = Arrays.copyOfRange(byteBuffer.array(),
                byteBuffer.position(), byteBuffer.limit());
        Arrays.fill(chars, '\u0000'); // clear sensitive data
        Arrays.fill(byteBuffer.array(), (byte) 0); // clear sensitive data
        return bytes;
    }

    private static String base64Encoding(byte[] input) {
        return Base64.encodeToString(input, Base64.NO_WRAP);
    }

    private static byte[] base64Decoding(String input) {
        return Base64.decode(input, Base64.NO_WRAP);
    }

    private void writeToUiToast(String message) {
        runOnUiThread(() -> {
            Toast.makeText(getApplicationContext(),
                    message,
                    Toast.LENGTH_SHORT).show();
        });
    }

// section for main menu

    private void exportDumpMail() {
        if (dataToSave == null) {
            writeToUiToast("Encrypt some data first before sending emails :-)");
            return;
        }
        String subject = "Encryption AES-256 GCM PBKDF2";
        String body = ciphertextBase64;
        Intent intent = new Intent(Intent.ACTION_SEND);
        intent.setType("text/plain");
        intent.putExtra(Intent.EXTRA_SUBJECT, subject);
        intent.putExtra(Intent.EXTRA_TEXT, body);
        if (intent.resolveActivity(getPackageManager()) != null) {
            startActivity(intent);
        }
    }

    private void exportDumpFile() {
        if (dataToSave == null) {
            writeToUiToast("Encrypt some data first before writing files :-)");
            return;
        }
        verifyPermissionsWriteString();
    }

    // section external storage permission check
    private void verifyPermissionsWriteString() {
        String[] permissions = {Manifest.permission.READ_EXTERNAL_STORAGE,
                Manifest.permission.WRITE_EXTERNAL_STORAGE};
        if (ContextCompat.checkSelfPermission(this.getApplicationContext(),
                permissions[0]) == PackageManager.PERMISSION_GRANTED
                && ContextCompat.checkSelfPermission(this.getApplicationContext(),
                permissions[1]) == PackageManager.PERMISSION_GRANTED) {
            writeStringToExternalSharedStorage();
        } else {
            ActivityCompat.requestPermissions(this,
                    permissions,
                    REQUEST_PERMISSION_WRITE_EXTERNAL_STORAGE);
        }
    }

    private void writeStringToExternalSharedStorage() {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        // Optionally, specify a URI for the file that should appear in the
        // system file picker when it loads.
        //boolean pickerInitialUri = false;
        //intent.putExtra(DocumentsContract.EXTRA_INITIAL_URI, pickerInitialUri);
        // get filename from edittext
        String filename = "test" + ".txt";
        // sanity check
        if (filename.equals("")) {
            writeToUiToast("scan a tag before writing the content to a file :-)");
            return;
        }
        intent.putExtra(Intent.EXTRA_TITLE, filename);
        fileSaverActivityResultLauncher.launch(intent);
    }

    ActivityResultLauncher<Intent> fileSaverActivityResultLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            new ActivityResultCallback<ActivityResult>() {
                @Override
                public void onActivityResult(ActivityResult result) {
                    if (result.getResultCode() == Activity.RESULT_OK) {
                        // There are no request codes
                        Intent resultData = result.getData();
                        // The result data contains a URI for the document or directory that
                        // the user selected.
                        Uri uri = null;
                        if (resultData != null) {
                            uri = resultData.getData();
                            // Perform operations on the document using its URI.
                            // get file content from edittext
                            String fileContent = ciphertextBase64;
                            try {
                                writeTextToUri(uri, fileContent);
                            } catch (IOException e) {
                                e.printStackTrace();
                                writeToUiToast("Error on writing data: " + e);
                                return;
                            }
                            writeToUiToast("file written to external shared storage: " + uri.toString());
                        }
                    }
                }
            });

    private void writeTextToUri(Uri uri, String data) throws IOException {
        try {
            OutputStreamWriter outputStreamWriter = new OutputStreamWriter(contextSave.getContentResolver().openOutputStream(uri));
            outputStreamWriter.write(data);
            outputStreamWriter.close();
        } catch (IOException e) {
            System.out.println("Exception File write failed: " + e.toString());
        }
    }

    private void writeByteToUri(Uri uri, byte[] data) throws IOException {




    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_activity_main, menu);

        MenuItem mExportMail = menu.findItem(R.id.action_export_mail);
        mExportMail.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                exportDumpMail();
                return false;
            }
        });

        MenuItem mExportFile = menu.findItem(R.id.action_export_file);
        mExportFile.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                exportDumpFile();
                return false;
            }
        });

        MenuItem mClearDump = menu.findItem(R.id.action_clear_dump);
        mClearDump.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                //dumpExportString = "";
                //readResult.setText("read result");
                return false;
            }
        });

        return super.onCreateOptionsMenu(menu);
    }
}