package main;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AESEncryptionSystem extends JFrame {
    private JTextField plaintextField;
    private JTextField keyField;
    private JTextArea resultArea;
    private JComboBox<String> modeComboBox;
    private JButton encryptButton;
    private JButton decryptButton;
    private JButton saveButton;
    private JButton loadButton;

    private String encryptedText; // Store the encrypted text

    public AESEncryptionSystem() {
        setTitle("AES Encryption/Decryption System");
        setSize(500, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        // Input Panel
        JPanel inputPanel = new JPanel(new GridLayout(3, 2));
        inputPanel.add(new JLabel("Plaintext:"));
        plaintextField = new JTextField();
        inputPanel.add(plaintextField);
        inputPanel.add(new JLabel("Secret Key (16/24/32 characters):"));
        keyField = new JTextField();
        inputPanel.add(keyField);
        inputPanel.add(new JLabel("Block Cipher Mode:"));
        modeComboBox = new JComboBox<>(new String[]{"ECB", "CBC", "CFB"});
        inputPanel.add(modeComboBox);

        // Button Panel
        JPanel buttonPanel = new JPanel(new FlowLayout());
        encryptButton = new JButton("Encrypt");
        decryptButton = new JButton("Decrypt");
        saveButton = new JButton("Save to File");
        loadButton = new JButton("Load from File");
        buttonPanel.add(encryptButton);
        buttonPanel.add(decryptButton);
        buttonPanel.add(saveButton);
        buttonPanel.add(loadButton);

        // Result Area
        resultArea = new JTextArea();
        resultArea.setEditable(false);
        resultArea.setLineWrap(true);
        resultArea.setWrapStyleWord(true);
        resultArea.setPreferredSize(new Dimension(450, 150));
        JScrollPane scrollPane = new JScrollPane(resultArea);

        // Add components to frame
        add(inputPanel, BorderLayout.NORTH);
        add(buttonPanel, BorderLayout.CENTER);
        add(scrollPane, BorderLayout.SOUTH);

        // Add action listeners
        encryptButton.addActionListener(e -> encryptAction());
        decryptButton.addActionListener(e -> decryptAction());
        saveButton.addActionListener(e -> saveAction());
        loadButton.addActionListener(e -> loadAction());
    }

    private void encryptAction() {
        try {
            String plaintext = plaintextField.getText();
            String key = keyField.getText();
            if (key.length() != 16 && key.length() != 24 && key.length() != 32) {
                throw new Exception("Key must be 16, 24, or 32 characters long.");
            }
            String mode = (String) modeComboBox.getSelectedItem();
            encryptedText = encrypt(plaintext, key, mode); // Store the encrypted text
            resultArea.setText("Encrypted: " + encryptedText);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(null, "Error during encryption: " + ex.getMessage());
        }
    }

    private void decryptAction() {
        try {
            String ciphertext = resultArea.getText().replace("Encrypted: ", "");
            String key = keyField.getText();
            if (key.length() != 16 && key.length() != 24 && key.length() != 32) {
                throw new Exception("Key must be 16, 24, or 32 characters long.");
            }
            String mode = (String) modeComboBox.getSelectedItem();
            String decryptedText = decrypt(ciphertext, key, mode);
            resultArea.setText("Decrypted: " + decryptedText);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(null, "Error during decryption: " + ex.getMessage());
        }
    }

    private void saveAction() {
        try {
            if (encryptedText == null || encryptedText.isEmpty()) {
                JOptionPane.showMessageDialog(null, "Nothing to save. Please encrypt some text first.");
                return;
            }
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();
                try (FileWriter writer = new FileWriter(file)) {
                    writer.write(encryptedText);
                }
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(null, "Error saving file: " + ex.getMessage());
        }
    }

    private void loadAction() {
        try {
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();
                try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                    String ciphertext = reader.readLine();
                    if (ciphertext == null || ciphertext.isEmpty()) {
                        JOptionPane.showMessageDialog(null, "File is empty or invalid.");
                        return;
                    }
                    String key = keyField.getText();
                    if (key.length() != 16 && key.length() != 24 && key.length() != 32) {
                        throw new Exception("Key must be 16, 24, or 32 characters long.");
                    }
                    String mode = (String) modeComboBox.getSelectedItem();
                    String decryptedText = decrypt(ciphertext, key, mode);
                    resultArea.setText("Decrypted: " + decryptedText);
                }
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(null, "Error loading file: " + ex.getMessage());
        }
    }

    private String encrypt(String plaintext, String key, String mode) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance("AES/" + mode + "/PKCS5Padding");
        if (mode.equals("CBC") || mode.equals("CFB")) {
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv); // Generate a random IV
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            // Prepend IV to the encrypted data
            byte[] combined = new byte[iv.length + encryptedBytes.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);
            return Base64.getEncoder().encodeToString(combined);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        }
    }

    private String decrypt(String ciphertext, String key, String mode) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance("AES/" + mode + "/PKCS5Padding");
        byte[] decoded = Base64.getDecoder().decode(ciphertext);
        if (mode.equals("CBC") || mode.equals("CFB")) {
            byte[] iv = new byte[16];
            System.arraycopy(decoded, 0, iv, 0, iv.length); // Extract IV
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            byte[] encryptedBytes = new byte[decoded.length - iv.length];
            System.arraycopy(decoded, iv.length, encryptedBytes, 0, encryptedBytes.length);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedBytes = cipher.doFinal(decoded);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            AESEncryptionSystem frame = new AESEncryptionSystem();
            frame.setVisible(true);
        });
    }
}