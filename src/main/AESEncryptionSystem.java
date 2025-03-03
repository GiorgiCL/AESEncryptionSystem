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
        inputPanel.add(new JLabel("Secret Key (16 characters):"));
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
        resultArea.setPreferredSize(new Dimension(450, 150)); // Increased height
        JScrollPane scrollPane = new JScrollPane(resultArea);

        // Add components to frame
        add(inputPanel, BorderLayout.NORTH);
        add(buttonPanel, BorderLayout.CENTER);
        add(scrollPane, BorderLayout.SOUTH);

        // Add action listeners
        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    String plaintext = plaintextField.getText();
                    String key = keyField.getText();
                    if (key.length() != 16) {
                        throw new Exception("Key must be exactly 16 characters long.");
                    }
                    String mode = (String) modeComboBox.getSelectedItem();
                    encryptedText = encrypt(plaintext, key, mode); // Store the encrypted text
                    resultArea.setText("Encrypted: " + encryptedText);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(null, "Error during encryption: " + ex.getMessage());
                }
            }
        });

        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    String ciphertext = resultArea.getText().replace("Encrypted: ", "");
                    String key = keyField.getText();
                    if (key.length() != 16) {
                        throw new Exception("Key must be exactly 16 characters long.");
                    }
                    String mode = (String) modeComboBox.getSelectedItem();
                    String decryptedText = decrypt(ciphertext, key, mode);
                    resultArea.setText("Decrypted: " + decryptedText);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(null, "Error during decryption: " + ex.getMessage());
                }
            }
        });

        saveButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
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
        });

        loadButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
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
                            if (key.length() != 16) {
                                throw new Exception("Key must be exactly 16 characters long.");
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
        });
    }

    private String encrypt(String plaintext, String key, String mode) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance("AES/" + mode + "/PKCS5Padding");
        if (mode.equals("CBC") || mode.equals("CFB")) {
            byte[] iv = new byte[16];
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        }
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private String decrypt(String ciphertext, String key, String mode) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance("AES/" + mode + "/PKCS5Padding");
        if (mode.equals("CBC") || mode.equals("CFB")) {
            byte[] iv = new byte[16];
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
        }
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            AESEncryptionSystem frame = new AESEncryptionSystem();
            frame.setVisible(true);
        });
    }
}
