// Enhanced utility functions
class CryptoUtils {
  static async generateRSAKeyPair() {
    return await window.crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"]
    );
  }

  static async exportPublicKey(key) {
    const spki = await window.crypto.subtle.exportKey("spki", key);
    return this.arrayBufferToBase64(spki);
  }

  static async exportPrivateKey(key) {
    const pk = await window.crypto.subtle.exportKey("pkcs8", key);
    return this.arrayBufferToBase64(pk);
  }

  static async importPublicKey(spkiBase64) {
    const spki = this.base64ToArrayBuffer(spkiBase64);
    return await window.crypto.subtle.importKey(
      "spki",
      spki,
      { name: "RSA-OAEP", hash: "SHA-256" },
      true,
      ["encrypt"]
    );
  }

  static async importPrivateKey(pkBase64) {
    const pk = this.base64ToArrayBuffer(pkBase64);
    return await window.crypto.subtle.importKey(
      "pkcs8",
      pk,
      { name: "RSA-OAEP", hash: "SHA-256" },
      true,
      ["decrypt"]
    );
  }

  static async generateAESKey() {
    return await window.crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
  }

  static async encryptAES(aesKey, data) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      aesKey,
      data
    );
    return { encrypted, iv };
  }

  static async decryptAES(aesKey, encrypted, iv) {
    return await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      aesKey,
      encrypted
    );
  }

  static arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let b of bytes) binary += String.fromCharCode(b);
    return btoa(binary);
  }

  static base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
}

// UI Management Class
class UIManager {
  static showNotification(message, type = 'info') {
    const notification = document.getElementById('notification');
    notification.textContent = message;
    notification.className = `notification ${type}`;
    notification.classList.add('show');
    
    setTimeout(() => {
      notification.classList.remove('show');
    }, 3000);
  }

  static updateProgress(elementId, percentage) {
    const progressBar = document.getElementById(elementId);
    const fill = progressBar.querySelector('.progress-fill');
    fill.style.width = percentage + '%';
    
    if (percentage === 100) {
      setTimeout(() => {
        progressBar.classList.add('hidden');
      }, 500);
    } else {
      progressBar.classList.remove('hidden');
    }
  }

  static async simulateProgress(elementId, duration = 2000) {
    return new Promise(resolve => {
      let progress = 0;
      const increment = 100 / (duration / 50);
      
      const interval = setInterval(() => {
        progress += increment;
        this.updateProgress(elementId, Math.min(progress, 100));
        
        if (progress >= 100) {
          clearInterval(interval);
          resolve();
        }
      }, 50);
    });
  }

  static addMessageToHistory(type, content, timestamp = new Date()) {
    const history = document.getElementById('messageHistory');
    const messageDiv = document.createElement('div');
    messageDiv.className = `message-bubble ${type === 'received' ? 'received' : ''}`;
    
    const timeStr = timestamp.toLocaleTimeString();
    messageDiv.innerHTML = `
      <div style="font-size: 12px; opacity: 0.7; margin-bottom: 5px;">
        ${type === 'sent' ? '📤 Encrypted' : '📥 Decrypted'} at ${timeStr}
      </div>
      <div>${content.substring(0, 100)}${content.length > 100 ? '...' : ''}</div>
    `;
    
    if (history.children.length === 1 && history.children[0].tagName === 'P') {
      history.innerHTML = '';
    }
    
    history.appendChild(messageDiv);
    history.scrollTop = history.scrollHeight;
  }

  static downloadFile(content, filename, type = 'text/plain') {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  static copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
      this.showNotification('📋 Copied to clipboard!', 'success');
    }).catch(() => {
      this.showNotification('❌ Failed to copy to clipboard', 'error');
    });
  }
}

// Application State
class AppState {
  constructor() {
    this.userKeyPair = null;
    this.messages = [];
  }

  setKeyPair(keyPair) {
    this.userKeyPair = keyPair;
  }

  addMessage(type, content) {
    this.messages.push({
      type,
      content,
      timestamp: new Date()
    });
    UIManager.addMessageToHistory(type, content);
  }

  clearMessages() {
    this.messages = [];
    document.getElementById('messageHistory').innerHTML = 
      '<p style="text-align: center; color: #666;">No messages yet. Start encrypting and decrypting messages!</p>';
  }

  exportMessages() {
    const data = JSON.stringify(this.messages, null, 2);
    UIManager.downloadFile(data, 'secure-messages.json', 'application/json');
  }
}

const appState = new AppState();

// Event Handlers
function initializeEventHandlers() {
  // Login handler
  document.getElementById('loginBtn').onclick = () => {
    const password = document.getElementById('passwordInput').value;
    if (password === 'rushi0612') {
      document.getElementById('loginSection').classList.add('hidden');
      document.getElementById('appSection').classList.remove('hidden');
      UIManager.showNotification('🎉 Welcome to SecureChat Pro!', 'success');
    } else {
      UIManager.showNotification('❌ Invalid password. Try again.', 'error');
    }
  };

  // Tab navigation
  document.querySelectorAll('.tab').forEach(tab => {
    tab.onclick = () => {
      const tabName = tab.dataset.tab;
      
      // Update active tab
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      
      tab.classList.add('active');
      document.getElementById(`${tabName}Tab`).classList.add('active');
    };
  });

  // Key Generation
  document.getElementById('generateKeysBtn').onclick = async () => {
    try {
      UIManager.showNotification('Generating RSA key pair...', 'info');
      const keyPair = await CryptoUtils.generateRSAKeyPair();
      appState.setKeyPair(keyPair);

      const publicKey = await CryptoUtils.exportPublicKey(keyPair.publicKey);
      const privateKey = await CryptoUtils.exportPrivateKey(keyPair.privateKey);

      document.getElementById('publicKeyDisplay').value = publicKey;
      document.getElementById('privateKeyDisplay').value = privateKey;
      document.getElementById('copyPublicBtn').disabled = false;
      document.getElementById('downloadPrivateBtn').disabled = false;
      UIManager.showNotification('Key pair generated successfully!', 'success');
    } catch (error) {
      console.error('Error generating keys:', error);
      UIManager.showNotification('Error generating keys. See console for details.', 'error');
    }
  };

  // Copy Public Key
  document.getElementById('copyPublicBtn').onclick = () => {
    const publicKey = document.getElementById('publicKeyDisplay').value;
    UIManager.copyToClipboard(publicKey);
  };

  // Download Private Key
  document.getElementById('downloadPrivateBtn').onclick = () => {
    const privateKey = document.getElementById('privateKeyDisplay').value;
    UIManager.downloadFile(privateKey, 'private_key.pem', 'application/x-pem-file');
    UIManager.showNotification('Downloading private key...', 'info');
  };

  // Import Private Key (File Input)
  document.getElementById('keyFileInput').onchange = async (event) => {
    const file = event.target.files[0];
    if (file) {
      try {
        const reader = new FileReader();
        reader.onload = async (e) => {
          const privateKeyBase64 = e.target.result;
          const privateKey = await CryptoUtils.importPrivateKey(privateKeyBase64);
          appState.setKeyPair({ privateKey: privateKey });
          document.getElementById('yourPrivateKey').value = privateKeyBase64;
          UIManager.showNotification('Private key imported successfully!', 'success');
        };
        reader.readAsText(file);
      } catch (error) {
        console.error('Error importing private key:', error);
        UIManager.showNotification('Error importing private key. Make sure it\'s a valid PEM/PKCS8 format.', 'error');
      }
    }
  };

  // Import Private Key (Drag and Drop)
  const keyDropZone = document.getElementById('keyDropZone');
  keyDropZone.ondragover = (e) => {
    e.preventDefault();
    e.stopPropagation();
    keyDropZone.style.backgroundColor = 'rgba(102, 126, 234, 0.2)';
  };
  keyDropZone.ondragleave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    keyDropZone.style.backgroundColor = '';
  };
  keyDropZone.ondrop = async (e) => {
    e.preventDefault();
    e.stopPropagation();
    keyDropZone.style.backgroundColor = '';
    const file = e.dataTransfer.files[0];
    if (file) {
      try {
        const reader = new FileReader();
        reader.onload = async (event) => {
          const privateKeyBase64 = event.target.result;
          const privateKey = await CryptoUtils.importPrivateKey(privateKeyBase64);
          appState.setKeyPair({ privateKey: privateKey });
          document.getElementById('yourPrivateKey').value = privateKeyBase64;
          UIManager.showNotification('Private key imported successfully!', 'success');
        };
        reader.readAsText(file);
      } catch (error) {
        console.error('Error importing private key:', error);
        UIManager.showNotification('Error importing private key. Make sure it\'s a valid PEM/PKCS8 format.', 'error');
      }
    }
  };
  keyDropZone.onclick = () => {
    document.getElementById('keyFileInput').click();
  };


  // Enable Encrypt button if inputs are present
  document.getElementById('recipientPublicKey').oninput = 
  document.getElementById('plainText').oninput = () => {
    const recipientKey = document.getElementById('recipientPublicKey').value;
    const message = document.getElementById('plainText').value;
    document.getElementById('encryptBtn').disabled = !recipientKey || !message;
    document.getElementById('charCount').textContent = message.length;
  };

  // Encryption
  document.getElementById('encryptBtn').onclick = async () => {
    const recipientPublicKeyBase64 = document.getElementById('recipientPublicKey').value;
    const plainText = document.getElementById('plainText').value;

    if (!recipientPublicKeyBase64 || !plainText) {
      UIManager.showNotification('Please provide recipient public key and message.', 'warning');
      return;
    }

    try {
      UIManager.showNotification('Encrypting message...', 'info');
      UIManager.updateProgress('encryptProgress', 0);
      await UIManager.simulateProgress('encryptProgress');

      const recipientPublicKey = await CryptoUtils.importPublicKey(recipientPublicKeyBase64);
      const aesKey = await CryptoUtils.generateAESKey();
      const exportedAesKey = await window.crypto.subtle.exportKey("raw", aesKey);
      
      const encryptedAESKey = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        recipientPublicKey,
        exportedAesKey
      );

      const encodedMessage = new TextEncoder().encode(plainText);
      const { encrypted, iv } = await CryptoUtils.encryptAES(aesKey, encodedMessage);

      document.getElementById('encryptedMessage').value = CryptoUtils.arrayBufferToBase64(encrypted);
      document.getElementById('encryptedAESKey').value = CryptoUtils.arrayBufferToBase64(encryptedAESKey);
      document.getElementById('iv').value = CryptoUtils.arrayBufferToBase64(iv);
      document.getElementById('encryptionResults').classList.remove('hidden');
      document.getElementById('copyEncryptedBtn').disabled = false;

      appState.addMessage('sent', plainText);
      UIManager.showNotification('Message encrypted successfully!', 'success');
    } catch (error) {
      console.error('Error encrypting message:', error);
      UIManager.showNotification('Error encrypting message. Check keys and message format.', 'error');
    }
  };

  // Copy Encrypted Data
  document.getElementById('copyEncryptedBtn').onclick = () => {
    const encryptedMessage = document.getElementById('encryptedMessage').value;
    const encryptedAESKey = document.getElementById('encryptedAESKey').value;
    const iv = document.getElementById('iv').value;
    const dataToCopy = `Encrypted Message:\n${encryptedMessage}\n\nEncrypted AES Key:\n${encryptedAESKey}\n\nIV:\n${iv}`;
    UIManager.copyToClipboard(dataToCopy);
  };

  // Enable Decrypt button if inputs are present
  document.getElementById('yourPrivateKey').oninput =
  document.getElementById('encMessageForDecryption').oninput =
  document.getElementById('encAESKeyForDecryption').oninput =
  document.getElementById('ivForDecryption').oninput = () => {
    const privateKey = document.getElementById('yourPrivateKey').value;
    const encMessage = document.getElementById('encMessageForDecryption').value;
    const encAESKey = document.getElementById('encAESKeyForDecryption').value;
    const iv = document.getElementById('ivForDecryption').value;
    document.getElementById('decryptBtn').disabled = !privateKey || !encMessage || !encAESKey || !iv;
  };

  // Decryption
  document.getElementById('decryptBtn').onclick = async () => {
    const yourPrivateKeyBase64 = document.getElementById('yourPrivateKey').value;
    const encryptedMessageBase64 = document.getElementById('encMessageForDecryption').value;
    const encryptedAESKeyBase64 = document.getElementById('encAESKeyForDecryption').value;
    const ivBase64 = document.getElementById('ivForDecryption').value;

    if (!yourPrivateKeyBase64 || !encryptedMessageBase64 || !encryptedAESKeyBase64 || !ivBase64) {
      UIManager.showNotification('Please fill all decryption fields.', 'warning');
      return;
    }

    try {
      UIManager.showNotification('Decrypting message...', 'info');
      UIManager.updateProgress('decryptProgress', 0);
      await UIManager.simulateProgress('decryptProgress');

      const privateKey = await CryptoUtils.importPrivateKey(yourPrivateKeyBase64);
      const encryptedAESKeyBuffer = CryptoUtils.base64ToArrayBuffer(encryptedAESKeyBase64);
      const encryptedMessageBuffer = CryptoUtils.base64ToArrayBuffer(encryptedMessageBase64);
      const ivBuffer = CryptoUtils.base64ToArrayBuffer(ivBase64);

      const decryptedAESKey = await window.crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        encryptedAESKeyBuffer
      );

      const aesKey = await window.crypto.subtle.importKey(
        "raw",
        decryptedAESKey,
        { name: "AES-GCM" },
        true,
        ["decrypt"]
      );

      const decrypted = await CryptoUtils.decryptAES(aesKey, encryptedMessageBuffer, ivBuffer);
      const decryptedText = new TextDecoder().decode(decrypted);

      document.getElementById('decryptedMessage').value = decryptedText;
      document.getElementById('decryptionResults').classList.remove('hidden');

      appState.addMessage('received', decryptedText);
      UIManager.showNotification('Message decrypted successfully!', 'success');
    } catch (error) {
      console.error('Error decrypting message:', error);
      UIManager.showNotification('Error decrypting message. Check keys, message, AES key, and IV.', 'error');
    }
  };

  // Clear Message History
  document.getElementById('clearHistoryBtn').onclick = () => {
    appState.clearMessages();
    UIManager.showNotification('Message history cleared.', 'info');
  };

  // Export Message History
  document.getElementById('exportHistoryBtn').onclick = () => {
    if (appState.messages.length > 0) {
      appState.exportMessages();
      UIManager.showNotification('Message history exported.', 'success');
    } else {
      UIManager.showNotification('No messages to export.', 'warning');
    }
  };
}

// Initialize event handlers when the DOM is loaded
document.addEventListener('DOMContentLoaded', initializeEventHandlers);