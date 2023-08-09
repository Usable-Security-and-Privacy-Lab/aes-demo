/* Based heavily on code from

https://github.com/mdn/dom-examples/blob/main/web-crypto/encrypt-decrypt/index.html

*/

/*
Wrap all the code in an anonymous function. This prevents any variables defined in this scope to pollute any other included script (or vice versa).
*/

(() => {

    /*
    Store the calculated ciphertext and IV here, so we can decrypt the message later.
    */
    let ciphertext;
    let iv;

    /*
    Fetch the contents of the "message" textbox, and encode it
    in a form we can use for the encrypt operation.
    */
    function getMessageEncoding() {
        const messageBox = document.querySelector("#aes-gcm-message");
        let message = messageBox.value;
        let enc = new TextEncoder();
        return enc.encode(message);
    }

    /*
    Convert a buffer of unsigned ints to base 64 encoding
    */
    const bufferToBase64 = (buff) => window.btoa(
        new Uint8Array(buff).reduce(
            (data, byte) => data + String.fromCharCode(byte), ''
        )
    );

    const bufferToHex = (buff) => {
        return buff.reduce((data, byte) => data + byte.toString(16), '')
    }

    /* 
    Convert a base64 string into a buffer of unsigned ints.
    */
    const base64ToBuffer = (b64) =>
        Uint8Array.from(window.atob(b64), (c) => c.charCodeAt(null));

    /*
    Get the encoded message, encrypt it and display a representation
    of the ciphertext in the "Ciphertext" element.
    */
    async function encryptMessage(key) {
        let encoded = getMessageEncoding();
        console.log(encoded);
        // The iv must never be reused with a given key.
        iv = window.crypto.getRandomValues(new Uint8Array(12));
        ciphertext = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            key,
            encoded
        );

        let buffer = new Uint8Array(ciphertext, 0, 5);
        const ciphertextValue = document.querySelector(".aes-gcm .ciphertext-value");
        ciphertextValue.classList.add('fade-in');
        ciphertextValue.addEventListener('animationend', () => {
            ciphertextValue.classList.remove('fade-in');
        });
        ciphertextValue.textContent = bufferToBase64(ciphertext);
        // ciphertextValue.textContent = bufferToHex(buffer);
        // ciphertextValue.textContent = `${buffer}...[${ciphertext.byteLength} bytes total]`;
    }

    /*
    Fetch the ciphertext and decrypt it.
    Write the decrypted message into the "Decrypted" box.
    */
    async function decryptMessage(key) {
        // export the key to raw format, which gives us an ArrayBuffer
        const exported = await window.crypto.subtle.exportKey("raw", key);
        // convert this to an array of 32 bit unsigned integers
        const exportedKeyBuffer = new Uint32Array(exported);

        // show the first integer of the exported key on the console
        console.log("first integer of exported key: ", exportedKeyBuffer[0]);

        // define a bit mask for the lower (right most) two bits
        mask = 0b11;
        // clear these bits
        exportedKeyBuffer[0] &= ~mask;

        // show the modified version of this first integer on the console.
        // this lets you see how the cleared bits result in new integer
        console.log(exportedKeyBuffer[0]);

        // Try all possible integers for this part of the key. 
        // Since we cleared 2 bits there are four choices.
        const times = 4;

        // This will hold the decrypted text.
        let decrypted;
        // This holds the original, first 32-bit unsigned int of the
        // exported key
        let original = exportedKeyBuffer[0];

        // loop over all possible versions of this portion of the key
        for (let i = 0; i < times; i++) {
            exportedKeyBuffer[0] = original + i;
            // since we are modifying the array of ints directly,
            // the ".buffer" converts this back to the the original
            // ArrayBuffer
            converted = exportedKeyBuffer.buffer;

            // Try to decrypt with this key we have guessed. If it fails,
            // it will trigger the "except" block.
            try {
                // Import the key from the guess we made.
                importedKey = await window.crypto.subtle.importKey("raw", converted, "AES-GCM", true, [
                    "encrypt",
                    "decrypt",
                ]);
                console.log("Trying the imported key: ", importedKey)
                decrypted = await window.crypto.subtle.decrypt(
                    {
                        name: "AES-GCM",
                        iv: iv
                    },
                    importedKey,
                    ciphertext
                );
                // Success! Break here since we found it.
                console.log("Decryption success")
                break;
            } catch {
                console.log("Decryption failure")
            }
        }


        let dec = new TextDecoder();
        const decryptedValue = document.querySelector(".aes-gcm .decrypted-value");
        decryptedValue.classList.add('fade-in');
        decryptedValue.addEventListener('animationend', () => {
            decryptedValue.classList.remove('fade-in');
        });
        decryptedValue.textContent = dec.decode(decrypted);
    }

    /*
    Generate an encryption key, then set up event listeners
    on the "Encrypt" and "Decrypt" buttons.
    */
    window.crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256,
        },
        true,
        ["encrypt", "decrypt"]
    ).then((key) => {
        const encryptButton = document.querySelector(".aes-gcm .encrypt-button");
        encryptButton.addEventListener("click", () => {
            encryptMessage(key);
        });

        const decryptButton = document.querySelector(".aes-gcm .decrypt-button");
        decryptButton.addEventListener("click", () => {
            decryptMessage(key);
        });
    });

})();