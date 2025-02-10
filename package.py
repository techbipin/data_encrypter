import base64
import pickle
from hashlib import sha256
from django.db import models


class DataEncrypter:
    """
    A class for encrypting and decrypting Django model instances using a password-derived key.

    This class uses XOR encryption combined with base64 encoding and pickling for serialization.
    It's important to note that this implementation is for demonstration and educational purposes.
    For production systems, consider using robust encryption libraries and key management solutions.
    """

    def generate_key(self, password):
        """
        Generates a SHA256 hash of the password to use as the encryption key.

        Args:
            password (str): The password to derive the key from.

        Returns:
            bytes: The SHA256 hash of the password.
        """
        return sha256(password.encode()).digest()

    def _xor_bytes(self, data, key):
        """
        Performs XOR encryption/decryption on the given data using the key.

        Args:
            data (bytes): The data to be processed.
            key (bytes): The encryption/decryption key.

        Returns:
            bytes: The XORed data.
        """
        return bytes(a ^ b for a, b in zip(data, key * (len(data) // len(key) + 1)))

    def format_field_value(self, field_value):
        """
        Formats field values for encryption/decryption.  Handles related models and managers.

        Args:
            field_value: The value of the field.

        Returns:
            str: A string representation of the field value.
        """
        if isinstance(field_value, models.Model):
            return f"Related {field_value._meta.model_name} (pk={field_value.pk})"
        elif isinstance(field_value, models.Manager):
            return f"Manager for {field_value.related_model._meta.model_name}"
        else:
            return str(field_value)

    def _process_model_instance(self, instance, password, operation):
        """
        Encrypts or decrypts the fields of a model instance.

        Args:
            instance (models.Model): The model instance to process.
            password (str): The password to use for encryption/decryption.
            operation (str): 'encrypt' or 'decrypt'.

        Returns:
            list: A list of field names that were updated.
        """
        key = self.generate_key(password)
        fields = instance._meta.get_fields()
        current_data = {}

        for field in fields:
            field_name = field.name
            try:
                field_value = getattr(instance, field_name)
                field_value_str = self.format_field_value(field_value)
                current_data[field_name] = field_value_str
            except AttributeError:
                print(f"  {field_name}: (Not accessible or related field)")

        processed_data = {}
        for key, value in current_data.items():
            secret_key = self.generate_key(password) # Key should be consistent for encryption/decryption
            if key != 'id':  # Don't encrypt the primary key
                if operation == 'encrypt':
                    processed_data[key] = self.encrypt(value, secret_key)
                elif operation == 'decrypt':
                    processed_data[key] = self.decrypt(value, secret_key)
                else:
                    raise ValueError("Invalid operation. Must be 'encrypt' or 'decrypt'.")

        fields_to_update = []
        for field_name, new_value in processed_data.items():
            if hasattr(instance, field_name):
                current_value = getattr(instance, field_name)
                if new_value != current_value:
                    setattr(instance, field_name, new_value)
                    fields_to_update.append(field_name)
            else:
                print(f" Warning: Field '{field_name}' not found on model. Skipping update.")

        return fields_to_update

    def encrypt(self, data, key):
        """
        Encrypts data using XOR encryption, base64 encoding, and pickling.

        Args:
            data: The data to encrypt.
            key (bytes): The encryption key.

        Returns:
            str: The encrypted data as a base64 encoded string.
        """
        serialized = pickle.dumps(data)
        encrypted = self._xor_bytes(serialized, key)
        return base64.b64encode(encrypted).decode()

    def decrypt(self, encrypted_data, key):
        """
        Decrypts data using base64 decoding, XOR decryption, and unpickling.

        Args:
            encrypted_data (str): The base64 encoded encrypted data.
            key (bytes): The decryption key.

        Returns:
            The decrypted data.
        """
        decoded_data = base64.b64decode(encrypted_data)
        decrypted = self._xor_bytes(decoded_data, key)
        return pickle.loads(decrypted)

    def encrypt_model_instance(self, instance, password):
        """
        Encrypts a model instance's fields and saves the changes to the database.

        Args:
            instance (models.Model): The model instance to encrypt.
            password (str): The password to use for encryption.
        """
        fields_to_update = self._process_model_instance(instance, password, 'encrypt')
        if fields_to_update:
            instance.save(update_fields=fields_to_update)
            print("Instance updated and saved.")
        else:
            print("No fields were updated.")

    def decrypt_model_instance(self, instance, password):
        """
        Decrypts a model instance's fields.  Does not save the changes.

        Args:
            instance (models.Model): The model instance to decrypt.
            password (str): The password to use for decryption.

        Returns:
            list: A list of field names that were updated.
        """
        return self._process_model_instance(instance, password, 'decrypt')