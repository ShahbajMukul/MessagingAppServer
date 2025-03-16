using System.Security.Cryptography;

namespace MessagingAppServer.Services
{
    public static class CryptographyService
    {
        public static (string publicKey, string privateKey) GenerateRSAKeyPair()
        {
            using (RSA rsa = RSA.Create(2048)) // 2048-bit key
            {
                // Export the public key
                string publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());

                // Export the private key
                string privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());

                return (publicKey, privateKey);
            }
        }

        // Helper method to import keys when needed
        public static RSA ImportPublicKey(string publicKeyBase64)
        {
            RSA rsa = RSA.Create();
            rsa.ImportRSAPublicKey(Convert.FromBase64String(publicKeyBase64), out _);
            return rsa;
        }

        public static RSA ImportPrivateKey(string privateKeyBase64)
        {
            RSA rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(Convert.FromBase64String(privateKeyBase64), out _);
            return rsa;
        }
    }
}
