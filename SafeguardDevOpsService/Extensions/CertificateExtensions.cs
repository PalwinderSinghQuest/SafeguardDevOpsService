using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace OneIdentity.DevOps.Extensions
{
    public static class CertificateExtensions
    {
        public static X509Certificate2 LoadFromBytes(byte[] rawData, string? password = null, X509KeyStorageFlags? keyStorageFlags = null)
        {
            // 1. Detect if the byte array is PKCS12 or PEM
            X509ContentType contentType = X509Certificate2.GetCertContentType(rawData);

            if (contentType == X509ContentType.Pkcs12)
            {
                if (keyStorageFlags.HasValue)
                {
                    // Use the new .NET 9 Loader for binary PKCS12/PFX
                    return X509CertificateLoader.LoadPkcs12(rawData, password, keyStorageFlags.Value);
                }
                else
                {
                    // Use the new .NET 9 Loader for binary PKCS12/PFX
                    return X509CertificateLoader.LoadPkcs12(rawData, password);
                }

            }
            else
            {
                // It's likely PEM (text-based). 
                // We convert the bytes to a string to use the PEM parser.
                string pemString = Encoding.UTF8.GetString(rawData);

                // This works if the PEM contains both the CERTIFICATE and PRIVATE KEY
                return X509Certificate2.CreateFromPem(pemString);
            }
        }
    }
}
